"""Build a deterministic Lambda zip from a hash-locked dependency staging directory."""

from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def build_release(package: Path, output: Path) -> dict:
    if not package.is_dir():
        raise ValueError("Install src/requirements.txt into --package-dir first")
    paths = {}
    for source, prefix in ((package, ""), (ROOT / "src", "")):
        for path in sorted(source.rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            relative = prefix + path.relative_to(source).as_posix()
            if relative == "requirements.txt":
                continue
            if source == package and (
                relative.startswith("bin/")
                or (
                    ".dist-info/" in relative
                    and path.name in {"RECORD", "INSTALLER", "REQUESTED", "direct_url.json"}
                )
            ):
                # Installer-local shebangs/paths are not runtime dependencies.
                # Preserve distribution metadata and licenses, not machine-specific records.
                continue
            paths[relative] = path
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative, path in sorted(paths.items()):
            info = zipfile.ZipInfo(relative, (2020, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())
    manifest = {
        "schema": 1,
        "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "lock_sha256": hashlib.sha256((ROOT / "src/requirements.txt").read_bytes()).hexdigest(),
        "template_sha256": hashlib.sha256((ROOT / "template.yaml").read_bytes()).hexdigest(),
        "files": len(paths),
    }
    output.with_suffix(".manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(build_release(args.package_dir, args.output), indent=2))
