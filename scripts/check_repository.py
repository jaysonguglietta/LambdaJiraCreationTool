"""Fail closed on private tracked files, populated templates and recognizable secrets.

This publication preflight is not a full-history or comprehensive secret scanner.
It reports file/line/rule only, never matched credential values.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
PRIVATE_PARTS = {
    "local",
    "exports",
    "reports",
    "data",
    "build",
    ".aws-sam",
    ".venv",
    "__pycache__",
    ".ruff_cache",
    ".pytest_cache",
    ".aws",
}
PATTERNS = {
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "aws-access-key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "github-token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b"),
    "atlassian-token": re.compile(r"\bATATT[A-Za-z0-9_-]{30,}\b"),
    "local-home-path": re.compile(r"/(?:Users|home)/[A-Za-z0-9_.-]+/"),
}


def private_path(name: str) -> bool:
    path = PurePosixPath(name)
    return (
        any(part in PRIVATE_PARTS for part in path.parts)
        or (path.name.startswith(".env") and path.name != ".env.example")
        or (path.name.startswith("samconfig") and path.name != "samconfig.toml.example")
        or path.name.endswith((".pem", ".key", ".p12", ".pfx", ".backup.json"))
        or (path.suffix == ".csv" and path.parts[:2] != ("tests", "fixtures"))
        or (
            path.parts[0] == "config"
            and path.suffix == ".json"
            and not path.name.endswith(".example.json")
        )
    )


def blank_values(value) -> bool:
    if isinstance(value, dict):
        return all(blank_values(v) for v in value.values())
    return value == ""


def scan_content(name: str, body: bytes) -> list[dict]:
    findings = []
    if private_path(name):
        findings.append({"file": name, "rule": "private-file"})
    if len(body) > 1024 * 1024:
        return findings + [{"file": name, "rule": "oversized-file"}]
    try:
        content = body.decode("utf-8")
    except UnicodeDecodeError:
        return findings + [{"file": name, "rule": "binary-file"}]
    if name in {"config/environment.example.json", "config/deployment.example.json"}:
        try:
            if not blank_values(json.loads(content)):
                findings.append({"file": name, "rule": "populated-settings-template"})
        except json.JSONDecodeError:
            findings.append({"file": name, "rule": "invalid-settings-template"})
    if name == ".env.example" and any(
        line.strip()
        and not line.lstrip().startswith("#")
        and ("=" not in line or line.split("=", 1)[1].strip())
        for line in content.splitlines()
    ):
        findings.append({"file": name, "rule": "populated-settings-template"})
    if name == "samconfig.toml.example":
        try:
            parameters = tomllib.loads(content)["default"]["deploy"]["parameters"]
            if any(
                parameters.get(k)
                for k in ("stack_name", "region", "profile", "parameter_overrides")
            ):
                findings.append({"file": name, "rule": "populated-settings-template"})
        except (tomllib.TOMLDecodeError, KeyError):
            findings.append({"file": name, "rule": "invalid-settings-template"})
    for number, line in enumerate(content.splitlines(), 1):
        for rule, pattern in PATTERNS.items():
            if pattern.search(line):
                findings.append({"file": name, "line": number, "rule": rule})
    return findings


def candidates(root: Path, *, staged: bool = False):
    git_binary = shutil.which("git")
    if not git_binary:
        raise ValueError("Git is required for publication checks")
    git = subprocess.run(  # noqa: S603 - fixed argv, resolved executable, no shell
        [git_binary, "ls-files", "-z"],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if git.returncode:
        if staged:
            raise ValueError("Staged validation requires a Git repository")
        names = [
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file()
            and ".git" not in path.relative_to(root).parts
            and not any(p in PRIVATE_PARTS for p in path.relative_to(root).parts)
            and path.name != ".DS_Store"
        ]
    else:
        names = [name for name in git.stdout.decode().split("\x00") if name]
    if len(names) > 1000:
        raise ValueError("Too many publication candidates; inspect scope before continuing")
    for name in sorted(names):
        path = root / name
        if path.is_symlink():
            yield name, b"", "symlink-file"
        elif staged:
            size = subprocess.run(  # noqa: S603 - index paths come from Git, not shell syntax
                [git_binary, "cat-file", "-s", f":{name}"],
                cwd=root,
                capture_output=True,
                check=True,
            )
            if int(size.stdout) > 1024 * 1024:
                yield name, b"", "oversized-file"
                continue
            body = subprocess.run(  # noqa: S603 - literal index revision; never shell execution
                [git_binary, "show", f":{name}"],
                cwd=root,
                capture_output=True,
                check=True,
            ).stdout
            yield name, body, None
        else:
            if path.stat().st_size > 1024 * 1024:
                yield name, b"", "oversized-file"
            else:
                yield name, path.read_bytes(), None


def check(root: Path, *, staged: bool = False):
    findings, count = [], 0
    seen = set()
    for name, body, error in candidates(root, staged=staged):
        count += 1
        seen.add(name)
        findings.extend([{"file": name, "rule": error}] if error else scan_content(name, body))
    for required in {"config/environment.example.json", "config/deployment.example.json"} - seen:
        findings.append({"file": required, "rule": "missing-settings-template"})
    return {
        "status": "BLOCKED" if findings else "PASS",
        "files_checked": count,
        "findings": findings,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--staged", action="store_true", help="Inspect the exact Git index, not working copies"
    )
    args = parser.parse_args(argv)
    result = check(ROOT, staged=args.staged)
    print(json.dumps(result, indent=2))
    return 1 if result["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
