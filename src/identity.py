"""Destination-scoped, signed identities. Labels alone never authorize adoption."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass

PROPERTY_KEY = "security-automation-v2"


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


@dataclass(frozen=True)
class Identity:
    origin: str
    project_id: str
    source: str
    repository: str
    finding_id: str = ""
    schema: int = 2

    @property
    def fingerprint(self) -> str:
        return digest(asdict(self))[:32]

    @property
    def label(self) -> str:
        kind = "finding" if self.finding_id else "campaign"
        return f"{self.source}-{kind}-v2-{self.fingerprint}"

    def signed(self, key: str, details: dict | None = None) -> dict:
        value = {"identity": asdict(self), **(details or {})}
        signature = hmac.new(key.encode(), canonical(value).encode(), hashlib.sha256).hexdigest()
        return {**value, "signature": signature}

    def matches(self, value: object, key: str) -> bool:
        if not isinstance(value, dict) or value.get("identity") != asdict(self):
            return False
        signature = value.get("signature")
        unsigned = {k: v for k, v in value.items() if k != "signature"}
        expected = hmac.new(key.encode(), canonical(unsigned).encode(), hashlib.sha256).hexdigest()
        return isinstance(signature, str) and hmac.compare_digest(signature, expected)
