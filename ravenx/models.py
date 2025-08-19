
from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Optional, Dict
import hashlib, time, urllib.parse as up

SEVERITY_ORDER = {"low":1, "medium":2, "high":3, "critical":4}

def now_ms() -> int:
    return int(time.time() * 1000)

def host_of(url: str) -> str:
    try:
        return up.urlparse(url).netloc.lower()
    except Exception:
        return ""

def fingerprint_of(sev: str, typ: str, host: str, url: str, evidence: str) -> str:
    m = hashlib.sha256()
    m.update((sev or "").encode())
    m.update((typ or "").encode())
    m.update((host or "").encode())
    m.update((url or "").encode())
    m.update((evidence or "")[:512].encode())
    return m.hexdigest()

class Finding(BaseModel):
    severity: str = Field(default="low")
    type: str = Field(default="unknown")
    url: str = Field(default="")
    evidence: str = Field(default="")
    fingerprint: str = Field(default_factory=lambda: "")
    first_seen_ms: int = Field(default_factory=now_ms)
    validated_ms: int = Field(default_factory=now_ms)
    method: Optional[str] = None
    impact: Optional[str] = None

    def to_dict(self) -> Dict:
        return self.model_dump()

    @staticmethod
    def from_dict(d: dict) -> "Finding":
        fp = d.get("fingerprint")
        if not fp:
            fp = fingerprint_of(d.get("severity","low"), d.get("type","unknown"), host_of(d.get("url","")), d.get("url",""), d.get("evidence",""))
        return Finding(
            severity=d.get("severity","low"),
            type=d.get("type","unknown"),
            url=d.get("url",""),
            evidence=d.get("evidence",""),
            fingerprint=fp,
            first_seen_ms=d.get("first_seen_ms") or now_ms(),
            validated_ms=d.get("validated_ms") or now_ms(),
            method=d.get("method"),
            impact=d.get("impact"),
        )
