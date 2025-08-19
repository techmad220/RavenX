
from __future__ import annotations
from typing import Iterable, Set
from urllib.parse import urlparse

def load_targets(path: str) -> list[str]:
    seeds: list[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if s and not s.startswith("#"):
                seeds.append(s)
    return seeds

class Scope:
    def __init__(self, seeds: Iterable[str]):
        self.seeds = list(seeds)
        self.allowed_hosts: Set[str] = set()
        for s in seeds:
            try:
                host = urlparse(s).netloc.lower()
                if host: self.allowed_hosts.add(host)
            except Exception:
                pass

    def in_scope(self, url: str) -> bool:
        try:
            host = urlparse(url).netloc.lower()
        except Exception:
            return False
        if not host: return False
        if host in self.allowed_hosts:
            return True
        # wildcard-ish check
        for h in list(self.allowed_hosts):
            if h.startswith("*.") and host.endswith(h.replace("*.", "")):
                return True
            if h and h in host:
                return True
        return False

    @staticmethod
    def from_config(targets_file: str, cfg: dict) -> "Scope":
        seeds = load_targets(targets_file)
        sc = Scope(seeds)
        for h in (cfg.get("allow_hosts") or []):
            sc.allowed_hosts.add(h.lower())
        return sc
