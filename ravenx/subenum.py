
from __future__ import annotations
from typing import Iterable, List, Set
import tldextract
import dns.resolver

def base_domains(seeds: Iterable[str]) -> Set[str]:
    out: Set[str] = set()
    for s in seeds:
        e = tldextract.extract(s)
        if e.registered_domain:
            out.add(e.registered_domain)
    return out

def wordlist_from_file(path: str) -> List[str]:
    words: List[str] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    words.append(s)
    except Exception:
        pass
    return list(dict.fromkeys(words))

def resolve_host(h: str) -> bool:
    try:
        dns.resolver.resolve(h, "A")
        return True
    except Exception:
        try:
            dns.resolver.resolve(h, "CNAME")
            return True
        except Exception:
            return False

def enumerate_subdomains(bases: Iterable[str], words: List[str], limit_per_base: int = 200) -> List[str]:
    found: List[str] = []
    for b in bases:
        cnt = 0
        for w in words:
            host = f"{w}.{b}"
            if resolve_host(host):
                found.append(host)
                cnt += 1
                if cnt >= limit_per_base:
                    break
    return found
