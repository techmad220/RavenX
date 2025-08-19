
from __future__ import annotations
import asyncio
from typing import Dict, List
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
import os
from .models import Finding, fingerprint_of, host_of

async def run_param_miner(client, urls: List[str], max_params_per_host: int, wordlist: List[str]) -> Dict[str, Finding]:
    out: Dict[str, Finding] = {}
    add_count = {}
    async def probe(url: str, key: str):
        p = urlparse(url)
        q = dict(parse_qsl(p.query))
        if key in q: return
        q[key] = "pm123"
        test = urlunparse((p.scheme, p.netloc, p.path, "", urlencode(q, doseq=True), ""))
        try:
            r = await client.get(test, timeout=8.0)
            if "pm123" in (r.text or ""):
                evid = f"Reflected parameter '{key}' on {test}"
                f = Finding(severity="low", type="reflected_xss_param_probe", url=str(test), evidence=evid)
                out[f.fingerprint] = f
        except Exception:
            return

    tasks = []
    for u in urls:
        host = urlparse(u).netloc
        add_count.setdefault(host, 0)
        for w in wordlist:
            if add_count[host] >= max_params_per_host: break
            tasks.append(asyncio.create_task(probe(u, w)))
            add_count[host] += 1
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    return out


def load_wordlist(default: list[str], file_path: str | None) -> list[str]:
    if not file_path or not os.path.exists(file_path):
        return default
    words = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if s and not s.startswith("#"):
                words.append(s)
    return list(dict.fromkeys(words))  # dedupe preserving order
