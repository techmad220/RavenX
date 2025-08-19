
from __future__ import annotations
from collections import Counter
from .models import Finding

def write_summary(findings: list[Finding], path: str):
    sev = Counter(f.severity for f in findings)
    ty = Counter(f.type for f in findings)
    lines = ["# RavenX Summary", "", "## Severities"]
    for k in ("critical","high","medium","low"):
        if sev.get(k): lines.append(f"- {k}: {sev[k]}")
    lines += ["", "## Top Types"]
    for t, c in ty.most_common(10):
        lines.append(f"- {t}: {c}")
    open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
