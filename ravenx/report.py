
from __future__ import annotations
from typing import List
from .models import Finding

def render_markdown(findings: List[Finding]) -> str:
    lines = ["# RavenX Findings", ""]
    for f in findings:
        lines += [f"## [{f.severity.upper()}] {f.type}", f"- URL: {f.url}", "", "```", (f.evidence or "")[:2000], "```", ""]
    return "\n".join(lines)
