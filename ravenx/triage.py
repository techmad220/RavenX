
from __future__ import annotations
from typing import List, Dict, Any
from .models import Finding, SEVERITY_ORDER
from .llm import chat_route

SYSTEM_PROMPT = "You are a security triage assistant. Rank findings by severity and deduplicate. Output JSON list with keys: severity, type, url, evidence, fingerprint."

def rule_based(findings: List[Finding]) -> List[dict]:
    # group by fingerprint (already uniq), bump severity for certain types
    bump = {"cors_misconfiguration":"high", "open_redirect_param":"medium", "reflected_xss_param_probe":"high"}
    outs = []
    for f in findings:
        sev = bump.get(f.type, f.severity)
        outs.append({"provider":"rule", "finding": f.to_dict() | {"severity": sev}})
    return outs

def llm_triage(findings: List[Finding], bias: list[str], ollama_host: str, max_tokens: int = 2000, openai_base_url: str | None = None, openai_model: str | None = None) -> List[Dict[str, Any]]:
    if not findings:
        return []
    user = "\n".join([f"{x.severity}|{x.type}|{x.url}|{(x.evidence or '')[:200]}" for x in findings][:50])
    provider, txt = chat_route("triage", [{"role":"user","content": user}], bias, ollama_host, system=SYSTEM_PROMPT, max_tokens=max_tokens, openai_base_url=openai_base_url, openai_model=openai_model)
    if provider.startswith("ollama") or provider.startswith("openai"):
        try:
            import json as _json
            data = _json.loads(txt)
            out = [{"provider": provider, "finding": d} for d in data]
            return out
        except Exception:
            pass
    return rule_based(findings)
