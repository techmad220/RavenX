
from __future__ import annotations
from typing import List, Dict, Any, Tuple
from .models import Finding, SEVERITY_ORDER
from .llm import chat_route

VOTE_PROMPT = (
    "You are one expert in a panel of security reviewers. "
    "Given a candidate web security finding, return STRICT JSON with keys: "
    "{severity: one of [none,low,medium,high,critical], confidence: 0-1, rationale: short, "
    "evidence_hint: short text of what to verify (reflection string, header, redirect target).}"
)

SUGGEST_PROMPT = (
    "You are a web bug hunter. Given a list of visited URLs for the same site, "
    "propose up to 15 likely GET parameter names to try for discovering reflected "
    "parameters, open redirects, and auth/OAuth issues. Return STRICT JSON array of strings."
)

def _vote_to_rank(sev: str) -> int:
    return SEVERITY_ORDER.get((sev or 'low').lower(), 0)

def run_panel_votes(findings: List[Finding], bias: List[str], ollama_host: str, models: List[Dict[str, str]], agree: int = 2, openai_fallback: Tuple[str,str] | None = None) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for f in findings:
        messages = [{"role":"user","content": f"{f.severity}|{f.type}|{f.url}|{(f.evidence or '')[:400]}"}]
        votes = []
        for spec in models:
            provider = spec.get("provider","ollama")
            model = spec.get("model")
            base_url = spec.get("base_url")
            try:
                prov, txt = chat_route("vote", messages, bias, ollama_host, system=VOTE_PROMPT, max_tokens=400, openai_base_url=base_url if provider=='openai' else None, openai_model=model if provider=='openai' else None)
                import json as _json
                v = _json.loads(txt)
                sev = str(v.get("severity","low")).lower()
                conf = float(v.get("confidence", 0.5))
                votes.append({"model": f"{provider}:{model}", "severity": sev, "confidence": conf, "rationale": v.get("rationale",""), "evidence_hint": v.get("evidence_hint","")})
            except Exception as e:
                votes.append({"model": f"{provider}:{model}", "error": str(e)})
                continue
        # Decision: pick majority of >= medium if count >= agree, else keep original
        tallies = {}
        for v in votes:
            sev = v.get("severity","low")
            tallies[sev] = tallies.get(sev, 0) + 1
        decision = f.severity
        # prioritize higher severities if they reach 'agree' threshold
        for sev in ["critical","high","medium"]:
            if tallies.get(sev, 0) >= agree:
                decision = sev
                break
        results.append({"finding": f.to_dict(), "panel": {"votes": votes, "decision": decision, "tally": tallies}})
    return results

def panel_suggest_params(visited: List[str], bias: List[str], ollama_host: str, models: List[Dict[str,str]]) -> List[str]:
    # sample up to 40 visited URLs for context
    sample = visited[:40]
    joined = "\n".join(sample)
    messages = [{"role":"user", "content": joined}]
    params: List[str] = []
    for spec in models:
        provider = spec.get("provider","ollama")
        model = spec.get("model")
        base_url = spec.get("base_url")
        try:
            prov, txt = chat_route("suggest", messages, bias, ollama_host, system=SUGGEST_PROMPT, max_tokens=400, openai_base_url=base_url if provider=='openai' else None, openai_model=model if provider=='openai' else None)
            import json as _json
            arr = _json.loads(txt)
            if isinstance(arr, list):
                for k in arr:
                    if isinstance(k, str) and 1 <= len(k) <= 30:
                        params.append(k.strip())
        except Exception:
            continue
    # dedupe, simple normalization
    norm = []
    seen = set()
    for k in params:
        kk = k.lower().strip()
        if kk and kk not in seen:
            seen.add(kk); norm.append(kk)
    return norm[:60]


# --- Sequential, conversation-style panel ---
TURN_PROMPT = (
    "You are part of a panel of web security experts taking turns. "
    "Read the case and the prior experts' notes. Respond in STRICT JSON: "
    "{severity:[none,low,medium,high,critical], confidence:0-1, rationale:'short', "
    "evidence_hint:'short'}. Keep it concise and grounded."
)

def _alias_to_spec(spec: dict) -> dict:
    # Allow 'alias: oss20b' to map to an env-configured model, defaulting to a solid OSS mid-size.
    if spec.get("alias") == "oss20b":
        m = os.getenv("OSS20B_MODEL", "").strip()
        if not m:
            # default fallback that runs on 16GB—swap if user provides env
            m = "qwen2.5:14b"
        return {"provider": spec.get("provider","ollama"), "model": m, "base_url": spec.get("base_url")}
    return spec

def run_panel_sequential(findings: List[Finding], bias: List[str], ollama_host: str, models: List[Dict[str,str]], openai_default: Tuple[str,str] | None = None) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    ordered = [_alias_to_spec(m) for m in models]
    for f in findings:
        # build a transcript of turns
        transcript = [{
            "role":"system",
            "content": TURN_PROMPT + " Case: " + f"{f.severity}|{f.type}|{f.url}|{(f.evidence or '')[:400]}"
        }]
        votes = []
        for spec in ordered:
            provider = spec.get("provider","ollama")
            model = spec.get("model")
            base_url = spec.get("base_url")
            try:
                prov, txt = chat_route(
                    "panel-turn",
                    [{"role":"user","content":"Consider prior notes and give your JSON verdict."}],
                    bias, ollama_host,
                    system=None,
                    max_tokens=450,
                    openai_base_url=base_url if provider=='openai' else None,
                    openai_model=model if provider=='openai' else None
                )
                import json as _json
                v = _json.loads(txt)
                sev = str(v.get("severity","low")).lower()
                conf = float(v.get("confidence", 0.5))
                entry = {"model": f"{provider}:{model}", "severity": sev, "confidence": conf, "rationale": v.get("rationale",""), "evidence_hint": v.get("evidence_hint","")}
                votes.append(entry)
                # Append concise note to transcript for the next model
                transcript.append({"role":"user", "content": f"{entry}"})
            except Exception as e:
                votes.append({"model": f"{provider}:{model}", "error": str(e)})
                transcript.append({"role":"user","content": f"model_error:{e}"})
                continue
        # Final decision: prefer the last agreeing higher-severity if at least two turns converged
        tallies = {}
        for v in votes:
            sev = v.get("severity","low")
            tallies[sev] = tallies.get(sev, 0) + 1
        decision = f.severity
        for sev in ["critical","high","medium"]:
            if tallies.get(sev,0) >= 2:
                decision = sev
                break
        results.append({"finding": f.to_dict(), "panel": {"mode":"sequential", "turns": votes, "decision": decision, "tally": tallies}})
    return results
