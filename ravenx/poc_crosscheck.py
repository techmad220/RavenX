
from __future__ import annotations
from typing import List, Dict, Any, Tuple
import os, json, hashlib, re
from .llm import chat_route
from .models import Finding

GEN_PROMPT = (
    "You are a security engineer. Given a finding, produce STRICT JSON with keys: "
    "{class: one of [xss, open_redirect, cors, csrf, header, sso, oauth, saml, takeover, mixed, jsonp, other], "
    "poc: a minimal reproducible PoC using ONLY curl or a GET URL, "
    "explain: one sentence why it works}. No markdown."
)

VERIFY_PROMPT = (
    "You are validating an exploit PoC. Given the finding and a PoC JSON, "
    "respond STRICT JSON {valid: true|false, reason: short}. No markdown."
)

def _normalize(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"\s+", " ", s)
    return s

def _hash(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()[:12]

def coder_generate_poc(f: Finding, provider: str, model: str, ollama_host: str, base_url: str | None = None) -> Dict[str, Any]:
    messages = [{"role":"user","content": f"{f.type}|{f.severity}|{f.url}|{(f.evidence or '')[:600]}"}]
    prov, txt = chat_route("genpoc", messages, [], ollama_host, system=GEN_PROMPT, max_tokens=600,
                           openai_base_url=base_url if provider=='openai' else None,
                           openai_model=model if provider=='openai' else None)
    try:
        data = json.loads(txt)
    except Exception:
        data = {"class":"other","poc":txt[:800],"explain":"parse_error"}
    data["_model"] = f"{provider}:{model}"
    data["_norm"] = _normalize(json.dumps(data, sort_keys=True))
    data["_sha"] = _hash(data["_norm"])
    return data

def coder_verify_poc(f: Finding, poc_json: Dict[str, Any], provider: str, model: str, ollama_host: str, base_url: str | None = None) -> Dict[str, Any]:
    messages = [{"role":"user","content": json.dumps({"finding": f.to_dict(), "poc": poc_json})[:2000]}]
    prov, txt = chat_route("verifypoc", messages, [], ollama_host, system=VERIFY_PROMPT, max_tokens=300,
                           openai_base_url=base_url if provider=='openai' else None,
                           openai_model=model if provider=='openai' else None)
    try:
        data = json.loads(txt)
    except Exception:
        data = {"valid": False, "reason": "parse_error"}
    data["_model"] = f"{provider}:{model}"
    return data

def crosscheck(findings: List[Finding], coder_specs: List[Dict[str,str]], ollama_host: str, openai_default: Tuple[str,str] | None, out_dir: str) -> Dict[str, Any]:
    os.makedirs(out_dir, exist_ok=True)
    results = []
    for f in findings:
        if (f.severity or "low").lower() not in ("critical","high","medium"):
            continue
        gens = []
        for spec in coder_specs:
            provider = spec.get("provider","ollama")
            model = spec.get("model")
            base_url = spec.get("base_url")
            if provider == "openai" and base_url is None and openai_default:
                base_url, model = openai_default
            try:
                g = coder_generate_poc(f, provider, model, ollama_host, base_url=base_url)
                gens.append(g)
            except Exception as e:
                gens.append({"_model": f"{provider}:{model}", "error": str(e)})
        # Pairwise compare first two coder outputs
        verdict = {"agree": False, "why": "insufficient"}
        if len(gens) >= 2 and gens[0].get("_sha") and gens[1].get("_sha"):
            same_class = gens[0].get("class") == gens[1].get("class")
            same_hash = gens[0]["_sha"] == gens[1]["_sha"]
            if same_class or same_hash:
                verdict = {"agree": True, "why": "class_match" if same_class else "hash_match"}
        # Optional: verifying step by opposite coder
        verifications = []
        try:
            v1 = coder_verify_poc(f, gens[0], coder_specs[1].get("provider","ollama"), coder_specs[1].get("model"), ollama_host, base_url=coder_specs[1].get("base_url"))
            v2 = coder_verify_poc(f, gens[1], coder_specs[0].get("provider","ollama"), coder_specs[0].get("model"), ollama_host, base_url=coder_specs[0].get("base_url"))
            verifications = [v1, v2]
            if all(v.get("valid") for v in verifications):
                verdict = {"agree": True, "why": "mutual_verify"}
        except Exception:
            pass
        # Save artifacts
        fp = f"{f.type}-{_hash(f.url)}"
        with open(os.path.join(out_dir, f"{fp}.json"), "w", encoding="utf-8") as jf:
            json.dump({"finding": f.to_dict(), "gens": gens, "verify": verifications, "verdict": verdict}, jf, indent=2)
        results.append({"finding": f.to_dict(), "gens": gens, "verify": verifications, "verdict": verdict, "artifact": f"{fp}.json"})
    # Write index
    with open(os.path.join(out_dir, "_index.json"), "w", encoding="utf-8") as idx:
        json.dump(results, idx, indent=2)
    return {"count": len(results), "dir": out_dir}
