
from __future__ import annotations
from typing import List, Dict, Optional, Tuple
import httpx, os, json, psutil, subprocess

def _vram_guess() -> int:
    try:
        out = subprocess.check_output(["nvidia-smi", "--query-gpu=memory.total", "--format=csv,noheader,nounits"], timeout=2).decode().strip()
        gb = int(out.splitlines()[0]) // 1024
        return gb
    except Exception:
        return int(os.getenv("RAVENX_VRAM_GB", "0"))

def ollama_chat(host: str, model: str, messages: List[Dict[str,str]], system: Optional[str]=None, temperature: float = 0.2, max_tokens: int = 2048) -> str:
    url = host.rstrip("/") + "/api/chat"
    body = {"model": model, "messages": ([{"role":"system","content":system}] if system else []) + messages, "options": {"temperature": temperature, "num_ctx": 8192}}
    with httpx.Client(timeout=60.0) as c:
        r = c.post(url, json=body)
        r.raise_for_status()
        data = r.json()
        # streaming or full
        if isinstance(data, dict) and "message" in data:
            return data["message"]["content"]
        if isinstance(data, list):
            return data[-1]["message"]["content"]
        return ""

def openai_chat(base_url: str, model: str, messages: List[Dict[str,str]], system: Optional[str]=None, temperature: float = 0.2, max_tokens: int = 2048) -> str:
    key = os.getenv("OPENAI_API_KEY", "")
    headers = {"Content-Type":"application/json"}
    if key: headers["Authorization"] = f"Bearer {key}"
    body = {"model": model, "messages": ([{"role":"system","content":system}] if system else []) + messages, "temperature": temperature, "max_tokens": max_tokens}
    with httpx.Client(timeout=60.0) as c:
        r = c.post(base_url.rstrip("/") + "/chat/completions", json=body, headers=headers)
        r.raise_for_status()
        data = r.json()
        return data["choices"][0]["message"]["content"]

class ModelSpec:
    def __init__(self, name: str, provider: str, pref: int):
        self.name=name; self.provider=provider; self.pref=pref

def choose_models(bias: List[str]) -> List[ModelSpec]:
    # simple preference ordering
    prefs = []
    if "deepseek" in ",".join(bias): prefs.append(ModelSpec("deepseek-r1:7b", "ollama", 9))
    prefs.append(ModelSpec("llama3.1:8b", "ollama", 7))
    prefs.append(ModelSpec("qwen2.5:14b", "ollama", 6))
    return prefs

def chat_route(task: str, messages: List[Dict[str,str]], bias: List[str], ollama_host: str, system: Optional[str]=None, max_tokens: int = 2048, openai_base_url: Optional[str]=None, openai_model: Optional[str]=None) -> Tuple[str, str]:
    # prefer local
    for spec in choose_models(bias):
        try:
            if spec.provider == "ollama":
                txt = ollama_chat(ollama_host, spec.name, messages, system=system, max_tokens=max_tokens)
                return (f"ollama:{spec.name}", txt)
        except Exception as e:
            continue
    # fallback to OpenAI-compatible (e.g., GLM via vLLM)
    if openai_base_url and openai_model:
        txt = openai_chat(openai_base_url, openai_model, messages, system=system, max_tokens=max_tokens)
        return (f"openai:{openai_model}", txt)
    # last resort: deterministic string
    return ("rule-based", "no-llm")
