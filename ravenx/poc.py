
from __future__ import annotations
import os, pathlib
from typing import List
from .models import Finding

def generate_pocs(out_dir: str, findings: List[Finding]):
    cor_dir = os.path.join(out_dir, "pocs", "cors"); pathlib.Path(cor_dir).mkdir(parents=True, exist_ok=True)
    xss_dir = os.path.join(out_dir, "pocs", "xss"); pathlib.Path(xss_dir).mkdir(parents=True, exist_ok=True)
    for f in findings:
        if f.type == "cors_misconfiguration":
            fn = os.path.join(cor_dir, f.fingerprint[:16] + ".html")
            with open(fn, "w", encoding="utf-8") as h:
                h.write(f"""<!doctype html><meta charset="utf-8"><script>
fetch("{f.url}", {{credentials:"include"}}).then(r=>r.text()).then(t=>console.log("CORS read OK", t.slice(0,200)));
</script>""")
        if f.type.startswith("reflected_xss"):
            fn = os.path.join(xss_dir, f.fingerprint[:16] + ".md")
            with open(fn, "w", encoding="utf-8") as m:
                m.write(f"# Reflected XSS repro\n\nVisit: {f.url}\n\nToken should reflect in response.")
