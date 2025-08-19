
from __future__ import annotations

WEAKNESS_MAP = {
    "security_headers_missing": "CWE-693",
    "cors_misconfiguration": "CWE-284",
    "cookie_flags_missing": "CWE-614",
    "dir_listing": "CWE-548",
    "reflected_xss_probe": "CWE-79",
    "reflected_xss_param_probe": "CWE-79",
    "open_redirect_param": "CWE-601",
    "csrf_missing_token": "CWE-352",
}

def guess_cwe(check_type: str):
    return WEAKNESS_MAP.get(check_type)
