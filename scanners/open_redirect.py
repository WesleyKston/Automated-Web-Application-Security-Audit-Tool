# scanners/open_redirect.py
import requests
from urllib.parse import urlparse, urlencode

def check_open_redirect(url, params):
    findings = []
    redirect_keywords = ["url", "redirect", "next", "dest", "return"]

    for param, value in params.items():
        if any(k in param.lower() for k in redirect_keywords):
            evil_url = "https://evil.example.com"
            test_params = params.copy()
            test_params[param] = evil_url
            try:
                r = requests.get(url, params=test_params, allow_redirects=False, timeout=8)
                loc = r.headers.get("Location", "")
                if evil_url in loc:
                    findings.append({
                        "type": "Open Redirect",
                        "parameter": param,
                        "evidence": f"Redirects to attacker-controlled site via '{param}'",
                        "severity": "High",
                        "owasp_mapping": "A01:2021",
                        "recommendation": "Validate and whitelist redirect parameters."
                    })
            except Exception:
                continue

    return findings
