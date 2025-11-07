import requests
from html import escape

def check_xss(url, params):
    payload = "<script>alert('xss')</script>"
    findings = []
    for key in params:
        test_params = params.copy()
        test_params[key] = payload
        try:
            r = requests.get(url, params=test_params, timeout=5)
            if payload in r.text:
                findings.append({
                    "type": "Reflected XSS",
                    "parameter": key,
                    "evidence": f"Payload reflected in response",
                    "severity": "High",
                    "owasp_mapping": "A03:2021",
                    "recommendation": "Escape user input before rendering"
                })
        except:
            continue
    return findings
