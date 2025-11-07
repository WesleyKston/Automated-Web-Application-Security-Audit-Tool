import requests

def check_security_headers(url):
    try:
        r = requests.get(url, timeout=5)
    except:
        return []
    findings = []
    headers = r.headers

    expected = {
        "Content-Security-Policy": "High",
        "X-Frame-Options": "Medium",
        "Strict-Transport-Security": "High",
        "X-Content-Type-Options": "Medium"
    }

    for h, sev in expected.items():
        if h not in headers:
            findings.append({
                "type": "Missing Header",
                "parameter": h,
                "evidence": f"{h} not set",
                "severity": sev,
                "owasp_mapping": "A05:2021",
                "recommendation": f"Add {h} header"
            })
    return findings
