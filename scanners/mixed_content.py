# scanners/mixed_content.py
import requests
import re

def check_mixed_content(url):
    findings = []
    try:
        if not url.startswith("https://"):
            return []  # Only relevant for HTTPS sites

        response = requests.get(url, timeout=8, verify=False)
        http_assets = re.findall(r'http://[^\s"\'<>]+', response.text)

        if http_assets:
            findings.append({
                "type": "Mixed Content",
                "parameter": None,
                "evidence": f"{len(http_assets)} insecure assets loaded over HTTP.",
                "severity": "Medium",
                "owasp_mapping": "A02:2021",
                "recommendation": "Ensure all assets (scripts, images, styles) are loaded via HTTPS."
            })
    except Exception:
        pass
    return findings
