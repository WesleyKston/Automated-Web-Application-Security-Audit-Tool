# scanners/insecure_cookies.py
import requests

def check_insecure_cookies(url):
    findings = []
    try:
        response = requests.get(url, timeout=8, verify=False)
        cookies = response.cookies

        for cookie in cookies:
            if not cookie.secure:
                findings.append({
                    "type": "Insecure Cookie",
                    "parameter": cookie.name,
                    "evidence": f"Cookie '{cookie.name}' missing Secure flag",
                    "severity": "Medium",
                    "owasp_mapping": "A05:2021",
                    "recommendation": "Set the Secure flag for all session cookies."
                })
            # cookies from requests don't directly reveal HttpOnly — we can parse header manually
        set_cookie_headers = response.headers.get("Set-Cookie", "")
        if isinstance(set_cookie_headers, str):
            set_cookie_headers = [set_cookie_headers]

        for header in set_cookie_headers:
            if "HttpOnly" not in header:
                name = header.split("=")[0].strip()
                findings.append({
                    "type": "Insecure Cookie",
                    "parameter": name,
                    "evidence": f"Cookie '{name}' missing HttpOnly flag",
                    "severity": "Medium",
                    "owasp_mapping": "A05:2021",
                    "recommendation": "Add HttpOnly flag to prevent client-side access to cookies."
                })

    except Exception as e:
        pass

    return findings
