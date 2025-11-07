import requests

def check_info_disclosure(url):
    """
    Checks for common information disclosure issues
    such as debug info, stack traces, or sensitive data in responses.
    Returns a list of findings.
    """
    findings = []

    try:
        res = requests.get(url, timeout=5)
        content = res.text.lower()

        # Check for debug pages or stack traces
        debug_keywords = [
            "stack trace", "exception", "debug", "error occurred", "traceback",
            "warning", "notice", "undefined", "fatal error", "application error"
        ]
        for kw in debug_keywords:
            if kw in content:
                findings.append({
                    "type": "Information Disclosure",
                    "parameter": None,
                    "evidence": f"Found keyword '{kw}' in response",
                    "severity": "Medium",
                    "owasp_mapping": "A01:2021 – Broken Access Control",
                    "recommendation": "Disable detailed error messages and debug mode in production."
                })
                break

        # Check for sensitive server info
        if "server" in res.headers:
            server_info = res.headers.get("server", "")
            if any(s in server_info.lower() for s in ["apache", "nginx", "iis", "tomcat"]):
                findings.append({
                    "type": "Information Disclosure",
                    "parameter": "HTTP Header",
                    "evidence": f"Server header discloses technology: {server_info}",
                    "severity": "Low",
                    "owasp_mapping": "A05:2021 – Security Misconfiguration",
                    "recommendation": "Hide or modify the 'Server' header to reduce fingerprinting."
                })

    except Exception as e:
        pass  # don't break the main scan if one page fails

    return findings
