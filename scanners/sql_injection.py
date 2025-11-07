import requests

def check_sql_injection(url, params):
    payloads = ["' OR '1'='1", "';--", "\" OR \"1\"=\"1"]
    findings = []
    for key in params:
        for p in payloads:
            test_params = params.copy()
            test_params[key] = p
            try:
                r = requests.get(url, params=test_params, timeout=5)
                if "sql" in r.text.lower() or "syntax" in r.text.lower():
                    findings.append({
                        "type": "SQL Injection",
                        "parameter": key,
                        "evidence": f"Payload {p} caused SQL error",
                        "severity": "High",
                        "owasp_mapping": "A01:2021",
                        "recommendation": "Use parameterized queries"
                    })
            except:
                continue
    return findings
