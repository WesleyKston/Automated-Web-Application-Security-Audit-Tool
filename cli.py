import traceback
from urllib.parse import urlparse, parse_qs
from crawler import crawl
from db import (
    init_db,
    create_scan,
    save_finding,
    update_scan_finished,
    update_scan_status,
    get_findings_for_scan,
)

# Import scanners (existing ones)
from scanners.headers import check_security_headers
from scanners.sql_injection import check_sql_injection
from scanners.xss import check_xss
from scanners.insecure_cookies import check_insecure_cookies
from scanners.mixed_content import check_mixed_content
from scanners.open_redirect import check_open_redirect
from scanners.info_disclosure_scan import check_info_disclosure


# ============================================================
# SMART SECURITY SCORING LOGIC
# ============================================================
def calculate_security_score(scan_id):
    findings = get_findings_for_scan(scan_id)
    if not findings:
        return 100

    severity_weights = {
        "Critical": 40,
        "High": 25,
        "Medium": 15,
        "Low": 5,
        "Info": 2,
    }

    total_deduction = 0
    has_high = False
    has_critical = False

    for f in findings:
        severity = (f[4] or "Low").capitalize().strip()
        owasp = (f[5] or "").upper().strip()
        base = severity_weights.get(severity, 10)
        bonus = 0

        # OWASP-based extra deduction
        if "A0" in owasp:
            try:
                num = int(owasp[2:4])
                if 1 <= num <= 5:
                    bonus = 10
                elif 6 <= num <= 10:
                    bonus = 5
            except Exception:
                pass

        total_deduction += base + bonus

        if severity == "High":
            has_high = True
        elif severity == "Critical":
            has_critical = True

    # Additional scaling rules
    complexity_penalty = 5 if len(findings) > 10 else 0
    safety_bonus = 10 if not (has_high or has_critical) else 0

    score = 100 - total_deduction - complexity_penalty + safety_bonus
    score = max(10, min(100, score))  # cap between 10 and 100

    return int(score)


# ============================================================
# MAIN SCAN FUNCTION
# ============================================================
def get_query_params(url):
    parsed = urlparse(url)
    raw = parse_qs(parsed.query)
    return {k: (v[0] if isinstance(v, list) and v else "") for k, v in raw.items()}


def run_scan(target, scan_id=None, return_results=False):
    print(f"[DEBUG] Starting scan for {target}")
    init_db()

    if scan_id is None:
        scan_id = create_scan(target, status="Running")
    else:
        update_scan_status(scan_id, "Running")

    findings_out = []

    try:
        try:
            pages = crawl(target)
            if not pages:
                pages = [{"url": target}]
            print(f"[DEBUG] Crawled {len(pages)} pages")
        except Exception as e:
            print("[ERROR] Crawler failed:", e)
            traceback.print_exc()
            pages = [{"url": target}]

        MAX_PAGES = 10
        pages = pages[:MAX_PAGES]

        for page in pages:
            url = page.get("url")
            if not url:
                continue

            print(f"[DEBUG] Scanning page: {url}")

            # --- Passive Scans ---
            all_passive = []
            try:
                all_passive += check_security_headers(url) or []
                all_passive += check_insecure_cookies(url) or []
                all_passive += check_mixed_content(url) or []
                all_passive += check_info_disclosure(url) or []
            except Exception as e:
                print("[ERROR] Passive scan error:", e)
                traceback.print_exc()

            for f in all_passive:
                f_type = f.get("type", "Unknown")
                param = f.get("parameter", None)
                evidence = f.get("evidence", "")
                severity = f.get("severity", "Medium")
                owasp = f.get("owasp_mapping", "A05:2021")
                rec = f.get("recommendation", "")

                save_finding(scan_id, url, f_type, param, evidence, severity, owasp, rec)
                findings_out.append(f)

            # --- Active Scans ---
            params = get_query_params(url)
            if params:
                try:
                    sqli = check_sql_injection(url, params) or []
                    xss = check_xss(url, params) or []
                    redirects = check_open_redirect(url, params) or []
                except Exception as e:
                    print("[ERROR] Active scan error:", e)
                    traceback.print_exc()
                    sqli, xss, redirects = [], [], []

                for f in (sqli + xss + redirects):
                    f_type = f.get("type", "Unknown")
                    param = f.get("parameter", None)
                    evidence = f.get("evidence", "")
                    severity = f.get("severity", "High")
                    owasp = f.get("owasp_mapping", "A01:2021")
                    rec = f.get("recommendation", "")

                    save_finding(scan_id, url, f_type, param, evidence, severity, owasp, rec)
                    findings_out.append(f)

        # Compute improved score
        score = calculate_security_score(scan_id)
        update_scan_finished(scan_id, score)
        print(f"[DEBUG] Scan completed for {target}. Final score: {score}/100")

    except Exception as e:
        print("[FATAL] Scan failed:", e)
        traceback.print_exc()
        update_scan_status(scan_id, "Failed")

    if return_results:
        rows = get_findings_for_scan(scan_id)
        findings_list = []
        for r in rows:
            findings_list.append({
                "page": r[0],
                "type": r[1],
                "parameter": r[2],
                "evidence": r[3],
                "severity": r[4],
                "owasp_mapping": r[5],
                "recommendation": r[6],
            })
        return findings_list, score

    return None


# ============================================================
# CLI ENTRY POINT
# ============================================================
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python cli.py <target_url>")
    else:
        run_scan(sys.argv[1], return_results=False)
