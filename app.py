# app.py
import os
import sqlite3
import subprocess
import socket
import traceback
from datetime import datetime
from threading import Thread

import requests
from flask import Flask, jsonify, redirect, render_template, request, send_file

# local modules
from cli import run_scan
import db  # your db.py with create_scan, update_scan_finished, update_scan_status, get_findings_for_scan, init_db

app = Flask(__name__)
DB_PATH = "audit.db"

# Ensure DB is initialised (db.init_db should create tables / migrations)
try:
    db.init_db()
except Exception:
    # fallback: try to create DB with simple schema (defensive)
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            started TEXT,
            finished TEXT,
            status TEXT,
            score INTEGER
        );
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            page TEXT,
            type TEXT,
            parameter TEXT,
            evidence TEXT,
            severity TEXT,
            owasp_mapping TEXT,
            recommendation TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        """)
        conn.commit()
        conn.close()
    except Exception:
        traceback.print_exc()


# ---------- small helper ----------
def query_db(query, args=(), one=False):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(query, args)
    rows = cur.fetchall()
    conn.commit()
    conn.close()
    return (rows[0] if rows else None) if one else rows


def get_scans():
    return query_db("SELECT id, target, started, finished, score, status FROM scans ORDER BY id DESC")


# ---------- Background runner ----------
def run_scan_thread(scan_id, target):
    """
    Runs the scan in a background thread.
    run_scan in cli.py accepts scan_id optionally (we assume it does).
    It must write findings into DB using db.save_finding etc.
    After run_scan returns we mark scan finished.
    """
    try:
        # update status (defensive)
        try:
            db.update_scan_status(scan_id, "Running")
        except Exception:
            query_db("UPDATE scans SET status=? WHERE id=?", ("Running", scan_id))

        # run scan (the cli.run_scan function should accept scan_id or return results)
        try:
            # if your run_scan uses scan_id param it will use existing DB row
            run_scan(target, scan_id=scan_id, return_results=False)
        except TypeError:
            # older signature - fallback to run_scan(target) and not return results
            run_scan(target)

        # fetch score from DB (if run_scan updated it) or compute fallback
        row = query_db("SELECT score FROM scans WHERE id=?", (scan_id,), one=True)
        score = row[0] if row and row[0] is not None else 0

        # finalize
        try:
            db.update_scan_finished(scan_id, score)
        except Exception:
            query_db("UPDATE scans SET finished=?, score=?, status=? WHERE id=?", (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), score, "Completed", scan_id))

    except Exception as e:
        traceback.print_exc()
        # mark failed
        try:
            db.update_scan_status(scan_id, f"Failed: {str(e)}")
        except Exception:
            query_db("UPDATE scans SET status=? WHERE id=?", (f"Failed: {str(e)}", scan_id))


# ---------- Routes ----------
@app.route("/")
def index():
    scans = get_scans()
    return render_template("index.html", scans=scans)


@app.route("/scan", methods=["POST"])
def start_scan():
    """
    Start a new scan:
    - create a DB row (scan_id)
    - start background thread to run scan
    - return scan_id so the frontend can poll results
    """
    data = request.get_json() or {}
    target = data.get("target") or data.get("url") or ""

    if not target:
        return jsonify({"error": "No target provided"}), 400

    # create scan row
    started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        # Prefer using db.create_scan if available
        try:
            scan_id = db.create_scan(target, status="Running")
        except Exception:
            # fallback insert
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("INSERT INTO scans (target, started, status, score) VALUES (?, ?, ?, ?)",
                        (target, started, "Running", 0))
            scan_id = cur.lastrowid
            conn.commit()
            conn.close()
    except Exception:
        traceback.print_exc()
        return jsonify({"error": "Failed to create scan record"}), 500

    # start background thread
    t = Thread(target=run_scan_thread, args=(scan_id, target), daemon=True)
    t.start()

    return jsonify({
        "scan_id": scan_id,
        "target": target,
        "status": "Running",
    })


@app.route("/scan/result/<int:scan_id>")
def scan_result(scan_id):
    """
    Return scan status and findings (used by frontend to poll).
    """
    # fetch scan info
    row = query_db("SELECT target, score, status, started, finished FROM scans WHERE id=?", (scan_id,), one=True)
    if not row:
        return jsonify({"error": "Scan not found"}), 404

    target, score, status, started, finished = row

    # fetch findings from DB (prefer db.get_findings_for_scan)
    try:
        rows = db.get_findings_for_scan(scan_id)
    except Exception:
        rows = query_db("""SELECT page, type, parameter, evidence, severity, owasp_mapping, recommendation
                           FROM findings WHERE scan_id=?""", (scan_id,))

    findings = []
    for r in rows:
        # r expected: (page, type, parameter, evidence, severity, owasp_mapping, recommendation)
        findings.append({
            "page": r[0],
            "type": r[1],
            "parameter": r[2],
            "evidence": r[3],
            "severity": r[4],
            "owasp_mapping": r[5],
            "recommendation": r[6],
        })

    return jsonify({
        "scan_id": scan_id,
        "target": target,
        "score": score or 0,
        "status": status,
        "started": started,
        "finished": finished,
        "findings": findings,
    })


@app.route("/reports")
def reports():
    scans = get_scans()
    return render_template("reports.html", scans=scans)


@app.route("/report/<int:scan_id>")
def report(scan_id):
    """
    Generate report.pdf for given scan_id using report.py (existing).
    If ?view=1 is present, serve inline (mimetype application/pdf) otherwise as attachment.
    """
    view_mode = request.args.get("view")
    # call report.py with scan id
    try:
        subprocess.run(["python", "report.py", str(scan_id)], check=False)
    except Exception:
        traceback.print_exc()

    pdf_path = "report.pdf"
    if os.path.exists(pdf_path):
        if view_mode:
            return send_file(pdf_path, mimetype="application/pdf")
        else:
            return send_file(pdf_path, as_attachment=True)
    return "Report not found.", 404


@app.route("/delete/<int:scan_id>", methods=["DELETE"])
def delete_scan(scan_id):
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        cur.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
        conn.commit()
        conn.close()
        return jsonify({"status": "ok"})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


# ---------- Tools pages ----------
import whois

@app.route("/tools")
def tools_page():
    return render_template("tools.html")


@app.route("/tools/whois")
def tools_whois():
    domain = request.args.get("domain", "").strip()
    if not domain:
        return "No domain provided", 400
    try:
        w = whois.whois(domain)
        output = ""
        for key, value in w.items():
            output += f"{key}: {value}\n"
        return output if output else "No WHOIS record found."
    except Exception:
        traceback.print_exc()
        return "WHOIS lookup failed.", 500


@app.route("/tools/dns")
def tools_dns():
    domain = request.args.get("domain", "").strip()
    if not domain:
        return "No domain provided", 400
    try:
        answers = socket.getaddrinfo(domain, None)
        ips = sorted(set([a[4][0] for a in answers if a and a[4]]))
        return "\n".join(ips) if ips else "No DNS records found."
    except Exception:
        return "DNS lookup failed.", 500


@app.route("/tools/server")
def tools_server():
    url = request.args.get("url", "").strip()
    if not url:
        return "No URL provided", 400

    # Ensure URL has scheme
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    try:
        r = requests.get(url, timeout=6)
        if r.status_code >= 400:
            return f"Server returned error {r.status_code}."

        headers_text = "\n".join([f"{k}: {v}" for k, v in r.headers.items()])
        return headers_text or "No headers returned."
    except Exception:
        return "Server request failed.", 500



@app.route("/settings")
def settings():
    return render_template("settings.html")


# ---------- run ----------
if __name__ == "__main__":
    # dev server
    app.run(debug=True)
