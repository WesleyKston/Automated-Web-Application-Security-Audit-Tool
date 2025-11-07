# Automated Web Application Security Audit Tool

This project is designed to automatically analyze web applications for common security vulnerabilities and generate clear audit reports. It supports scanning for OWASP Top 10 risks, assigns severity-based scores, and provides actionable remediation recommendations for each finding.




## 🔍 Overview

Modern web applications frequently handle sensitive data, making security testing essential. However, manual security analysis is time-consuming and prone to oversight. This tool automates the vulnerability scanning process and assists developers, auditors, and IT teams in identifying weaknesses early.

The tool performs:

- Automated scanning
- Vulnerability detection
- Risk scoring
- Report generation (PDF format)

---

## ✨ Key Features

| Feature | Description |
|--------|-------------|
| **Automated Scanning** | Crawls and scans web targets automatically |
| **OWASP Security Checks** | Detects high-risk vulnerabilities from OWASP Top-10 |
| **Severity Score Calculation** | Computes overall security score (0-100) |
| **Detailed Findings Table** | Displays vulnerabilities with severity tags |
| **PDF Report Generator** | One-click report export with charts & summaries |
| **Built-in Tools** | WHOIS, DNS Lookup, Server Info Fetch |
| **Simple Dashboard UI** | Clean and user-friendly interface |

---

## 🛡️ Vulnerabilities Detected

| Category | Examples |
|---------|----------|
| **Injection Attacks** | SQL Injection, Reflected XSS |
| **Security Misconfiguration** | Missing security headers, exposed server info |
| **Insecure Cookies** | Missing `Secure` / `HttpOnly` flags |
| **Open Redirects** | Incorrect redirect parameter validation |
| **Mixed Content** | HTTP resources loaded over HTTPS |


---

## 🛠️ Tech Stack

| Component | Technology Used |
|----------|----------------|
| Backend | Python (Flask) |
| Frontend | HTML, TailwindCSS, Chart.js |
| Database | SQLite |
| Reporting | ReportLab PDF Engine |

---

## 🚀 Installation & Usage

```bash
# Clone the repository
git clone https://github.com/YourUsername/Automated-Web-Application-Security-Audit-Tool.git
cd Automated-Web-Application-Security-Audit-Tool

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py

#Then open:
http://127.0.0.1:5000



