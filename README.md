# Advanced Security Scanner - All-in-One Tool

## 🔒 Project Overview

An educational cybersecurity tool that combines keystroke logging capabilities with comprehensive network vulnerability scanning. Designed for learning penetration testing techniques and understanding security vulnerabilities.

**Version:** 1.0.0
**Status:** Development
**License:** MIT

---

## ⚠️ DISCLAIMER

This tool is for **educational purposes and authorized penetration testing only**. Unauthorized access to computer systems is illegal. Users are solely responsible for ensuring they have proper authorization before using this tool on any system.

---

## 📋 Features

### 1. Network Port Scanning
- Scans target IP addresses for open ports (1-1024)
- Identifies active network services
- Supports both IP addresses and hostnames

### 2. Service Banner Grabbing
- Captures service banners from open ports
- Identifies service versions
- Helps in vulnerability assessment

### 3. Vulnerability Detection
- Detects known vulnerable services
- Maps to CVE (Common Vulnerabilities and Exposures)
- Provides severity ratings (CRITICAL, HIGH, MEDIUM, LOW)

### 4. Professional Reporting
- JSON format scan reports
- Comprehensive vulnerability summaries
- Risk assessment and recommendations

---

## 🛠️ Installation & Setup

### Prerequisites

- Python 3.7 or higher
- pip (Python package manager)
- Git

### Step 1: Clone the Repository

git clone https://github.com/MhdAsfan/keylogger-scanner.git
cd keylogger-scanner

text

### Step 2: Install Dependencies

pip install -r requirements.txt

text

### Step 3: Run the Scanner

python security_scanner.py 192.168.1.1

text

---

## 🚀 Usage Guide

### Basic Port Scanning

Scan a specific IP address
python security_scanner.py 192.168.1.1

Scan a hostname
python security_scanner.py example.com

text

### Understanding Output

[+] Port 80 is OPEN
[+] Port 443 is OPEN
[+] Port 3306 is OPEN
[!] Port 3306 (MySQL) - Severity: HIGH

text

### Generated Reports

After each scan, a JSON report is generated: `scan_report.json`

---

## 📊 Vulnerability Database

The scanner checks against these known vulnerable services:

| Port | Service | Severity |
|------|---------|----------|
| 21 | FTP | HIGH |
| 23 | TELNET | CRITICAL |
| 445 | SMB | CRITICAL |
| 3306 | MySQL | HIGH |
| 5984 | CouchDB | CRITICAL |
| 27017 | MongoDB | CRITICAL |

---

## 🔐 Security Considerations

### Ethical Guidelines

- ✅ Use on systems you own or have explicit written permission
- ✅ Test in isolated lab environments
- ✅ Document all findings responsibly
- ❌ Never use on production systems without authorization
- ❌ Don't distribute tools to unauthorized users

---

## 📚 Learning Resources

- OWASP Top 10
- TryHackMe
- HackTheBox
- OverTheWire

---

## 📝 License

This project is licensed under the MIT License

---

**Last Updated:** 2025-11-05
**Educational Purpose Only**

