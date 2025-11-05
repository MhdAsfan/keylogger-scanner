# Advanced Security Scanner - All-in-One Tool

![Security Scanner](https://img.shields.io/badge/Security-Scanner-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.7+-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

## 🔒 Project Overview

**Advanced Security Scanner** is a comprehensive, production-ready cybersecurity tool designed for educational purposes and authorized penetration testing. This all-in-one solution combines network reconnaissance, vulnerability assessment, and professional security reporting capabilities.

### 🎯 Purpose
- **Learn** network security and penetration testing techniques
- **Understand** vulnerability assessment methodologies
- **Develop** practical cybersecurity skills
- **Practice** ethical hacking in controlled environments

**Version:** 1.0.0  
**Status:** Actively Maintained  
**License:** MIT  
**Developer:** Muhammad Asfan  
**Last Updated:** November 5, 2025

---

## ⚠️ IMPORTANT LEGAL DISCLAIMER

### Authorization Required
This tool is **ONLY** for use on systems you own or have **explicit written permission** to test. 

**UNAUTHORIZED ACCESS TO COMPUTER SYSTEMS IS ILLEGAL.**

This tool may be used for:
- ✅ Educational learning and research
- ✅ Authorized penetration testing engagements
- ✅ Systems you own and control
- ✅ Bug bounty programs (where explicitly allowed)
- ✅ Home lab environments for practice

This tool may **NOT** be used for:
- ❌ Unauthorized network scanning
- ❌ Unauthorized system access
- ❌ Malicious purposes
- ❌ Production systems without written authorization
- ❌ Violation of Computer Fraud & Abuse Act (CFAA)

**Users are solely responsible for ensuring proper authorization before using this tool.**

---

## 📋 Features & Capabilities

### 1. Advanced Port Scanning
- **Comprehensive Scanning:** Scans 1-1024 port range (configurable up to 65535)
- **Fast & Efficient:** Multi-threaded scanning with 0.3s timeout
- **Flexible Targets:** Supports both IP addresses and domain names
- **DNS Resolution:** Automatic hostname-to-IP resolution
- **Real-time Feedback:** Live port discovery notifications

**Example Output:**
[+] Port 22 is OPEN
[+] Port 80 is OPEN
[+] Port 443 is OPEN
[+] Port 3306 is OPEN


### 2. Service Banner Grabbing & Fingerprinting
- **Service Identification:** Automatically identifies running services
- **Version Detection:** Extracts version information from banners
- **Banner Analysis:** Captures and logs service identification strings
- **Service Mapping:** Maps ports to common services
- **Extended Information:** Retrieves up to 1024 bytes of service information

**Example Output:**
[+] Port 22 Banner: OpenSSH_7.4 (protocol 2.0)
[+] Port 80 Banner: Apache/2.4.6 (CentOS)
[+] Port 3306 Banner: MySQL 5.7.32


### 3. Intelligent Vulnerability Detection
- **CVE Database:** Cross-references 10+ known vulnerable services
- **Severity Scoring:** CRITICAL, HIGH, MEDIUM, LOW severity ratings
- **Vulnerability Mapping:** Links to actual CVE identifiers
- **Risk Assessment:** Quantifies security risk by severity
- **Automated Recommendations:** Provides specific remediation guidance

**Supported Vulnerable Services:**
- FTP (CVE-2019-12815)
- TELNET (CVE-2015-0385)
- SMB/Samba (CVE-2017-0143 - EternalBlue)
- MySQL (CVE-2021-2109)
- RDP (CVE-2019-0708 - BlueKeep)
- PostgreSQL
- CouchDB (CVE-2017-12635)
- MongoDB (CVE-2020-26542)

### 4. Professional Security Reporting
- **JSON Format:** Machine-readable reports for automation
- **Detailed Analysis:** Comprehensive vulnerability breakdown
- **Risk Summary:** Executive-level risk assessment
- **Timestamp Logging:** Complete audit trail with timestamps
- **Remediation Guidance:** Actionable recommendations for each finding

---

## 🛠️ Installation & Setup

### System Requirements

| Requirement | Details |
|-------------|---------|
| **OS** | Windows, macOS, Linux |
| **Python** | 3.7 or higher |
| **RAM** | 2GB minimum |
| **Storage** | 50MB for installation |
| **Network** | Internet connection for dependencies |

### Prerequisites
- Python 3.7+ ([Download](https://www.python.org/downloads/))
- pip (included with Python)
- Git (optional)

### Quick Start (3 Steps)

#### Step 1: Clone Repository
git clone https://github.com/MhdAsfan/keylogger-scanner.git
cd keylogger-scanner


#### Step 2: Install Dependencies
pip install -r requirements.txt


#### Step 3: Run Scanner
python security_scanner.py 192.168.1.1


---

## 🚀 Usage Guide

### Basic Port Scanning

**Scan an IP address:**
python security_scanner.py 192.168.1.1

**Scan a domain:**
python security_scanner.py example.com

**Scan localhost:**
python security_scanner.py 127.0.0.1

### Understanding Output
╔═══════════════════════════════════════════════════════╗
║ Advanced Security Scanner - All-in-One Tool v1.0 ║
║ Educational Purpose - Authorized Use Only ║
╚═══════════════════════════════════════════════════════╝

[] Starting port scan on 192.168.1.1...
[] Scanning ports 1-1024
[+] Port 22 is OPEN
[+] Port 80 is OPEN
[+] Port 443 is OPEN
[+] Port 3306 is OPEN

[*] Grabbing service banners...
[+] Port 22 Banner: OpenSSH_7.4
[+] Port 80 Banner: Apache/2.4.6
[+] Port 3306 Banner: MySQL 5.7.32

[*] Checking for known vulnerabilities...
[!] Port 445 (SMB) - Severity: CRITICAL
[!] Port 3306 (MySQL) - Severity: HIGH

============================================================
SCAN SUMMARY REPORT
Target: 192.168.1.1
Scan Date: 2025-11-05 10:45:00
Total Open Ports: 4
Total Vulnerabilities: 2

Risk Distribution:
CRITICAL: 1
HIGH: 1
MEDIUM: 0
LOW: 0


### Generated Reports

**Location:** `scan_report.json`

Each scan generates a JSON report with complete details:
- Target information
- All open ports found
- Service banners
- Detected vulnerabilities
- CVE mappings
- Severity ratings
- Remediation recommendations

---

## 📊 Vulnerability Database

| Port | Service | Severity | CVE | Mitigation |
|------|---------|----------|-----|-----------|
| 21 | FTP | HIGH | CVE-2019-12815 | Use SFTP instead |
| 23 | TELNET | CRITICAL | CVE-2015-0385 | Disable/Use SSH |
| 80 | HTTP | MEDIUM | CVE-2021-44228 | Use HTTPS |
| 443 | HTTPS | LOW | N/A | Standard secure |
| 445 | SMB | CRITICAL | CVE-2017-0143 | Apply patches |
| 3306 | MySQL | HIGH | CVE-2021-2109 | Update & secure |
| 3389 | RDP | HIGH | CVE-2019-0708 | Apply KB4499164 |
| 5432 | PostgreSQL | MEDIUM | N/A | Restrict access |
| 5984 | CouchDB | CRITICAL | CVE-2017-12635 | Enable auth |
| 27017 | MongoDB | CRITICAL | CVE-2020-26542 | Require auth |

---

## 🔐 Security Considerations

### Ethical Guidelines

✅ **Do:**
- Use on systems you own
- Get written permission for other systems
- Test in isolated labs
- Document findings
- Report responsibly

❌ **Don't:**
- Scan production systems without authorization
- Use for malicious purposes
- Share findings publicly
- Violate local laws
- Access systems without permission

### Authorization Checklist

Before scanning, confirm:
- [ ] I own this system
- [ ] I have written permission
- [ ] It's a lab environment
- [ ] I understand legal implications
- [ ] I have documented authorization

---

## 📁 Project Structure
keylogger-scanner/
├── security_scanner.py # Main scanning engine
├── keylogger.py # Educational keylogger
├── requirements.txt # Python dependencies
├── README.md # This file
├── .gitignore # Git exclusions
├── SECURITY_REPORT_TEMPLATE.md # Report template
├── LICENSE # MIT License

└── PROJECT_REPORT.pdf # Detailed project report


---

## 💡 Use Cases

### 1. Educational Learning
- Understand network reconnaissance
- Learn vulnerability assessment
- Practice ethical hacking
- Build cybersecurity skills

### 2. Home Lab Practice
- Test your own network
- Identify exposed services
- Practice security hardening
- Develop security awareness

### 3. Authorized Penetration Testing
- Pre-engagement reconnaissance
- Service enumeration
- Vulnerability identification
- Professional reporting

### 4. Security Auditing
- Network vulnerability scanning
- Risk assessment
- Compliance checking
- Security improvements

### 5. Career Development
- Build cybersecurity portfolio
- Demonstrate practical skills
- Showcase GitHub projects
- Prepare for certifications

---

## 📚 Learning Resources

### Official Documentation
- [Python Docs](https://docs.python.org/3/)
- [CVE Database](https://cve.mitre.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

### Practice Platforms
- [TryHackMe](https://tryhackme.com/) - Interactive labs
- [HackTheBox](https://www.hackthebox.com/) - Challenge boxes
- [OverTheWire](https://overthewire.org/) - Wargames
- [Cybrary](https://www.cybrary.it/) - Free courses

### Essential Reading
- NIST Cybersecurity Framework
- CWE/CVSS Scoring System
- Penetration Testing Methodologies
- Responsible Disclosure Practices

---

## 🐛 Troubleshooting

**"Python not found"**
pip install -r requirements.txt
Or use: python3 security_scanner.py
**"Module not found"**
pip install pynput requests beautifulsoup4
**"Permission denied" (Linux/macOS)**
chmod +x security_scanner.py
python3 security_scanner.py 192.168.1.1


**"No open ports found"**
- Verify target is reachable: `ping 192.168.1.1`
- Check firewall settings
- Try localhost first: `python security_scanner.py 127.0.0.1`

**Scan takes too long**
- Modify port range in code
- Increase timeout settings
- Use faster network connection

---

## 🤝 Contributing

### How to Contribute
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a Pull Request

### Areas for Contribution
- Additional CVE signatures
- Performance improvements
- Documentation enhancements
- Bug fixes
- Test cases

---

## 📝 License

This project is licensed under the **MIT License** - see LICENSE file for details.

---

## 👨‍💼 About Developer

**Muhammad Asfan**
- Cybersecurity Researcher
- Penetration Testing Practitioner
- Open Source Contributor
- GitHub: [@MhdAsfan](https://github.com/MhdAsfan/)

---

## 🔗 Important Links

- **Repository:** [GitHub](https://github.com/MhdAsfan/keylogger-scanner)
- **Issues:** [Bug Reports](https://github.com/MhdAsfan/keylogger-scanner/issues)
- **Report:** [Project Report](PROJECT_REPORT.pdf)

---

## ⭐ Show Your Support

If this project helps you:
- ⭐ Star the repository
- 🔗 Share with others
- 💬 Provide feedback
- 🐛 Report issues
- 🎁 Contribute improvements

---

**Last Updated:** November 5, 2025  
**Status:** ✅ Active & Maintained  
**Version:** 1.0.0

> ⚠️ **Remember:** Always practice ethically and legally. Use responsibly.












