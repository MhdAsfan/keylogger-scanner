#!/usr/bin/env python3
"""
Advanced Security Scanner - All-in-One Tool
Educational Purpose Only - For Authorized Use Only

This scanner combines:
1. Network vulnerability scanning
2. Port scanning and banner grabbing
3. Service vulnerability detection

Author: Your Name
Date: 2025-11-05
Version: 1.0.0
"""

import socket
import subprocess
import platform
import sys
import os
import json
import logging
from datetime import datetime
from typing import List, Dict, Set
import re

# Configure logging
logging.basicConfig(
    filename='security_scan_report.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class SecurityScanner:
    """
    Comprehensive security scanner for educational and authorized penetration testing
    """
    
    def __init__(self, target: str):
        """
        Initialize the scanner with a target IP or hostname
        
        Args:
            target (str): Target IP address or hostname to scan
        """
        self.target = target
        self.open_ports = []
        self.banners = []
        self.vulnerabilities = []
        self.scan_results = {
            'target': target,
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'scan_type': 'Comprehensive Security Assessment',
            'open_ports': [],
            'services': [],
            'vulnerabilities': [],
            'risk_summary': {}
        }
        
        logging.info(f"Scanner initialized for target: {target}")
        
    def print_banner(self):
        """Display application banner"""
        banner = """
        ╔═══════════════════════════════════════════════════════╗
        ║   Advanced Security Scanner - All-in-One Tool v1.0    ║
        ║   Educational Purpose - Authorized Use Only           ║
        ║   Combining Keylogger & Network Vulnerability Scan    ║
        ╚═══════════════════════════════════════════════════════╝
        """
        print(banner)
        
    def validate_target(self) -> bool:
        """
        Validate if the target is a valid IP address or hostname
        
        Returns:
            bool: True if valid, False otherwise
        """
        # Simple IP validation (IPv4)
        ip_pattern = r'^\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b$'
        
        if re.match(ip_pattern, self.target):
            return True
        
        # Try to resolve hostname
        try:
            socket.gethostbyname(self.target)
            return True
        except socket.gaierror:
            return False
    
    def port_scan(self, port_range: tuple = (1, 1024)) -> List[int]:
        """
        Perform port scanning on the target
        
        Args:
            port_range (tuple): Range of ports to scan (start, end)
            
        Returns:
            List[int]: List of open ports found
        """
        print(f"\\n[*] Starting port scan on {self.target}...")
        print(f"[*] Scanning ports {port_range[0]}-{port_range[1]}")
        print("[*] This may take a few minutes...\\n")
        
        open_ports = []
        
        for port in range(port_range[0], port_range[1] + 1):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                
                result = sock.connect_ex((self.target, port))
                
                if result == 0:
                    open_ports.append(port)
                    print(f"[+] Port {port} is OPEN")
                    logging.info(f"Open port found: {port}")
                    
                sock.close()
                
            except Exception as e:
                logging.error(f"Error scanning port {port}: {str(e)}")
                pass
        
        self.open_ports = open_ports
        return open_ports
    
    def banner_grab(self) -> Dict[int, str]:
        """
        Grab service banners from open ports
        
        Returns:
            Dict[int, str]: Dictionary mapping ports to their banners
        """
        print(f"\\n[*] Grabbing service banners...")
        banners_dict = {}
        
        for port in self.open_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                
                sock.connect((self.target, port))
                
                try:
                    banner = sock.recv(1024).decode().strip()
                    if banner:
                        banners_dict[port] = banner
                        print(f"[+] Port {port} Banner: {banner[:80]}")
                        logging.info(f"Banner grabbed from port {port}: {banner[:100]}")
                except:
                    banners_dict[port] = "No banner"
                    
                sock.close()
                
            except Exception as e:
                logging.error(f"Error grabbing banner from port {port}: {str(e)}")
                pass
        
        self.banners = banners_dict
        return banners_dict
    
    def check_vulnerabilities(self) -> List[Dict]:
        """
        Check for known vulnerabilities based on open services
        
        Returns:
            List[Dict]: List of potential vulnerabilities
        """
        print(f"\\n[*] Checking for known vulnerabilities...")
        
        # Known vulnerable services and their ports
        vulnerable_services = {
            21: {'name': 'FTP', 'severity': 'HIGH', 'cves': ['CVE-2019-12815']},
            23: {'name': 'TELNET', 'severity': 'CRITICAL', 'cves': ['CVE-2015-0385']},
            80: {'name': 'HTTP', 'severity': 'MEDIUM', 'cves': ['CVE-2021-44228']},
            443: {'name': 'HTTPS', 'severity': 'LOW', 'cves': []},
            445: {'name': 'SMB', 'severity': 'CRITICAL', 'cves': ['CVE-2017-0143']},
            3306: {'name': 'MySQL', 'severity': 'HIGH', 'cves': ['CVE-2021-2109']},
            3389: {'name': 'RDP', 'severity': 'HIGH', 'cves': ['CVE-2019-0708']},
            5432: {'name': 'PostgreSQL', 'severity': 'MEDIUM', 'cves': []},
            5984: {'name': 'CouchDB', 'severity': 'CRITICAL', 'cves': ['CVE-2017-12635']},
            27017: {'name': 'MongoDB', 'severity': 'CRITICAL', 'cves': ['CVE-2020-26542']},
        }
        
        vulnerabilities = []
        
        for port in self.open_ports:
            if port in vulnerable_services:
                vuln = vulnerable_services[port]
                vuln_record = {
                    'port': port,
                    'service': vuln['name'],
                    'severity': vuln['severity'],
                    'cves': vuln['cves'],
                    'recommendation': f"Update or disable {vuln['name']} service"
                }
                vulnerabilities.append(vuln_record)
                
                severity_color = {
                    'CRITICAL': '\\033[91m',
                    'HIGH': '\\033[93m',
                    'MEDIUM': '\\033[94m',
                    'LOW': '\\033[92m'
                }
                
                color = severity_color.get(vuln['severity'], '')
                reset = '\\033[0m'
                
                print(f"{color}[!] Port {port} ({vuln['name']}) - Severity: {vuln['severity']}{reset}")
                logging.warning(f"Vulnerability found - Port {port}: {vuln['name']}")
        
        self.vulnerabilities = vulnerabilities
        return vulnerabilities
    
    def generate_report(self, output_file: str = 'scan_report.json') -> Dict:
        """
        Generate comprehensive scan report
        
        Args:
            output_file (str): Output file path for JSON report
            
        Returns:
            Dict: Complete scan results
        """
        print(f"\\n[*] Generating comprehensive report...")
        
        self.scan_results['open_ports'] = self.open_ports
        self.scan_results['services'] = self.banners
        self.scan_results['vulnerabilities'] = self.vulnerabilities
        
        # Calculate risk summary
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        
        for vuln in self.vulnerabilities:
            severity_counts[vuln['severity']] += 1
        
        self.scan_results['risk_summary'] = severity_counts
        
        # Save JSON report
        with open(output_file, 'w') as f:
            json.dump(self.scan_results, f, indent=4)
        
        print(f"[+] Report saved to: {output_file}")
        logging.info(f"Scan report generated: {output_file}")
        
        return self.scan_results
    
    def print_report_summary(self):
        """Print a summary of the scan results"""
        print("\\n" + "="*60)
        print("SCAN SUMMARY REPORT")
        print("="*60)
        print(f"Target: {self.scan_results['target']}")
        print(f"Scan Date: {self.scan_results['scan_date']}")
        print(f"Total Open Ports: {len(self.scan_results['open_ports'])}")
        print(f"Total Vulnerabilities: {len(self.scan_results['vulnerabilities'])}")
        
        print("\\nRisk Distribution:")
        for severity, count in self.scan_results['risk_summary'].items():
            print(f"  {severity}: {count}")
        
        print("\\nOpen Ports Found:")
        for port in sorted(self.scan_results['open_ports']):
            print(f"  - Port {port}")
        
        print("\\nVulnerabilities:")
        if self.scan_results['vulnerabilities']:
            for vuln in self.scan_results['vulnerabilities']:
                print(f"  - Port {vuln['port']}: {vuln['service']} (Severity: {vuln['severity']})")
        else:
            print("  No known vulnerabilities detected")
        
        print("="*60 + "\\n")
    
    def run_full_scan(self):
        """Execute a complete security scan"""
        self.print_banner()
        
        # Validate target
        if not self.validate_target():
            print(f"[!] Error: Invalid target {self.target}")
            logging.error(f"Invalid target: {self.target}")
            sys.exit(1)
        
        # Perform port scan
        self.port_scan((1, 1024))
        
        # If ports found, grab banners
        if self.open_ports:
            self.banner_grab()
            self.check_vulnerabilities()
        else:
            print("[*] No open ports found")
        
        # Generate report
        self.generate_report()
        self.print_report_summary()


def main():
    """Main execution function"""
    
    if len(sys.argv) < 2:
        print("Usage: python security_scanner.py <target_ip_or_hostname>")
        print("Example: python security_scanner.py 192.168.1.1")
        print("Example: python security_scanner.py example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Create scanner instance
    scanner = SecurityScanner(target)
    
    # Run full scan
    try:
        scanner.run_full_scan()
    except KeyboardInterrupt:
        print("\\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error during scan: {str(e)}")
        logging.error(f"Scan error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
