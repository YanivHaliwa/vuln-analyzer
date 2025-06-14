#!/usr/bin/env python3
"""
Sample Data Generator for Pentester Analysis Tool

Generates sample scan outputs for testing the tool without actual scans
"""
import json
import random
import argparse
import os
from datetime import datetime

# Common ports and services
COMMON_PORTS = {
    21: {"service": "ftp", "versions": ["vsftpd 2.3.4", "ProFTPD 1.3.5", "FileZilla Server 0.9.60"]},
    22: {"service": "ssh", "versions": ["OpenSSH 7.6p1", "OpenSSH 8.2p1", "Dropbear SSH 2019.78"]},
    23: {"service": "telnet", "versions": ["Linux telnetd", "Cisco router telnetd", "Mini telnetd 0.9.2"]},
    25: {"service": "smtp", "versions": ["Postfix smtpd", "Exim 4.94", "Sendmail 8.15.2"]},
    53: {"service": "domain", "versions": ["ISC BIND 9.11.3", "dnsmasq 2.80", "Microsoft DNS 6.1.7601"]},
    80: {"service": "http", "versions": ["Apache httpd 2.4.29", "nginx 1.18.0", "Microsoft IIS 10.0"]},
    110: {"service": "pop3", "versions": ["Dovecot pop3d", "UW imapd 2007f", "Courier pop3d 4.17.0"]},
    139: {"service": "netbios-ssn", "versions": ["Samba smbd 3.X", "Samba smbd 4.7.6"]},
    443: {"service": "https", "versions": ["Apache/2.4.29 (Ubuntu)", "nginx/1.18.0", "Microsoft IIS/10.0"]},
    445: {"service": "microsoft-ds", "versions": ["Samba smbd 3.X", "Samba smbd 4.7.6", "Windows Server 2016"]},
    1433: {"service": "ms-sql-s", "versions": ["Microsoft SQL Server 2017", "Microsoft SQL Server 2019"]},
    3306: {"service": "mysql", "versions": ["MySQL 5.7.33", "MySQL 8.0.23", "MariaDB 10.3.27"]},
    3389: {"service": "ms-wbt-server", "versions": ["Microsoft Terminal Services", "xrdp"]},
    8080: {"service": "http-proxy", "versions": ["Apache Tomcat/9.0.37", "Jetty 9.4.24.v20191120", "WEBrick 1.4.2"]},
    8443: {"service": "https-alt", "versions": ["Apache Tomcat/9.0.37", "Jetty 9.4.24.v20191120", "Jboss EAP 7.1.0"]}
}

# Common web directories and files
WEB_DIRECTORIES = [
    "/admin", "/login", "/wp-admin", "/dashboard", "/phpmyadmin", "/manager",
    "/app", "/api", "/backup", "/config", "/dev", "/test", "/uploads", "/images"
]

WEB_FILES = [
    "/robots.txt", "/sitemap.xml", "/index.php", "/wp-login.php", "/config.php",
    "/.htaccess", "/readme.html", "/info.php", "/server-status", "/LICENSE.txt"
]

# Common software with vulnerability data
VULNERABLE_SOFTWARE = [
    {
        "name": "Apache Tomcat",
        "versions": [
            {"version": "9.0.30", "vulns": ["CVE-2020-1935", "CVE-2020-1938"]},
            {"version": "8.5.50", "vulns": ["CVE-2020-1938"]}
        ]
    },
    {
        "name": "WordPress",
        "versions": [
            {"version": "5.3.2", "vulns": ["CVE-2020-11027", "CVE-2020-11026"]},
            {"version": "4.9.15", "vulns": ["CVE-2020-4046", "CVE-2020-4047"]}
        ]
    },
    {
        "name": "OpenSSH",
        "versions": [
            {"version": "7.6p1", "vulns": ["CVE-2019-6111", "CVE-2018-15473"]},
            {"version": "6.8p1", "vulns": ["CVE-2015-5600", "CVE-2016-0777"]}
        ]
    }
]

def generate_nmap_scan(target_ip, open_ports=None, num_ports=10):
    """Generate a sample Nmap scan output"""
    if open_ports is None:
        open_ports = random.sample(list(COMMON_PORTS.keys()), min(num_ports, len(COMMON_PORTS)))
    
    current_time = datetime.now().strftime("%a %b %d %H:%M:%S %Y")
    scan_output = f"""
# Nmap 7.93 scan initiated {current_time} as: nmap -sC -sV -oA scan_result {target_ip}
Nmap scan report for {target_ip}
Host is up (0.076s latency).
Not shown: 990 closed ports

PORT     STATE SERVICE    VERSION
"""
    
    # Generate port info
    for port in open_ports:
        port_info = COMMON_PORTS[port]
        version = random.choice(port_info["versions"])
        scan_output += f"{port}/tcp   open  {port_info['service']}    {version}\n"
        
        # Add additional details for HTTP services
        if port_info["service"] in ["http", "https"] or port == 8080:
            scan_output += f"|_http-title: Site title: Welcome to {target_ip}\n"
            if random.random() > 0.5:
                scan_output += f"|_http-server-header: {version}\n"
    
    scan_output += f"\nService detection performed. Please report any incorrect results at https://nmap.org/submit/ .\n"
    scan_output += f"# Nmap done at {current_time} -- 1 IP address (1 host up) scanned in 15.36 seconds\n"
    
    return scan_output

def generate_nikto_scan(target_ip, port=80):
    """Generate a sample Nikto scan output"""
    current_time = datetime.now().strftime("%a %b %d %H:%M:%S %Y")
    scan_output = f"""
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          {target_ip}
+ Target Hostname:    {target_ip}
+ Target Port:        {port}
+ Start Time:         {current_time}
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server may leak inodes via ETags, header found with file /, inode: 2aa6, size: 5abef5d527e30, mtime: gzip
"""
    
    # Add some random findings
    findings = [
        f"+ OSVDB-3092: /{random.choice(['admin', 'login', 'manager', 'backend'])}/: This might be interesting...",
        f"+ OSVDB-3268: /icons/: Directory indexing found.",
        f"+ OSVDB-3233: /icons/README: Apache default file found.",
        f"+ /phpinfo.php: Output from the phpinfo() function was found.",
        f"+ OSVDB-3092: /config.bak: This might be interesting...",
        f"+ OSVDB-3268: /img/: Directory indexing found.",
        f"+ /server-status: Apache Server Status was found.",
        f"+ /wp-login.php: WordPress login page found.",
        f"+ /phpmyadmin/: phpMyAdmin installation found."
    ]
    
    # Add random number of findings
    num_findings = random.randint(3, 7)
    selected_findings = random.sample(findings, num_findings)
    for finding in selected_findings:
        scan_output += finding + "\n"
    
    scan_output += f"\n+ {len(selected_findings)} findings.\n"
    scan_output += f"+ End Time: {current_time} (12 seconds)\n"
    
    return scan_output

def generate_gobuster_scan(target_ip, port=80):
    """Generate a sample directory scan output"""
    scan_output = f"""
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://{target_ip}:{port}
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
"""
    
    # Generate found directories
    num_dirs = random.randint(5, 15)
    found_dirs = random.sample(WEB_DIRECTORIES, min(num_dirs, len(WEB_DIRECTORIES)))
    found_files = random.sample(WEB_FILES, min(num_dirs, len(WEB_FILES)))
    
    status_codes = [200, 301, 302, 403]
    
    # Add directories
    for directory in found_dirs:
        status = random.choice(status_codes)
        size = random.randint(100, 10000)
        scan_output += f"{directory}                 (Status: {status}) [Size: {size}]\n"
    
    # Add files
    for file in found_files:
        status = random.choice(status_codes)
        size = random.randint(100, 10000)
        scan_output += f"{file}                 (Status: {status}) [Size: {size}]\n"
    
    scan_output += f"\nEnd Time: {datetime.now().strftime('%a %b %d %H:%M:%S %Y')}\n"
    
    return scan_output

def generate_vulnerable_service():
    """Generate a vulnerable service with CVE info"""
    software = random.choice(VULNERABLE_SOFTWARE)
    version_info = random.choice(software["versions"])
    
    return {
        "name": software["name"],
        "version": version_info["version"],
        "cves": version_info["vulns"]
    }

def generate_complete_scan(target_ip=None, output_file=None, scan_types=None):
    """Generate a complete set of scan outputs"""
    if target_ip is None:
        # Generate a random IP address
        target_ip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
    
    # Default to all scan types if none specified
    if scan_types is None:
        scan_types = ["nmap", "nikto", "gobuster"]
    
    # Generate open ports
    open_ports = random.sample(list(COMMON_PORTS.keys()), random.randint(5, 10))
    
    # Initialize output
    output = f"# Comprehensive Scan Results for {target_ip}\n"
    output += f"# Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    
    # Add Nmap scan
    if "nmap" in scan_types:
        output += "=" * 80 + "\n"
        output += "# NMAP SCAN RESULTS\n"
        output += "=" * 80 + "\n"
        output += generate_nmap_scan(target_ip, open_ports)
        output += "\n\n"
    
    # Add Nikto scan if port 80 or 443 is open
    if "nikto" in scan_types and (80 in open_ports or 443 in open_ports or 8080 in open_ports):
        web_port = 80 if 80 in open_ports else (443 if 443 in open_ports else 8080)
        output += "=" * 80 + "\n"
        output += "# NIKTO SCAN RESULTS\n"
        output += "=" * 80 + "\n"
        output += generate_nikto_scan(target_ip, web_port)
        output += "\n\n"
    
    # Add Gobuster scan if port 80 or 443 is open
    if "gobuster" in scan_types and (80 in open_ports or 443 in open_ports or 8080 in open_ports):
        web_port = 80 if 80 in open_ports else (443 if 443 in open_ports else 8080)
        output += "=" * 80 + "\n"
        output += "# GOBUSTER SCAN RESULTS\n"
        output += "=" * 80 + "\n"
        output += generate_gobuster_scan(target_ip, web_port)
        output += "\n\n"
    
    # Generate JSON output if required
    json_output = {
        "target": target_ip,
        "timestamp": datetime.now().isoformat(),
        "open_ports": [{"port": port, "service": COMMON_PORTS[port]["service"]} for port in open_ports],
        "vulnerabilities": []
    }
    
    # Add some vulnerabilities
    num_vulns = random.randint(2, 5)
    for _ in range(num_vulns):
        vuln_service = generate_vulnerable_service()
        json_output["vulnerabilities"].append({
            "service": vuln_service["name"],
            "version": vuln_service["version"],
            "cves": vuln_service["cves"]
        })
    
    # Write to file or return
    if output_file:
        with open(output_file, 'w') as f:
            f.write(output)
        
        # Also write JSON version
        json_file = output_file.replace('.txt', '.json')
        if json_file == output_file:
            json_file += '.json'
        
        with open(json_file, 'w') as f:
            json.dump(json_output, f, indent=2)
        
        return f"Scan data written to {output_file} and {json_file}"
    else:
        return output

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate sample security scan data for testing')
    parser.add_argument('--ip', help='Target IP address (default: random)')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--scans', help='Comma-separated list of scan types (nmap,nikto,gobuster)', default='nmap,nikto,gobuster')
    
    args = parser.parse_args()
    
    scan_types = args.scans.split(',')
    result = generate_complete_scan(args.ip, args.output, scan_types)
    
    if not args.output:
        print(result)
