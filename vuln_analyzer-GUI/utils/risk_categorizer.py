#!/usr/bin/env python3
"""
Risk Categorizer Module

Implements the custom risk categorization rules for determining severity 
levels of security findings based on predefined criteria.
"""

import re
import logging

logger = logging.getLogger(__name__)

# Define lists of keywords that match different severity levels
CRITICAL_KEYWORDS = [
    'remote code execution', 'rce', 'root access', 'system access', 'elevated privilege',
    'backdoor', 'remote shell', 'remote access', 'unauthenticated access',
    'anonymous access', 'critical data', 'sensitive data exposure',
    'default credential', 'hardcoded password', 'default password',
    'eol', 'end of life', 'unpatched', 'telnet', 'ftp backdoor', 
    'vsftpd 2.3.4', 'ms17-010', 'eternalblue', 'smb exploit', 'nfs export',
    'ghost', 'cat', 'heartbleed', 'cve-2011-2523', 'cve-2014-0160',
    'cve-2020-1938', 'ajp13', 'apache jserv', 'dvwa', 'jboss'
]

HIGH_KEYWORDS = [
    'privilege escalation', 'denial of service', 'dos', 'data exposure',
    'csrf', 'cross-site request forgery', 'sql injection', 'sqli',
    'weak configuration', 'default configuration', 'outdated software',
    'outdated version', 'weak credential', 'weak password',
    'authentication bypass', 'cleartext', 'clear text', 'plaintext',
    'plain text', 'brute force', 'path traversal', 'weak encryption',
    'cve-2017-', 'cve-2018-', 'cve-2019-', 'cve-2020-', 'cve-2021-',
    'apache < 2.4.50', 'exposed service', 'exposed port', 'exposed database',
    'smb', 'netbios', 'http exploit', 'ssh exploit'
]

MEDIUM_KEYWORDS = [
    'directory listing', 'information disclosure', 'information leakage',
    'version disclosure', 'banner disclosure', 'header leakage',
    'xss', 'cross-site scripting', 'reflected parameter', 'file upload',
    'misconfigured service', 'unnecessary service', 'unnecessary port',
    'outdated but not eol', 'redis', 'mongodb', 'vnc', 'open port',
    'smtp', 'mail port', 'pop3', 'imap'
]

LOW_KEYWORDS = [
    'informational', 'no known vulnerability', 'outdated banner',
    'version disclosure', 'icmp', 'ping', 'snmp', 'dns without recursion',
    'unused port', 'rate limit', 'security header', 'dnssec',
    'good practice', 'best practice', 'minor issue'
]

def categorize_vulnerability(vulnerability, service_count=None):
    """
    Categorize a vulnerability based on predefined rules.
    
    Args:
        vulnerability (dict): Vulnerability information dictionary
        service_count (dict, optional): Count of service types by severity
        
    Returns:
        str: Severity category ('critical', 'high', 'medium', or 'low')
    """
    # Extract vulnerability information
    description = vulnerability.get('description', '').lower()
    service = vulnerability.get('service', '').lower()
    cve = vulnerability.get('cve', '')
    if isinstance(cve, list):
        cve = ' '.join(cve).lower()
    else:
        cve = str(cve).lower()
    
    # Set default severity based on provided risk field if available
    if 'risk' in vulnerability:
        severity = vulnerability.get('risk', '').lower()
        if severity in ['critical', 'high', 'medium', 'low']:
            return severity
    
    severity = 'low'  # Default severity
    
    # Check for critical indicators
    if any(keyword in description or keyword in service or keyword in cve for keyword in CRITICAL_KEYWORDS):
        return 'critical'
    
    # Known critical CVEs or services
    critical_indicators = [
        'vsftpd 2.3.4', 'ms17-010', 'cve-2011-2523', 'cve-2014-0160',
        'backdoor', 'distccd', 'anonymous ftp', 'anonymous smb', 
        'nfs export', 'cve-2020-1938', 'ghostcat'
    ]
    
    if any(indicator in description or indicator in service or indicator in cve for indicator in critical_indicators):
        return 'critical'
    
    # Check for high indicators
    if any(keyword in description or keyword in service or keyword in cve for keyword in HIGH_KEYWORDS):
        return 'high'
    
    # Known high services
    high_indicators = [
        'telnet', 'apache 2.2', 'apache httpd 2.2', 'smb', 'samba',
        'rmi', 'rmiregistry', 'cleartext', 'plaintext'
    ]
    
    if any(indicator in description or indicator in service for indicator in high_indicators):
        return 'high'
    
    # Check for medium indicators
    if any(keyword in description or keyword in service or keyword in cve for keyword in MEDIUM_KEYWORDS):
        return 'medium'
    
    # Default to low
    return severity

def categorize_service(service_info):
    """
    Categorize a service based on its description and known risk.
    
    Args:
        service_info (dict): Service information dictionary
        
    Returns:
        str: Severity category ('critical', 'high', 'medium', or 'low')
    """
    service_name = service_info.get('service', '').lower()
    port = service_info.get('port', '')
    
    # Critical services
    critical_services = [
        'ftp', 'telnet', 'rsh', 'rlogin', 'rexec', 
        'anonymous ftp', 'vsftpd 2.3'
    ]
    
    # High risk services
    high_risk_services = [
        'smb', 'netbios', 'mysql', 'postgresql', 'mongodb',
        'redis', 'vnc', 'x11', 'rmi', 'rmiregistry'
    ]
    
    # Medium risk services
    medium_risk_services = [
        'smtp', 'pop3', 'imap', 'http', 'snmp'
    ]
    
    if any(critical in service_name for critical in critical_services):
        return 'critical'
    
    if any(high_risk in service_name for high_risk in high_risk_services):
        return 'high'
    
    if any(medium_risk in service_name for medium_risk in medium_risk_services):
        return 'medium'
    
    return 'low'

def assess_overall_risk(vulnerabilities, ports_and_services=None):
    """
    Determine the overall risk based on all vulnerabilities and services.
    
    Args:
        vulnerabilities (list): List of vulnerability dictionaries
        ports_and_services (list, optional): List of port/service dictionaries
        
    Returns:
        dict: Risk assessment with categories and lists of findings
    """
    if not vulnerabilities:
        vulnerabilities = []
    
    if not ports_and_services:
        ports_and_services = []
    
    # Initialize severity counts
    severity_counts = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0
    }
    
    # Initialize findings lists
    critical_findings = []
    high_findings = []
    medium_findings = []
    low_findings = []
    
    # Track unique findings to avoid duplicates
    unique_findings = set()
    
    # Categorize vulnerabilities
    for vuln in vulnerabilities:
        severity = vuln.get('risk', categorize_vulnerability(vuln, severity_counts))
        
        # Create a finding string
        finding = vuln.get('name', vuln.get('service', 'Unknown vulnerability'))
        if vuln.get('description'):
            finding += f" - {vuln.get('description')}"
        
        # Skip if we've already seen this exact finding
        if finding in unique_findings:
            continue
            
        # Add to the unique findings set
        unique_findings.add(finding)
        
        # Add to the appropriate severity category
        if severity == 'critical':
            critical_findings.append(finding)
            severity_counts['critical'] += 1
        elif severity == 'high':
            high_findings.append(finding)
            severity_counts['high'] += 1
        elif severity == 'medium':
            medium_findings.append(finding)
            severity_counts['medium'] += 1
        else:
            low_findings.append(finding)
            severity_counts['low'] += 1
    
    # Count open ports by risk category
    high_risk_ports = ['21', '23', '161', '445', '1433', '3389']
    medium_risk_ports = ['22', '25', '53', '110', '143', '993', '995']
    
    high_risk_port_count = 0
    medium_risk_port_count = 0
    
    for port_service in ports_and_services:
        port = str(port_service.get('port', ''))
        
        if port in high_risk_ports:
            high_risk_port_count += 1
            
        if port in medium_risk_ports:
            medium_risk_port_count += 1
    
    # Apply special rules for service count
    if len(ports_and_services) > 10:
        if not critical_findings:
            critical_findings.append(f"High number of open ports/services: {len(ports_and_services)}")
            severity_counts['critical'] += 1
    
    if high_risk_port_count > 5:
        if not critical_findings and not high_findings:
            high_findings.append(f"Multiple high-risk ports open: {high_risk_port_count}")
            severity_counts['high'] += 1
    
    # Determine overall severity based on counts
    overall_severity = 'low'
    
    if severity_counts['critical'] > 0:
        overall_severity = 'critical'
    elif severity_counts['high'] > 0:
        overall_severity = 'high'
    elif severity_counts['medium'] > 0:
        overall_severity = 'medium'
    
    # Build justification
    if overall_severity == 'critical':
        justification = "The system has at least one vulnerability that provides remote access with elevated privileges or exposes critical data, or combines multiple severe weaknesses."
    elif overall_severity == 'high':
        justification = "The system has a significant vulnerability that can lead to privilege escalation, DoS, or sensitive data exposure but not direct root access without chaining."
    elif overall_severity == 'medium':
        justification = "Vulnerabilities that can assist attackers or be part of a chain but do not pose immediate danger alone."
    else:
        justification = "Informational findings or minor issues that present no realistic attack path alone."
    
    # Return structured risk assessment
    return {
        'overall': overall_severity,
        'critical': critical_findings,
        'high': high_findings,
        'medium': medium_findings,
        'low': low_findings,
        'justification': justification,
        'counts': severity_counts
    }

def parse_unstructured_risk_assessment(risk_text):
    """
    Parse a plain text risk assessment and convert it to structured format.
    
    Args:
        risk_text (str): Unstructured risk assessment text
        
    Returns:
        dict: Structured risk assessment
    """
    if not risk_text:
        return None
    
    # Attempt to identify the overall risk from text
    overall = None
    if re.search(r'critical', risk_text, re.IGNORECASE):
        overall = 'critical'
    elif re.search(r'high', risk_text, re.IGNORECASE):
        overall = 'high'
    elif re.search(r'medium', risk_text, re.IGNORECASE):
        overall = 'medium'
    elif re.search(r'low', risk_text, re.IGNORECASE):
        overall = 'low'
    
    # Default if we can't find anything
    if not overall:
        overall = 'medium'
    
    # Return structured format with text as justification
    return {
        'overall': overall,
        'critical': [],
        'high': [],
        'medium': [],
        'low': [],
        'justification': risk_text
    }

if __name__ == "__main__":
    # Example usage
    test_vuln = {
        "service": "vsftpd 2.3.4",
        "description": "Backdoor vulnerability allowing remote code execution"
    }
    
    severity = categorize_vulnerability(test_vuln)
    print(f"Severity: {severity}")