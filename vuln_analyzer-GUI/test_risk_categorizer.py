#!/usr/bin/env python3
"""
Test the risk categorizer integration with the analyzer

This script loads the PentesterAnalyzer and tests the risk categorization 
functionality with a sample vulnerability dataset.
"""

import json
import logging
from analyzer import PentesterAnalyzer
from utils.risk_categorizer import (
    categorize_vulnerability, 
    categorize_service, 
    assess_overall_risk
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_vulnerability_categorization():
    """Test the vulnerability categorization functionality"""
    # Create sample vulnerabilities with different characteristics
    test_vulnerabilities = [
        {
            "name": "Remote Code Execution in Web Service", 
            "description": "A remote code execution vulnerability allows attackers to execute arbitrary code.",
            "cve": "CVE-2021-44228",
            "service": "Apache Tomcat"
        },
        {
            "name": "SQL Injection", 
            "description": "SQL injection vulnerability in login form",
            "cve": "",
            "service": "Web Application"
        },
        {
            "name": "Directory Listing", 
            "description": "Web server reveals directory contents",
            "cve": "",
            "service": "http"
        },
        {
            "name": "SSLv2 Support", 
            "description": "Server supports outdated SSL version",
            "cve": "",
            "service": "https"
        }
    ]
    
    # Test categorization
    print("\nTesting individual vulnerability categorization:")
    for vuln in test_vulnerabilities:
        severity = categorize_vulnerability(vuln)
        print(f"{vuln['name']}: {severity}")
    
    # Test service categorization  
    test_services = [
        {"port": 21, "service": "ftp", "version": "vsftpd 2.3.4"},
        {"port": 22, "service": "ssh", "version": "OpenSSH 7.6"},
        {"port": 80, "service": "http", "version": "Apache 2.4.29"},
        {"port": 445, "service": "smb", "version": "Samba 4.5.16"}
    ]
    
    print("\nTesting service categorization:")
    for service in test_services:
        risk_level = categorize_service(service)
        print(f"{service['service']} on port {service['port']}: {risk_level}")
    
    # Test overall risk assessment
    risk_assessment = assess_overall_risk(test_vulnerabilities, test_services)
    
    print("\nOverall risk assessment:")
    print(f"Overall risk level: {risk_assessment['overall']}")
    print("\nCritical findings:")
    for finding in risk_assessment['critical']:
        print(f"- {finding}")
    
    print("\nHigh findings:")
    for finding in risk_assessment['high']:
        print(f"- {finding}")
    
    print("\nJustification:")
    print(risk_assessment['justification'])
    
    return risk_assessment

def test_analyzer_integration():
    """Test the integration with the PentesterAnalyzer"""
    analyzer = PentesterAnalyzer()
    
    # Create a mock scan result
    mock_scan_result = {
        "ports_and_services": [
            {"port": 21, "protocol": "tcp", "service": "ftp", "version": "vsftpd 2.3.4", "state": "open"},
            {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 8.2p1", "state": "open"},
            {"port": 80, "protocol": "tcp", "service": "http", "version": "Apache 2.4.41", "state": "open"},
            {"port": 445, "protocol": "tcp", "service": "smb", "version": "Samba 4.11.6", "state": "open"}
        ],
        "vulnerabilities": [
            {
                "name": "FTP Backdoor", 
                "cve": "CVE-2011-2523", 
                "description": "vsftpd 2.3.4 backdoor vulnerability", 
                "affected_component": "FTP service", 
                "verified": True
            },
            {
                "name": "HTTP Directory Listing", 
                "description": "The web server reveals directory contents", 
                "affected_component": "Web server", 
                "verified": True
            }
        ],
        "target_info": {
            "ip_address": "192.168.1.100",
            "hostname": "test-target",
            "os": "Linux 4.15"
        }
    }
    
    # Use the risk categorizer directly first
    print("\nDirect risk assessment:")
    risk_assessment = assess_overall_risk(
        mock_scan_result.get("vulnerabilities", []),
        mock_scan_result.get("ports_and_services", [])
    )
    print(f"Overall risk: {risk_assessment['overall']}")
    
    # Now use the analyzer's method
    print("\nAnalyzer risk assessment:")
    categorized_result = analyzer._categorize_vulnerabilities_with_risk_rules(mock_scan_result)
    print(f"Overall risk: {categorized_result['overall']}")
    
    # Verify that vulnerabilities have been categorized
    for vuln in mock_scan_result["vulnerabilities"]:
        print(f"{vuln['name']}: {vuln.get('severity', 'Not categorized')}")
    
    # Verify that services have been categorized
    for service in mock_scan_result["ports_and_services"]:
        print(f"{service['service']} on port {service['port']}: {service.get('risk_level', 'Not categorized')}")
    
    # Check that full risk assessment structure is present
    print("\nRisk assessment categories:")
    for category in ["critical", "high", "medium", "low"]:
        if category in categorized_result:
            print(f"{category.capitalize()}: {len(categorized_result[category])} findings")
    
    return categorized_result

if __name__ == "__main__":
    print("Testing risk categorizer functionality...")
    risk_assessment = test_vulnerability_categorization()
    
    print("\nTesting analyzer integration...")
    analyzer_result = test_analyzer_integration()
    
    print("\nTest completed successfully!")