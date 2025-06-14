#!/usr/bin/env python3
"""
Pentester Analysis Tool - Unified Analyzer Module

This module provides the core analysis functionality for the Pentester Analysis Tool,
integrating AI-powered analysis with traditional security scan parsing.
"""
import os
import re
import json
import logging
import openai
from dotenv import load_dotenv
from utils.risk_categorizer import (
    categorize_vulnerability, 
    categorize_service, 
    assess_overall_risk,
    parse_unstructured_risk_assessment
)

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class PentesterAnalyzer:
    """
    Core analyzer that integrates AI analysis capabilities with security scan parsing.
    Handles all aspects of scan data processing and enrichment.
    """
    
    def __init__(self):
        """Initialize the analyzer with API clients and configurations"""
        self.ai_provider = os.getenv('AI_PROVIDER', 'openai')
        self._init_openai_client()
        
        # Configuration options
        self.enable_streaming = os.getenv('ENABLE_STREAMING', 'false').lower() == 'true'
        self.openai_model = os.getenv('OPENAI_MODEL', 'gpt-4o-mini')  # Default to GPT-4o mini
        
        logger.info(f"Analyzer initialized with {self.ai_provider} using model {self.openai_model}")
    
    def _init_openai_client(self):
        """Initialize OpenAI client with API key from environment"""
        openai_api_key = os.getenv('OPENAI_API_KEY')
        if openai_api_key:
            openai.api_key = openai_api_key
            logger.info("OpenAI client initialized successfully")
        else:
            logger.warning("OpenAI API key not found in environment variables")
    
    def analyze(self, scan_data, analysis_type='general', deep_analysis=False, 
                content_types=None, enrich_cve=True):
        """
        Main analysis function that processes scan data and returns structured results.
        
        Args:
            scan_data (str): The raw scan output text
            analysis_type (str): Type of analysis to perform (general, network, web, vuln)
            deep_analysis (bool): Whether to perform in-depth analysis
            content_types (list): List of content types to focus on
            enrich_cve (bool): Whether to enrich CVE data with external sources
            
        Returns:
            dict: A structured analysis of the scan data
        """
        if not scan_data:
            return {"error": "No scan data provided"}
        
        logger.info(f"Starting analysis with type: {analysis_type}, deep: {deep_analysis}")
        
        # Parse scan data to extract key information
        try:
            parsed_data = self._parse_scan_data(scan_data)
            logger.info(f"Successfully parsed scan data: {len(parsed_data.keys())} categories extracted")
        except Exception as e:
            logger.error(f"Error parsing scan data: {str(e)}")
            parsed_data = {}
        
        # Enhance with AI analysis if we have OpenAI API key
        try:
            if os.getenv('OPENAI_API_KEY'):
                ai_analysis = self._perform_ai_analysis(
                    scan_data, 
                    analysis_type, 
                    deep_analysis,
                    content_types
                )
                parsed_data['ai_analysis'] = ai_analysis
                
                # Extract structured data from AI analysis where possible
                self._enhance_parsed_data_from_ai(parsed_data, ai_analysis)
                
                logger.info("AI analysis completed and integrated into results")
            else:
                parsed_data['ai_analysis'] = "API key required for AI-powered analysis."
                logger.warning("Skipping AI analysis due to missing API key")
        except Exception as e:
            logger.error(f"Error during AI analysis: {str(e)}")
            parsed_data['ai_analysis'] = f"Error during AI analysis: {str(e)}"
        
        # Apply risk categorization rules
        try:
            categorized_data = self._categorize_vulnerabilities_with_risk_rules(parsed_data)
            parsed_data.update(categorized_data)
            logger.info("Risk categorization completed")
        except Exception as e:
            logger.error(f"Error during risk categorization: {str(e)}")
        
        return parsed_data
    
    def _parse_scan_data(self, scan_data):
        """
        Parse raw scan output to extract structured information.
        
        Args:
            scan_data (str): Raw scan output text
            
        Returns:
            dict: Structured data extracted from scan
        """
        results = {
            'target_info': {},
            'ports_and_services': [],
            'vulnerabilities': [],
            'web_directories': [],
            'remote_files': []
        }
        
        # Extract target information
        # IP address pattern
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ip_matches = re.findall(ip_pattern, scan_data)
        if ip_matches:
            results['target_info']['ip_address'] = ip_matches[0]
        
        # Extract ports and services (basic parsing)
        port_pattern = r'(\d+)/(\w+)\s+open\s+(\S+)\s*(.*)'
        port_matches = re.findall(port_pattern, scan_data)
        
        for match in port_matches:
            port, protocol, service, version = match
            results['ports_and_services'].append({
                'port': port,
                'protocol': protocol,
                'service': service,
                'version': version.strip(),
                'state': 'open'
            })
        
        # Extract potential vulnerabilities
        # Look for common patterns in scan data that indicate vulnerabilities
        # This is a simplified version - in a real implementation, you'd have more sophisticated parsing
        vuln_keywords = [
            'vulnerability', 'vulnerable', 'CVE-', 'exploit', 
            'outdated', 'weak', 'misconfiguration', 'disclosure'
        ]
        
        # Check each line for vulnerability indicators
        for line in scan_data.splitlines():
            # Skip empty lines
            if not line.strip():
                continue
                
            # Check for vulnerability keywords
            found_keyword = False
            for keyword in vuln_keywords:
                if keyword.lower() in line.lower():
                    found_keyword = True
                    break
            
            if found_keyword:
                # Look for CVE IDs
                cve_matches = re.findall(r'CVE-\d{4}-\d{4,}', line)
                
                # Create vulnerability entry
                vuln = {
                    'name': line[:50] + ('...' if len(line) > 50 else ''),
                    'description': line,
                    'cve': cve_matches[0] if cve_matches else 'N/A',
                    'verified': False  # Default to unverified
                }
                
                results['vulnerabilities'].append(vuln)
        
        # Extract web directories from gobuster/dirbuster output
        if 'directory enum' in scan_data.lower() or 'gobuster' in scan_data.lower() or 'dirb' in scan_data.lower():
            # Multiple patterns to match different gobuster/dirb output formats
            dir_patterns = [
                r'(/\S+)\s+\(Status:\s+(\d+)\)',  # GoBuster v3 format
                r'Discovered:\s+(/\S+)\s+\(Status:\s+(\d+)\)',  # Alternate format
                r'(/[\w\-\.\/]+)\s+\(\s*Size:\s*\d+\)',  # Size-based format
                r'=+\s+(/\S+)\s+=+',  # DIRB format
                r'200\s+\S+\s+(/[\w\-\.\/]+)'  # Simple status+path format
            ]

            for pattern in dir_patterns:
                dir_matches = re.findall(pattern, scan_data)
                for match in dir_matches:
                    if isinstance(match, tuple) and len(match) >= 2:
                        path, status = match[0], match[1]
                    else:
                        path = match
                        status = '200'  # Default status if not found

                    # Check if already in results
                    if not any(d.get('path') == path for d in results['web_directories']):
                        results['web_directories'].append({
                            'path': path,
                            'status_code': status,
                            'type': 'directory' if path.endswith('/') else 'file'
                        })
        
        return results
    
    def _perform_ai_analysis(self, scan_data, analysis_type, deep_analysis, content_types):
        """
        Use AI to analyze the scan data and provide insights.
        
        Args:
            scan_data (str): Raw scan output
            analysis_type (str): Type of analysis to perform
            deep_analysis (bool): Whether to perform in-depth analysis
            content_types (list): Content types to focus on
            
        Returns:
            str: AI-generated analysis
        """
        try:
            # Construct prompt based on analysis parameters
            system_prompt = """
            You are a cybersecurity expert analyzing penetration testing scan output.
            Extract key information, identify vulnerabilities, and provide a comprehensive assessment.
            Format your response to be clearly structured and highlight important findings.

            IMPORTANT: Use specific section headers and formatting to help extract structured data:
            - Label directories as "Directory: /path/to/dir"
            - Label subdomains as "Subdomain: name.example.com"
            - Label remote files as "Remote file: /path/to/file"
            - Format credentials as "Username: user, Password: pass"
            - Format vulnerabilities with severity: "Critical vulnerability: description"
            """

            user_prompt = f"""
            Please analyze the following {analysis_type} security scan output and provide a detailed structured report.
            """

            if deep_analysis:
                user_prompt += """
                Provide a comprehensive analysis including:

                # TARGET INFORMATION
                - IP address, hostname, and OS details if available

                # PORTS AND SERVICES
                - List all open ports with services and versions

                # WEB DIRECTORIES
                - Any web directories discovered (format as "Directory: /path")
                - Include status codes if available

                # REMOTE FILES
                - Any accessible files found (format as "Remote file: /path/to/file")
                - Include permissions if available

                # SUBDOMAINS
                - Any subdomains discovered (format as "Subdomain: name.domain.com")

                # CREDENTIALS
                - Any exposed credentials (format as "Username: user, Password: pass")

                # VULNERABILITIES
                - List all vulnerabilities with severity ratings (Critical/High/Medium/Low)
                - Include CVE IDs when available
                - Format as "Critical vulnerability: description"

                # EXPLOITATION
                - Exploitation possibilities
                - Commands or techniques that could be used

                # RISK ASSESSMENT
                - Overall risk level (Critical/High/Medium/Low)
                - Justification for the assessment
                """
            else:
                user_prompt += """
                Provide a concise but structured summary of:

                # TARGET INFORMATION
                - Key target details (IP, hostname)

                # PORTS AND SERVICES
                - Most notable open ports and services

                # VULNERABILITIES
                - Most critical security issues with severity ratings
                - Format as "Critical vulnerability: description"

                # RISK ASSESSMENT
                - Brief risk assessment (Critical/High/Medium/Low)
                """
            
            if content_types:
                content_focus = ", ".join(content_types)
                user_prompt += f"\nFocus especially on these aspects: {content_focus}."
            
            user_prompt += f"\n\nSCAN DATA:\n{scan_data}"
            
            # Call OpenAI API
            response = openai.chat.completions.create(
                model=self.openai_model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.1,  # Lower temperature for more factual responses
                max_tokens=2000
            )
            
            # Extract and return analysis content
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            logger.error(f"Error in AI analysis: {str(e)}")
            return f"AI analysis failed: {str(e)}"
    
    def _enhance_parsed_data_from_ai(self, parsed_data, ai_analysis):
        """
        Extract structured data from AI analysis to enhance the parsed results.

        Args:
            parsed_data (dict): The structured data extracted from scan
            ai_analysis (str): The AI-generated analysis

        Returns:
            None (modifies parsed_data in place)
        """
        # Extract structured data from AI-generated analysis

        # 1. Extract CVEs if any new ones are mentioned
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        cve_matches = re.findall(cve_pattern, ai_analysis)

        # Add any new CVEs to vulnerabilities
        existing_cves = set()
        for vuln in parsed_data.get('vulnerabilities', []):
            if 'cve' in vuln:
                existing_cves.add(vuln['cve'])

        # Add new vulnerabilities from CVEs found
        for cve in cve_matches:
            if cve not in existing_cves:
                # Find the surrounding context
                context_pattern = r'.{0,100}' + re.escape(cve) + r'.{0,100}'
                context_match = re.search(context_pattern, ai_analysis)

                context = context_match.group(0) if context_match else ""

                # Create a new vulnerability entry
                new_vuln = {
                    'name': f"Potential issue: {cve}",
                    'description': context.strip(),
                    'cve': cve,
                    'verified': False,
                    'source': 'AI detection',
                    'severity': 'high',  # Default to high for CVEs
                    'affected_component': 'Unknown'
                }

                parsed_data.setdefault('vulnerabilities', []).append(new_vuln)

        # 2. Extract web directories
        web_dir_patterns = [
            r'(?:Directory|Path|URL):\s*/(\S+)',
            r'(?:discovered|found|identified)\s+(?:directory|folder|path).*?[:/](\S+)',
            r'/(\w+(?:/\w+)*)\s+\(Status:\s+\d+\)'
        ]

        for pattern in web_dir_patterns:
            matches = re.findall(pattern, ai_analysis, re.IGNORECASE)
            for match in matches:
                dir_path = f"/{match.strip('/')}"

                # Check if this directory is already in the results
                if not any(d.get('path') == dir_path for d in parsed_data.get('web_directories', [])):
                    parsed_data.setdefault('web_directories', []).append({
                        'path': dir_path,
                        'status_code': '200',  # Default status code
                        'type': 'directory' if not '.' in dir_path.split('/')[-1] else 'file',
                        'source': 'AI detection'
                    })

        # 3. Extract remote files
        remote_file_patterns = [
            r'(?:Remote file|File found|Remote access).*?[:/](\S+)',
            r'(?:NFS|SMB|FTP).*?(?:shared|exported|accessible).*?[:/](\S+)',
            r'(?:file system|filesystem).*?(?:found|discovered|exposed).*?[:/](\S+)'
        ]

        for pattern in remote_file_patterns:
            matches = re.findall(pattern, ai_analysis, re.IGNORECASE)
            for match in matches:
                file_path = f"/{match.strip('/')}"

                # Check if this file is already in the results
                if not any(f.get('path') == file_path for f in parsed_data.get('remote_files', [])):
                    parsed_data.setdefault('remote_files', []).append({
                        'path': file_path,
                        'type': 'directory' if not '.' in file_path.split('/')[-1] else 'file',
                        'permissions': 'unknown',
                        'source': 'AI detection'
                    })

        # 4. Extract subdomains
        subdomain_patterns = [
            r'(?:Subdomain|Domain):\s*(\S+\.\S+)',
            r'(?:discovered|found|identified)\s+(?:subdomain|domain).*?(\w+\.\w+\.\w+)',
            r'(?:subdomain).*?(\w+\.\w+\.\w+)'
        ]

        for pattern in subdomain_patterns:
            matches = re.findall(pattern, ai_analysis, re.IGNORECASE)
            for match in matches:
                # Check if this subdomain is already in the results
                if not any(s.get('name') == match for s in parsed_data.get('subdomains', [])):
                    parsed_data.setdefault('subdomains', []).append({
                        'name': match,
                        'ip': 'unknown',
                        'status': 'active',
                        'source': 'AI detection'
                    })

        # 5. Extract credentials
        credential_patterns = [
            r'(?:Username|User|Login):\s*(\S+).*?(?:Password|Pass):\s*(\S+)',
            r'(?:discovered|found|identified)\s+(?:credential|login|password).*?(\w+):(\S+)',
            r'(?:Default credentials|Plain text credentials).*?(\w+):(\S+)'
        ]

        for pattern in credential_patterns:
            matches = re.findall(pattern, ai_analysis, re.IGNORECASE)
            for match in matches:
                if len(match) >= 2:
                    username, password = match[0], match[1]

                    # Check if these credentials are already in the results
                    if not any(c.get('username') == username and c.get('secret') == password
                              for c in parsed_data.get('credentials', [])):
                        parsed_data.setdefault('credentials', []).append({
                            'type': 'login',
                            'username': username,
                            'secret': password,
                            'source': 'AI detection'
                        })

        # 6. Extract additional vulnerabilities based on keywords
        vulnerability_patterns = [
            r'((?:Critical|High|Medium|Low)\s+(?:risk|severity)\s+vulnerability):?\s*(.*?)(?:\.|$)',
            r'((?:Remote Code Execution|SQL Injection|XSS|CSRF|Authentication Bypass|Directory Traversal|File Inclusion).*?)(?:\.|$)',
            r'((?:Vulnerable to|Affected by).*?)(?:\.|$)'
        ]

        for pattern in vulnerability_patterns:
            matches = re.findall(pattern, ai_analysis, re.IGNORECASE)
            for match in matches:
                if len(match) >= 1:
                    vuln_name = match[0]
                    vuln_desc = match[1] if len(match) > 1 else ""

                    # Determine severity based on the description
                    severity = 'medium'  # Default
                    if re.search(r'critical|severe|remote code|command exec|backdoor', vuln_name.lower()):
                        severity = 'critical'
                    elif re.search(r'high|sql inject|authentica|authoriz|bypass', vuln_name.lower()):
                        severity = 'high'
                    elif re.search(r'medium|moderate|xss|csrf', vuln_name.lower()):
                        severity = 'medium'
                    elif re.search(r'low|info|disclosure', vuln_name.lower()):
                        severity = 'low'

                    # Check if this vulnerability is already in the results
                    if not any(v.get('name') == vuln_name for v in parsed_data.get('vulnerabilities', [])):
                        parsed_data.setdefault('vulnerabilities', []).append({
                            'name': vuln_name,
                            'description': vuln_desc.strip() if vuln_desc else vuln_name,
                            'cve': 'N/A',
                            'verified': False,
                            'severity': severity,
                            'affected_component': 'Unknown',
                            'source': 'AI detection'
                        })
    
    def _categorize_vulnerabilities_with_risk_rules(self, parsed_data):
        """
        Apply risk categorization rules to the parsed data.
        
        Args:
            parsed_data (dict): Structured data from scan
            
        Returns:
            dict: Risk assessment and categorized data
        """
        # Get vulnerabilities and services from parsed data
        vulnerabilities = parsed_data.get('vulnerabilities', [])
        ports_and_services = parsed_data.get('ports_and_services', [])
        
        # Categorize each vulnerability
        for vuln in vulnerabilities:
            severity = categorize_vulnerability(vuln)
            vuln['severity'] = severity
        
        # Categorize each service
        for service in ports_and_services:
            risk_level = categorize_service(service)
            service['risk_level'] = risk_level
        
        # Perform overall risk assessment
        risk_assessment = assess_overall_risk(vulnerabilities, ports_and_services)
        
        # If AI analysis includes a risk assessment, parse and integrate it
        if 'ai_analysis' in parsed_data and parsed_data['ai_analysis']:
            ai_risk = parse_unstructured_risk_assessment(parsed_data['ai_analysis'])
            if ai_risk:
                # Merge AI risk assessment with rule-based assessment
                # giving priority to rule-based critical/high findings
                for category in ['critical', 'high', 'medium', 'low']:
                    # Keep rule-based findings and add unique AI findings
                    ai_findings = ai_risk.get(category, [])
                    if isinstance(ai_findings, list):
                        risk_assessment.setdefault(category, []).extend(
                            [f for f in ai_findings if f not in risk_assessment.get(category, [])]
                        )
                    elif isinstance(ai_findings, str) and ai_findings.strip():
                        # If AI finding is a string, add it if we don't have findings yet
                        if not risk_assessment.get(category):
                            risk_assessment[category] = [ai_findings]
        
        return risk_assessment
    
    def lookup_cve(self, cve_id):
        """
        Look up information about a specific CVE.
        
        Args:
            cve_id (str): The CVE ID to look up
            
        Returns:
            dict: Information about the CVE
        """
        # Here you would implement a lookup to a CVE database or service
        # For now, we'll use a placeholder implementation
        return {
            "id": cve_id,
            "summary": f"Information for {cve_id} would be retrieved from a vulnerability database.",
            "severity": "Unknown",
            "cvss": None,
            "references": []
        }