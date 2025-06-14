#!/usr/bin/env python3
import requests
import csv
import feedparser
import re
import os
import json
import time
import sys
import argparse
from io import StringIO
from bs4 import BeautifulSoup
import html

def clean_text(text):
    """Clean and format text from HTML content"""
    if not text:
        return ""
    
    # Decode HTML entities
    text = html.unescape(text)
    
    # Replace multiple newlines with a single newline
    text = re.sub(r'\n\s*\n', '\n', text)
    
    # Replace multiple spaces with a single space
    text = re.sub(r'\s+', ' ', text)
    
    # Remove leading/trailing whitespace
    text = text.strip()
    
    # Fix spacing around dots in version numbers (e.g., "9. 4" to "9.4")
    text = re.sub(r'(\d)\s*\.\s*(\d)', r'\1.\2', text)
    
    # Normalize spacing after punctuation (but not inside version numbers)
    text = re.sub(r'([.,;:!?])\s*(?!\d)', r'\1 ', text)
    
    # Fix spacing issues
    text = re.sub(r'\s+', ' ', text)
    
    return text

def show_help():
    """Display detailed help information about the vulnerability ID types supported"""
    help_text = """
Penetration Testing Analysis CLI Tool
------------------------------------

This tool helps you retrieve information about various vulnerability identifiers 
commonly encountered in penetration testing reports and security assessments.

USAGE:
    python all.py [OPTIONS]

OPTIONS:
    -h, --help      Show this help message and usage information
    -f, --file      Specify a custom input file (default: vulns.txt)
    -s, --single    Lookup a single vulnerability ID
    
SUPPORTED VULNERABILITY ID FORMATS:

    1. CVE IDs: 
       - Format: CVE-YYYY-NNNNN
       - Example: CVE-2021-44228 (Log4Shell)
       
    2. Exploit-DB IDs:
       - Format: EDB-ID:NNNNN
       - Example: EDB-ID:46874
       
    3. Metasploit Modules:
       - Format: MSF:MODULE-TYPE-SUBTYPES
       - Example: MSF:AUXILIARY-SCANNER-HTTP-APACHE_NORMALIZE_PATH

HOW TO USE:
    1. Create a file (default: vulns.txt) with one vulnerability ID per line
    2. Run the script: python all.py
    3. For a single lookup: python all.py -s CVE-2023-12345

FILE FORMAT EXAMPLE:
    CVE-2021-44228
    EDB-ID:46874
    MSF:AUXILIARY-SCANNER-HTTP-APACHE_NORMALIZE_PATH

NOTE: The script does not handle Vulners references (VN:IDENTIFICATION) at this time.
"""
    print(help_text)
    sys.exit(0)

# Functions for each type

def get_cve_info(cve_id):
    """Get CVE information from NVD using API key if available"""
    # Use NVD API key if available
    api_key = os.environ.get('NVD_API_KEY')
    headers = {'apiKey': api_key} if api_key else {}
    
    # Using the new 2.0 API endpoint which is more reliable
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    
    try:
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            data = r.json()
            if data.get('vulnerabilities') and len(data['vulnerabilities']) > 0:
                vuln = data['vulnerabilities'][0]['cve']
                desc = vuln.get('descriptions', [{}])[0].get('value', 'No description available')
                
                # Get CVSS score if available
                metrics = vuln.get('metrics', {})
                cvss_data = metrics.get('cvssMetricV31', [{}])[0] if 'cvssMetricV31' in metrics else \
                           metrics.get('cvssMetricV30', [{}])[0] if 'cvssMetricV30' in metrics else \
                           metrics.get('cvssMetricV2', [{}])[0] if 'cvssMetricV2' in metrics else {}
                
                base_score = cvss_data.get('cvssData', {}).get('baseScore', 'N/A')
                severity = cvss_data.get('cvssData', {}).get('baseSeverity', 'N/A')
                
                cvss_info = f" (CVSS: {base_score}, Severity: {severity})" if base_score != 'N/A' else ""
                
                return {"title": cve_id + cvss_info, "description": desc}
            return {"error": "No vulnerability data found"}
        return {"error": f"API Error: {r.status_code}"}
    except Exception as e:
        return {"error": f"Error fetching CVE info: {str(e)}"}

def get_edb_info(edb_id):
    """Get ExploitDB information by ID"""
    # Clean up the ID in case it has spaces or colons
    edb_id = edb_id.strip()
    
    # Function to format the final output for consistency
    def format_final_output(title, description):
        # Ensure we have clean, consistent output
        cleaned_title = clean_text(title)
        
        # For descriptions, perform more aggressive cleaning
        if description:
            # Remove any HTML or markdown formatting
            cleaned_desc = re.sub(r'<[^>]+>', '', description)
            
            # Normalize whitespace
            cleaned_desc = re.sub(r'\s+', ' ', cleaned_desc)
            
            # Replace multiple newlines with a single space
            cleaned_desc = re.sub(r'\n+', ' ', cleaned_desc)
            
            # Fix spacing around dots in version numbers
            # This handles cases like "9. 4" -> "9.4" as well as "9 . 4" -> "9.4"
            cleaned_desc = re.sub(r'(\d)\s*\.\s*(\d)', r'\1.\2', cleaned_desc)
            
            # Fix for complex version numbers with multiple dots (e.g., "9. 4-0. 5. 3" -> "9.4-0.5.3")
            cleaned_desc = re.sub(r'(\d+)\s*\.\s*(\d+)(?:-\s*\d+\s*\.\s*\d+\s*\.\s*\d+)', 
                                  lambda m: m.group(0).replace(' ', ''), cleaned_desc)
            
            # Remove redundant spaces around punctuation
            cleaned_desc = re.sub(r'\s*([.,;:!?])\s*', r'\1 ', cleaned_desc)
            
            # Clean up any remaining issues
            cleaned_desc = cleaned_desc.strip()
            
            # Ensure description doesn't start with redundant title text
            if cleaned_desc.lower().startswith(cleaned_title.lower()):
                cleaned_desc = cleaned_desc[len(cleaned_title):].strip()
                if cleaned_desc.startswith('-'):
                    cleaned_desc = cleaned_desc[1:].strip()
                
            # If the description is still too short or empty, skip this result
            if not cleaned_desc or len(cleaned_desc) < 20:
                return {"error": ""}
        
        # Return the formatted result
        return {"title": cleaned_title, "description": cleaned_desc}
    
    try:
        # Try the most direct API first
        direct_api_url = f"https://www.exploit-db.com/api/v1/exploits/{edb_id}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'application/json'
        }
        
        try:
            r = requests.get(direct_api_url, headers=headers)
            if r.status_code == 200:
                try:
                    api_data = r.json()
                    if 'data' in api_data:
                        exploit_data = api_data['data'][0] if api_data['data'] else None
                        if exploit_data:
                            # Extract comprehensive information
                            title = exploit_data.get('title', f"EDB-ID:{edb_id}")
                            desc_parts = []
                            
                            # Add description if available
                            if 'description' in exploit_data and exploit_data['description']:
                                desc_parts.append(exploit_data['description'])
                            
                            # Add additional metadata
                            if 'app' in exploit_data and exploit_data['app']:
                                desc_parts.append(f"Application: {exploit_data['app']}")
                                
                            if 'author' in exploit_data and exploit_data['author']:
                                desc_parts.append(f"Author: {exploit_data['author']}")
                                
                            if 'date' in exploit_data and exploit_data['date']:
                                desc_parts.append(f"Date: {exploit_data['date']}")
                                
                            if 'platform' in exploit_data and exploit_data['platform']:
                                desc_parts.append(f"Platform: {exploit_data['platform']}")
                                
                            if 'type' in exploit_data and exploit_data['type']:
                                desc_parts.append(f"Type: {exploit_data['type']}")
                                
                            # Get any CVEs  
                            if 'cve' in exploit_data and exploit_data['cve']:
                                cves = [cve.strip() for cve in exploit_data['cve'].split(',')]
                                desc_parts.append(f"CVE: {', '.join(cves)}")
                                
                            description = " | ".join(desc_parts)
                            return format_final_output(title, description)
                except:
                    # If JSON parsing fails, continue with other methods
                    pass
        except:
            # Continue with other methods if API request fails
            pass
            
        # Using Offensive Security's ExploitDB CSV database
        url = "https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv"
        r = requests.get(url)
        if r.status_code == 200:
            csvfile = StringIO(r.text)
            reader = csv.DictReader(csvfile)
            for row in reader:
                if row['id'] == str(edb_id):
                    desc = row['description']
                    return format_final_output(f"EDB-ID:{edb_id}", desc)
        
        # If not found in the CSV, try the Offensive Security JSON API
        alt_url = "https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.json"
        r = requests.get(alt_url)
        if r.status_code == 200:
            data = r.json()
            for entry in data:
                if str(entry.get('id')) == str(edb_id):
                    desc = entry.get('description', 'No description available')
                    return format_final_output(f"EDB-ID:{edb_id}", desc)
        
        # Try the alternate Offensive Security format (files.csv)
        alt_url2 = "https://raw.githubusercontent.com/offensive-security/exploitdb/master/files.csv"
        r = requests.get(alt_url2)
        if r.status_code == 200:
            csvfile = StringIO(r.text)
            reader = csv.DictReader(csvfile)
            for row in reader:
                if row.get('id') == str(edb_id):
                    desc = row.get('description', 'No description available')
                    return format_final_output(f"EDB-ID:{edb_id}", desc)
        
        # If still not found, try searching the Exploit-DB website directly
        # First try the direct URL
        exploit_url = f"https://www.exploit-db.com/exploits/{edb_id}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        r = requests.get(exploit_url, headers=headers)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'html.parser')
            
            # Extract the title from the h1 tag with class card-title
            title_elem = soup.find('h1', class_='card-title')
            
            # Try to get a better description:
            desc = ""
            
            # Extract the primary description from the text that appears after "Description" in the content section
            desc_section = soup.select_one('.detail-content-wrapper')
            if desc_section:
                # First try to find the Description h2 header specifically
                desc_header = desc_section.find('h2', string='Description')
                
                # If no specific Description header, try any content block
                if not desc_header:
                    desc_parts = []
                    # Look for paragraphs with substantial content
                    paragraphs = desc_section.find_all('p')
                    for p in paragraphs:
                        if p and p.text and len(p.text.strip()) > 20:  # Only paragraphs with meaningful content
                            desc_parts.append(p.text)
                    
                    if desc_parts:
                        desc = clean_text(" ".join(desc_parts))
                else:
                    # Get all content after the "Description" header
                    all_content = []
                    current = desc_header.next_sibling
                    
                    # Collect all relevant content until the next header
                    while current and (not isinstance(current, type(desc_header)) or current.name != 'h2'):
                        if hasattr(current, 'get_text'):
                            text = current.get_text()
                            if text.strip():
                                all_content.append(text)
                        elif isinstance(current, str) and current.strip():
                            all_content.append(current)
                        
                        if not current.next_sibling:
                            break
                        current = current.next_sibling
                    
                    if all_content:
                        raw_desc = " ".join(all_content)
                        desc = clean_text(raw_desc)
            
            # If we didn't find a description in the main content, try the metadata table
            if not desc:
                # Build a comprehensive description from metadata
                metadata = []
                
                # Get application details
                app_desc = soup.select_one('th:-soup-contains("Application") + td')
                if app_desc:
                    metadata.append(f"Application: {clean_text(app_desc.get_text())}")
                
                # Get vulnerability type
                vuln_type = soup.select_one('th:-soup-contains("Vulnerabilities") + td')
                if vuln_type:
                    metadata.append(f"Vulnerability: {clean_text(vuln_type.get_text())}")
                
                # Get author information
                author = soup.select_one('th:-soup-contains("Author") + td')
                if author:
                    metadata.append(f"Author: {clean_text(author.get_text())}")
                
                # Get platform information
                platform = soup.select_one('th:-soup-contains("Platform") + td')
                if platform:
                    metadata.append(f"Platform: {clean_text(platform.get_text())}")
                
                # Get date information
                date_elem = soup.select_one('th:-soup-contains("Date") + td')
                if date_elem:
                    metadata.append(f"Date: {clean_text(date_elem.get_text())}")
                    
                # Get verified status
                verified_elem = soup.select_one('th:-soup-contains("Verified") + td')
                if verified_elem:
                    metadata.append(f"Verified: {clean_text(verified_elem.get_text())}")
                    
                # Get CVE references directly from the table
                cve_elem = soup.select_one('th:-soup-contains("CVE") + td')
                if cve_elem:
                    cve_text = clean_text(cve_elem.get_text())
                    if cve_text and cve_text.lower() != "n/a":
                        metadata.append(f"CVE: {cve_text}")
                
                if metadata:
                    desc = " | ".join(metadata)
            
            # If we still don't have a description, try to extract from the code view
            if not desc:
                code_view = soup.select_one('#code-view pre')
                if code_view:
                    code_text = code_view.get_text()
                    # Look for comments at the beginning of the code that might contain description
                    if code_text:
                        lines = code_text.split('\n')[:15]  # Get more lines for better context
                        comment_lines = [line for line in lines if line.strip().startswith('#') or 
                                        line.strip().startswith('//') or 
                                        line.strip().startswith('/*') or 
                                        line.strip().startswith('*') or
                                        'description' in line.lower() or
                                        'vulnerability' in line.lower()]
                        
                        comment_text = ' '.join(comment_lines)
                        if comment_text:
                            desc = clean_text(comment_text)
                            
                        # If we couldn't find comments, try to extract some code that might be descriptive
                        # like function signatures or classes that explain the exploit
                        if not desc and len(lines) > 5:
                            # Extract function declarations or class definitions that might be informative
                            code_summary = []
                            for line in lines:
                                if any(keyword in line.lower() for keyword in ['def ', 'class ', 'function', 'exploit', 'vulnerability']):
                                    code_summary.append(line.strip())
                            if code_summary:
                                desc = clean_text(" | ".join(code_summary))
            
            # If we still don't have anything, try to get title and associated CVEs
            if not desc:
                if title_elem:
                    desc = clean_text(title_elem.get_text())
                
                # Add any CVE references
                cve_elems = soup.select('a[href*="cve"]')
                if cve_elems:
                    cves = []
                    for cve in cve_elems:
                        cve_text = clean_text(cve.get_text())
                        # Ensure it's an actual CVE ID format
                        if re.match(r'CVE-\d{4}-\d+', cve_text):
                            cves.append(cve_text)
                    if cves:
                        desc += f" Associated with {', '.join(cves)}."
            
            # If we still have nothing, try to extract any text from the page
            if not desc:
                desc_elem = soup.find('div', class_='card-body')
                if desc_elem:
                    # Remove script and style elements
                    for script in desc_elem(["script", "style"]):
                        script.decompose()
                    
                    # Extract text with proper formatting
                    extracted_text = desc_elem.get_text(separator=' ', strip=True)
                    desc = clean_text(extracted_text)
            
            # Limit description length but ensure it's not cut mid-sentence
            if len(desc) > 300:
                # Try to cut at the end of a sentence
                cut_point = desc[:300].rfind('.')
                if cut_point > 200:  # Only use sentence break if it's not too short
                    desc = desc[:cut_point+1] + "..."
                else:
                    # Otherwise cut at the word boundary
                    cut_point = desc[:300].rfind(' ')
                    desc = desc[:cut_point] + "..."
            
            if title_elem:
                title = title_elem.get_text()
                return format_final_output(f"EDB-ID:{edb_id} - {title}", desc)
            
        # Try the search functionality on Exploit-DB
        search_url = f"https://www.exploit-db.com/?id={edb_id}"
        r = requests.get(search_url, headers=headers)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'html.parser')
            results = soup.find_all('a', class_='text-dark')
            for result in results:
                if str(edb_id) in result.get('href', ''):
                    result_text = result.text
                    return format_final_output(f"EDB-ID:{edb_id}", f"Found via search: {result_text}")
                    
    except Exception as e:
        return {"error": f"Error fetching EDB info: {str(e)}"}
    
    # Return an error for fallback rather than a generic message
    return {"error": ""}

# PACKETSTORM functionality completely removed

# Function to get impact based on vulnerability type
def get_vuln_impact(vuln_type):
    """Return standardized impact description based on vulnerability type"""
    vuln_type = vuln_type.lower()
    
    impacts = {
        "privilege escalation": "gain elevated access to restricted resources or execute commands with higher privileges than intended",
        "sql injection": "access or manipulate database content, potentially leading to data theft or modification",
        "xss": "execute malicious scripts in users' browsers and potentially steal sensitive information or sessions",
        "cross-site scripting": "execute malicious scripts in users' browsers and potentially steal sensitive information or sessions",
        "remote code execution": "execute arbitrary commands on the target system, potentially gaining complete control",
        "rce": "execute arbitrary commands on the target system, potentially gaining complete control",
        "information disclosure": "access sensitive data that should be protected, such as passwords, personal information, or configuration details",
        "denial of service": "disrupt normal functioning of the target system, making it unavailable to legitimate users",
        "authentication bypass": "access restricted areas without valid credentials, bypassing authentication mechanisms",
        "directory traversal": "access files and directories stored outside the intended directory path",
        "memory corruption": "manipulate program memory, potentially leading to arbitrary code execution or application crashes",
        "buffer overflow": "overwrite memory buffers and potentially execute arbitrary code or crash the application",
        "command injection": "execute arbitrary commands on the host operating system through a vulnerable application",
        "csrf": "trick authenticated users into performing unintended actions without their knowledge",
        "xxe": "access local files, perform server-side request forgery, or execute remote code via XML processing vulnerabilities"
    }
    
    # Find the closest match in our impact dictionary
    for key, impact in impacts.items():
        if key in vuln_type:
            return impact
    
    # Default impact description
    return "exploit the vulnerability to compromise system security or data integrity"

def search_msf(msf_name):
    """Get Metasploit module information with enhanced description extraction"""
    try:
        # Save the original input for reference
        original_input = msf_name
        
        # Clean up module name by removing MSF: prefix for searching
        had_prefix = msf_name.startswith("MSF:")
        msf_name = msf_name.replace("MSF:", "").strip()
        
        # Handle modules with trailing dash
        has_trailing_dash = msf_name.endswith('-')
        if has_trailing_dash:
            msf_name = msf_name.rstrip('-')
        
        # We'll retrieve all information dynamically instead of using hardcoded entries

        # Try to get info from Rapid7 GitHub repo
        module_parts = msf_name.lower().split("-")
        if len(module_parts) >= 2:
            module_type = module_parts[0]  # e.g., auxiliary, exploit
            
            # Build Github URL based on module type and path
            base_url = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/modules"
            
            # Try different path variations
            paths_to_try = []
            
            # Original path
            module_path = "/".join(module_parts[1:])
            paths_to_try.append(module_path)
            
            # Alternative path structures - try both dashes and underscores
            if len(module_parts) > 2:
                alt_path = module_parts[1] + "/" + "_".join(module_parts[2:])
                paths_to_try.append(alt_path)
                
                # Try with folders separated by / and internal words with underscores
                alt_path2 = "/".join([p.replace("-", "_") for p in module_parts[1:]])
                paths_to_try.append(alt_path2)
                
                # Try with folders with fixed names for scanner modules
                if module_type == "auxiliary" and module_parts[1] == "scanner":
                    scanner_type = module_parts[2] if len(module_parts) > 2 else ""
                    remaining_parts = "_".join(module_parts[3:]) if len(module_parts) > 3 else ""
                    alt_path3 = f"scanner/{scanner_type}/{remaining_parts}"
                    paths_to_try.append(alt_path3)
            
            # For each path variant, try with and without .rb extension
            for path in paths_to_try:
                urls = [
                    f"{base_url}/{module_type}/{path}.rb",
                    f"{base_url}/{module_type}/{path}"
                ]
                
                for url in urls:
                    try:
                        r = requests.get(url, timeout=3)
                        if r.status_code == 200:
                            # Comprehensive extraction of module information
                            module_info = []
                            
                            # Try to extract name, description, author, references, and CVEs
                            desc_match = re.search(r"['\"]Description['\"].*?=>.*?['\"]([^'\"]+)['\"]", r.text, re.DOTALL)
                            if desc_match:
                                desc = desc_match.group(1).strip()
                                module_info.append(desc)
                            
                            # Extract author information
                            author_match = re.search(r"['\"]Author['\"].*?\[(.*?)\]", r.text, re.DOTALL)
                            if author_match:
                                authors_text = author_match.group(1).strip()
                                authors = re.findall(r"['\"]([^'\"]+)['\"]", authors_text)
                                if authors:
                                    module_info.append(f"Authors: {', '.join(authors)}")
                            
                            # Extract CVE references
                            cve_matches = re.findall(r"['\"]CVE['\"],\s*['\"](\d{4}-\d+)['\"]", r.text)
                            if cve_matches:
                                cves = [f"CVE-{cve}" for cve in cve_matches]
                                module_info.append(f"CVEs: {', '.join(cves)}")
                                
                            # Extract disclosure date
                            date_match = re.search(r"['\"]DisclosureDate['\"].*?['\"]([^'\"]+)['\"]", r.text)
                            if date_match:
                                module_info.append(f"Disclosed: {date_match.group(1).strip()}")
                                
                            # If we have a good description, return it
                            if module_info:
                                title = "MSF:" + msf_name
                                return {"title": title, "description": " | ".join(module_info)}
                            
                            # If not, but we found the file, at least return the name
                            name_match = re.search(r"['\"]Name['\"].*?=>.*?['\"]([^'\"]+)['\"]", r.text, re.DOTALL)
                            if name_match:
                                name = name_match.group(1).strip()
                                title = "MSF:" + msf_name
                                # Only return if the name is substantial
                                if name and len(name) > 10:
                                    return {"title": title, "description": f"Metasploit module: {name}"}
                                else:
                                    return {"error": ""}
                    except:
                        continue
        
        # Try searching the Metasploit GitHub repo
        search_terms = [msf_name]
        if had_prefix:
            search_terms.append(msf_name.rstrip('-'))
            
        for search_term in search_terms:
            search_url = f"https://github.com/search?q=repo%3Arapid7%2Fmetasploit-framework+{search_term}&type=code"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            try:
                r = requests.get(search_url, headers=headers, timeout=3)
                if r.status_code == 200:
                    soup = BeautifulSoup(r.text, 'html.parser')
                    
                    # Look for code snippets
                    code_results = soup.find_all('div', class_='js-file-line-container')
                    if code_results and len(code_results) > 0:
                        for code_result in code_results:
                            code_text = code_result.get_text(strip=True)
                            # Look for description text in the code snippet
                            if "Description" in code_text and "=>" in code_text:
                                desc_match = re.search(r"Description.*?=>.*?['\"]([^'\"]+)['\"]", code_text)
                                if desc_match:
                                    title = "MSF:" + msf_name
                                    return {"title": title, "description": desc_match.group(1).strip()}
                    
                    # If no code snippet with description, look for file names
                    file_results = soup.find_all('div', class_='f4 text-normal')
                    if file_results and len(file_results) > 0:
                        title = "MSF:" + msf_name
                        for result in file_results:
                            # Try to extract useful info from file path
                            filepath = result.text.strip()
                            if filepath:
                                # Parse the filepath to get module information
                                path_parts = filepath.split('/')
                                if len(path_parts) >= 4 and 'modules' in path_parts:
                                    module_idx = path_parts.index('modules')
                                    if len(path_parts) > module_idx + 2:
                                        module_type = path_parts[module_idx + 1]  # e.g., auxiliary
                                        module_function = path_parts[-1].replace('.rb', '')  # e.g., apache_optionsbleed
                                        return {"title": title, "description": f"Metasploit {module_type} module for {module_function.replace('_', ' ')}. Found in file path: {filepath}"}
                                
                                # Return error for generic information with no details
                                return {"error": ""}
            except:
                continue
                
        # Parse module name for additional context
        if module_parts:
            module_description_parts = []
            
            # Determine module type
            if module_parts[0].lower() == 'auxiliary':
                module_description_parts.append("Auxiliary module")
            elif module_parts[0].lower() == 'exploit':
                module_description_parts.append("Exploit module")
            elif module_parts[0].lower() == 'post':
                module_description_parts.append("Post-exploitation module")
            
            # Determine functionality
            if len(module_parts) > 1:
                if module_parts[1].lower() == 'scanner':
                    module_description_parts.append("for scanning")
                elif module_parts[1].lower() == 'dos':
                    module_description_parts.append("for denial-of-service")
                    
            # Add target information
            if len(module_parts) > 2:
                module_description_parts.append(f"targeting {module_parts[2].upper()}")
                
            # Extract vulnerability/feature
            if len(module_parts) > 3:
                vuln_name = "_".join(module_parts[3:]).upper()
                vuln_name = vuln_name.replace('_', ' ')
                module_description_parts.append(f"for {vuln_name}")
                
            if module_description_parts:
                title = "MSF:" + msf_name
                return {"title": title, "description": " ".join(module_description_parts) + ". This is a Metasploit Framework module."}
    
    except Exception as e:
        return {"error": f"Error fetching MSF info: {str(e)}"}
    
    # Fallback with better contextual information based on the module name
    title = "MSF:" + msf_name
    
    # Extract meaningful information from the module name
    parts = msf_name.split('-')
    if len(parts) >= 2:
        module_type = parts[0].lower()  # auxiliary, exploit, post, etc.
        module_subtype = parts[1].lower() if len(parts) > 1 else ""
        target = parts[2].lower() if len(parts) > 2 else ""
        vuln_name = "_".join(parts[3:]) if len(parts) > 3 else ""
        
        desc_parts = []
        
        # Describe the module type
        if module_type == "auxiliary":
            desc_parts.append("Auxiliary module (used for scanning, probing, or testing)")
        elif module_type == "exploit":
            desc_parts.append("Exploit module (used to execute attacks on vulnerable systems)")
        elif module_type == "post":
            desc_parts.append("Post-exploitation module (used after gaining initial access)")
        else:
            desc_parts.append(f"{module_type.capitalize()} module")
            
        # Describe the subtype
        if module_subtype == "scanner":
            desc_parts.append("for scanning and identifying vulnerabilities")
        elif module_subtype == "dos":
            desc_parts.append("for denial-of-service testing")
        elif module_subtype == "fuzzer":
            desc_parts.append("for fuzzing and discovering input vulnerabilities")
        
        # Describe the target
        if target:
            if target in ["http", "https", "ftp", "ssh", "smb", "smtp", "imap", "ldap"]:
                desc_parts.append(f"targeting {target.upper()} protocol")
            else:
                desc_parts.append(f"targeting {target}")
        
        # Describe the vulnerability
        if vuln_name:
            readable_vuln = vuln_name.replace("_", " ").title()
            desc_parts.append(f"exploiting {readable_vuln}")
        
        # Build the final description
        if desc_parts:
            return {"title": title, "description": " ".join(desc_parts) + "."}
    
    # Return an error rather than a generic message
    return {"error": ""}


def detect_and_search(vuln_id):
    """Detect vulnerability ID type and search for information"""
    vuln_id = vuln_id.strip()

    # CVE identifiers
    if re.match(r'^CVE-\d{4}-\d+$', vuln_id):
        result = get_cve_info(vuln_id)
        # Check if content is useful
        if "description" in result and len(result["description"]) < 30:
            return {"error": ""}
        return result

    # PostgreSQL prefixed CVEs
    elif vuln_id.startswith("POSTGRESQL:CVE-"):
        cve = vuln_id.replace("POSTGRESQL:", "")
        result = get_cve_info(cve)
        # Check if content is useful
        if "description" in result and len(result["description"]) < 30:
            return {"error": ""}
        return result

    # ExploitDB identifiers
    elif vuln_id.startswith("EDB-ID:"):
        edb = vuln_id.split(":")[1].strip()  # Ensure clean ID
        result = get_edb_info(edb)
        # Check if content is useful
        if "description" in result and len(result["description"]) < 30:
            return {"error": ""}
        return result

    # Metasploit identifiers
    elif vuln_id.startswith("MSF:"):
        result = search_msf(vuln_id)
        # Check if content is useful
        if "description" in result and len(result["description"]) < 30:
            return {"error": ""}
        return result

    # PacketStorm identifiers - completely skip in this module
    elif vuln_id.startswith("PACKETSTORM:"):
        return {"error": ""}

    # Unknown format
    else:
        return {"error": ""}

def main(input_file="vulns.txt"):
    """Main function to process vulnerability IDs from input file"""
    # Check if file exists
    if not os.path.exists(input_file):
        print(f"[!] Error: Input file '{input_file}' not found")
        return
    
    print(f"[*] Processing vulnerability IDs from {input_file}...\n")
    
    results_summary = {"success": 0, "error": 0, "total": 0}
    
    with open(input_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("//"):  # Skip empty lines and comments
                continue
                
            print(f"[*] Looking up: {line}")
            result = detect_and_search(line)
            
            results_summary["total"] += 1
            
            if "error" not in result and result.get("title") and result.get("description"):
                results_summary["success"] += 1
                print(f"[+] {result['title']}\n    {result['description']}\n")
            else:
                results_summary["error"] += 1
                # Skip output for errors - silent fail
            
            # Add a small delay to avoid hitting rate limits
            time.sleep(0.5)
    
    # Print summary
    print("\n[*] Summary:")
    print(f"    Total vulnerabilities processed: {results_summary['total']}")
    print(f"    Successfully retrieved: {results_summary['success']}")
    print(f"    Failed to retrieve: {results_summary['error']}")

if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Penetration Testing Analysis CLI Tool')
    parser.add_argument('-f', '--file', type=str, help='Input file with vulnerability IDs (one per line)')
    parser.add_argument('-s', '--single', type=str, help='Lookup a single vulnerability ID')
    parser.add_argument('input_file', nargs='?', help='Input file with vulnerability IDs (alternative to -f)')
    
    args = parser.parse_args()
    
    # Show help if requested
    if (args.file and args.file == "help") or (args.single and args.single == "help"):
        show_help()
    
    # Determine which input file to use
    file_path = None
    if args.file:
        file_path = args.file
    elif args.input_file:
        file_path = args.input_file
    else:
        file_path = "vulns.txt"
    
    # If single lookup requested, perform the lookup and exit
    if args.single:
        vuln_id = args.single
        result = detect_and_search(vuln_id)
        if "error" not in result and result.get("title") and result.get("description"):
            print(f"[+] {result['title']}")
            print(f"    {result['description']}")
        # Silent fail if no results
        sys.exit(0)
    
    # Proceed with processing the input file
    main(file_path)