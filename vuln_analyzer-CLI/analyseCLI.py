#!/usr/bin/env python3
import sys
import re
from datetime import datetime
import os
import subprocess
import json
import requests
from collections import defaultdict
import importlib.util
import argparse
from io import StringIO

# Try to import the helper modules
try:
    # Define paths to helper scripts
    script_dir = os.path.dirname(os.path.abspath(__file__))
    vulns_titels_path = os.path.join(script_dir, "vulns_titels.py")
    vulners_titles_path = os.path.join(script_dir, "vulners_titles.py")
    
    # Import vulns_titels.py as a module
    if os.path.exists(vulns_titels_path):
        spec = importlib.util.spec_from_file_location("vulns_titels", vulns_titels_path)
        vulns_titels = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(vulns_titels)
    
    # Import vulners_titles.py as a module
    if os.path.exists(vulners_titles_path):
        spec = importlib.util.spec_from_file_location("vulners_titles", vulners_titles_path)
        vulners_titles = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(vulners_titles)
except Exception as e:
    print(f"Warning: Failed to import helper modules: {str(e)}")

# Define constants for report engines
ENGINE_REGULAR = "regular"
ENGINE_VULNERS = "vulners"
DEFAULT_ENGINE = ENGINE_REGULAR


def extract_ports(output):
    if output:
        port_info_dict = {}  # Using a dictionary with port as key to handle duplicates
        lines = output.split("\n")
        for line in lines:
            if "open" in line and not line.strip().startswith("Warning"):
                match = re.search(
                    r"(\d+)/tcp\s+open\s+(\S+)(?:\s+(.*))?", line)
                if match:
                    port = match.group(1)
                    service = match.group(2)
                    version = match.group(3) if match.group(3) is not None else ''
                    
                    # If we already have this port and the new entry has version info, update it
                    if port in port_info_dict:
                        if version and not port_info_dict[port][2]:
                            port_info_dict[port] = [port, service, version]
                    else:
                        # First time seeing this port
                        port_info_dict[port] = [port, service, version]
        
        # Convert dictionary to list for return
        port_info_list = list(port_info_dict.values())
        return port_info_list
    else:
        return None

def extract_domain(text):
    if text:
        match = re.search(r"Domain:\s*([^,\s]+)", text, re.IGNORECASE)
        if match:
            return match.group(1)
    else:
        return None
    
def extract_dns_domain(text):
    if text:
        match = re.search(r"DNS_Domain_Name:\s*([^,\s]+)", text, re.IGNORECASE)
        if match:
            return match.group(1)
    else:
        return None
    
def extract_dns_computer(text):
    if text:
        match = re.search(r"DNS_Computer_Name:\s*([^,\s]+)", text, re.IGNORECASE)
        if match:
            return match.group(1)
    else:
        return None

def extract_nb_domain(text):
    if text:
    # Adjusted regular expression to handle variable spacing and ensure capture until end of line
        match = re.search(r"NetBIOS_Domain_Name:\s*([^\r\n]+)", text, re.IGNORECASE)
        if match:
            # Adding a strip to remove any trailing whitespace characters
            return match.group(1).strip()
    else:
        return None


def extract_target_name(text):
    if text:
        match = re.search(r"Target_Name:\s*([^,\s]+)", text, re.IGNORECASE)
        if match:
            return match.group(1)
    else:
        return None
    
    
def extract_computer_name(text):
    if text:
        match = re.search(r"Computer_Name:\s*([^,\s]+)", text, re.IGNORECASE)
        if match:
            return match.group(1)
    else:
        return None

def extract_os_details(nmap_output):
    if nmap_output:
        # First, try to find the 'OS details' line
        os_details_pattern = r'OS details: (.*)'
        os_details_match = re.search(os_details_pattern, nmap_output)

        if os_details_match:
            os_details = os_details_match.group(1)
            # Regular expression to extract OS name and version
            match = re.search(r'([a-zA-Z ]+) (\d+(\.\d+)?( - \d+(\.\d+)?)?)', os_details)
            if match:
                return [match.group(1).strip(), match.group(2).strip()]
        else:
            # If 'OS details' line isn't found or doesn't match, try 'Operating System' line
            os_details_pattern = r'Operating System: (.*)'
            os_details_match = re.search(os_details_pattern, nmap_output)

            if os_details_match:
                os_details = os_details_match.group(1)
                match = re.search(r'([a-zA-Z ]+) (\d+(\.\d+)?( - \d+(\.\d+)?)?)', os_details)
                if match:
                    return [match.group(1).strip(), match.group(2).strip()]
            else:
                # If 'Operating System' line isn't found, look for aggressive OS guesses
                aggressive_guesses_pattern = r'Aggressive OS guesses: ([^,]+),'
                aggressive_guesses_match = re.search(aggressive_guesses_pattern, nmap_output)

                if aggressive_guesses_match:
                    first_guess = aggressive_guesses_match.group(1)
                    match = re.search(r'([a-zA-Z ]+) (\d+(\.\d+)?( - \d+(\.\d+)?)?)', first_guess)
                    if match:
                        return [match.group(1).strip(), match.group(2).strip()]
                else:
                    # If no guesses found, check for a direct 'OS' line
                    os_pattern = r'OS: ([^;]+);'
                    os_match = re.search(os_pattern, nmap_output)
                    if os_match:
                        os_name = os_match.group(1).strip()
                        return [os_name, ""]  # The version is not specified directly in this case
    else:
        return None

 
def extract_smb_oscomp(nmap_output):
    os_info = {}
    # Adjusted pattern to match the output format
    os_pattern = r"\|\s*smb-os-discovery:\s*(.*?)\n\n"
    os_match = re.search(os_pattern, nmap_output, re.DOTALL)
    if os_match:
        os_details = os_match.group(1)
        # Adjusted pattern to match the output format for Computer name

        comp_name_match = re.search(r"\|\s*Computer name:\s*([^\r\n]+)", os_details)
        if comp_name_match:
            os_info['Computer name'] = comp_name_match.group(1).strip()

        # Adjusted pattern to match the output format for Domain name
        domain_name_match = re.search(r"\|\s*Domain name:\s*([^\\]+)", os_details)
        if domain_name_match:
            os_info['Domain name'] = domain_name_match.group(1).strip()

        # Return the structured data
        return {'OS_Info': os_info}
    return None
    
def parse_ftp_nmap_results(nmap_output):
    if nmap_output:
        lines = nmap_output.split('\n')
        files = []
        anon_login = "Not Allowed"
        in_ftp_section = False
        
        for line in lines:
            # Check if we're entering an FTP section (condition 1)
            if '21/tcp' in line or ('open' in line and 'ftp' in line):
                in_ftp_section = True
                
            # Check for anonymous login allowed
            if in_ftp_section and 'ftp-anon:' in line and "Anonymous FTP login allowed" in line:
                anon_login = "Allowed"
                
            # Look for file listings (condition 2)
            # Unix-style permission pattern at start of line
            if in_ftp_section and (line.strip().startswith('|') or line.strip().startswith('|_')):
                parts = line.strip().split()
                
                # Check if second part starts with Unix-style permission pattern
                if len(parts) >= 2:
                    # Handle both "| -rw-r--r--" and "|_-rw-r--r--" cases
                    perm_candidate = ""
                    filename_parts = []
                    
                    if parts[0] == '|' and len(parts) >= 3:
                        # Format: | -rw-r--r-- filename
                        perm_candidate = parts[1]
                        filename_parts = parts[2:]
                    elif parts[0].startswith('|_'):
                        # Format: |_-rw-r--r-- filename
                        perm_candidate = parts[0][2:]  # Remove |_ prefix
                        filename_parts = parts[1:]
                    
                    # Check if this looks like a permission string
                    if re.match(r'[-d][rwx-]{9}', perm_candidate):
                        permissions = perm_candidate
                        filename = ' '.join(filename_parts).strip()
                        
                        # Only add if we have a valid filename
                        if filename and not filename.startswith('Total'):
                            files.append({'permissions': permissions, 'filename': filename})
            
            # Exit FTP section when we reach a new port
            if in_ftp_section and re.match(r'\d+/tcp', line) and '21/tcp' not in line:
                in_ftp_section = False

        return {
            "anonymous_login": anon_login,
            "files": files
        }
    else:
        return None
    
def parse_nfs_nmap_results(nmap_output):
    if nmap_output:
        lines = nmap_output.split('\n')
        shares = set()  # Using a set to avoid duplicates
        files = []
        files_section = False  # Flag to indicate if we are in the file details section

        for line in lines:
            # Capture NFS mount share locations
            if line.strip().startswith('|_  /'):
                share = line.strip('|_ ').split()[0]
                shares.add(share)

            # Identify the start of the nfs-ls section
            if 'nfs-ls:' in line:
                files_section = True

            # Process the file details section
            if files_section:
                av1 = ['nfs-ls:','???', ' .', ' ..','PERMISSION','access:','|_']              
                if line.strip().startswith('|') and all(x not in line for x in av1):
                        parts = line.split()
                        permission = parts[1]
                        uid = parts[2]
                        gid = parts[3]
                        filename = ' '.join(parts[6:])
                        files.append({
                            'permission': permission,
                            'uid': uid,
                            'gid': gid,
                            'filename': filename
                        })

                # Break out of the loop if we reach the end of the NFS section
                if line.startswith('|_'):
                    files_section = False

        return {
            "mount_shares": list(shares),
            "files": files
        }
    else:
        return None
    
def smb_share(scan_result):
    lines = scan_result.split('\n')
    shares = []
    share_info = None
    smb_section = False
    for idx, line in enumerate(lines):
        if ('smb-enum-shares:' in line or 
            'smb-share-enum:' in line or
            'smb-ls:' in line and 'Volume \\\\' in line or
            'smb-mbenum:' in line):
            smb_section = True
            continue
        ip_share_pattern = r'\|\s*\\\\(\d+\.\d+\.\d+\.\d+)\\([^:]+):'
        if re.search(ip_share_pattern, line):
            if idx + 1 < len(lines) and idx + 2 < len(lines):
                next_line = lines[idx + 1]
                next_next_line = lines[idx + 2]
                if ('Type:' in next_line):
                    smb_section = True
        if smb_section and (line.strip() == '' or 
                           (line.startswith('|_') and not '\\\\' in line and 'Anonymous access:' not in line) or
                           ('MAC Address:' in line) or
                           (line.startswith('|') and 'smb-' in line and not 'smb-enum-shares' in line and not 'smb-share-enum' in line)):
            smb_section = False
        if smb_section and '\\\\' in line:
            if share_info:
                shares.append(share_info)
            try:
                share_pattern = r'\|\s*\\\\[\d\.]+\\([^:]+)'
                share_match = re.search(share_pattern, line)
                if share_match:
                    share_name = share_match.group(1).strip()
                    share_info = {'Share Name': share_name}
                else:
                    parts = line.split('\\\\')
                    if len(parts) >= 2 and '\\' in parts[1]:
                        server_share = parts[1]
                        share_parts = server_share.split('\\')
                        if len(share_parts) >= 2:
                            share_name = share_parts[1].rstrip(':').strip()
                            share_info = {'Share Name': share_name}
            except Exception:
                continue
        elif smb_section and share_info and (line.startswith('|') or line.startswith('|_')):
            line_content = line[1:].strip()
            props = {
                "Type:": "Type",
                "Comment:": "Comment",
                "Path:": "Path",
                "Anonymous access:": "Anonymous Access",      
                "Users:": "Users",
                "Max Users:": "Max Users"
            }
            for prop_text, key in props.items():
                if prop_text in line_content:
                    try:
                        value = line_content.split(prop_text)[1].strip()
                        share_info[key] = value
                    except Exception:
                        pass
    if share_info:
        shares.append(share_info)
    return shares
    
def smb_files(scan_result, share_name):
    """
    Extracts files from SMB share listings in nmap output.
    
    Args:
        scan_result (str): The nmap scan output
        share_name (str): The name of the share to extract files from
        
    Returns:
        list: List of files with their details, or None if no files found
    """
    lines = scan_result.split('\n')
    files_section = False
    files = []
    found_files = False
    header_found = False
    in_valid_share = False
    current_ip = None
    
    # First, try to extract the target IP from the scan result
    ip_pattern = r"Nmap scan report for .*?(\d+\.\d+\.\d+\.\d+)"
    ip_match = re.search(ip_pattern, scan_result)
    if ip_match:
        current_ip = ip_match.group(1)
    
    for idx, line in enumerate(lines):
        # Look for the smb-ls section for the specified share - more flexible patterns
        if not files_section:
            # Pattern 1: Standard smb-ls output
            if 'smb-ls:' in line and 'Volume' in line:
                share_pattern = r"smb-ls: Volume \\\\[\d\.]+\\([^\\]+)"
                share_match = re.search(share_pattern, line)
                
                if share_match:
                    found_share = share_match.group(1)
                    
                    if found_share.lower() == share_name.lower():
                        files_section = True
                        in_valid_share = True
                        continue
            
            # Pattern 2: Another possible format
            elif '\\\\' in line and share_name in line:
                # If we see a line with the share name in a path format
                files_section = True
                in_valid_share = True
                continue
                
        # Once we're in the correct section, look for the header line with more flexibility
        if files_section and not header_found:
            header_indicators = ['SIZE', 'TIME', 'FILENAME', 'DIRECTORY', 'FILE', 'NAME']
            # Check if any 2 or more header indicators are present
            matches = sum(1 for indicator in header_indicators if indicator in line.upper())
            
            if matches >= 2:
                header_found = True
                continue
            
            # If we don't find a header after a few lines, assume we're already in the content
            if in_valid_share and idx > 0 and lines[idx-1].strip() == '|':
                header_found = True
            
        # Process file entries after we've found the header
        if files_section and (header_found or in_valid_share):
            # Stop if we reach the end of the section or a new section
            if not line.strip() or line.strip() == '|_' or (line.startswith('|') and 'smb-' in line and 'smb-ls' not in line):
                break
                
            # Skip entries for current and parent directories
            if ' . ' in line or line.strip().endswith(' .') or ' .. ' in line or line.strip().endswith(' ..'):
                continue
                
            # Process valid file entries
            if line.startswith('|'):
                line_content = line[1:].strip()
                
                # Try different patterns for file entries
                if '<DIR>' in line_content:
                    # Directory entry format
                    parts = line_content.split()
                    if len(parts) >= 2:
                        dir_idx = parts.index('<DIR>')
                        if dir_idx + 1 < len(parts):
                            entry_type = 'Directory'
                            filename = ' '.join(parts[dir_idx+1:])
                            
                            found_files = True
                            files.append({
                                'Type': entry_type,
                                'Size': '<DIR>',
                                'Time': parts[dir_idx-1] if dir_idx > 0 else '',
                                'Name': filename
                            })
                else:
                    # Regular file format
                    parts = line_content.split()
                    
                    # Make sure we have at least 2 parts (size and name)
                    if len(parts) >= 2:
                        try:
                            # Try to identify if first part is a size (numeric)
                            size_str = parts[0]
                            int(size_str) # Just to check if it's numeric
                            
                            # If it's numeric, assume it's a size followed by time and filename
                            entry_type = 'File'
                            time_str = parts[1] if len(parts) > 2 else ''
                            filename = ' '.join(parts[2:]) if len(parts) > 2 else parts[1]
                            
                            found_files = True
                            files.append({
                                'Type': entry_type,
                                'Size': size_str,
                                'Time': time_str,
                                'Name': filename
                            })
                        except ValueError:
                            # Not a size, try other patterns
                            if len(parts) >= 3 and re.match(r'\d+/\d+/\d+', parts[1]):
                                # Looks like a DATE TIME FILENAME pattern
                                entry_type = 'File'
                                time_str = f"{parts[0]} {parts[1]}"
                                filename = ' '.join(parts[2:])
                                
                                found_files = True
                                files.append({
                                    'Type': entry_type,
                                    'Size': '',
                                    'Time': time_str,
                                    'Name': filename
                                })

    # If no files were found and we did enter the smb-ls section, return None
    if not found_files and files_section:
        return None
        
    return files


def extract_web_paths(nmap_output):
    """
    Extracts unique web paths from nmap HTTP scan output.
    Particularly focuses on paths found in http-csrf sections.
    """
    if not nmap_output:
        return None
        
    paths = set()  # Using a set to avoid duplicates
    lines = nmap_output.split('\n')
    
    for i, line in enumerate(lines):
        if 'Path:' in line and ('http://' in line or 'https://' in line):
            # Extract the URL from the line
            url_start = line.find('http')
            if url_start != -1:
                full_url = line[url_start:].strip()
                
                # Parse the URL to extract just the path
                try:
                    # Split by // to handle protocol, then by / to get the path
                    path_part = full_url.split('//')[1].split('/', 1)
                    if len(path_part) > 1:
                        path = '/' + path_part[1]
                        
                        # Remove query parameters if they exist
                        if '?' in path:
                            path = path.split('?')[0]
                            
                        # Add to our set of paths
                        paths.add(path)
                except Exception:
                    # If parsing fails, skip this entry
                    continue
    
    # Convert set to sorted list for return
    unique_paths = sorted(list(paths))
    return unique_paths

def extract_smb_users(nmap_output):
    """
    Extracts SMB users from nmap output, particularly from smb-enum-users script.
    Returns a list of user dictionaries with username, full name, and flags.
    """
    if not nmap_output:
        return None
        
    users = []
    lines = nmap_output.split('\n')
    user_section = False
    current_user = {}
    
    for line in lines:
        if '| smb-enum-users:' in line:
            user_section = True
            continue
        
        # Exit if we reach a new script section
        if user_section and line.strip().startswith('|') and 'smb-' in line and 'smb-enum-users' not in line:
            user_section = False
            break
            
        # Look for user lines - they usually start with "|   DOMAIN\username (RID: xxxx)"
        if user_section and '(RID:' in line:
            # Save previous user if exists
            if current_user:
                users.append(current_user)
                
            # Extract username
            parts = line.split('\\')
            if len(parts) < 2:
                continue
                
            username_part = parts[1].split(' ')[0].strip()
            domain = parts[0].split()[-1].strip()
            
            current_user = {
                'Username': username_part,
                'Domain': domain
            }
            
        # Extract additional user details
        elif user_section and current_user and line.strip().startswith('|'):
            if 'Full name:' in line:
                full_name = line.split('Full name:')[1].strip()
                current_user['Full name'] = full_name
            elif 'Flags:' in line:
                flags = line.split('Flags:')[1].strip()
                current_user['Flags'] = flags
                
                # After getting flags, this user entry is complete
                users.append(current_user)
                current_user = {}
    
    # Add the last user if necessary
    if current_user:
        users.append(current_user)
        
    return users

def extract_vulnerabilities(nmap_output):
    """
    Extract vulnerability information from nmap output with vulners script.
    
    Args:
        nmap_output (str): The nmap scan output with vulners script results
        
    Returns:
        list: A list of dictionaries containing port, service, version, and vulnerability information
    """
    if not nmap_output:
        return None
    
    results = []
    lines = nmap_output.split('\n')
    current_port_info = None
    in_vulners_section = False
    vulnerabilities = []
    
    for line in lines:
        line = line.strip()
        
        # Identify port/service lines
        port_match = re.search(r'(\d+)/tcp\s+open\s+(\S+)(?:\s+(.*))?', line)
        if port_match:
            # If we were processing a previous port, save its results
            if current_port_info and vulnerabilities:
                current_port_info['vulnerabilities'] = vulnerabilities
                results.append(current_port_info)
            
            # Start a new port entry
            port = port_match.group(1)
            service = port_match.group(2)
            version = port_match.group(3) if port_match.group(3) else ''
            
            current_port_info = {
                'port': port,
                'service': service,
                'version': version
            }
            vulnerabilities = []
            in_vulners_section = False
            continue
        
        # Detect the start of vulners section
        if '| vulners:' in line:
            in_vulners_section = True
            continue
        
        # Process vulnerabilities
        if in_vulners_section and line.startswith('|'):
            # Skip the CPE line
            if 'cpe:' in line:
                continue
                
            # Extract CVE entries
            cve_match = re.search(r'\|\s+(\S+)\s+(\d+\.\d+)\s+(https://vulners\.com/\S+)', line)
            if cve_match:
                vuln_id = cve_match.group(1)
                score = cve_match.group(2)
                url = cve_match.group(3)
                
                # Check if this is a CVE
                is_exploit = '*EXPLOIT*' in line
                
                vulnerabilities.append({
                    'id': vuln_id,
                    'score': float(score),
                    'url': url,
                    'is_exploit': is_exploit
                })
        
        # Detect the end of vulners section
        if in_vulners_section and (line.strip() == '' or not line.startswith('|')):
            in_vulners_section = False
    
    # Don't forget to add the last port if we have one
    if current_port_info and vulnerabilities:
        current_port_info['vulnerabilities'] = vulnerabilities
        results.append(current_port_info)
    
    return results

def format_vulnerability_info(vuln_data):
    """
    Format vulnerability information for display
    
    Args:
        vuln_data (list): A list of dictionaries containing port, service, version, and vulnerability information
        
    Returns:
        str: Formatted string with vulnerability information
    """
    if not vuln_data:
        return "No vulnerability information found."
    
    output_lines = []
    
    # Collect all vulnerability IDs across all ports to remove duplicates
    all_vuln_ids = set()
    
    for port_info in vuln_data:
        port = port_info['port']
        service = port_info['service']
        version = port_info['version']
        
        # Start with port and service info
        output_lines.append(f"=== VULNERABILITIES FOR PORT {port} ({service} {version}) ===")
        
        # Sort vulnerabilities by score (highest first)
        vulnerabilities = sorted(
            port_info.get('vulnerabilities', []),
            key=lambda x: x['score'],
            reverse=True
        )
        
        if not vulnerabilities:
            output_lines.append("No specific vulnerabilities identified.")
            continue
            
        # Count CVEs and exploits
        cve_count = sum(1 for v in vulnerabilities if v['id'].startswith('CVE-'))
        exploit_count = sum(1 for v in vulnerabilities if v['is_exploit'])
        
        output_lines.append(f"Found {len(vulnerabilities)} vulnerabilities")
        
        output_lines.append(f"Total CVEs: {cve_count}")       
        # List high severity vulnerabilities (score >= 7.0)
        high_severity = [v for v in vulnerabilities if v['score'] >= 7.0]
        if high_severity:
             output_lines.append(f"{len(high_severity)} High Severity Vulnerabilities")
        
        count_exploit = 0
        for vuln in vulnerabilities:
            if vuln['is_exploit']:
                count_exploit += 1
            # Add to our global collection of unique vulnerability IDs
            all_vuln_ids.add(vuln['id'])
            
        output_lines.append(f"{count_exploit} Exploitable Vulnerabilities")
        output_lines.append("")
    
    # After processing all ports, save all unique vulnerabilities to file
    if all_vuln_ids:
        # Sort vulnerability IDs - CVEs first, then other vulnerabilities
        cve_ids = sorted([vid for vid in all_vuln_ids if vid.startswith('CVE-')])
        other_ids = sorted([vid for vid in all_vuln_ids if not vid.startswith('CVE-')])
        sorted_ids = cve_ids + other_ids
        
        with open("cve_found.txt", "w") as f:
            for vuln_id in sorted_ids:
                f.write(f"{vuln_id}\n")
        output_lines.append(f"Saved {len(all_vuln_ids)} unique vulnerability IDs to cve_found.txt")

        output_lines.append("")
    
    return "\n".join(output_lines)

def get_cve_title_from_engine(cve_id, engine=DEFAULT_ENGINE):
    """
    Use the specified engine to get the title and description for a vulnerability ID

    Args:
        cve_id (str): The vulnerability ID to look up (can be CVE, EDB-ID, MSF, POSTGRESQL)
        engine (str): The engine to use, either "regular" or "vulners"

    Returns:
        tuple: (title, description) of the vulnerability, or (None, None) if not found
    """
    # Check if this is a PACKETSTORM ID and we're not using Vulners API
    if cve_id.startswith("PACKETSTORM:") and engine == ENGINE_REGULAR:
        # Skip PacketStorm IDs when using regular engine
        return None, None

    # Track if we're using vulners API for reporting
    using_vulners = (engine == ENGINE_VULNERS)

    try:
        # Determine if this is an EDB or PACKETSTORM entry - we'll handle them specially
        is_edb = cve_id.startswith("EDB-ID:")
        is_packetstorm = cve_id.startswith("PACKETSTORM:")

        if using_vulners and 'vulners_titles' in globals():
            # Use vulners_titles.py API
            try:
                # Redirect stdout to capture the output
                original_stdout = sys.stdout
                sys.stdout = StringIO()

                # Call the function from vulners_titles.py
                vulners_titles.get_cve_for_id(cve_id)

                # Get the printed output
                output = sys.stdout.getvalue()

                # Restore stdout
                sys.stdout = original_stdout

                # Parse the output to extract title and description
                title_match = re.search(r'\[\+\] Title: (.+)', output)
                desc_match = re.search(r'\[\+\] Description: (.+)', output)

                if title_match and desc_match:
                    title = title_match.group(1).strip()
                    description = desc_match.group(1).strip()

                    # If title is too long, truncate for display
                    if len(title) > 150:
                        display_title = title[:150] + "..."
                    else:
                        display_title = title

                    # For empty or too short descriptions, return None
                    if not description or len(description) < 20:
                        return None, None

                    return display_title, description
                return None, None
            except Exception as e:
                print(f"Error using vulners_titles for {cve_id}: {str(e)}")
                # Fall back to regular engine if vulners fails
                return None, None

        # Use vulns_titels.py (regular engine)
        if 'vulns_titels' in globals():
            try:
                # Try to use detect_and_search from vulns_titels.py
                result = vulns_titels.detect_and_search(cve_id)

                if result and "error" not in result:
                    # Only proceed if we have both title and description
                    if result.get('title') and result.get('description'):
                        title = result.get('title')
                        description = result.get('description')

                        # If title is too long, truncate for display
                        if len(title) > 150:
                            display_title = title[:150] + "..."
                        else:
                            display_title = title

                        # Skip entries with insufficient information
                        if not description or len(description) < 20:
                            return None, None

                        return display_title, description

                # If we get here, we didn't find good data
                return None, None
            except Exception as e:
                print(f"Error using vulns_titels for {cve_id}: {str(e)}")
                return None, None

        # Fall back to subprocess if direct import fails
        script_dir = os.path.dirname(os.path.abspath(__file__))
        script_path = os.path.join(script_dir, "vulns_titels.py" if engine == ENGINE_REGULAR else "vulners_titles.py")

        if not os.path.exists(script_path):
            # If the requested script doesn't exist, use any available script
            alt_script = "vulners_titles.py" if engine == ENGINE_REGULAR else "vulns_titels.py"
            alt_path = os.path.join(script_dir, alt_script)
            if os.path.exists(alt_path):
                script_path = alt_path

        if os.path.exists(script_path):
            # Use subprocess to call the script
            cmd = [sys.executable, script_path, "-s", cve_id] if "vulns_titels.py" in script_path else [sys.executable, script_path, cve_id]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            output = result.stdout

            # Parse the output to extract title and description
            title_match = re.search(r'\[\+\] Title: (.+)', output)
            desc_match = re.search(r'\[\+\] Description: (.+)', output)

            # Only proceed if we have both title and description
            if title_match and desc_match:
                title = title_match.group(1).strip()
                description = desc_match.group(1).strip()

                # If title is too long, truncate it for display purposes
                if len(title) > 150:
                    title = title[:150] + "..."

                # Skip entries with insufficient information
                if not description or len(description) < 20:
                    return None, None

                return title, description

            # If we don't have both title and description, skip
            return None, None

        # If we got here, we couldn't find information
        return None, None
    except Exception as e:
        print(f"Error getting title for {cve_id}: {str(e)}")
        return None, None

def generate_cve_titles_report(cve_ids, engine=DEFAULT_ENGINE):
    """
    Generate a report of CVE titles and group them by similar titles
    
    Args:
        cve_ids (set): Set of unique CVE IDs
        engine (str): Engine to use for lookups, either "regular" or "vulners"
    """
    if not cve_ids:
        print("No CVEs to process.")
        return
    
    # Warning about API limits
    api_type = "Vulners" if engine == ENGINE_VULNERS else "vulnerability lookup"
    print(f"\nWARNING: This process will query the {api_type} API for each CVE.")
    print("If you have many CVEs, this may exceed API limits.")
    print("Press Ctrl+C at any time to stop and save progress.")
    user_input = input("Do you want to continue? (y/n): ")
    if user_input.lower() != 'y':
        print("CVE report generation cancelled.")
        return
    
    # All vulnerability IDs will be processed together
    all_vuln_ids = list(cve_ids)
    cve_format_ids = [cid for cid in all_vuln_ids if re.match(r'^CVE-\d{4}-\d+$', cid)]
    other_format_ids = [cid for cid in all_vuln_ids if not re.match(r'^CVE-\d{4}-\d+$', cid)]
    
    print(f"Found {len(cve_format_ids)} CVE format IDs and {len(other_format_ids)} other vulnerability format IDs")
    
    if not all_vuln_ids:
        print("No vulnerability IDs to process.")
        return
    
    print(f"Processing {len(all_vuln_ids)} unique vulnerability IDs using {engine} engine...")
    
    # Dictionary to store CVEs by title
    cves_by_title = defaultdict(list)
    title_descriptions = {}  # To store descriptions for each title
    processed_count = 0
    
    # Flag to track if we were interrupted
    interrupted = False
    
    try:
        # Process each vulnerability ID with progress information
        total = len(all_vuln_ids)
        for i, vuln_id in enumerate(all_vuln_ids):
            # Show progress every 5 vulnerabilities or for the last one
            if i % 5 == 0 or i == total - 1:
                print(f"Progress: {i+1}/{total} ({int((i+1)/total*100)}%)")
            
            # Get title and description using the specified engine
            try:
                title, description = get_cve_title_from_engine(vuln_id, engine)
                processed_count += 1

                # Skip items where title or description is None, empty, or contains "Unknown title"
                if title and description and "Unknown title" not in title:
                    cves_by_title[title].append(vuln_id)
                    title_descriptions[title] = description
            except Exception as e:
                print(f"Error processing {vuln_id}: {str(e)}")
                # Continue to the next vulnerability ID
                continue
    except KeyboardInterrupt:
        print("\n\nProcess interrupted by user! Saving progress...")
        interrupted = True
        
        if not cves_by_title:
            print("No data collected yet. Report generation cancelled.")
            return
    
    print(f"\nProcessed {processed_count} out of {total} vulnerability IDs ({int(processed_count/total*100)}%)" +
          f"{' before interruption' if interrupted else ''}")
    
    # Generate timestamp and filename base for all reports
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    engine_suffix = "_vulners" if engine == ENGINE_VULNERS else "_regular"
    progress_suffix = "_partial" if interrupted else ""
    base_filename = f"vuln_titles{engine_suffix}{progress_suffix}"
    
    # Always create a CSV version for easy import into spreadsheets
    csv_filename = f"{base_filename}.csv"
    print(f"Creating CSV report: {csv_filename}...")
    with open(csv_filename, "w") as f:
        # Write header
        f.write("Vulnerability ID,Title,Description\n")
        
        # Write data
        for title, cve_list in cves_by_title.items():
            description = title_descriptions.get(title, "")
            # Escape quotes in CSV
            safe_title = title.replace('"', '""')
            safe_desc = description.replace('"', '""')
            
            for cve in cve_list:
                f.write(f'"{cve}","{safe_title}","{safe_desc}"\n')
    
    print(f"CSV report generated: {csv_filename}")
    
    # Now create a markdown report
    md_filename = f"{base_filename}.md"
    print(f"Creating markdown report: {md_filename}...")
    with open(md_filename, "w") as f:
        f.write(f"# Vulnerability Titles Report ({engine.capitalize()} Engine)\n\n")
        f.write(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"Total unique vulnerability IDs processed: {len(all_vuln_ids)}\n\n")
        
        # Group by title
        f.write("## Vulnerabilities by Title\n\n")
        
        # Sort by number of entries (most frequent first)
        sorted_titles = sorted(cves_by_title.keys(), 
                              key=lambda x: len(cves_by_title[x]), 
                              reverse=True)
        
        for title in sorted_titles:
            vuln_list = cves_by_title[title]
            description = title_descriptions.get(title, "")
            
            f.write(f"### {title}\n")
            if description:
                f.write(f"*{description}*\n\n")
            
            f.write(f"**Found in {len(vuln_list)} vulnerability IDs:**\n\n")
            for vuln_id in sorted(vuln_list):  # Sort for better readability
                f.write(f"- {vuln_id}\n")
            f.write("\n")
    
    print(f"Markdown report generated: {md_filename}")
    
    # Also create a simplified text version
    txt_filename = f"{base_filename}.txt"
    with open(txt_filename, "w") as f:
        f.write(f"VULNERABILITY TITLES REPORT ({engine.upper()} ENGINE) - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"===============================================\n\n")
        
        for title in sorted_titles:
            vuln_list = cves_by_title[title]
            description = title_descriptions.get(title, "")
            
            # Write title with count - no redundant ID listing
            f.write(f"{title} ({len(vuln_list)} {'entry' if len(vuln_list) == 1 else 'entries'})\n")
            
            # Add description if available (with better formatting)
            if description:
                # Format the description to fit nicely in the text report
                # Limit to ~80 characters per line with proper indentation
                desc_lines = []
                current_line = "  Description: "
                
                # Split description into words and build lines with proper wrapping
                for word in description.split():
                    if len(current_line + word) > 78:  # Leave room for word plus space
                        desc_lines.append(current_line)
                        current_line = "               " + word  # Indent continuation lines
                    else:
                        current_line += word + " "
                
                # Add the last line if not empty
                if current_line.strip():
                    desc_lines.append(current_line)
                
                # Write all description lines
                for line in desc_lines:
                    f.write(f"{line}\n")
            
            # Blank line after each entry for readability
            f.write("\n")
    
    print(f"Text report generated: {txt_filename}")

def sort_cve_file(filepath="cve_found.txt"):
    """
    Sort and deduplicate the CVE file, putting CVE IDs first followed by other vulnerability IDs.
    
    Args:
        filepath (str): Path to the CVE file, defaults to cve_found.txt
    
    Returns:
        tuple: (num_total, num_cve, num_other) counts of entries
    """
    if not os.path.exists(filepath):
        print(f"Error: File '{filepath}' not found.")
        return (0, 0, 0)
        
    try:
        with open(filepath, "r") as f:
            # Read all IDs and remove duplicates
            vuln_ids = set(line.strip() for line in f.readlines() if line.strip())
            
        # Sort vulnerability IDs - CVEs first, then other vulnerabilities
        cve_ids = sorted([vid for vid in vuln_ids if vid.startswith('CVE-')])
        other_ids = sorted([vid for vid in vuln_ids if not vid.startswith('CVE-')])
        sorted_ids = cve_ids + other_ids
        
        # Write them back to file
        with open(filepath, "w") as f:
            for vuln_id in sorted_ids:
                f.write(f"{vuln_id}\n")
                
        return (len(sorted_ids), len(cve_ids), len(other_ids))
    
    except Exception as e:
        print(f"Error sorting CVE file: {str(e)}")
        return (0, 0, 0)

def show_usage():
    """Show usage information"""
    print("Usage: python3 analyseCLI.py <nmap_output_file>")
    print("       python3 analyseCLI.py --report [-r|-v]  (generate report from cve_found.txt)")
    print("       python3 analyseCLI.py --list  (list CVEs without API lookups)")
    print("       python3 analyseCLI.py --sort  (sort and deduplicate cve_found.txt)")
    print("       python3 analyseCLI.py --help  (show this help message)\n")
    print("Options:")
    print("  --report        Generate a report of CVE titles and descriptions from cve_found.txt")
    print("  -r              Use regular engine (vulns_titels.py) for lookups [default]")
    print("  -v              Use Vulners API engine (vulners_titles.py) for lookups")
    print("                  WARNING: API lookups may exceed monthly limits")
    print("  --list          List the unique CVEs without using the API")
    print("  --sort          Sort and deduplicate the cve_found.txt file (CVEs first, then other IDs)")
    print("  --help          Show this help message and exit\n")
    print("Description:")
    print("  This tool analyzes nmap output for various services and vulnerabilities.")
    print("  It can extract information about ports, OS details, domain info, FTP, NFS,")
    print("  SMB shares, web paths, and vulnerabilities.\n")
    print("  When run with an nmap output file, it will save identified vulnerabilities")
    print("  to cve_found.txt. You can then use --report to generate detailed")
    print("  information about these vulnerabilities using either the regular (-r)")
    print("  or Vulners API (-v) engine.")

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Penetration Testing Analysis CLI Tool')
    parser.add_argument('nmap_file', nargs='?', help='Nmap output file to analyze')
    parser.add_argument('--report', action='store_true', help='Generate a CVE titles report from cve_found.txt')
    parser.add_argument('--list', action='store_true', help='List CVEs without API lookups')
    parser.add_argument('--sort', action='store_true', help='Sort and deduplicate cve_found.txt file')
    parser.add_argument('-r', action='store_true', help='Use regular engine (vulns_titels.py)')
    parser.add_argument('-v', action='store_true', help='Use Vulners API engine (vulners_titles.py)')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Show help if no arguments
    if len(sys.argv) == 1:
        show_usage()
        sys.exit(1)
    
    # Determine which engine to use based on flags
    engine = ENGINE_VULNERS if args.v else ENGINE_REGULAR
    
    # Handle --sort option
    if args.sort:
        print("Sorting and deduplicating cve_found.txt...")
        total, cve_count, other_count = sort_cve_file()
        if total > 0:
            print(f"Successfully sorted {total} unique vulnerability IDs")
            print(f"- {cve_count} CVE IDs")
            print(f"- {other_count} other vulnerability IDs")
        sys.exit(0)
    
    # Handle --list option
    if args.list:
        print("=== LISTING CVE IDs FROM cve_found.txt ===")
        if os.path.exists("cve_found.txt"):
            with open("cve_found.txt", "r") as f:
                cve_ids = set(line.strip() for line in f.readlines() if line.strip())
            
            # Sort vulnerability IDs - CVEs first, then other vulnerabilities
            cve_ids_list = sorted([vid for vid in cve_ids if vid.startswith('CVE-')])
            other_ids_list = sorted([vid for vid in cve_ids if not vid.startswith('CVE-')])
            
            print(f"Found {len(cve_ids)} unique vulnerability IDs:")
            print(f"- {len(cve_ids_list)} CVE IDs")
            print(f"- {len(other_ids_list)} other vulnerability IDs")
            
            if cve_ids_list:
                print("\nCVE IDs:")
                for cve_id in cve_ids_list:
                    print(f"  {cve_id}")
            
            if other_ids_list:
                print("\nOther Vulnerability IDs:")
                for vuln_id in other_ids_list:
                    print(f"  {vuln_id}")
        else:
            print("No CVE file found (cve_found.txt). Run the vulnerability scan first.")
        sys.exit(0)
    
    # Handle --report option
    if args.report:
        engine_name = "Vulners API" if engine == ENGINE_VULNERS else "Regular"
        print(f"=== GENERATING CVE TITLES REPORT USING {engine_name.upper()} ENGINE ===")
        
        # Check if cve_found.txt exists
        if os.path.exists("cve_found.txt"):
            with open("cve_found.txt", "r") as f:
                # Remove duplicates with set and convert back to list for sorting
                cve_ids = set(line.strip() for line in f.readlines() if line.strip())
            print(f"Found {len(cve_ids)} unique vulnerability IDs in cve_found.txt")
            generate_cve_titles_report(cve_ids, engine)
        else:
            print("No CVE file found (cve_found.txt). Run the vulnerability scan first.")
        sys.exit(0)
    
    # If we get here, we're analyzing an nmap file
    if not args.nmap_file:
        print("Error: No nmap file specified.")
        show_usage()
        sys.exit(1)
    
    # Read the nmap output file
    file_path = sys.argv[1]
    try:
        with open(file_path, 'r') as file:
            file_results = file.read()
        print(f"Analyzing nmap results from: {file_path}")
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {str(e)}")
        sys.exit(1)

    # Extract information using all functions
    print("\n===== NMAP ANALYSIS RESULTS =====\n")
    
    # Extract open ports
    try:
        open_ports = extract_ports(file_results)
        if open_ports:
            # Sort ports numerically
            open_ports.sort(key=lambda x: int(x[0]))
            
            print("=== OPEN PORTS ===")
            for port in open_ports:
                print(f"Port: {port[0]}, Service: {port[1]}, Version: {port[2]}")
            print()
    except Exception as e:
        print(f"Error extracting open ports: {str(e)}")
    
    # Extract OS details
    try:
        os_details = extract_os_details(file_results)
        if os_details:
            print("=== OS DETAILS ===")
            print(f"OS Name: {os_details[0]}")
            print(f"OS Version: {os_details[1]}")
         
    except Exception as e:
        print(f"Error extracting OS details: {str(e)}")
    
    # Extract domain info
    try:
        domain_info_found = False     
        # First collect all domain information
        domain = extract_domain(file_results)
        computer = extract_computer_name(file_results)
        dnsdomain = extract_dns_domain(file_results)
        nbdomain = extract_nb_domain(file_results)
        dnscomputer = extract_dns_computer(file_results)
        targetn = extract_target_name(file_results)
        
        # Check if any domain info was found
        if domain or computer or dnsdomain or nbdomain or dnscomputer or targetn:
            domain_info_found = True
            
        # Only print the header if we found domain info
        if domain_info_found:
            print("=== DOMAIN INFO ===")
            
            if domain:
                print(f"Domain: {domain}")
            
            if computer:
                print(f"Computer Name: {computer}")
            
            if dnsdomain:
                print(f"DNS Domain Name: {dnsdomain}")
            
            if nbdomain:
                print(f"NetBIOS Domain Name: {nbdomain}")
            
            if dnscomputer:
                print(f"DNS Computer Name: {dnscomputer}")
            
            if targetn:
                print(f"Target Name: {targetn}")
            
            print()
    except Exception as e:
        print(f"Error extracting domain information: {str(e)}\n")
       
    # Extract FTP info
    try:
        ftp_info = parse_ftp_nmap_results(file_results)
        if ftp_info:        
            anon = ftp_info.get('anonymous_login', '')
            files = ftp_info.get('files', [])
            if anon == "Allowed" or files: 
                 print(f"\n=== FTP INFO ===")               
            if anon == "Allowed":
                print("Anonymous Login: Allowed")    
            if files:
                print("Found interesting files in FTP:")
                for f in files:
                    print(f"  {f['permissions']} {f['filename']}")
    except Exception as e:
        print(f"Error extracting FTP info: {str(e)}")
   
    # Extract NFS info
    try:
        nfs_info = parse_nfs_nmap_results(file_results)
        if nfs_info:
            # print("=== NFS/RPC INFO ===")
            if nfs_info['mount_shares']:
                print(f"\n=== NFS/RPC INFO ===")
                print("Mount Shares:")
                for share in nfs_info['mount_shares']:
                    print(f"  {share}")
            
            if nfs_info['files']:
                print("Files:")
                for file in nfs_info['files']:
                    print(f"  {file['permission']} {file['uid']}:{file['gid']} {file['filename']}")
            print()
    except Exception as e:
        print(f"Error extracting NFS info: {str(e)}")
    
    # Try to extract SMB info 
    try:
        smb_info = extract_smb_oscomp(file_results)
        if smb_info:
            print("=== SMB OS INFO ===")
            os_info = smb_info.get('OS_Info', {})
            for key, value in os_info.items():
                print(f"{key}: {value}")          
    except Exception as e:
        print(f"Error extracting SMB OS info: {str(e)}")

    # get smb shares if we can infer the IP address
    try:
        shares = smb_share(file_results)
        if shares:
            print("=== SMB SHARES ===")

            # Then show details of all shares
            for share in shares:
                print(f"Share: {share['Share Name']}")
                if 'Type' in share:
                    print(f"  Type: {share['Type']}")
                if 'Path' in share:
                    print(f"  Path: {share['Path']}")
                if 'Comment' in share and share['Comment'].strip() != '':
                    print(f"  Comment: {share['Comment']}")
                if 'Anonymous Access' in share and "none" not in share['Anonymous Access'].strip():
                    print(f"  Anonymous Access: {share['Anonymous Access']}")

                # Try to get files for this share if it has READ access
                try:
                    
                    if 'Anonymous Access' in share and 'READ' in share['Anonymous Access']:
                        files = smb_files(file_results, share['Share Name'])
                        # print(files)
                        if files:
                            print("  Files:")
                            for file in files:
                                print(f"    {file['Type']} {file['Name']}")
                except Exception as e:
                    print(f"  Error extracting files for share {share['Share Name']}: {str(e)}")
                print()
    except Exception as e:
        print(f"Error extracting SMB shares: {str(e)}")

    # Extract SMB users
    try:
        smb_users = extract_smb_users(file_results)
        if smb_users:
            print("=== SMB USERS ===")
            # Count enabled accounts
            enabled_accounts = [user for user in smb_users if "Account disabled" not in user.get('Flags', '')]
            print(f"Found {len(smb_users)} total users, {len(enabled_accounts)} enabled accounts")
            
            # First display enabled accounts
            if enabled_accounts:
                print("\nEnabled Accounts:")
                for user in enabled_accounts:
                    print(f"  Username: {user['Username']}")
                    if 'Full name' in user:
                        print(f"    Full name: {user['Full name']}")
                    if 'Flags' in user:
                        print(f"    Flags: {user['Flags']}")
                print()
            
            # Option to show all users (disabled by default)
            print("All User Accounts:")
            for user in smb_users:
                print(f"  {user['Username']}")
                
            print()
    except Exception as e:
        print(f"Error extracting SMB users: {str(e)}")
        
    # Extract web paths from HTTP output
    try:
        web_paths = extract_web_paths(file_results)
        if web_paths:
            print("=== WEB PATHS ===")
            print("Discovered web paths on target:")
            for path in web_paths:
                print(f"  {path}")
            print()
    except Exception as e:
        print(f"Error extracting web paths: {str(e)}")

    # Extract vulnerabilities using vulners script
    try:
        vulners_data = extract_vulnerabilities(file_results)
        if vulners_data:
            print("=== VULNERABILITIES ===")
            formatted_info = format_vulnerability_info(vulners_data)
            print(formatted_info)
            
            # Always show the prompt to generate the report, but don't generate automatically
            print("\nTo generate a detailed CVE report, run:")
            print(f"python3 {sys.argv[0]} --report -r  (regular engine)")
            print(f"python3 {sys.argv[0]} --report -v  (vulners API engine)")
            print("\nTo just list the CVEs without using any API, run:")
            print(f"python3 {sys.argv[0]} --list")
            print("\nTo sort and deduplicate the CVE file, run:")
            print(f"python3 {sys.argv[0]} --sort")
            print("\nFor more options, run:")
            print(f"python3 {sys.argv[0]} --help")
        else:
            print("No vulnerabilities found.")
    except Exception as e:
        print(f"Error extracting vulnerabilities: {str(e)}")

if __name__ == "__main__":
    main()