#!/usr/bin/env python3
import requests
import sys
import os
import re
import json
import time

# Get API keys from environment variables
API_KEY = os.environ.get("VULNERS_API_KEY")
NVD_API_KEY = os.environ.get("NVD_API_KEY")

# Debug flag - set to True to enable detailed output
DEBUG = False

# User agent for NVD API requests
USER_AGENT = "CVELookupTool/1.0"

def detect_id_type(vuln_id):
    """Detect the type of vulnerability ID and return appropriate format for API."""
    # UUID format - GitHub exploit
    if re.match(r'^[A-F0-9\-]{36}$', vuln_id, re.I):
        return f"githubexploit/{vuln_id}"
    # CVE format
    elif re.match(r'^CVE-\d{4}-\d{4,7}$', vuln_id, re.I):
        return vuln_id
    # Default - try as is
    return vuln_id

def try_direct_search(vuln_id):
    """Try a direct text search for the ID using the search API."""
    try:
        url = f"https://vulners.com/api/v3/search/audit/?query={vuln_id}&apiKey={API_KEY}"
        headers = {"Content-Type": "application/json"}
        
        if DEBUG:
            print(f"[+] Performing direct search for: {vuln_id}")
            
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            if DEBUG:
                print(f"[!] HTTP Error {response.status_code}")
            return False
            
        data = response.json()
        if data.get("result") != "OK" or not data.get("data", {}).get("search"):
            if DEBUG:
                print("[!] No search results found.")
            return False

        # Look for CVEs in the results
        for doc in data["data"]["search"]:
            cve_list = doc.get("cvelist", [])
            if cve_list:
                print(f"Found by search: {cve_list[0]}")
                return True
                
        print("[!] No CVE found in search results.")
        return False
        
    except Exception as e:
        # if verbose or DEBUG:
        #     print(f"[!] Error in direct search: {str(e)}")
        return False

def get_cve_for_id(vuln_id):
    # Check if API key is set
    if not API_KEY:
        print("[!] Error: VULNERS_API_KEY environment variable not set")
        print("    Set it with: export VULNERS_API_KEY='your_api_key'")
        return
    
    # Try different ID formats if first attempt fails
    id_formats = [
        detect_id_type(vuln_id),  # Standard format detection
        vuln_id,                  # Raw ID
        f"githubexploit/{vuln_id}"  # Force GitHub format
    ]
    
    for search_id in id_formats:
        if  DEBUG:
            print(f"[+] Trying ID format: {search_id}")
            
        url = f"https://vulners.com/api/v3/search/id/?id={search_id}&apiKey={API_KEY}"
        headers = {"Content-Type": "application/json"}

        try:
            response = requests.get(url, headers=headers)
            if response.status_code != 200:
                if DEBUG:
                    print(f"[!] HTTP Error {response.status_code}")
                continue

            data = response.json()
            if DEBUG:
                print(json.dumps(data, indent=2))  # Pretty print JSON only in debug mode
            if DEBUG:
                print(f"[+] API Response status: {data.get('result')}")

            if data.get("result") != "OK":
                continue
            
            # Check if documents exist and are not empty
            if not data.get("data", {}).get("documents"):
                if DEBUG:
                    print(f"[!] No documents found for ID format: {search_id}")
                continue

            doc = list(data["data"]["documents"].values())[0]
            cve_list = doc.get("cvelist", [])
            # Extract title and description when available
            title = doc.get("title", "No title found")
            description = doc.get("description", "No description found")

            print(f"\n[+] Title: {title}")
            print(f"[+] Description: {description}")
 
            break
            
        except Exception as e:
            if DEBUG:
                print(f"[!] Error processing {search_id}: {str(e)}")
            continue
    else:
        # This executes if the loop completes without a break - silent fail
        # Try a direct search as last resort
        if DEBUG:
            print("[+] Attempting direct search as fallback...")
        try_direct_search(vuln_id)
        return

    # Try CVE field
    
    if cve_list:
        print(f"[+] CVE found: {cve_list[0]}")
        return cve_list[0]

    # Fallback: regex in description/title
    title = doc.get("title", "")
    description = doc.get("description", "")
    match = re.search(r'CVE-\d{4}-\d{4,7}', title + ' ' + description)
    if match:
        print(f"[+] CVE found in title/description: {match.group(0)}")
        return match.group(0)
    else:
        print("[!] No CVE found.")
        return None
 

def process_file(input_file):
    """Process a file containing vulnerability IDs line by line"""
    if not os.path.exists(input_file):
        print(f"[!] Error: Input file '{input_file}' not found")
        return

    print(f"[*] Processing vulnerability IDs from {input_file}...")

    with open(input_file, "r") as f:
        for line in f:
            vuln_id = line.strip()
            if not vuln_id or vuln_id.startswith("//"):  # Skip empty lines and comments
                continue

            print(f"\n[*] Looking up: {vuln_id}")
            # Call get_cve_for_id but don't output anything if it fails
            get_cve_for_id(vuln_id)

            # Add a small delay to avoid hitting rate limits
            time.sleep(1)

if __name__ == "__main__":
    import argparse

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Get CVE ID and information for vulnerability IDs")
    parser.add_argument("input", help="Either a single vulnerability ID or a file containing vulnerability IDs")
    parser.add_argument("-f", "--file", action="store_true", help="Treat input as a file containing vulnerability IDs")
    args = parser.parse_args()

    try:
        # Determine if we're processing a file or a single ID
        if args.file or os.path.isfile(args.input):
            process_file(args.input)
        else:
            # Process single vulnerability ID
            get_cve_for_id(args.input)
    except Exception:
        # Silent fail if anything goes wrong
        pass
    