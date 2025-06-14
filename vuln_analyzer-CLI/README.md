# Penetration Testing Analysis CLI Tool

A powerful command-line tool for analyzing nmap scan results and generating reports about vulnerabilities and services discovered during penetration tests.

## Architecture and Data Flow

The tool consists of three main Python scripts that work together in a modular architecture:

1. **analyseCLI.py** - Main analysis and orchestration script
2. **vulns_titels.py** - Regular vulnerability lookup engine (no API key required)
3. **vulners_titles.py** - Vulners API-based lookup engine (requires API key)

### How the Files Work Together

**Step 1: Nmap Output Analysis (analyseCLI.py)**
- User provides an nmap XML output file to analyseCLI.py
- The script parses the file to extract various information:
  - Open ports and services
  - OS details and versions
  - Domain names and computer names
  - FTP/SMB/NFS shares and files
  - Web paths and directories
  - Vulnerability IDs (CVE, EDB-ID, MSF, etc.)
- Extracted vulnerability IDs are saved to `cve_found.txt`

**Step 2: Vulnerability Lookup (Report Generation)**
- When the user runs `--report` option, analyseCLI.py reads `cve_found.txt`
- Depending on the engine selected (-r or -v), it calls either:
  - **vulns_titels.py**: Uses multiple public sources (NVD, ExploitDB, etc.)
  - **vulners_titles.py**: Uses the Vulners API for more comprehensive data
- Each vulnerability ID is processed to retrieve its title and description
- The lookup results are grouped by title and saved in three formats:
  - CSV (for spreadsheets)
  - Markdown (for documentation)
  - Text (for simple viewing)

### Function Flow Between Files

1. `analyseCLI.py`: 
   - Handles command-line arguments and user interaction
   - Contains the `get_cve_title_from_engine()` function that decides which engine to use
   - Imports the other modules dynamically with `importlib.util`
   - Handles report generation and formatting logic

2. `vulns_titels.py`:
   - Contains specialized functions for different vulnerability types:
     - `get_cve_info()` - Retrieves CVE information from NVD
     - `get_edb_info()` - Retrieves Exploit-DB information
     - `search_msf()` - Retrieves Metasploit module information
   - The core `detect_and_search()` function determines the type of vulnerability ID
   - Can be used as a standalone tool with its own command-line interface

3. `vulners_titles.py`:
   - Uses Vulners API for lookups via `get_cve_for_id()` function
   - Handles API authentication and rate limiting
   - Contains fallback mechanisms when direct API lookups fail
   - Can also be used standalone for single lookups or processing files

## Features

- Parse nmap scan results to extract:
  - Open ports and services
  - Operating system details
  - Domain information
  - FTP, SMB, and NFS services and shares
  - Web paths
  - Vulnerabilities using Vulners script results

- CVE/Vulnerability Management:
  - Extract and sort vulnerability IDs
  - Generate reports with titles and descriptions
  - Support for multiple lookup engines (Regular and Vulners API)
  - CSV output for easy import into spreadsheets

- Supports multiple vulnerability ID formats from various sources:
  - CVE IDs (`CVE-YYYY-NNNNN`)
  - Exploit-DB IDs (`EDB-ID:NNNNN`)
  - PacketStorm IDs (`PACKETSTORM:NNNNN`) - Regular engine skips these, Vulners engine processes them
  - Metasploit Modules (`MSF:MODULE-TYPE-SUBTYPES`)
  - And many more formats (1337DAY-ID, CNVD, etc.)

## Installation

1. Clone this repository or download the scripts

you can clone ONLY this folder if you run this command: 

```bash
git clone --filter=blob:none --no-checkout https://github.com/YanivHaliwa/Cyber-Stuff.git && cd Cyber-Stuff && git sparse-checkout init --cone && git sparse-checkout set vuln-analyzer  && git checkout
```

OR you can Clone the repository using the following command:

```bash
git clone https://github.com/YanivHaliwa/Cyber-Stuff.git
```

then
```bash
cd Cyber-Stuff/vuln-analyzer/vuln_analyzer-CLI
```



2. Install required dependencies:

```bash
pip install requests beautifulsoup4 feedparser
```

## Usage

### Analyze Nmap Results

Process an nmap scan output file to extract information about services and vulnerabilities:

```bash
python3 analyseCLI.py nmap_output.xml
```

### Generate Vulnerability Reports

Generate a report using the Regular engine (vulns_titels.py):

```bash
python3 analyseCLI.py --report -r
```

Generate a report using the Vulners API engine (vulners_titles.py):

```bash
python3 analyseCLI.py --report -v
```

### List CVEs Without API Lookups

Simply list the unique CVEs without querying any APIs:

```bash
python3 analyseCLI.py --list
```

### Sort and Deduplicate Vulnerability IDs

Sort and deduplicate the vulnerability IDs in cve_found.txt:

```bash
python3 analyseCLI.py --sort
```

### Help Information

Display detailed help information:

```bash
python3 analyseCLI.py --help
```

## Report Engines

The tool supports two different engines for vulnerability lookups:

1. **Regular Engine** (-r): Uses `vulns_titels.py` which supports multiple vulnerability databases 
   and ID formats (CVE, EDB-ID, MSF, etc.). Does not process PacketStorm IDs.

2. **Vulners API Engine** (-v): Uses `vulners_titles.py` with the Vulners API for more accurate 
   and detailed information. Requires an API key in the VULNERS_API_KEY environment variable.
   Can process all vulnerability ID types including PacketStorm.

## Report Formats

Reports are generated in three formats:

- **CSV** - Easy to import into spreadsheets (vuln_titles_*.csv)
- **Markdown** - Structured information with descriptions (vuln_titles_*.md)
- **Plain text** - Simple listing format (vuln_titles_*.txt)

## Environment Variables

- `VULNERS_API_KEY` - API key for Vulners (used with -v option)
- `NVD_API_KEY` - Optional API key for National Vulnerability Database

## Example Output

```
[*] Looking up: CVE-2021-44228
[+] CVE-2021-44228 (CVSS: 10.0, Severity: CRITICAL)
    Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.

[*] Looking up: MSF:AUXILIARY-SCANNER-HTTP-APACHE_NORMALIZE_PATH
[+] MSF:AUXILIARY-SCANNER-HTTP-APACHE_NORMALIZE_PATH
    Apache Normalize Path Directory Traversal Scanner. Detects vulnerability CVE-2022-30556 - an Apache HTTP Server normalize path bug that allows attackers to perform directory traversal and access restricted files by exploiting improper path handling in URL validation.
```

## Notes

- The script adds a small delay between lookups to avoid hitting rate limits.
- Some vulnerability databases may block automated lookups; the script includes fallback mechanisms.
- When using the Vulners API, be mindful of API rate limits.
- The regular engine (vulns_titels.py) skips PacketStorm IDs entirely. To process these, use the Vulners API engine.
- Both lookup engines return None for vulnerability IDs that don't have sufficient detailed information, to avoid generic responses.

## Author

Created by [Yaniv Haliwa](https://github.com/YanivHaliwa) for security testing and educational purposes.