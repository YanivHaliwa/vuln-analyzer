# Vuln-Analyzer Suite

A collection of advanced penetration testing tools for analyzing scan results, identifying vulnerabilities, and generating actionable security reports. This suite is designed for cybersecurity professionals and ethical hackers seeking both automation and interactive analysis.

## Overview

The Vuln-Analyzer suite includes two complementary tools:

### 1. vuln_analyzer-CLI
A powerful command-line tool for parsing and analyzing scan outputs (such as Nmap XML), extracting open ports, services, vulnerabilities (CVE, EDB-ID, etc.), and generating detailed reports. Ideal for automation, scripting, and fast workflows.

- Modular Python scripts for flexible analysis
- Supports public and API-based vulnerability lookups
- Generates vulnerability reports and exploitation references

### 2. vuln_analyzer-GUI
A modern, AI-powered graphical interface for penetration testers. Features a sleek, cybersecurity-themed UI and leverages GPT-4o-mini for in-depth analysis, vulnerability categorization, and exploitation guidance.

- Upload or paste scan outputs (Nmap, Nikto, SQLMap, etc.)
- Multi-tab analysis: ports, web directories, credentials, subdomains, and more
- AI-driven vulnerability assessment and exploitation tips
- Secure API key management and terminal-style displays

## Usage
- Use the CLI tool for fast, scriptable analysis and report generation.
- Use the GUI tool for interactive, AI-enhanced exploration and guidance.

For detailed instructions, see the README in each subfolder.

## Author

Created by [Yaniv Haliwa](https://github.com/YanivHaliwa) for security testing and educational purposes.
