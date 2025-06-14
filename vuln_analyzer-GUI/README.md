# Pentester Analysis Tool

An advanced security analysis tool for penetration testers that leverages AI to analyze scan data, categorize vulnerabilities, and provide exploitation guidance with a sleek cybersecurity-themed UI.

![Pentester Analysis Tool](screenshots/main_interface.png)

## Features

- **Modern Cyber UI**: Sleek, dark-themed interface with matrix animation background
- **Scan Input**: Upload or paste scan outputs from tools like Nmap, Nikto, SQLMap, etc.
- **Multi-Tab Analysis**: Organized view of findings across categories:
  - Ports & Services
  - Web Directories
  - Remote File System
  - Subdomains
  - Credentials
  - Software Versions
- **AI-Powered Analysis**: In-depth security assessment using OpenAI's GPT-4o-mini model
- **Content Type Selection**: Focus analysis on specific aspects (ports, web, vulnerabilities, directories)
- **Vulnerability Categorization**: Identification and classification of vulnerabilities
- **Exploitation Guidance**: Practical exploitation techniques for verified vulnerabilities
- **API Key Management**: Secure handling of OpenAI API keys
- **Terminal-Style UI**: Hacker-themed input and output displays

## Installation

### Using Docker (Recommended)

```bash

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


# Configure your .env file
cp .env.example .env
# Edit the .env file with your API keys

# Build and run with Docker Compose
docker-compose up -d
```

### Manual Installation

```bash
# Clone the repository
git clone https://github.com/YanivHaliwa/pentester-analysis-tool.git
cd pentester-analysis-tool

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure your .env file
cp .env.example .env
# Edit the .env file with your API keys

# Run the application
python app.py
```

## Usage

1. Access the web interface at `http://localhost:5000`
2. Enter a session title (optional)
3. Paste scan output or upload scan files
4. Select the scan type
5. Click "Analyze Target" to process the data
6. Navigate through the tabs to see the analysis results

## Supported Scan Formats

- **Nmap**: `.nmap`, `.gnmap`, `.xml` outputs
- **Nikto**: Web vulnerability scanner output
- **SQLMap**: SQL injection test results
- **Gobuster/Dirbuster**: Directory scanning results
- **Any text-based scanner output**

## Screenshots

### Scan Input Interface
![Scan Input](screenshots/scan_input.png)

### Analysis Results
![Analysis Results](screenshots/analysis_results.png)

### Vulnerability Report
![Vulnerability Report](screenshots/vulnerabilities.png)

## Configuration

Edit the `.env` file to configure:

```
# OpenAI API Key
OPENAI_API_KEY=your_openai_api_key_here

# Flask Secret Key (randomly generated for security)
SECRET_KEY=your_secret_key_here

# Enable response streaming (optional)
ENABLE_STREAMING=false
```

You can also configure the tool through the Settings tab in the web interface:

- **API Key Management**: Set or update your OpenAI API key
- **Analysis Options**: Configure default settings for scans
- **History Management**: Enable/disable scan history saving

## Project Structure

- **app.py**: Main Flask application
- **analyzer.py**: Unified scan parsing and AI analysis module
- **templates/**: HTML templates for web interface
- **static/**: CSS, JavaScript, and image files
- **uploads/**: Directory for scan file uploads and results storage

## Author

Created by [Yaniv Haliwa](https://github.com/YanivHaliwa) for security testing and educational purposes.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is designed for legitimate security testing by authorized security professionals. Do not use for unauthorized testing of systems you don't own or have explicit permission to test.