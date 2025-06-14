#!/bin/bash
# Run script for Pentester Analysis Tool
# This script starts the Flask application with proper environment setup

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit

# Check if .env file exists
if [[ ! -f .env ]]; then
    echo "Error: .env file not found"
    echo "Creating a default .env file..."
    
    # Generate a secure key
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    
    # Create default .env
    cat > .env << EOF
# Pentester Analysis Tool Configuration

# Security
SECRET_KEY=$SECRET_KEY

# AI Provider (openai or claude)
AI_PROVIDER=openai

# API Keys
OPENAI_API_KEY=your_openai_api_key_here
CLAUDE_API_KEY=your_claude_api_key_here
EOF
    
    echo "Please edit the .env file to add your API keys"
    exit 1
fi

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 not found"
    exit 1
fi

# Check for virtual environment
if [[ -d venv ]]; then
    echo "Activating virtual environment..."
    source venv/bin/activate
fi

# Check if requirements are installed
echo "Checking requirements..."
pip install -r requirements.txt > /dev/null 2>&1

# Create uploads directory if it doesn't exist
mkdir -p uploads

# Run the Flask application
echo "Starting Pentester Analysis Tool..."
echo "======================================"
echo "Access the web interface at: http://localhost:5001"
echo "Press Ctrl+C to stop the server"
echo "======================================"

# Run the application
python3 app.py --port=5001
