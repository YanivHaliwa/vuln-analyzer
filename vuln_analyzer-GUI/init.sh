#!/usr/bin/env bash
# Initialize the project structure for Pentester Analysis Tool

# Make script executable from any directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit

echo "Setting up Pentester Analysis Tool directory structure..."

# Create necessary directories
mkdir -p uploads
mkdir -p static/{css,js,img}
mkdir -p templates
mkdir -p screenshots
mkdir -p utils
mkdir -p config

# Set proper permissions
chmod 775 uploads

echo "Directory structure setup complete!"

# Initialize Python environment if requested
if [[ "$1" == "--venv" ]]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Install dependencies
    echo "Installing dependencies..."
    pip install -r requirements.txt
    
    echo "Python environment setup complete!"
    echo "To activate the environment: source venv/bin/activate"
fi

# Initialize config file
if [[ ! -f .env ]]; then
    echo "Creating initial .env file..."
    if [[ -f .env.example ]]; then
        cp .env.example .env
        echo "Created .env file from .env.example"
        echo "Please edit .env with your API keys."
    else
        # Generate a random secret key
        SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
        
        # Create minimal .env file
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
        echo "Created initial .env file with a generated secret key."
        echo "Please edit .env with your API keys."
    fi
fi

echo "Setup complete!"
echo "Run the application with: python app.py"
