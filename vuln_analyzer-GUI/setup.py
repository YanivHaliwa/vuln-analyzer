#!/usr/bin/env python3
"""
Setup script for Pentester Analysis Tool.

This script performs initial setup tasks like:
1. Creating necessary directories
2. Generating a secure key for the Flask application
3. Creating an initial configuration file
"""
import os
import sys
import secrets
import argparse

def generate_key(length=32):
    """Generate a secure random key for the Flask application"""
    return secrets.token_hex(length)

def create_directory(path):
    """Create directory if it doesn't exist"""
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)
        print(f"Created directory: {path}")

def create_env_file(base_dir):
    """Create initial .env file with a secure key"""
    env_path = os.path.join(base_dir, '.env')
    example_path = os.path.join(base_dir, '.env.example')
    
    if os.path.exists(env_path):
        print(f".env file already exists at {env_path}")
        return
    
    # Generate secure key
    secret_key = generate_key()
    
    # If example file exists, use it as template
    if os.path.exists(example_path):
        with open(example_path, 'r') as f:
            content = f.read()
        
        # Replace placeholder with actual key
        content = content.replace('generate_a_random_secret_key_here', secret_key)
        
        with open(env_path, 'w') as f:
            f.write(content)
            
    else:
        # Create minimal .env file
        with open(env_path, 'w') as f:
            f.write(f"SECRET_KEY={secret_key}\n")
            f.write("AI_PROVIDER=openai\n")
            f.write("# Add your API keys here\n")
            f.write("OPENAI_API_KEY=your_openai_api_key_here\n")
            f.write("CLAUDE_API_KEY=your_claude_api_key_here\n")
    
    print(f"Created .env file with a secure key at {env_path}")

def check_dependencies():
    """Check if required Python packages are installed"""
    try:
        import flask
        import openai
        import anthropic
        import dotenv
        print("All required dependencies are installed.")
        return True
    except ImportError as e:
        print(f"Missing dependency: {e}")
        print("Please install required dependencies using: pip install -r requirements.txt")
        return False

def setup(args):
    """Perform setup tasks"""
    # Determine base directory
    if args.dir:
        base_dir = os.path.abspath(args.dir)
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))
    
    print(f"Setting up Pentester Analysis Tool in {base_dir}")
    
    # Create required directories
    create_directory(os.path.join(base_dir, 'uploads'))
    create_directory(os.path.join(base_dir, 'static', 'css'))
    create_directory(os.path.join(base_dir, 'static', 'js'))
    create_directory(os.path.join(base_dir, 'static', 'img'))
    create_directory(os.path.join(base_dir, 'screenshots'))
    
    # Create .env file
    create_env_file(base_dir)
    
    # Check dependencies
    if not check_dependencies():
        return
    
    print("\nSetup completed successfully!")
    print("\nTo run the application:")
    print("1. Make sure your API keys are set in the .env file")
    print("2. Run: python app.py")
    print("3. Access the application at http://localhost:5000")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Setup Pentester Analysis Tool')
    parser.add_argument('--dir', help='Base directory for the application')
    
    args = parser.parse_args()
    setup(args)
