#!/usr/bin/env python3
"""
Generate a secure key for Flask application
"""

import os
import secrets

def generate_secret_key(length=32):
    """Generate a secure random key"""
    return secrets.token_hex(length)

if __name__ == "__main__":
    key = generate_secret_key()
    print(f"Generated Secret Key: {key}")
    
    # Check if .env file exists
    if os.path.exists('.env'):
        with open('.env', 'r') as f:
            content = f.read()
        
        if 'SECRET_KEY=' in content:
            # Replace existing key
            print("Updating existing SECRET_KEY in .env file...")
            with open('.env', 'w') as f:
                new_content = content.replace(
                    'SECRET_KEY=your_secret_key_here', 
                    f'SECRET_KEY={key}'
                )
                f.write(new_content)
        else:
            # Add new key
            print("Adding SECRET_KEY to .env file...")
            with open('.env', 'a') as f:
                f.write(f'\nSECRET_KEY={key}')
    else:
        # Create new .env file
        print("Creating new .env file with SECRET_KEY...")
        with open('.env', 'w') as f:
            f.write(f'SECRET_KEY={key}\n')
            f.write('AI_PROVIDER=openai\n')
            f.write('OPENAI_API_KEY=your_openai_api_key_here\n')
            f.write('#CLAUDE_API_KEY=your_claude_api_key_here\n')
    
    print("Done! Your application now has a secure SECRET_KEY.")
