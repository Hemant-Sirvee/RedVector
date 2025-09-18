#!/bin/bash

echo "[*] Setting up RedVector tool..."

# Install Python3 pip if not installed
if ! command -v pip3 &>/dev/null; then
    echo "[*] Installing pip3..."
    sudo apt update
    sudo apt install -y python3-pip
fi

# Install required Python packages globally
if [ -f "requirements.txt" ]; then
    echo "[*] Installing Python dependencies..."
    sudo pip3 install -r requirements.txt
fi

# Make main script executable
chmod +x redvector.py

# Move the script to /usr/local/bin for global access
sudo mv redvector.py /usr/local/bin/redvector

echo "[*] Setup completed! You can now run RedVector by typing 'redvector' in the terminal."
