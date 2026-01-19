#!/bin/bash
set -e

echo "Starting Installation"

if [[ "$OSTYPE" != "linux-gnu"* && "$OSTYPE" != "darwin"* ]]; then
    echo "Unsupported OS. This script supports Linux and macOS."
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo "Python 3 not found. Please install Python 3.7+."
    exit 1
fi

echo "Installing system dependencies..."
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    sudo apt-get update
    sudo apt-get install -y bluez python3-bluez libbluetooth-dev python3-pip python3-venv
elif [[ "$OSTYPE" == "darwin"* ]]; then
    if ! command -v brew &> /dev/null; then
        echo "Homebrew not found. Please install it from https://brew.sh"
        exit 1
    fi
    brew install bluez python3
fi

echo "Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "Installation complete."
echo "Activate the environment with: source venv/bin/activate"
echo "On Linux, you may need to grant network capabilities: sudo setcap cap_net_raw+eip \$(which python3)"
