#!/bin/bash

# Check if the virtual environment already exists
if [ ! -d "venv" ]; then
    echo "Creating a virtual environment..."
    python3 -m venv venv

    # Activate the virtual environment
    source venv/bin/activate

    echo "Installing the required packages..."
    pip install discord shodan
else
    # Activate the virtual environment
    source venv/bin/activate
fi

# Run the bot
python3 main.py