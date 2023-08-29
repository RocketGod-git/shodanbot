@echo off

REM Check if the virtual environment already exists
if not exist "venv\" (
    echo Creating a virtual environment...
    python -m venv venv
)

REM Activate the virtual environment
call venv\Scripts\activate

echo Installing the required packages...
pip install discord shodan

REM Run the bot
python main.py