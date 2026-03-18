@echo off
:: PacketSpy Launcher — must be run as Administrator

:: Check for admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"

:: Check for Npcap
if not exist "%WINDIR%\System32\Npcap\wpcap.dll" (
    echo ============================================
    echo  Npcap is required but not installed.
    echo  Opening the Npcap download page...
    echo ============================================
    echo.
    echo  1. Download the installer from the page that opens
    echo  2. Run it and check "Install Npcap in WinPcap API-compatible Mode"
    echo  3. After installing, run this script again
    echo.
    start "" "https://npcap.com/#download"
    pause
    exit /b
)

:: Check for Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ============================================
    echo  Python is required but not found in PATH.
    echo  Please install Python 3.12 from python.org
    echo ============================================
    pause
    exit /b
)

:: Create venv if it doesn't exist
if not exist "venv\Scripts\activate.bat" (
    echo Creating virtual environment...
    python -m venv venv
    call venv\Scripts\activate.bat
    echo Installing dependencies...
    pip install -r requirements.txt
) else (
    call venv\Scripts\activate.bat
)

:: Open browser after a short delay
start "" cmd /c "timeout /t 3 /nobreak >nul & start http://127.0.0.1:5000"

:: Start PacketSpy
python app.py
