@echo off
REM Hackathon Launcher - Windows
REM Double-cliquez pour demarrer le systeme IDS/IPS

echo ========================================
echo   Systeme de Protection IDS/IPS
echo ========================================
echo.

REM Check if venv exists
if not exist "venv\Scripts\python.exe" (
    echo Environment virtuel non trouve.
    echo Lancez: python setup_hackathon.py
    pause
    exit /b 1
)

REM Start the application
echo Demarrage du systeme...
echo.
echo Accédez au dashboard: http://localhost:9090
echo Login: admin / admin
echo.

venv\Scripts\python.exe main.py

pause