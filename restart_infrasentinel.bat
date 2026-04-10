@echo off
setlocal
cd /d "%~dp0"

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0restart_infrasentinel.ps1"
set EXIT_CODE=%ERRORLEVEL%

if not "%EXIT_CODE%"=="0" (
    echo.
    echo Redemarrage echoue. Verifie app_stderr.log
)

endlocal & exit /b %EXIT_CODE%

