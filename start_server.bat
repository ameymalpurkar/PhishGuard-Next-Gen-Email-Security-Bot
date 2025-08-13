@echo off
echo Starting Phishing Detection Server with Debug Logging
echo ------------------------------------------------------
echo.
echo This script runs the phishing detection server with detailed logging
echo to help diagnose issues with the Gemini API and other components.
echo.
echo Press Ctrl+C to stop the server.
echo.

REM Create logs directory if it doesn't exist
if not exist "logs" mkdir logs

REM Get current date and time for log filename
for /f "tokens=2 delims==" %%a in ('wmic OS Get localdatetime /value') do set "dt=%%a"
set "YYYY=%dt:~0,4%"
set "MM=%dt:~4,2%"
set "DD=%dt:~6,2%"
set "HH=%dt:~8,2%"
set "Min=%dt:~10,2%"
set "Sec=%dt:~12,2%"

set "logfile=logs\server_%YYYY%-%MM%-%DD%_%HH%-%Min%-%Sec%.log"

echo Starting server with logs at: %logfile%
echo.

REM Run the server with output to both console and log file
python phishing_detection.py 2>&1 | tee %logfile%
