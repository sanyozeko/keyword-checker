@echo off
cd /d "%~dp0"
echo Starting Keyword Checker server...
echo Open http://localhost:5000/checker.html in your browser
echo Press Ctrl+C to stop
echo.
python server.py
pause
