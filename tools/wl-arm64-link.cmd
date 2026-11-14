@echo off
python "%~dp0wl-arm64-link.py" %*
exit /b %errorlevel%
