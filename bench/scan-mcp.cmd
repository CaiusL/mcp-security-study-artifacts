@echo off
python "%~dp0scan_mcp.py" %*
if "%~1"=="" pause
