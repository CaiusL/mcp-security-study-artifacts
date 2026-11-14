@echo off
setlocal
set PYTHONUTF8=1
"%~dp0mcp-fence\.venv\Scripts\mcp-fence.exe" %*
