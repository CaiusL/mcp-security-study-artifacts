@echo off
rem Keeps drift snapshots in one place so reruns from any folder compare against them.
setlocal
set PYTHONUTF8=1
if not defined MCP_SCAN_SNAPSHOTS set "MCP_SCAN_SNAPSHOTS=%~dp0fr2endly-mcp-scan\.mcp-scan-snapshots"
"%~dp0fr2endly-mcp-scan\.venv\Scripts\mcp-scan.exe" %*
