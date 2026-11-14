@echo off
rem Runs from its own folder so the default rule files resolve; reports land there too.
setlocal
set PYTHONUTF8=1
pushd "%~dp0nova-proximity"
".venv\Scripts\python.exe" novaprox.py -n %*
popd
