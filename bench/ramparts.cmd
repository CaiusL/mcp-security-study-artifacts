@echo off
rem Linux build via WSL: the Windows release is built without YARA support.
wsl.exe -e /mnt/c/Test/ramparts/ramparts %*
