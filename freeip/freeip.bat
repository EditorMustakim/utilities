@echo off
rem Usage: freeip 172.25.155.33/27   (run from an open cmd window)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0freeip.ps1" %*
rem If launched by double-click, keep the window open so output can be read
echo %cmdcmdline% | find /i "%~nx0" >nul && pause
