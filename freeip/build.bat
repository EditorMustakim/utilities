@echo off
rem Compiles freeip.cs into freeip.exe using the C# compiler built into Windows.
setlocal
set CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" set CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe
if not exist "%CSC%" (
    echo Could not find csc.exe. The .NET Framework 4 compiler is missing.
    goto :end
)
"%CSC%" /nologo /optimize /target:exe /out:"%~dp0freeip.exe" "%~dp0freeip.cs"
if errorlevel 1 (
    echo.
    echo Build FAILED. Copy the error lines above and send them to Claude.
) else (
    echo.
    echo Build OK: %~dp0freeip.exe
)
:end
pause
