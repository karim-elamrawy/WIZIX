@echo off
setlocal
chcp 65001 >nul
title WIZIX Windows Security Center
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 goto use_py
where python >nul 2>nul
if %errorlevel%==0 goto use_python
echo.
echo [WIZIX] Python 3 was not found.
echo Install Python 3.10 or newer from https://www.python.org/downloads/
echo During setup, enable the option to add Python to PATH.
pause
exit /b 1
:use_py
py -3 wizix_scanner.py
if errorlevel 1 echo [WIZIX] The local engine stopped with an error. Read the message above.
goto finish
:use_python
python wizix_scanner.py
if errorlevel 1 echo [WIZIX] The local engine stopped with an error. Read the message above.
:finish
echo.
echo [WIZIX] Keep this window open while using the application.
pause
endlocal
