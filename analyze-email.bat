@echo off
REM PhishGuard SOC - drag-and-drop analysis helper.
REM
REM Usage: drag a .eml file onto this .bat file in Windows Explorer,
REM or double-click it to be prompted for a path interactively.
REM
REM Requires: Python 3.11+ installed and on PATH, and this project's
REM dependencies already installed (pip install -r requirements.txt),
REM ideally inside the project's venv. If you use a venv, uncomment
REM and adjust the "call" line below to activate it first.

setlocal
cd /d "%~dp0"

REM If you created a virtual environment named "venv" in this project
REM folder, uncomment the next line so this script uses it automatically:
REM call venv\Scripts\activate.bat

if "%~1"=="" (
    echo No file was dropped onto this shortcut.
    echo Starting PhishGuard SOC in interactive mode instead...
    echo.
    python -m src.main analyze
) else (
    python -m src.main analyze "%~1"
)

echo.
pause