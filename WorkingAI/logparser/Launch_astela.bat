@echo off
REM Always run from the folder this .bat file lives in.
cd /d "%~dp0"

REM Use the project's virtualenv Python directly instead of whatever
REM "python" happens to resolve to on PATH. A fresh cmd window does not
REM inherit an activated venv from another terminal, which causes
REM "ModuleNotFoundError" for installed packages. Pointing straight at
REM the venv's python.exe avoids activation entirely, and every
REM subprocess launch_astela.py spawns inherits the same interpreter.

REM Default: the venv sits one folder above this file (WorkingAI\.venv),
REM resolved relative to this .bat so it works wherever the repo lives.
for %%I in ("%~dp0..\.venv\Scripts\python.exe") do set "VENV_PYTHON=%%~fI"

REM Optional override: if WorkingAI\.env defines VENV_PYTHON, use that.
if exist "%~dp0..\.env" (
    for /f "usebackq tokens=1,* delims==" %%A in ("%~dp0..\.env") do (
        if /i "%%A"=="VENV_PYTHON" set "VENV_PYTHON=%%B"
    )
)

if not exist "%VENV_PYTHON%" (
    echo [!] Could not find the virtual environment's Python at:
    echo     %VENV_PYTHON%
    echo.
    echo     Fix: create the venv one folder above this file, then install dependencies:
    echo       python -m venv .venv
    echo       .venv\Scripts\python.exe -m pip install -r requirements.txt
    echo     Or set VENV_PYTHON in .env to your python.exe path.
    pause
    exit /b 1
)

"%VENV_PYTHON%" Launch_astela.py

echo.
pause