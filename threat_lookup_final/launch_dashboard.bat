@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo Virtual environment not found. Running setup first...
  powershell -ExecutionPolicy Bypass -File "%~dp0setup.ps1"
  if errorlevel 1 (
    echo Setup failed.
    exit /b 1
  )
)

echo Launching Threat Lookup Dashboard...
".venv\Scripts\python.exe" "%~dp0run_gui.py"
