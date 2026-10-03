@echo off
set PYTHONDONTWRITEBYTECODE=1
where python >nul 2>nul
if %ERRORLEVEL% equ 0 (
    python -B "%~dp0extension_backup_agent.py"
) else (
    "C:\Python314\python.exe" -B "%~dp0extension_backup_agent.py"
)
