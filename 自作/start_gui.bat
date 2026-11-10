@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\pythonw.exe" (
  start "Mabinogi JP DPS" ".venv\Scripts\pythonw.exe" "%~dp0start_gui.py"
) else (
  py -3 "%~dp0start_gui.py"
)
