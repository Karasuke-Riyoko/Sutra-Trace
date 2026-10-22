@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"
set "LOG=%~dp0cockpit_start.log"
echo SUTRA-Trace start log %DATE% %TIME% > "%LOG%"
echo Folder: %CD% >> "%LOG%"

if not exist "sector_e_dashboard.py" (
  echo Could not find sector_e_dashboard.py next to this file.
  echo Keep "Start SUTRA-Trace Cockpit.bat" inside the prototype folder.
  echo ERROR: sector_e_dashboard.py missing >> "%LOG%"
  pause
  exit /b 1
)

rem ---- stop any cockpit that is already running (only sector_e_dashboard.py --serve/--port) ----
echo Checking for an older cockpit that is still running...
set "KILLOUT=%TEMP%\sutra_cockpit_kill.txt"
powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand JABFAHIAcgBvAHIAQQBjAHQAaQBvAG4AUAByAGUAZgBlAHIAZQBuAGMAZQAgAD0AIAAnAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUAJwAKACQAUAByAG8AZwByAGUAcwBzAFAAcgBlAGYAZQByAGUAbgBjAGUAIAA9ACAAJwBTAGkAbABlAG4AdABsAHkAQwBvAG4AdABpAG4AdQBlACcACgAkAG4AIAA9ACAAMAAKACQAcAByAG8AYwBzACAAPQAgAEcAZQB0AC0AQwBpAG0ASQBuAHMAdABhAG4AYwBlACAAVwBpAG4AMwAyAF8AUAByAG8AYwBlAHMAcwAgAHwAIABXAGgAZQByAGUALQBPAGIAagBlAGMAdAAgAHsAIAAkAF8ALgBQAHIAbwBjAGUAcwBzAEkAZAAgAC0AbgBlACAAJABQAEkARAAgAC0AYQBuAGQAIAAkAF8ALgBDAG8AbQBtAGEAbgBkAEwAaQBuAGUAIAAtAGEAbgBkACAAJABfAC4AQwBvAG0AbQBhAG4AZABMAGkAbgBlACAALQBsAGkAawBlACAAJwAqAHMAZQBjAHQAbwByAF8AZQBfAGQAYQBzAGgAYgBvAGEAcgBkAC4AcAB5ACoAJwAgAC0AYQBuAGQAIAAoACQAXwAuAEMAbwBtAG0AYQBuAGQATABpAG4AZQAgAC0AbABpAGsAZQAgACcAKgAtAC0AcwBlAHIAdgBlACoAJwAgAC0AbwByACAAJABfAC4AQwBvAG0AbQBhAG4AZABMAGkAbgBlACAALQBsAGkAawBlACAAJwAqAC0ALQBwAG8AcgB0ACoAJwApACAAfQAKAGYAbwByAGUAYQBjAGgAIAAoACQAcAAgAGkAbgAgACQAcAByAG8AYwBzACkAIAB7ACAAUwB0AG8AcAAtAFAAcgBvAGMAZQBzAHMAIAAtAEkAZAAgACQAcAAuAFAAcgBvAGMAZQBzAHMASQBkACAALQBGAG8AcgBjAGUAOwAgACQAbgArACsAOwAgAFcAcgBpAHQAZQAtAE8AdQB0AHAAdQB0ACAAKAAnAFMAdABvAHAAcABlAGQAIABvAGwAZAAgAGMAbwBjAGsAcABpAHQAIABwAHIAbwBjAGUAcwBzACAAJwAgACsAIAAkAHAALgBQAHIAbwBjAGUAcwBzAEkAZAAgACsAIAAnACAAKAAnACAAKwAgACQAcAAuAE4AYQBtAGUAIAArACAAJwApACcAKQAgAH0ACgAkAHcAaQBuAHMAIAA9ACAARwBlAHQALQBQAHIAbwBjAGUAcwBzACAALQBOAGEAbQBlACAAYwBtAGQAIAB8ACAAVwBoAGUAcgBlAC0ATwBiAGoAZQBjAHQAIAB7ACAAJABfAC4ASQBkACAALQBuAGUAIAAkAFAASQBEACAALQBhAG4AZAAgACQAXwAuAE0AYQBpAG4AVwBpAG4AZABvAHcAVABpAHQAbABlACAALQBsAGkAawBlACAAJwBTAFUAVABSAEEALQBUAHIAYQBjAGUAIABDAG8AYwBrAHAAaQB0ACoAJwAgAH0ACgBmAG8AcgBlAGEAYwBoACAAKAAkAHcAIABpAG4AIAAkAHcAaQBuAHMAKQAgAHsAIABTAHQAbwBwAC0AUAByAG8AYwBlAHMAcwAgAC0ASQBkACAAJAB3AC4ASQBkACAALQBGAG8AcgBjAGUAOwAgAFcAcgBpAHQAZQAtAE8AdQB0AHAAdQB0ACAAKAAnAEMAbABvAHMAZQBkACAAbwBsAGQAIABjAG8AYwBrAHAAaQB0ACAAdwBpAG4AZABvAHcAIAAnACAAKwAgACQAdwAuAEkAZAApACAAfQAKAGkAZgAgACgAJABuACAALQBlAHEAIAAwACkAIAB7ACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAE4AbwAgAG8AbABkACAAYwBvAGMAawBwAGkAdAAgAHcAYQBzACAAcgB1AG4AbgBpAG4AZwAuACcAIAB9AAoA > "%KILLOUT%" 2>nul
type "%KILLOUT%"
type "%KILLOUT%" >> "%LOG%"
del "%KILLOUT%" >nul 2>nul
ping -n 2 127.0.0.1 >nul
title SUTRA-Trace Cockpit

rem ---- find Python 3 ----
set "PY="
py -3 --version >nul 2>nul && set "PY=py -3"
if not defined PY (
  python --version >nul 2>nul && set "PY=python"
)
if not defined PY (
  python3 --version >nul 2>nul && set "PY=python3"
)
if not defined PY (
  echo.
  echo Python 3 was not found on this computer.
  echo Install it from https://www.python.org/downloads/
  echo and tick "Add python.exe to PATH" during setup, then try again.
  echo ERROR: no Python found (py, python, python3^) >> "%LOG%"
  pause
  exit /b 1
)
for /f "delims=" %%v in ('%PY% --version 2^>^&1') do set "PYVER=%%v"
echo Python: %PY% (!PYVER!) >> "%LOG%"

rem ---- pick a free port (another program may still hold 5000) ----
set "PORT="
for %%p in (5000 5001 5050 8050 8765) do (
  if not defined PORT (
    netstat -ano | findstr /r /c:":%%p .*LISTENING" >nul 2>nul || set "PORT=%%p"
  )
)
if not defined PORT set "PORT=5099"
echo Port: %PORT% >> "%LOG%"

echo.
echo Starting the SUTRA-Trace cockpit with !PYVER! ...
echo Your browser will open at http://127.0.0.1:%PORT%
echo Keep this window open while you use it. Close it to stop the cockpit.
echo.
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
%PY% sector_e_dashboard.py --serve --port %PORT% 2>> "%LOG%"
set "RC=%ERRORLEVEL%"
echo Exit code: %RC% >> "%LOG%"
echo.
if not "%RC%"=="0" (
  echo The cockpit stopped. If that was not you closing it, details are in
  echo cockpit_start.log in this folder.
) else (
  echo The cockpit has stopped.
)
pause
