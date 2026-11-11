@echo off
setlocal
cd /d "%~dp0"
title MODUS FLOW
set "PYTHON=.venv\Scripts\python.exe"
if not exist "%PYTHON%" (
    python -c "import sys; sys.exit(sys.version_info < (3, 11))" >nul 2>&1
    if errorlevel 1 (
        py -3.11 -m venv .venv || goto python_missing
    ) else (
        python -m venv .venv || goto failed
    )
)

if not exist ".venv\modus-requirements.txt" goto install
fc /b requirements.txt ".venv\modus-requirements.txt" >nul 2>&1
if not errorlevel 1 goto frontend
:install
"%PYTHON%" -m pip install -r requirements.txt || goto failed
copy /y requirements.txt ".venv\modus-requirements.txt" >nul || goto failed

:frontend
where npm >nul 2>&1
if errorlevel 1 (
    echo Install Node.js and npm and add them to PATH.
    goto failed
)
pushd frontend-react || goto failed
if not exist "node_modules\.bin\vite.cmd" goto install_frontend
fc /b package-lock.json "node_modules\modus-package-lock.json" >nul 2>&1
if not errorlevel 1 goto build_frontend
:install_frontend
call npm ci || goto frontend_failed
copy /y package-lock.json "node_modules\modus-package-lock.json" >nul || goto frontend_failed
:build_frontend
call npm run build || goto frontend_failed
popd

if not exist ".venv\modus-session-secret.txt" (
    "%PYTHON%" -c "import secrets; print(secrets.token_hex(32))" > ".venv\modus-session-secret.txt" || goto failed
)
if not defined SESSION_SECRET set /p SESSION_SECRET=<".venv\modus-session-secret.txt"

"%PYTHON%" -m scripts.run_services || goto failed
exit /b 0

:frontend_failed
popd
:failed
echo.
echo MODUS FLOW could not start. Check the output above and README.md.
pause
exit /b 1


:python_missing
echo Install Python 3.11 or newer and add python.exe to PATH.
goto failed
