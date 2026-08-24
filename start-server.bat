@echo off
REM ============================================================
REM  CGT local test server  --  ALWAYS use this to start the site
REM ============================================================
REM  Double-click this file (or run it) to serve the site at
REM  http://127.0.0.1:8000 with the CORRECT clean-URL routing.
REM
REM  Do NOT run  "python -m http.server"  --  that dumb builtin
REM  server breaks /private-keys, /mnemonic-converter,
REM  /brainwallet-generator, /mnemonic-seeds/ etc. serve.py
REM  mirrors the LIVE site's pretty-URL rules (extensionless
REM  URLs -> .html, no directory listings), so every option
REM  works locally exactly like on the website.
REM ============================================================
cd /d "%~dp0"
echo.
echo   Starting CGT server on http://127.0.0.1:8000
echo   (close this window, or press Ctrl+C, to stop it)
echo.
where python >nul 2>nul
if %errorlevel%==0 (
    python serve.py
) else (
    py serve.py
)
echo.
echo   Server stopped.
pause
