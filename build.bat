@echo off
REM ================================================================
REM  SafeCheck Desktop - Windows .exe build script
REM  Run on Windows 10/11 with Python 3.10+ (64-bit) installed.
REM  Python install karte waqt "Add python.exe to PATH" tick karna.
REM ================================================================
cd /d "%~dp0"

python -c "import struct,sys; sys.exit(0 if struct.calcsize('P')==8 else 1)"
if errorlevel 1 (
  echo WARNING: 32-bit Python detected. Please install 64-bit Python 3.12 for the best results.
  echo          A 32-bit build cannot see some Windows system files correctly.
  pause
)
echo [1/3] Creating isolated build environment (.venv) ...
python -m venv .venv || goto :err
call .venv\Scripts\activate.bat

echo [2/3] Installing psutil + PyInstaller (only inside .venv) ...
python -m pip install --upgrade pip >nul
python -m pip install -r requirements.txt || goto :err

echo [3/3] Building SafeCheckDesktop.exe ...
python -m PyInstaller --noconfirm --clean --onefile --windowed --name SafeCheckDesktop safecheck.py || goto :err

echo.
echo DONE:  %~dp0dist\SafeCheckDesktop.exe
echo Right-click it and choose "Run as administrator" for complete results.
pause
exit /b 0

:err
echo.
echo BUILD FAILED - check the error above.
pause
exit /b 1
