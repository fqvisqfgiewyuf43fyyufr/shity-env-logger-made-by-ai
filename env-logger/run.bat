@echo off
rem ---------------------------------------------------------------------------
rem run.bat - one-click runner for env_logger
rem
rem Drops into this folder, then logs script.lua with a preset tuned for
rem obfuscated/hostile scripts that take a while to unpack:
rem
rem   python env_logger.py script.lua -o logged.lua --no-fetched --timeout 360 --clean
rem
rem   --no-fetched  don't dump fetched payload sources, just the calls
rem   --timeout 360 give the script up to 6 minutes to unpack
rem   --clean       keep only readable calls, drop VM junk
rem
rem Put the script you want to log in this folder as "script.lua", then
rem double-click this file. script.lua ships empty on purpose: the folder is
rem the drop-in slot. run.bat stops with a clear message if it is still empty.
rem Results land in logged.lua + logged.trace.lua.
rem ---------------------------------------------------------------------------

setlocal
cd /d "%~dp0"

set "_SIZE=0"
if exist "script.lua" for %%A in ("script.lua") do set "_SIZE=%%~zA"
if "%_SIZE%"=="0" (
    echo.
    echo   error: script.lua is missing or empty.
    echo     %CD%
    echo.
    echo   Put the script you want to log in this folder as "script.lua",
    echo   then run this again.
    echo.
    pause
    exit /b 1
)

echo.
echo   logging script.lua ^(timeout 360s, this can take a while^)
echo.

python env_logger.py script.lua -o logged.lua --no-fetched --timeout 360 --clean
set "_RC=%ERRORLEVEL%"

echo.
if not "%_RC%"=="0" echo   env_logger exited with code %_RC%
echo   output: logged.lua   trace: logged.trace.lua
echo.
pause
exit /b %_RC%