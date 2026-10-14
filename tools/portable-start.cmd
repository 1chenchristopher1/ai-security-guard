@echo off
REM ===========================================================================
REM  AI Security Guard - launcher
REM
REM  Just double-click this file. Nothing needs to be installed.
REM
REM  This file is deliberately PURE ASCII. On a Chinese Windows installation
REM  cmd.exe reads batch files as GBK, so UTF-8 Chinese text inside a .cmd file
REM  shifts the parser and produces "not recognized as an internal or external
REM  command" errors from fragments of the text. All Chinese guidance therefore
REM  lives in a separate Markdown file that ships alongside this one.
REM
REM  After starting, open http://127.0.0.1:8080
REM ===========================================================================
setlocal

set "HERE=%~dp0"
set "JAR=%HERE%ai-security-guard.jar"
set "KEYFILE=%HERE%apikey.txt"
set "RUNTIME=%HERE%runtime\bin\java.exe"

echo.
echo ==============================================================
echo   AI Security Guard
echo ==============================================================
echo.

REM ---------------------------------------------------------------- check jar
if not exist "%JAR%" (
  echo [ERROR] ai-security-guard.jar was not found.
  echo [ERROR] Please EXTRACT the whole archive to a folder first,
  echo [ERROR] then run start.cmd from inside that folder.
  echo.
  pause
  exit /b 1
)

REM ---------------------------------------------------------------- which java
REM Prefer the bundled runtime, so the presenter needs nothing installed.
set "JAVA_EXE="
if exist "%RUNTIME%" set "JAVA_EXE=%RUNTIME%"
if not defined JAVA_EXE (
  for %%I in (java.exe) do if not "%%~$PATH:I"=="" set "JAVA_EXE=%%~$PATH:I"
)
if not defined JAVA_EXE (
  echo [ERROR] No Java runtime found, and this archive has no runtime folder.
  echo [ERROR] Install Java 21 on this machine, then run start.cmd again.
  echo.
  pause
  exit /b 1
)

REM ---------------------------------------------------------------- api key
REM Resolution order: apikey.txt next to this file, then the DEEPSEEK_API_KEY
REM environment variable. The file wins because it is the one a presenter can
REM actually edit without knowing anything about environment variables.
REM
REM The line is selected with findstr rather than taken from the start of the
REM file. Two traps made the obvious approaches fail:
REM   - without eol=#, for /f reads the FIRST line, which is an instruction
REM     comment, and uses that as the key;
REM   - with a plain loop, the BLANK lines yield an empty token, which sets the
REM     variable and then blocks the real key from being picked up.
set "API_KEY="
if exist "%KEYFILE%" (
  for /f "usebackq delims=" %%K in (`findstr /R /C:"^sk-" "%KEYFILE%"`) do (
    if not defined API_KEY set "API_KEY=%%K"
  )
)
if not defined API_KEY if defined DEEPSEEK_API_KEY set "API_KEY=%DEEPSEEK_API_KEY%"

REM The application reads DEEPSEEK_API_KEY from its own environment, so the key
REM resolved above has to be exported under that exact name. Setting only
REM API_KEY starts the app successfully but leaves the agent with no credential,
REM which shows up as a polite "no API key configured" assessment rather than a
REM startup error - a confusing way to discover a one-line mistake.
set "DEEPSEEK_API_KEY=%API_KEY%"

REM A real key starts with "sk-" and is long. Both conditions are checked because
REM the placeholder line in apikey.txt must not be mistaken for a key: a check on
REM the prefix alone would accept a template that happened to contain it.
set "KEY_OK=0"
echo %API_KEY% | findstr /I /C:"sk-" >nul 2>nul
if not errorlevel 1 if not "%API_KEY:~33,1%"=="" set "KEY_OK=1"
if "%KEY_OK%"=="0" set "DEEPSEEK_API_KEY="

if not defined DEEPSEEK_API_KEY (
  echo --------------------------------------------------------------
  echo   A DeepSeek API key is required
  echo --------------------------------------------------------------
  echo.
  echo   The AI agent uses it to make decisions during the demo.
  echo.
  echo   How to get one:
  echo     1. Open  https://platform.deepseek.com
  echo     2. Sign up or log in, and go to the API Keys page
  echo     3. Create a key  ^(it looks like  sk-xxxxxxxx^)
  echo     4. Open  apikey.txt  in this folder with Notepad,
  echo        paste the key in, and save the file
  echo     5. Double-click start.cmd again
  echo.
  echo   The key is a secret. Do not screenshot it or send it anywhere.
  echo.
  echo   No key available? You can still show the interface:
  echo     open this file in Notepad and change the POLICY line below
  echo     from llm to reference. That uses a built-in deterministic
  echo     policy with no network and no key - but the demo is weaker,
  echo     because no real AI is making the decisions.
  echo.
  pause
  exit /b 1
)

set "POLICY=llm"

REM ---------------------------------------------------------------- port
set "PORT=8080"
if not "%SERVER_PORT%"=="" set "PORT=%SERVER_PORT%"

netstat -ano | findstr ":%PORT% " | findstr "LISTENING" >nul 2>nul
if not errorlevel 1 (
  echo [NOTE] Port %PORT% is already in use, so the application is probably
  echo [NOTE] already running.
  echo.
  echo        Open your browser at:   http://127.0.0.1:%PORT%
  echo.
  echo        If that does not load, something else holds the port. Stop it:
  echo          taskkill /F /IM java.exe
  echo        then double-click start.cmd again.
  echo.
  pause
  exit /b 1
)

REM ---------------------------------------------------------------- run
echo   Starting, please wait (about 5 seconds)...
echo.
echo   When it has started, open your browser at:
echo.
echo       http://127.0.0.1:8080
echo.
echo   Leave this window open. Press Ctrl+C to stop.
echo.

"%JAVA_EXE%" -Dfile.encoding=UTF-8 -jar "%JAR%" "--aisecurityguard.agent.policy=%POLICY%" "--server.port=%PORT%"

echo.
echo The application has stopped.
pause
exit /b 0
