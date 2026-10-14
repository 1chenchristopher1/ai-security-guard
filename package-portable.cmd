@echo off
REM ---------------------------------------------------------------------------
REM Builds the portable distribution for handing to a presenter.
REM
REM   package-portable.cmd
REM
REM Produces AI-Security-Guard-portable.zip in this folder. The presenter
REM extracts it, pastes a DeepSeek API key into apikey.txt, and double-clicks
REM start.cmd. Nothing needs to be installed on their machine: the Java runtime
REM is bundled.
REM
REM This file is pure ASCII on purpose. cmd.exe on a Chinese Windows console
REM reads .cmd files as GBK, so non-ASCII text inside one shifts the parser.
REM ---------------------------------------------------------------------------
setlocal

set "PROJECT_DIR=%~dp0"
if "%MAVEN_REPO_LOCAL%"=="" set "MAVEN_REPO_LOCAL=%PROJECT_DIR%.m2repo"
set "JAR=%PROJECT_DIR%target\agentic-cyber-defence-0.0.1-SNAPSHOT.jar"

REM ---------------------------------------------------------------- Maven
set "MVN_CMD="
for %%I in (mvn.cmd) do if not "%%~$PATH:I"=="" set "MVN_CMD=%%~$PATH:I"
if defined MVN_CMD goto :havemaven

if defined MAVEN_HOME if exist "%MAVEN_HOME%\bin\mvn.cmd" set "MVN_CMD=%MAVEN_HOME%\bin\mvn.cmd"
if defined MVN_CMD goto :havemaven
if defined M2_HOME if exist "%M2_HOME%\bin\mvn.cmd" set "MVN_CMD=%M2_HOME%\bin\mvn.cmd"
if defined MVN_CMD goto :havemaven

set "MVN_BEST_VER=0.0.0"
for /f "delims=" %%F in ('dir /b /s "%USERPROFILE%\.m2\wrapper\dists\*mvn.cmd" 2^>nul') do call :consider "%%F"

:havemaven
if not defined MVN_CMD (
  echo [package] ERROR: no Maven installation found.
  exit /b 1
)

echo [package] Building the application jar...
call "%MVN_CMD%" -f "%PROJECT_DIR%pom.xml" -Dmaven.repo.local="%MAVEN_REPO_LOCAL%" -q package -DskipTests
if errorlevel 1 (
  echo [package] ERROR: the build failed.
  exit /b 1
)

echo [package] Assembling the portable distribution...
REM "%~dp0" ends with a backslash, and passing it as "...Guard\" makes PowerShell read the
REM backslash as escaping the closing quote, so the argument never terminates. The "." suffix
REM removes the trailing separator.
powershell -NoProfile -ExecutionPolicy Bypass -File "%PROJECT_DIR%tools\build-portable.ps1" -OutDirectory "%PROJECT_DIR%."
if errorlevel 1 (
  echo [package] ERROR: the portable build failed.
  exit /b 1
)

echo.
echo [package] Done:  %PROJECT_DIR%AI-Security-Guard-portable.zip
echo.
exit /b 0

REM ---------------------------------------------------------------- helpers
:consider
set "CAND=%~1"
set "REST=%CAND:*apache-maven-=%"
for /f "tokens=1 delims=\" %%V in ("%REST%") do set "CANDVER=%%V"
set "CANDVER=%CANDVER:-bin=%"
if "%CANDVER%"=="" exit /b 0
if "%CANDVER%"=="%MVN_BEST_VER%" exit /b 0
call :isNewer "%CANDVER%" "%MVN_BEST_VER%"
if not "%NEWER%"=="1" exit /b 0
set "MVN_BEST_VER=%CANDVER%"
set "MVN_CMD=%CAND%"
exit /b 0

:isNewer
set "NEWER=0"
for /f "tokens=1,2,3 delims=." %%A in ("%~1") do set "VA=%%A" & set "VB=%%B" & set "VC=%%C"
for /f "tokens=1,2,3 delims=." %%A in ("%~2") do set "WA=%%A" & set "WB=%%B" & set "WC=%%C"
if "%VC%"=="" set "VC=0"
if "%WC%"=="" set "WC=0"
if %VA% GTR %WA% set "NEWER=1" & exit /b 0
if %VA% LSS %WA% exit /b 0
if %VB% GTR %WB% set "NEWER=1" & exit /b 0
if %VB% LSS %WB% exit /b 0
if %VC% GTR %WC% set "NEWER=1"
exit /b 0
