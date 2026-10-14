@echo off
REM ---------------------------------------------------------------------------
REM Run the terminal demonstration.
REM
REM   demo.cmd              reference policy (deterministic, offline)
REM   demo.cmd --llm        live DeepSeek model (needs DEEPSEEK_API_KEY)
REM   demo.cmd --fast       skip the pauses between segments
REM
REM Anything else is passed through to the runner.
REM ---------------------------------------------------------------------------
setlocal

set "PROJECT_DIR=%~dp0"
if "%MAVEN_REPO_LOCAL%"=="" set "MAVEN_REPO_LOCAL=%PROJECT_DIR%.m2repo"

set "MVN_CMD="
for %%I in (mvn.cmd) do if not "%%~$PATH:I"=="" set "MVN_CMD=%%~$PATH:I"
if not defined MVN_CMD if defined MAVEN_HOME if exist "%MAVEN_HOME%\bin\mvn.cmd" set "MVN_CMD=%MAVEN_HOME%\bin\mvn.cmd"
if not defined MVN_CMD if defined M2_HOME if exist "%M2_HOME%\bin\mvn.cmd" set "MVN_CMD=%M2_HOME%\bin\mvn.cmd"
if not defined MVN_CMD (
  set "MVN_BEST_VER=0.0.0"
  for /f "delims=" %%F in ('dir /b /s "%USERPROFILE%\.m2\wrapper\dists\*mvn.cmd" 2^>nul') do call :consider "%%F"
)
if not defined MVN_CMD goto :notfound

REM The exec plugin is addressed by full coordinates: bare "exec:java" makes Maven scan the
REM configured plugin groups, which touches unrelated repositories and can fail on permissions.
set "EXEC_GOAL=org.codehaus.mojo:exec-maven-plugin:3.1.0:java"
set "MAIN_CLASS=com.aisecurityguard.demo.DemoRunner"

call "%MVN_CMD%" -f "%PROJECT_DIR%pom.xml" -Dmaven.repo.local="%MAVEN_REPO_LOCAL%" -q ^
  "%EXEC_GOAL%" "-Dexec.mainClass=%MAIN_CLASS%" "-Dexec.args=%*"
exit /b %ERRORLEVEL%

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

:notfound
echo [demo] ERROR: no Maven installation found. Set MAVEN_HOME or install Maven.
exit /b 1
