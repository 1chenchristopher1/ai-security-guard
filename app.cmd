@echo off
REM ---------------------------------------------------------------------------
REM Start the web application.
REM
REM   app.cmd              reference policy (deterministic, offline)
REM   app.cmd --llm        live DeepSeek model (needs DEEPSEEK_API_KEY)
REM
REM Then open http://127.0.0.1:8080
REM
REM If the jar has not been built, this builds it first. Maven is located the
REM same way mvnw.cmd locates it; on this machine it only exists in the Maven
REM Wrapper cache, so searching PATH alone is not enough.
REM
REM The "spring-boot:run" goal is avoided because it resolves the buildpack
REM plugin, which is unnecessary here and fails on some repository permissions.
REM ---------------------------------------------------------------------------
setlocal

set "PROJECT_DIR=%~dp0"
if "%MAVEN_REPO_LOCAL%"=="" set "MAVEN_REPO_LOCAL=%PROJECT_DIR%.m2repo"
set "JAR=%PROJECT_DIR%target\agentic-cyber-defence-0.0.1-SNAPSHOT.jar"

set "POLICY=reference"
if /I "%~1"=="--llm" set "POLICY=llm"
if /I "%~2"=="--llm" set "POLICY=llm"
if /I "%~1"=="--restart" set "AE_RESTART=1"
if /I "%~2"=="--restart" set "AE_RESTART=1"

REM Argument echoed back in the "already running" hint, so the suggested command is correct.
set "POLICY_ARG="
if /I "%POLICY%"=="llm" set "POLICY_ARG=--llm"

REM How a previous instance is stopped, when --restart is given. Java processes only: killing
REM whatever happens to hold the port would be reckless.
set "AE_STOP_CMD=taskkill /F /IM java.exe"

REM Port the application serves on. Override with SERVER_PORT if 8080 is taken by something else.
if "%SERVER_PORT%"=="" set "SERVER_PORT=8080"

REM ---------------------------------------------------------------- Maven
REM 1) PATH
set "MVN_CMD="
for %%I in (mvn.cmd) do if not "%%~$PATH:I"=="" set "MVN_CMD=%%~$PATH:I"
if defined MVN_CMD goto :buildcheck

REM 2) MAVEN_HOME / M2_HOME
if defined MAVEN_HOME if exist "%MAVEN_HOME%\bin\mvn.cmd" set "MVN_CMD=%MAVEN_HOME%\bin\mvn.cmd"
if defined MVN_CMD goto :buildcheck
if defined M2_HOME if exist "%M2_HOME%\bin\mvn.cmd" set "MVN_CMD=%M2_HOME%\bin\mvn.cmd"
if defined MVN_CMD goto :buildcheck

REM 3) Maven Wrapper distribution cache. The cached layouts are inconsistent, so every candidate
REM    is inspected and the highest version wins.
REM
REM    No parenthesised block here on purpose: a label inside one is not reachable by "call", and
REM    a variable set inside one is not visible to "if defined" parsed in the same block.
set "MVN_BEST_VER=0.0.0"
for /f "delims=" %%F in ('dir /b /s "%USERPROFILE%\.m2\wrapper\dists\*mvn.cmd" 2^>nul') do call :consider "%%F"

REM ---------------------------------------------------------------- already running?
REM Checked BEFORE building, not after. A running instance holds the jar open, so repackaging
REM fails with "Unable to rename ... -> .jar.original", which is a confusing error for what is
REM really just "it is already running".
call :portInUse %SERVER_PORT%
if "%PORT_IN_USE%"=="0" goto :buildcheck

REM Something is on the port. Stop it only when --restart was given: killing a process the user did
REM not ask us to kill would be worse than refusing to start.
if not defined AE_RESTART goto :alreadyRunning

:stopRunning
echo [app] Port %SERVER_PORT% is in use; --restart given, so stopping the previous instance...
call %AE_STOP_CMD% >nul 2>nul
call :waitForPortFree
if "%PORT_IN_USE%"=="1" (
  echo [app] ERROR: the port is still in use after stopping Java processes.
  echo [app] Something else holds it. Find it with:  netstat -ano ^| findstr :%SERVER_PORT%
  exit /b 1
)
echo [app] Previous instance stopped.
echo.

REM ---------------------------------------------------------------- build if needed
:buildcheck
REM Rebuild when the jar is missing OR older than the newest source file. Without the timestamp
REM check, a code change followed by "app.cmd" silently runs the previous build - which looks
REM exactly like the change having had no effect, and is a miserable thing to debug.
set "NEED_BUILD=0"
if not exist "%JAR%" set "NEED_BUILD=1"
if "%NEED_BUILD%"=="1" goto :doBuild

REM An existing jar is not necessarily a runnable one: a failed repackage leaves a small jar that
REM contains the project classes but no Main-Class, and "java -jar" then fails with "no main
REM manifest attribute", which does not obviously point at the build. Check it explicitly.
call :jarIsRunnable
if not "%JAR_OK%"=="1" (
  echo [app] The existing jar is not runnable: %JAR_REASON%
  echo [app] Rebuilding.
  set "NEED_BUILD=1"
  goto :doBuild
)

for /f "delims=" %%F in ('dir /b /s /o-d "%PROJECT_DIR%src\main\*.java" "%PROJECT_DIR%src\main\*.properties" "%PROJECT_DIR%src\main\*.html" "%PROJECT_DIR%src\main\*.js" 2^>nul') do call :checkStale "%%F"
if "%NEED_BUILD%"=="0" goto :launch

:doBuild
echo [app] Building the application...
echo.

if not defined MVN_CMD (
  echo [app] ERROR: the build is needed but no Maven installation was found.
  echo [app] Install Maven, or set MAVEN_HOME.
  exit /b 1
)

call "%MVN_CMD%" -f "%PROJECT_DIR%pom.xml" -Dmaven.repo.local="%MAVEN_REPO_LOCAL%" package -DskipTests
if errorlevel 1 (
  echo.
  echo [app] ERROR: the build failed. The output above says why.
  exit /b 1
)
if not exist "%JAR%" (
  echo.
  echo [app] ERROR: the build reported success but produced no jar at:
  echo [app]   %JAR%
  exit /b 1
)
echo.

REM ---------------------------------------------------------------- launch
:launch
if /I "%POLICY%"=="llm" (
  if not defined DEEPSEEK_API_KEY (
    echo [app] --llm was requested but DEEPSEEK_API_KEY is not set in this window.
    echo [app] If you set it with setx, open a NEW window first.
    echo [app] Starting with the reference policy instead.
    set "POLICY=reference"
  )
)

echo [app] Starting with policy: %POLICY%
echo [app] Open http://127.0.0.1:%SERVER_PORT% in your browser.
echo [app] Leave this window open. Press Ctrl+C to stop.
echo.

java -Dfile.encoding=UTF-8 -jar "%JAR%" "--aisecurityguard.agent.policy=%POLICY%" "--server.port=%SERVER_PORT%"
exit /b %ERRORLEVEL%

REM ---------------------------------------------------------------- already running
:alreadyRunning
echo [app] Port %SERVER_PORT% is already in use, so the application is probably already running.
echo.
echo [app] Open http://127.0.0.1:%SERVER_PORT% in your browser and try it.
echo.
echo [app] To stop it and start a fresh build, use:
echo [app]   app.cmd --restart %POLICY_ARG%
echo.
echo [app] If something ELSE holds the port, find it with:
echo [app]   netstat -ano ^| findstr :%SERVER_PORT%
echo [app] and stop that process, or start this one on another port with:
echo [app]   set SERVER_PORT=8081 ^&^& app.cmd --llm
echo.
exit /b 1

REM ---------------------------------------------------------------- helpers

:jarIsRunnable
REM Sets JAR_OK=1 when the jar can actually be started with "java -jar", and JAR_REASON otherwise.
set "JAR_OK=0"
set "JAR_REASON=unknown"
for /f "delims=" %%R in ('powershell -NoProfile -ExecutionPolicy Bypass -File "%PROJECT_DIR%tools\verify-jar.ps1" -Jar "%JAR%" 2^>nul') do set "JAR_REASON=%%R"
if /I "%JAR_REASON%"=="OK" set "JAR_OK=1"
exit /b 0

:waitForPortFree
REM Polls the port for a few seconds: the previous process needs a moment to release both its
REM listening socket and its lock on the jar.
set /a WAITED=0
:waitLoop
call :portInUse %SERVER_PORT%
if "%PORT_IN_USE%"=="0" exit /b 0
set /a WAITED+=1
if %WAITED% GEQ 10 exit /b 0
REM A short pause without relying on timeout.exe, which needs an interactive console.
ping -n 2 127.0.0.1 >nul 2>nul
goto :waitLoop

:checkStale
REM %1 = a source file. Sets NEED_BUILD=1 when it is newer than the jar.
REM The listing is sorted newest-first, so only the first entry really needs comparing; the
REM NEED_BUILD guard makes the rest cheap.
if not "%NEED_BUILD%"=="0" exit /b 0
for %%A in ("%~1") do set "SRC_TIME=%%~tA"
for %%B in ("%JAR%") do set "JAR_TIME=%%~tB"
if "%SRC_TIME%" GTR "%JAR_TIME%" set "NEED_BUILD=1"
exit /b 0

:portInUse
REM %1 = port. Sets PORT_IN_USE=1 when something is accepting connections on it.
REM
REM Uses a TCP connect rather than Get-NetTCPConnection: the latter needs administrator rights and
REM silently returns nothing without them, which made this check useless. Connecting needs no
REM privileges and answers the question that actually matters - is something already serving there.
set "PORT_IN_USE=0"
for /f "delims=" %%P in ('powershell -NoProfile -Command "try { $c = New-Object Net.Sockets.TcpClient; $c.Connect('127.0.0.1', %~1); $c.Close(); '1' } catch { '0' }" 2^>nul') do set "PORT_IN_USE=%%P"
exit /b 0

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
