@echo off
REM ---------------------------------------------------------------------------
REM Maven launcher for this project.
REM
REM Maven itself is not installed on this machine and the standard Maven Wrapper
REM cannot be used as-is, so this script locates an existing Maven (PATH,
REM MAVEN_HOME, or the Maven Wrapper distribution cache) and runs it against the
REM local repository.
REM
REM Network access to Maven Central works from the JVM, so this is NOT offline.
REM If you are on a machine without connectivity, pass -o explicitly:
REM     mvnw.cmd -o test
REM
REM Usage:  mvnw.cmd test
REM ---------------------------------------------------------------------------
setlocal

REM The Maven repository lives inside the workspace. The file sandbox permits writes only under
REM the session workspace, so a repository under %USERPROFILE%\.m2 can be read but not updated:
REM any new artefact fails with AccessDeniedException when Maven tries to write it. Pointing at a
REM workspace copy keeps the build self-contained and writable.
REM
REM Override with MAVEN_REPO_LOCAL if you prefer somewhere else.
if "%MAVEN_REPO_LOCAL%"=="" set "MAVEN_REPO_LOCAL=%~dp0.m2repo"

REM Maven is invoked against this script's own pom.xml, so the wrapper works regardless of the
REM caller's current directory.
set "PROJECT_POM=%~dp0pom.xml"

set "MVN_CMD="

REM 1) Maven already on PATH
for %%I in (mvn.cmd) do if not "%%~$PATH:I"=="" set "MVN_CMD=%%~$PATH:I"
if defined MVN_CMD goto :run

REM 2) MAVEN_HOME / M2_HOME
if defined MAVEN_HOME if exist "%MAVEN_HOME%\bin\mvn.cmd" set "MVN_CMD=%MAVEN_HOME%\bin\mvn.cmd"
if defined MVN_CMD goto :run
if defined M2_HOME if exist "%M2_HOME%\bin\mvn.cmd" set "MVN_CMD=%M2_HOME%\bin\mvn.cmd"
if defined MVN_CMD goto :run

REM 3) Maven Wrapper distribution cache.
REM    "dir /s /b <pattern>" anchors the pattern's leading directory and only recurses from
REM    there, so a trailing wildcard is what actually walks the tree.
REM    The cached layouts are inconsistent (some nest an extra apache-maven-<ver> level), so
REM    every candidate is inspected and the highest <major>.<minor>.<patch> wins.
REM    No parenthesised blocks are used below on purpose: a variable set inside one is not
REM    visible to "if defined" parsed in the same block without delayed expansion.
set "MVN_BEST_VER=0.0.0"
for /f "delims=" %%F in ('dir /b /s "%USERPROFILE%\.m2\wrapper\dists\*mvn.cmd" 2^>nul') do call :consider "%%F"

if not defined MVN_CMD goto :notfound
goto :run

REM ---------------------------------------------------------------------------
:consider
REM %~1 = candidate path; derive the apache-maven-<ver> token it belongs to.
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

REM ---------------------------------------------------------------------------
:isNewer
REM %1, %2 = version strings "major.minor.patch". Sets NEWER=1 when %1 is newer than %2.
REM Compared numerically per component: plain string order gets 3.9.16 vs 3.10.0 wrong.
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

REM ---------------------------------------------------------------------------
:notfound
echo [mvnw] ERROR: no Maven installation found.
echo [mvnw] Install Maven, or set MAVEN_HOME, or populate %%USERPROFILE%%\.m2\wrapper\dists.
exit /b 1

REM ---------------------------------------------------------------------------
:run
echo [mvnw] using %MVN_CMD%
echo [mvnw] local repository %MAVEN_REPO_LOCAL%
call "%MVN_CMD%" -f "%PROJECT_POM%" -Dmaven.repo.local="%MAVEN_REPO_LOCAL%" %*
exit /b %ERRORLEVEL%
