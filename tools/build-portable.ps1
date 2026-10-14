# Builds the portable distribution of AI Security Guard.
#
# Produces build-portable/ containing everything a presenter needs, and a zip
# of it. The presenter installs nothing: the Java runtime is bundled.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\build-portable.ps1
#
# Called by package-portable.cmd, which finds Maven first.

param(
    # Skip the zip, for a quick local check.
    [switch]$NoZip,
    # Where the zip is written. Defaults to the workspace root.
    [string]$OutDirectory = ""
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$stage = Join-Path $root 'build-portable'
$jar = Join-Path $root 'target\agentic-cyber-defence-0.0.1-SNAPSHOT.jar'
$portableJar = Join-Path $stage 'ai-security-guard.jar'
$runtime = Join-Path $stage 'runtime'
$keyFile = Join-Path $stage 'apikey.txt'

if (-not (Test-Path -LiteralPath $jar)) {
    throw "The application jar was not found at $jar. Run 'mvnw.cmd package -DskipTests' first."
}

Write-Host "[portable] staging into $stage"
New-Item -ItemType Directory -Force -Path $stage | Out-Null

# ---------------------------------------------------------------- the jar
Copy-Item -LiteralPath $jar -Destination $portableJar -Force
Write-Host ("[portable] jar: {0:N1} MB" -f ((Get-Item $portableJar).Length / 1MB))

# ---------------------------------------------------------------- bundled runtime
# A trimmed Java 21 runtime, so the presenter needs nothing installed. jlink is
# part of the JDK. The module list is the minimum that actually starts this
# application; java.security.jgss is required by the embedded web server's
# authentication support and its absence fails the startup with
# NoClassDefFoundError org/ietf/jgss/GSSException, which does not obviously
# point at a missing module.
$javaHome = $env:JAVA_HOME
if (-not $javaHome) {
    $candidates = @(
        'C:\Program Files\Java\jdk-21',
        'C:\Program Files\Eclipse Adoptium\jdk-21*',
        'C:\Program Files\Microsoft\jdk-21*'
    )
    foreach ($candidate in $candidates) {
        $found = Get-Item $candidate -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { $javaHome = $found.FullName; break }
    }
}
if (-not $javaHome) { throw "JAVA_HOME is not set and no JDK 21 was found, so jlink cannot run." }

$jlink = Join-Path $javaHome 'bin\jlink.exe'
if (-not (Test-Path -LiteralPath $jlink)) { throw "jlink was not found at $jlink" }

if (Test-Path -LiteralPath $runtime) { Remove-Item -LiteralPath $runtime -Recurse -Force }

$modules = @(
    'java.base', 'java.logging', 'java.xml', 'java.naming', 'java.management',
    'java.instrument', 'java.desktop', 'java.net.http', 'java.sql',
    'java.security.jgss', 'java.security.sasl', 'jdk.unsupported', 'jdk.crypto.ec'
) -join ','

Write-Host "[portable] building the bundled runtime with jlink"
& $jlink --add-modules $modules --strip-debug --no-header-files --no-man-pages `
    --compress=zip-6 --output $runtime
if ($LASTEXITCODE -ne 0) { throw "jlink failed with exit code $LASTEXITCODE" }

$runtimeSize = (Get-ChildItem $runtime -Recurse -File | Measure-Object Length -Sum).Sum / 1MB
Write-Host ("[portable] runtime: {0:N1} MB" -f $runtimeSize)

# ---------------------------------------------------------------- the key template
# Left unconfigured on purpose, and the placeholder deliberately contains no
# "sk-" so it cannot be mistaken for a key.
$template = @(
    '# ---------------------------------------------------------------',
    '# Paste your DeepSeek API key on the line below, then save.',
    '# A key looks like: three letters, a dash, then a long string.',
    '# Lines starting with a hash are ignored.',
    '# ---------------------------------------------------------------',
    '',
    'PASTE-YOUR-KEY-HERE',
    ''
) -join "`r`n"
Set-Content -LiteralPath $keyFile -Value $template -Encoding Ascii -NoNewline

# ---------------------------------------------------------------- the launcher
# Already authored in the tree; copied so a stale one cannot be shipped.
$startSource = Join-Path $PSScriptRoot 'portable-start.cmd'
$startTarget = Join-Path $stage 'start.cmd'
Copy-Item -LiteralPath $startSource -Destination $startTarget -Force

# A launcher with non-ASCII bytes in it breaks cmd.exe on a GBK console, which is
# exactly the machine this ships to. Fail the build rather than ship that.
$startBytes = [System.IO.File]::ReadAllBytes($startTarget)
$nonAscii = ($startBytes | Where-Object { $_ -gt 127 }).Count
if ($nonAscii -gt 0) { throw "start.cmd contains $nonAscii non-ASCII bytes; cmd.exe will mis-parse it." }
if ($startBytes.Length -ge 3 -and $startBytes[0] -eq 0xEF -and $startBytes[1] -eq 0xBB -and $startBytes[2] -eq 0xBF) {
    throw "start.cmd begins with a UTF-8 BOM, which cmd.exe treats as part of the first command."
}
Write-Host "[portable] launcher: pure ASCII, no BOM"

# ---------------------------------------------------------------- the guide
# The guide's SOURCE name is ASCII and it is renamed on the way out. Windows
# PowerShell 5.1 reads a BOM-less .ps1 as ANSI/GBK, so a Chinese filename written
# as a literal in this script arrives mojibake and the file is "not found". Using
# the literal only for the destination name is safe because by then the string
# comes from this script's own runtime, not from re-reading its source.
$guideSource = Join-Path $PSScriptRoot 'portable-guide.md'
$guideTarget = Join-Path $stage ([char]0x8FD0 + [char]0x884C + [char]0x8BF4 + [char]0x660E + '.md')
if (Test-Path -LiteralPath $guideSource) {
    Copy-Item -LiteralPath $guideSource -Destination $guideTarget -Force
    Write-Host ("[portable] guide: {0}" -f (Split-Path -Leaf $guideTarget))
} else {
    Write-Warning "[portable] guide not found at $guideSource"
}

# ---------------------------------------------------------------- verify
Copy-Item -LiteralPath $portableJar -Destination (Join-Path $stage 'verify.tmp.jar') -Force -ErrorAction SilentlyContinue
$verifyJar = Join-Path $stage 'verify.tmp.jar'
if (Test-Path -LiteralPath $verifyJar) {
    $verdict = & (Join-Path $PSScriptRoot 'verify-jar.ps1') -Jar $verifyJar
    Remove-Item -LiteralPath $verifyJar -Force
    if ($verdict -ne 'OK') { throw "The staged jar is not runnable: $verdict" }
    Write-Host "[portable] staged jar verified runnable"
}

$total = (Get-ChildItem $stage -Recurse -File | Measure-Object Length -Sum).Sum / 1MB
Write-Host ("[portable] total: {0:N1} MB" -f $total)

if ($NoZip) {
    Write-Host "[portable] -NoZip given, stopping here"
    exit 0
}

# ---------------------------------------------------------------- zip
if (-not $OutDirectory) { $OutDirectory = $root }
# A trailing separator, as passed in from "%~dp0", makes Join-Path and Test-Path
# unhappy with the resulting "dir\\file" form, so trim it first.
$OutDirectory = $OutDirectory.TrimEnd('\', '/')
if (-not $OutDirectory) { $OutDirectory = $root }
if (-not (Test-Path -LiteralPath $OutDirectory)) {
    New-Item -ItemType Directory -Force -Path $OutDirectory | Out-Null
}

$zipPath = Join-Path $OutDirectory 'AI-Security-Guard-portable.zip'
if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }

Write-Host "[portable] compressing"
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zipPath -CompressionLevel Optimal
Write-Host ("[portable] zip: {0} ({1:N1} MB)" -f $zipPath, ((Get-Item $zipPath).Length / 1MB))
Write-Host "[portable] done"
