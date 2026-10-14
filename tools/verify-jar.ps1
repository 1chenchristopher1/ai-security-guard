# Checks that a jar is runnable with "java -jar".
#
# Prints OK, or a reason on stdout, and exits 0 or 1.
#
# This exists because a failed Spring Boot repackage leaves behind a small, valid-looking jar that
# contains the project classes but no Main-Class and no dependencies. "java -jar" then fails with
# "no main manifest attribute", which does not obviously point at a broken build - so the check is
# made explicit rather than left to be diagnosed from that message.
param(
    [Parameter(Mandatory = $true)][string]$Jar,
    [int]$MinimumBytes = 1000000
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Jar)) {
    Write-Output "the jar does not exist"
    exit 1
}

$file = Get-Item -LiteralPath $Jar
if ($file.Length -lt $MinimumBytes) {
    # A repackaged Spring Boot jar carries every dependency; anything tiny is a bare class jar.
    Write-Output ("the jar is only {0:N0} bytes, which is far too small to be a runnable build" -f $file.Length)
    exit 1
}

try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($file.FullName)
    try {
        $entry = $zip.Entries | Where-Object { $_.FullName -eq 'META-INF/MANIFEST.MF' } | Select-Object -First 1
        if ($null -eq $entry) {
            Write-Output "the jar has no META-INF/MANIFEST.MF"
            exit 1
        }
        $reader = New-Object System.IO.StreamReader($entry.Open())
        try { $manifest = $reader.ReadToEnd() } finally { $reader.Dispose() }
    }
    finally { $zip.Dispose() }
}
catch {
    Write-Output ("the jar could not be read: {0}" -f $_.Exception.Message)
    exit 1
}

# The Main-Class attribute is what "java -jar" needs. Spring Boot writes Main-Class (its launcher)
# and Start-Class (the application). Without Main-Class the jar is not executable.
if ($manifest -notmatch '(?m)^Main-Class:') {
    Write-Output "the jar has no Main-Class in its manifest, so it is not executable (a repackage probably failed)"
    exit 1
}

Write-Output "OK"
exit 0
