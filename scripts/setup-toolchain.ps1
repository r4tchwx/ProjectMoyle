# Pinned portable compiler. No administrator rights, PATH changes, or system installation.
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$toolDir = Join-Path $projectRoot '.tools'
$zigDir = Join-Path $toolDir 'zig-x86_64-windows-0.15.2'
$zigExe = Join-Path $zigDir 'zig.exe'
$required = @('zig.exe', 'lib\std\std.zig', 'lib\libcxx\include\vector')
$complete = $true
foreach ($relative in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $zigDir $relative) -PathType Leaf)) { $complete = $false }
}
if ($complete) {
    $version = & $zigExe version
    if ($LASTEXITCODE -ne 0 -or "$version".Trim() -ne '0.15.2') {
        throw 'The local compiler cannot run or is not Zig 0.15.2. Check the .tools directory and execution permissions.'
    }
    Write-Host "Ready: $zigExe"
    return
}
New-Item -ItemType Directory -Force $toolDir | Out-Null
$archive = Join-Path $toolDir 'zig-0.15.2.zip'
$expected = '3a0ed1e8799a2f8ce2a6e6290a9ff22e6906f8227865911fb7ddedc3cc14cb0c'
$archiveValid = (Test-Path -LiteralPath $archive -PathType Leaf) -and
    ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -eq $expected)
if (-not $archiveValid) {
    Write-Host 'Downloading pinned Zig 0.15.2 from ziglang.org (about 93 MB)...'
    Invoke-WebRequest -Uri 'https://ziglang.org/download/0.15.2/zig-x86_64-windows-0.15.2.zip' -OutFile $archive -UseBasicParsing
}
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $expected) {
    throw 'Compiler archive checksum mismatch. Archive will not be extracted.'
}
Expand-Archive -LiteralPath $archive -DestinationPath $toolDir -Force
$version = & $zigExe version
if ($LASTEXITCODE -ne 0 -or "$version".Trim() -ne '0.15.2') {
    throw 'The extracted compiler cannot run or is not Zig 0.15.2.'
}
Write-Host "Ready: $zigExe"
