$ErrorActionPreference = 'Stop'
$version = '15.0.23'
$name = "tor-expert-bundle-windows-x86_64-$version.tar.gz"
$expected = '231dad6b9cb401a54c260db7046965ef04e4f72ff071b140d423fb5da281ab1e'
$destination = Join-Path $PSScriptRoot 'third_party\tor'
$tor = Join-Path $destination 'tor\tor.exe'
if (Test-Path -LiteralPath $tor) {
    Write-Output "Tor already installed: $tor"
    exit 0
}
$archive = Join-Path $env:TEMP $name
Invoke-WebRequest -Uri "https://dist.torproject.org/torbrowser/$version/$name" -OutFile $archive
$actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "Tor SHA256 mismatch: $actual" }
New-Item -ItemType Directory -Path $destination -Force | Out-Null
tar -xzf $archive -C $destination
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $tor)) { throw 'Tor extraction failed' }
Write-Output "Tor installed: $tor"
