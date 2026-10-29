$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
function Run-Checked([string]$Executable, [string[]]$Arguments) {
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Executable exited with $LASTEXITCODE" }
}
$uvCmd = Get-Command uv -ErrorAction SilentlyContinue
$uvPath = if ($uvCmd) { $uvCmd.Source } else { Join-Path $env:APPDATA 'Python/Python310/Scripts/uv.exe' }
if (-not (Test-Path -LiteralPath $uvPath)) {
    Run-Checked '.venv/Scripts/python.exe' @('-m', 'pip', 'install', 'uv')
    $uvPath = Join-Path $PSScriptRoot '.venv/Scripts/uv.exe'
}
$sources = @(
    @('theHarvester', 'https://github.com/laramies/theHarvester.git', '49a38f8d33c32336bbf6a111ea723ea223116265'),
    @('ghunt', 'https://github.com/mxrch/GHunt.git', '5ee893929c51c7a8a665b199bbae04ce85a662b4'),
    @('instaloader', 'https://github.com/instaloader/instaloader.git', '7efc78de12e02feb1794b71125a48e66250f0db0')
)
foreach ($source in $sources) {
    $checkout = Join-Path $PSScriptRoot ('third_party/' + $source[0])
    if (-not (Test-Path -LiteralPath $checkout)) {
        Run-Checked 'git' @('clone', '--no-checkout', '--filter=blob:none', $source[1], $checkout)
        Run-Checked 'git' @('-C', $checkout, 'checkout', '--detach', $source[2])
    }
    $actual = (& git -C $checkout rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $actual -ne $source[2]) { throw "Unexpected source revision in $checkout; preserve local changes and reconcile it manually." }
}
Run-Checked $uvPath @('python', 'install', '3.12', '3.14')
if (-not (Test-Path -LiteralPath '.tools-venv/Scripts/python.exe')) {
    Run-Checked $uvPath @('venv', '--python', '3.12', '.tools-venv')
}
if (-not (Test-Path -LiteralPath '.harvester-venv/Scripts/python.exe')) {
    Run-Checked $uvPath @('venv', '--python', '3.14', '.harvester-venv')
}
Run-Checked $uvPath @('pip', 'install', '--python', '.tools-venv/Scripts/python.exe', './third_party/ghunt', './third_party/instaloader')
Run-Checked $uvPath @('pip', 'install', '--python', '.harvester-venv/Scripts/python.exe', './third_party/theHarvester')
$singleFolder = Join-Path $PSScriptRoot 'third_party/single-file-cli'
New-Item -ItemType Directory -Force -Path $singleFolder | Out-Null
$single = Join-Path $singleFolder 'single-file.exe'
if (-not (Test-Path -LiteralPath $single)) {
    Invoke-WebRequest 'https://github.com/gildas-lormeau/single-file-cli/releases/download/v2.16.0/single-file.exe' -OutFile $single
}
if ((Get-FileHash -LiteralPath $single -Algorithm SHA256).Hash.ToLower() -ne '29cf02fcd4bdb395774338ff6ca6a92aca6190b6d59b11419afb3e4f46fa2a55') {
    throw 'SingleFile v2.16.0 binary hash mismatch'
}
$phoneFolder = Join-Path $PSScriptRoot 'third_party/phoneinfoga'
New-Item -ItemType Directory -Force -Path $phoneFolder | Out-Null
if (-not (Test-Path -LiteralPath (Join-Path $phoneFolder 'phoneinfoga.exe'))) {
    $archive = Join-Path $phoneFolder 'phoneinfoga.tar.gz'
    $checksums = Join-Path $phoneFolder 'checksums.txt'
    Invoke-WebRequest 'https://github.com/sundowndev/phoneinfoga/releases/download/v2.11.0/phoneinfoga_Windows_x86_64.tar.gz' -OutFile $archive
    Invoke-WebRequest 'https://github.com/sundowndev/phoneinfoga/releases/download/v2.11.0/phoneinfoga_checksums.txt' -OutFile $checksums
    $expected = Get-Content -LiteralPath $checksums | Where-Object { $_ -match 'phoneinfoga_Windows_x86_64.tar.gz$' }
    $digest = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLower()
    if (-not $expected -or -not $expected.StartsWith($digest)) { throw 'PhoneInfoga checksum mismatch' }
    Run-Checked 'tar' @('-xf', $archive, '-C', $phoneFolder)
}
& (Join-Path $PSScriptRoot 'setup-phoneinfoga.ps1')
Write-Host 'FindAll research engines installed. GHunt authentication is available through ghunt-login.bat.'
