$ErrorActionPreference = 'Stop'
$bridge = Join-Path $PSScriptRoot 'third_party/phoneinfoga-bridge'
$destination = Join-Path $PSScriptRoot 'third_party/phoneinfoga'
New-Item -ItemType Directory -Force -Path $destination | Out-Null
Push-Location -LiteralPath $bridge
try {
    & go mod download
    if ($LASTEXITCODE -ne 0) { throw 'PhoneInfoga pinned dependencies could not be downloaded' }
    $modulePath = (& go list -m -f '{{.Dir}}' github.com/sundowndev/phoneinfoga/v2).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'PhoneInfoga source path unavailable' }
    Copy-Item -LiteralPath (Join-Path $modulePath 'LICENSE') -Destination (Join-Path $destination 'LICENSE') -Force
    & go build -mod=readonly -trimpath -o (Join-Path $destination 'findall-phoneinfoga.exe') .
    if ($LASTEXITCODE -ne 0) { throw 'PhoneInfoga integration build failed' }
} finally { Pop-Location }
Write-Host 'PhoneInfoga structured scanners are ready in FindAll.'
