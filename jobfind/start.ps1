$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

$executable = @('findall-ui.exe', 'rust-ui\target\release\findall-ui.exe') |
    ForEach-Object { Get-Item -LiteralPath (Join-Path $PSScriptRoot $_) -ErrorAction SilentlyContinue } |
    Where-Object { -not $_.PSIsContainer } |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1
if (-not $executable) {
    $executable = Get-Item -LiteralPath (Join-Path $PSScriptRoot 'jobfind-ui.exe') -ErrorAction SilentlyContinue
}
if ($executable) {
    & $executable.FullName @args
    exit $LASTEXITCODE
}

$cargo = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
if (-not (Test-Path -LiteralPath $cargo -PathType Leaf)) {
    $cargo = (Get-Command cargo.exe -ErrorAction SilentlyContinue).Source
}
if (-not $cargo) {
    Write-Error 'Rust/Cargo is needed to build the FindAll interface. Install Rust or restore findall-ui.exe.'
    exit 1
}
& $cargo run --release --locked --manifest-path (Join-Path $PSScriptRoot 'rust-ui\Cargo.toml') -- @args
exit $LASTEXITCODE
