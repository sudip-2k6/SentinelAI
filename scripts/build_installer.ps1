param(
    [string]$Python = 'python',
    [string]$Compiler = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
)

$ErrorActionPreference = 'Stop'
Push-Location -LiteralPath (Split-Path -Parent $PSScriptRoot)
try {
    $wheelDir = (New-Item -ItemType Directory -Force -Path 'build/installer-wheel').FullName
    $output = (New-Item -ItemType Directory -Force -Path 'dist/installer').FullName
    $version = & $Python -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])"
    if ($LASTEXITCODE -ne 0 -or $version -notmatch '^\d+\.\d+\.\d+$') { throw 'Invalid project version.' }
    & $Python -m pip wheel --no-deps --wheel-dir $wheelDir .
    if ($LASTEXITCODE -ne 0) { throw 'Could not build the SentinelAI wheel.' }
    $wheel = "sentinelai_desktop-$version-py3-none-any.whl"
    if (-not (Test-Path -LiteralPath (Join-Path $wheelDir $wheel))) { throw 'Expected wheel not found.' }
    & $Compiler "/DAppVersion=$version" "/DWheelDirectory=$wheelDir" "/DWheelName=$wheel" `
        "/DOutputDirectory=$output" (Join-Path $PSScriptRoot 'windows/SentinelAI.iss')
    if ($LASTEXITCODE -ne 0) { throw 'Inno Setup compilation failed.' }
} finally {
    Pop-Location
}
