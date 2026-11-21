param(
    [Parameter(Mandatory)]
    [string]$Wheel
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$work = Split-Path -Parent $Wheel
$runtime = Join-Path $work 'runtime'
$stage = Join-Path $work ([guid]::NewGuid().ToString('N'))
$archive = Join-Path $stage 'python.zip'
$expanded = Join-Path $stage 'python-package'
$log = Join-Path ([IO.Path]::GetTempPath()) 'SentinelAI-Setup.log'
$version = '3.13.17'
$expectedHash = 'DCE409744B088F94C6E37BA41F8100C384C27E029E843237364C602D30D475E5'

try {
    if (Test-Path -LiteralPath $runtime -PathType Container) { exit 0 }
    New-Item -ItemType Directory -Path $stage | Out-Null
    Set-Content -LiteralPath $log -Value "Preparing SentinelAI with Python $version"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -UseBasicParsing -TimeoutSec 90 `
        -Uri "https://api.nuget.org/v3-flatcontainer/python/$version/python.$version.nupkg" `
        -OutFile $archive
    $sha256 = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($archive)
    try {
        $hash = [BitConverter]::ToString($sha256.ComputeHash($stream)).Replace('-', '')
    } finally {
        $stream.Dispose()
        $sha256.Dispose()
    }
    if ($hash -ne $expectedHash) {
        throw 'The downloaded Python package did not match its expected SHA-256.'
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($archive, $expanded)
    $tools = Join-Path $expanded 'tools'
    $python = Join-Path $tools 'python.exe'
    & $python -I -m pip --isolated --log $log install --no-user --no-cache-dir --no-input `
        --disable-pip-version-check --only-binary=:all: --index-url https://pypi.org/simple "$Wheel[ml]"
    if ($LASTEXITCODE -ne 0) { throw "Installing SentinelAI dependencies failed ($LASTEXITCODE)." }
    Move-Item -LiteralPath $tools -Destination $runtime
} catch {
    Add-Content -LiteralPath $log -Value $_.Exception.Message
    exit 1
}
