param(
    [Parameter(Mandatory)]
    [string]$Wheel
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$work = Split-Path -Parent $Wheel
$runtime = Join-Path $work 'runtime'
$stage = Join-Path $work ([guid]::NewGuid().ToString('N'))
$archive = Join-Path $work 'python-runtime.zip'
$expanded = Join-Path $stage 'python-package'
$log = Join-Path ([IO.Path]::GetTempPath()) 'SentinelAI-Setup.log'
$version = '3.13.17'

try {
    if (Test-Path -LiteralPath $runtime -PathType Container) { exit 0 }
    New-Item -ItemType Directory -Path $stage | Out-Null
    Set-Content -LiteralPath $log -Value "Preparing SentinelAI with Python $version"
    # The Setup download page verifies each archive before this step runs.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($archive, $expanded)
    $tools = Join-Path $expanded 'tools'
    $python = Join-Path $tools 'python.exe'
    $arguments = '-I -m pip --isolated --log "' + $log + '" install --no-user ' +
        '--no-index --no-cache-dir --no-input --no-compile --disable-pip-version-check ' +
        '--only-binary=:all: --find-links "' + $work + '" "' + $Wheel + '[ml]"'
    $process = Start-Process -FilePath $python -ArgumentList $arguments -PassThru -WindowStyle Hidden
    if (-not $process.WaitForExit(90000)) {
        $process.Kill()
        $process.WaitForExit()
        throw 'Preparing the downloaded packages exceeded 90 seconds.'
    }
    if ($process.ExitCode -ne 0) { throw "Installing SentinelAI dependencies failed ($($process.ExitCode))." }
    Move-Item -LiteralPath $tools -Destination $runtime
} catch {
    Add-Content -LiteralPath $log -Value $_.Exception.Message
    exit 1
}
