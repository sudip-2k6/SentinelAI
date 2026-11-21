param(
    [string]$Python = "python",
    [switch]$SmokeTest,
    [string]$DistPath = "dist"
)
$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $repo
try {
    New-Item -ItemType Directory -Path build -Force | Out-Null
    $output = [System.IO.Path]::GetFullPath($DistPath, $repo)
    $arguments = @(
        "-m", "PyInstaller", "--noconfirm", "--windowed", "--onedir", "--name", "SentinelAI",
        "--specpath", "build", "--workpath", "build/pyinstaller", "--distpath", $output,
        "--add-data", "app/assets:app/assets", "--icon", "app/assets/sentinelai.ico",
        "--collect-binaries", "lightgbm", "--collect-data", "lightgbm", "--exclude-module", "pandas",
        "--exclude-module", "matplotlib", "--exclude-module", "IPython", "--exclude-module", "pytest",
        "--exclude-module", "tkinter", "app/__main__.py"
    )
    & $Python @arguments
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed with exit code $LASTEXITCODE" }
    if ($SmokeTest) {
        $scratch = Join-Path $repo ("build/smoke-" + [guid]::NewGuid().ToString("N"))
        $exe = Join-Path $output "SentinelAI/SentinelAI.exe"
        $options = @("--smoke-test", "--data-dir", ('"' + $scratch + '"'))
        $process = Start-Process -FilePath $exe -WindowStyle Hidden -PassThru -ArgumentList $options
        if (-not $process.WaitForExit(60000)) {
            $process.Kill()
            throw "Packaged smoke test timed out after 60 seconds"
        }
        $resultPath = Join-Path $scratch "smoke-result.txt"
        if (Test-Path -LiteralPath $resultPath) { Get-Content -LiteralPath $resultPath }
        if ($process.ExitCode -ne 0) { throw "Packaged smoke test failed with exit code $($process.ExitCode)" }
    }
} finally {
    Pop-Location
}
