param(
    [string]$Python = 'python',
    [string]$Compiler = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    [string]$SigningCertificateThumbprint,
    [string]$SignTool = 'signtool.exe'
)

$ErrorActionPreference = 'Stop'
Push-Location -LiteralPath (Split-Path -Parent $PSScriptRoot)
try {
    & $Python -c "import sys, sysconfig; sys.exit(not (sys.version_info[:2] == (3, 13) and sysconfig.get_platform() == 'win-amd64'))"
    if ($LASTEXITCODE -ne 0) { throw 'The installer must be built with Windows x64 Python 3.13.' }
    $wheelDir = (New-Item -ItemType Directory -Force -Path 'build/installer-wheel').FullName
    $output = (New-Item -ItemType Directory -Force -Path 'dist/installer').FullName
    $version = & $Python -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])"
    if ($LASTEXITCODE -ne 0 -or $version -notmatch '^\d+\.\d+\.\d+$') { throw 'Invalid project version.' }
    & $Python -m pip wheel --no-deps --wheel-dir $wheelDir .
    if ($LASTEXITCODE -ne 0) { throw 'Could not build the SentinelAI wheel.' }
    $wheel = "sentinelai_desktop-$version-py3-none-any.whl"
    if (-not (Test-Path -LiteralPath (Join-Path $wheelDir $wheel))) { throw 'Expected wheel not found.' }
    $report = Join-Path $wheelDir 'windows-runtime.json'
    $wheelPath = Join-Path $wheelDir $wheel
    & $Python -m pip --isolated install --dry-run --ignore-installed --only-binary=:all: `
        --index-url https://pypi.org/simple --report $report "$wheelPath[ml]"
    if ($LASTEXITCODE -ne 0) { throw 'Could not resolve Windows dependencies.' }
    $downloads = Join-Path $wheelDir 'downloads.iss'
    $lines = foreach ($item in (Get-Content -Raw -LiteralPath $report | ConvertFrom-Json).install) {
        if ($item.is_direct) { continue }
        $url = [uri]$item.download_info.url
        $name = $url.Segments[-1]
        $hash = $item.download_info.archive_info.hashes.sha256
        if ($url.Scheme -ne 'https' -or $url.Host -ne 'files.pythonhosted.org' -or
            $name -notmatch '^[A-Za-z0-9_.+-]+\.whl$' -or $hash -notmatch '^[a-f0-9]{64}$') {
            throw "Unexpected Windows dependency download metadata."
        }
        "    DownloadPage.Add('$($url.AbsoluteUri)', '$name', '$hash');"
    }
    if (-not $lines) { throw 'No Windows dependencies resolved.' }
    $lines | Set-Content -Encoding ascii -LiteralPath $downloads
    & $Compiler "/DAppVersion=$version" "/DWheelDirectory=$wheelDir" "/DWheelName=$wheel" `
        "/DDownloadsFile=$downloads" `
        "/DOutputDirectory=$output" (Join-Path $PSScriptRoot 'windows/SentinelAI.iss')
    if ($LASTEXITCODE -ne 0) { throw 'Inno Setup compilation failed.' }
    if ($SigningCertificateThumbprint) {
        $setup = Join-Path $output 'SentinelAI-Setup-x64.exe'
        & $SignTool sign /sha1 $SigningCertificateThumbprint /fd SHA256 `
            /tr 'http://timestamp.digicert.com' /td SHA256 $setup
        if ($LASTEXITCODE -ne 0) { throw 'Signing setup failed.' }
        & $SignTool verify /pa $setup
        if ($LASTEXITCODE -ne 0) { throw 'Setup signature verification failed.' }
    }
} finally {
    Pop-Location
}
