# DKCISSP Privacy Posture Assessment -- single-command installer (Windows PowerShell)
#
#   iwr -useb https://raw.githubusercontent.com/deepakkumarcissp/Public-Website-Privacy-Posture-Assessment/main/install.ps1 | iex
#
# Downloads the project, sets up a private virtual environment, installs
# dependencies, starts the local web UI, and opens it in your browser.
# Only assess domains you own or are authorized to test.

$ErrorActionPreference = "Stop"

$RepoUrl = "https://github.com/deepakkumarcissp/Public-Website-Privacy-Posture-Assessment"
$InstallDir = if ($env:DKCISSP_INSTALL_DIR) { $env:DKCISSP_INSTALL_DIR } else { "$HOME\dkcissp-privacy-posture-assessment" }

Write-Host "DKCISSP Privacy Posture Assessment -- installer"
Write-Host "Installing to: $InstallDir"
Write-Host ""

if (Get-Command python -ErrorAction SilentlyContinue) {
    $Py = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $Py = "py"
} else {
    Write-Host "Python 3.9+ is required but was not found."
    Write-Host "Install it from https://www.python.org/downloads/ (check 'Add python.exe to PATH') and run this again."
    exit 1
}

if (Test-Path "$InstallDir\.git") {
    Write-Host "Existing install found -- updating..."
    git -C $InstallDir pull --ff-only
} elseif (Get-Command git -ErrorAction SilentlyContinue) {
    Write-Host "Downloading (git clone)..."
    git clone --depth 1 "$RepoUrl.git" $InstallDir
} else {
    Write-Host "git not found -- downloading a zip archive instead..."
    $TmpZip = New-TemporaryFile
    Invoke-WebRequest -UseBasicParsing -Uri "$RepoUrl/archive/refs/heads/main.zip" -OutFile $TmpZip
    $TmpExtract = Join-Path $env:TEMP ([System.IO.Path]::GetRandomFileName())
    Expand-Archive -Path $TmpZip -DestinationPath $TmpExtract
    if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir }
    Move-Item (Join-Path $TmpExtract "Public-Website-Privacy-Posture-Assessment-main") $InstallDir
    Remove-Item -Recurse -Force $TmpExtract, $TmpZip
}

Set-Location $InstallDir

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "First-time setup -- this takes a minute..."
    & $Py -m venv .venv
    & .venv\Scripts\python.exe -m pip install -q --upgrade pip
    & .venv\Scripts\python.exe -m pip install -q -e ".[web,dynamic-scan]"
}

if (-not $env:PORT) { $env:PORT = "1009" }
Start-Process "http://127.0.0.1:$($env:PORT)"

Write-Host ""
Write-Host "DKCISSP Privacy Posture Assessment is starting at http://127.0.0.1:$($env:PORT)"
Write-Host "Leave this window open while you use it. Press Ctrl+C to stop."
Write-Host ""
& .venv\Scripts\dkcissp-privacy-assessment-web.exe
