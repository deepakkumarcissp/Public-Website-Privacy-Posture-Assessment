# DKCISSP Privacy Posture Assessment -- single-command installer (Windows PowerShell)
#
#   iwr -useb https://raw.githubusercontent.com/deepakkumarcissp/Public-Website-Privacy-Posture-Assessment/main/install.ps1 | iex
#
# Installs missing prerequisites (Python, Chrome) via winget, downloads the project, sets up a private virtual environment, installs
# dependencies, starts the local web UI, and opens it in your browser.
# Only assess domains you own or are authorized to test.

$ErrorActionPreference = "Stop"

$RepoUrl = "https://github.com/deepakkumarcissp/Public-Website-Privacy-Posture-Assessment"
$InstallDir = if ($env:DKCISSP_INSTALL_DIR) { $env:DKCISSP_INSTALL_DIR } else { "$HOME\dkcissp-privacy-posture-assessment" }

Write-Host "DKCISSP Privacy Posture Assessment -- installer"
Write-Host "Installing to: $InstallDir"
Write-Host ""

function Refresh-Path {
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
}

function Find-Python {
    foreach ($c in @("python", "py")) {
        if (Get-Command $c -ErrorAction SilentlyContinue) {
            & $c -c "import sys, venv; sys.exit(0 if sys.version_info >= (3, 9) else 1)" 2>$null
            if ($LASTEXITCODE -eq 0) { return $c }
        }
    }
    return $null
}

function Find-Chrome {
    $paths = @(
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
        "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe",
        "$env:ProgramFiles\Chromium\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
    )
    foreach ($p in $paths) { if ($p -and (Test-Path $p)) { return $p } }
    return $null
}

$HaveWinget = [bool](Get-Command winget -ErrorAction SilentlyContinue)

# -- Prerequisites: install anything missing with winget -----------------------
$Py = Find-Python
if (-not $Py) {
    if ($HaveWinget) {
        Write-Host "Python 3.9+ not found -- installing it with winget..."
        winget install -e --id Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements
        Refresh-Path
        $Py = Find-Python
    }
    if (-not $Py) {
        Write-Host "Could not install Python automatically."
        Write-Host "Install Python 3.9+ from https://www.python.org/downloads/ (check 'Add python.exe to PATH') and run this again."
        exit 1
    }
}

if (-not (Find-Chrome)) {
    if ($HaveWinget) {
        Write-Host "Chrome not found -- installing it with winget (needed for the full dynamic scan)..."
        winget install -e --id Google.Chrome --silent --accept-package-agreements --accept-source-agreements
    }
    if (-not (Find-Chrome)) {
        Write-Host "Note: no Chrome/Chromium/Edge found. The app will still run using the static scan only."
        Write-Host "Install Chrome any time and the dynamic scan is picked up automatically."
    }
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

if (-not (Test-Path ".venv\Scripts\python.exe")) { & $Py -m venv .venv }
Write-Host "Installing/updating dependencies -- this takes a minute the first time..."
& .venv\Scripts\python.exe -m pip install -q --upgrade pip
& .venv\Scripts\python.exe -m pip install -q -e ".[web,dynamic-scan]"
if ($LASTEXITCODE -ne 0) { Write-Host "Dependency install failed (see above)."; exit 1 }

if (-not $env:PORT) { $env:PORT = "1009" }
# Stop any previous copy of this app so the port is free.
Get-Process -Name "dkcissp-privacy-assessment-web" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Process "http://127.0.0.1:$($env:PORT)"

Write-Host ""
Write-Host "DKCISSP Privacy Posture Assessment is starting at http://127.0.0.1:$($env:PORT)"
Write-Host "Leave this window open while you use it. Press Ctrl+C to stop."
Write-Host ""
& .venv\Scripts\dkcissp-privacy-assessment-web.exe
