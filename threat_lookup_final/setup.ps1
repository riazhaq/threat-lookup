$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

Write-Host "[1/4] Checking Python..." -ForegroundColor Cyan
$pythonExe = ""
if (Test-Path ".\.venv\Scripts\python.exe") {
    $pythonExe = ".\.venv\Scripts\python.exe"
} else {
    $candidates = @(
        "$env:LocalAppData\Programs\Python\Python312\python.exe",
        "$env:LocalAppData\Programs\Python\Python311\python.exe",
        "$env:LocalAppData\Programs\Python\Python310\python.exe"
    )
    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            $pythonExe = $candidate
            break
        }
    }

    if (-not $pythonExe) {
        try {
            $resolvedPy = (Get-Command py -ErrorAction Stop).Source
            if ($resolvedPy -and ($resolvedPy -notlike "*WindowsApps*")) {
                $pythonExe = $resolvedPy
            }
        } catch {}
    }

    if (-not $pythonExe) {
        try {
            $resolvedPython = (Get-Command python -ErrorAction Stop).Source
            if ($resolvedPython -and ($resolvedPython -notlike "*WindowsApps*")) {
                $pythonExe = $resolvedPython
            }
        } catch {}
    }

    if (-not $pythonExe) {
        throw "Python was not found. Install Python 3.10+ first (python.org installer), then rerun setup."
    }
}

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    Write-Host "[2/4] Creating virtual environment..." -ForegroundColor Cyan
    if ($pythonExe -like "*py.exe") {
        & $pythonExe -3 -m venv .venv
    } else {
        & $pythonExe -m venv .venv
    }

    if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
        throw "Virtual environment creation failed."
    }
}

$venvPython = ".\.venv\Scripts\python.exe"
Write-Host "[3/4] Installing dependencies..." -ForegroundColor Cyan
& $venvPython -m pip install --upgrade pip
& $venvPython -m pip install -r requirements.txt

if (-not (Test-Path ".\.env") -and (Test-Path ".\.env.example")) {
    Write-Host "[4/4] Creating .env from .env.example..." -ForegroundColor Cyan
    Copy-Item ".\.env.example" ".\.env"
    Write-Host "Created .env. Please add API keys before running deep features." -ForegroundColor Yellow
} else {
    Write-Host "[4/4] .env already exists (not modified)." -ForegroundColor Cyan
}

Write-Host "Setup complete." -ForegroundColor Green
Write-Host "Next: run launch_dashboard.bat" -ForegroundColor Green