#Requires -Version 5.0
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$RepoDir = $PSScriptRoot

Write-Host ""
Write-Host "  MeshBreaker - Windows Install" -ForegroundColor Cyan
Write-Host "  ==============================" -ForegroundColor Cyan
Write-Host ""

function Find-Python {
    foreach ($cmd in @("python", "python3", "py")) {
        try {
            $out = & $cmd --version 2>&1 | Out-String
            if ($out -match "Python (\d+)\.(\d+)") {
                if ([int]$Matches[1] -ge 3 -and [int]$Matches[2] -ge 10) {
                    return $cmd
                }
            }
        } catch {}
    }
    return $null
}

$python = Find-Python

if (-not $python) {
    Write-Host "Python 3.10+ not found - trying to install automatically..." -ForegroundColor Yellow

    $installed = $false

    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Host "Installing Python via winget..." -ForegroundColor Cyan
        try {
            winget install --id Python.Python.3.11 --silent --accept-package-agreements --accept-source-agreements
            $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" +
                        [System.Environment]::GetEnvironmentVariable("PATH", "User")
            $python = Find-Python
            if ($python) {
                $installed = $true
                Write-Host "Python installed via winget." -ForegroundColor Green
            }
        } catch {
            Write-Host "winget failed, trying next option..." -ForegroundColor Yellow
        }
    }

    if (-not $installed -and (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Host "Installing Python via Chocolatey..." -ForegroundColor Cyan
        try {
            choco install python --yes --no-progress 2>&1 | Out-Null
            $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" +
                        [System.Environment]::GetEnvironmentVariable("PATH", "User")
            $python = Find-Python
            if ($python) {
                $installed = $true
                Write-Host "Python installed via Chocolatey." -ForegroundColor Green
            }
        } catch {
            Write-Host "Chocolatey failed." -ForegroundColor Yellow
        }
    }

    if (-not $python) {
        Write-Host ""
        Write-Host "ERROR: Could not install Python automatically." -ForegroundColor Red
        Write-Host "Install it manually from: https://www.python.org/downloads/" -ForegroundColor Yellow
        Write-Host "During install, check 'Add Python to PATH', then re-run this script."
        Write-Host ""
        exit 1
    }
}

$pyVersion = & $python --version 2>&1
Write-Host "Python: $pyVersion" -ForegroundColor Green

Write-Host "Installing dependencies..." -ForegroundColor Cyan
try {
    & $python -m pip install --quiet --upgrade pip
    & $python -m pip install --quiet -r "$RepoDir\requirements.txt"
    Write-Host "Dependencies installed." -ForegroundColor Green
} catch {
    Write-Host "ERROR: pip install failed: $_" -ForegroundColor Red
    exit 1
}

$BinDir = "$env:USERPROFILE\.local\bin"
if (-not (Test-Path $BinDir)) {
    New-Item -ItemType Directory -Path $BinDir | Out-Null
}

$bat = "@echo off`r`n`"$python`" `"$RepoDir\meshbreaker.py`" %*"
Set-Content -Path "$BinDir\meshbreaker.bat" -Value $bat -Encoding ASCII
Write-Host "Wrapper created: $BinDir\meshbreaker.bat" -ForegroundColor Green

$currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($currentPath -notlike "*$BinDir*") {
    [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$BinDir", "User")
    Write-Host "Added $BinDir to PATH." -ForegroundColor Green
    Write-Host "Restart your terminal for it to take effect." -ForegroundColor Yellow
} else {
    Write-Host "$BinDir already in PATH." -ForegroundColor Green
}

Write-Host ""
Write-Host "Done! Restart your terminal then run: meshbreaker --help" -ForegroundColor Green
Write-Host ""
Write-Host "Note: L2CAP and SDP fuzzing require Linux. All other commands work here." -ForegroundColor DarkGray
Write-Host ""
