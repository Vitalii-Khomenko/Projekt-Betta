$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\pip.exe install -e .
.\.venv\Scripts\pip.exe install pyright

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
}

Write-Host "[betta-morpho] autonomous environment bootstrapped"
