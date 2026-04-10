$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

if (Test-Path ".env") {
    Get-Content ".env" | ForEach-Object {
        if ($_ -match '^\s*#' -or $_ -match '^\s*$') { return }
        $parts = $_ -split '=', 2
        if ($parts.Length -eq 2) {
            [Environment]::SetEnvironmentVariable($parts[0], $parts[1])
        }
    }
}

$PythonBin = if ($env:BETTA_PYTHON) { $env:BETTA_PYTHON } else { ".\.venv\Scripts\python.exe" }

$Args = @(
    "launcher.py",
    "scan",
    "--target", ($(if ($env:BETTA_TARGET) { $env:BETTA_TARGET } else { "127.0.0.1" })),
    "--ports", ($(if ($env:BETTA_PORTS) { $env:BETTA_PORTS } else { "top20" })),
    "--profile", ($(if ($env:BETTA_PROFILE) { $env:BETTA_PROFILE } else { "x10" })),
    "--transport", ($(if ($env:BETTA_TRANSPORT) { $env:BETTA_TRANSPORT } else { "connect" })),
    "--artifact", ($(if ($env:BETTA_ARTIFACT) { $env:BETTA_ARTIFACT } else { "artifacts/scanner_model.json" })),
    "--report", ($(if ($env:BETTA_REPORT) { $env:BETTA_REPORT } else { "artifacts/snn_model.json" })),
    "--checkpoint-every", ($(if ($env:BETTA_CHECKPOINT_EVERY) { $env:BETTA_CHECKPOINT_EVERY } else { "1000" }))
)

if ($env:BETTA_VERIFY_WITH_NMAP -eq "1") {
    $Args += "--verify-with-nmap"
}

if ($env:BETTA_SPEED_LEVEL) {
    $Args += @("--speed-level", $env:BETTA_SPEED_LEVEL)
}

& $PythonBin @Args
