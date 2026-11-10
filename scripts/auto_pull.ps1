<#
.SYNOPSIS
    TRUSTTRACE Auto-Pull Watcher for Windows PowerShell.
.DESCRIPTION
    Continuously polls remote origin/main and automatically pulls any changes pushed by teammates.
#>
param(
    [int]$Interval = 10,
    [string]$Remote = "origin",
    [string]$Branch = "main"
)

Write-Host "Starting TRUSTTRACE Auto-Pull Watcher..." -ForegroundColor Cyan
python "$PSScriptRoot\auto_pull.py" --interval $Interval --remote $Remote --branch $Branch
