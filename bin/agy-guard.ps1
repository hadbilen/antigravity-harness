# bin/agy-guard.ps1 — Windows PowerShell Launcher for Antigravity Guard
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ScriptArgs
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$HarnessDir = Resolve-Path (Join-Path $ScriptDir "..")
$GuardScript = Join-Path $HarnessDir "guard.py"

$PythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $PythonCmd) {
    $PythonCmd = Get-Command py -ErrorAction SilentlyContinue
}

if (-not $PythonCmd) {
    Write-Error "Error: Python 3 was not found in PATH."
    exit 1
}

& $PythonCmd.Source $GuardScript @ScriptArgs
exit $LASTEXITCODE
