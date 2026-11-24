# bin/plumb-guard.ps1 — Windows PowerShell Launcher for Plumb Guard
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ScriptArgs
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$HarnessDir = Resolve-Path (Join-Path $ScriptDir "..")
$GuardScript = Join-Path $HarnessDir "guard.py"

$PythonCmd = Get-Command python -ErrorAction SilentlyContinue
$PythonArgs = @()
if (-not $PythonCmd) {
    $PythonCmd = Get-Command py -ErrorAction SilentlyContinue
    if ($PythonCmd) {
        $PythonArgs = @("-3")
    }
}

if (-not $PythonCmd) {
    Write-Error "Error: Python 3 was not found in PATH."
    exit 1
}

& $PythonCmd.Source @PythonArgs $GuardScript @ScriptArgs
exit $LASTEXITCODE
