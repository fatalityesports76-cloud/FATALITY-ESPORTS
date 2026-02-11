$ErrorActionPreference = "Stop"

function Write-AutostartLog([string]$message) {
  $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Write-Output "[autostart][$timestamp] $message"
}

function Ensure-Running {
  param(
    [Parameter(Mandatory = $true)][string]$MatchPattern,
    [Parameter(Mandatory = $true)][string]$StartCommand,
    [Parameter(Mandatory = $true)][string]$WorkingDir
  )

  $alreadyRunning = Get-CimInstance Win32_Process |
    Where-Object { ($_.CommandLine -as [string]) -like "*$MatchPattern*" } |
    Select-Object -First 1

  if ($alreadyRunning) {
    Write-AutostartLog "Ja em execucao: $MatchPattern (PID $($alreadyRunning.ProcessId))."
    return
  }

  Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $StartCommand -WorkingDirectory $WorkingDir -WindowStyle Hidden | Out-Null
  Write-AutostartLog "Processo iniciado: $MatchPattern"
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$logsDir = Join-Path $repoRoot "logs"
New-Item -Path $logsDir -ItemType Directory -Force | Out-Null

$deployLog = Join-Path $logsDir "auto-deploy.log"
$serverLog = Join-Path $logsDir "local-server.log"
$startServerScript = Join-Path $repoRoot "start-local-server.ps1"

Ensure-Running `
  -MatchPattern "auto-deploy-watch.ps1" `
  -StartCommand "npm run deploy:auto >> ""$deployLog"" 2>&1" `
  -WorkingDir $repoRoot

Ensure-Running `
  -MatchPattern "start-local-server.ps1" `
  -StartCommand "powershell -NoProfile -ExecutionPolicy Bypass -File ""$startServerScript"" >> ""$serverLog"" 2>&1" `
  -WorkingDir $repoRoot
