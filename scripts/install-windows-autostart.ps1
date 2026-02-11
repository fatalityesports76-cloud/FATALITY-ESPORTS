$ErrorActionPreference = "Stop"

$taskName = "Fatality Auto Start (Deploy + Server)"
$scriptPath = Join-Path $PSScriptRoot "autostart-on-logon.ps1"

if (-not (Test-Path $scriptPath)) {
  throw "Script de bootstrap nao encontrado: $scriptPath"
}

$quotedScript = '"' + $scriptPath + '"'
$taskCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $quotedScript"

# Recria para garantir parametros corretos.
schtasks /Delete /TN $taskName /F 1>$null 2>$null | Out-Null

schtasks /Create `
  /F `
  /TN $taskName `
  /SC ONLOGON `
  /RL LIMITED `
  /TR $taskCommand | Out-Null

Write-Output "Tarefa criada: $taskName"
Write-Output "Comando: $taskCommand"
