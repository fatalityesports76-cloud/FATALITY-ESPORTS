$ErrorActionPreference = "Stop"

$taskName = "Fatality-AutoStart-Deploy-Server"
$scriptPath = Join-Path $PSScriptRoot "autostart-on-logon.ps1"

if (-not (Test-Path $scriptPath)) {
  throw "Script de bootstrap nao encontrado: $scriptPath"
}

$quotedScript = '"' + $scriptPath + '"'
$taskCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $quotedScript"

# Recria para garantir parametros corretos.
$deleteCmd = "schtasks /Delete /TN ""$taskName"" /F >nul 2>&1"
cmd.exe /c $deleteCmd | Out-Null

$createCmd = "schtasks /Create /F /TN ""$taskName"" /SC ONLOGON /RL LIMITED /TR ""$taskCommand"""
$createOutput = cmd.exe /c $createCmd 2>&1

if ($LASTEXITCODE -ne 0) {
  throw "Falha ao criar tarefa agendada: $createOutput"
}

Write-Output "Tarefa criada: $taskName"
Write-Output "Comando: $taskCommand"
