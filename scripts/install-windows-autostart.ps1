$ErrorActionPreference = "Stop"

$taskName = "Fatality-AutoStart-Deploy-Server"
$scriptPath = Join-Path $PSScriptRoot "autostart-on-logon.ps1"

if (-not (Test-Path $scriptPath)) {
  throw "Script de bootstrap nao encontrado: $scriptPath"
}

$taskArgument = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""

Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $taskArgument
$trigger = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERNAME"
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$task = New-ScheduledTask `
  -Action $action `
  -Trigger $trigger `
  -Principal $principal `
  -Settings $settings `
  -Description "Inicia auto deploy e servidor local da Fatality no login do Windows."

Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null

Write-Output "Tarefa criada: $taskName"
Write-Output "Comando: powershell.exe $taskArgument"
