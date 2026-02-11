$ErrorActionPreference = "Stop"

$taskName = "Fatality-AutoStart-Deploy-Server"

$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($null -eq $task) {
  Write-Output "Tarefa nao existia: $taskName"
  exit 0
}

Unregister-ScheduledTask -TaskName $taskName -Confirm:$false | Out-Null
Write-Output "Tarefa removida: $taskName"
