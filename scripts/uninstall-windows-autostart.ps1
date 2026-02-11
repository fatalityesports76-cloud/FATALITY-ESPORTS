$ErrorActionPreference = "Stop"

$taskName = "Fatality Auto Start (Deploy + Server)"

schtasks /Delete /TN $taskName /F | Out-Null
Write-Output "Tarefa removida: $taskName"
