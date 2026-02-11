$ErrorActionPreference = "Stop"

$taskName = "Fatality-AutoStart-Deploy-Server"

& schtasks /Delete /TN $taskName /F *> $null

if ($LASTEXITCODE -eq 0) {
  Write-Output "Tarefa removida: $taskName"
} else {
  Write-Output "Tarefa nao existia: $taskName"
}
