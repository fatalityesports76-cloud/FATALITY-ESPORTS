$ErrorActionPreference = "Stop"

$taskName = "Fatality-AutoStart-Deploy-Server"

cmd.exe /c "schtasks /Delete /TN ""$taskName"" /F >nul 2>&1" | Out-Null

if ($LASTEXITCODE -eq 0) {
  Write-Output "Tarefa removida: $taskName"
} else {
  Write-Output "Tarefa nao existia: $taskName"
}
