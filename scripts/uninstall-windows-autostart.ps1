$ErrorActionPreference = "Stop"

$startupDir = [Environment]::GetFolderPath("Startup")
$launcherPath = Join-Path $startupDir "Fatality-AutoStart.cmd"

if (-not (Test-Path $launcherPath)) {
  Write-Output "Launcher nao existia: $launcherPath"
  exit 0
}

Remove-Item -Path $launcherPath -Force
Write-Output "Inicializacao automatica removida: $launcherPath"
