$ErrorActionPreference = "Stop"

$scriptPath = Join-Path $PSScriptRoot "autostart-on-logon.ps1"
$startupDir = [Environment]::GetFolderPath("Startup")
$launcherPath = Join-Path $startupDir "Fatality-AutoStart.cmd"

if (-not (Test-Path $scriptPath)) {
  throw "Script de bootstrap nao encontrado: $scriptPath"
}

$launcherContent = @"
@echo off
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "$scriptPath"
"@

Set-Content -Path $launcherPath -Value $launcherContent -Encoding ASCII

Write-Output "Inicializacao automatica instalada."
Write-Output "Launcher: $launcherPath"
