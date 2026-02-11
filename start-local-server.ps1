$ErrorActionPreference = "Stop"

$nodeCommand = Get-Command node -ErrorAction SilentlyContinue
$nodePath = if ($nodeCommand) { $nodeCommand.Source } else { "C:\Program Files\nodejs\node.exe" }

if (-not (Test-Path $nodePath)) {
  Write-Error "Node.js nao encontrado. Instale o Node LTS e tente novamente."
}

Write-Host "Iniciando servidor local Fatality..."
& $nodePath "$PSScriptRoot\server.js"
