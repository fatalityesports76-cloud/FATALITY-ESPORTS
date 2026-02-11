$ErrorActionPreference = "Stop"

$envFile = Join-Path $PSScriptRoot ".cloudflare.env"
if (-not (Test-Path $envFile)) {
  Write-Error "Arquivo .cloudflare.env nao encontrado. Use .cloudflare.env.example como base."
}

Get-Content $envFile | ForEach-Object {
  $line = $_.Trim()
  if (-not $line -or $line.StartsWith("#")) {
    return
  }

  $parts = $line -split "=", 2
  if ($parts.Count -ne 2) {
    return
  }

  $key = $parts[0].Trim()
  $value = $parts[1].Trim().Trim('"').Trim("'")
  [Environment]::SetEnvironmentVariable($key, $value, "Process")
}

npm.cmd run security:cloudflare-hardening
