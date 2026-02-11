param(
  [string]$Domain = "fatality.local"
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
  Write-Host "Abra o PowerShell como Administrador e execute novamente:"
  Write-Host "  .\\setup-own-local-domain.ps1"
  exit 1
}

$hostsPath = "C:\Windows\System32\drivers\etc\hosts"
$entry = "127.0.0.1 $Domain"
$pattern = "^\s*127\.0\.0\.1\s+$([Regex]::Escape($Domain))(\s|$)"

if (Select-String -Path $hostsPath -Pattern $pattern -Quiet) {
  Write-Host "Dominio ja configurado no hosts: $Domain"
} else {
  Add-Content -Path $hostsPath -Value "`r`n$entry"
  Write-Host "Dominio configurado: $Domain -> 127.0.0.1"
}

ipconfig /flushdns | Out-Null
Write-Host "DNS local atualizado. Agora voce pode acessar:"
Write-Host "  http://$Domain"
Write-Host "  https://$Domain (se o certificado HTTPS local estiver configurado)"
