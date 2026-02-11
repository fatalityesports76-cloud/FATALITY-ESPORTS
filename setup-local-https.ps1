param(
  [string]$PrimaryDomain = "fatality.local",
  [string[]]$AdditionalDomains = @()
)

$ErrorActionPreference = "Stop"

function Test-IsAdmin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-HostsEntry {
  param(
    [string]$Domain
  )

  $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
  $entry = "127.0.0.1 $Domain"
  $pattern = "^\s*127\.0\.0\.1\s+$([Regex]::Escape($Domain))(\s|$)"

  if (Select-String -Path $hostsPath -Pattern $pattern -Quiet) {
    Write-Host "Hosts ja configurado para $Domain"
    return
  }

  Add-Content -Path $hostsPath -Value "`r`n$entry"
  Write-Host "Hosts atualizado: $entry"
}

function Get-NormalizedDomains {
  param(
    [string[]]$Values
  )

  return $Values |
    Where-Object { $_ -and $_.Trim().Length -gt 0 } |
    ForEach-Object { $_.Trim().ToLowerInvariant() } |
    Select-Object -Unique
}

function New-StrongPassword {
  $bytes = New-Object byte[] 24
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  $rng.GetBytes($bytes)
  $rng.Dispose()
  return [Convert]::ToBase64String($bytes).Replace("/", "_").Replace("+", "-")
}

$isAdmin = Test-IsAdmin
if (-not $isAdmin) {
  Write-Error "Execute este script como Administrador."
}

$officialDomain = "fatality-e-sports-official.com.br"
$requestedDomains = @($PrimaryDomain) + $AdditionalDomains + @("fatality.local", "fatality.lvh.me", "localhost")
$dnsNames = Get-NormalizedDomains -Values $requestedDomains

foreach ($domain in $dnsNames) {
  if ($domain -eq "localhost") {
    continue
  }

  if ($domain -eq "fatality.lvh.me") {
    continue
  }

  if ($domain -eq $officialDomain) {
    Write-Host "Ignorando dominio oficial no hosts: $domain"
    continue
  }

  Ensure-HostsEntry -Domain $domain
}

ipconfig /flushdns | Out-Null
$certsDir = Join-Path $PSScriptRoot "certs"
New-Item -Path $certsDir -ItemType Directory -Force | Out-Null

$pfxPath = Join-Path $certsDir "fatality-local.pfx"
$cerPath = Join-Path $certsDir "fatality-local.cer"
$passwordFile = Join-Path $certsDir "fatality-local.pass.txt"

$passwordPlain = if (Test-Path $passwordFile) {
  (Get-Content -Path $passwordFile -Raw).Trim()
} else {
  $value = New-StrongPassword
  Set-Content -Path $passwordFile -Value $value -Encoding ASCII
  $value
}

if (-not $passwordPlain) {
  $passwordPlain = New-StrongPassword
  Set-Content -Path $passwordFile -Value $passwordPlain -Encoding ASCII
}

$securePassword = ConvertTo-SecureString -String $passwordPlain -AsPlainText -Force

$cert = New-SelfSignedCertificate `
  -DnsName $dnsNames `
  -FriendlyName "Fatality Local HTTPS" `
  -CertStoreLocation "Cert:\CurrentUser\My" `
  -KeyAlgorithm RSA `
  -KeyLength 2048 `
  -HashAlgorithm "SHA256" `
  -NotAfter (Get-Date).AddYears(5) `
  -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1")

Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $securePassword -Force | Out-Null
Export-Certificate -Cert $cert -FilePath $cerPath -Force | Out-Null

Import-Certificate -FilePath $cerPath -CertStoreLocation "Cert:\CurrentUser\Root" | Out-Null

Write-Host "Certificado HTTPS criado e confiavel para o usuario atual."
Write-Host "PFX: $pfxPath"
Write-Host "Senha PFX: $passwordFile"
Write-Host "Dominios no certificado:"
$dnsNames | ForEach-Object { Write-Host " - $_" }
Write-Host "Agora inicie o servidor e acesse https://$PrimaryDomain"
