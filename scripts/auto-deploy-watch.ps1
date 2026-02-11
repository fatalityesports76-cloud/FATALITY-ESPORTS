param(
  [string]$Branch = "main",
  [int]$DebounceSeconds = 6,
  [switch]$RunOnce
)

$ErrorActionPreference = "Stop"

function Write-Step([string]$Message) {
  Write-Host "[auto-deploy] $Message"
}

function Require-GitRepository {
  $inside = git rev-parse --is-inside-work-tree 2>$null
  if ($LASTEXITCODE -ne 0 -or $inside -ne "true") {
    throw "Este diretorio nao e um repositorio Git."
  }
}

function Has-StagedChanges {
  git diff --cached --quiet
  return ($LASTEXITCODE -ne 0)
}

function Sync-Now {
  git add -A
  if (-not (Has-StagedChanges)) {
    Write-Step "Nenhuma mudanca nova para publicar."
    return $false
  }

  $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  git commit -m "chore(auto): sync $timestamp" | Out-Null
  git push origin $Branch | Out-Null
  Write-Step "Publicado com sucesso em origin/$Branch."
  return $true
}

function Ensure-RemoteAndBranch([string]$ExpectedBranch) {
  git remote get-url origin 1>$null 2>$null
  if ($LASTEXITCODE -ne 0) {
    throw "Remote 'origin' nao configurado. Execute: git remote add origin <URL_DO_REPO>"
  }

  $currentBranch = (git rev-parse --abbrev-ref HEAD).Trim()
  if ($currentBranch -ne $ExpectedBranch) {
    throw "Branch atual e '$currentBranch'. Troque para '$ExpectedBranch' antes de usar o auto deploy."
  }
}

function New-Watcher([string]$Path, [ref]$LastChangeRef) {
  $watcher = New-Object System.IO.FileSystemWatcher
  $watcher.Path = $Path
  $watcher.IncludeSubdirectories = $true
  $watcher.NotifyFilter = [IO.NotifyFilters]'FileName, DirectoryName, LastWrite, Size, CreationTime'
  $watcher.EnableRaisingEvents = $true

  $handler = {
    param($sender, $eventArgs)
    $fullPath = $eventArgs.FullPath
    if (
      $fullPath -match "\\\.git\\" -or
      $fullPath -match "\\node_modules\\" -or
      $fullPath -match "\\data\\" -or
      $fullPath -match "\\logs\\" -or
      $fullPath -match "\\secrets\\" -or
      $fullPath -match "\\keys\\" -or
      $fullPath -match "\\certs\\"
    ) {
      return
    }
    $LastChangeRef.Value = Get-Date
  }

  $created = Register-ObjectEvent $watcher Created -Action $handler
  $changed = Register-ObjectEvent $watcher Changed -Action $handler
  $renamed = Register-ObjectEvent $watcher Renamed -Action $handler
  $deleted = Register-ObjectEvent $watcher Deleted -Action $handler

  return @{
    Watcher = $watcher
    Subscriptions = @($created, $changed, $renamed, $deleted)
  }
}

function Dispose-Watcher($bundle) {
  if ($null -eq $bundle) { return }
  foreach ($sub in $bundle.Subscriptions) {
    try { Unregister-Event -SourceIdentifier $sub.Name -ErrorAction SilentlyContinue } catch {}
    try { Remove-Job -Id $sub.Id -Force -ErrorAction SilentlyContinue } catch {}
  }
  try { $bundle.Watcher.EnableRaisingEvents = $false } catch {}
  try { $bundle.Watcher.Dispose() } catch {}
}

Require-GitRepository
Ensure-RemoteAndBranch -ExpectedBranch $Branch

if ($RunOnce) {
  [void](Sync-Now)
  exit 0
}

$repoPath = (Get-Location).Path
$lastChange = Get-Date
$isPublishing = $false
$watcherBundle = $null

try {
  $watcherBundle = New-Watcher -Path $repoPath -LastChangeRef ([ref]$lastChange)
  Write-Step "Observando alteracoes em $repoPath"
  Write-Step "Quando houver mudancas, vou commitar e publicar automaticamente em origin/$Branch."
  Write-Step "Pressione Ctrl+C para parar."

  while ($true) {
    Start-Sleep -Milliseconds 800
    if ($isPublishing) { continue }

    $elapsed = (New-TimeSpan -Start $lastChange -End (Get-Date)).TotalSeconds
    if ($elapsed -lt $DebounceSeconds) { continue }

    $isPublishing = $true
    try {
      [void](Sync-Now)
    } catch {
      Write-Step "Falha ao publicar: $($_.Exception.Message)"
      Write-Step "Corrija o erro (auth/permissao/rede) e mantenha o script rodando."
    } finally {
      $lastChange = Get-Date
      $isPublishing = $false
    }
  }
} finally {
  Dispose-Watcher -bundle $watcherBundle
}
