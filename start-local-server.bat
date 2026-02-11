@echo off
setlocal

set "NODE_EXE=node"
where node >nul 2>&1
if errorlevel 1 (
  if exist "C:\Program Files\nodejs\node.exe" (
    set "NODE_EXE=C:\Program Files\nodejs\node.exe"
  ) else (
    echo Node.js nao encontrado. Instale o Node LTS e tente novamente.
    exit /b 1
  )
)

echo Iniciando servidor local Fatality...
"%NODE_EXE%" "%~dp0server.js"
