# Dominio local gratis (com HTTPS)

Este projeto roda com dominio oficial (producao) e dominios locais (desenvolvimento):

- Gratis sem admin: `https://fatality.lvh.me`
- Proprio offline (com hosts): `https://fatality.local`
- Fallback automatico HTTPS: `:8443` (se a porta 443 estiver ocupada)
- Redirect HTTP: `80/8080 -> HTTPS`

## Como iniciar

No PowerShell, dentro da pasta do projeto:

```powershell
.\start-local-server.ps1
```

Ou com duplo clique:

```bat
start-local-server.bat
```

## Como parar

No terminal do servidor, pressione:

`Ctrl + C`

## Observacoes

- Para producao com `fatality-e-sports-official.com.br`, o dominio precisa estar registrado e apontado no DNS.
- Para testes locais, nao precisa comprar dominio.
- `fatality.lvh.me` aponta para `127.0.0.1` e funciona sem editar hosts.
- Nao mapeie o dominio oficial no `hosts` local. Isso quebra a validacao publica de DNS/SSL.

## Habilitar HTTPS

Rode como administrador:

```powershell
.\setup-local-https.ps1
```

Esse comando:

- cria e confia um certificado local (usuario atual)
- garante apenas dominios locais no arquivo `hosts`

Depois inicie o servidor normalmente e acesse:

- `https://fatality.lvh.me`
- `https://fatality.local`
- ou `https://fatality.local:8443` se a porta 443 estiver ocupada

## Backend seguro

Consulte `SECURITY-BACKEND.md` para:

- setup de chaves e segredos
- senha de admin
- descriptografia offline das inscricoes

## Dominio proprio sem HTTPS (legado)

Se quiser apenas mapear host sem certificado:

```powershell
.\setup-own-local-domain.ps1
```
