# Backend de seguranca Fatality

## Recursos implementados

- API HTTPS com redirecionamento forcado de HTTP para HTTPS
- Headers de seguranca fortes (Helmet + CSP restritiva)
- Protecao CSRF com cookies assinados
- Rate limit global, por login e por inscricao
- Bloqueio adaptativo por risco (IP ban temporario para comportamento suspeito)
- Hardening anti-DoS no servidor Node (timeouts, limites de conexao e socket)
- Suporte a operacao atras de Cloudflare com validacao de `CF-Connecting-IP`
- Honeypot anti-bot no formulario
- Auditoria de eventos em `logs/security-audit.jsonl`
- Sessao admin com cookie `HttpOnly`, `Secure`, `SameSite=Strict`
- Vinculo de sessao por hash de IP + hash de User-Agent
- Armazenamento de inscricoes em envelope criptografado E2E
- Chaves de criptografia E2E separadas (`keys/` publica, `secrets/` privada)
- Script offline para descriptografar inscricoes
- Camada anti-inspecao no frontend (dissuasao)

## Criptografia ponta a ponta

Fluxo:

1. Frontend busca chave publica em `/api/security/bootstrap`
2. Frontend criptografa os dados com AES-256-GCM
3. Chave AES e encapsulada com RSA-OAEP-256
4. Backend salva apenas envelope criptografado
5. Descriptografia ocorre offline com `scripts/decrypt-submissions.js`

## Setup rapido

1. HTTPS local (admin):

```powershell
.\setup-local-https.ps1
```

2. Setup de seguranca do backend:

```powershell
npm.cmd run security:setup
```

3. Definir senha admin forte:

```powershell
npm.cmd run security:set-admin -- "SENHA_FORTE_AQUI"
```

4. Iniciar servidor:

```powershell
.\start-local-server.ps1
```

5. Rodar red team local automatizado:

```powershell
npm.cmd run security:red-team-local
```

6. Hardening de borda Cloudflare (WAF + rate limits):

```powershell
# copie .cloudflare.env.example para .cloudflare.env e preencha token/zone
.\\apply-cloudflare-hardening.ps1
```

## Dominio local

- `https://fatality-e-sports-official.com.br` (oficial)
- `https://fatality.local`
- `https://fatality.lvh.me`
- fallback HTTPS: `:8443`

## Painel admin

- URL: `/admin`
- Login padrao: usuario `admin`
- Se senha nao for definida manualmente, verifique arquivo temporario:
  - `secrets/admin-temporary-password.txt`

## Arquivos importantes

- `server.js`
- `scripts/setup-security.js`
- `scripts/set-admin-password.js`
- `scripts/decrypt-submissions.js`
- `data/submissions.jsonl`
- `logs/security-audit.jsonl`
- `keys/e2e-public.pem`
- `secrets/e2e-private.pem`

## Limites reais

- Nao existe protecao 100% contra DDoS apenas no backend local.
- Para mitigacao forte de DDoS em producao, use CDN/WAF (Cloudflare) + reverse proxy + firewall na borda.
- Nao existe bloqueio 100% de DevTools/Inspecionar no navegador; o que foi implementado e camada de dissuasao.
