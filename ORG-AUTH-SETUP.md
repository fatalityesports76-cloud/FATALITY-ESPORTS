# Fatality Org Auth Setup

## 1) Donos com numero fixo
- Edite `.env.local`:
  - `ORG_OWNER_FIXED_NUMBERS=900001,900002` (exemplo)
- Reinicie o servidor.

## 2) Credenciais iniciais de dono
- Arquivo gerado automaticamente:
  - `secrets/org-owner-bootstrap.txt`
- Troque a senha no primeiro login.

## 3) Fluxo de cadastro/aprovacao
- Usuario preenche cadastro com: funcao, email, nome completo, nome no jogo, ID e Server ID.
- Antes do envio final, o sistema mostra um resumo com confirmar/recusar.
- Ao confirmar, o sistema envia um codigo de 6 digitos para o e-mail do cadastro.
- Usuario valida o codigo em `/confirmar-email` para concluir a solicitacao.
- Dono aprova/reprova no painel de login da org, com todos os dados preenchidos no cadastro.
- Ao aprovar:
  - sistema gera `numero de usuario` fixo interno,
  - senha inicial aleatoria,
  - envia credenciais conforme canais configurados.

## 4) Recuperacao de senha (confirmacao de e-mail)
- Endpoint interno:
  - confirma e-mail + atualiza senha: `/api/org/password/request-reset`
- Campos exigidos:
  - `userNumber`, `email`, `emailConfirm`, `newPassword`
- O endpoint legado `/api/org/password/confirm-reset` foi desativado.

## 5) Provedores de entrega
- WhatsApp:
  - Provider direto Meta Cloud API:
    - `ORG_WHATSAPP_PROVIDER=meta_cloud`
    - `ORG_META_WA_PHONE_NUMBER_ID`
    - `ORG_META_WA_ACCESS_TOKEN`
    - `ORG_META_WA_API_VERSION` (ex.: `v21.0`)
    - `ORG_META_WA_GRAPH_BASE_URL` (normalmente `https://graph.facebook.com`)
  - Opcional (fallback legado):
    - `ORG_WHATSAPP_WEBHOOK_URL`
  - Verificar configuracao webhook legado:
    - `npm.cmd run org:whatsapp:check`
  - Teste de envio webhook legado (numero com DDI):
    - `npm.cmd run org:whatsapp:test -- --to=5511999999999`
- Email:
  - `ORG_EMAIL_PROVIDER=resend` ou `webhook`
  - Obrigatorio para enviar o codigo de confirmacao de cadastro.
  - Resend:
    - `ORG_RESEND_API_KEY`
    - `ORG_EMAIL_FROM`
    - `ORG_EMAIL_SUBJECT_PREFIX`

## 6) Auditoria e logs
- Store de usuarios/cargos:
  - `data/org-auth-store.json`
- Log de entregas:
  - `logs/org-delivery-log.jsonl`

## 7) Teste rapido local
- Execute:
  - `npm.cmd run org:smoke` (PowerShell no Windows)
  - `npm run org:smoke` (terminals sem bloqueio de script)
- Resultado esperado:
  - linha com `Org smoke test OK`.
