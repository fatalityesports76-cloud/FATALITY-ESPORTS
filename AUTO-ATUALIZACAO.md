# Atualizacao automatica do site (sem push manual)

## O que este fluxo faz

- Monitora alteracoes locais no projeto.
- Faz `git add`, `commit` e `push` automaticos na branch `main`.
- Ao chegar no GitHub, seu provedor (Netlify/Render) faz deploy automatico.

## Como ligar

No terminal, dentro da pasta do projeto:

```powershell
npm run deploy:auto
```

Enquanto esse comando estiver rodando, qualquer edicao salva sera publicada automaticamente.

## Publicar uma vez so

```powershell
npm run deploy:once
```

## Importante

- Isso nao e "tempo real" instantaneo: o deploy publico normalmente leva de 30 segundos a alguns minutos.
- O script publica na branch `main`; mantenha as alteracoes nessa branch.
- Se der erro 403 no push, refaca login no GitHub com a conta que tem permissao no repositorio.
