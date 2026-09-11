# Fracta — CLAUDE.md do repositório

Este repositório segue o **Protocolo Anti-Quebra v2** (núcleo e fases em `~/.claude/CLAUDE.md`; camadas complementares em `docs/protocolo/`). Este arquivo traz só o que é específico deste SaaS. Em conflito, o protocolo prevalece.

## Identidade
- SaaS: Fracta
- Função no ecossistema: <preencha em 1 linha>
- Stack detectada: Node/TS
- Roda em produção como container Docker numa VPS compartilhada com outros SaaS. **Nada aqui é executado na VPS pelo agente.** Deploy só por `git push` → CI → merge humano.

## Comandos (o agente usa estes e só estes)
- Testes: `npm test`
- Lint: `npm run lint`
- Build/typecheck: `npm run build`
- Testes de uma pasta: <ex.: `npx vitest run --dir src/modulos/X` ou `pytest tests/X -q`>

## Zona Vermelha específica deste repositório (além da lista padrão do protocolo)
- <ex.: src/shared/ — usado por billing, PDF e fila>
- <ex.: src/core/tenant/ — isolamento multi-tenant>
- <ex.: src/integracoes/ — PJe, pagamento, WhatsApp>

## Multi-tenant e dados
- Chave de tenant: <ex.: `escritorio_id`> imposta em: <middleware / ORM scope / RLS>
- Tenant de teste com dados fictícios: <id ou "não existe">
- Categorias de dado pessoal tratadas: <identificação / financeiro / saúde / criminal / segredo de justiça>

## ⚠️ `fleet-baseline.json` da raiz é SEMENTE — não é o baseline real

O arquivo versionado no `master` está **congelado em 13/07/2026** e mostra sites em D
que hoje são A. Ele existe só como rede de recuperação: o workflow o sobrescreve com o
baseline vivo quando a branch existe (`fleet-monitor.yml`, passo "Configure").

O **baseline vivo** é reescrito todo dia na branch **`monitor-baseline`**. Leia assim:

```
gh api "repos/andersongadelhaadv-cmyk/fracta/contents/fleet-baseline.json?ref=monitor-baseline" --jq .content | base64 -d
```

Ler o da raiz e concluir "a frota está degradada" **já aconteceu** (05/09/2026: dois
sites reportados em D estavam em A, confirmado por scan ao vivo). Na dúvida, escaneie:
`POST https://fracta.pro/api/scan` com `{"url": "..."}` devolve `grade` na hora.

⛔ **Não "comente" o JSON nem acrescente chave explicativa nele.** O tipo é
`Record<domínio, BaselineEntry>` (mapa liso, sem envelope): qualquer chave inventada
vira domínio falso e a catraca (`ratchetBaseline`, `{...baseline}`) a copia para o
baseline vivo permanentemente.

## Produção e observabilidade
- Onde ver erros: <Sentry / logs do container / painel>
- Feature flags: <mecanismo ou "não existe">
- Janela de menor uso: <ex.: 00h–06h>
- Jobs agendados que passam por este código: <cron / fila>

## Fluxo por ticket
1. Humano escreve a pasta do problema em `.claude/zona-verde` e cria branch `fix/<slug>`.
2. Primeira mensagem = `docs/protocolo/ENTRADA.md` preenchido.
3. O agente segue as fases; quando um hook bloquear, ele para e pede fronteira.
4. Entrega = PR com a saída de `bash scripts/scope-check.sh` no relatório.
