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
