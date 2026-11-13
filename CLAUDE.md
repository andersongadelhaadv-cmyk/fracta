<!-- FROTA:INICIO v1 2026-11-13 — gerado pelo repo fleet-rules. NÃO edite aqui: edite no fleet-rules e rode o sync. -->
# Regras da frota PreviusIA (bloco comum)

Este bloco vale igual em todos os repositórios, na máquina local, na nuvem e no Codex.
O resto deste CLAUDE.md vale só para este produto e prevalece no que for específico dele.
Em conflito entre este bloco e uma trava mecânica (hook, CI), vale a trava.

## 1. Faixa de risco de cada tarefa
Classifique pelos caminhos alterados. Vale a faixa mais alta tocada. Na dúvida, suba a faixa.

- **ALTA:** `prisma/`, migrations, `.github/`, `infra/`, `nginx/`, Docker, `.env*`, `.claude/`,
  scripts de deploy; código de autenticação, isolamento de tenant, pagamento e webhook,
  motores de cálculo, envio a clientes, exclusão de dados.
- **BAIXA:** só conteúdo, documentação, textos, estilos, `public/` e arquivos de teste.
- **MÉDIA:** todo o resto.

O que cada faixa exige:
- **BAIXA:** passa no build. Sem revisão.
- **MÉDIA:** testes do repo (`TEST_CMD`) passam; sem `TEST_CMD`, typecheck + build.
  Uma revisão que lista só bloqueadores. Sem nota.
- **ALTA:** o mesmo da média + revisor independente + OK do dono antes do merge.

Máximo de 2 ciclos de correção por tarefa. Se não fechar, pare e escale para o dono.
Não existe nota mínima. Nenhuma nota substitui teste.

## 2. Quem publica
- O agente trabalha numa branch e abre PR. O merge que publica é sempre do dono.
- Nunca dê push direto em `main`, `master`, `dev` ou `develop`. Nunca use o remoto `vps`.
- Deploy padrão: merge → GitHub Actions → imagem no GHCR → a VPS só puxa. Não existe staging.
- SSH na VPS e comandos em produção (`docker exec`, `psql`, `scp`): só o dono executa.
  Entregue o comando exato e o impacto.

## 3. Decisões de produto que valem para toda a frota
- **Pagamento:** destino é a Efí. Stripe e Woovi não recebem integração nova.
  Onde o código ainda usa uma delas, escreva "estado atual: X; destino: Efí" e não remova
  recepção existente sem tarefa específica.
- **IA:** Anthropic é o provedor principal; Gemini é reserva; OpenAI fica fora.
  Motores de cálculo determinísticos nunca chamam LLM.
- **Voz:** ElevenLabs não recebe integração nova.

## 4. Como trabalhar
- Um alvo por tarefa. Leitura e auditoria podem cobrir a frota; alteração, um repo por vez.
- Migration e mudança de schema são faixa ALTA, inclusive `prisma migrate dev`.
- Nunca use `|| true`, `continue-on-error` ou `--no-verify` para fazer algo passar.
  Todo job de CI tem `timeout-minutes`.
- Nunca escreva valor de chave, token ou senha em arquivo, commit, log ou resposta.
- Resposta curta, em prosa, com o resultado primeiro. Sem formulários.

## 5. Onde fica o estado
Este arquivo guarda regra, não estado. "Em andamento", "pendente" e listas de tarefas vão
para issue, PR ou o cockpit, nunca para o CLAUDE.md.
<!-- FROTA:FIM -->

# Fracta — CLAUDE.md do repositório

Daqui para baixo, só o que é específico deste SaaS.

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
