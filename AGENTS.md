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
