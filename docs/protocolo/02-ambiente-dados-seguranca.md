# CAMADA 2 — AMBIENTE, DADOS, SEGURANÇA E INCIDENTE

## Ambientes

| Ambiente | Pode | Nunca |
|---|---|---|
| **LOCAL** (máquina/container da sessão, banco local com dado sintético) | Editar, testar, migrations locais, ler tudo exceto secrets, comandos livres | Apontar para banco/API de produção; usar dump de produção não anonimizado |
| **STAGING** (dado anonimizado) | Deploy de branch, smoke, dry-run de migration, ler logs | Se contiver dado real → é PRODUÇÃO para todos os efeitos |
| **PRODUÇÃO** (VPS, banco, storage, serviços com usuários) | Somente comandos de leitura de estado de infra autorizados por escrito, por comando, naquela sessão: `systemctl status`, `docker ps`, `df -h`, `free -m`, `uptime`, versão | Sem autorização por comando: conectar ao banco, ler log sem filtro, ler secrets, instalar, alterar config/firewall/cron/nginx/certificado/usuário/chave SSH/permissão, restart, deploy, executar script, escrever arquivo |

Antes do primeiro comando da sessão, declare o ambiente e como confirmou (hostname, `NODE_ENV`, nome do banco em `DATABASE_URL` sem exibir credencial). **Na dúvida, é produção.** Credencial disponível não é credencial autorizada: se a tarefa não exige VPS ou banco, declare "esta tarefa não precisa de acesso a produção" e não use, mesmo que esteja disponível. Antes de qualquer comando que conecte a banco/fila/serviço, imprima o host de destino.

## Dados: hierarquia para reprodução e teste
1. Fixture sintética (faker pt-BR; CPF 000.000.000-00 inválido de propósito; "Fulano Teste").
2. Seed anonimizada versionada no repositório.
3. Cópia de staging anonimizada (nomes, CPFs, e-mails, telefones, endereços e conteúdo de documentos substituídos; IDs internos e estrutura preservados).
4. Registro real de produção — **somente** com AUTORIZADO, `LIMIT 5`, colunas mínimas, nunca `*`, usado só para inspeção do agente e nunca copiado para chat, arquivo, teste, commit ou relatório. O pedido diz tabela, colunas, WHERE, quantidade e por que 1–3 não bastam.

Para reproduzir, peça ao usuário o **identificador**, nunca o conteúdo; se só o registro real reproduz, é bloqueante: ele exporta cópia anonimizada ou roda a reprodução e cola apenas o stack trace sem payload.

**Nunca, com dado real:** colar em resposta, comentário, commit, issue, relatório; gravar em fixture, seed, snapshot, `.json` de exemplo, `.md`; usar como entrada de teste; enviar a serviço externo (IA, validador online, pastebin, diff online); manter em `/tmp` após a sessão; `SELECT *`, `pg_dump`, `mongodump`, `COPY TO`, export de tabela; usar dado de um tenant para testar outro; reproduzir bug logando o objeto inteiro.

## Secrets
Nunca ler, imprimir, ecoar ou copiar o conteúdo de `.env*`, `*.pem`, `*.key`, `credentials.json`, docker-compose com senha, saída de `printenv`/`env`/`ps aux`/`docker inspect`, histórico de shell. Para saber se uma variável existe: `grep -c NOME .env` ou `[ -n "$VAR" ] && echo definida`. Nunca mover secret de env para código, de servidor para cliente (`NEXT_PUBLIC_*`, `VITE_*`, bundle), de arquivo ignorado para versionado. Nenhum valor literal de credencial em código, nem como fallback ou exemplo. Se um secret aparecer acidentalmente na saída de um comando, não o repita e avise que foi exposto no contexto da sessão, recomendando rotação.

## Backup obrigatório antes de
Qualquer migration em ambiente com dado real; `UPDATE`/`DELETE`/`ALTER` manual; script de correção/normalização de dados; alteração de permissões, roles ou RLS; alteração em storage (bucket, ACL, lifecycle); deploy que inclua qualquer um desses. **Backup válido** = existe, posterior à última escrita relevante, com tamanho e hash registrados e procedimento de restore conhecido. "O provedor faz snapshot diário" não vale sem confirmar horário e ponto de restauração. `UPDATE`/`DELETE` de correção: sempre em transação, com `SELECT COUNT(*)` da mesma cláusula WHERE colado no relatório antes de executar e número esperado de linhas declarado.

## Auth, permissões e webhooks
Middleware/guards/policies, roles/RBAC, RLS, regras de storage, validação de sessão/JWT, rate limit, CORS, CSP, cookies, rotas de webhook e validação de assinatura: sempre Zona Vermelha. Nenhum bypass "temporário" (`if DEBUG`, `skipAuth`, role hardcoded, token de teste). Ações sensíveis (exportar, excluir, alterar dado de cliente, alterar permissão) continuam exigindo o mesmo perfil de antes.

## Vetos automáticos do Agente 5 (Segurança/LGPD)
1. Remoção/afrouxamento de filtro de tenant ou de checagem de autorização.
2. Dado real de produção no chat, diff, teste, fixture, log ou relatório.
3. Secret no diff ou ecoado na sessão.
4. Migration ou correção de dado sem backup verificado.
5. Dependência nova sem verificação de supply chain (nome por URL, versão pinada, postinstall, CVEs, lockfile no diff); `npx`/`pipx`/`curl | sh`/`pip install` ad hoc no ambiente com acesso ao repo ou à VPS.
6. Novo destino de dado pessoal (serviço externo, tabela, arquivo, log) sem base legal declarada; transferência para IA/analytics/storage de terceiro sem contrato de operador.
7. Comando não autorizado em produção ou conexão não autorizada ao banco.
8. Log novo com objeto de domínio.
9. Bypass de auth/validação "temporário".
10. Mudança que impeça exclusão/portabilidade de dado do titular (art. 18 LGPD) ou crie cópia paralela sem expurgo.
11. Injeção: concatenação de string em query, `eval`/`exec`/`child_process` com entrada do usuário, `dangerouslySetInnerHTML` com conteúdo de terceiro, path traversal em upload; upload sem validação de tipo/tamanho no servidor ou servido sem URL assinada por tenant.

## Protocolo de incidente
Se em qualquer momento você perceber que expôs secret ou dado pessoal (chat, arquivo, commit), executou comando não autorizado em produção, alterou dado sem backup, ou uma mudança aplicada pode ter permitido acesso entre tenants — **pare toda atividade, não corrija em silêncio**, e escreva:

```
### INCIDENTE
O que aconteceu / quando / o que foi exposto ou alterado / quem pode ter sido afetado (tenants, titulares, volume) / o que ainda está exposto agora / ações imediatas sugeridas (rotacionar chave X, reverter commit Y, restaurar backup Z, desligar flag W) / possível obrigação de comunicação (ANPD art. 48 — 3 dias úteis; titulares; OAB art. 34 VII).
```

Suspeita de dado de um tenant visível a outro **encerra o fluxo normal**: é incidente de segurança, não bug; não toque em código; reporte imediatamente.

---
