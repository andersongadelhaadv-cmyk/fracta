---
title: "Checklist de segurança antes de lançar seu SaaS"
description: "Checklist de segurança para SaaS: transporte, headers, cookies, auth, segredos, LGPD e operação. O que é bloqueante, o que dá pra verificar de fora."
slug: "checklist-seguranca-saas"
date: "2026-06-30"
updated: "2026-06-30"
author: "Anderson Gadelha"
tags: ["segurança", "saas", "checklist"]
keyword: "checklist de segurança saas"
---

Lançar um SaaS sem revisar segurança é apostar que ninguém vai olhar antes de você. Mau negócio: bots varrem a internet atrás de headers ausentes, cookies sem flag e painéis admin esquecidos abertos, 24 horas por dia. Um **checklist de segurança SaaS** não torna seu produto "100% seguro" — isso não existe. Ele reduz risco, fecha as portas óbvias e te dá a chance de dormir. A ideia aqui é exatamente essa: itens acionáveis, organizados por área, com o que é **bloqueante** (não lança sem) separado do que é desejável.

Vou marcar também o que dá pra verificar **de fora**, sem acesso ao seu código — o que chamamos de checagem passiva — versus o que só dá pra confirmar com acesso ao servidor, ao banco ou ao repositório. Essa distinção importa: a fatia observável você consegue auditar em segundos; o resto exige disciplina interna.

## Transporte: HTTPS de verdade, em tudo

Antes de qualquer header sofisticado, o básico inegociável é o transporte. Se o tráfego trafega em claro em algum ponto, todo o resto vira teatro.

| Item | Por quê | Bloqueante? |
|------|---------|-------------|
| HTTPS em todas as rotas (app, API, assets) | Tráfego em claro permite leitura e adulteração por quem está no caminho | **Sim** |
| Certificado TLS válido e não expirado | Cert vencido ou de hostname errado quebra confiança e bloqueia clientes | **Sim** |
| Redirect 80 → 443 | Sem ele, o primeiro acesso vai em HTTP antes de subir pra HTTPS | **Sim** |
| HSTS (`Strict-Transport-Security`) | Força o browser a só falar HTTPS, fecha a janela do downgrade | Sim |
| TLS 1.2+ apenas (sem SSLv3/TLS 1.0/1.1) | Versões antigas têm ataques conhecidos | Sim |

Tudo nesta tabela é **verificável de fora**. Um scan passivo já te diz se o cert é válido, se o redirect existe e se o HSTS está presente. É o lugar certo pra começar.

## Security headers: defesa barata e quase sempre esquecida

Headers HTTP de segurança custam minutos pra configurar e resolvem classes inteiras de ataque no navegador. A maioria dos SaaS sobe sem nenhum. É a fruta mais baixa do checklist.

| Item | Por quê | Bloqueante? |
|------|---------|-------------|
| `Content-Security-Policy` (CSP) | Mitiga XSS limitando de onde scripts podem carregar | Sim (mesmo que básica) |
| `X-Content-Type-Options: nosniff` | Impede o browser de "adivinhar" tipo de conteúdo e executar o que não devia | Sim |
| `X-Frame-Options` ou `frame-ancestors` na CSP | Bloqueia clickjacking via iframe | Sim |
| `Referrer-Policy` | Evita vazar URLs internas (com tokens) no header Referer | Desejável |
| `Permissions-Policy` | Desliga APIs do browser que você não usa (câmera, geo, etc.) | Desejável |

CSP é a mais trabalhosa porque pode quebrar scripts legítimos se feita no susto. Comece em modo `Report-Only`, observe os relatórios e só então aplique. Mas comece — uma CSP imperfeita protege mais que nenhuma. **Todos esses headers são observáveis de fora**, então um scanner aponta os ausentes na hora.

## Cookies e sessão: três flags que mudam tudo

Cookie de sessão é a chave da casa do usuário. As flags certas evitam que essa chave vaze ou seja roubada por scripts de terceiros.

| Item | Por quê | Bloqueante? |
|------|---------|-------------|
| `Secure` em cookies de sessão | Impede o cookie de trafegar em HTTP claro | **Sim** |
| `HttpOnly` em cookies de sessão | JavaScript não acessa o cookie, corta roubo via XSS | **Sim** |
| `SameSite=Lax` ou `Strict` | Reduz CSRF ao não enviar o cookie em requisições cross-site | Sim |
| Expiração e rotação de sessão | Sessão eterna é sessão roubável indefinidamente | Sim |
| Invalidação no logout | Logout que não mata a sessão no servidor não é logout | Sim |

As três flags (`Secure`, `HttpOnly`, `SameSite`) são **verificáveis de fora** — aparecem no header `Set-Cookie`. Já a expiração real e a invalidação no servidor exigem testar o fluxo com acesso.

## Autenticação: onde mais gente erra

Autenticação é o ponto onde um erro silencioso vira manchete. Nenhum desses itens é opcional.

| Item | Por quê | Bloqueante? |
|------|---------|-------------|
| Senhas com hash forte (**bcrypt** ou **argon2**) | MD5/SHA1 ou texto puro = vazamento total no primeiro dump de banco | **Sim** |
| Rate-limit no login | Sem ele, força-bruta e credential stuffing rodam à vontade | **Sim** |
| Sem `alg: none` em JWT; valide a assinatura | `alg: none` permite forjar tokens; é falha clássica | **Sim** |
| MFA disponível (ao menos pra contas sensíveis/admin) | Segunda camada quando a senha vaza | Desejável (Sim para admin) |
| Mensagens de erro genéricas no login | "Usuário não existe" entrega quais e-mails são válidos | Desejável |
| Política de senha mínima razoável | Barra as senhas triviais sem irritar o usuário | Desejável |

Isto é quase tudo **interno** — só se confirma com acesso ao código e ao fluxo. De fora dá pra inferir pouca coisa (a presença de rate-limit, às vezes). Por isso autenticação exige revisão de código, não scan.

## Autorização: o bug que o scanner não vê

Autenticação confirma **quem** você é. Autorização confirma o que você **pode fazer**. A falha mais comum e mais cara aqui é o **IDOR** (Insecure Direct Object Reference): trocar `/pedidos/123` por `/pedidos/124` e ver o pedido de outra pessoa.

| Item | Por quê | Bloqueante? |
|------|---------|-------------|
| Checagem de propriedade do objeto em cada endpoint | Sem ela, qualquer ID na URL vira acesso indevido (IDOR) | **Sim** |
| Isolamento multi-tenant rigoroso | Um cliente jamais pode ler dados de outro; vazamento entre tenants é fatal | **Sim** |
| Autorização no backend, nunca só no front | Esconder o botão não protege a rota | **Sim** |
| Princípio do menor privilégio nos papéis | Usuário comum não deveria alcançar ação de admin | Sim |

Tudo aqui é **interno e exige acesso**. É a categoria de risco mais perigosa justamente porque é invisível de fora — só revisão de código e testes de fluxo pegam. Trate IDOR e isolamento de tenant como bloqueantes absolutos. (Esses dois itens estão no topo do OWASP Top 10, sob "Broken Access Control", e por bons motivos.)

## Segredos: o que vaza enquanto você dorme

Chave de API commitada é um dos vazamentos mais frequentes e mais bobos. E tem um detalhe cruel: apagar a chave do código **não basta**. Ela continua no histórico do Git, e ferramentas como o **gitleaks** varrem todo o histórico do repositório — não só o último commit. Se vazou uma vez, considere comprometida e rotacione.

| Item | Por quê | Bloqueante? |
|------|---------|-------------|
| Nenhuma chave/segredo no código | Repo público ou vazado expõe tudo de uma vez | **Sim** |
| `.env` no `.gitignore` | Evita commitar credenciais por descuido | **Sim** |
| Varredura de histórico (ex.: gitleaks no CI) | Segredo some do HEAD mas fica no histórico | Sim |
| Rotação de chaves expostas | Chave que já vazou é chave queimada, sempre | **Sim** se houve exposição |
| Segredos em cofre/variáveis de ambiente | Centraliza e controla o acesso | Sim |

**Interno.** Você roda gitleaks no seu próprio CI — eu rodo na minha frota inteira e já me salvou de vazamento real. De fora ninguém vê seu `.env`, mas se o repositório for público, qualquer um vê o histórico.

## Dependências: o ataque que vem de terceiros

Seu código pode estar impecável e ainda assim ter uma falha crítica, herdada de uma biblioteca desatualizada. Dependência é superfície de ataque.

| Item | Por quê | Bloqueante? |
|------|---------|-------------|
| `npm audit` (ou equivalente) sem vulnerabilidade crítica | Falha conhecida em dependência é exploração pronta | Sim |
| Dependências atualizadas | Versões antigas acumulam CVEs públicos | Sim |
| Dependabot / Renovate ligado | Automatiza o aviso antes de virar incidente | Desejável |
| Lockfile commitado | Garante build reproduzível e auditável | Desejável |

**Interno** — depende do seu `package.json` e do pipeline. Liga o Dependabot e deixa a máquina te avisar.

## Configuração: o que prod nunca deveria expor

Configuração de produção que ficou em modo desenvolvimento é convite aberto. São erros de descuido, não de arquitetura — e por isso fáceis de corrigir.

| Item | Por quê | Bloqueante? |
|------|---------|-------------|
| CORS não-permissivo (sem `*` com credenciais) | CORS frouxo deixa qualquer site chamar sua API autenticada | **Sim** |
| Sem stack-trace/debug em produção | Erro detalhado entrega caminhos, libs e versões ao atacante | **Sim** |
| Painéis admin protegidos (auth + IP/rota não óbvia) | Admin exposto é o alvo número um dos bots | **Sim** |
| Sem diretórios/arquivos sensíveis servidos (`.git`, `.env`, backups) | Listagem aberta vaza tudo de bandeja | **Sim** |

Boa parte é **observável de fora**: dá pra ver se a CSP responde, se o `.git/` está exposto, se um endpoint cospe stack-trace. CORS e proteção do admin dão pra sondar parcialmente de fora, mas confirmar mesmo só com acesso.

## Dados e LGPD: o mínimo legal antes de coletar dados

No Brasil, tratar dado pessoal sem base legal e sem transparência é risco jurídico, não só técnico. Não precisa de um programa de privacidade inteiro pra lançar — precisa do mínimo honesto.

| Item | Por quê | Bloqueante? |
|------|---------|-------------|
| Política de privacidade linkada e acessível | Transparência é dever legal sob a LGPD | **Sim** |
| Base legal definida para cada tratamento | Coletar dado sem base legal é tratamento irregular | **Sim** |
| Política de retenção (não guardar pra sempre) | Dado retido além do necessário é passivo e risco | Sim |
| Canal de contato do titular/encarregado | Titular tem direito de pedir acesso e exclusão | Sim |
| Consentimento de cookies quando aplicável | Cookies não essenciais exigem base e aviso | Desejável |

A existência da política e do link é **verificável de fora** (uma checagem LGPD-lite). Base legal, retenção e os fluxos de direito do titular são **internos** — dependem de como você de fato trata os dados. Sou advogado, construo legaltechs, e repito: a página bonita não substitui a base legal por trás.

## Operação: o que te salva quando algo dá errado

Nenhum checklist evita 100% dos incidentes. A pergunta não é "se", é "quando" — e se você vai conseguir reagir.

| Item | Por quê | Bloqueante? |
|------|---------|-------------|
| Backups automáticos **e testados** (restore real) | Backup que nunca foi restaurado pode não existir | **Sim** |
| Logs de acesso e de erro | Sem log, você não sabe o que aconteceu nem quando | Sim |
| Plano de resposta a incidente (mesmo simples) | Saber a quem avisar e o que fazer economiza horas críticas | Desejável |
| Monitoramento de disponibilidade | Descobrir que caiu pelo cliente é tarde demais | Desejável |

**Interno**, todo ele. O detalhe que mais gente pula: backup **testado**. Backup que você nunca restaurou é uma promessa, não uma garantia.

## Passivo vs. interno: por onde começar

Resumindo a distinção que costurou o texto inteiro:

- **Verificável de fora (passivo):** TLS e redirect, HSTS, todos os security headers, flags de cookie no `Set-Cookie`, exposição de `.git`/`.env`, stack-trace em erro, presença da política de privacidade. Dá pra auditar sem tocar no seu servidor.
- **Exige acesso (interno):** hash de senha, rate-limit, JWT, IDOR e isolamento de tenant, segredos no histórico, `npm audit`, base legal da LGPD, backups testados. Aqui não tem atalho — é revisão de código, de fluxo e de processo.

Comece pela fatia observável. É a mais rápida de fechar, a que os bots checam primeiro, e a que te dá um retorno imediato sobre a postura básica do produto. Depois desça para o interno, que é mais lento porém mais profundo.

## Comece pelo scan grátis

É exatamente a fatia observável que o **Fracta** cobre: headers, TLS, cookies e uma checagem LGPD-lite, com uma **nota de A a F** em segundos, sem cadastro, de graça e determinístico — o mesmo resultado toda vez. Não é o checklist inteiro (a parte interna nenhum scan externo enxerga, e a gente é honesto sobre isso), mas é o ponto de partida certo: aponta as portas óbvias que ficaram abertas antes que um bot aponte por você.

Antes de marcar os itens internos deste checklist, rode o scan grátis em **[fracta.pro](https://fracta.pro)** e veja a nota do seu SaaS agora. É o primeiro item da lista que você consegue riscar em menos de um minuto.
