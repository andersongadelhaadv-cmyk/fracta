---
title: "Security headers para SaaS: o guia prático (e como testar de graça)"
description: "Guia prático de security headers para SaaS: HSTS, CSP, nosniff, frame-ancestors e mais — sintaxe real, erros comuns e como testar de graça."
slug: "security-headers-saas"
date: "2026-06-30"
updated: "2026-06-30"
author: "Anderson Gadelha"
tags: ["security headers", "owasp", "saas"]
keyword: "security headers"
---

Security headers são instruções que o seu servidor envia junto com cada resposta HTTP dizendo ao navegador como se comportar: forçar HTTPS, recusar scripts de origens estranhas, impedir que sua página seja embutida num iframe alheio. São baratos de ligar, difíceis de errar de forma perigosa e quase sempre o primeiro item que falta num SaaS jovem. Não substituem código seguro — um header presente é um bom sinal, não um certificado de que você está protegido — mas representam uma camada de defesa na borda que cobre justamente a parte que você menos controla: o navegador do seu usuário.

Este guia cobre os headers que importam para um SaaS, com a sintaxe real de cada um, o que protege, o erro comum que se vê em produção e como conferir tudo isso no seu próprio site.

## Por que headers importam: defesa em profundidade na borda

A maior parte das proteções de uma aplicação web mora no backend: validação de input, autenticação, autorização. Mas várias classes de ataque acontecem dentro do navegador da vítima — XSS, clickjacking, MIME sniffing, downgrade de HTTPS. O servidor não roda lá. Os headers são o canal pelo qual você instrui o navegador a fechar essas portas.

Pense neles como camadas. Cada header sozinho cobre um caminho de ataque. Juntos, eles encarecem a vida de quem tenta. Nenhum deles conserta um bug de XSS no seu código — mas um bom Content-Security-Policy pode neutralizar a exploração desse bug antes que ele vire vazamento de sessão. Isso é defesa em profundidade: você assume que algo vai falhar e adiciona barreiras independentes.

A referência viva aqui é o projeto **OWASP Secure Headers**, que mantém recomendações práticas por header, e a documentação da **MDN** para a semântica de cada um. Os comportamentos abaixo são definidos em RFCs e specs do W3C/WHATWG — não são opinião.

## HSTS — Strict-Transport-Security

**O que protege:** impede o downgrade de HTTPS para HTTP. Sem HSTS, na primeira visita o usuário pode ser interceptado num man-in-the-middle e empurrado para uma versão HTTP da sua aplicação. Com HSTS, o navegador memoriza que aquele domínio só fala HTTPS e recusa qualquer tentativa de HTTP por conta própria.

```http
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

- `max-age` é em segundos. `63072000` são dois anos — valor comum para produção. Comece menor (ex.: `300`) se estiver testando, depois aumente.
- `includeSubDomains` estende a regra a todos os subdomínios. Só ligue se **todos** eles realmente servem HTTPS.
- `preload` sinaliza que você quer entrar na lista de preload embutida nos navegadores (HSTS aplicado já na primeira visita, antes mesmo de ver o header). Exige submissão à lista oficial de HSTS preload e que você atenda os requisitos dela.

**Erro comum:** colocar `preload` ou `includeSubDomains` antes de ter certeza de que tudo serve HTTPS. Preload é difícil de reverter — a remoção da lista leva tempo e enquanto isso um subdomínio só-HTTP fica inacessível. Ligue HSTS sem preload primeiro, valide, depois evolua.

## Content-Security-Policy (CSP) — o mais poderoso e o mais trabalhoso

**O que protege:** controla de quais origens o navegador pode carregar scripts, estilos, imagens, fontes, frames. É a defesa mais forte contra XSS: mesmo que um atacante injete `<script>`, o CSP pode impedir o navegador de executá-lo. Também é o mecanismo correto para controlar quem pode embutir sua página (via `frame-ancestors`).

Vou ser honesto: CSP é o header que mais dá trabalho. Uma policy restritiva quebra coisas — inline scripts, libs de terceiros, widgets de analytics. Acertar exige inventariar tudo que sua página carrega e, em geral, refatorar `onclick=` inline e `<script>` embutido. Não é um header de "ligar e esquecer".

Um ponto de partida razoável, que você endurece com o tempo:

```http
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self'
```

- `default-src 'self'` é o fallback: por padrão, só carrega do próprio domínio.
- `script-src 'self'` restringe scripts à sua origem. Para inline scripts legítimos, o caminho seguro é usar **nonce** (`script-src 'self' 'nonce-<valor-aleatório-por-request>'`) em vez de cair em `'unsafe-inline'`.
- `object-src 'none'` mata plugins legados.
- `base-uri 'self'` impede que um `<base>` injetado sequestre URLs relativas.

Antes de aplicar em modo bloqueio, rode em modo relatório com `Content-Security-Policy-Report-Only`. O navegador não bloqueia nada, só reporta o que **teria** bloqueado — assim você descobre o que sua policy quebra sem derrubar a aplicação.

**Erro comum:** liberar `'unsafe-inline'` no `script-src` para "fazer funcionar". Isso esvazia quase toda a proteção contra XSS, que é justamente o motivo de existir o CSP. Se precisa de inline, use nonce ou hash.

## X-Content-Type-Options: nosniff

**O que protege:** impede o MIME sniffing. Sem ele, alguns navegadores tentam adivinhar o tipo de um recurso ignorando o `Content-Type` que você enviou — e podem acabar executando como script algo que era pra ser um upload de "imagem". `nosniff` manda o navegador respeitar o `Content-Type` declarado.

```http
X-Content-Type-Options: nosniff
```

Não tem variação: ou está, ou não está. É um dos headers de menor custo e menor risco — não há motivo para um SaaS não ter.

**Erro comum:** servir o `Content-Type` errado e ligar `nosniff` ao mesmo tempo, quebrando recursos legítimos. A solução não é tirar o `nosniff` — é corrigir o `Content-Type` na origem.

## X-Frame-Options vs frame-ancestors do CSP

**O que protege:** clickjacking — quando um atacante embute sua página num iframe transparente sobre uma isca, e o usuário clica em algo seu sem perceber. A proteção é controlar quem pode te embutir.

Existem dois mecanismos. O antigo:

```http
X-Frame-Options: DENY
```

(`DENY` proíbe qualquer embedding; `SAMEORIGIN` permite só a própria origem.)

E o moderno, dentro do CSP:

```http
Content-Security-Policy: frame-ancestors 'self'
```

`frame-ancestors` é mais expressivo (aceita lista de origens permitidas) e é o caminho recomendado hoje. `X-Frame-Options` continua útil como compatibilidade para clientes antigos. Servir os dois é seguro e comum — onde houver conflito, navegadores modernos dão prioridade ao `frame-ancestors`.

**Erro comum:** usar `X-Frame-Options: ALLOW-FROM https://parceiro.com`. Esse valor foi descontinuado e é inconsistente entre navegadores. Se você precisa permitir um embedder específico, use `frame-ancestors` no CSP.

## Referrer-Policy

**O que protege:** evita o vazamento de informação no header `Referer` que o navegador envia ao navegar para outro site. URLs internas do seu SaaS muitas vezes carregam dados sensíveis (IDs, tokens em query string — o que já é um problema à parte); a Referrer-Policy controla quanto disso vaza para terceiros.

```http
Referrer-Policy: strict-origin-when-cross-origin
```

Esse valor envia a URL completa em navegações dentro da mesma origem, só a origem (sem path) ao cruzar para outra origem em HTTPS, e nada num downgrade para HTTP. É um equilíbrio sensato e já é o padrão de vários navegadores — declarar explicitamente garante o comportamento. Se quer ser mais rígido, `no-referrer` não envia nada.

**Erro comum:** confiar que o padrão do navegador basta e não declarar nada — o que deixa o comportamento variável entre clientes. Declare.

## Permissions-Policy

**O que protege:** controla quais APIs do navegador (câmera, microfone, geolocalização, etc.) a sua página — e os iframes dentro dela — podem usar. Reduz a superfície de abuso caso um script de terceiros ou uma injeção tente acessar hardware do usuário.

```http
Permissions-Policy: geolocation=(), camera=(), microphone=()
```

A lista vazia `()` desativa o recurso para todos. Para permitir só a própria origem: `geolocation=(self)`. Liste apenas o que sua aplicação realmente usa e desligue o resto.

**Erro comum:** confundir com o antigo `Feature-Policy` (sintaxe diferente, já obsoleta) ou desativar um recurso que sua própria aplicação precisa — teste depois de ligar.

## Cuidado com CORS permissivo

CORS não é exatamente um header de segurança defensivo — é um mecanismo de relaxamento controlado da same-origin policy. O perigo é relaxar demais:

```http
Access-Control-Allow-Origin: *
```

Esse `*` diz "qualquer site pode ler as respostas desta API pelo navegador". Numa API pública sem dados sensíveis, pode ser aceitável. Numa API autenticada, é um problema — especialmente combinado com `Access-Control-Allow-Credentials: true` (combinação que os navegadores aliás recusam, mas que sinaliza a intenção errada). O correto é refletir explicitamente apenas as origens que você confia.

**Erro comum:** copiar `Access-Control-Allow-Origin: *` de um tutorial para "resolver o erro de CORS" e deixar assim em produção numa API que serve dados de conta.

## Tabela resumo

| Header | Protege contra | Valor recomendado |
|---|---|---|
| `Strict-Transport-Security` | Downgrade de HTTPS / MITM | `max-age=63072000; includeSubDomains` |
| `Content-Security-Policy` | XSS, injeção, clickjacking | `default-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self'` |
| `X-Content-Type-Options` | MIME sniffing | `nosniff` |
| `X-Frame-Options` | Clickjacking (clientes antigos) | `DENY` ou `SAMEORIGIN` |
| `Referrer-Policy` | Vazamento de URL no Referer | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | Abuso de APIs do navegador | `geolocation=(), camera=(), microphone=()` |
| `Access-Control-Allow-Origin` | Exposição de API via CORS | Origens explícitas (nunca `*` em API autenticada) |

Use a tabela como checklist, não como cópia cega — `frame-ancestors` e CSP em geral exigem ajuste ao que sua aplicação realmente carrega.

## Como conferir os headers do seu site

A forma mais rápida, sem ferramenta nenhuma, é o `curl`. O `-I` faz uma requisição `HEAD` e mostra só os headers de resposta:

```bash
curl -I https://seu-saas.com.br
```

Procure na saída pelas linhas `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options` e companhia. O que não aparecer, não está configurado. Para inspecionar uma rota específica (por exemplo, depois do login, atrás de um proxy), repita o `curl -I` na URL exata — headers podem variar por rota se a configuração não for global.

O `curl` te diz o que está presente. Ele não te diz se o valor está fraco — um `max-age` de HSTS pequeno demais, um CSP com `'unsafe-inline'`, um CORS aberto demais passam batido numa leitura rápida.

É aí que entra o **Fracta**. Ele é um scanner web passivo e gratuito: você cola a URL e ele lê os security headers, o TLS, as flags de cookie e sinais de LGPD usando só requisições públicas — sem ataque ativo, sem login, sem cadastro. A detecção é determinística (regras, não palpite de IA), e você recebe uma nota de A a F na hora, explicando header por header o que está bom e o que está faltando. É open-source e operado pela PreviusIA.

Repetindo o que vale repetir: um header presente é um bom sinal, não uma garantia de que você está seguro. CSP mal configurado ainda passa; código vulnerável continua vulnerável. Mas um SaaS com a maioria desses headers no lugar já fechou os caminhos de ataque mais baratos e mais comuns — e isso é exatamente o trabalho que a borda deveria fazer.

Quer ver onde o seu site está agora? **Analise seu site grátis em [fracta.pro](https://fracta.pro)** e receba a nota A–F em segundos.
