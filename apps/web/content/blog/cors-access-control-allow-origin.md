---
title: "CORS mal configurado: o perigo do Access-Control-Allow-Origin: * (e como acertar)"
description: "CORS mal configurado expõe dados autenticados. Entenda Access-Control-Allow-Origin: *, o eco de Origin e a combinação proibida com credenciais — e como acertar."
slug: "cors-access-control-allow-origin"
date: "2026-06-30"
updated: "2026-06-30"
author: "Anderson Gadelha"
tags: ["cors", "api", "security headers"]
keyword: "cors access-control-allow-origin"
---

Quase todo dev já bateu de frente com um erro de CORS no console e resolveu da forma mais rápida que o Stack Overflow ofereceu: jogou um `Access-Control-Allow-Origin: *` na API e seguiu a vida. O erro sumiu. O problema é que, dependendo do que essa API serve, você acabou de autorizar qualquer site do mundo a ler as respostas dela em nome dos seus usuários logados.

CORS é uma das configurações de segurança mais incompreendidas justamente porque ela aparece como um obstáculo no desenvolvimento — algo que "atrapalha" e que você quer calar. Mas o CORS não é o inimigo: ele é o mecanismo que decide **quem pode ler as respostas da sua API a partir do navegador de outra pessoa**. Configurá-lo no modo "libera geral" numa API com sessão é abrir a porta que a same-origin policy existia para fechar.

## O que CORS é — e o que não é

Primeiro, o que **não** é: CORS não é firewall, não é autenticação e não impede ninguém de chamar sua API com `curl` ou Postman. Ele não protege o servidor.

O que ele é: o **Cross-Origin Resource Sharing** é a forma de um servidor **relaxar** a *same-origin policy* do navegador. Por padrão, o JavaScript rodando em `site-a.com` não consegue ler a resposta de uma requisição feita para `api.site-b.com` — o navegador busca, mas esconde a resposta do script. O CORS é o servidor de `api.site-b.com` dizendo ao navegador "pode deixar `site-a.com` ler isto aqui". Ou seja: **CORS afrouxa uma proteção que já existe**. Quanto mais você afrouxa, mais sites podem ler suas respostas no contexto autenticado do usuário.

## Como o fluxo funciona

Para requisições "simples" (GET/POST básicos), o navegador manda a requisição com um header `Origin: https://site-a.com` e olha a resposta: se vier um `Access-Control-Allow-Origin` que combina, libera o script a ler; senão, bloqueia.

Para requisições "não simples" (com `Authorization`, `Content-Type: application/json`, métodos como PUT/DELETE), o navegador faz antes um **preflight**: um `OPTIONS` perguntando "posso fazer essa requisição?". O servidor responde com `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`. Só se o preflight aprovar a requisição real acontece.

A peça crítica de segurança aparece quando entram **credenciais** (cookies, ou `fetch` com `credentials: 'include'`). É aí que a configuração errada vira vazamento.

## O perigo nº 1: `Access-Control-Allow-Origin: *` com dados autenticados

`Access-Control-Allow-Origin: *` significa "qualquer origem pode ler minhas respostas". Para uma API **pública e sem credenciais** — um endpoint de cotação, um catálogo aberto — isso é aceitável. O problema é usar `*` numa API que devolve dados do usuário logado com base em **cookie de sessão**.

Cenário concreto: sua API em `api.seusaas.com` responde `GET /me` com os dados do usuário autenticado por cookie, e você setou `Access-Control-Allow-Origin: *`. Um site malicioso que a vítima visita logada faz `fetch('https://api.seusaas.com/me')` — o navegador anexa o cookie, a API responde, e o `*` autoriza o script do site malicioso a **ler** a resposta. Dados pessoais vazados via navegador da própria vítima.

A spec do CORS tenta te proteger desse caso específico com uma regra dura:

## A combinação proibida: `*` + credenciais

A especificação **proíbe** combinar `Access-Control-Allow-Origin: *` com `Access-Control-Allow-Credentials: true`. Se você tentar, o navegador rejeita a requisição com credenciais. Foi uma decisão de design para evitar exatamente o vazamento acima.

O perigo é a "solução" que os devs inventam para contornar essa proibição:

## O anti-padrão real: refletir o Origin sem validar

Como `*` não funciona com credenciais, muita gente faz o servidor **ecoar de volta** o header `Origin` recebido:

```js
// PERIGOSO — reflete qualquer origem
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin)   // ⚠️
  res.setHeader('Access-Control-Allow-Credentials', 'true')          // ⚠️
  next()
})
```

Isso parece resolver: cada site recebe seu próprio `Allow-Origin` e as credenciais passam. Mas o efeito é **pior que o `*`**: agora **qualquer** origem é refletida e aprovada **com credenciais**. O site malicioso manda `Origin: https://malicioso.com`, o servidor devolve `Access-Control-Allow-Origin: https://malicioso.com` + `Allow-Credentials: true`, e o ataque que a spec tentou impedir volta a funcionar — com cookies. Refletir o Origin sem checar contra uma allowlist é o equivalente a `*` com credenciais, feito à mão.

## Como acertar: allowlist explícita

A configuração correta valida o `Origin` recebido contra uma **lista fechada** de origens confiáveis e só então responde:

```js
// Express + cors: allowlist explícita
import cors from 'cors'

const allowlist = ['https://app.seusaas.com', 'https://www.seusaas.com']

app.use(cors({
  origin(origin, callback) {
    // origin undefined = same-origin / curl: libere se quiser
    if (!origin || allowlist.includes(origin)) return callback(null, true)
    return callback(new Error('Origin não permitida'))
  },
  credentials: true,
}))
```

Manualmente, o mesmo princípio:

```js
const ALLOW = new Set(['https://app.seusaas.com'])
app.use((req, res, next) => {
  const origin = req.headers.origin
  if (origin && ALLOW.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin)
    res.setHeader('Access-Control-Allow-Credentials', 'true')
    res.setHeader('Vary', 'Origin')   // não deixe o cache servir o Allow-Origin errado
  }
  next()
})
```

Dois detalhes que faltam na maioria das implementações:

- **`Vary: Origin`** — quando você devolve um `Allow-Origin` diferente por origem, precisa dizer aos caches (CDN, navegador) que a resposta varia conforme o `Origin`. Sem isso, um cache pode servir a resposta com o `Allow-Origin` de outra origem.
- **Cuidado com `null`** — a origem `null` aparece em sandboxes de iframe, arquivos locais e alguns redirects. Nunca a inclua na allowlist; tratá-la como confiável reabre a porta.

## Qual `Access-Control-Allow-Origin` usar em cada cenário

| Cenário | Resposta correta |
| --- | --- |
| API pública, **sem** cookie/credencial | `Access-Control-Allow-Origin: *` é aceitável |
| API com sessão/cookie (dados do usuário) | Allowlist de origens + `Allow-Credentials: true` + `Vary: Origin` |
| SPA própria consumindo a própria API | Allowlist com o domínio do app (não `*`) |
| Reflexo automático do `Origin` recebido | **Nunca** — equivale a `*` com credenciais |
| Origem `null` | Nunca autorizar |

## Como inspecionar o seu CORS

Simule uma origem qualquer e veja como o servidor responde:

```bash
curl -sI https://api.seusaas.com/me -H 'Origin: https://malicioso.com' | grep -i access-control
```

Se a resposta refletir `Access-Control-Allow-Origin: https://malicioso.com` (ou trouxer `*` junto de `Allow-Credentials: true`), você tem um CORS perigoso. O ideal é não ver nenhum `Allow-Origin` para uma origem que não está na sua lista.

Para um diagnóstico rápido e sem cadastro da configuração de CORS e dos demais security headers do seu site, rode o **[Fracta](https://fracta.pro)** — scanner web passivo grátis. Ele examina os headers que o seu domínio entrega, sinaliza CORS permissivo e o que mais estiver fraco, e devolve uma nota A–F na hora, com detecção determinística (regra, não palpite de IA).

**[Cheque seu CORS grátis em fracta.pro](https://fracta.pro)** e descubra, em segundos, se a sua API está dizendo "sim" para sites que deveria recusar.
