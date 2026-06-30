---
title: "Como configurar Content-Security-Policy (CSP) no Next.js sem quebrar o app"
description: "Guia prático de Content-Security-Policy no Next.js: nonce por request no middleware, Report-Only, strict-dynamic e as diretivas que importam — com código real."
slug: "csp-next-js"
date: "2026-06-30"
updated: "2026-06-30"
author: "Anderson Gadelha"
tags: ["csp", "next.js", "security headers"]
keyword: "content-security-policy next.js"
---

A Content-Security-Policy é a header de segurança mais poderosa que você pode ligar — e a mais fácil de errar de um jeito que quebra o app em produção. Bem configurada, ela transforma um XSS de "o atacante executa qualquer script na sua página" em "o navegador recusa o script e nada acontece". Mal configurada, ela ou não protege nada (o caso do `unsafe-inline`) ou apaga metade da sua interface no primeiro deploy.

No Next.js o desafio é específico: o framework injeta scripts inline para hidratação e usa estilos inline em vários pontos, então uma CSP estrita batendo de frente com isso costuma quebrar. A boa notícia é que existe um caminho oficial e robusto — **nonce por requisição via middleware** — e uma forma de implantar sem susto: o modo **Report-Only**. Este guia mostra os dois, com código real.

## O que a CSP resolve (e o que a esvazia)

A CSP é uma lista de regras que o servidor manda no header dizendo ao navegador **de onde** ele pode carregar e executar cada tipo de recurso: scripts, estilos, imagens, fontes, conexões. Se um script injetado por um atacante não bate com a política, o navegador simplesmente não o executa. É a diferença entre conter um XSS e sofrer um.

O erro que anula tudo é o `'unsafe-inline'` em `script-src`. Ele autoriza qualquer `<script>` inline — inclusive o que o atacante injetou. Uma CSP com `script-src 'self' 'unsafe-inline'` dá uma falsa sensação de proteção: o header existe, o scanner vê "CSP presente", mas contra XSS ela não vale quase nada. O mesmo vale para `'unsafe-eval'`, que reabre `eval()` e amigos.

O objetivo, então, é uma CSP **sem `unsafe-inline` em scripts**. E é aí que entra o nonce.

## Por que o Next.js complica

O Next.js precisa rodar scripts inline para a hidratação (o bootstrap do React no cliente). Se você proibir todo script inline, a página quebra. As duas saídas honestas são:

- **Nonce por request:** o servidor gera um número aleatório único a cada requisição, marca os scripts confiáveis com ele e autoriza apenas scripts que carreguem esse nonce. O Next.js, a partir das versões recentes do App Router, propaga automaticamente o nonce do header para os seus próprios scripts.
- **Hash:** você lista o hash SHA de cada script inline estático. Funciona para sites estáticos, mas é frágil com conteúdo dinâmico. Para a maioria dos apps Next, o nonce é o caminho.

## A solução robusta: nonce por request no middleware

O `middleware.ts` roda antes de cada requisição — é o lugar certo para gerar o nonce e montar a CSP. Exemplo completo:

```ts
// middleware.ts
import { NextRequest, NextResponse } from 'next/server'

export function middleware(request: NextRequest) {
  // nonce aleatório por request (base64 de 16 bytes)
  const nonce = Buffer.from(crypto.randomUUID()).toString('base64')

  const csp = [
    `default-src 'self'`,
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,
    `style-src 'self' 'nonce-${nonce}'`,
    `img-src 'self' blob: data:`,
    `font-src 'self'`,
    `connect-src 'self'`,
    `frame-ancestors 'none'`,
    `base-uri 'self'`,
    `form-action 'self'`,
    `object-src 'none'`,
    `upgrade-insecure-requests`,
  ].join('; ')

  // repassa o nonce adiante para os componentes server lerem
  const requestHeaders = new Headers(request.headers)
  requestHeaders.set('x-nonce', nonce)
  requestHeaders.set('content-security-policy', csp)

  const response = NextResponse.next({ request: { headers: requestHeaders } })
  response.headers.set('content-security-policy', csp)
  return response
}

// roda em todas as rotas, menos assets estáticos e a API
export const config = {
  matcher: [
    { source: '/((?!api|_next/static|_next/image|favicon.ico).*)' },
  ],
}
```

Para aplicar o nonce a um script seu, leia-o do header no Server Component:

```tsx
// app/layout.tsx (trecho)
import { headers } from 'next/headers'
import Script from 'next/script'

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const nonce = headers().get('x-nonce') ?? undefined
  return (
    <html lang="pt-BR">
      <body>
        {children}
        <Script src="https://exemplo.com/analytics.js" nonce={nonce} strategy="afterInteractive" />
      </body>
    </html>
  )
}
```

O `'strict-dynamic'` é o que faz o nonce escalar: ele diz que um script já confiado (porque carrega o nonce) pode carregar outros scripts, sem você ter que listar cada domínio em `script-src`. É a forma moderna recomendada — você confia na cadeia a partir do nonce, não numa allowlist de hosts que envelhece mal.

## Alternativa simples: CSP estática no next.config

Se o seu app não tem scripts inline próprios e você não precisa de nonce, dá para declarar uma CSP estática direto no `next.config.js`:

```js
// next.config.js
const csp = "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; object-src 'none'"

module.exports = {
  async headers() {
    return [{
      source: '/:path*',
      headers: [{ key: 'Content-Security-Policy', value: csp }],
    }]
  },
}
```

É mais simples, mas estático: vale para casos sem inline dinâmico. Na dúvida entre estática-com-`unsafe-inline` e nonce, escolha o nonce — a estática com `unsafe-inline` é justamente a que não protege.

## As diretivas que importam

| Diretiva | Para que serve | Valor seguro comum |
| --- | --- | --- |
| `default-src` | Fallback de todas as outras | `'self'` |
| `script-src` | De onde scripts podem rodar | `'self' 'nonce-…' 'strict-dynamic'` |
| `style-src` | Folhas de estilo | `'self' 'nonce-…'` |
| `img-src` | Imagens | `'self' data: blob:` |
| `connect-src` | fetch/XHR/WebSocket | `'self'` + APIs que você usa |
| `font-src` | Fontes | `'self'` |
| `frame-ancestors` | Quem pode te embutir em iframe | `'none'` (substitui X-Frame-Options) |
| `base-uri` | Restringe a tag `<base>` | `'self'` |
| `form-action` | Para onde forms podem postar | `'self'` |
| `object-src` | `<object>`/`<embed>` (legado) | `'none'` |

`frame-ancestors 'none'` é o equivalente moderno e mais forte do `X-Frame-Options: DENY` — protege contra clickjacking e é respeitado por navegadores atuais.

## Implante sem quebrar: Report-Only primeiro

A jogada que evita derrubar a interface: rode a política em **modo de relatório** antes de impor. Em vez de `Content-Security-Policy`, mande `Content-Security-Policy-Report-Only` com o mesmo valor. O navegador **não bloqueia nada** — só registra (e, se você configurar `report-to`/`report-uri`, envia) cada violação que a política causaria.

Você roda assim por alguns dias, observa o que quebraria (um CDN de fonte esquecido, um script de terceiro, um estilo inline), ajusta a política, e só então troca o header para o modo de imposição. Em produção real, pular essa etapa é a causa nº 1 de "liguei CSP e o app quebrou".

> Regra de ouro: **Report-Only em produção → coletar violações → ajustar → impor.** Nunca empurre uma CSP estrita direto para enforcement sem ter visto os relatórios.

## Erros comuns

- **`'unsafe-inline'` em `script-src`** — anula a proteção contra XSS. Se está aí, sua CSP é decorativa.
- **Esquecer `connect-src`** — o app funciona, mas as chamadas de API/telemetria falham silenciosamente. Liste seus endpoints.
- **`base-uri` ausente** — permite que um atacante sequestre URLs relativas via tag `<base>` injetada. Sempre `base-uri 'self'`.
- **Nonce reutilizado** — o nonce precisa ser único **por request**. Gerar uma vez e cachear o destrói. Por isso ele nasce no middleware, não numa constante.

## Confira o seu CSP no ar

Depois de implantar, verifique o header como ele chega ao navegador:

```bash
curl -sI https://seusaas.com.br | grep -i content-security-policy
```

Se o valor tiver `unsafe-inline` em `script-src`, ou se não houver header nenhum, você ainda está exposto. Para um diagnóstico rápido e sem cadastro do CSP e dos demais security headers do seu site, rode o **[Fracta](https://fracta.pro)** — scanner web passivo grátis: ele lê os headers que o seu domínio entrega, aponta o que falta e o que está fraco, e devolve uma nota A–F na hora, com detecção determinística (regra, não palpite).

**[Analise seu site grátis em fracta.pro](https://fracta.pro)** e veja em segundos se o seu Content-Security-Policy realmente protege — ou se só está lá para constar.
