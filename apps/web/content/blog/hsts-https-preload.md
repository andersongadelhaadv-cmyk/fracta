---
title: "HSTS: o header que força HTTPS — e o erro de preload que pode te derrubar"
description: "Como o HSTS força HTTPS e fecha a brecha do SSL stripping — e por que o preload é uma armadilha difícil de reverter se você ativar cedo demais."
slug: "hsts-https-preload"
date: "2026-06-30"
updated: "2026-06-30"
author: "Anderson Gadelha"
tags: ["hsts", "https", "tls"]
keyword: "hsts preload"
---

Você instalou o certificado, configurou o redirect de `http://` para `https://` e marcou HTTPS como resolvido. Na maioria dos dias, está. Mas existe uma janela — o primeiríssimo acesso de um usuário ao seu domínio — em que o navegador ainda fala HTTP em texto puro antes de aprender que deveria usar HTTPS. É nessa janela que mora o ataque de **SSL stripping**. O **HSTS** existe para fechá-la, e o **HSTS preload** existe para fechá-la por completo. O problema: o preload é uma decisão quase irreversível, e ativá-lo no momento errado derruba subdomínios que você nem lembrava que existiam.

Este artigo explica o que cada peça faz, qual é a armadilha real e qual é o caminho de rollout que não te queima.

## O problema: o primeiro acesso é HTTP

Pense no que acontece quando alguém digita `seuapp.com` na barra de endereços. Sem nenhum esquema declarado, o navegador assume `http://`. Ele faz uma requisição em texto puro. Seu servidor responde com um `301` para `https://`, e a partir daí tudo é criptografado. Funciona — mas aquela primeira requisição saiu desprotegida.

Um atacante posicionado na rede (Wi-Fi público, rede corporativa comprometida, ISP malicioso) intercepta esse `http://` inicial. Em vez de deixar o redirect chegar ao usuário, ele **mantém a conexão em HTTP** com a vítima e fala HTTPS com o servidor real, atuando como intermediário. A vítima nunca vê o cadeado, mas tudo parece normal. Senhas, cookies de sessão, tokens — tudo trafega em claro para o atacante. Esse é o SSL stripping, descrito por Moxie Marlinspike lá em 2009 e ainda perfeitamente viável hoje em qualquer rede hostil.

O redirect `http → https` no servidor **não resolve isso**, porque ele depende da requisição HTTP chegar ao servidor. Se o atacante está no meio, o redirect nunca acontece para a vítima.

## A solução: Strict-Transport-Security

O HSTS (HTTP Strict Transport Security, definido na **RFC 6797**) é um header de resposta que instrui o navegador: *"a partir de agora, para este domínio, use HTTPS sempre — nem tente HTTP."*

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

Uma vez que o navegador vê esse header numa conexão HTTPS válida, ele passa a reescrever qualquer tentativa de `http://seuapp.com` para `https://seuapp.com` **internamente, antes de a requisição sair da máquina**. Não há mais primeiro acesso em texto puro nas visitas seguintes. O redirect deixa de ser uma sugestão do servidor e vira uma regra forçada pelo cliente.

### O que cada diretiva faz

- **`max-age=<segundos>`** — por quanto tempo o navegador lembra dessa regra. `31536000` são 365 dias. Durante esse período, toda requisição ao domínio é forçada para HTTPS. O contador reinicia a cada visita em que o header é servido de novo.
- **`includeSubDomains`** — estende a regra para **todos** os subdomínios: `api.seuapp.com`, `app.seuapp.com`, `blog.seuapp.com`, `interno.seuapp.com` e qualquer outro. Esta é a diretiva que parece inofensiva e não é. Guarde isso.
- **`preload`** — sinaliza que você quer entrar na **lista de preload do HSTS**, embarcada diretamente no código dos navegadores. Não é um efeito do header sozinho; é uma intenção que você ainda precisa submeter em `hstspreload.org`.

## Trust on first use — e por que o preload existe

Repare numa brecha residual: o HSTS só age **depois** que o navegador viu o header pelo menos uma vez. O primeiro acesso de um navegador que nunca esteve no seu site continua sendo HTTP. É o problema do *trust on first use* (TOFU): a proteção depende de um encontro anterior, limpo, com o servidor. Cliente novo, máquina nova, navegador recém-instalado, modo anônimo — todos começam vulneráveis na primeira requisição.

A **lista de preload** fecha essa janela. Domínios na lista vêm com a regra HSTS **já embutida no navegador**, antes de qualquer requisição. Chrome, Firefox, Safari e Edge baixam essa lista (mantida pelo projeto Chromium e compartilhada entre os browsers). Para um domínio preloaded, o navegador **nunca** fala HTTP, nem no primeiríssimo acesso. O TOFU desaparece.

Soa perfeito. E é exatamente por ser tão definitivo que ele é perigoso.

## A armadilha do preload

> Entrar na lista de preload é rápido. **Sair é lento e doloroso.** Você submete em `hstspreload.org`, mas o efeito real depende do ciclo de release dos navegadores — a remoção é processada e propagada ao longo de **semanas a meses**, e usuários com versões antigas do browser continuam forçando HTTPS no seu domínio até atualizarem. Não existe botão de rollback instantâneo. Trate o preload como um caminho de mão única.

O cenário que derruba gente de verdade é a combinação `includeSubDomains` **mais** `preload` ativada antes de **100% dos seus subdomínios** estarem servindo HTTPS com certificado válido.

Lembre que `includeSubDomains` força HTTPS em *todos* os subdomínios. Com o preload, essa força fica embutida no navegador. Agora suponha que existam:

- `legado.seuapp.com` — um sistema antigo só em HTTP, que ninguém migrou.
- `interno.seuapp.com` — ferramenta interna sem certificado.
- `staging.seuapp.com` — ambiente com certificado autoassinado.

No segundo em que seu domínio raiz entra na lista de preload com `includeSubDomains`, **todos esses subdomínios param de abrir** para qualquer pessoa com um navegador atualizado. Não é um aviso, não é um cadeado quebrado — é o navegador se **recusando** a conectar via HTTP e não encontrando HTTPS válido do outro lado. Conexão recusada. E você não consegue reverter rápido, porque está na lista de preload.

É a diferença entre um erro que você corrige numa configuração de servidor em cinco minutos e um erro que fica embutido na versão do Chrome do seu cliente por semanas.

## O caminho seguro de rollout

A regra é simples: **aumente o compromisso aos poucos e nunca pule etapas.** Comece com um `max-age` curto, que é trivial de reverter (basta esperar o tempo passar), e só escale quando tiver certeza.

```http
# Etapa 1 — teste com janela curta (5 minutos)
Strict-Transport-Security: max-age=300

# Etapa 4 — produção, com subdomínios cobertos
Strict-Transport-Security: max-age=31536000; includeSubDomains

# Etapa 5 — só quando 100% em HTTPS: o compromisso final
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

| Etapa | Header | `max-age` | O que validar antes de avançar |
|---|---|---|---|
| 1 | `max-age=300` | 5 min | Site abre normal em HTTPS; nada quebrou no domínio raiz. |
| 2 | `max-age=86400` | 1 dia | Sem reclamações; redirect HTTP→HTTPS consistente em todas as rotas. |
| 3 | `max-age=31536000` | 1 ano | Domínio raiz estável por dias. Ainda **sem** `includeSubDomains`. |
| 4 | `+ includeSubDomains` | 1 ano | **Inventário completo de subdomínios**, todos com HTTPS e cert válido. |
| 5 | `+ preload` (`max-age=63072000`) | 2 anos | Tudo acima confirmado e estável. Submeter em `hstspreload.org`. |

Dois pontos não negociáveis na etapa 5:

1. **`max-age` mínimo de 1 ano para preload.** O `hstspreload.org` exige no mínimo `31536000` (1 ano) para aceitar a submissão. A recomendação prática é **`63072000` (2 anos)**, que é o valor que a maioria dos sites grandes usa.
2. **Inventário de subdomínios feito de verdade.** Antes de `includeSubDomains` + `preload`, liste *todo* registro DNS do seu domínio e confirme que cada host que responde está em HTTPS válido. O subdomínio esquecido é o que te derruba.

E a etapa que quase todo mundo pula: **redirecionar a raiz para HTTPS na porta 443 e servir o header lá.** O `hstspreload.org` exige que `http://seudominio` redirecione para `https://seudominio` (mesmo host, antes de qualquer redirect para `www`), e que o header de preload esteja presente nessa resposta HTTPS da raiz.

## Como verificar o HSTS do seu site

Antes de qualquer coisa, olhe o que você já está servindo. Com `curl`:

```bash
curl -sI https://seuapp.com | grep -i strict-transport-security
```

Se vier vazio, você não tem HSTS. Se vier algo como `strict-transport-security: max-age=31536000; includeSubDomains; preload`, leia com atenção: **você está com `preload` ligado de propósito, com inventário de subdomínios feito?** Se a resposta for "não sei", esse header é um risco, não uma proteção.

Para um diagnóstico completo — HSTS junto com os outros headers de segurança que importam (CSP, `X-Content-Type-Options`, `Referrer-Policy`, cookies) e uma leitura de exposição LGPD — passe seu domínio no scanner do **[Fracta](https://fracta.pro)**. É um scan passivo, gratuito, sem cadastro: ele lê o que seu servidor responde, te dá uma nota A–F na hora e aponta exatamente o que está faltando. Nada destrutivo, nada que toque na sua aplicação.

O HSTS é um dos headers mais valiosos que você pode servir e um dos mais fáceis de configurar errado em definitivo. Acerte o `max-age`, suba degrau por degrau, e só assine o compromisso do preload quando tiver certeza de que cada subdomínio seu está pronto para HTTPS — porque, depois dele, voltar atrás é caro.

**Cheque o HSTS do seu domínio agora, grátis, em [fracta.pro](https://fracta.pro).**
