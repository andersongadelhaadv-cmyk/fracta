---
title: "Banner de cookies que cumpre a LGPD (e por que o seu provavelmente não cumpre)"
description: "Por que a maioria dos banner de cookies não cumpre a LGPD: consentimento livre, bloqueio prévio, revogação e um checklist prático para corrigir."
slug: "banner-de-cookies-lgpd"
date: "2026-06-30"
updated: "2026-06-30"
author: "Anderson Gadelha"
tags: ["lgpd", "cookies", "consentimento"]
keyword: "banner de cookies lgpd"
---

Quase todo SaaS brasileiro tem hoje um banner de cookies. E quase todo banner de cookies brasileiro está errado. Não por má-fé — na maioria das vezes o time instalou um plugin pronto, marcou a tarefa como concluída e seguiu em frente. O problema é que esse banner foi desenhado para *parecer* conforme, não para *ser* conforme. Ele tranquiliza o jurídico, mas não protege a empresa, porque ignora o que a LGPD efetivamente exige do consentimento.

Este artigo é direto: vou mostrar a diferença entre o cookie que precisa de consentimento e o que não precisa, por que o requisito legal de consentimento "livre, informado, inequívoco e específico" derruba a maioria dos banners decorativos, e qual é o erro técnico número um — os scripts de rastreamento que carregam *antes* de o usuário clicar em "aceitar". No fim, um checklist prático para você comparar o seu banner com um banner que de fato cumpre a lei.

## Nem todo cookie precisa de consentimento

Primeiro, a parte que confunde muita gente: você **não** precisa pedir consentimento para todos os cookies. A LGPD não trata cookie como categoria única. O que importa é a **finalidade** do tratamento e a **base legal** que o sustenta (Art. 7º).

Existem, na prática, dois grandes grupos:

- **Cookies estritamente necessários (ou essenciais):** aqueles sem os quais o serviço simplesmente não funciona. Token de sessão, autenticação, carrinho de compras, balanceamento de carga, preferência de idioma escolhida pelo usuário, proteção contra fraude. Esses se apoiam em bases legais como execução de contrato ou legítimo interesse, e **não dependem de consentimento prévio**. Você os carrega porque sem eles não há serviço.

- **Cookies não-essenciais:** analytics, marketing, remarketing, pixels de rede social, mapas de calor, testes A/B comportamentais, publicidade direcionada. Eles existem para o *seu* benefício comercial, não para entregar a função que o usuário pediu. Para esses, a base mais segura — e na prática a esperada — é o **consentimento** (Art. 7º, I).

A linha divisória não é "cookie próprio vs. cookie de terceiro", nem "técnico vs. não-técnico". É: **o serviço quebra sem ele?** Se a resposta é não, presuma que precisa de consentimento. Google Analytics não é essencial. Meta Pixel não é essencial. Hotjar não é essencial. Por mais útil que sejam para o negócio.

## O consentimento da LGPD é exigente de propósito

Aqui está o coração do problema. Quando o cookie depende de consentimento, esse consentimento precisa cumprir o padrão do **Art. 8º**:

> Art. 8º O consentimento previsto no inciso I do art. 7º desta Lei deverá ser fornecido por escrito ou por outro meio que demonstre a manifestação de vontade do titular.

E o Art. 5º, XII, define o que é esse consentimento:

> XII - consentimento: manifestação livre, informada e inequívoca pela qual o titular concorda com o tratamento de seus dados pessoais para uma finalidade determinada.

Quatro qualidades, então, precisam coexistir. O consentimento tem que ser **livre**, **informado**, **inequívoco** e **específico** (para finalidade determinada). Parecem palavras de manual, mas cada uma derruba uma prática comum de banner:

- **Livre** derruba o *cookie wall* e o "ao continuar navegando você aceita". Se o usuário não tem escolha real — ou aceita, ou perde o acesso — a manifestação não é livre. Continuar navegando não é um ato de vontade dirigido a consentir; é só usar o site.
- **Informado** derruba o banner que diz "usamos cookies" e ponto. O titular precisa saber *quais* finalidades, *quais* terceiros recebem os dados, e como revogar.
- **Inequívoco** derruba a caixa pré-marcada e o consentimento "presumido". Tem que haver uma ação afirmativa e clara. Silêncio e inércia não são consentimento.
- **Específico** derruba o botão único "aceitar tudo" sem alternativa. Cada finalidade distinta (analytics, marketing) pede sua própria escolha — é a **granularidade por finalidade**.

Repare que o banner decorativo típico falha em todas as quatro. Ele informa pouco, não dá escolha real, presume aceitação e empacota tudo num botão só.

## O erro nº 1: o rastreador sobe antes do clique

Esse é o ponto técnico que praticamente ninguém audita, e é o mais grave. Você pode ter o banner mais bonito do mundo, com texto jurídico impecável, e ainda assim **esvaziar** o consentimento por um detalhe de implementação: os scripts de rastreamento disparam no carregamento da página, *antes* de o usuário tocar em qualquer botão.

Pense no que isso significa. O Google Analytics, o Meta Pixel, o tag manager — todos sobem junto com o HTML. Quando o banner aparece na tela pedindo consentimento, o rastreamento **já aconteceu**. Os dados já foram coletados e enviados a terceiros. O clique em "aceitar" vira teatro: ele não autoriza coisa nenhuma, só confirma o que já foi feito sem autorização.

Um consentimento que chega depois da coleta não é consentimento prévio — é, na melhor das hipóteses, uma ratificação tardia de um tratamento que já ocorreu sem base legal no momento em que ocorreu.

A correção técnica chama-se **bloqueio prévio** (ou *prior blocking*). Na prática: os scripts não-essenciais **não carregam** até existir consentimento. Eles ficam suspensos, em estado inerte, e só são injetados na página *depois* que o usuário escolhe ativamente aceitar aquela finalidade. Cookie essencial sobe normalmente; analytics e marketing ficam congelados atrás do consentimento.

A maioria dos plugins de banner não faz isso por padrão. Eles desenham a interface, mas deixam as tags soltas no `<head>`. Resultado: o banner é cosmético, e o rastreamento real ignora a vontade do usuário. Se você só conferir uma coisa deste artigo, confira esta — **o que sobe antes do clique no seu próprio site**.

## "Continuar navegando" e cookie wall: por que não valem

Vale isolar dois padrões porque são teimosos.

**"Ao continuar navegando, você aceita nossos cookies."** Isso transforma um ato neutro (rolar a página, clicar num link interno) em suposta manifestação de vontade. Mas rolar a página não é dirigir a vontade a consentir — falta o caráter **inequívoco** e a ação afirmativa. O usuário queria ler o conteúdo, não autorizar marketing. É consentimento presumido disfarçado.

**Cookie wall** — "aceite todos os cookies ou não entre". Aqui o problema é a liberdade. Se a única alternativa a consentir é ser barrado de um serviço que, de outra forma, estaria disponível, a escolha não é **livre**. O consentimento condicionado dessa forma fica viciado na origem.

## Aceitar não pode ser mais fácil que recusar

Esse é o ponto dos *dark patterns*, e é onde a liberdade do consentimento encontra o design. Se o banner tem um botão grande, colorido e óbvio escrito "Aceitar tudo", e a recusa está escondida atrás de "gerenciar preferências", em letra cinza, dois cliques abaixo — a arquitetura da tela está empurrando o usuário para o "sim".

Um banner que oferece **só "Aceitar"**, sem um "Rejeitar" no mesmo nível de visibilidade e esforço, é problemático. A simetria importa: **recusar tem que ser tão fácil quanto aceitar**. Mesmo destaque, mesma camada, mesmo número de cliques. Quando recusar custa mais que aceitar, a "liberdade" do consentimento vira ficção.

## Revogar tem que ser tão fácil quanto consentir

A LGPD não trata o consentimento como um clique definitivo. O titular pode mudar de ideia a qualquer momento — e o §5º do Art. 8º é explícito sobre isso:

> § 5º O consentimento pode ser revogado a qualquer momento mediante manifestação expressa do titular, por procedimento gratuito e facilitado.

Some-se a isso o **Art. 18**, que garante ao titular o direito de obter informação, correção e eliminação dos dados tratados com base no consentimento. Na prática, isso significa que o usuário que aceitou cookies de marketing semana passada precisa conseguir **desligá-los hoje** com a mesma facilidade com que os ligou — gratuitamente e sem fricção.

O teste é simples: se dar consentimento leva um clique, mas revogar exige mandar e-mail para o DPO e esperar resposta, você não tem "procedimento facilitado". O caminho prático é um link permanente e visível — no rodapé, num ícone fixo — que reabre as preferências de cookies a qualquer momento.

## Registro e prova: consentir não basta, tem que comprovar

Se um dia a empresa precisar demonstrar que obteve consentimento válido, ela vai precisar de **prova**. O ônus de demonstrar a base legal recai sobre quem trata os dados. Por isso, um banner sério **registra**: qual finalidade foi aceita ou recusada, quando, e qual versão do texto de consentimento estava no ar naquele momento.

Sem esse log, o "aceitar" do usuário é uma afirmação sem lastro. Com ele, você consegue mostrar — para a ANPD, para um titular, para um auditor — exatamente o que foi consentido e quando.

## O banner não vive sozinho: Política de Cookies e de Privacidade

O banner é a porta de entrada, não o documento. Ele precisa apontar para uma **Política de Cookies** (ou seção dedicada na Política de Privacidade) que liste, em linguagem acessível, cada cookie/rastreador, sua finalidade, o terceiro envolvido e o prazo de retenção. O "Informado" do Art. 8º se completa aí: o banner resume e dá a escolha; a política detalha. Um sem o outro não fecha o requisito.

## Checklist: banner que cumpre vs. banner decorativo

| Critério | Banner que cumpre a LGPD | Banner decorativo (não cumpre) |
| --- | --- | --- |
| Cookies não-essenciais | **Bloqueados** até o consentimento (prior blocking) | Carregam ao abrir a página, antes do clique |
| Base do "aceitar" | Ação afirmativa, inequívoca | "Continuar navegando" / caixa pré-marcada |
| Botão Rejeitar | Mesmo destaque e esforço do Aceitar | Ausente ou escondido em "preferências" |
| Granularidade | Escolha por finalidade (analytics, marketing) | Botão único "aceitar tudo" |
| Liberdade | Site funciona mesmo sem aceitar não-essenciais | Cookie wall: aceite ou saia |
| Revogação | Link permanente, 1 clique, gratuito (Art. 8º §5º) | Sem caminho claro / só por e-mail ao DPO |
| Registro de prova | Log de finalidade, data e versão do texto | Nenhum registro |
| Informação | Aponta para Política de Cookies detalhada | "Usamos cookies" e nada mais |

Se a sua coluna ficou na direita em três ou mais linhas, o banner é decorativo.

## Como implementar na prática

Sem fórmulas mágicas, mas com a sequência certa:

1. **Mapeie o que carrega.** Antes de escrever qualquer banner, descubra todos os rastreadores e cookies de terceiros que o site dispara hoje. Você não consegue bloquear o que não enxerga.
2. **Classifique por finalidade.** Separe essencial de não-essencial. Na dúvida, pergunte "o serviço quebra sem isso?". Se não quebra, é não-essencial.
3. **Implemente bloqueio prévio.** Não-essenciais ficam suspensos até o consentimento. Essa é a parte que a maioria pula.
4. **Desenhe simetria.** Aceitar e Rejeitar no mesmo nível. Granularidade por finalidade.
5. **Crie o caminho de revogação.** Link fixo que reabre as preferências.
6. **Registre.** Logue cada decisão com data e versão do texto.
7. **Conecte à Política de Cookies.** O detalhe mora lá.

## Comece descobrindo o que o seu site realmente carrega

O passo 1 costuma ser o ponto cego, e é onde o **Fracta** entra. O Fracta é um scanner web passivo e gratuito: ele abre o seu site, observa o que carrega e **lista os rastreadores de terceiros e os cookies não-essenciais** que entram em cena — sem cadastro, com nota A–F na hora.

Sendo honesto sobre o que a ferramenta faz: o Fracta sinaliza, de forma passiva, *quais* rastreadores e cookies não-essenciais o seu site dispara e *quando* eles aparecem. Isso ajuda a flagrar exatamente o erro nº 1 deste artigo — algo não-essencial subindo antes do consentimento. O que o Fracta **não** faz é julgar se o seu consentimento é juridicamente válido; essa análise é jurídica e depende do contexto. A ferramenta te dá o mapa; a leitura legal é sua (ou do seu advogado).

Ainda assim, o mapa é metade da batalha. A maioria das empresas se surpreende com a quantidade de coisa que sobe antes de qualquer clique.

**Veja os rastreadores do seu site de graça em [fracta.pro](https://fracta.pro)** — e descubra, em segundos, se o seu banner está protegendo a empresa ou só decorando a tela.
