---
title: "Política de Privacidade para SaaS: o que a LGPD exige de verdade"
description: "O que a política de privacidade LGPD precisa informar de verdade no seu SaaS: finalidade, base legal, direitos do titular e o canal do encarregado."
slug: "politica-de-privacidade-saas"
date: "2026-06-30"
updated: "2026-06-30"
author: "Anderson Gadelha"
tags: ["lgpd", "política de privacidade", "saas"]
keyword: "política de privacidade lgpd"
---

Quase todo SaaS brasileiro tem um link de "Política de Privacidade" no rodapé. Quase nenhum tem uma política que realmente descreve o que o produto faz com os dados das pessoas. Essa distância — entre ter o documento e o documento ser verdadeiro — é exatamente onde mora o risco de LGPD.

A política de privacidade não é burocracia de rodapé nem peça de marketing. Ela é o **principal instrumento de transparência** que a Lei 13.709/2018 exige de quem trata dados pessoais. É por meio dela que você cumpre, de forma escrita e acessível, o dever de informar o titular sobre o que faz, por quê, com quem compartilha e como ele pode reagir. Quando ela está errada, genérica ou copiada, o problema não é estético: é uma falha no cumprimento de um dever legal.

Este artigo é direto ao ponto: o que a LGPD realmente obriga a sua política a conter, artigo por artigo, e onde a maioria dos SaaS escorrega.

## Por que a política é a peça central de transparência

A LGPD elege a **transparência** como um dos princípios fundamentais do tratamento de dados.

> **Art. 6º** As atividades de tratamento de dados pessoais deverão observar a boa-fé e os seguintes princípios:
> [...] **VI - transparência:** garantia, aos titulares, de informações claras, precisas e facilmente acessíveis sobre a realização do tratamento e os respectivos agentes de tratamento, observados os segredos comercial e industrial;

Repare em três palavras: **claras, precisas e facilmente acessíveis**. Uma política escondida, escrita em juridiquês ou que não bate com a realidade do produto viola esse princípio mesmo que exista. Transparência não é "ter um PDF"; é a pessoa conseguir entender, de fato, o que acontece com os dados dela.

E a política é o veículo natural desse princípio porque é nela que se concentra o conjunto de informações que o titular tem **direito de receber**, listado no Art. 9º. Não é opcional, não é "boa prática": é o conteúdo mínimo que a lei manda comunicar.

## O que a política OBRIGATORIAMENTE precisa informar (Art. 9º)

O Art. 9º é o coração do dever de informar. Ele diz que o titular tem direito ao **acesso facilitado** às informações sobre o tratamento dos seus dados, que devem ser disponibilizadas de forma clara, adequada e ostensiva. E lista o que precisa constar:

> **Art. 9º** O titular tem direito ao acesso facilitado às informações sobre o tratamento de seus dados, que deverão ser disponibilizadas de forma clara, adequada e ostensiva acerca de, entre outras características previstas em regulamentação para o atendimento do princípio do livre acesso:
> **I -** finalidade específica do tratamento;
> **II -** forma e duração do tratamento, observados os segredos comercial e industrial;
> **III -** identificação do controlador;
> **IV -** informações de contato do controlador;
> **V -** informações acerca do uso compartilhado de dados pelo controlador e a finalidade;
> **VI -** responsabilidades dos agentes que realizarão o tratamento; e
> **VII -** direitos do titular, com menção explícita aos direitos contidos no art. 18 desta Lei.

Traduzindo para a realidade de um SaaS, sua política precisa responder, sem rodeios:

- **Finalidade específica (I):** para que você usa cada categoria de dado. "Para melhorar a experiência" não é finalidade específica — é enrolação. "Para autenticar o login", "para faturar a assinatura", "para enviar e-mails transacionais" são finalidades específicas.
- **Forma e duração (II):** como você coleta e trata (formulário, cookies, integrações, logs) e por quanto tempo guarda.
- **Identificação e contato do controlador (III e IV):** razão social, CNPJ e um canal real de contato. Nada de "Fulano Tecnologia" sem CNPJ nem e-mail que ninguém lê.
- **Uso compartilhado e finalidade (V):** com quem você compartilha — gateways de pagamento, provedores de e-mail, analytics, hospedagem — e por quê.
- **Responsabilidades dos agentes (VI):** quem é controlador, quem é operador, e o que cada um responde.
- **Direitos do titular (VII):** os direitos do Art. 18, com **menção explícita** — a lei usa essa expressão.

Faltou um desses itens? A política está incompleta perante o Art. 9º.

## Base legal: cada finalidade precisa de uma

Aqui está o erro mais comum e mais silencioso. Muitos SaaS acham que "pedi consentimento" resolve tudo. Não resolve. A LGPD exige uma **base legal** (Art. 7º para dados comuns, Art. 11 para dados sensíveis) para **cada finalidade** de tratamento — e o consentimento é apenas uma das dez hipóteses.

Na prática, em um SaaS:

- Tratar dados para **executar o contrato** (entregar o serviço que o cliente assinou) costuma se apoiar na execução de contrato.
- Cumprir obrigações fiscais e guardar nota fiscal apoia-se em **obrigação legal/regulatória**.
- Prevenir fraude e garantir segurança costuma apoiar-se no **legítimo interesse** (com o devido balanceamento).
- Enviar marketing para quem ainda não é cliente geralmente depende de **consentimento**.

Uma política madura **declara a base legal de cada finalidade**. Isso não é detalhe técnico para advogado: é o que demonstra que você pensou no tratamento antes de fazê-lo, e não inventou uma justificativa depois.

## Operadores, sub-processadores e transferência internacional

Nenhum SaaS opera sozinho. Você usa hospedagem, e-mail transacional, gateway de pagamento, analytics, talvez um modelo de IA. Cada um desses é, na prática, um **operador** (ou sub-processador) que trata dados em seu nome. A política deve mencionar essas categorias e a finalidade do compartilhamento (Art. 9º, V).

E quando esses fornecedores estão fora do Brasil — o que é a regra para nuvem e ferramentas de produtividade — entra a **transferência internacional**:

> **Art. 33** A transferência internacional de dados pessoais somente é permitida nos seguintes casos: [...]

Se o seu banco de dados está em um data center nos EUA ou na Europa, ou se você usa um provedor estrangeiro, há transferência internacional acontecendo. Sua política deve **informar isso ao titular** e indicar em qual hipótese do Art. 33 você se apoia. Omitir é esconder um fato relevante sobre o tratamento.

## Retenção: até quando você guarda

A LGPD não permite guardar dados para sempre "por via das dúvidas". O tratamento deve terminar quando a finalidade se esgota, e os dados devem ser eliminados:

> **Art. 15** O término do tratamento de dados pessoais ocorrerá nas seguintes hipóteses: I - verificação de que a finalidade foi alcançada ou de que os dados deixaram de ser necessários [...]
>
> **Art. 16** Os dados pessoais serão eliminados após o término de seu tratamento [...] autorizada a conservação para as seguintes finalidades: I - cumprimento de obrigação legal ou regulatória pelo controlador; [...]

Sua política deve indicar **prazos ou critérios de retenção** por categoria de dado — e as exceções legítimas (por exemplo, guardar dados fiscais pelo prazo legal mesmo após o cancelamento da conta). "Guardamos seus dados pelo tempo necessário" sem critério algum é vago demais para cumprir o Art. 9º, II.

## O canal do encarregado (Art. 41)

A LGPD exige que o controlador indique um **encarregado** (DPO) e divulgue essa informação publicamente — e o lugar natural para isso é a política de privacidade.

> **Art. 41** O controlador deverá indicar encarregado pelo tratamento de dados pessoais.
> § 1º A identidade e as informações de contato do encarregado deverão ser divulgadas publicamente, de forma clara e objetiva, preferencialmente no sítio eletrônico do controlador.

Na prática: a política precisa trazer **um canal de contato do encarregado** (nome ou função, e um e-mail/formulário) para o titular exercer seus direitos e tirar dúvidas. Sem isso, falta o ponto de entrada que a própria lei pressupõe.

## O erro de copiar a política do concorrente

Esta é a parte honesta que poucos dizem. Copiar a política de um concorrente — ou colar um modelo genérico da internet — **não protege**. Pelo contrário: cria um documento que **não reflete o seu tratamento real**, e isso é pior do que não ter.

Se a política diz que você não usa cookies de terceiros, mas o seu site carrega pixel de anúncio e analytics, há uma **declaração falsa** sobre o tratamento. Se ela cita finalidades que você não pratica e omite as que pratica, ela viola justamente o princípio de transparência e a exatidão que o Art. 6º exige. Uma política bonita só vale se for **verdadeira para o seu produto**.

Antes de redigir, mapeie o tratamento de verdade: que dados você coleta, em quais telas, por quais ferramentas, com quem compartilha, onde armazena e por quanto tempo. A política é o **espelho** desse mapeamento — não o substituto dele.

## Política de Privacidade ≠ Termos de Uso

São dois documentos com funções distintas, e juntá-los confunde o titular:

- **Termos de Uso** regulam a **relação contratual**: o que é permitido na plataforma, planos, pagamento, responsabilidades, rescisão. É a regra do jogo.
- **Política de Privacidade** cumpre o **dever de informar sobre dados pessoais** da LGPD: finalidades, bases legais, direitos, compartilhamento, retenção. É o documento de transparência.

Pode haver remissão entre eles, mas a política de privacidade precisa existir e se sustentar por si só.

## O que incluir | artigo da LGPD

| O que incluir na política | Artigo da LGPD |
| --- | --- |
| Princípio de transparência (informação clara e acessível) | Art. 6º, VI |
| Finalidade específica de cada tratamento | Art. 9º, I |
| Forma e duração do tratamento | Art. 9º, II |
| Identificação e contato do controlador | Art. 9º, III e IV |
| Compartilhamento de dados e finalidade | Art. 9º, V |
| Responsabilidades dos agentes (controlador/operador) | Art. 9º, VI |
| Direitos do titular, com menção explícita | Art. 9º, VII + Art. 18 |
| Base legal de cada finalidade | Art. 7º / Art. 11 |
| Transferência internacional de dados | Art. 33 |
| Critérios de retenção e eliminação | Art. 15 e 16 |
| Canal de contato do encarregado (DPO) | Art. 41 |

## Mini-esqueleto de uma política de privacidade

Use como ponto de partida — sempre preenchendo com o seu tratamento real:

1. **Quem somos** — controlador, razão social, CNPJ, contato.
2. **Quais dados coletamos** — por categoria (cadastro, uso, pagamento, cookies/logs).
3. **Para que usamos (finalidades)** — finalidade específica de cada uso.
4. **Com que base legal** — a hipótese do Art. 7º/11 para cada finalidade.
5. **Com quem compartilhamos** — operadores/sub-processadores e finalidade.
6. **Transferência internacional** — se há, e em qual hipótese do Art. 33.
7. **Por quanto tempo guardamos** — critérios de retenção e eliminação.
8. **Seus direitos e como exercê-los** — os direitos do Art. 18 e o canal.
9. **Cookies e rastreadores** — quais, para quê, e como gerenciar.
10. **Encarregado (DPO)** — nome/função e canal de contato (Art. 41).
11. **Atualizações** — data de vigência e como mudanças são comunicadas.

## Linguagem clara não é opcional

Por fim, lembre que o Art. 9º fala em informação **clara e ostensiva**, e o Art. 6º em **facilmente acessível**. Uma política que só um advogado entende falha no objetivo. Escreva para o titular: frases curtas, sem latim desnecessário, com seções navegáveis. Transparência que ninguém consegue ler não é transparência.

## Comece pelo diagnóstico passivo — de graça

Antes de reescrever qualquer política, vale saber **o ponto de partida real do seu site**: ele sequer tem uma política de privacidade linkada de forma acessível? E quais rastreadores e cookies já estão carregando — que a sua política precisaria declarar?

O **Fracta** faz exatamente esse primeiro diagnóstico, de forma **passiva e gratuita**, sem cadastro. Ele verifica se o seu SaaS tem uma política de privacidade linkada e sinaliza a presença de rastreadores/cookies, devolvendo uma nota A–F na hora. Não substitui a redação jurídica nem o mapeamento do tratamento — mas é o raio-x inicial que mostra onde você está antes de começar a se adequar.

**Veja grátis em [fracta.pro](https://fracta.pro) se o seu site tem política de privacidade linkada e quais rastreadores ele carrega** — leva segundos e é o primeiro passo honesto rumo à conformidade.
