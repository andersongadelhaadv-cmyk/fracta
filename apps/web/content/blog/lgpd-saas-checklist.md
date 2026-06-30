---
title: "LGPD para SaaS: o checklist mínimo que evita dor de cabeça com a ANPD"
description: "Checklist prático de LGPD para SaaS: base legal, política, direitos do titular, DPO, contratos e cookies. O mínimo para reduzir risco com a ANPD."
slug: "lgpd-saas-checklist"
date: "2026-06-30"
updated: "2026-06-30"
author: "Anderson Gadelha"
tags: ["lgpd", "saas", "anpd"]
keyword: "lgpd para saas"
---

Você lançou o produto, conseguiu os primeiros clientes e agora alguém perguntou: "vocês estão adequados à LGPD?". A resposta honesta, para a maioria dos SaaS brasileiros, é "mais ou menos". E "mais ou menos" é exatamente o terreno onde a Autoridade Nacional de Proteção de Dados (ANPD) pode atuar.

A boa notícia: você não precisa de um departamento jurídico inteiro para sair do "mais ou menos". Precisa de um **checklist mínimo bem feito** — os controles que, na prática, separam um SaaS com risco controlado de um SaaS exposto. Este artigo é esse checklist, escrito por quem é advogado e constrói software. Sem juridiquês inútil, sem alarmismo, com os artigos da Lei 13.709/2018 onde eles importam.

Uma observação de honestidade antes de começar: **adequação à LGPD não é um botão**. É um conjunto de decisões jurídicas, técnicas e de processo. O que segue é o mínimo viável — o que reduz o risco mais relevante com o menor esforço.

## Por que SaaS é um caso especial de LGPD

Todo SaaS, por definição, **trata dados pessoais de terceiros**. Você coleta dados dos seus usuários (cadastro, e-mail, comportamento) e, muitas vezes, hospeda dados que seus clientes coletam dos *clientes deles*. Isso te coloca em dois papéis distintos da LGPD ao mesmo tempo:

- **Controlador** dos dados dos seus próprios usuários e leads.
- **Operador** dos dados que seus clientes processam na sua plataforma (Art. 5º, VII).

Esses papéis têm obrigações diferentes. Confundi-los é o erro número um. O checklist abaixo cobre principalmente o seu papel de **controlador**, mas marca onde o papel de operador muda o jogo.

## O checklist mínimo de LGPD para SaaS

Marque cada item. O que estiver desmarcado é um gap — e os gaps têm prioridades diferentes.

| # | Controle | Base na LGPD | Prioridade |
|---|----------|--------------|------------|
| 1 | Mapeei a base legal de cada tratamento de dados | Art. 7º e 11 | Crítico |
| 2 | Tenho política de privacidade transparente e acessível | Art. 9º | Crítico |
| 3 | Existe canal para o titular exercer seus direitos | Art. 18 | Crítico |
| 4 | Encarregado (DPO) nomeado e divulgado | Art. 41 | Crítico |
| 5 | Contratos com operadores e sub-processadores | Art. 39 | Alto |
| 6 | Transferência internacional tratada (cloud/ferramentas) | Art. 33 | Alto |
| 7 | Consentimento e banner de cookies (rastreadores não-essenciais) | Art. 7º, I e 8º | Alto |
| 8 | Plano de resposta a incidentes e notificação à ANPD | Art. 48 | Alto |
| 9 | Política de retenção e eliminação de dados | Art. 15 e 16 | Médio |
| 10 | Medidas de segurança técnicas e administrativas | Art. 46 | Crítico |

A seguir, o que cada item realmente exige.

### 1. Base legal de cada tratamento (Art. 7º e 11) — Crítico

Esse é o alicerce. **Todo tratamento de dado pessoal precisa de uma das dez bases legais do Art. 7º** (ou do Art. 11, para dados sensíveis). Não basta "ter consentimento para tudo" — consentimento é frágil e revogável, e muitas vezes a base correta é outra.

Exemplos comuns em SaaS:

- Cadastro e cobrança do cliente → **execução de contrato** (Art. 7º, V).
- E-mail transacional (recibo, alerta de segurança) → execução de contrato ou **obrigação legal**.
- Logs de segurança e prevenção a fraude → **legítimo interesse** (Art. 7º, IX).
- Newsletter e marketing para quem não é cliente → normalmente **consentimento** (Art. 7º, I).

> **Art. 7º** O tratamento de dados pessoais somente poderá ser realizado nas seguintes hipóteses: [...] I - mediante o fornecimento de consentimento pelo titular; [...] V - quando necessário para a execução de contrato [...]; IX - quando necessário para atender aos interesses legítimos do controlador [...]

Atenção à **zona cinzenta do legítimo interesse**: ele exige um teste de proporcionalidade (o chamado *teste de balanceamento* ou LIA) e não vale para dados sensíveis. Marketing por legítimo interesse é defensável em alguns cenários e contestável em outros — se você for por esse caminho, documente o raciocínio. Não trate como certeza o que a lei trata como ponderação.

### 2. Política de privacidade transparente (Art. 9º) — Crítico

A política de privacidade não é enfeite de rodapé. O Art. 9º dá ao titular o direito de acesso facilitado e claro sobre o tratamento. Uma política mínima precisa dizer:

- **Quais dados** você coleta e com qual finalidade específica.
- **A base legal** de cada finalidade (item 1).
- **Com quem** você compartilha (operadores, ferramentas, sub-processadores).
- **Se há transferência internacional** (item 6).
- **Por quanto tempo** retém os dados (item 9).
- **Como** o titular exerce seus direitos e contata o encarregado (itens 3 e 4).

> **Art. 9º** O titular tem direito ao acesso facilitado às informações sobre o tratamento de seus dados, que deverão ser disponibilizadas de forma clara, adequada e ostensiva [...]

Política copiada de concorrente é um risco: ela descreve o tratamento *deles*, não o seu. Se você usa um analytics que o texto não menciona, a política já está mentindo.

A existência (e a acessibilidade) de uma política de privacidade é justamente um dos sinais que dá para checar de fora. No **[Fracta](https://fracta.pro)** — scanner web passivo grátis — você vê em segundos se o seu site expõe uma política acessível, quais rastreadores de terceiros estão carregando e se há cookies não-essenciais antes do consentimento. É um diagnóstico de *sinais*, não um substituto da adequação jurídica, mas mostra rápido o que está visível para qualquer um (inclusive para a ANPD).

### 3. Canal de direitos do titular (Art. 18) — Crítico

O titular pode pedir confirmação de tratamento, acesso, correção, anonimização, portabilidade e eliminação dos seus dados, entre outros direitos do Art. 18. Você precisa de um **canal real** para receber e responder esses pedidos — um e-mail dedicado, um formulário, algo rastreável.

> **Art. 18** O titular dos dados pessoais tem direito a obter do controlador [...]: I - confirmação da existência de tratamento; II - acesso aos dados; III - correção [...]; VI - eliminação dos dados pessoais tratados com o consentimento [...]

O mínimo viável aqui é processo, não tecnologia: defina quem recebe, em quanto tempo responde e como confirma a identidade de quem pede. Automação vem depois.

### 4. Encarregado / DPO divulgado (Art. 41) — Crítico

A lei exige que o controlador **indique um encarregado** pelo tratamento de dados e **divulgue publicamente** sua identidade e contato (Art. 41, §1º). Na prática, para a maioria dos SaaS pequenos, isso é um nome e um e-mail na política de privacidade.

> **Art. 41** O controlador deverá indicar encarregado pelo tratamento de dados pessoais. §1º A identidade e as informações de contato do encarregado deverão ser divulgadas publicamente, de forma clara e objetiva [...]

A ANPD já sinalizou flexibilização para agentes de pequeno porte, mas **divulgar um canal de contato do encarregado segue sendo a postura segura**. É barato e fecha um gap visível.

### 5. Contratos com operadores e sub-processadores (Art. 39) — Alto

Você usa banco de dados gerenciado, e-mail transacional, processador de pagamento, suporte, analytics. Cada um desses é um **operador** que trata dados pessoais por sua conta. O Art. 39 exige que o operador siga suas instruções — e isso precisa estar **contratualizado** (o famoso DPA, *Data Processing Agreement*).

> **Art. 39** O operador deverá realizar o tratamento segundo as instruções fornecidas pelo controlador [...]

O mínimo: garanta que cada fornecedor relevante tenha um DPA assinado (a maioria dos serviços sérios oferece um padrão) e mantenha uma **lista de sub-processadores**. Se você é operador dos dados dos seus clientes, é você quem precisa oferecer esse DPA a eles — e isso costuma ser exigência de venda B2B.

### 6. Transferência internacional (Art. 33) — Alto

Aqui mora um gap silencioso de **quase todo SaaS brasileiro**: se você usa nuvem ou ferramentas hospedadas fora do Brasil (a maioria das grandes), você está fazendo **transferência internacional de dados** sob o Art. 33.

> **Art. 33** A transferência internacional de dados pessoais somente é permitida nos seguintes casos: I - para países [...] que proporcionem grau de proteção adequado; [...] VIII - quando o titular tenha fornecido o seu consentimento específico [...] ou IX - quando necessário para a execução de contrato [...]

O mínimo viável: **declare a transferência na política de privacidade** e ancore-a em uma hipótese do Art. 33 (execução de contrato e cláusulas contratuais são caminhos usuais). O regime de cláusulas-padrão da ANPD vem amadurecendo; mantenha-se atento, mas não use isso como desculpa para o silêncio. Omitir a transferência é o pior cenário.

### 7. Consentimento e banner de cookies (Art. 7º, I e 8º) — Alto

Cookies e rastreadores **estritamente necessários** (sessão, segurança) não exigem consentimento. Os demais — analytics, pixels de anúncio, mapas de calor — são tratamento que normalmente depende de **consentimento livre, informado e inequívoco** (Art. 8º).

> **Art. 8º** O consentimento [...] será fornecido por escrito ou por outro meio que demonstre a manifestação de vontade do titular. §4º O consentimento deverá referir-se a finalidades determinadas [...]

O erro clássico: o banner aparece, mas os scripts de rastreamento **já carregaram antes de o usuário clicar**. Isso esvazia o consentimento. O mínimo é: rastreador não-essencial só dispara *depois* do "aceitar".

Esse é outro sinal verificável de fora. O **[scanner do Fracta](https://fracta.pro)** lista os rastreadores de terceiros que o seu site carrega e ajuda a flagrar quando algo não-essencial sobe antes do consentimento — um sintoma comum de banner decorativo.

### 8. Resposta a incidentes e notificação à ANPD (Art. 48) — Alto

Vazamento acontece. O que diferencia o SaaS preparado é ter um **plano**. O Art. 48 obriga o controlador a comunicar à ANPD e aos titulares afetados a ocorrência de incidente de segurança que possa acarretar risco ou dano relevante.

> **Art. 48** O controlador deverá comunicar à autoridade nacional e ao titular a ocorrência de incidente de segurança que possa acarretar risco ou dano relevante aos titulares.

O mínimo viável é um documento curto que responda: quem detecta, quem decide se notifica, em que prazo, quem comunica titulares e ANPD. A ANPD possui regulamento próprio sobre prazos e formato da comunicação — alinhe seu plano a ele.

### 9. Retenção e eliminação (Art. 15 e 16) — Médio

Dado guardado para sempre é passivo, não ativo. A LGPD prevê o **término do tratamento** (Art. 15) e a **eliminação** dos dados quando a finalidade se encerra (Art. 16), ressalvadas hipóteses de guarda legal.

> **Art. 16** Os dados pessoais serão eliminados após o término de seu tratamento [...] autorizada a conservação para [...] I - cumprimento de obrigação legal ou regulatória [...]

Sobre **anonimização** (uma das alternativas à eliminação): a lei a reconhece, mas anonimização verdadeira é tecnicamente exigente — dado "anonimizado" que pode ser reidentificado continua sendo dado pessoal. Não marque esse item levianamente. O mínimo realista costuma ser definir prazos de retenção por categoria e ter rotina de descarte.

### 10. Segurança técnica e administrativa (Art. 46) — Crítico

O Art. 46 obriga adotar medidas de segurança aptas a proteger os dados. Não há uma lista fechada, mas o piso prático de qualquer SaaS inclui HTTPS em tudo, criptografia de dados sensíveis, controle de acesso, senhas e segredos fora do código, e atualização de dependências.

> **Art. 46** Os agentes de tratamento devem adotar medidas de segurança, técnicas e administrativas aptas a proteger os dados pessoais de acessos não autorizados [...]

Muitos desses controles de superfície são **observáveis de fora**: cabeçalhos de segurança ausentes, HTTPS mal configurado, segredos expostos. É exatamente o que um scanner passivo enxerga — e o que um atacante enxerga primeiro.

## O que a ANPD pode fazer (sem inventar números)

Vale entender o risco real. A ANPD pode aplicar as sanções do **Art. 52**: desde **advertência** até **multa simples de até 2% do faturamento** da empresa no último exercício, **limitada a R$ 50 milhões por infração**, além de publicização da infração, bloqueio e eliminação dos dados.

> **Art. 52** Os agentes de tratamento [...] ficam sujeitos às seguintes sanções administrativas [...]: II - multa simples, de até 2% (dois por cento) do faturamento [...], limitada, no total, a R$ 50.000.000,00 (cinquenta milhões de reais) por infração;

Para a maioria dos SaaS em estágio inicial, o risco mais provável não é a multa máxima — é a **advertência com prazo para corrigir** e o dano reputacional de um incidente mal conduzido. O checklist acima ataca justamente esses cenários.

## Por onde começar (e o que o Fracta enxerga)

Se você só puder fazer três coisas esta semana: **mapeie suas bases legais (item 1)**, **publique uma política de privacidade honesta (item 2)** e **divulgue o contato do encarregado (item 4)**. São os gaps mais visíveis e os mais baratos de fechar.

Para checar o que está exposto agora, o **[Fracta](https://fracta.pro)** roda um scan passivo e te dá uma nota A–F na hora, sem cadastro: ele avalia sinais de segurança e **sinais passivos de LGPD** — existência de política acessível, rastreadores de terceiros e cookies não-essenciais. Praticamos o que pregamos: o próprio Fracta passa pela auditoria completa de LGPD (16 dimensões) e é 100% adequado.

Seja claro consigo mesmo sobre o limite: **o Fracta mede sinais, não substitui adequação jurídica completa**. Um "A" no scanner não é um certificado de conformidade — é a evidência de que a superfície está limpa. O trabalho de base legal, contratos e processos (os itens 1, 5, 8 e 9) vive abaixo do que qualquer scanner vê.

**[Faça o scan grátis do seu SaaS em fracta.pro](https://fracta.pro)** e descubra, em segundos, quais sinais de LGPD você está deixando à mostra.
