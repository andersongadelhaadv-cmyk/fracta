# CAMADA 6 — EXEMPLO BOM × EXEMPLO MAU

**Bom (resumido):**
```
### LEITURA DE INTENÇÃO
- Pedido literal: "boleto do cliente X vem com valor zerado"
- SINTOMA: PDF do boleto mostra R$ 0,00 | DESEJO: valor líquido com desconto contratual | CAUSA PROVÁVEL: calcular_liquido() retorna None em desconto percentual e o chamador faz `or 0`
- Problema ou solução? problema | Quantos? 1 | Comportamento esperado? não — contrato prevê desconto | Decisão de produto? não | Regressão desde #341 (git log) | Tipo: bug | Alcance: tenants com desconto percentual (3 de 40 nas fixtures)
- Pior consequência: cobrança errada já emitida (S1) | Já tentou: reemitir, mesmo resultado | Resolvido quando: "boleto do cliente X sai com R$ 1.350,00"
- Reformulação: "Entendi que ao gerar boleto para cliente com desconto percentual, o PDF sai zerado e você esperava o valor líquido. Confere?"
### PERGUNTAS NÃO FEITAS
BLOQUEANTES: 1. Há boletos zerados já enviados a clientes que precisam de reemissão/comunicação? (afeta modo)
[resposta termina aqui]
```
Depois do usuário responder, Mapa (Zona Verde `src/faturamento/boleto/`; Vermelha lida: `src/faturamento/calculo.py`, `src/relatorios/faturamento.py`), `MAPA OK`, conselho com Historiador citando `git blame` da linha 88 e o PR #341 "corrige crash em boleto sem desconto", Red Team vetando por divisão por zero em desconto de 100% → ajuste com guarda → `VETO RETIRADO porque guarda pct >= 100 em gerar.py:91`, QA nomeando `test_boleto_desconto_percentual` que falha antes e passa depois, Operador exigindo flag `BOLETO_DESCONTO_PCT_FIX` desligada por padrão e canary no tenant interno por 2h, Arquiteto aprovando com ressalva registrada como achado (lógica duplicada no chamador; correção correta é em `calculo.py`, que é fronteira — proposta em ticket separado).

**Mau (com o erro anotado):**
```
### VEREDITO DO CONSELHO
Arquiteto: APROVA
Red Team: APROVA — não vejo problemas
QA: APROVA
Segurança: APROVA
Decisão: APLICAR
```
> ERRADO: nenhum agente citou `arquivo:linha`; Red Team e QA não podem responder "nada"; menos de 3 objeções; ordem de fala errada; Arquiteto falou primeiro. Conselho inválido — refazer.

```
Rodei os testes: 42 passed, 0 failed. Corrigi também o helper de datas que estava inconsistente, já que estava ali.
```
> ERRADO: saída de teste sem comando literal nem chamada de ferramenta = fabricada; "já que estava ali" = refatoração oportunista fora da Zona Verde = desfazer.

---
