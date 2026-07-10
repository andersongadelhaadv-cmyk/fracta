# Benchmark reprodutível — Fracta vs gitleaks / semgrep / trivy

Prova, com um comando, o claim de `docs/benchmark.md`: os incumbentes cobrem só a **própria pista**;
a coluna **LGPD é não-zero apenas no Fracta**; o Fracta cobre a **união**.

## Rodar

```bash
bash run.sh /tmp/fracta-bench      # planta o repo, roda as 4 ferramentas, imprime a tabela
```

Requer `node`. Opcional (cada ausente entra como 0): `gitleaks`, `semgrep`, `trivy` (ou `docker`), e o
Fracta buildado (`pnpm build` no monorepo → a coluna do Fracta usa `fracta-run.mjs`, que importa o `dist`).

## Arquivos

- **`plant.mjs`** — gera o repo plantado (18 itens: 6 segredos SINTÉTICOS + 4 SAST + 3 deps + 5 LGPD).
  Os segredos são montados por partes → nada com forma de credencial fica versionado neste repo.
- **`ground-truth.json`** — o gabarito machine-checkable (categoria + arquivo/pacote de cada item).
- **`score.mjs`** — normaliza a saída de cada ferramenta e calcula o recall por categoria.
- **`run.sh`** / **`fracta-run.mjs`** — orquestração e o runner do pipeline `scan_repo` do Fracta.

## Como ler os números (honestidade)

`score.mjs` casa **grosso** (por categoria + arquivo/pacote). Para gitleaks/semgrep/trivy/npm-audit isso
é exato. Para o **Fracta** é um **piso conservador**: achados repo-level (ROPA, senha-sem-hashing,
operadores) nem sempre citam o arquivo na evidência, então o matcher automático pode subcontá-los. A
medição **canônica** é a **tabela conferida à mão** em `docs/benchmark.md` (15/18), com o raciocínio
item a item. O `score.mjs` existe para um cético **reproduzir a FORMA** sem confiar na minha contagem:
- incumbentes presos à sua pista (gitleaks só segredos, semgrep só SAST, trivy/npm só deps);
- **LGPD = 0 para todos os incumbentes, não-zero só para o Fracta** — o fosso, verificável por máquina.

Ou seja: o piso automático já prova o que importa; a tabela à mão dá o número fino.
