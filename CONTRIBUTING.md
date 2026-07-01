# Contribuindo para o Fracta

Bem-vindo! O Fracta é um framework de auditoria de SaaS, e contribuições da comunidade são muito bem-vindas — sejam novos agents, correções de bugs, melhorias na documentação ou ideias.

Este guia descreve como rodar o projeto localmente, o padrão de commits, fluxo de branches, abertura de PRs e como criar um novo agent.

## Rodando localmente

Pré-requisitos: Node.js 20+ e [pnpm](https://pnpm.io) 9+.

```bash
git clone https://github.com/andersongadelhaadv-cmyk/fracta.git
cd fracta
pnpm install
pnpm build
pnpm test
```

Para rodar o CLI em modo dev:

```bash
pnpm --filter fractascan dev -- scan ./path/to/target
```

## Padrão de commits

Usamos [Conventional Commits](https://www.conventionalcommits.org/). O escopo é opcional. Mensagens em pt-BR ou en, ambos aceitos.

Tipos principais:

- `feat`: nova funcionalidade
- `fix`: correção de bug
- `chore`: tarefa de manutenção (deps, lockfile, config)
- `docs`: apenas documentação
- `test`: adicionar/ajustar testes
- `refactor`: refator sem mudança de comportamento
- `ci`: pipelines, GitHub Actions, templates

Exemplos:

```
feat(agents-auth): detecta JWT sem expiração
fix(cli): corrige caminho relativo em --output
docs: adiciona exemplo de scan no README
chore: bump turbo para 2.1
```

## Branches

Nomes em kebab-case com prefixo por tipo:

- `feat/<nome-curto>` — nova feature
- `fix/<nome-curto>` — correção
- `chore/<nome-curto>` — manutenção
- `docs/<nome-curto>` — documentação

Branches saem de `master` e voltam pra `master` via PR.

## Abrindo um Pull Request

1. Faça fork (ou crie branch direto, se tiver acesso de escrita).
2. Escreva o código e os testes.
3. Rode localmente:
   ```bash
   pnpm tsc --noEmit
   pnpm test
   ```
4. Abra o PR seguindo o template (`.github/PULL_REQUEST_TEMPLATE.md`).
5. Inclua na descrição:
   - O que muda e por quê
   - Screenshots ou output de terminal, quando relevante
   - Checklist preenchido

PRs sem descrição clara ou sem testes podem ser fechados pedindo ajustes.

## Como criar um novo agent

Cada agent vive em `packages/agents-<nome>` e implementa a interface `IAgent` exportada por `@fracta/core`.

Estrutura mínima:

```
packages/agents-<nome>/
├── package.json
├── tsconfig.json
├── src/
│   ├── index.ts        # exporta o agent
│   └── agent.ts        # implementação
└── test/
    └── agent.test.ts   # teste mínimo
```

Esqueleto do agent:

```ts
import type { IAgent, ScanContext, Finding } from '@fracta/core';

export const myAgent: IAgent = {
  name: 'my-agent',
  description: 'O que esse agent faz, em uma linha.',
  async scan(ctx: ScanContext): Promise<Finding[]> {
    // sua lógica aqui
    return [];
  },
};
```

Teste mínimo (vitest):

```ts
import { describe, it, expect } from 'vitest';
import { myAgent } from '../src/agent';

describe('myAgent', () => {
  it('retorna findings vazios quando nada é detectado', async () => {
    const findings = await myAgent.scan({ /* mock ctx */ });
    expect(findings).toEqual([]);
  });
});
```

Registre o agent no `packages/cli` para que apareça no `fracta scan`.

## Code review

- Todo PR precisa de **pelo menos 1 aprovação** antes do merge.
- Merge direto em `master` (sem PR) **não é permitido**.
- O autor do PR não pode aprovar o próprio PR.
- Use *squash & merge* para manter o histórico linear.

## Dúvidas?

Abra uma issue com a label `question` ou contate o mantenedor em [contato@previusia.com.br](mailto:contato@previusia.com.br).
