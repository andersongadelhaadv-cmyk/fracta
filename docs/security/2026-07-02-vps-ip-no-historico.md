# Decisão de segurança — IP da VPS no histórico Git (#31)

- **Data:** 2026-07-02
- **Status:** ACEITO
- **Decisão:** **Endurecer o SSH da VPS** (mitigar o risco), **não reescrever o histórico Git** (teatro).

## Contexto

O IP e a topologia da VPS de deploy (o IP público — **não reproduzido aqui**, é justamente
o valor que o guard do #27 barra —, path `/opt/apps`, alias `ssh hostinger`)
foram commitados em docs de um repositório **público**. Foram **removidos do tree atual** na
issue #27 (commit `ba103d4`), com um guard de regressão (`packages/core/src/__tests__/repo-hygiene.test.ts`)
que impede reintroduzi-los. Porém o valor **permanece no histórico Git** (commits `a0dcaeb`,
`9ac5ed8`, `2244434`, entre outros).

Confirmado com `git grep`: o IP **não está no tree atual**, apenas no histórico.
Confirmado com `git log -S`: nenhum outro segredo acompanhou o vazamento — só IP/topologia
(credenciais/chaves nunca estiveram versionadas; a camada de segredos + gitleaks cobrem isso).

## Opções consideradas

### A) Reescrever o histórico (git filter-repo / BFG) + force-push + rotacionar
- **Contra:** o repositório **já é/foi público**. O IP já foi clonado, forkado, cacheado por
  crawlers e potencialmente indexado. Reescrever o histórico **não des-expõe** um valor que já
  está fora. Além disso, quebra todo fork/clone/PR aberto e reescreve SHAs (deploys, tags, links).
- **Fato-chave:** um **IP não é uma credencial**. Não há o que "rotacionar" — trocar o IP da VPS
  é caro e o novo IP seria igualmente escaneável. A internet inteira é port-scaneada continuamente;
  conhecer o IP **não** dá acesso a nada por si só.
- **Veredito:** teatro de segurança. Custo alto, ganho ~zero.

### B) Aceitar a exposição do IP e **endurecer o SSH** (ESCOLHIDA)
O risco real de um IP conhecido é acesso não-autorizado a portas expostas (SSH sobretudo).
Mitiga-se tornando o host **resistente independentemente de o IP ser conhecido**:

1. **SSH key-only** — `PasswordAuthentication no` + `PubkeyAuthentication yes` no `sshd_config`.
2. **Root sem senha** — `PermitRootLogin prohibit-password` (ou `no`, com usuário sudo).
3. **fail2ban** ativo na jail `sshd` (banir brute-force).
4. **Firewall** (ufw/nftables): expor só o necessário; app web fica atrás do **Cloudflare**
   (origem não recebe tráfego direto na 80/443 fora do Cloudflare).
5. **Sem segredos versionados** — já garantido pelo agente SECRETS + gitleaks no CI.

Com isso, o IP no histórico vira **informação inócua**: saber o endereço não abre nenhuma porta.

## Ação de acompanhamento (owner: Anderson — outward-facing, exige acesso à VPS)

Verificar/confirmar o endurecimento, read-only:

```sh
ssh hostinger "sudo sshd -T | grep -Ei 'passwordauthentication|permitrootlogin|pubkeyauthentication'; \
  systemctl is-active fail2ban; sudo ufw status verbose"
```

Esperado: `passwordauthentication no`, `permitrootlogin prohibit-password` (ou `no`),
`pubkeyauthentication yes`, fail2ban `active`, ufw restrito. Se algo divergir, ajustar
antes de considerar o #31 plenamente fechado na infra.

## Consequências

- O histórico **não** será reescrito. Nenhum SHA muda; forks/clones/CI seguem válidos.
- A issue #31 é fechada **por decisão documentada**; a mitigação efetiva mora na config da VPS
  (ação de acompanhamento acima), não no repositório.
- Guard de higiene (#27) segue impedindo **reintrodução** do IP no tree.
