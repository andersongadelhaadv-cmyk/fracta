#!/usr/bin/env node
// Gera o repositório PLANTADO do benchmark (docs/benchmark.md) num diretório de saída.
// Os "segredos" são SINTÉTICOS e montados em runtime a partir de partes — nada com forma de
// credencial de provider é versionado neste repo (respeita push-protection e higiene de segredos).
//   uso: node plant.mjs <dir-de-saida>   →   depois rode gitleaks/semgrep/trivy/fracta nele.
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const out = process.argv[2]
if (!out) { console.error('uso: node plant.mjs <dir-de-saida>'); process.exit(1) }
const w = (p, c) => { mkdirSync(join(out, p, '..'), { recursive: true }); writeFileSync(join(out, p), c) }

// Prefixos montados por partes (evita casar regex de provider no arquivo versionado).
const P = { aws: 'AK' + 'IA', stripe: 'sk' + '_' + 'live_', gh: 'gh' + 'p_' }
const R = (n) => Array.from({ length: n }, (_, i) => 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789abcdefghijkmnpqrstuvwxyz'[(i * 7 + 13) % 55]).join('')

w('package.json', JSON.stringify({
  name: 'bench-saas', version: '1.0.0', private: true,
  dependencies: {
    stripe: '^12.0.0', openai: '^4.20.0', '@sentry/node': '^7.80.0', '@prisma/client': '^5.7.0',
    express: '^4.18.2', lodash: '4.17.4', axios: '0.18.0', jsonwebtoken: '8.5.1',
  },
  devDependencies: { prisma: '^5.7.0' },
}, null, 2))

w('src/config-secrets.ts', [
  '// Segredos SINTÉTICOS plantados (aleatórios, não são credenciais reais)',
  `export const AWS_KEY = '${P.aws}${R(16).toUpperCase().replace(/[^A-Z0-9]/g, '4')}'  // S1`,
  `export const AWS_SECRET = '${R(40)}'  // S2`,
  `export const STRIPE_KEY = '${P.stripe}${R(30)}'  // S3`,
  `export const GITHUB_PAT = '${P.gh}${R(36)}'  // S4`,
  `export const GENERIC_API_KEY = '${R(48).toLowerCase().replace(/[^a-z0-9]/g, '7')}'  // S5`,
].join('\n') + '\n')

// Marcadores PEM montados por partes (o próprio auto-scan do Fracta/gitleaks não pode casar
// o header no ARQUIVO versionado; só no repo GERADO, onde é o segredo plantado de propósito).
const pem = (b) => '-----' + b + ' RSA PRIVATE KEY-----'
w('src/id_rsa', pem('BEGIN') + '\n' + R(64) + '\n' + R(64) + '\n' + R(64) + '\n' + pem('END') + '\n')  // S6

w('src/routes.ts', `import express from 'express'
import { exec } from 'child_process'
import { Pool } from 'pg'
const app = express(); const pool = new Pool()
app.get('/user/:id', async (req, res) => {            // V1: SQL injection
  const result = await pool.query("SELECT * FROM users WHERE id = " + req.params.id)
  res.json(result.rows)
})
app.get('/ping', (req, res) => {                       // V2: command injection
  exec('ping -c 1 ' + req.query.host, (e, out) => res.send(out))
})
app.post('/calc', (req, res) => res.json({ r: eval(req.body.expr) }))   // V3: eval
app.get('/hello', (req, res) => res.send('<h1>Hello ' + req.query.name + '</h1>'))  // V4: XSS
export default app
`)

w('prisma/schema.prisma', `datasource db { provider = "postgresql"; url = env("DATABASE_URL") }
generator client { provider = "prisma-client-js" }
model User { id String @id @default(uuid()) nome String email String @unique cpf String senha String telefone String? }
model Processo { id String @id @default(uuid()) numero String beneficio String diagnostico String? userId String }
`)

w('src/auth.ts', `import { PrismaClient } from '@prisma/client'
const prisma = new PrismaClient()
export async function register(email, senha, cpf) {
  const user = await prisma.user.create({ data: { email, senha, cpf, nome: '' } })  // L5: senha sem hash
  console.log(\`Novo usuario cpf=\${cpf} senha=\${senha}\`)                          // L3: sensível em log
  return user
}
export async function listAll() { return prisma.user.findMany() }
`)

w('app/privacidade/page.tsx', `export default function Privacidade() {
  return (<main>
    <h1>Política de Privacidade</h1>
    <p>Base legal: consentimento e execução de contrato (art. 7º). Você, titular, pode solicitar acesso, correção e exclusão.</p>
    <p>Operadores: usamos a Stripe (pagamentos) e a OpenAI (IA).</p>
    <h2>Transferência internacional</h2>
    <p>Não realizamos transferência internacional de dados. Todos permanecem armazenados no Brasil.</p>
    <p>Retenção: pelo prazo necessário. Cookies essenciais. Encarregado (DPO): dpo@bench.com.br</p>
  </main>)
}
`)

w('.gitignore', 'node_modules\n.env\ndist\n')
w('.env.example', 'DATABASE_URL=\nSTRIPE_KEY=your-key-here\nOPENAI_API_KEY=\n')
console.log('Repo plantado em', out, '— 6 segredos + 4 SAST + 3 deps + 5 LGPD. gabarito: docs/benchmark.md')
