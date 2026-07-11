// Redação de segredos em profundidade (defense-in-depth) para o que fica EM DISCO.
// O Fracta já trunca segredos na evidência; isto garante que nenhum valor bruto de
// credencial sobreviva no raw.json local. Determinístico: o mesmo segredo vira o mesmo
// stub (‹redacted:HASH›), então o arquivo é estável entre execuções (reprodutível).
import { createHash } from 'node:crypto'

const stub = (m) => `‹redacted:${createHash('sha256').update(m).digest('hex').slice(0, 8)}›`

// Blocos PEM: mascara TODO o corpo entre BEGIN/END (o corpo pode ser curto, então
// não dá para depender do limiar de entropia).
const PEM = /-----BEGIN[^-]*-----[\s\S]*?-----END[^-]*-----/g
// Prefixos de provider (pegam tokens curtos que o limiar genérico não alcança).
const PROVIDER = /\b(?:AKIA[0-9A-Z]{12,}|sk_live_[A-Za-z0-9]{10,}|sk_test_[A-Za-z0-9]{10,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|ya29\.[A-Za-z0-9._-]{20,}|npm_[A-Za-z0-9]{20,})\b/g
// Token genérico de alta entropia: >=32 chars alfanuméricos com letra E dígito
// (evita over-redaction de nomes/paths, que raramente misturam por 32+ chars).
const HIGH_ENTROPY = /\b(?=[A-Za-z0-9]*[A-Za-z])(?=[A-Za-z0-9]*[0-9])[A-Za-z0-9]{32,}\b/g

export function redactSecrets(text) {
  if (typeof text !== 'string') return text
  return text
    .replace(PEM, stub)
    .replace(PROVIDER, stub)
    .replace(HIGH_ENTROPY, stub)
}

// Redige, em profundidade, os campos de texto-livre de um finding (não toca em
// category/file/line/rule/severity/confidence/id — o que o relatório e o oráculo usam).
export function redactFinding(f) {
  if (!f || typeof f !== 'object') return f
  const out = { ...f }
  for (const k of ['evidence', 'description', 'title', 'recommendation']) {
    if (typeof out[k] === 'string') out[k] = redactSecrets(out[k])
  }
  return out
}
