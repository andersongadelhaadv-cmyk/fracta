// Intervalo de confiança de Wilson para uma proporção (precisão/recall/FPR).
// Escolhido em vez do Wald (normal) porque é honesto nas pontas (k=0 ou k=n) e com n pequeno —
// exatamente o regime da amostragem rotulada. Um ponto sem IC não é medição; isto dá a barra de erro.
const round = (x, d = 4) => Math.round(x * 10 ** d) / 10 ** d

export function wilson(k, n, z = 1.96) {
  if (k > n) throw new Error(`wilson: k(${k}) > n(${n})`)
  if (n === 0) return { point: null, low: 0, high: 1, n: 0, k: 0 }
  const p = k / n
  const z2 = z * z
  const denom = 1 + z2 / n
  const center = (p + z2 / (2 * n)) / denom
  const half = (z / denom) * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n))
  return {
    point: round(p),
    low: round(Math.max(0, center - half)),
    high: round(Math.min(1, center + half)),
    n,
    k,
  }
}

// Tamanho de amostra p/ uma largura-alvo de IC (metade da largura ~= margem), aprox. normal
// no pior caso p=0.5. Usado p/ dimensionar a fila de rotulagem — não "40 fixo".
export function sampleSizeFor(margin, z = 1.96) {
  return Math.ceil((z * z * 0.25) / (margin * margin))
}
