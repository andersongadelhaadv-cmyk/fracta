import type { Target } from '@fracta/core'

/**
 * `true` se a string é uma URL http(s) — o gatilho para o modo "URL direta" dos
 * checks READ-ONLY (check_headers). Distingue de um nome de target configurado
 * (ex.: `doutor-inss`) e recusa esquemas não-web (`file://`, `ftp://`).
 */
export function looksLikeUrl(s: string | undefined): boolean {
  return typeof s === 'string' && /^https?:\/\//i.test(s.trim())
}

/**
 * Constrói um Target ad-hoc a partir de uma URL — sem targets.yaml. Usado pelos
 * checks read-only (GET de headers), que são seguros em produção e não deveriam
 * exigir arquivo de config. Nomeado pelo host para legibilidade do relatório;
 * cai para a URL crua se o host for impronunciável (nunca crasha).
 */
export function targetFromUrl(url: string): Target {
  const clean = url.trim()
  let name = clean
  try {
    const h = new URL(clean).hostname
    if (h) name = h
  } catch {
    /* host impronunciável — mantém a URL crua como nome */
  }
  return { name, url: clean, stack: [] }
}
