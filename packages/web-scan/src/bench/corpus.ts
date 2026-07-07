/**
 * Corpus de benchmark — casos rotulados por GROUND-TRUTH externo (CSP spec / OWASP / MDN),
 * NÃO pelo que o nosso detector faz. Inclui de propósito casos-gap: regras que um scanner
 * completo emitiria mas o Fracta AINDA não cobre (`csp-no-frame-ancestors`, `csp-no-form-action`)
 * → viram false-negative honesto, pra o número não ser 100% por construção.
 *
 * `expected` = ids de regra que DEVERIAM disparar. Regras do analyzeCsp:
 *   csp-unsafe-inline-script, csp-unsafe-eval, csp-no-script-src, csp-broad-script-src,
 *   csp-no-default-src, csp-object-src, csp-no-base-uri, csp-unsafe-inline-style.
 * Regras-gap (não emitidas hoje): csp-no-frame-ancestors, csp-no-form-action.
 */
export interface CspCase {
  name: string
  csp: string
  expected: string[]
  rationale: string
}

/** Regras que um bom scanner emite mas o Fracta ainda NÃO cobre (documenta os gaps). */
export const CSP_GAP_RULES = ['csp-no-frame-ancestors', 'csp-no-form-action'] as const

export const CSP_CORPUS: CspCase[] = [
  {
    name: 'strict-limpo',
    csp: "default-src 'self'; script-src 'self' 'nonce-r'; style-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
    expected: [],
    rationale: 'Política endurecida e completa — nenhum achado esperado (mede falso-positivo).',
  },
  {
    name: 'unsafe-inline-script',
    csp: "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
    expected: ['csp-unsafe-inline-script'],
    rationale: "'unsafe-inline' em script-src sem nonce/hash anula a proteção contra XSS.",
  },
  {
    name: 'unsafe-inline-suprimido-por-nonce',
    csp: "default-src 'self'; script-src 'self' 'unsafe-inline' 'nonce-abc'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
    expected: [],
    rationale: 'Com nonce presente o browser ignora unsafe-inline → NÃO deve flagar (mede FP de nonce).',
  },
  {
    name: 'unsafe-inline-suprimido-por-hash',
    csp: "default-src 'self'; script-src 'self' 'unsafe-inline' 'sha256-xyz'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
    expected: [],
    rationale: 'Hash presente → unsafe-inline ignorado pelo browser → sem achado.',
  },
  {
    name: 'unsafe-eval',
    csp: "default-src 'self'; script-src 'self' 'unsafe-eval'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
    expected: ['csp-unsafe-eval'],
    rationale: "'unsafe-eval' reabre eval()/Function — amplia superfície de XSS.",
  },
  {
    name: 'sem-script-nem-default',
    csp: "img-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
    expected: ['csp-no-script-src', 'csp-no-default-src'],
    rationale: 'Sem script-src nem default-src, a origem dos scripts fica irrestrita.',
  },
  {
    name: 'script-src-amplo-https',
    csp: "default-src 'self'; script-src https:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
    expected: ['csp-broad-script-src'],
    rationale: "'https:' em script-src permite script de quase qualquer origem.",
  },
  {
    name: 'default-src-curinga',
    csp: "default-src *; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
    expected: ['csp-broad-script-src'],
    rationale: 'Sem script-src, o fallback é default-src *; script fica irrestrito (broad).',
  },
  {
    name: 'sem-object-src',
    csp: "default-src 'self'; script-src 'self'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
    expected: ['csp-object-src'],
    rationale: "Sem object-src 'none', <object>/<embed> continuam como vetor legado.",
  },
  {
    name: 'sem-base-uri',
    csp: "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'",
    expected: ['csp-no-base-uri'],
    rationale: 'Sem base-uri, uma <base> injetada sequestra URLs relativas.',
  },
  {
    name: 'sem-default-src',
    csp: "script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
    expected: ['csp-no-default-src'],
    rationale: 'Sem default-src, diretivas não declaradas ficam sem fallback restritivo.',
  },
  {
    name: 'unsafe-inline-style',
    csp: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
    expected: ['csp-unsafe-inline-style'],
    rationale: "'unsafe-inline' em style-src (menor risco, mas relevante — CSS injetado).",
  },
  {
    name: 'multi-problema-realista',
    csp: "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:",
    expected: [
      'csp-unsafe-inline-script',
      'csp-unsafe-eval',
      'csp-broad-script-src',
      'csp-object-src',
      'csp-no-base-uri',
      'csp-no-frame-ancestors',
      'csp-no-form-action',
    ],
    rationale: 'Política frouxa e incompleta — vários achados, incl. os gaps de clickjacking/form-action.',
  },
  {
    // GAP: política forte de XSS mas SEM frame-ancestors → clickjacking. Fracta não cobre → FN honesto.
    name: 'gap-sem-frame-ancestors',
    csp: "default-src 'self'; script-src 'self' 'nonce-r'; object-src 'none'; base-uri 'self'; form-action 'self'",
    expected: ['csp-no-frame-ancestors'],
    rationale: 'GAP conhecido: sem frame-ancestors há risco de clickjacking; o Fracta ainda não checa isso.',
  },
  {
    // GAP: sem form-action → hijack de formulário. Fracta não cobre → FN honesto.
    name: 'gap-sem-form-action',
    csp: "default-src 'self'; script-src 'self' 'nonce-r'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    expected: ['csp-no-form-action'],
    rationale: 'GAP conhecido: sem form-action um form injetado pode postar p/ origem arbitrária.',
  },
  {
    name: 'apenas-default-self',
    csp: "default-src 'self'",
    expected: ['csp-object-src', 'csp-no-base-uri', 'csp-no-frame-ancestors', 'csp-no-form-action'],
    rationale: "default-src 'self' cobre script/style, mas faltam object-src 'none', base-uri, frame-ancestors e form-action.",
  },
]

/** Cookies: `expected` = ids `cookie-flags:<name>` que devem disparar (cookie sem Secure/HttpOnly/SameSite). */
export interface CookieCase {
  name: string
  setCookie: string[]
  expected: string[]
  rationale: string
}

export const COOKIE_CORPUS: CookieCase[] = [
  {
    name: 'cookie-limpo',
    setCookie: ['sid=abc; Secure; HttpOnly; SameSite=Lax; Path=/'],
    expected: [],
    rationale: 'Tem Secure+HttpOnly+SameSite → sem achado (mede FP).',
  },
  {
    name: 'sem-nenhuma-flag',
    setCookie: ['sid=abc; Path=/'],
    expected: ['cookie-flags:sid'],
    rationale: 'Cookie de sessão sem nenhuma flag de segurança.',
  },
  {
    name: 'sem-httponly',
    setCookie: ['sid=abc; Secure; SameSite=Lax'],
    expected: ['cookie-flags:sid'],
    rationale: 'Sem HttpOnly, o cookie é legível por JS (roubo via XSS).',
  },
  {
    name: 'sem-samesite',
    setCookie: ['sid=abc; Secure; HttpOnly'],
    expected: ['cookie-flags:sid'],
    rationale: 'Sem SameSite, exposto a envio cross-site (CSRF).',
  },
  {
    name: 'valor-contem-secure-mas-sem-flag',
    setCookie: ['token=secure-jwt-123'],
    expected: ['cookie-flags:token'],
    rationale: 'O VALOR contém "secure" mas não há atributo Secure — não pode virar falso-negativo.',
  },
  {
    name: 'samesite-none-sem-secure',
    setCookie: ['sid=abc; SameSite=None'],
    expected: ['cookie-flags:sid'],
    rationale: 'SameSite=None sem Secure é inválido no browser; pego via Secure ausente.',
  },
  {
    name: 'host-prefix-sem-secure',
    setCookie: ['__Host-sid=abc; Path=/'],
    expected: ['cookie-flags:__Host-sid'],
    rationale: 'Prefixo __Host- EXIGE Secure; aqui faltam todas as flags.',
  },
  {
    name: 'multiplos-um-inseguro',
    setCookie: ['ok=1; Secure; HttpOnly; SameSite=Strict', 'ruim=2; Path=/'],
    expected: ['cookie-flags:ruim'],
    rationale: 'Só o cookie sem flags deve ser flagado (o seguro não).',
  },
]
