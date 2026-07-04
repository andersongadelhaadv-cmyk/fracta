/** Playwright/Chromium não instalado — o chamador degrada com graça. */
export class BrowserUnavailableError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'BrowserUnavailableError'
  }
}

/** Host recusado antes de navegar (privado/loopback). */
export class SsrfError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'SsrfError'
  }
}

/** Navegação falhou (timeout/DNS/target down) → veredito inconclusive, nunca verde falso. */
export class NavigationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'NavigationError'
  }
}
