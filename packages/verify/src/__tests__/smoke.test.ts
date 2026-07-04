import { describe, it, expect } from 'vitest'
import { VERIFY_PACKAGE } from '../index.js'

describe('@fracta/verify scaffold', () => {
  it('exporta o identificador do pacote', () => {
    expect(VERIFY_PACKAGE).toBe('@fracta/verify')
  })
})
