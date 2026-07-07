import { describe, it, expect } from 'vitest'
import { SqliteScanStore } from '../scan-store.js'

describe('SqliteScanStore — assinaturas de monitoramento (opt-in LGPD)', () => {
  it('subscribe cria assinatura ATIVA e devolve token de opt-out', () => {
    const s = new SqliteScanStore(':memory:')
    const { token } = s.subscribe('dev@ex.com', 'https://ex.com', { genToken: () => 'tok-1' })
    expect(token).toBe('tok-1')
    const active = s.listActiveSubscriptions()
    expect(active).toHaveLength(1)
    expect(active[0]).toMatchObject({ email: 'dev@ex.com', url: 'https://ex.com', unsubToken: 'tok-1' })
  })

  it('subscribe do mesmo (email,url) faz UPSERT (não duplica) e reativa', () => {
    const s = new SqliteScanStore(':memory:')
    const a = s.subscribe('dev@ex.com', 'https://ex.com', { genToken: () => 't1' })
    s.unsubscribe(a.token)
    expect(s.listActiveSubscriptions()).toHaveLength(0)
    s.subscribe('dev@ex.com', 'https://ex.com', { genToken: () => 't2' }) // re-assina
    expect(s.listActiveSubscriptions()).toHaveLength(1) // upsert, não 2ª linha
  })

  it('unsubscribe(token) desativa; token desconhecido → false, sem efeito', () => {
    const s = new SqliteScanStore(':memory:')
    const { token } = s.subscribe('a@ex.com', 'https://a.com', { genToken: () => 'z' })
    expect(s.unsubscribe('inexistente')).toBe(false)
    expect(s.listActiveSubscriptions()).toHaveLength(1)
    expect(s.unsubscribe(token)).toBe(true)
    expect(s.listActiveSubscriptions()).toHaveLength(0)
  })

  it('markNotified grava o shareId da última notificação (anti re-notificar)', () => {
    const s = new SqliteScanStore(':memory:')
    s.subscribe('a@ex.com', 'https://a.com', { genToken: () => 'z' })
    const sub = s.listActiveSubscriptions()[0]
    expect(sub.lastNotifiedScanId).toBeNull()
    s.markNotified(sub.id, 'scan-42')
    expect(s.listActiveSubscriptions()[0].lastNotifiedScanId).toBe('scan-42')
  })
})
