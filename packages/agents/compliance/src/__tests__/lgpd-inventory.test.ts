import { describe, it, expect } from 'vitest'
import { parsePrismaModels, classifyField, buildInventory, detectOperators } from '../lgpd-inventory.js'

describe('classifyField', () => {
  it('classifica sensível', () => {
    expect(classifyField('cpf')).toBe('sensivel')
    expect(classifyField('senha')).toBe('sensivel')
    expect(classifyField('dadosSaude')).toBe('sensivel')
  })
  it('classifica pessoal', () => {
    expect(classifyField('email')).toBe('pessoal')
    expect(classifyField('nomeCompleto')).toBe('pessoal')
    expect(classifyField('telefone')).toBe('pessoal')
  })
  it('classifica comum', () => {
    expect(classifyField('id')).toBe('comum')
    expect(classifyField('createdAt')).toBe('comum')
    expect(classifyField('status')).toBe('comum')
  })
})

describe('parsePrismaModels + buildInventory', () => {
  const schema = `
    generator client { provider = "prisma-client-js" }
    model User {
      id        String  @id
      email     String  @unique
      nome      String
      cpf       String
      createdAt DateTime @default(now())
      // comentário
      @@index([email])
    }
    model Log {
      id   String @id
      msg  String
    }
  `
  it('parseia modelos e campos', () => {
    const models = parsePrismaModels(schema)
    expect(models.map(m => m.model)).toEqual(['User', 'Log'])
    expect(models[0].fields).toContain('email')
    expect(models[0].fields).not.toContain('@@index') // atributo de bloco ignorado
  })
  it('inventaria só modelos com dado pessoal, classificado', () => {
    const inv = buildInventory(parsePrismaModels(schema))
    expect(inv).toHaveLength(1) // Log não tem dado pessoal
    expect(inv[0].model).toBe('User')
    expect(inv[0].sensivel).toContain('cpf')
    expect(inv[0].pessoal).toEqual(expect.arrayContaining(['email', 'nome']))
  })
})

describe('detectOperators', () => {
  it('mapeia operadores e flag de transferência internacional', () => {
    const pkg = JSON.stringify({ dependencies: { stripe: '^1', '@aws-sdk/client-s3': '^3', openai: '^4', pg: '^8' } })
    const ops = detectOperators(pkg)
    const byName = Object.fromEntries(ops.map(o => [o.name, o]))
    expect(byName['Stripe'].international).toBe(true)
    expect(byName['AWS'].international).toBe(true)
    expect(byName['OpenAI'].international).toBe(true)
    expect(byName['Banco de dados (self-hosted)'].international).toBe(false)
  })
  it('retorna [] p/ package.json inválido', () => {
    expect(detectOperators('not json')).toEqual([])
  })
})
