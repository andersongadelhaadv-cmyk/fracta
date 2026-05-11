import { randomUUID } from 'crypto'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export type AgentCategory =
  | 'security'
  | 'docs'
  | 'code'
  | 'deps'
  | 'infra'
  | 'compliance'
  | 'performance'

export type StackType = string

export const KNOWN_STACKS = [
  'nestjs', 'nextjs', 'prisma', 'stripe', 'supabase',
  'whatsapp', 'redis', 'docker',
] as const

export type ScanDepth = 'quick' | 'full' | 'paranoid'

export interface TargetAuth {
  type: 'jwt' | 'apikey' | 'basic' | 'oauth'
  endpoint?: string
  credentials?: {
    email?: string
    password?: string
    apiKey?: string
  }
  headerName?: string
  headerPrefix?: string
}

export interface Target {
  name: string
  url: string
  stack: StackType[]
  auth?: TargetAuth
  agents?: string[]
  skills?: string[]
  ignore?: string[]
}

export interface Finding {
  id: string
  runId: string
  agent: string
  category: AgentCategory
  severity: Severity
  title: string
  description: string
  endpoint?: string
  evidence?: string
  recommendation: string
  references?: string[]
  createdAt: Date
}

export interface ScanScope {
  target: Target
  depth: ScanDepth
  agents: string[]
  runId: string
  startedAt: Date
}

export interface ScanReport {
  runId: string
  target: string
  startedAt: Date
  finishedAt: Date
  durationMs: number
  summary: {
    total: number
    critical: number
    high: number
    medium: number
    low: number
    info: number
  }
  findings: Finding[]
  passed: boolean
}

export interface SecurityAgent {
  name: string
  category: AgentCategory
  concurrency: number
  timeoutMs: number
  run(scope: ScanScope): Promise<Finding[]>
}

export interface HttpResponse {
  status: number
  headers: Record<string, string>
  body: unknown
  raw: string
}

export interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  headers?: Record<string, string>
  body?: unknown
  timeoutMs?: number
}

export interface SecurityTest {
  name: string
  path: string
  method: RequestOptions['method']
  headers?: Record<string, string>
  body?: unknown
  expect: (response: HttpResponse) => Finding[]
}

export interface FractaSkill {
  name: string
  targets: StackType[]
  detect(target: Target): boolean
  getTests(): SecurityTest[]
  evaluate(response: HttpResponse): Finding[]
}

export function makeFinding(
  partial: Omit<Finding, 'id' | 'createdAt'>
): Finding {
  return {
    ...partial,
    id: randomUUID(),
    createdAt: new Date(),
  }
}
