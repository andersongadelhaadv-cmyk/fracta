import Link from 'next/link'
import { CopyBlock } from './CopyBlock'
import { MCP_INSTALL_CMD } from '@/lib/config'

/**
 * Ponte web→ferramenta: no fim do relatório, convida a corrigir os achados rodando
 * o Fracta no editor (MCP) sobre o próprio repositório.
 */
export function EditorCta() {
  return (
    <div className="mx-auto mt-10 max-w-content px-5">
      <div className="rounded-md border border-border bg-surface p-6">
        <p className="font-mono text-xs uppercase tracking-wide text-accent">e agora?</p>
        <h2 className="mt-3 text-lg font-semibold text-text">Corrija isso direto no seu editor.</h2>
        <p className="mt-2 max-w-2xl text-sm leading-relaxed text-muted">
          Instale o Fracta no Claude e peça <span className="text-text">“escaneie o repositório e me ajude a corrigir os
          headers”</span>. Ele lê o seu código (read-only, na sua máquina) e propõe o fix ciente do seu stack.
        </p>
        <div className="mt-4 max-w-2xl">
          <CopyBlock text={MCP_INSTALL_CMD} />
        </div>
        <Link href="/mcp" className="mt-4 inline-block font-mono text-sm text-accent hover:underline">
          como funciona o MCP + CLI →
        </Link>
      </div>
    </div>
  )
}
