/**
 * Rodapé de conversão anexado às saídas de VALOR das tools do MCP.
 *
 * Porquê: o MCP é o ímã de tráfego (o dev vive na IDE, não no site). Sem este
 * rodapé, cada scan devolve só texto técnico e o dev nunca tem motivo de visitar
 * o fracta.pro — a captura de e-mail do site fica inalcançável a partir do MCP.
 *
 * Regras (para não virar spam):
 * - Só nas saídas de valor entregue (scan concluído / relatório), NUNCA em erro,
 *   validação ("informe url") ou saída JSON (get_findings) — texto quebraria o parse.
 * - Uma linha de valor (grátis/OSS + upsell on-topic: "monitore a cada deploy")
 *   + uma linha de cross-sell leve (mesma casa do zap-api).
 * - `?ref=*` distinto por superfície → dá pra medir de onde vem a conversão.
 */
export const MCP_FOOTER =
  '\n\n—\n' +
  'Fracta é grátis e open-source · [monitore isto a cada deploy](https://fracta.pro?ref=mcp&utm_source=fracta-mcp&utm_medium=mcp&utm_campaign=footer) (badge + regressão contínua).\n' +
  'Da PreviusIA — também fazemos o [zap-api.tech](https://zap-api.tech?ref=fracta-mcp&utm_source=fracta-mcp&utm_medium=mcp&utm_campaign=crosssell): API de WhatsApp pra devs, segura por padrão.'

/**
 * Rodapé de conversão respeitando `FRACTA_NO_PROMO` — defina a var (qualquer valor
 * não-vazio) para SILENCIAR o rodapé em demos/apresentações. Lido em tempo de chamada
 * (o MCP é um processo longo; a var é definida no launch do cliente MCP).
 */
export function promoFooter(): string {
  return process.env.FRACTA_NO_PROMO ? '' : MCP_FOOTER
}
