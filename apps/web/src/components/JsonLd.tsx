const SITE = 'https://fracta.pro'

/** Dados estruturados (schema.org) — ajudam o Google a entender o produto e a ferramenta grátis. */
const data = [
  {
    '@context': 'https://schema.org',
    '@type': 'Organization',
    name: 'Fracta',
    url: SITE,
    logo: `${SITE}/brand/og.png`,
    sameAs: ['https://github.com/andersongadelhaadv-cmyk/fracta'],
    parentOrganization: { '@type': 'Organization', name: 'PreviusIA', url: 'https://previusia.com.br' },
  },
  {
    '@context': 'https://schema.org',
    '@type': 'WebSite',
    name: 'Fracta',
    url: SITE,
    inLanguage: 'pt-BR',
  },
  {
    '@context': 'https://schema.org',
    '@type': 'WebApplication',
    name: 'Fracta',
    url: SITE,
    applicationCategory: 'SecurityApplication',
    operatingSystem: 'Web',
    offers: { '@type': 'Offer', price: '0', priceCurrency: 'BRL' },
    description:
      'Scanner web passivo grátis: headers de segurança, TLS, cookies e sinais de LGPD. Nota A–F na hora, sem cadastro.',
    inLanguage: 'pt-BR',
  },
]

export function JsonLd() {
  return <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }} />
}
