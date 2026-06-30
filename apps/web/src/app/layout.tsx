import type { Metadata, Viewport } from 'next'
import { Inter, JetBrains_Mono, Chakra_Petch } from 'next/font/google'
import './globals.css'

const sans = Inter({ subsets: ['latin'], variable: '--font-sans', display: 'swap' })
const mono = JetBrains_Mono({ subsets: ['latin'], variable: '--font-mono', display: 'swap' })
const display = Chakra_Petch({ subsets: ['latin'], weight: ['600', '700'], variable: '--font-display', display: 'swap' })

const SITE = 'https://fracta.pro'

export const metadata: Metadata = {
  metadataBase: new URL(SITE),
  title: {
    default: 'Fracta — scanner de segurança e LGPD para o seu SaaS',
    template: '%s · Fracta',
  },
  description:
    'Analise GRÁTIS os headers de segurança, TLS, cookies e sinais de LGPD do seu site. Sem cadastro, nota A–F na hora, detecção determinística — e dizemos quando não conseguimos verificar.',
  keywords: ['segurança', 'headers', 'TLS', 'LGPD', 'scanner', 'SaaS', 'OWASP', 'cookies'],
  authors: [{ name: 'Anderson Gadelha' }],
  openGraph: {
    type: 'website',
    locale: 'pt_BR',
    url: SITE,
    siteName: 'Fracta',
    title: 'Fracta — scanner de segurança e LGPD para o seu SaaS',
    description:
      'Headers, TLS, cookies e LGPD-lite. Nota A–F na hora, detecção determinística, sem cadastro. Honesto: dizemos quando não conseguimos verificar.',
    images: [{ url: '/brand/og.png', width: 1200, height: 630, alt: 'Fracta — scanner passivo de segurança e LGPD' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Fracta — scanner de segurança e LGPD',
    description: 'Grátis, sem cadastro. Nota A–F na hora. Detecção determinística.',
    images: ['/brand/og.png'],
  },
  robots: { index: true, follow: true },
}

export const viewport: Viewport = {
  themeColor: '#0a0b0d',
  colorScheme: 'dark',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="pt-BR" className={`${sans.variable} ${mono.variable} ${display.variable}`}>
      <body>{children}</body>
    </html>
  )
}
