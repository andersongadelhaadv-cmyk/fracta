import type { Metadata } from 'next'
import { Inter, JetBrains_Mono } from 'next/font/google'
import './globals.css'

const sans = Inter({ subsets: ['latin'], variable: '--font-sans', display: 'swap' })
const mono = JetBrains_Mono({ subsets: ['latin'], variable: '--font-mono', display: 'swap' })

const SITE = 'https://fracta.pro'

export const metadata: Metadata = {
  metadataBase: new URL(SITE),
  title: {
    default: 'Fracta — scanner de segurança e LGPD para o seu SaaS',
    template: '%s · Fracta',
  },
  description:
    'Analise headers de segurança, TLS, cookies e sinais de LGPD do seu site. Detecção determinística, sem cadastro. Nota A–F na hora — e dizemos quando não conseguimos verificar.',
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
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Fracta — scanner de segurança e LGPD',
    description: 'Nota A–F na hora. Detecção determinística. Sem cadastro.',
  },
  robots: { index: true, follow: true },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="pt-BR" className={`${sans.variable} ${mono.variable}`}>
      <body>{children}</body>
    </html>
  )
}
