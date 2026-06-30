import type { MetadataRoute } from 'next'

const SITE = 'https://fracta.pro'
const updated = new Date('2026-06-30')

/** Sitemap dinâmico. Páginas de blog entram aqui quando existirem. */
export default function sitemap(): MetadataRoute.Sitemap {
  return [
    { url: SITE, lastModified: updated, changeFrequency: 'weekly', priority: 1 },
    { url: `${SITE}/privacidade`, lastModified: updated, changeFrequency: 'monthly', priority: 0.4 },
  ]
}
