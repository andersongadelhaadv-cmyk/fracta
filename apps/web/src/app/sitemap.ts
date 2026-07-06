import type { MetadataRoute } from 'next'
import { getAllPosts } from '@/lib/blog'

const SITE = 'https://fracta.pro'
const updated = new Date('2026-06-30')

/** Sitemap dinâmico. Home + institucional + todos os artigos do blog. */
export default function sitemap(): MetadataRoute.Sitemap {
  const posts = getAllPosts().map((post) => ({
    url: `${SITE}/blog/${post.slug}`,
    lastModified: new Date(post.updated ?? post.date),
    changeFrequency: 'monthly' as const,
    priority: 0.7,
  }))

  return [
    { url: SITE, lastModified: updated, changeFrequency: 'weekly', priority: 1 },
    { url: `${SITE}/mcp`, lastModified: new Date('2026-07-06'), changeFrequency: 'weekly', priority: 0.9 },
    { url: `${SITE}/blog`, lastModified: updated, changeFrequency: 'weekly', priority: 0.8 },
    { url: `${SITE}/privacidade`, lastModified: updated, changeFrequency: 'monthly', priority: 0.4 },
    ...posts,
  ]
}
