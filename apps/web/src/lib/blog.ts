import 'server-only'
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import matter from 'gray-matter'
import { unified } from 'unified'
import remarkParse from 'remark-parse'
import remarkGfm from 'remark-gfm'
import remarkRehype from 'remark-rehype'
import rehypeSlug from 'rehype-slug'
import rehypeStringify from 'rehype-stringify'

/**
 * Blog file-based, SSG. Markdown em content/blog/*.md → HTML no build.
 * Sem fs em runtime: as páginas são pré-renderizadas (generateStaticParams).
 */

const BLOG_DIR = join(process.cwd(), 'content', 'blog')

export interface PostMeta {
  slug: string
  title: string
  description: string
  date: string
  updated?: string
  author: string
  tags: string[]
  keyword?: string
  readingMinutes: number
}

export interface Post extends PostMeta {
  html: string
}

function readingMinutes(markdown: string): number {
  const words = markdown.trim().split(/\s+/).length
  return Math.max(1, Math.round(words / 200))
}

function slugFromFile(file: string): string {
  return file.replace(/\.mdx?$/, '')
}

function listFiles(): string[] {
  try {
    return readdirSync(BLOG_DIR).filter((f) => /\.mdx?$/.test(f))
  } catch {
    return []
  }
}

function parse(file: string): { meta: PostMeta; body: string } {
  const raw = readFileSync(join(BLOG_DIR, file), 'utf8')
  const { data, content } = matter(raw)
  const slug = (data.slug as string) || slugFromFile(file)
  return {
    body: content,
    meta: {
      slug,
      title: String(data.title ?? slug),
      description: String(data.description ?? ''),
      date: String(data.date ?? '2026-06-30'),
      updated: data.updated ? String(data.updated) : undefined,
      author: String(data.author ?? 'Anderson Gadelha'),
      tags: Array.isArray(data.tags) ? (data.tags as string[]) : [],
      keyword: data.keyword ? String(data.keyword) : undefined,
      readingMinutes: readingMinutes(content),
    },
  }
}

/** Metadados de todos os posts, mais recentes primeiro. Sem conversão de markdown (barato). */
export function getAllPosts(): PostMeta[] {
  return listFiles()
    .map((f) => parse(f).meta)
    .sort((a, b) => (a.date < b.date ? 1 : -1))
}

export function getAllSlugs(): string[] {
  return listFiles().map((f) => parse(f).meta.slug)
}

const processor = unified()
  .use(remarkParse)
  .use(remarkGfm)
  .use(remarkRehype)
  .use(rehypeSlug)
  .use(rehypeStringify)

/** Post completo com HTML renderizado. Usado na página do artigo (build-time). */
export async function getPostBySlug(slug: string): Promise<Post | null> {
  const file = listFiles().find((f) => parse(f).meta.slug === slug)
  if (!file) return null
  const { meta, body } = parse(file)
  const html = String(await processor.process(body))
  return { ...meta, html }
}
