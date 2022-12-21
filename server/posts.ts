import fs from 'fs'
import matter from 'gray-matter'
import { join, resolve } from 'path'

const postsDirectory = resolve('./_posts')

export interface Post {
  title: string,
  date: string,
  content: string,
  slug: string
}

export async function getSlugs() {
  const slugs = fs.readdirSync(postsDirectory).map(slug => slug.replace('.md', ''))
  return slugs
}

export async function getPosts() {
  const slugs = await getSlugs()
  const posts = await Promise.all(slugs.map(async slug => await getPost(slug)))
  return posts
}

export async function getPost(slug: string): Promise<Post> {
  const content = matter(
    fs.readFileSync(join(postsDirectory, slug + '.md'), 'utf8')
  )
  const { title, date } = content.data
  return { content: content.content, title, date, slug }
}
