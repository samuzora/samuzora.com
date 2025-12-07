import { defineCollection, z } from "astro:content";

import { glob } from "astro/loaders";

const blog = defineCollection({
  loader: glob({ pattern: "**/*.{md,mdx}", base: "./src/content/blog" }),
  schema: z.object({
    title: z.string(),
    date: z.coerce.date(),
    excerpt: z.string(),
    category: z.string(), // should be a normalized-string, no caps, spaces, or slashes
    tags: z.array(z.string()),
    draft: z.boolean().optional()
  })
});

const challs = defineCollection({
  loader: glob({ pattern: "**/*.{md,mdx}", base: "./src/content/challs" }),
  schema: z.object({
    title: z.string(),
    flag: z.string(),
    files: z.array(z.object({name: z.string(), url: z.string()}))
  })
});

export const collections = { blog, challs };
