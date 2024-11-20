// @ts-check
import { defineConfig } from "astro/config";
import yaml from "@rollup/plugin-yaml"
import { remarkReadingTime } from "./remark-reading-time.mjs";
import sectionize from "remark-sectionize";

import vue from "@astrojs/vue";

import tailwind from "@astrojs/tailwind";

import sitemap from "@astrojs/sitemap";

// https://astro.build/config
export default defineConfig({
  site: "https://samuzora.com",
  integrations: [vue(), tailwind(), sitemap()],

  markdown: {
    remarkPlugins: [remarkReadingTime, sectionize],
    shikiConfig: {
      theme: "catppuccin-mocha",
      wrap: true
    }
  },

  vite: {
    plugins: [yaml()]
  },
});
