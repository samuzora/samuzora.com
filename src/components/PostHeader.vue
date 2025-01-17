<script setup>
const props = defineProps(["post", "remarkPluginFrontmatter"]);
</script>

<template>
  <div class="pt-5 pb-5 text-center text-3xl lg:text-4xl font-black">
    {{post.data.title}}
  </div>
  <div>
    <div class="flex gap-3">
      <div>
        <img class="rounded-xl aspect-square w-14 border border-[--secondary-bg]" src="/assets/samuzora.webp"
          alt="author" />
      </div>
      <div class="flex flex-col justify-around">
        <div>
          samuzora
        </div>
        <div class="flex justify-start items-center gap-4 text-sm text-[--fourth-text-color]">
          <div class="flex items-center gap-1">
            <i class="fa-regular fa-pencil"></i>
            {{post.data.date.toLocaleDateString("en-SG", { year: "numeric", month: "short", day: "numeric" })}}
          </div>

          <div class="hidden md:flex items-center gap-1">
            <i class="fa-regular fa-folder"></i>
            {{post.data.category}}
          </div>

          <div class="hidden lg:flex items-center gap-1">
            <i class="fa-regular fa-tags"></i>
            {{post.data.tags.join(" | ")}}
          </div>

          <div class="flex items-center gap-1">
            <i class="fa-regular fa-clock"></i>
            {{remarkPluginFrontmatter.minutesRead}}
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
