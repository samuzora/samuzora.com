<script setup>
import { onMounted, onUnmounted } from "vue";

const props = defineProps(["headings"]);
let observer = undefined;

onMounted(() => {
  const markdownBody = document.getElementsByClassName("markdown-body")[0];
  const toc = document.getElementById("toc");

  const onElementObserved = (entries) => {
    entries.forEach(({ target, isIntersecting }) => {
      const header = target.querySelector("h1, h2");
      if (header) {
        const id = header.getAttribute("id");
        if (isIntersecting) {
          toc.querySelector(`a[href="#${id}"]`).classList.add("!text-[--second-text-color]");
        } else {
          toc.querySelector(`a[href="#${id}"]`).classList.remove("!text-[--second-text-color]");
        }
      }
    })
  }

  observer = new IntersectionObserver(onElementObserved, {
    // 150px == ~the height we reach when clicking on the hash href
    // 30px == ~1.8rem == h1 height
    rootMargin: "-150px 0px -60px 0px"
  })

  markdownBody
    .querySelectorAll("section")
    .forEach(section => {
      observer.observe(section)
    })
})

onUnmounted(() => {
  observer.disconnect();
})
</script>

<!-- up to h2 nested headings -->
<template>
  <div class="text-xs">
    <div class="text-xl font-bold text-[--second-text-color] pb-2">
      Contents
    </div>
    <ul id="toc" class="flex flex-col justify-start gap-1">
      <li class="my-0 lg:my-0.5" v-for="heading in props.headings" v-bind:key="heading.slug">
        <a class="transition-all" :href="'#' + heading.slug">{{ heading.text }}</a>
        <ul class="ml-3">
          <li class="my-0 lg:my-0.5" v-for="sub in heading.subheadings" v-bind:key="sub.slug">
            <a class="transition-all" :href="'#' + sub.slug">{{ sub.text }}</a>
          </li>
        </ul>
      </li>
    </ul>
  </div>
</template>

<style>
a:hover {
  /* to override the regular a behaviour */
  color: var(--first-text-color);
}
</style>
