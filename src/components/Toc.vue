<script setup>
import { onMounted, onUnmounted } from "vue";
import TocEntry from "./TocEntry.vue"

const props = defineProps(["headings"]);
const toc = buildToc(props.headings);

function buildToc(headings) {
  const toc = []
  const stack = []

  headings.forEach((h) => {
    const heading = { ...h, subheadings: [] }

    while (stack.length > 0 && stack[stack.length - 1].depth >= heading.depth) {
      stack.pop()
    }

    if (stack.length === 0) {
      toc.push(heading)
    } else {
      stack[stack.length - 1].subheadings.push(heading)
    }

    stack.push(heading)
  })

  return toc
}


let observer = undefined;

onMounted(() => {
  const markdownBody = document.getElementsByClassName("markdown-body")[0];
  const toc = document.getElementById("toc");

  const onElementObserved = (entries) => {
    entries.forEach(({ target, isIntersecting }) => {
      const header = target.querySelector("h1, h2, h3, h4, h5, h6");
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

<template>
  <div class="text-xs">
    <div class="mr-3" id="toc">
      <TocEntry
        v-for="heading in toc"
        v-bind:heading="heading"
        v-bind:key="heading.slug"
      />
    </div>
  </div>
</template>

<style>
a:hover {
  /* to override the regular a behaviour */
  color: var(--first-text-color);
}
</style>
