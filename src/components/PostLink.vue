<script setup>
import { getCollection } from "astro:content";
const props = defineProps(["posts"]);

const posts = await getCollection("blog", (post) => {
  console.log(post.id);
  return props.posts.includes(post.id);
})
</script>

<template>
  <div class="grid gap-8 grid-cols-2">
    <a
      class="post-link rounded-xl flex flex"
      v-for="post in posts"
      v-bind:key="post"
      v-bind:href="post"
    >
      <div class="post-link-background rounded-t-xl">
      </div>
      <div class="post-link-header text-xl m-3">
        {{post.data.title}}
      </div>
    </a>
  </div>
</template>

<style>
.post-link {
  outline: solid 1px var(--secondary-bg);
  text-decoration: none !important;
  word-break: normal !important;

  .post-link-background {
    height: 60%;
    background-image: url("/assets/bg-dark.png");
    background-size: auto 100%;
    transition: ease-in-out 0.2s;
  }
  .post-link-header {
    height: 40%;
    transition: ease-in-out 0.2s;
    color: white !important;
  }
}

.post-link:hover {
  .post-link-background {
    height: 50%;
  }
  .post-link-header {
    height: 50%;
  }
}
</style>
