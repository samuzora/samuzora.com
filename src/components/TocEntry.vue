<script setup>
const props = defineProps(["heading"])
</script>

<template>
  <li class="list-inside py-0.5" v-bind:key="heading.slug">
    <a class="transition-all" :href="'#' + heading.slug">{{ heading.text }}</a>
  </li>
  <ul class="translate-x-3">
    <TocEntry 
      v-for="subheading in heading.subheadings" 
      v-bind:heading="subheading" 
      v-bind:key="subheading.slug" 
    />
  </ul>
</template>
