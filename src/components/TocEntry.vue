<script setup>
const props = defineProps(["heading"])
</script>

<template>
  <div class="list-inside mb-1" v-bind:key="heading.slug">
    <a class="transition-all break-words" :href="'#' + heading.slug">{{ heading.text }}</a>
  </div>
  <div class="px-3">
    <TocEntry 
      v-for="subheading in heading.subheadings" 
      v-bind:heading="subheading" 
      v-bind:key="subheading.slug" 
    />
  </div>
</template>
