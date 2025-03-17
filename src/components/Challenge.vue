<script setup lang="ts">
import Card from "./Card.vue";

const props = defineProps<{
  title: string
  solves?: number
  files?: {
    name: String
    url: String
  }[]
  flag?: string
}>()
</script>

<template>
  <div class="my-4 border border-[--secondary-bg]">
    <div class="border-b border-[--secondary-bg] text-lg pb-4 mt-4">
      <span class="p-4 border-r border-[--secondary-bg] text-[--second-text-color]">
        {{ props.solves ?? "?" }} solves
      </span>
    </div>

    <div class="my-6">
      <h3 class="text-center">{{ props.title }}</h3>
    </div>
    <div class="mx-6">
      <p>
        <slot />
      </p>
    </div>
    <div class="flex mx-6 my-6 gap-3" v-if="props.files?.length">
      <a
        v-for="file in props.files"
        v-bind:key="file.name"
        v-bind:href="file.url"
        class="!no-underline"
        target="_blank"
      >
        <span
          class="px-3 py-2 bg-[--primary-color] rounded text-[--primary-bg] hover:bg-[--primary-color-transparent-60]
          transition-all"
        >
          <i class="fa-regular fa-download"></i>
          {{ file.name }}
        </span>
      </a>
    </div>
    <div class="flex mx-6 mt-4 mb-6 justify-between gap-3">
      <input 
        readonly
        class="p-2 grow border border-[--secondary-bg] rounded bg-[--tertiary-bg] outline-none"
        v-bind:value="props.flag ?? 'FLAG{???}'"
      />
      <span class="px-3 py-2 bg-[--primary-color] rounded text-[--primary-bg] hover:bg-[--primary-color-transparent-60]
        transition-all cursor-pointer">
        Submit
      </span>
    </div>
  </div>
</template>

<style>

</style>
