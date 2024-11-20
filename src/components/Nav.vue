<script setup>
  const props = defineProps(["active", "href"]);
</script>

<template>
  <a class="nav text-[15px] md:text-[18px] align-middle" :class="{ active: props.active }" v-bind:href="props.href">
      <slot />
  </a>
</template>

<style>
  .nav {
    height: 50px;
    line-height: 50px;
    border-bottom: 2.5px solid transparent;
    cursor: pointer;
    transition: color 0.2s, height 0.2s, line-height 0.2s, border 0.2s;
  }

  .active {
    border-bottom: 2.5px solid var(--primary-color);
  }

  .nav:hover {
    color: var(--primary-color) !important;
    border-bottom: 2.5px solid var(--primary-color);
  }
</style>
