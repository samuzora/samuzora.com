<template>
  <div class="card p-5 rounded-lg backdrop-blur-lg">
    <slot />
  </div>
</template>

<style>
  .card {
    background-color: var(--primary-bg-transparent-80);
    outline: solid 1px var(--secondary-bg);
  }
</style>
