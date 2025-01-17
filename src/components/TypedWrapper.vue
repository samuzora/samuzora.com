<script setup lang="ts">
import { Typed } from "@duskmoon/vue3-typed-js";
import type { TypedOptions } from "@duskmoon/vue3-typed-js";

const options: TypedOptions = {
  strings: [
    "learning pwn, web and smart contract",
    "p.sendline(b\'A\'*0x1000)",
    "nvim4life",
    "b *main+429",
    "ctf writeups", 
    "cat ./flag.txt",
    "x/50gx 0xfff8881012996000",
    "nvim solve.py",
    "p.interactive()",
    "\' or 1=1 -- ",
    "b\'\\xd0\\x9e\\xdb\\xf7\\xff\\x7f\\x00\\x00\'"
  ],
  startDelay: 500,
  backDelay: 1500,
  typeSpeed: 100,
  backSpeed: 60,
  loop: true,
  smartBackspace: true,
}
</script>

<template>
  <Typed :options="options">
    <p class="typed">
      <i class="typing"></i>
    </p>
  </Typed>
</template>
