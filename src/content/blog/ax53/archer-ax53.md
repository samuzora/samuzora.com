---
title: "A deep dive into the TP-Link Archer AX53 Router"
date: 2026-04-28 00:00:04
excerpt: "Exploring initial setup, internal services and maybe some vulns"
category: research
tags:
    - hardware
    - reversing
    - pwn
---

Last year, from Feb to Mar 2025, I interned at Ensign InfoSecurity in their
vulnerability research department. I was initially assigned a more theoretical
project in instrumenting LLMs to write fuzzing harnesses for generic white-box
codebases. But I didn't find that particularly fun so I requested to work on the
AX53 router instead. Honestly, I wasn't expecting to find anything interesting
and was prepared to just release a series of writeups on the internals of the
router. However, I managed to find the buffer overflow leading to CVE-2025-15608
on my first day of gaining access to the router, and CVE-2025-15607 after a few
more weeks. This article will be a bit lengthy as I document down the various
relevant serivces, so feel free to skip ahead to the respective articles
[CVE-2025-15607](/posts/ax53/cve-2025-15607) and
[CVE-2025-15608](/posts/ax53/cve-2025-15608) if you're more interested in the
CVEs themselves!

# Initial access

The target that I'm focusing on is TP-Link's Archer AX53. Fortunately for us,
TP-Link usually allows people to download firmware from their website directly.
Even better, the firmware is not encrypted, which makes our lives a lot easier!

## Emulation

With the firmware, it should be technically possible to setup an emulator for
the router. There are generally a few different firmware analysis/emulation
tools. The first of its kind was
[Firmadyne](https://github.com/firmadyne/firmadyne) - it's basically a
collection of modified kernels for the more common embedded architectures
(MIPS/ARM) and a bunch of scripts to extract the filesystem from the firmware
and generate a disk image for emulation. Other similar tools like FirmAE and
EMBA are built on Firmadyne to provide a higher level of automation, but
honestly Firmadyne itself is already quite automated and easy to use.

Of course, not everything is smooth-sailing, and I encountered a few issues when
trying to emulate the firmware. I won't go through the step-by-step process to
get the emulation up and running, since these can be found in the Firmadyne
repo. Instead, I'll detail the issues I faced and the workarounds I did to solve
these issues.

By the way, I'm using ` Archer AX53(US)_V1_240509` which I [downloaded from
here](https://www.tp-link.com/my/support/download/archer-ax53/v1/#Firmware), but
some of the issues I encountered will probably be the same for other
versions/images as well.

### rootfs extraction

Of course, the very first step failed - Firmadyne couldn't detect the filesystem
in the firmware image. On running the extractor script, no errors were logged,
but the extractor script didn't detect any filesystem and hence didn't create
the tarball in the `images` directory.

No problem though, it's quite easy to extract it manually. This is the output from `binwalk`:

```ansi
                                                        /home/samuzora/ax53/temp/ax53-20240509.bin
----------------------------------------------------------------------------------------------------------------------------------------------------------
DECIMAL                            HEXADECIMAL                        DESCRIPTION
----------------------------------------------------------------------------------------------------------------------------------------------------------
4754                               0x1292                             UBI image, version: 1, image size: 27918336 bytes
----------------------------------------------------------------------------------------------------------------------------------------------------------

Analyzed 1 file for 85 file signatures (187 magic patterns) in 42.0 milliseconds
```

Using `ubireader-extract-images`, we get both the kernel and rootfs images,
`img-906274389_vol-kernel.ubifs` and `img-906274389_vol-ubi_rootfs.ubifs`. Now
the rootfs is a squashfs filesystem, but this seems to differ between firmware
releases even for the exact same model. Anyway, running `unsquashfs` on the
rootfs will give us the uncompressed root filesystem. Then, we can tar this new
directory and place it at `images/1.tar.gz`, and update the Firmadyne database
to use this tarball instead.

### `preInit.sh`

After everything is set up, I realized that emulation failed because the
generated `preInit.sh` wasn't being run. In `run.sh`, the kernel option `rdinit`
is being passed with the `preInit.sh` script as its value. According to
<https://github.com/firmadyne/firmadyne/issues/176>, because the kernels have
been updated, `rdinit` is no longer run on boot, and changing it to `init`
should fix the issue. Then, adding this line `exec /etc/preinit` to the end of
`preInit.sh` script will allow the system to continue running the rest of the
init sequence as pid 1.

---

Fortunately, that's all I had to fix to get emulation up and running! Sadly, I
had some networking issues that I couldn't resolve, because some of the network
interfaces were missing. So I couldn't reach any of the services from my host,
making the emulation a bit useless for our purposes. Well, at least I managed to
get a shell! 

## UART access

Since I had the physical router with me, I decided not to waste so much time on
emulation and try to access the debugging shell on the UART interface instead.
UART is a simple interface that allows for i/o access via logic inputs and
outputs. What this interface is used for depends on the developer's intentions:
sometimes, it can just be a simple logging console; other times, the developer
may implement an entire debugging shell.

There are usually 4 pins on UART: VCC, GND, RX, and TX. VCC and GND are used to
indicate the signal high and low respectively, while RX and TX are the ones that
receive and transit data.

On most TP-Link routers, we indeed do have a debugging shell enabled on the UART
serial. However, according to online sources, the RX pin is usually disconnected
physically on the hardware, so that consumers aren't able to access the console
and possibly brick their routers. In fact, for the Archer AX53, both RX and TX
were disconnected. To fix this, we need to trace where the signal stops, and
either resolder the connection or solder header pins to redirect the signal out.

### Tracing the signal

Before we start probing for the signal, we need to get a rough idea of the
pinout configuration first. First, we should solder header pins to each hole to
make things easier for us. We can then use a multimeter to check the p.d. on
each of the pins wrt. ground. In the picture below, the leftmost pin was found
to have a constant voltage of 3.3V, so we know that it's the VCC pin. The rest
of the pins were at 0V, but it's likely that the pin second from left, next to
the VCC pin, is the GND pin; it's common to have them side-by-side. So that
leaves the last 2 pins on the right; one is RX and one is TX. 

![Pin configuration](@images/2025/tp-link/hardware/pinout-clear-image.jpg)

Time to trace the circuitry! (Please excuse the poor image as I didn't take good
photos of the board before soldering it)

![Unsoldered circuitry](@images/2025/tp-link/hardware/unsoldered.png)

In the above pic, we can see that the 3rd pin is connected to R77, and the 4th
pin is connected to R70. By probing connectivity with a multimeter, I realized
that the exact places missing resistors are the 2 contacts to the left of the
triangular-shaped solder pad groups. Using the multimeter to measure the
voltage, I can also see fluctuating p.d. on the top left pad of the rightmost
solder pad group. Additionally, on power on, if I tap the multimeter to the top
left pad of the leftmost solder pad group, one of the LEDS on the router
immediately turns orange, probably indicating that it has detected some input
and is entering a special boot sequence. Looks like we found our RX and TX -
the 3rd pin is RX, while the 4th pin is TX!

### Re-bridging the circuit

Now, we just need to solder blobs across the 2 places with the missing resistors
to hopefully get a UART shell. Unfortunately, I wasn't very good at soldering,
and held the soldering iron too close to the contacts for too long, eventually
burning the contacts off. As a workaround, I bridged directly from the bottom
pad to the top left pad for both groups, and fortunately those were easier to
solder as they were larger. The final result still isn't pretty but it works!

![Soldered blobs](@images/2025/tp-link/hardware/soldered.jpg)

### Connecting to the UART

Previously, when I was probing the signals with the multimeter, I realized that
even though the VCC had a 3.3V high, the TX was only transmitting a 1.8V high. I
only had 5V and 3.3V UART-to-USB adapters, and I didn't want to connect the 3.3V
to the 1.8V in case the higher voltage shorts the PCB. So, I took a little
detour with a logic shifter that can pull up and pull down voltages
respectively. It's quite a cool device actually.

![Logic shifter](@images/2025/tp-link/hardware/logic-shifter.jpg)

Hoewver, the logic shifter requires a constant input of the desired pull-down
voltage at VCCA, and the pull-up voltage at VCCB. VCCB was no issue as I could
use the UART's 3.3V VCC pin, but for VCCA, I didn't have a 1.8V source to
connect it to. I dug through some of my CTF hardware badges, poked at them with
the multimeter, and found a few points outputting around 1.6V to 1.8V. To get
these outputs to the logic shifter, I tried to solder header pins onto them.
However, as testament to my lackluster soldering skills, I broke the first badge
that I tried to solder. After that I gave up and just connected the UART
directly to the adapter, and surprisingly, nothing broke and I was able to read
and write to the UART interface at a baud rate of 115200 and settings 8/N/1 (8
data bits, no parity, 1 stop bit).

> 1 year later, I'm using the Bus Pirate v4 to connect to the UART instead of
> just a UART to USB interface. The configuration is quite simple and I followed
> this guide to start interacting with the UART interface:
> <https://trustedsec.com/blog/hardware-hacking-plunder-with-a-bus-pirate>

### Services on the UART

With access to the UART, I found 2 services running on this interface, the
U-Boot shell and a root shell locked behind a password. 

#### U-Boot shell

For the U-Boot shell, it activates when any key is pressed within the first 1s
of the boot sequence, as we observed earlier when identifying the RX pin. I
explored it a little, but since I already downloaded the firmware from online, I
didn't really need to use the U-Boot shell to dump the firmware or anything.

```ansi
U-Boot 2016.01 (Apr 13 2022 - 08:55:25 +0800)
...
led_gpio init done~
button_init done~
Hit any key to stop autoboot:  0

Net:   cmbblk is stable 5
MAC0 addr:0:11:22:33:44:55
PHY ID1: 0x4d
PHY ID2: 0xd0c0
MAC1 addr:0:11:22:33:44:56
rtk_switch_init ret = 0!!!!!!!!!!!!
rtk_vlan_init ret = 0!!!!!!!!!!!!
Set RTL8367S SGMII 2.5Gbps
rtk_port_macForceLinkExt_set port 16 ret = 0!!!!!!!!!!!!
rtk_port_sgmiiNway_set port 16 ret = 0!!!!!!!!!!!!
rtk_port_macForceLinkExt_set port 17 ret = 0!!!!!!!!!!!!
rtk_port_sgmiiNway_set port 17 ret = 0!!!!!!!!!!!!
..............probe rtk switch 4
eth0, eth1
IPQ5018#
```

#### Root shell

The root shell was locked behind a username and password login as shown below.

```ansi
...
Please press Enter to activate this console.
Archer_AX53 login: asdf
Password:
```

Since I already have the firmware, I decided to reverse the firmware directly to
try and find where the password is being set.

Searching through the firmware for the "Please press enter" login prompt, I get
a lot of binaries that all have an occurrence of this string. There's no way
that so many different binaries are all used to authenticate the shell, so most
likely, the authentication is defined in Busybox (since Busybox is usually
copied across many different filenames to implement different functionalities
based on the binary name). Opening Busybox in Ghidra and searching for
references to "Password:", I found the following function:

```c
char * FUN_00059510(char **passwd_entry) {
  int iVar1;
  size_t username_len;
  char *__s;
  char *__s2;
  char *username;
  uint local_238;
  undefined auStack_234 [36];
  undefined auStack_210 [256];
  char local_110 [256];
  
  memset(local_110,0,0x100);
  if (passwd_entry == (char **)0x0) {
    __s2 = "aa";
  }
  else {
    __s2 = passwd_entry[1];
    if ((*__s2 == '*' || *__s2 == 'x') && ((byte)__s2[1] == 0)) {
      local_238 = (uint)(byte)__s2[1];
      iVar1 = getspnam_r(*passwd_entry,auStack_234,auStack_210,0x100,&local_238);
      if ((iVar1 == 0) && (local_238 != 0)) {
        __s2 = *(char **)(local_238 + 4);
      }
      else {
        __s2 = "aa";
      }
    }
    username = *passwd_entry;
    username_len = strlen(username);
    iVar1 = strncmp(username,"root",username_len);
    if (iVar1 == 0) {
      iVar1 = set_root_password(local_110,0x100);
      if ((iVar1 == 0) || (local_110[0] == '\0')) {
        puts("Login: Set root password failed.");
        return (char *)0x0;
      }
      __s2 = local_110;
    }
    if (*__s2 == '\0') {
      return (char *)0x1;
    }
  }
  __s = (char *)get_password_from_user("Password: ");
  username = __s;
  if (__s != (char *)0x0) {
    username = (char *)hash_password(__s,__s2);
    iVar1 = strcmp(username,__s2);
    free(username);
    username_len = strlen(__s);
    username = (char *)(uint)(iVar1 == 0);
    memset(__s,0,username_len);
  }
  return username;
}
```

And under `set_root_password{:c}`:

```c
undefined4 set_root_password(char *param_1,uint param_2) {
  int iVar1;
  char *__s;
  size_t sVar2;
  uint local_48;
  undefined4 local_44;
  undefined local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined local_34;
  char acStack_30 [32];
  
  memset(acStack_30,0,0x20);
  local_48 = 0;
  local_44 = 0;
  local_40 = 0;
  local_3c = 0;
  local_38 = 0;
  local_34 = 0;
  generate_salt(&local_48,9);
  if ((local_48 & 0xff) != 0) {
    sprintf(acStack_30,"$1$%s$",&local_48);
    iVar1 = TPLink_generate_password(&local_3c,9);
    if (((iVar1 != 0) && (__s = (char *)hash_password(&local_3c,acStack_30), __s != (char *)0x0)) &&
       (sVar2 = strlen(__s), sVar2 < param_2)) {
      sVar2 = strlen(__s);
      strncpy(param_1,__s,sVar2);
      return 1;
    }
  }
  return 0;
}

undefined4 TPLink_generate_password(char *param_1,int param_2) {
  int iVar1;
  FILE *pFVar2;
  size_t sVar3;
  bool bVar4;
  bool bVar5;
  char acStack_159 [64];
  char acStack_119 [129];
  char acStack_98 [132];
  
  memset(acStack_119 + 1,0,0x80);
  memset(acStack_98,0,0x80);
  memset(acStack_159 + 1,0,0x40);
  pFVar2 = popen("getfirm MODEL","r");
  if (pFVar2 != (FILE *)0x0) {
    fgets_unlocked(acStack_119 + 1,0x80,pFVar2);
    pclose(pFVar2);
    sVar3 = strlen(acStack_119 + 1);
    if (0 < (int)sVar3) {
      acStack_119[sVar3] = '\0';
      sVar3 = strlen(acStack_119 + 1);
      if (sVar3 < 100) {
        sprintf(acStack_98,"echo -n \'TProuter%s\'|md5sum|cut -d \' \' -f1",acStack_119 + 1);
        pFVar2 = popen(acStack_98,"r");
        if (pFVar2 != (FILE *)0x0) {
          fgets_unlocked(acStack_159 + 1,0x40,pFVar2);
          pclose(pFVar2);
          sVar3 = strlen(acStack_159 + 1);
          if (0 < (int)sVar3) {
            bVar5 = SBORROW4(sVar3,0xf);
            iVar1 = sVar3 - 0xf;
            bVar4 = sVar3 == 0xf;
            if (0xf < (int)sVar3) {
              bVar5 = SBORROW4(param_2,8);
              iVar1 = param_2 + -8;
              bVar4 = param_2 == 8;
            }
            acStack_159[sVar3] = '\0';
            if (!bVar4 && iVar1 < 0 == bVar5) {
              strncpy(param_1,acStack_159 + 1,8);
              param_1[8] = '\0';
              return 1;
            }
          }
        }
      }
    }
  }
  return 0;
}
```

Seems like for all TP-Link routers, the UART password is set using the md5sum of
the router's model. To get the exact hash from the model name, I used the
emulator that we've already setup and ran the same commands, which yielded the
password `c07d69da`.

```ansi
Please press Enter to activate this console.
Archer_AX53 login: root
Password:


BusyBox v1.19.4 (2023-05-30 22:35:53 CST) built-in shell (ash)
Enter 'help' for a list of built-in commands.

     MM           NM                    MMMMMMM          M       M
   $MMMMM        MMMMM                MMMMMMMMMMM      MMM     MMM
  MMMMMMMM     MM MMMMM.              MMMMM:MMMMMM:   MMMM   MMMMM
MMMM= MMMMMM  MMM   MMMM       MMMMM   MMMM  MMMMMM   MMMM  MMMMM'
MMMM=  MMMMM MMMM    MM       MMMMM    MMMM    MMMM   MMMMNMMMMM
MMMM=   MMMM  MMMMM          MMMMM     MMMM    MMMM   MMMMMMMM
MMMM=   MMMM   MMMMMM       MMMMM      MMMM    MMMM   MMMMMMMMM
MMMM=   MMMM     MMMMM,    NMMMMMMMM   MMMM    MMMM   MMMMMMMMMMM
MMMM=   MMMM      MMMMMM   MMMMMMMM    MMMM    MMMM   MMMM  MMMMMM
MMMM=   MMMM   MM    MMMM    MMMM      MMMM    MMMM   MMMM    MMMM
MMMM$ ,MMMMM  MMMMM  MMMM    MMM       MMMM   MMMMM   MMMM    MMMM
  MMMMMMM:      MMMMMMM     M         MMMMMMMMMMMM  MMMMMMM MMMMMMM
    MMMMMM       MMMMN     M           MMMMMMMMM      MMMM    MMMM
     MMMM          M                    MMMMMMM        M       M
       M
 ---------------------------------------------------------------
   For those about to rock... (Attitude Adjustment, unknown)
 ---------------------------------------------------------------
root@Archer_AX53:~#
```

Success! Now, we can start enumerating services and hunting for bugs!

# Analysis

The first step is to run `netstat` to see which services are open to the intranet.

```ansi
root@Archer_AX53:~# netstat -lnp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:20001           0.0.0.0:*               LISTEN      9268/dropbear
tcp        0      0 127.0.0.1:20002         0.0.0.0:*               LISTEN      8312/tmpServer
tcp        0      0 127.0.0.1:20015         0.0.0.0:*               LISTEN      8267/easymesh-contr
tcp        0      0 127.0.0.1:10000         0.0.0.0:*               LISTEN      9290/mcsd
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      8969/uhttpd
tcp        0      0 0.0.0.0:53              0.0.0.0:*               LISTEN      2591/dnsmasq
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      8969/uhttpd
tcp        0      0 :::80                   :::*                    LISTEN      8969/uhttpd
tcp        0      0 :::53                   :::*                    LISTEN      2591/dnsmasq
tcp        0      0 :::443                  :::*                    LISTEN      8969/uhttpd
udp        0      0 0.0.0.0:20002           0.0.0.0:*                           8313/tdpServer
udp        0      0 0.0.0.0:53              0.0.0.0:*                           2591/dnsmasq
udp        0      0 0.0.0.0:67              0.0.0.0:*                           2591/dnsmasq
udp        0      0 0.0.0.0:8080            0.0.0.0:*                           3211/cnssdaemon
udp        0      0 0.0.0.0:34207           0.0.0.0:*                           10363/conn-indicato
udp        0      0 127.0.0.1:9900          0.0.0.0:*                           1138/hostapd
udp        0      0 127.0.0.1:9902          0.0.0.0:*                           1149/wpa_supplicant
udp        0      0 :::1                    :::*                                10363/conn-indicato
udp        0      0 :::53                   :::*                                2591/dnsmasq
raw        0      0 0.0.0.0:2               0.0.0.0:*               2           21693/improxy
Active UNIX domain sockets (only servers)
Proto RefCnt Flags       Type       State         I-Node PID/Program name    Path
unix  2      [ ACC ]     STREAM     LISTENING       4627 1080/ubusd          /var/run/ubus.sock
unix  2      [ ACC ]     STREAM     LISTENING       4634 1087/ledctrl        /var/run/ledctrl_sock
unix  2      [ ACC ]     STREAM     LISTENING      15213 9717/cloud-brd      /tmp/cloud-brd
```

There are quite a few ports bound to the loopback address `0.0.0.0` here! These
services are exposed to the LAN-side of things, while those on `127.0.0.1` are
only exposed to localhost.

> Note that those exposed on LAN are still not exposed on WAN, so access to
> these services are limited to within the network only. Commonly, this is known
> as LAN-side services, as opposed to WAN-side services which are very rare.

## tdpServer

tdpServer - Tether Device Protocol - is a proprietary daemon that is used for
various purposes. Specifically, OneMesh devices communicate with each other via
this daemon, and the Tether mobile app also interfaces with this daemon. Many
other services eventually interact with this service in one way or another,
through shared memory buffers, UBus, or plaintext files in `/tmp`. 

This service has 3 main components: `tdp_ubus`, `tdp_server`, and
`tdp_broadcast`. For this article, I will only focus on the `tdp_server` and
`tdp_broadcast` components, since the `tdp_ubus` component is quite unrelated to
the other 2.

In general, the 2 components are used for OneMesh device discovery. When OneMesh
is enabled on the device, it can broadcast itself and probe for other
OneMesh-enabled devices on the same network. Based on the names of the 2
components, you can already guess what does what: `tdp_broadcast` will send
packets out to a listening `tdp_server`, which `tdp_server` will respond to with
a acknowledgement response.

The service will repeatedly broadcast packets of type 0xf0, which is a OneMesh
packet. If the receiving device is a TP-Link device, then it will collect some
info about the broadcasting device, send back a response packet to also register
itself on the broadcasting device, and the 2 devices will henceforth
continuously send packets to each other to ensure that they are still on the
network. When an admin user wishes to connect the devices via OneMesh, these
devices will already be cached in memory and hence the connection process is
very fast.

The service will also listen on UDP port 20002, listening for packets of type
0x00 (Tether app packet) or type 0xf0 (OneMesh discovery packet) and responding
accordingly. 

## dropbear

dropbear is a simple SSH client listening on port 20001 that implements port
forwarding in the TP-Link router. This version of dropbear is patched such that
the remote shell functionality is disabled, and only certain ports can be
forwarded (ports 20002 and 20003). A LAN-side attacker can interface with this
dropbear client to forward tmpServer and another service running on port
20003.

## tmpServer

tmpServer, implementing the Tether Management Protocol, is another proprietary
daemon that listens on TCP port 20002, and is mainly used by the Tether app to
remotely control certain services on the router. It needs to be forwarded via
dropbear to be interfaced with.

## mcsd

mcsd is an internal service that listens on TDP port 10000. It seems to be
some sort of service to aid debugging and logging. I'm not sure of its exact
purpose, as it only listens on the localhost interface and I didn't find any
other services that interact with it. It's likely that it was an artifact of
development that wasn't removed in the final product.

---

I'll continue to update this page with more stuff as I explore the router.
Hopefully this is helpful to others trying to get started on TP-Link vuln
research! Meanwhile, please check out the 2 other vulns I found,
[CVE-2025-15608](posts/ax53/cve-2025-15608) and
[CVE-2025-15607](posts/ax53/cve-2025-15607).
