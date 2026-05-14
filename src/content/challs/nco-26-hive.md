---
title: nco-2026/hive
flag: "NCO26{r00mba_t0_r00mba_c0mmun1c4ti0n_84733f86e863}"
files:
    - name: nco-hive.zip
      url: "https://github.com/samuzora/filedump/releases/download/nco-2026/hive-dist.zip"
---

A non-null terminated string seems pretty innocent at first, but with this
primitive (and a bit of spraying), we are able to build heap leaks, invalid
free, and even arb write. Based on my exploit for the TP-Link tdpServer service. [Writeup here!](/posts/nco-26)
