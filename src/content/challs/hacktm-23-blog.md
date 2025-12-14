---
title: hacktm-2023/blog
flag: "HackTM{r3t__toString_1s_s0_fun_13c573f6}"
files:
    - name: hacktm-23-blog.zip
      url: "https://github.com/samuzora/filedump/releases/download/hacktm-ctf-2023/hacktm-23-blog.zip"
---

Using PHP deserialization, we craft an object that when extracted, exploits the
provided SQLite database interface to create a new SQLite database file. This
file contains our PHP webshell hence leading to RCE.
