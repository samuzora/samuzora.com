---
title: blahaj-2023/christmas
flag: "blahaj{i_h3ar_th0se_sl3igh_sh3lls_r1nging}"
files:
    - name: blahaj-23-christmas.zip
      url: "https://github.com/samuzora/filedump/releases/download/blahaj-2023-christmas/blahaj-23-christmas.zip"
---

The stack contains an array of heap pointers, as well as a const limit 
variable that appears to decompilers, like IDA, as a primitive value, due to 
the const marker. A negative OOB write from the array can overwrite this limit, 
which then grants us positive OOB read/write, which we can use to do leaks, 
double free, and RCE.
