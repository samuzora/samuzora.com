---
title: lnc-2025/feedback-form
flag: 'LNC25{"solved":true,"response":"h0pe_y0u_enj0y3d_th3_ctf"}'
files:
    - name: lnc-25-feedback-form.zip
      url: "https://github.com/samuzora/filedump/releases/download/lnc-25/lnc-25-feedback-form.zip"
---

Exploit a UAF in usage of cJSON library, and exploit the cJSON object struct
(with a bit of unsorted chunk feng shui) to get heap leak, libc leak via an 
arbitrary read in valuestring, arbitrary free via the child pointer pointing to
a fake object, and finally, RCE via House of Apple. 
[Writeup here!](/posts/lnc-2025#feedback-form)
