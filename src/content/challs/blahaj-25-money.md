---
title: blahaj-2025/money
flag: blahaj{d0es_th1s_c0un7_a5_a_bl0ckch41n_ch4ll?}
files:
    - name: blahaj-25-money.zip
      url: "https://github.com/samuzora/filedump/releases/download/blahaj-2025-money/money.zip"
---

The challenge moves an object and replaces it with a locked object, rendering
the object unusable. We exploit the negative size of `ob_size` in longs, allowing
for negative OOB. The negative OOB allows us to modify the copy size of the
attacker object, which causes us to read out-of-bounds from the original
attacker object and overwrite into another lock object's buffer, eventually
leading to `fakeobj` primitive. [Writeup here!](/posts/blahaj-2025)
