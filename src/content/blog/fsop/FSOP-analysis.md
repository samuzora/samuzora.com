---
title: Analysis of FSOP techniques
date: 2023-12-04
excerpt: FSOP series introduction
category: fsop-series
tags:
  - pwn
  - fsop
---

`_IO_FILE_PLUS` struct is a powerful target to attack after getting a single
arb write. It has a pointer to a vtable that contains different functions to
perform read/write etc.

```c
struct _IO_FILE
{
  int _flags; // 0x00
  char *_IO_read_ptr; // 0x08
  char *_IO_read_end; // 0x10
  char *_IO_read_base; // 0x18
  char *_IO_write_base;	// 0x20
  char *_IO_write_ptr; // 0x28
  char *_IO_write_end; // 0x30
  char *_IO_buf_base; // 0x38
  char *_IO_buf_end; // 0x40
  char *_IO_save_base; // 0x48
  char *_IO_backup_base; // 0x50
  char *_IO_save_end; // 0x58
  struct _IO_marker *_markers; // 0x60
  struct _IO_FILE *_chain; // 0x68
  int _fileno; // 0x70
  int _flags2; // 0x78
  __off_t _old_offset;
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];
  _IO_lock_t *_lock;
  __off64_t _offset;
  struct _IO_codecvt *_codecvt; // 0x98
  struct _IO_wide_data *_wide_data; // 0xa0
  struct _IO_FILE *_freeres_list; // 0xa8
  void *_freeres_buf; // 0xb0
  size_t __pad5; // 0xb8
  int _mode; // 0xc0
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
};

struct _IO_FILE_plus
{
  FILE file;
  const struct _IO_jump_t *vtable; // 0xd8
};
```

Unfortunately, >2.23 there is a check to make sure that the vtable pointer is
pointing to a valid vtable in the `__libc_IO_vtables` section:

```c
/* Perform vtable pointer validation.  If validation fails, terminate
   the process.  */
static inline const struct _IO_jump_t *
IO_validate_vtable (const struct _IO_jump_t *vtable)
{
  /* Fast path: The vtable pointer is within the __libc_IO_vtables
     section.  */
  uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables;
  const char *ptr = (const char *) vtable;
  uintptr_t offset = ptr - __start___libc_IO_vtables;
  if (__glibc_unlikely (offset >= section_length))
    /* The vtable pointer is not in the expected section.  Use the
       slow path, which will terminate the process if necessary.  */
    _IO_vtable_check ();
  return vtable;
}

void attribute_hidden _IO_vtable_check (void)
{
#ifdef SHARED
  /* Honor the compatibility flag.  */
  void (*flag) (void) = atomic_load_relaxed (&IO_accept_foreign_vtables);
#ifdef PTR_DEMANGLE
  PTR_DEMANGLE (flag);
#endif
  if (flag == &_IO_vtable_check)
    return;

  /* In case this libc copy is in a non-default namespace, we always
     need to accept foreign vtables because there is always a
     possibility that FILE * objects are passed across the linking
     boundary.  */
  {
    Dl_info di;
    struct link_map *l;
    if (_dl_open_hook != NULL
        || (_dl_addr (_IO_vtable_check, &di, &l, NULL) != 0
            && l->l_ns != LM_ID_BASE))
      return;
  }

#else /* !SHARED */
  /* We cannot perform vtable validation in the static dlopen case
     because FILE * handles might be passed back and forth across the
     boundary.  Therefore, we disable checking in this case.  */
  if (__dlopen != NULL)
    return;
#endif

  __libc_fatal ("Fatal error: glibc detected an invalid stdio handle\n");
}
```

With this check the vtable pointer must be one of the vtables defined
[here](https://elixir.bootlin.com/glibc/glibc-2.38/source/libio/vtables.c).
This actually makes things quite fun - how can we exploit these vtables and
other FILE features to get RCE?

The next few posts will be my notes while exploring some previously discovered houses.

- <a href="/posts/fsop/house-of-apple">House of Apple</a>
- House of Kiwi
- House of Banana
- House of Emma
- House of Pig
