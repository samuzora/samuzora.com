---
title: House of Apple
date: 2023-12-05
excerpt: "Analysis of FSOP techniques: House of Apple"
category: fsop-series
tags:
    - pwn
    - fsop
---

Original article: <https://www.roderickchan.cn/zh-cn/house-of-apple-一种新的glibc中io攻击方法-1/>

Requirements:
1. can call `exit` or return from `main`
2. heap_base and libc_base
3. single largebin chunk

# Overview

In glibc, jumps from vtables are made via these macros:

```c
// example jump macro with 1 extra argument
#define JUMP1(FUNC, THIS, X1) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1)
#define WJUMP1(FUNC, THIS, X1) (_IO_WIDE_JUMPS_FUNC(THIS)->FUNC) (THIS, X1)

#define _IO_JUMPS_FUNC(THIS) (IO_validate_vtable(_IO_JUMPS_FILE_plus (THIS) + (THIS)->_vtable_offset) )
#define _IO_WIDE_JUMPS_FUNC(THIS) _IO_WIDE_JUMPS(THIS)

#define _IO_JUMPS_FILE_plus(THIS) _IO_CAST_FIELD_ACCESS ((THIS), struct _IO_FILE_plus, vtable)
#define _IO_WIDE_JUMPS(THIS) _IO_CAST_FIELD_ACCESS ((THIS), struct _IO_FILE, _wide_data)->_wide_vtable
```

The macros for `WXXX` are not protected by `IO_validate_vtable`, so we can use
this to call arbitrary function. These macros are used in functions of
`_IO_wfile_jumps` vtable:

```c
const struct _IO_jump_t _IO_wfile_jumps libio_vtable =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_new_file_finish),
  JUMP_INIT(overflow, (_IO_overflow_t) _IO_wfile_overflow),
  JUMP_INIT(underflow, (_IO_underflow_t) _IO_wfile_underflow),
  JUMP_INIT(uflow, (_IO_underflow_t) _IO_wdefault_uflow),
  JUMP_INIT(pbackfail, (_IO_pbackfail_t) _IO_wdefault_pbackfail),
  JUMP_INIT(xsputn, _IO_wfile_xsputn),
  JUMP_INIT(xsgetn, _IO_file_xsgetn),
  JUMP_INIT(seekoff, _IO_wfile_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_new_file_setbuf),
  JUMP_INIT(sync, (_IO_sync_t) _IO_wfile_sync),
  JUMP_INIT(doallocate, _IO_wfile_doallocate),
  JUMP_INIT(read, _IO_file_read),
  JUMP_INIT(write, _IO_new_file_write),
  JUMP_INIT(seek, _IO_file_seek),
  JUMP_INIT(close, _IO_file_close),
  JUMP_INIT(stat, _IO_file_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};
```

The struct of `f->_wide_data` is

```c
/* Extra data for wide character streams.  */
struct _IO_wide_data
{
  wchar_t *_IO_read_ptr;
  wchar_t *_IO_read_end;
  wchar_t *_IO_read_base;
  wchar_t *_IO_write_base; // 0x18
  wchar_t *_IO_write_ptr;
  wchar_t *_IO_write_end;
  wchar_t *_IO_buf_base; // 0x30
  wchar_t *_IO_buf_end;	
  wchar_t *_IO_save_base;
  wchar_t *_IO_backup_base;
  wchar_t *_IO_save_end;
  __mbstate_t _IO_state;
  __mbstate_t _IO_last_state;
  struct _IO_codecvt _codecvt;
  wchar_t _shortbuf[1];
  const struct _IO_jump_t *_wide_vtable; // 0xe0
};
```

It's quite similar to FILE, but vtable is at 0xe0.

## _IO_wfile_overflow

### Analysis

When `exit` is called, the FILE cleanup call stack is `fcloseall -> _IO_cleanup -> _IO_flush_all_lockp`.

```c
int _IO_flush_all_lockp (int do_lock)
{
  int result = 0;
  FILE *fp;

#ifdef _IO_MTSAFE_IO
  _IO_cleanup_region_start_noarg (flush_cleanup);
  _IO_lock_lock (list_all_lock);
#endif

  for (fp = (FILE *) _IO_list_all; fp != NULL; fp = fp->_chain)
    {
      run_fp = fp;
      if (do_lock)
	_IO_flockfile (fp);

      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
	   || (_IO_vtable_offset (fp) == 0
	       && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
				    > fp->_wide_data->_IO_write_base))
	   )
	  && _IO_OVERFLOW (fp, EOF) == EOF) // <--- overflow call
	result = EOF;

      if (do_lock)
	_IO_funlockfile (fp);
      run_fp = NULL;
    }

#ifdef _IO_MTSAFE_IO
  _IO_lock_unlock (list_all_lock);
  _IO_cleanup_region_end (0);
#endif

  return result;
}

// definition of _IO_OVERFLOW
typedef int (*_IO_overflow_t) (FILE *, int);
#define _IO_OVERFLOW(FP, CH) JUMP1 (__overflow, FP, CH)
#define _IO_WOVERFLOW(FP, CH) WJUMP1 (__overflow, FP, CH)
```

So for each FILE in `_IO_list_all`, its `vtable->__overflow` is called when the below requirements are satisfied:

1. `fp->_mode == 0`
2. `fp->_IO_write_ptr > fp->_IO_write_base`

We can set our victim FILE (`stderr`) to point to this vtable. On exit, it will call the
overflow function, `_IO_wfile_overflow`, which is defined as:

```c
wint_t _IO_wfile_overflow (FILE *f, wint_t wch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return WEOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0)
    {
      /* Allocate a buffer if needed. */
      if (f->_wide_data->_IO_write_base == 0)
	{
	  _IO_wdoallocbuf (f); // <-- call to _IO_wdallocbuf macro
	  _IO_free_wbackup_area (f);
	  _IO_wsetg (f, f->_wide_data->_IO_buf_base,
		     f->_wide_data->_IO_buf_base, f->_wide_data->_IO_buf_base);

	  if (f->_IO_write_base == NULL)
	    {
	      _IO_doallocbuf (f);
	      _IO_setg (f, f->_IO_buf_base, f->_IO_buf_base, f->_IO_buf_base);
	    }
    // ...
    }
}

void _IO_wdoallocbuf (_IO_FILE *fp)
{
  if (fp->_wide_data->_IO_buf_base)
    return;
  if (!(fp->_flags & _IO_UNBUFFERED))
    if ((wint_t)_IO_WDOALLOCATE (fp) != WEOF)
      return;
  _IO_wsetb (fp, fp->_wide_data->_shortbuf,
		     fp->_wide_data->_shortbuf + 1, 0);
}

#define _IO_WDOALLOCATE(FP) WJUMP0 (__doallocate, FP)
#define WJUMP0(FUNC, THIS) (_IO_WIDE_JUMPS_FUNC(THIS)->FUNC) (THIS)
```

The `_IO_wfile_overflow` function calls `_IO_wdoallocbuf`, which then calls
`__doallocate` of the `_wide_vtable`, passing the FILE struct as the first
argument. As mentioned, the `_wide_vtable` performs no checks so we can point
this to system.

So our call stack looks like this:

```
_IO_wfile_overflow -> _IO_wdoallocbuf -> _IO_WDOALLOCATE -> _wide_data._wide_vtable.__doallocate
```

Analyzing each of the functions, we need to satisfy:
1. `f->flags == ~(0x8 | 0x800 | 0x2)` (unset `_IO_NO_WRITES`, `_IO_CURRENTLY_PUTTING` and `_IO_UNBUFFERED`)
2. `f->_wide_data->_IO_write_base == 0`
2. `f->_wide_data->_IO_buf_base == 0`

Then our desired function goes into `__doallocate (_wide_vtable+0x68)`, and rdi goes into `flags`.

### Payload

With the above conditions satisfied, our FILE struct will look like this:

```c
// FILE
f->_flags = "  sh";
f->write_base = 0; // +0x20
f->write_ptr = 1; // +0x28
f->_wide_data = ; // <ptr to forged wide_data struct> at +0xa0
f->_mode = 0; // +0xc0 (note: pwntools FILE struct doesn't have this, but can leave as blank cos default is likely 0)
f->vtable = &_IO_wfile_jumps; // +0xd8

// _wide_data (can forge in heap etc)
_wide_data->_IO_write_base = 0; // +0x18
_wide_data->_IO_buf_base = 0; // +0x30
_wide_data->_wide_vtable = *(&(system) - 0x68); // <ptr to (system - 0x68)> at +0xe0
```

There are a few more gadget chains using `_IO_wfile_underflow_mmap`,
`_IO_wdefault_xgetn`, `_IO_wfile_underflow`, `_IO_wdo_write` and
`_IO_wfile_sync` which I will put here once I analyze them.
