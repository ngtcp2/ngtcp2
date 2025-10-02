/*
 * ngtcp2
 *
 * Copyright (c) 2017 ngtcp2 contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include "ngtcp2_ringbuf.h"

#include <assert.h>
#ifdef WIN32
#  include <intrin.h>
#endif /* defined(WIN32) */

#include "ngtcp2_macro.h"

#ifndef NDEBUG
/* Provide fastest path when POPCNT is available: we detect once and then
   call the selected implementation without an extra branch each time. */
#  if defined(_MSC_VER) && !defined(__clang__) &&                              \
    (defined(_M_ARM) || (defined(_M_ARM64) && _MSC_VER < 1941))
static int ispow2(size_t n) { /* Simple portable fallback */
  return n && !(n & (n - 1));
}
#  elif defined(WIN32)
#    if defined(_M_IX86) || defined(_M_X64)
static int ispow2_popcnt(size_t n) { return 1 == __popcnt((unsigned int)n); }
#    endif /* x86/x64 */
static int ispow2_fallback(size_t n) { return n && !(n & (n - 1)); }
#    if defined(_M_IX86) || defined(_M_X64)
static int ispow2_runtime(size_t n) {
  int info[4] = {0};
  __cpuid(info, 1);
  /* ECX bit 23 indicates POPCNT support */
  if (info[2] & (1 << 23)) {
    /* Publish chosen implementation; benign data race acceptable in debug */
    extern int (*ngtcp2_ispow2_impl)(size_t); /* forward */
    ngtcp2_ispow2_impl = ispow2_popcnt;
  } else {
    extern int (*ngtcp2_ispow2_impl)(size_t);
    ngtcp2_ispow2_impl = ispow2_fallback;
  }
  return ngtcp2_ispow2_impl(n);
}
static int (*ngtcp2_ispow2_impl)(size_t) = ispow2_runtime;
static int ispow2(size_t n) { return ngtcp2_ispow2_impl(n); }
#    else  /* non x86/x64 WIN32 (e.g. ARM) */
static int ispow2(size_t n) { return ispow2_fallback(n); }
#    endif /* defined(_M_IX86) || defined(_M_X64) */
#  else  /* other toolchains */
static int ispow2(size_t n) { return 1 == __builtin_popcount((unsigned int)n); }
#  endif /* platform selection */
#endif /* !defined(NDEBUG) */

int ngtcp2_ringbuf_init(ngtcp2_ringbuf *rb, size_t nmemb, size_t size,
                        const ngtcp2_mem *mem) {
  uint8_t *buf = ngtcp2_mem_malloc(mem, nmemb * size);

  if (buf == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  ngtcp2_ringbuf_buf_init(rb, nmemb, size, buf, mem);

  return 0;
}

void ngtcp2_ringbuf_buf_init(ngtcp2_ringbuf *rb, size_t nmemb, size_t size,
                             uint8_t *buf, const ngtcp2_mem *mem) {
  assert(ispow2(nmemb));

  rb->buf = buf;
  rb->mem = mem;
  rb->mask = nmemb - 1;
  rb->size = size;
  rb->first = 0;
  rb->len = 0;
}

void ngtcp2_ringbuf_free(ngtcp2_ringbuf *rb) {
  if (rb == NULL) {
    return;
  }

  ngtcp2_mem_free(rb->mem, rb->buf);
}

void *ngtcp2_ringbuf_push_front(ngtcp2_ringbuf *rb) {
  rb->first = (rb->first - 1) & rb->mask;
  if (rb->len < rb->mask + 1) {
    ++rb->len;
  }

  return (void *)&rb->buf[rb->first * rb->size];
}

void *ngtcp2_ringbuf_push_back(ngtcp2_ringbuf *rb) {
  size_t offset = (rb->first + rb->len) & rb->mask;

  if (rb->len == rb->mask + 1) {
    rb->first = (rb->first + 1) & rb->mask;
  } else {
    ++rb->len;
  }

  return (void *)&rb->buf[offset * rb->size];
}

void ngtcp2_ringbuf_pop_front(ngtcp2_ringbuf *rb) {
  rb->first = (rb->first + 1) & rb->mask;
  --rb->len;
}

void ngtcp2_ringbuf_pop_back(ngtcp2_ringbuf *rb) {
  assert(rb->len);
  --rb->len;
}

void ngtcp2_ringbuf_resize(ngtcp2_ringbuf *rb, size_t len) {
  assert(len <= rb->mask + 1);
  rb->len = len;
}

void *ngtcp2_ringbuf_get(const ngtcp2_ringbuf *rb, size_t offset) {
  assert(offset < rb->len);
  offset = (rb->first + offset) & rb->mask;

  return &rb->buf[offset * rb->size];
}

int ngtcp2_ringbuf_full(const ngtcp2_ringbuf *rb) {
  return rb->len == rb->mask + 1;
}
