/*
 * ngtcp2
 *
 * Copyright (c) 2022 ngtcp2 contributors
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
#ifndef NGTCP2_BALLOC_H
#define NGTCP2_BALLOC_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <ngtcp2/ngtcp2.h>

#include "ngtcp2_buf.h"

typedef struct ngtcp2_memblock_hd ngtcp2_memblock_hd;

struct ngtcp2_memblock_hd {
  union {
    ngtcp2_memblock_hd *next;
    struct {
      uint64_t p1, p2;
    };
  };
};

typedef struct ngtcp2_balloc {
  const ngtcp2_mem *mem;
  size_t blklen;
  ngtcp2_memblock_hd *head;
  ngtcp2_buf buf;
} ngtcp2_balloc;

void ngtcp2_balloc_init(ngtcp2_balloc *balloc, size_t blklen,
                        const ngtcp2_mem *mem);

void ngtcp2_balloc_free(ngtcp2_balloc *balloc);

int ngtcp2_balloc_get(ngtcp2_balloc *balloc, void **pbuf, size_t n);

void ngtcp2_balloc_clear(ngtcp2_balloc *balloc);

#endif /* NGTCP2_BALLOC_H */
