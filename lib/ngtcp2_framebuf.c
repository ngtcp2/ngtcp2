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
#include "ngtcp2_framebuf.h"

#include <string.h>

int ngtcp2_framebuf_new(ngtcp2_framebuf **pfb, ngtcp2_stream *fm,
                        ngtcp2_mem *mem) {
  uint8_t *data;

  *pfb = ngtcp2_mem_malloc(mem, sizeof(ngtcp2_framebuf) + fm->datalen);
  if (*pfb == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  data = ((uint8_t *)*pfb) + sizeof(ngtcp2_framebuf);
  memcpy(data, fm->data, fm->datalen);

  (*pfb)->fm.stream = *fm;
  (*pfb)->fm.stream.data = data;

  return 0;
}

void ngtcp2_framebuf_del(ngtcp2_framebuf *fb, ngtcp2_mem *mem) {
  ngtcp2_mem_free(mem, fb);
}
