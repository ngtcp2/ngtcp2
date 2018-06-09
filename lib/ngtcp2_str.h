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
#ifndef NGTCP2_STR_H
#define NGTCP2_STR_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <ngtcp2/ngtcp2.h>

/* ngtcp2_array is a fixed size array. */
typedef struct {
  /* base points to the beginning of the buffer. */
  uint8_t *base;
  /* len is the capacity of the buffer. */
  size_t len;
} ngtcp2_array;

uint8_t *ngtcp2_cpymem(uint8_t *dest, const uint8_t *src, size_t n);

/*
 * ngtcp2_encode_hex encodes |data| of length |len| in hex string.  It
 * writes additional NULL bytes at the end of the buffer.  The buffer
 * pointed by |dest| must have at least |len| * 2 + 1 bytes space.
 * This function returns |dest|.
 */
uint8_t *ngtcp2_encode_hex(uint8_t *dest, const uint8_t *data, size_t len);

#endif /* NGTCP2_STR_H */
