/*
 * ngtcp2
 *
 * Copyright (c) 2018 ngtcp2 contributors
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
#include "ngtcp2_cid.h"

#include <assert.h>
#include <string.h>

#include "ngtcp2_str.h"

void ngtcp2_cid_zero(ngtcp2_cid *cid) { cid->datalen = 0; }

void ngtcp2_cid_init(ngtcp2_cid *cid, const uint8_t *data, size_t datalen) {
  assert(datalen <= NGTCP2_MAX_CIDLEN);

  cid->datalen = datalen;
  if (datalen) {
    ngtcp2_cpymem(cid->data, data, datalen);
  }
}

int ngtcp2_cid_eq(const ngtcp2_cid *cid, const ngtcp2_cid *other) {
  return cid->datalen == other->datalen &&
         0 == memcmp(cid->data, other->data, cid->datalen);
}

int ngtcp2_cid_less(const ngtcp2_cid *lhs, const ngtcp2_cid *rhs) {
  int s = lhs->datalen < rhs->datalen;
  size_t n = s ? lhs->datalen : rhs->datalen;
  int c = memcmp(lhs->data, rhs->data, n);

  return c < 0 || (c == 0 && s);
}

int ngtcp2_cid_empty(const ngtcp2_cid *cid) { return cid->datalen == 0; }
