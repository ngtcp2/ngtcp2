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
#include "ngtcp2_upe.h"

#include <assert.h>
#include <string.h>

#include "ngtcp2_pkt.h"
#include "ngtcp2_str.h"
#include "ngtcp2_conv.h"

void ngtcp2_upe_init(ngtcp2_upe *upe, uint8_t *out, size_t outlen) {
  ngtcp2_buf_init(&upe->buf, out, outlen);
}

int ngtcp2_upe_encode_hd(ngtcp2_upe *upe, const ngtcp2_pkt_hd *hd) {
  /* Unprotected Packet always has long header */
  ssize_t rv;
  ngtcp2_buf *buf = &upe->buf;

  rv = ngtcp2_pkt_encode_hd_long(buf->last, ngtcp2_buf_left(buf), hd);
  if (rv < 0) {
    return (int)rv;
  }

  buf->last += rv;

  return 0;
}

int ngtcp2_upe_encode_frame(ngtcp2_upe *upe, const ngtcp2_frame *fm) {
  ssize_t rv;
  ngtcp2_buf *buf = &upe->buf;

  if (ngtcp2_buf_left(buf) < NGTCP2_PKT_MDLEN) {
    return NGTCP2_ERR_NOBUF;
  }

  rv = ngtcp2_pkt_encode_frame(buf->last,
                               ngtcp2_buf_left(buf) - NGTCP2_PKT_MDLEN, fm);
  if (rv < 0) {
    return (int)rv;
  }

  buf->last += rv;

  return 0;
}

void ngtcp2_upe_padding(ngtcp2_upe *upe) {
  ngtcp2_buf *buf = &upe->buf;
  size_t len;

  assert(ngtcp2_buf_left(buf) >= NGTCP2_PKT_MDLEN);

  len = ngtcp2_buf_left(buf) - NGTCP2_PKT_MDLEN;
  memset(buf->last, 0, len);
  buf->last += len;
}

size_t ngtcp2_upe_final(ngtcp2_upe *upe, const uint8_t **ppkt) {
  ngtcp2_buf *buf = &upe->buf;
  uint64_t h;

  assert(ngtcp2_buf_left(buf) >= NGTCP2_PKT_MDLEN);

  h = ngtcp2_fnv1a(buf->begin, ngtcp2_buf_len(buf));
  buf->last = ngtcp2_put_uint64be(buf->last, h);

  *ppkt = buf->begin;

  return ngtcp2_buf_len(buf);
}
