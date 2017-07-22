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
#ifndef NGTCP2_PPE_H
#define NGTCP2_PPE_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <ngtcp2/ngtcp2.h>

#include "ngtcp2_buf.h"
#include "ngtcp2_crypto.h"

/*
 * ngtcp2_ppe is the Protected Packet Encoder.
 */
typedef struct {
  ngtcp2_buf buf;
  ngtcp2_crypto_ctx *ctx;
  /* hdlen is the number of bytes for packet header written in buf. */
  size_t hdlen;
  /* pkt_num is the packet number written in buf. */
  uint64_t pkt_num;
  ngtcp2_mem *mem;
  /* nonce is the buffer to store nonce.  It should be equal or longer
     than then length of IV. */
  uint8_t nonce[32];
} ngtcp2_ppe;

/*
 * ngtcp2_ppe_init initializes |ppe| with the given buffer.
 */
void ngtcp2_ppe_init(ngtcp2_ppe *ppe, uint8_t *out, size_t outlen,
                     ngtcp2_crypto_ctx *cctx, ngtcp2_mem *mem);

int ngtcp2_ppe_encode_hd(ngtcp2_ppe *ppe, const ngtcp2_pkt_hd *hd);

int ngtcp2_ppe_encode_frame(ngtcp2_ppe *ppe, const ngtcp2_frame *fr);

ssize_t ngtcp2_ppe_final(ngtcp2_ppe *ppe, const uint8_t **ppkt);

/*
 * ngtcp2_ppe_left returns the number of bytes left to write
 * additional frames.  This does not count AEAD overhead.
 */
size_t ngtcp2_ppe_left(ngtcp2_ppe *ppe);

#endif /* NGTCP2_PPE_H */
