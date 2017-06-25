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
  uint8_t *nonce;
  ngtcp2_buf cbuf;
  ngtcp2_buf pbuf;
  ngtcp2_crypto_ctx *ctx;
  uint64_t pkt_num;
  ngtcp2_mem *mem;
} ngtcp2_ppe;

/*
 * ngtcp2_ppe_init initializes |ppe| with the given buffer.
 */
int ngtcp2_ppe_init(ngtcp2_ppe *ppe, uint8_t *out, size_t outlen,
                    ngtcp2_crypto_ctx *cctx, ngtcp2_mem *mem);

void ngtcp2_ppe_free(ngtcp2_ppe *ppe);

int ngtcp2_ppe_encode_hd(ngtcp2_ppe *ppe, const ngtcp2_pkt_hd *hd);

int ngtcp2_ppe_encode_frame(ngtcp2_ppe *ppe, const ngtcp2_frame *fr);

ssize_t ngtcp2_ppe_final(ngtcp2_ppe *ppe, const uint8_t **ppkt);

#endif /* NGTCP2_PPE_H */
