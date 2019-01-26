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
#include "ngtcp2_ppe.h"

#include <string.h>
#include <assert.h>

#include "ngtcp2_pkt.h"
#include "ngtcp2_str.h"
#include "ngtcp2_conv.h"
#include "ngtcp2_conn.h"
#include "ngtcp2_macro.h"

void ngtcp2_ppe_init(ngtcp2_ppe *ppe, uint8_t *out, size_t outlen,
                     ngtcp2_crypto_ctx *cctx) {
  ngtcp2_buf_init(&ppe->buf, out, outlen);

  ppe->hdlen = 0;
  ppe->len_offset = 0;
  ppe->pkt_num_offset = 0;
  ppe->pkt_numlen = 0;
  ppe->pkt_num = 0;
  ppe->sample_offset = 0;
  ppe->ctx = cctx;
}

int ngtcp2_ppe_encode_hd(ngtcp2_ppe *ppe, const ngtcp2_pkt_hd *hd) {
  ssize_t rv;
  ngtcp2_buf *buf = &ppe->buf;
  ngtcp2_crypto_ctx *ctx = ppe->ctx;

  if (ngtcp2_buf_left(buf) < ctx->aead_overhead) {
    return NGTCP2_ERR_NOBUF;
  }

  if (hd->flags & NGTCP2_PKT_FLAG_LONG_FORM) {
    ppe->len_offset = 1 + 4 + 1 + hd->dcid.datalen + hd->scid.datalen;
    if (hd->type == NGTCP2_PKT_INITIAL) {
      ppe->len_offset += ngtcp2_put_varint_len(hd->tokenlen) + hd->tokenlen;
    }
    ppe->pkt_num_offset = ppe->len_offset + 2;
    rv = ngtcp2_pkt_encode_hd_long(
        buf->last, ngtcp2_buf_left(buf) - ctx->aead_overhead, hd);
  } else {
    ppe->pkt_num_offset = 1 + hd->dcid.datalen;
    rv = ngtcp2_pkt_encode_hd_short(
        buf->last, ngtcp2_buf_left(buf) - ctx->aead_overhead, hd);
  }
  if (rv < 0) {
    return (int)rv;
  }

  ppe->sample_offset = ppe->pkt_num_offset + 4;

  buf->last += rv;

  ppe->pkt_numlen = hd->pkt_numlen;
  ppe->hdlen = (size_t)rv;

  ppe->pkt_num = hd->pkt_num;

  return 0;
}

int ngtcp2_ppe_encode_frame(ngtcp2_ppe *ppe, ngtcp2_frame *fr) {
  ssize_t rv;
  ngtcp2_buf *buf = &ppe->buf;
  ngtcp2_crypto_ctx *ctx = ppe->ctx;

  if (ngtcp2_buf_left(buf) < ctx->aead_overhead) {
    return NGTCP2_ERR_NOBUF;
  }

  rv = ngtcp2_pkt_encode_frame(buf->last,
                               ngtcp2_buf_left(buf) - ctx->aead_overhead, fr);
  if (rv < 0) {
    return (int)rv;
  }

  buf->last += rv;

  return 0;
}

ssize_t ngtcp2_ppe_final(ngtcp2_ppe *ppe, const uint8_t **ppkt) {
  ssize_t nwrite;
  ngtcp2_buf *buf = &ppe->buf;
  ngtcp2_crypto_ctx *ctx = ppe->ctx;
  ngtcp2_conn *conn = ctx->user_data;
  uint8_t *payload = buf->begin + ppe->hdlen;
  size_t payloadlen = ngtcp2_buf_len(buf) - ppe->hdlen;
  size_t destlen = (size_t)(buf->end - buf->begin) - ppe->hdlen;
  uint8_t mask[NGTCP2_HP_SAMPLELEN];
  uint8_t *p;
  size_t i;

  assert(ppe->ctx->encrypt);
  assert(ppe->ctx->hp_mask);

  if (ppe->len_offset) {
    ngtcp2_put_varint14(
        buf->begin + ppe->len_offset,
        (uint16_t)(payloadlen + ppe->pkt_numlen + ctx->aead_overhead));
  }

  ngtcp2_crypto_create_nonce(ppe->nonce, ctx->ckm->iv.base, ctx->ckm->iv.len,
                             ppe->pkt_num);

  nwrite = ppe->ctx->encrypt(conn, payload, destlen, payload, payloadlen,
                             ctx->ckm->key.base, ctx->ckm->key.len, ppe->nonce,
                             ctx->ckm->iv.len, buf->begin, ppe->hdlen,
                             conn->user_data);
  if (nwrite < 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  buf->last = payload + nwrite;

  /* TODO Check that we have enough space to get sample */
  assert(ppe->sample_offset + NGTCP2_HP_SAMPLELEN <= ngtcp2_buf_len(buf));

  nwrite = ppe->ctx->hp_mask(conn, mask, sizeof(mask), ctx->hp->base,
                             ctx->hp->len, buf->begin + ppe->sample_offset,
                             NGTCP2_HP_SAMPLELEN, conn->user_data);
  if (nwrite < NGTCP2_HP_MASKLEN) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  p = buf->begin;
  if (*p & NGTCP2_HEADER_FORM_BIT) {
    *p = (uint8_t)(*p ^ (mask[0] & 0x0f));
  } else {
    *p = (uint8_t)(*p ^ (mask[0] & 0x1f));
  }

  p = buf->begin + ppe->pkt_num_offset;
  for (i = 0; i < ppe->pkt_numlen; ++i) {
    *(p + i) ^= mask[i + 1];
  }

  if (ppkt != NULL) {
    *ppkt = buf->begin;
  }

  return (ssize_t)ngtcp2_buf_len(buf);
}

size_t ngtcp2_ppe_left(ngtcp2_ppe *ppe) {
  ngtcp2_crypto_ctx *ctx = ppe->ctx;

  if (ngtcp2_buf_left(&ppe->buf) < ctx->aead_overhead) {
    return 0;
  }

  return ngtcp2_buf_left(&ppe->buf) - ctx->aead_overhead;
}

size_t ngtcp2_ppe_padding(ngtcp2_ppe *ppe) {
  ngtcp2_crypto_ctx *ctx = ppe->ctx;
  ngtcp2_buf *buf = &ppe->buf;
  size_t len;

  assert(ngtcp2_buf_left(buf) >= ctx->aead_overhead);

  len = ngtcp2_buf_left(buf) - ctx->aead_overhead;
  memset(buf->last, 0, len);
  buf->last += len;

  return len;
}

size_t ngtcp2_ppe_padding_hp_sample(ngtcp2_ppe *ppe) {
  ngtcp2_crypto_ctx *ctx = ppe->ctx;
  ngtcp2_buf *buf = &ppe->buf;
  size_t max_samplelen;
  size_t len = 0;

  max_samplelen = ngtcp2_buf_len(buf) + ctx->aead_overhead - ppe->sample_offset;
  if (max_samplelen < NGTCP2_HP_SAMPLELEN) {
    len = NGTCP2_HP_SAMPLELEN - max_samplelen;
    assert(ngtcp2_ppe_left(ppe) >= len);
    memset(buf->last, 0, len);
    buf->last += len;
  }

  return len;
}

int ngtcp2_ppe_ensure_hp_sample(ngtcp2_ppe *ppe) {
  ngtcp2_buf *buf = &ppe->buf;
  return ngtcp2_buf_left(buf) >= (4 - ppe->pkt_numlen) + NGTCP2_HP_SAMPLELEN;
}
