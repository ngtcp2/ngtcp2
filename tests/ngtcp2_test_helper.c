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
#include "ngtcp2_test_helper.h"

#include <string.h>
#include <assert.h>

#include "ngtcp2_conv.h"
#include "ngtcp2_pkt.h"
#include "ngtcp2_ppe.h"
#include "ngtcp2_upe.h"

size_t ngtcp2_t_encode_stream_frame(uint8_t *out, uint8_t flags,
                                    uint64_t stream_id, uint64_t offset,
                                    uint16_t datalen) {
  uint8_t *p = out;

  if (offset) {
    flags |= NGTCP2_STREAM_OFF_BIT;
  }
  *p++ = NGTCP2_FRAME_STREAM | flags;

  p = ngtcp2_put_varint(p, stream_id);

  if (offset) {
    p = ngtcp2_put_varint(p, offset);
  }

  if (flags & NGTCP2_STREAM_LEN_BIT) {
    p = ngtcp2_put_varint(p, datalen);
  }

  memset(p, 0, datalen);
  p += datalen;

  return (size_t)(p - out);
}

size_t ngtcp2_t_encode_ack_frame(uint8_t *out, uint64_t largest_ack,
                                 uint64_t first_ack_blklen, uint64_t gap,
                                 uint64_t ack_blklen) {
  uint8_t *p = out;

  p = out;

  *p++ = NGTCP2_FRAME_ACK;
  /* Largest Acknowledged */
  p = ngtcp2_put_varint(p, largest_ack);
  /* ACK Delay */
  p = ngtcp2_put_varint(p, 0);
  /* ACK Block Count */
  p = ngtcp2_put_varint(p, 1);
  /* First ACK Block */
  p = ngtcp2_put_varint(p, first_ack_blklen);
  /* Gap (1) */
  p = ngtcp2_put_varint(p, gap);
  /* Additional ACK Block (1) */
  p = ngtcp2_put_varint(p, ack_blklen);

  return (size_t)(p - out);
}

static ssize_t null_encrypt(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                            const uint8_t *plaintext, size_t plaintextlen,
                            const uint8_t *key, size_t keylen,
                            const uint8_t *nonce, size_t noncelen,
                            const uint8_t *ad, size_t adlen, void *user_data) {
  (void)conn;
  (void)dest;
  (void)destlen;
  (void)plaintext;
  (void)key;
  (void)keylen;
  (void)nonce;
  (void)noncelen;
  (void)ad;
  (void)adlen;
  (void)user_data;
  return (ssize_t)plaintextlen;
}

size_t write_single_frame_pkt(ngtcp2_conn *conn, uint8_t *out, size_t outlen,
                              uint64_t conn_id, uint64_t pkt_num,
                              ngtcp2_frame *fr) {
  ngtcp2_crypto_ctx ctx;
  ngtcp2_ppe ppe;
  ngtcp2_pkt_hd hd;
  int rv;
  ssize_t n;

  memset(&ctx, 0, sizeof(ctx));
  ctx.encrypt = null_encrypt;
  ctx.ckm = conn->rx_ckm;
  ctx.user_data = conn;

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_03, conn_id, pkt_num,
                     NGTCP2_PROTO_VER_MAX);

  ngtcp2_ppe_init(&ppe, out, outlen, &ctx);
  rv = ngtcp2_ppe_encode_hd(&ppe, &hd);
  assert(0 == rv);
  rv = ngtcp2_ppe_encode_frame(&ppe, fr);
  assert(0 == rv);
  n = ngtcp2_ppe_final(&ppe, NULL);
  assert(n > 0);
  return (size_t)n;
}

size_t write_single_frame_pkt_without_conn_id(ngtcp2_conn *conn, uint8_t *out,
                                              size_t outlen, uint64_t pkt_num,
                                              ngtcp2_frame *fr) {
  ngtcp2_crypto_ctx ctx;
  ngtcp2_ppe ppe;
  ngtcp2_pkt_hd hd;
  int rv;
  ssize_t n;

  memset(&ctx, 0, sizeof(ctx));
  ctx.encrypt = null_encrypt;
  ctx.ckm = conn->rx_ckm;
  ctx.user_data = conn;

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_OMIT_CONN_ID, NGTCP2_PKT_03, 0,
                     pkt_num, NGTCP2_PROTO_VER_MAX);

  ngtcp2_ppe_init(&ppe, out, outlen, &ctx);
  rv = ngtcp2_ppe_encode_hd(&ppe, &hd);
  assert(0 == rv);
  rv = ngtcp2_ppe_encode_frame(&ppe, fr);
  assert(0 == rv);
  n = ngtcp2_ppe_final(&ppe, NULL);
  assert(n > 0);
  return (size_t)n;
}

size_t write_single_frame_handshake_pkt(uint8_t *out, size_t outlen,
                                        uint8_t pkt_type, uint64_t conn_id,
                                        uint64_t pkt_num, uint32_t version,
                                        ngtcp2_frame *fr) {
  ngtcp2_upe upe;
  ngtcp2_pkt_hd hd;
  int rv;

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_LONG_FORM, pkt_type, conn_id, pkt_num,
                     version);

  ngtcp2_upe_init(&upe, out, outlen);
  rv = ngtcp2_upe_encode_hd(&upe, &hd);
  assert(0 == rv);
  rv = ngtcp2_upe_encode_frame(&upe, fr);
  assert(0 == rv);
  return ngtcp2_upe_final(&upe, NULL);
}

ngtcp2_strm *open_stream(ngtcp2_conn *conn, uint64_t stream_id) {
  ngtcp2_strm *strm;
  int rv;

  strm = ngtcp2_mem_malloc(conn->mem, sizeof(ngtcp2_strm));
  assert(strm);

  rv = ngtcp2_conn_init_stream(conn, strm, stream_id, NULL);
  assert(0 == rv);

  return strm;
}
