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
#include "ngtcp2_vec.h"

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

static int null_encrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                        const uint8_t *plaintext, size_t plaintextlen,
                        const uint8_t *key, const uint8_t *nonce,
                        size_t noncelen, const uint8_t *ad, size_t adlen) {
  (void)dest;
  (void)aead;
  (void)plaintext;
  (void)plaintextlen;
  (void)key;
  (void)nonce;
  (void)noncelen;
  (void)ad;
  (void)adlen;
  memset(dest + plaintextlen, 0, NGTCP2_FAKE_AEAD_OVERHEAD);
  return 0;
}

static int null_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                        const uint8_t *hp_key, const uint8_t *sample) {
  (void)hp;
  (void)hp_key;
  (void)sample;
  memcpy(dest, NGTCP2_FAKE_HP_MASK, sizeof(NGTCP2_FAKE_HP_MASK) - 1);
  return 0;
}

size_t write_single_frame_pkt(ngtcp2_conn *conn, uint8_t *out, size_t outlen,
                              const ngtcp2_cid *dcid, int64_t pkt_num,
                              ngtcp2_frame *fr) {
  return write_single_frame_pkt_flags(conn, out, outlen, NGTCP2_PKT_FLAG_NONE,
                                      dcid, pkt_num, fr);
}

size_t write_single_frame_pkt_flags(ngtcp2_conn *conn, uint8_t *out,
                                    size_t outlen, uint8_t flags,
                                    const ngtcp2_cid *dcid, int64_t pkt_num,
                                    ngtcp2_frame *fr) {
  ngtcp2_crypto_cc cc;
  ngtcp2_ppe ppe;
  ngtcp2_pkt_hd hd;
  int rv;
  ngtcp2_ssize n;

  memset(&cc, 0, sizeof(cc));
  cc.encrypt = null_encrypt;
  cc.hp_mask = null_hp_mask;
  cc.ckm = conn->pktns.crypto.rx.ckm;
  cc.hp_key = conn->pktns.crypto.rx.hp_key;
  cc.aead_overhead = NGTCP2_FAKE_AEAD_OVERHEAD;

  ngtcp2_pkt_hd_init(&hd, flags, NGTCP2_PKT_SHORT, dcid, NULL, pkt_num, 4,
                     NGTCP2_PROTO_VER_MAX, 0);

  ngtcp2_ppe_init(&ppe, out, outlen, &cc);
  rv = ngtcp2_ppe_encode_hd(&ppe, &hd);
  assert(0 == rv);
  rv = ngtcp2_ppe_encode_frame(&ppe, fr);
  assert(0 == rv);
  n = ngtcp2_ppe_final(&ppe, NULL);
  assert(n > 0);

  return (size_t)n;
}

size_t write_pkt(ngtcp2_conn *conn, uint8_t *out, size_t outlen,
                 const ngtcp2_cid *dcid, int64_t pkt_num, ngtcp2_frame *fr,
                 size_t frlen) {
  return write_pkt_flags(conn, out, outlen, NGTCP2_PKT_FLAG_NONE, dcid, pkt_num,
                         fr, frlen);
}

size_t write_pkt_flags(ngtcp2_conn *conn, uint8_t *out, size_t outlen,
                       uint8_t flags, const ngtcp2_cid *dcid, int64_t pkt_num,
                       ngtcp2_frame *fr, size_t frlen) {
  ngtcp2_crypto_cc cc;
  ngtcp2_ppe ppe;
  ngtcp2_pkt_hd hd;
  int rv;
  ngtcp2_ssize n;
  size_t i;

  memset(&cc, 0, sizeof(cc));
  cc.encrypt = null_encrypt;
  cc.hp_mask = null_hp_mask;
  cc.ckm = conn->pktns.crypto.rx.ckm;
  cc.hp_key = conn->pktns.crypto.rx.hp_key;
  cc.aead_overhead = NGTCP2_FAKE_AEAD_OVERHEAD;

  ngtcp2_pkt_hd_init(&hd, flags, NGTCP2_PKT_SHORT, dcid, NULL, pkt_num, 4,
                     NGTCP2_PROTO_VER_MAX, 0);

  ngtcp2_ppe_init(&ppe, out, outlen, &cc);
  rv = ngtcp2_ppe_encode_hd(&ppe, &hd);
  assert(0 == rv);

  for (i = 0; i < frlen; ++i, ++fr) {
    rv = ngtcp2_ppe_encode_frame(&ppe, fr);
    assert(0 == rv);
  }

  n = ngtcp2_ppe_final(&ppe, NULL);
  assert(n > 0);

  return (size_t)n;
}

size_t write_single_frame_pkt_without_conn_id(ngtcp2_conn *conn, uint8_t *out,
                                              size_t outlen, int64_t pkt_num,
                                              ngtcp2_frame *fr) {
  ngtcp2_crypto_cc cc;
  ngtcp2_ppe ppe;
  ngtcp2_pkt_hd hd;
  int rv;
  ngtcp2_ssize n;

  memset(&cc, 0, sizeof(cc));
  cc.encrypt = null_encrypt;
  cc.hp_mask = null_hp_mask;
  cc.ckm = conn->pktns.crypto.rx.ckm;
  cc.hp_key = conn->pktns.crypto.rx.hp_key;
  cc.aead_overhead = NGTCP2_FAKE_AEAD_OVERHEAD;

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_SHORT, NULL, NULL,
                     pkt_num, 4, NGTCP2_PROTO_VER_MAX, 0);

  ngtcp2_ppe_init(&ppe, out, outlen, &cc);
  rv = ngtcp2_ppe_encode_hd(&ppe, &hd);
  assert(0 == rv);
  rv = ngtcp2_ppe_encode_frame(&ppe, fr);
  assert(0 == rv);
  n = ngtcp2_ppe_final(&ppe, NULL);
  assert(n > 0);
  return (size_t)n;
}

size_t write_single_frame_handshake_pkt(ngtcp2_conn *conn, uint8_t *out,
                                        size_t outlen, uint8_t pkt_type,
                                        const ngtcp2_cid *dcid,
                                        const ngtcp2_cid *scid, int64_t pkt_num,
                                        uint32_t version, ngtcp2_frame *fr) {
  ngtcp2_crypto_cc cc;
  ngtcp2_ppe ppe;
  ngtcp2_pkt_hd hd;
  int rv;
  ngtcp2_ssize n;

  memset(&cc, 0, sizeof(cc));
  cc.encrypt = null_encrypt;
  cc.hp_mask = null_hp_mask;
  switch (pkt_type) {
  case NGTCP2_PKT_INITIAL:
    cc.ckm = conn->in_pktns->crypto.rx.ckm;
    cc.hp_key = conn->in_pktns->crypto.rx.hp_key;
    cc.aead_overhead = NGTCP2_INITIAL_AEAD_OVERHEAD;
    break;
  case NGTCP2_PKT_HANDSHAKE:
    cc.ckm = conn->hs_pktns->crypto.rx.ckm;
    cc.hp_key = conn->hs_pktns->crypto.rx.hp_key;
    cc.aead_overhead = NGTCP2_FAKE_AEAD_OVERHEAD;
    break;
  default:
    assert(0);
  }

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_LONG_FORM, pkt_type, dcid, scid,
                     pkt_num, 4, version, 0);

  ngtcp2_ppe_init(&ppe, out, outlen, &cc);
  rv = ngtcp2_ppe_encode_hd(&ppe, &hd);
  assert(0 == rv);
  rv = ngtcp2_ppe_encode_frame(&ppe, fr);
  assert(0 == rv);
  n = ngtcp2_ppe_final(&ppe, NULL);
  assert(n > 0);
  return (size_t)n;
}

size_t write_single_frame_initial_pkt(ngtcp2_conn *conn, uint8_t *out,
                                      size_t outlen, const ngtcp2_cid *dcid,
                                      const ngtcp2_cid *scid, int64_t pkt_num,
                                      uint32_t version, ngtcp2_frame *fr,
                                      const uint8_t *token, size_t tokenlen) {
  ngtcp2_crypto_cc cc;
  ngtcp2_ppe ppe;
  ngtcp2_pkt_hd hd;
  int rv;
  ngtcp2_ssize n;

  memset(&cc, 0, sizeof(cc));
  cc.encrypt = null_encrypt;
  cc.hp_mask = null_hp_mask;
  cc.ckm = conn->in_pktns->crypto.rx.ckm;
  cc.hp_key = conn->in_pktns->crypto.rx.hp_key;
  cc.aead_overhead = NGTCP2_INITIAL_AEAD_OVERHEAD;

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_LONG_FORM, NGTCP2_PKT_INITIAL, dcid,
                     scid, pkt_num, 4, version, 0);
  hd.token = (uint8_t *)token;
  hd.tokenlen = tokenlen;

  ngtcp2_ppe_init(&ppe, out, outlen, &cc);
  rv = ngtcp2_ppe_encode_hd(&ppe, &hd);
  assert(0 == rv);
  rv = ngtcp2_ppe_encode_frame(&ppe, fr);
  assert(0 == rv);
  n = ngtcp2_ppe_final(&ppe, NULL);
  assert(n > 0);
  return (size_t)n;
}

size_t write_single_frame_0rtt_pkt(ngtcp2_conn *conn, uint8_t *out,
                                   size_t outlen, const ngtcp2_cid *dcid,
                                   const ngtcp2_cid *scid, int64_t pkt_num,
                                   uint32_t version, ngtcp2_frame *fr,
                                   const uint8_t *key, const uint8_t *iv,
                                   const uint8_t *hp_key, size_t keylen,
                                   size_t ivlen) {
  ngtcp2_crypto_km *ckm;
  ngtcp2_vec hp_keyv;
  ngtcp2_crypto_cc cc;
  ngtcp2_ppe ppe;
  ngtcp2_pkt_hd hd;
  int rv;
  ngtcp2_ssize n;

  rv = ngtcp2_crypto_km_new(&ckm, NULL, 0, key, keylen, iv, ivlen, conn->mem);

  assert(rv == 0);

  memset(&cc, 0, sizeof(cc));
  cc.encrypt = null_encrypt;
  cc.hp_mask = null_hp_mask;
  cc.ckm = ckm;
  cc.hp_key = ngtcp2_vec_init(&hp_keyv, hp_key, keylen);
  cc.aead_overhead = NGTCP2_FAKE_AEAD_OVERHEAD;

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_LONG_FORM, NGTCP2_PKT_0RTT, dcid,
                     scid, pkt_num, 4, version, 0);

  ngtcp2_ppe_init(&ppe, out, outlen, &cc);
  rv = ngtcp2_ppe_encode_hd(&ppe, &hd);
  assert(0 == rv);
  rv = ngtcp2_ppe_encode_frame(&ppe, fr);
  assert(0 == rv);
  n = ngtcp2_ppe_final(&ppe, NULL);
  assert(n > 0);

  ngtcp2_crypto_km_del(ckm, conn->mem);

  return (size_t)n;
}

size_t write_handshake_pkt(ngtcp2_conn *conn, uint8_t *out, size_t outlen,
                           uint8_t pkt_type, const ngtcp2_cid *dcid,
                           const ngtcp2_cid *scid, int64_t pkt_num,
                           uint32_t version, ngtcp2_frame *fra, size_t frlen) {
  ngtcp2_crypto_cc cc;
  ngtcp2_ppe ppe;
  ngtcp2_pkt_hd hd;
  ngtcp2_frame *fr;
  int rv;
  ngtcp2_ssize n;
  size_t i;

  memset(&cc, 0, sizeof(cc));
  cc.encrypt = null_encrypt;
  cc.hp_mask = null_hp_mask;
  switch (pkt_type) {
  case NGTCP2_PKT_INITIAL:
    cc.ckm = conn->in_pktns->crypto.rx.ckm;
    cc.hp_key = conn->in_pktns->crypto.rx.hp_key;
    cc.aead_overhead = NGTCP2_INITIAL_AEAD_OVERHEAD;
    break;
  case NGTCP2_PKT_HANDSHAKE:
    cc.ckm = conn->hs_pktns->crypto.rx.ckm;
    cc.hp_key = conn->hs_pktns->crypto.rx.hp_key;
    cc.aead_overhead = NGTCP2_FAKE_AEAD_OVERHEAD;
    break;
  case NGTCP2_PKT_0RTT:
    cc.ckm = conn->early.ckm;
    cc.hp_key = conn->early.hp_key;
    cc.aead_overhead = NGTCP2_FAKE_AEAD_OVERHEAD;
    break;
  default:
    assert(0);
  }

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_LONG_FORM, pkt_type, dcid, scid,
                     pkt_num, 4, version, 0);

  ngtcp2_ppe_init(&ppe, out, outlen, &cc);
  rv = ngtcp2_ppe_encode_hd(&ppe, &hd);
  assert(0 == rv);

  for (i = 0; i < frlen; ++i) {
    fr = &fra[i];
    rv = ngtcp2_ppe_encode_frame(&ppe, fr);
    assert(0 == rv);
  }

  n = ngtcp2_ppe_final(&ppe, NULL);
  assert(n > 0);
  return (size_t)n;
}

ngtcp2_strm *open_stream(ngtcp2_conn *conn, int64_t stream_id) {
  ngtcp2_strm *strm;
  int rv;

  strm = ngtcp2_mem_malloc(conn->mem, sizeof(ngtcp2_strm));
  assert(strm);

  rv = ngtcp2_conn_init_stream(conn, strm, stream_id, NULL);
  assert(0 == rv);

  return strm;
}

size_t rtb_entry_length(const ngtcp2_rtb_entry *ent) {
  size_t len = 0;

  for (; ent; ent = ent->next) {
    ++len;
  }

  return len;
}

void dcid_init(ngtcp2_cid *cid) {
  static const uint8_t id[] = "\xff\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                              "\xaa\xaa\xaa\xaa\xaa\xff";
  ngtcp2_cid_init(cid, id, sizeof(id) - 1);
}

void scid_init(ngtcp2_cid *cid) {
  static const uint8_t id[] = "\xee\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                              "\xaa\xaa\xaa\xaa\xaa\xee";
  ngtcp2_cid_init(cid, id, sizeof(id) - 1);
}

void rcid_init(ngtcp2_cid *cid) {
  static const uint8_t id[] = "\xdd\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                              "\xaa\xaa\xaa\xaa\xaa\xdd";
  ngtcp2_cid_init(cid, id, sizeof(id) - 1);
}

uint64_t read_pkt_payloadlen(const uint8_t *pkt, const ngtcp2_cid *dcid,
                             const ngtcp2_cid *scid) {
  size_t nread;

  return ngtcp2_get_varint(&nread,
                           &pkt[1 + 4 + 1 + dcid->datalen + 1 + scid->datalen]);
}

void write_pkt_payloadlen(uint8_t *pkt, const ngtcp2_cid *dcid,
                          const ngtcp2_cid *scid, uint64_t payloadlen) {
  assert(payloadlen < 16384);
  ngtcp2_put_varint14(&pkt[1 + 4 + 1 + dcid->datalen + 1 + scid->datalen],
                      (uint16_t)payloadlen);
}

ngtcp2_ssize pkt_decode_hd_long(ngtcp2_pkt_hd *dest, const uint8_t *pkt,
                                size_t pktlen) {
  const uint8_t *p;
  ngtcp2_ssize nread;

  nread = ngtcp2_pkt_decode_hd_long(dest, pkt, pktlen);
  if (nread < 0 || dest->type == NGTCP2_PKT_VERSION_NEGOTIATION) {
    return nread;
  }

  if ((size_t)nread == pktlen) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  p = pkt + nread;

  dest->pkt_numlen = (size_t)(pkt[0] & NGTCP2_PKT_NUMLEN_MASK) + 1;
  if (pktlen < (size_t)nread + dest->pkt_numlen) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  dest->pkt_num = ngtcp2_get_pkt_num(p, dest->pkt_numlen);

  return nread + (ngtcp2_ssize)dest->pkt_numlen;
}

ngtcp2_ssize pkt_decode_hd_short(ngtcp2_pkt_hd *dest, const uint8_t *pkt,
                                 size_t pktlen, size_t dcidlen) {
  const uint8_t *p;
  ngtcp2_ssize nread;

  nread = ngtcp2_pkt_decode_hd_short(dest, pkt, pktlen, dcidlen);
  if (nread < 0) {
    return nread;
  }

  if ((size_t)nread == pktlen) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  p = pkt + nread;

  dest->pkt_numlen = (size_t)(pkt[0] & NGTCP2_PKT_NUMLEN_MASK) + 1;
  if (pktlen < (size_t)nread + dest->pkt_numlen) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  dest->pkt_num = ngtcp2_get_pkt_num(p, dest->pkt_numlen);

  return nread + (ngtcp2_ssize)dest->pkt_numlen;
}

ngtcp2_ssize pkt_decode_hd_short_mask(ngtcp2_pkt_hd *dest, const uint8_t *pkt,
                                      size_t pktlen, size_t dcidlen) {
  static const uint8_t mask[] = NGTCP2_FAKE_HP_MASK;
  const uint8_t *p;
  ngtcp2_ssize nread;
  uint8_t hb;
  uint8_t pkt_numbuf[4];
  size_t i;

  nread = ngtcp2_pkt_decode_hd_short(dest, pkt, pktlen, dcidlen);
  if (nread < 0) {
    return nread;
  }

  if ((size_t)nread == pktlen) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  p = pkt + nread;

  hb = (uint8_t)(pkt[0] ^ (mask[0] & 0x1f));

  dest->pkt_numlen = (size_t)(hb & NGTCP2_PKT_NUMLEN_MASK) + 1;
  if (pktlen < (size_t)nread + dest->pkt_numlen) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  for (i = 0; i < dest->pkt_numlen; ++i) {
    pkt_numbuf[i] = *(p + i) ^ mask[i + 1];
  }

  dest->pkt_num = ngtcp2_get_pkt_num(pkt_numbuf, dest->pkt_numlen);

  return nread + (ngtcp2_ssize)dest->pkt_numlen;
}
