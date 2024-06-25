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
#include "ngtcp2_net.h"

size_t ngtcp2_t_encode_stream_frame(uint8_t *out, uint8_t flags,
                                    uint64_t stream_id, uint64_t offset,
                                    uint16_t datalen) {
  uint8_t *p = out;

  if (offset) {
    flags |= NGTCP2_STREAM_OFF_BIT;
  }
  *p++ = NGTCP2_FRAME_STREAM | flags;

  p = ngtcp2_put_uvarint(p, stream_id);

  if (offset) {
    p = ngtcp2_put_uvarint(p, offset);
  }

  if (flags & NGTCP2_STREAM_LEN_BIT) {
    p = ngtcp2_put_uvarint(p, datalen);
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
  p = ngtcp2_put_uvarint(p, largest_ack);
  /* ACK Delay */
  p = ngtcp2_put_uvarint(p, 0);
  /* ACK Block Count */
  p = ngtcp2_put_uvarint(p, 1);
  /* First ACK Block */
  p = ngtcp2_put_uvarint(p, first_ack_blklen);
  /* Gap (1) */
  p = ngtcp2_put_uvarint(p, gap);
  /* Additional ACK Block (1) */
  p = ngtcp2_put_uvarint(p, ack_blklen);

  return (size_t)(p - out);
}

static int null_encrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                        const ngtcp2_crypto_aead_ctx *aead_ctx,
                        const uint8_t *plaintext, size_t plaintextlen,
                        const uint8_t *nonce, size_t noncelen,
                        const uint8_t *aad, size_t aadlen) {
  (void)dest;
  (void)aead;
  (void)aead_ctx;
  (void)plaintext;
  (void)plaintextlen;
  (void)nonce;
  (void)noncelen;
  (void)aad;
  (void)aadlen;
  memset(dest + plaintextlen, 0, NGTCP2_FAKE_AEAD_OVERHEAD);
  return 0;
}

static int null_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                        const ngtcp2_crypto_cipher_ctx *hp_ctx,
                        const uint8_t *sample) {
  (void)hp;
  (void)hp_ctx;
  (void)sample;
  memcpy(dest, NGTCP2_FAKE_HP_MASK, sizeof(NGTCP2_FAKE_HP_MASK) - 1);
  return 0;
}

/*
 * write_short_pkt writes a QUIC short header packet containing
 * |frlen| frames pointed by |fr| into |out| whose capacity is
 * |outlen|.  This function returns the number of bytes written.
 */
static size_t write_short_pkt(uint8_t *out, size_t outlen, uint8_t flags,
                              const ngtcp2_cid *dcid, int64_t pkt_num,
                              ngtcp2_frame *fr, size_t frlen,
                              ngtcp2_crypto_km *ckm) {
  ngtcp2_crypto_cc cc;
  ngtcp2_ppe ppe;
  ngtcp2_pkt_hd hd;
  int rv;
  ngtcp2_ssize n;
  size_t i;

  memset(&cc, 0, sizeof(cc));
  cc.encrypt = null_encrypt;
  cc.hp_mask = null_hp_mask;
  cc.ckm = ckm;
  cc.aead.max_overhead = NGTCP2_FAKE_AEAD_OVERHEAD;

  ngtcp2_pkt_hd_init(&hd, flags, NGTCP2_PKT_1RTT, dcid, NULL, pkt_num, 4,
                     NGTCP2_PROTO_VER_V1, 0);

  ngtcp2_ppe_init(&ppe, out, outlen, 0, &cc);
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

/*
 * write_long_pkt writes a QUIC long header packet containing |frlen|
 * frames pointed by |fr| into |out| whose capacity is |outlen|.  This
 * function returns the number of bytes written.
 */
static size_t write_long_pkt(uint8_t *out, size_t outlen, uint8_t flags,
                             uint8_t pkt_type, const ngtcp2_cid *dcid,
                             const ngtcp2_cid *scid, int64_t pkt_num,
                             uint32_t version, const uint8_t *token,
                             size_t tokenlen, ngtcp2_frame *fr, size_t frlen,
                             ngtcp2_crypto_km *ckm) {
  ngtcp2_crypto_cc cc;
  ngtcp2_ppe ppe;
  ngtcp2_pkt_hd hd;
  int rv;
  ngtcp2_ssize n;
  size_t i;

  memset(&cc, 0, sizeof(cc));
  cc.encrypt = null_encrypt;
  cc.hp_mask = null_hp_mask;
  cc.ckm = ckm;
  switch (pkt_type) {
  case NGTCP2_PKT_INITIAL:
    cc.aead.max_overhead = NGTCP2_INITIAL_AEAD_OVERHEAD;
    break;
  case NGTCP2_PKT_HANDSHAKE:
  case NGTCP2_PKT_0RTT:
    cc.aead.max_overhead = NGTCP2_FAKE_AEAD_OVERHEAD;
    break;
  default:
    assert(0);
  }

  /* ngtcp2_pkt_encode_hd_long requires known QUIC version.  If we
     need to write unsupported version for testing purpose, just
     pretend that it is QUIC v1 here and rewrite the version field
     later. */
  ngtcp2_pkt_hd_init(
      &hd, NGTCP2_PKT_FLAG_LONG_FORM | flags, pkt_type, dcid, scid, pkt_num, 4,
      version != NGTCP2_PROTO_VER_V1 && version != NGTCP2_PROTO_VER_V2
          ? NGTCP2_PROTO_VER_V1
          : version,
      0);

  hd.token = token;
  hd.tokenlen = tokenlen;

  ngtcp2_ppe_init(&ppe, out, outlen, 0, &cc);
  rv = ngtcp2_ppe_encode_hd(&ppe, &hd);
  assert(0 == rv);
  ngtcp2_put_uint32be(&out[1], version);

  for (i = 0; i < frlen; ++i, ++fr) {
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
  (void)rv;

  strm = ngtcp2_objalloc_strm_get(&conn->strm_objalloc);
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
  uint64_t len;

  ngtcp2_get_uvarint(&len, &pkt[1 + 4 + 1 + dcid->datalen + 1 + scid->datalen]);

  return len;
}

void write_pkt_payloadlen(uint8_t *pkt, const ngtcp2_cid *dcid,
                          const ngtcp2_cid *scid, uint64_t payloadlen) {
  assert(payloadlen < 1073741824);
  ngtcp2_put_uvarint30(&pkt[1 + 4 + 1 + dcid->datalen + 1 + scid->datalen],
                       (uint32_t)payloadlen);
}

ngtcp2_ssize pkt_decode_hd_long(ngtcp2_pkt_hd *dest, const uint8_t *pkt,
                                size_t pktlen) {
  const uint8_t *p;
  ngtcp2_ssize nread;

  nread = ngtcp2_pkt_decode_hd_long(dest, pkt, pktlen);
  if (nread < 0 || (!(dest->flags & NGTCP2_PKT_FLAG_LONG_FORM) &&
                    dest->type == NGTCP2_PKT_VERSION_NEGOTIATION)) {
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

static void addr_init(ngtcp2_sockaddr_in *dest, uint32_t addr, uint16_t port) {
  memset(dest, 0, sizeof(*dest));

  dest->sin_family = NGTCP2_AF_INET;
  dest->sin_port = ngtcp2_htons(port);
  dest->sin_addr.s_addr = ngtcp2_htonl(addr);
}

void path_init(ngtcp2_path_storage *path, uint32_t local_addr,
               uint16_t local_port, uint32_t remote_addr,
               uint16_t remote_port) {
  ngtcp2_sockaddr_in la, ra;

  addr_init(&la, local_addr, local_port);
  addr_init(&ra, remote_addr, remote_port);

  ngtcp2_path_storage_init(path, (ngtcp2_sockaddr *)&la, sizeof(la),
                           (ngtcp2_sockaddr *)&ra, sizeof(ra), NULL);
}

void ngtcp2_tpe_init(ngtcp2_tpe *tpe, const ngtcp2_cid *dcid,
                     const ngtcp2_cid *scid, uint32_t version) {
  memset(tpe, 0, sizeof(*tpe));

  tpe->dcid = *dcid;

  if (scid) {
    tpe->scid = *scid;
  }

  tpe->version = version;
  tpe->initial.last_pkt_num = -1;
  tpe->handshake.last_pkt_num = -1;
  tpe->app.last_pkt_num = -1;
}

void ngtcp2_tpe_init_conn(ngtcp2_tpe *tpe, ngtcp2_conn *conn) {
  ngtcp2_tpe_init(tpe, &conn->oscid, ngtcp2_conn_get_dcid(conn),
                  conn->client_chosen_version);

  if (conn->in_pktns) {
    tpe->initial.ckm = conn->in_pktns->crypto.rx.ckm;
  }

  if (conn->hs_pktns) {
    tpe->handshake.ckm = conn->hs_pktns->crypto.rx.ckm;
  }

  tpe->early.ckm = conn->early.ckm;
  tpe->app.ckm = conn->pktns.crypto.rx.ckm;
}

size_t ngtcp2_tpe_write_initial(ngtcp2_tpe *tpe, uint8_t *out, size_t outlen,
                                ngtcp2_frame *fr, size_t frlen) {
  return write_long_pkt(out, outlen, tpe->flags, NGTCP2_PKT_INITIAL, &tpe->dcid,
                        &tpe->scid, ++tpe->initial.last_pkt_num, tpe->version,
                        tpe->token, tpe->tokenlen, fr, frlen, tpe->initial.ckm);
}

size_t ngtcp2_tpe_write_handshake(ngtcp2_tpe *tpe, uint8_t *out, size_t outlen,
                                  ngtcp2_frame *fr, size_t frlen) {
  return write_long_pkt(out, outlen, tpe->flags, NGTCP2_PKT_HANDSHAKE,
                        &tpe->dcid, &tpe->scid, ++tpe->handshake.last_pkt_num,
                        tpe->version, NULL, 0, fr, frlen, tpe->handshake.ckm);
}

size_t ngtcp2_tpe_write_0rtt(ngtcp2_tpe *tpe, uint8_t *out, size_t outlen,
                             ngtcp2_frame *fr, size_t frlen) {
  return write_long_pkt(out, outlen, tpe->flags, NGTCP2_PKT_0RTT, &tpe->dcid,
                        &tpe->scid, ++tpe->app.last_pkt_num, tpe->version, NULL,
                        0, fr, frlen, tpe->early.ckm);
}

size_t ngtcp2_tpe_write_1rtt(ngtcp2_tpe *tpe, uint8_t *out, size_t outlen,
                             ngtcp2_frame *fr, size_t frlen) {
  return write_short_pkt(out, outlen, tpe->flags, &tpe->dcid,
                         ++tpe->app.last_pkt_num, fr, frlen, tpe->app.ckm);
}
