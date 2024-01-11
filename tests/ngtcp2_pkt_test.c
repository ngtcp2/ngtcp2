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
#include "ngtcp2_pkt_test.h"

#include <stdio.h>

#include <CUnit/CUnit.h>

#include "ngtcp2_pkt.h"
#include "ngtcp2_test_helper.h"
#include "ngtcp2_conv.h"
#include "ngtcp2_cid.h"
#include "ngtcp2_str.h"
#include "ngtcp2_vec.h"

static int null_retry_encrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
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

  if (plaintextlen && plaintext != dest) {
    memcpy(dest, plaintext, plaintextlen);
  }
  memset(dest + plaintextlen, 0, NGTCP2_RETRY_TAGLEN);

  return 0;
}

void test_ngtcp2_pkt_decode_version_cid(void) {
  uint8_t buf[NGTCP2_MAX_UDP_PAYLOAD_SIZE];
  ngtcp2_version_cid vc;
  int rv;
  uint8_t *p;

  /* Supported QUIC version */
  p = buf;
  *p++ = NGTCP2_HEADER_FORM_BIT;
  p = ngtcp2_put_uint32be(p, NGTCP2_PROTO_VER_V1);
  *p++ = NGTCP2_MAX_CIDLEN;
  p = ngtcp2_setmem(p, 0xf1, NGTCP2_MAX_CIDLEN);
  *p++ = NGTCP2_MAX_CIDLEN - 1;
  p = ngtcp2_setmem(p, 0xf2, NGTCP2_MAX_CIDLEN - 1);

  rv = ngtcp2_pkt_decode_version_cid(&vc, buf, (size_t)(p - buf), 0);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NGTCP2_PROTO_VER_V1 == vc.version);
  CU_ASSERT(NGTCP2_MAX_CIDLEN == vc.dcidlen);
  CU_ASSERT(&buf[6] == vc.dcid);
  CU_ASSERT(NGTCP2_MAX_CIDLEN - 1 == vc.scidlen);
  CU_ASSERT(&buf[6 + NGTCP2_MAX_CIDLEN + 1] == vc.scid);

  /* Unsupported QUIC version */
  memset(buf, 0, sizeof(buf));
  p = buf;
  *p++ = NGTCP2_HEADER_FORM_BIT;
  p = ngtcp2_put_uint32be(p, 0xffffff00);
  *p++ = NGTCP2_MAX_CIDLEN;
  p = ngtcp2_setmem(p, 0xf1, NGTCP2_MAX_CIDLEN);
  *p++ = NGTCP2_MAX_CIDLEN - 1;
  ngtcp2_setmem(p, 0xf2, NGTCP2_MAX_CIDLEN - 1);

  rv = ngtcp2_pkt_decode_version_cid(&vc, buf, sizeof(buf), 0);

  CU_ASSERT(NGTCP2_ERR_VERSION_NEGOTIATION == rv);
  CU_ASSERT(0xffffff00 == vc.version);
  CU_ASSERT(NGTCP2_MAX_CIDLEN == vc.dcidlen);
  CU_ASSERT(&buf[6] == vc.dcid);
  CU_ASSERT(NGTCP2_MAX_CIDLEN - 1 == vc.scidlen);
  CU_ASSERT(&buf[6 + NGTCP2_MAX_CIDLEN + 1] == vc.scid);

  /* Unsupported QUIC version with UDP payload size < 1200 */
  p = buf;
  *p++ = NGTCP2_HEADER_FORM_BIT;
  p = ngtcp2_put_uint32be(p, 0xffffff00);
  *p++ = NGTCP2_MAX_CIDLEN;
  p = ngtcp2_setmem(p, 0xf1, NGTCP2_MAX_CIDLEN);
  *p++ = NGTCP2_MAX_CIDLEN - 1;
  p = ngtcp2_setmem(p, 0xf2, NGTCP2_MAX_CIDLEN - 1);

  rv = ngtcp2_pkt_decode_version_cid(&vc, buf, (size_t)(p - buf), 0);

  CU_ASSERT(NGTCP2_ERR_INVALID_ARGUMENT == rv);

  /* Supported QUIC version with long CID */
  p = buf;
  *p++ = NGTCP2_HEADER_FORM_BIT;
  p = ngtcp2_put_uint32be(p, NGTCP2_PROTO_VER_V1);
  *p++ = NGTCP2_MAX_CIDLEN + 1;
  p = ngtcp2_setmem(p, 0xf1, NGTCP2_MAX_CIDLEN + 1);
  *p++ = NGTCP2_MAX_CIDLEN;
  p = ngtcp2_setmem(p, 0xf2, NGTCP2_MAX_CIDLEN);

  rv = ngtcp2_pkt_decode_version_cid(&vc, buf, (size_t)(p - buf), 0);

  CU_ASSERT(NGTCP2_ERR_INVALID_ARGUMENT == rv);

  /* Unsupported QUIC version with long CID */
  memset(buf, 0, sizeof(buf));
  p = buf;
  *p++ = NGTCP2_HEADER_FORM_BIT;
  p = ngtcp2_put_uint32be(p, 0xffffff00);
  *p++ = NGTCP2_MAX_CIDLEN + 1;
  p = ngtcp2_setmem(p, 0xf1, NGTCP2_MAX_CIDLEN + 1);
  *p++ = NGTCP2_MAX_CIDLEN;
  ngtcp2_setmem(p, 0xf2, NGTCP2_MAX_CIDLEN);

  rv = ngtcp2_pkt_decode_version_cid(&vc, buf, sizeof(buf), 0);

  CU_ASSERT(NGTCP2_ERR_VERSION_NEGOTIATION == rv);
  CU_ASSERT(0xffffff00 == vc.version);
  CU_ASSERT(NGTCP2_MAX_CIDLEN + 1 == vc.dcidlen);
  CU_ASSERT(&buf[6] == vc.dcid);
  CU_ASSERT(NGTCP2_MAX_CIDLEN == vc.scidlen);
  CU_ASSERT(&buf[6 + NGTCP2_MAX_CIDLEN + 1 + 1] == vc.scid);

  /* VN */
  p = buf;
  *p++ = NGTCP2_HEADER_FORM_BIT;
  p = ngtcp2_put_uint32be(p, 0);
  *p++ = NGTCP2_MAX_CIDLEN;
  p = ngtcp2_setmem(p, 0xf1, NGTCP2_MAX_CIDLEN);
  *p++ = NGTCP2_MAX_CIDLEN - 1;
  p = ngtcp2_setmem(p, 0xf2, NGTCP2_MAX_CIDLEN - 1);

  rv = ngtcp2_pkt_decode_version_cid(&vc, buf, (size_t)(p - buf), 0);

  CU_ASSERT(0 == rv);
  CU_ASSERT(0 == vc.version);
  CU_ASSERT(NGTCP2_MAX_CIDLEN == vc.dcidlen);
  CU_ASSERT(&buf[6] == vc.dcid);
  CU_ASSERT(NGTCP2_MAX_CIDLEN - 1 == vc.scidlen);
  CU_ASSERT(&buf[6 + NGTCP2_MAX_CIDLEN + 1] == vc.scid);

  /* VN with long CID */
  p = buf;
  *p++ = NGTCP2_HEADER_FORM_BIT;
  p = ngtcp2_put_uint32be(p, 0);
  *p++ = NGTCP2_MAX_CIDLEN + 1;
  p = ngtcp2_setmem(p, 0xf1, NGTCP2_MAX_CIDLEN + 1);
  *p++ = NGTCP2_MAX_CIDLEN;
  p = ngtcp2_setmem(p, 0xf2, NGTCP2_MAX_CIDLEN);

  rv = ngtcp2_pkt_decode_version_cid(&vc, buf, (size_t)(p - buf), 0);

  CU_ASSERT(0 == rv);
  CU_ASSERT(0 == vc.version);
  CU_ASSERT(NGTCP2_MAX_CIDLEN + 1 == vc.dcidlen);
  CU_ASSERT(&buf[6] == vc.dcid);
  CU_ASSERT(NGTCP2_MAX_CIDLEN == vc.scidlen);
  CU_ASSERT(&buf[6 + NGTCP2_MAX_CIDLEN + 1 + 1] == vc.scid);

  /* Malformed Long packet */
  p = buf;
  *p++ = NGTCP2_HEADER_FORM_BIT;
  p = ngtcp2_put_uint32be(p, NGTCP2_PROTO_VER_V1);
  *p++ = NGTCP2_MAX_CIDLEN;
  p = ngtcp2_setmem(p, 0xf1, NGTCP2_MAX_CIDLEN);
  *p++ = NGTCP2_MAX_CIDLEN - 1;
  p = ngtcp2_setmem(p, 0xf2, NGTCP2_MAX_CIDLEN - 1);
  --p;

  rv = ngtcp2_pkt_decode_version_cid(&vc, buf, (size_t)(p - buf), 0);

  CU_ASSERT(NGTCP2_ERR_INVALID_ARGUMENT == rv);

  /* Short packet */
  p = buf;
  *p++ = 0;
  p = ngtcp2_setmem(p, 0xf1, NGTCP2_MAX_CIDLEN);

  rv = ngtcp2_pkt_decode_version_cid(&vc, buf, (size_t)(p - buf),
                                     NGTCP2_MAX_CIDLEN);

  CU_ASSERT(0 == rv);
  CU_ASSERT(0 == vc.version);
  CU_ASSERT(&buf[1] == vc.dcid);
  CU_ASSERT(NGTCP2_MAX_CIDLEN == vc.dcidlen);
  CU_ASSERT(NULL == vc.scid);
  CU_ASSERT(0 == vc.scidlen);

  /* Malformed Short packet */
  p = buf;
  *p++ = 0;
  p = ngtcp2_setmem(p, 0xf1, NGTCP2_MAX_CIDLEN);
  --p;

  rv = ngtcp2_pkt_decode_version_cid(&vc, buf, (size_t)(p - buf),
                                     NGTCP2_MAX_CIDLEN);

  CU_ASSERT(NGTCP2_ERR_INVALID_ARGUMENT == rv);
}

void test_ngtcp2_pkt_decode_hd_long(void) {
  ngtcp2_pkt_hd hd, nhd;
  uint8_t buf[256];
  ngtcp2_ssize rv;
  ngtcp2_cid dcid, scid;
  size_t len;

  dcid_init(&dcid);
  scid_init(&scid);

  /* Handshake */
  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_LONG_FORM, NGTCP2_PKT_HANDSHAKE,
                     &dcid, &scid, 0xe1e2e3e4u, 4, NGTCP2_PROTO_VER_V1, 16383);

  rv = ngtcp2_pkt_encode_hd_long(buf, sizeof(buf), &hd);

  len = 1 + 4 + 1 + dcid.datalen + 1 + scid.datalen + NGTCP2_PKT_LENGTHLEN + 4;

  CU_ASSERT((ngtcp2_ssize)len == rv);
  CU_ASSERT(buf[0] & NGTCP2_FIXED_BIT_MASK);

  rv = pkt_decode_hd_long(&nhd, buf, len);

  CU_ASSERT((ngtcp2_ssize)len == rv);
  CU_ASSERT(hd.type == nhd.type);
  CU_ASSERT(hd.flags == nhd.flags);
  CU_ASSERT(ngtcp2_cid_eq(&hd.dcid, &nhd.dcid));
  CU_ASSERT(ngtcp2_cid_eq(&hd.scid, &nhd.scid));
  CU_ASSERT(0xe1e2e3e4u == nhd.pkt_num);
  CU_ASSERT(hd.version == nhd.version);
  CU_ASSERT(hd.len == nhd.len);

  /* Handshake without Fixed Bit set */
  ngtcp2_pkt_hd_init(
      &hd, NGTCP2_PKT_FLAG_LONG_FORM | NGTCP2_PKT_FLAG_FIXED_BIT_CLEAR,
      NGTCP2_PKT_HANDSHAKE, &dcid, &scid, 0xe1e2e3e4u, 4, NGTCP2_PROTO_VER_V1,
      16383);

  rv = ngtcp2_pkt_encode_hd_long(buf, sizeof(buf), &hd);

  len = 1 + 4 + 1 + dcid.datalen + 1 + scid.datalen + NGTCP2_PKT_LENGTHLEN + 4;

  CU_ASSERT((ngtcp2_ssize)len == rv);
  CU_ASSERT((buf[0] & NGTCP2_FIXED_BIT_MASK) == 0);

  rv = pkt_decode_hd_long(&nhd, buf, len);

  CU_ASSERT((ngtcp2_ssize)len == rv);
  CU_ASSERT(hd.type == nhd.type);
  CU_ASSERT(hd.flags == nhd.flags);
  CU_ASSERT(ngtcp2_cid_eq(&hd.dcid, &nhd.dcid));
  CU_ASSERT(ngtcp2_cid_eq(&hd.scid, &nhd.scid));
  CU_ASSERT(0xe1e2e3e4u == nhd.pkt_num);
  CU_ASSERT(hd.version == nhd.version);
  CU_ASSERT(hd.len == nhd.len);

  /* VN */
  /* Set random packet type */
  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_LONG_FORM, NGTCP2_PKT_HANDSHAKE,
                     &dcid, &scid, 0, 4, NGTCP2_PROTO_VER_V1, 0);

  rv = ngtcp2_pkt_encode_hd_long(buf, sizeof(buf), &hd);
  /* Set version field to 0 */
  memset(&buf[1], 0, 4);

  len = 1 + 4 + 1 + dcid.datalen + 1 + scid.datalen;

  CU_ASSERT((ngtcp2_ssize)len == rv - NGTCP2_PKT_LENGTHLEN - 4 /* pkt_num */);

  rv = pkt_decode_hd_long(&nhd, buf, len);

  CU_ASSERT((ngtcp2_ssize)len == rv);
  CU_ASSERT(NGTCP2_PKT_VERSION_NEGOTIATION == nhd.type);
  CU_ASSERT((hd.flags & ~NGTCP2_PKT_FLAG_LONG_FORM) == nhd.flags);
  CU_ASSERT(ngtcp2_cid_eq(&hd.dcid, &nhd.dcid));
  CU_ASSERT(ngtcp2_cid_eq(&hd.scid, &nhd.scid));
  CU_ASSERT(hd.pkt_num == nhd.pkt_num);
  CU_ASSERT(0 == nhd.version);
  CU_ASSERT(hd.len == nhd.len);
}

void test_ngtcp2_pkt_decode_hd_short(void) {
  ngtcp2_pkt_hd hd, nhd;
  uint8_t buf[256];
  ngtcp2_ssize rv;
  size_t expectedlen;
  ngtcp2_cid dcid, zcid;

  dcid_init(&dcid);
  ngtcp2_cid_zero(&zcid);

  /* 4 bytes packet number */
  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_1RTT, &dcid, NULL,
                     0xe1e2e3e4u, 4, 0xd1d2d3d4u, 0);

  expectedlen = 1 + dcid.datalen + 4;

  rv = ngtcp2_pkt_encode_hd_short(buf, sizeof(buf), &hd);

  CU_ASSERT((ngtcp2_ssize)expectedlen == rv);
  CU_ASSERT(buf[0] & NGTCP2_FIXED_BIT_MASK);

  rv = pkt_decode_hd_short(&nhd, buf, expectedlen, dcid.datalen);

  CU_ASSERT((ngtcp2_ssize)expectedlen == rv);
  CU_ASSERT(hd.flags == nhd.flags);
  CU_ASSERT(NGTCP2_PKT_1RTT == nhd.type);
  CU_ASSERT(ngtcp2_cid_eq(&dcid, &nhd.dcid));
  CU_ASSERT(ngtcp2_cid_empty(&nhd.scid));
  CU_ASSERT(0xe1e2e3e4u == nhd.pkt_num);
  CU_ASSERT(hd.pkt_numlen == nhd.pkt_numlen);
  CU_ASSERT(0 == nhd.version);
  CU_ASSERT(0 == nhd.len);

  /* 4 bytes packet number without Fixed Bit set */
  ngtcp2_pkt_hd_init(
      &hd, NGTCP2_PKT_FLAG_NONE | NGTCP2_PKT_FLAG_FIXED_BIT_CLEAR,
      NGTCP2_PKT_1RTT, &dcid, NULL, 0xe1e2e3e4u, 4, 0xd1d2d3d4u, 0);

  expectedlen = 1 + dcid.datalen + 4;

  rv = ngtcp2_pkt_encode_hd_short(buf, sizeof(buf), &hd);

  CU_ASSERT((ngtcp2_ssize)expectedlen == rv);
  CU_ASSERT((buf[0] & NGTCP2_FIXED_BIT_MASK) == 0);

  rv = pkt_decode_hd_short(&nhd, buf, expectedlen, dcid.datalen);

  CU_ASSERT((ngtcp2_ssize)expectedlen == rv);
  CU_ASSERT(hd.flags == nhd.flags);
  CU_ASSERT(NGTCP2_PKT_1RTT == nhd.type);
  CU_ASSERT(ngtcp2_cid_eq(&dcid, &nhd.dcid));
  CU_ASSERT(ngtcp2_cid_empty(&nhd.scid));
  CU_ASSERT(0xe1e2e3e4u == nhd.pkt_num);
  CU_ASSERT(hd.pkt_numlen == nhd.pkt_numlen);
  CU_ASSERT(0 == nhd.version);
  CU_ASSERT(0 == nhd.len);

  /* 2 bytes packet number */
  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_1RTT, &dcid, NULL,
                     0xe1e2e3e4u, 2, 0xd1d2d3d4u, 0);

  expectedlen = 1 + dcid.datalen + 2;

  rv = ngtcp2_pkt_encode_hd_short(buf, sizeof(buf), &hd);

  CU_ASSERT((ngtcp2_ssize)expectedlen == rv);

  rv = pkt_decode_hd_short(&nhd, buf, expectedlen, dcid.datalen);

  CU_ASSERT((ngtcp2_ssize)expectedlen == rv);
  CU_ASSERT(hd.flags == nhd.flags);
  CU_ASSERT(NGTCP2_PKT_1RTT == nhd.type);
  CU_ASSERT(ngtcp2_cid_eq(&dcid, &nhd.dcid));
  CU_ASSERT(ngtcp2_cid_empty(&nhd.scid));
  CU_ASSERT(0xe3e4u == nhd.pkt_num);
  CU_ASSERT(hd.pkt_numlen == nhd.pkt_numlen);
  CU_ASSERT(0 == nhd.version);
  CU_ASSERT(0 == nhd.len);

  /* 1 byte packet number */
  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_1RTT, &dcid, NULL,
                     0xe1e2e3e4u, 1, 0xd1d2d3d4u, 0);

  expectedlen = 1 + dcid.datalen + 1;

  rv = ngtcp2_pkt_encode_hd_short(buf, sizeof(buf), &hd);

  CU_ASSERT((ngtcp2_ssize)expectedlen == rv);

  rv = pkt_decode_hd_short(&nhd, buf, expectedlen, dcid.datalen);

  CU_ASSERT((ngtcp2_ssize)expectedlen == rv);
  CU_ASSERT(hd.flags == nhd.flags);
  CU_ASSERT(NGTCP2_PKT_1RTT == nhd.type);
  CU_ASSERT(ngtcp2_cid_eq(&dcid, &nhd.dcid));
  CU_ASSERT(ngtcp2_cid_empty(&nhd.scid));
  CU_ASSERT(0xe4 == nhd.pkt_num);
  CU_ASSERT(hd.pkt_numlen == nhd.pkt_numlen);
  CU_ASSERT(0 == nhd.version);
  CU_ASSERT(0 == nhd.len);

  /* With Key Phase */
  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_KEY_PHASE, NGTCP2_PKT_1RTT, &dcid,
                     NULL, 0xe1e2e3e4u, 4, 0xd1d2d3d4u, 0);

  expectedlen = 1 + dcid.datalen + 4;

  rv = ngtcp2_pkt_encode_hd_short(buf, sizeof(buf), &hd);

  CU_ASSERT((ngtcp2_ssize)expectedlen == rv);

  rv = pkt_decode_hd_short(&nhd, buf, expectedlen, dcid.datalen);

  CU_ASSERT((ngtcp2_ssize)expectedlen == rv);
  /* key phase bit is protected by header protection and
     ngtcp2_pkt_decode_hd_short does not decode it. */
  CU_ASSERT(NGTCP2_PKT_FLAG_NONE == nhd.flags);
  CU_ASSERT(NGTCP2_PKT_1RTT == nhd.type);
  CU_ASSERT(ngtcp2_cid_eq(&dcid, &nhd.dcid));
  CU_ASSERT(ngtcp2_cid_empty(&nhd.scid));
  CU_ASSERT(0xe1e2e3e4u == nhd.pkt_num);
  CU_ASSERT(hd.pkt_numlen == nhd.pkt_numlen);
  CU_ASSERT(0 == nhd.version);
  CU_ASSERT(0 == nhd.len);

  /* With empty DCID */
  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_1RTT, NULL, NULL,
                     0xe1e2e3e4u, 4, 0xd1d2d3d4u, 0);

  expectedlen = 1 + 4;

  rv = ngtcp2_pkt_encode_hd_short(buf, sizeof(buf), &hd);

  CU_ASSERT((ngtcp2_ssize)expectedlen == rv);

  rv = pkt_decode_hd_short(&nhd, buf, expectedlen, 0);

  CU_ASSERT((ngtcp2_ssize)expectedlen == rv);
  CU_ASSERT(hd.flags == nhd.flags);
  CU_ASSERT(NGTCP2_PKT_1RTT == nhd.type);
  CU_ASSERT(ngtcp2_cid_empty(&nhd.dcid));
  CU_ASSERT(ngtcp2_cid_empty(&nhd.scid));
  CU_ASSERT(0xe1e2e3e4u == nhd.pkt_num);
  CU_ASSERT(hd.pkt_numlen == nhd.pkt_numlen);
  CU_ASSERT(0 == nhd.version);
  CU_ASSERT(0 == nhd.len);
}

void test_ngtcp2_pkt_decode_frame(void) {
  const uint8_t malformed_stream_frame[] = {
      0xff, 0x01, 0x01, 0x01, 0x01,
  };
  const uint8_t good_stream_frame[] = {
      0x0f, 0x01, 0x01, 0x01, 0x01,
  };
  ngtcp2_ssize rv;
  ngtcp2_frame fr;

  rv = ngtcp2_pkt_decode_frame(&fr, malformed_stream_frame,
                               sizeof(malformed_stream_frame));

  CU_ASSERT(NGTCP2_ERR_FRAME_ENCODING == rv);

  rv = ngtcp2_pkt_decode_frame(&fr, good_stream_frame,
                               sizeof(good_stream_frame));

  CU_ASSERT(5 == rv);
  CU_ASSERT(NGTCP2_FRAME_STREAM == fr.type);
  CU_ASSERT(0x7 == fr.stream.flags);
  CU_ASSERT(1 == fr.stream.stream_id);
  CU_ASSERT(1 == fr.stream.offset);
  CU_ASSERT(1 == fr.stream.fin);
  CU_ASSERT(1 == fr.stream.datacnt);
  CU_ASSERT(1 == fr.stream.data[0].len);
}

void test_ngtcp2_pkt_decode_stream_frame(void) {
  uint8_t buf[256];
  size_t buflen;
  ngtcp2_frame fr;
  ngtcp2_ssize rv;
  size_t expectedlen;

  /* 32 bits Stream ID + 62 bits Offset + Data Length */
  buflen = ngtcp2_t_encode_stream_frame(buf, NGTCP2_STREAM_LEN_BIT, 0xf1f2f3f4u,
                                        0x31f2f3f4f5f6f7f8llu, 0x14);

  expectedlen = 1 + 8 + 8 + 1 + 20;

  CU_ASSERT(expectedlen == buflen);

  rv = ngtcp2_pkt_decode_stream_frame(&fr.stream, buf, buflen);

  CU_ASSERT((ngtcp2_ssize)expectedlen == rv);
  CU_ASSERT(0 == fr.stream.fin);
  CU_ASSERT(0xf1f2f3f4u == fr.stream.stream_id);
  CU_ASSERT(0x31f2f3f4f5f6f7f8llu == fr.stream.offset);
  CU_ASSERT(1 == fr.stream.datacnt);
  CU_ASSERT(0x14 == fr.stream.data[0].len);

  /* Cutting 1 bytes from the tail must cause invalid argument
     error */
  rv = ngtcp2_pkt_decode_stream_frame(&fr.stream, buf, buflen - 1);

  CU_ASSERT(NGTCP2_ERR_FRAME_ENCODING == rv);

  memset(&fr, 0, sizeof(fr));

  /* 6 bits Stream ID + no Offset + Data Length */
  buflen = ngtcp2_t_encode_stream_frame(buf, NGTCP2_STREAM_LEN_BIT, 0x31, 0x00,
                                        0x14);

  expectedlen = 1 + 1 + 0 + 1 + 20;

  CU_ASSERT(expectedlen == buflen);

  rv = ngtcp2_pkt_decode_stream_frame(&fr.stream, buf, buflen);

  CU_ASSERT((ngtcp2_ssize)expectedlen == rv);
  CU_ASSERT(0 == fr.stream.fin);
  CU_ASSERT(0x31 == fr.stream.stream_id);
  CU_ASSERT(0x00 == fr.stream.offset);
  CU_ASSERT(1 == fr.stream.datacnt);
  CU_ASSERT(0x14 == fr.stream.data[0].len);

  /* Cutting 1 bytes from the tail must cause invalid argument
     error */
  rv = ngtcp2_pkt_decode_stream_frame(&fr.stream, buf, buflen - 1);

  CU_ASSERT(NGTCP2_ERR_FRAME_ENCODING == rv);

  memset(&fr, 0, sizeof(fr));

  /* Fin bit set + no Data Length */
  buflen = ngtcp2_t_encode_stream_frame(buf, NGTCP2_STREAM_FIN_BIT, 0x31f2f3f4u,
                                        0x00, 0x14);

  expectedlen = 1 + 4 + 20;

  CU_ASSERT(expectedlen == buflen);

  rv = ngtcp2_pkt_decode_stream_frame(&fr.stream, buf, buflen);

  CU_ASSERT((ngtcp2_ssize)expectedlen == rv);
  CU_ASSERT(1 == fr.stream.fin);
  CU_ASSERT(0x31f2f3f4u == fr.stream.stream_id);
  CU_ASSERT(0x00 == fr.stream.offset);
  CU_ASSERT(1 == fr.stream.datacnt);
  CU_ASSERT(0x14 == fr.stream.data[0].len);

  memset(&fr, 0, sizeof(fr));
}

void test_ngtcp2_pkt_decode_ack_frame(void) {
  uint8_t buf[256];
  size_t buflen;
  ngtcp2_frame fr;
  ngtcp2_ssize rv;
  size_t expectedlen;

  /* 62 bits Largest Acknowledged */
  buflen = ngtcp2_t_encode_ack_frame(buf, 0x31f2f3f4f5f6f7f8llu,
                                     0x31e2e3e4e5e6e7e8llu, 99,
                                     0x31d2d3d4d5d6d7d8llu);

  expectedlen = 1 + 8 + 1 + 1 + 8 + 2 + 8;

  CU_ASSERT(expectedlen == buflen);

  rv = ngtcp2_pkt_decode_ack_frame(&fr.ack, buf, buflen);

  CU_ASSERT((ngtcp2_ssize)expectedlen == rv);
  CU_ASSERT(0x31f2f3f4f5f6f7f8llu == fr.ack.largest_ack);
  CU_ASSERT(1 == fr.ack.rangecnt);
  CU_ASSERT(0x31e2e3e4e5e6e7e8llu == fr.ack.first_ack_range);
  CU_ASSERT(99 == fr.ack.ranges[0].gap);
  CU_ASSERT(0x31d2d3d4d5d6d7d8llu == fr.ack.ranges[0].len);
}

void test_ngtcp2_pkt_decode_padding_frame(void) {
  uint8_t buf[256];
  ngtcp2_frame fr;
  ngtcp2_ssize rv;
  size_t paddinglen = 31;

  memset(buf, 0, paddinglen);
  buf[paddinglen] = NGTCP2_FRAME_STREAM;

  rv = ngtcp2_pkt_decode_padding_frame(&fr.padding, buf, paddinglen + 1);

  CU_ASSERT((ngtcp2_ssize)paddinglen == rv);
  CU_ASSERT((size_t)31 == fr.padding.len);
}

void test_ngtcp2_pkt_encode_stream_frame(void) {
  const uint8_t data[] = "0123456789abcdef0";
  uint8_t buf[256];
  ngtcp2_frame fr, nfr;
  ngtcp2_ssize rv;
  size_t framelen;
  size_t i;

  /* 32 bits Stream ID + 62 bits Offset + Data Length */
  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.fin = 0;
  fr.stream.stream_id = 0xf1f2f3f4u;
  fr.stream.offset = 0x31f2f3f4f5f6f7f8llu;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = strsize(data);
  fr.stream.data[0].base = (uint8_t *)data;

  framelen = 1 + 8 + 8 + 1 + 17;

  rv = ngtcp2_pkt_encode_stream_frame(buf, sizeof(buf), &fr.stream);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_stream_frame(&nfr.stream, buf, framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr.type == nfr.type);
  CU_ASSERT((NGTCP2_STREAM_OFF_BIT | NGTCP2_STREAM_LEN_BIT) ==
            nfr.stream.flags);
  CU_ASSERT(fr.stream.fin == nfr.stream.fin);
  CU_ASSERT(fr.stream.stream_id == nfr.stream.stream_id);
  CU_ASSERT(fr.stream.offset == nfr.stream.offset);
  CU_ASSERT(1 == nfr.stream.datacnt);
  CU_ASSERT(fr.stream.data[0].len == nfr.stream.data[0].len);
  CU_ASSERT(0 == memcmp(fr.stream.data[0].base, nfr.stream.data[0].base,
                        fr.stream.data[0].len));

  memset(&nfr, 0, sizeof(nfr));

  /* 6 bits Stream ID + No Offset + Data Length */
  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.fin = 0;
  fr.stream.stream_id = 0x31;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = strsize(data);
  fr.stream.data[0].base = (uint8_t *)data;

  framelen = 1 + 1 + 1 + 17;

  rv = ngtcp2_pkt_encode_stream_frame(buf, sizeof(buf), &fr.stream);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_stream_frame(&nfr.stream, buf, framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr.type == nfr.type);
  CU_ASSERT(NGTCP2_STREAM_LEN_BIT == nfr.stream.flags);
  CU_ASSERT(fr.stream.fin == nfr.stream.fin);
  CU_ASSERT(fr.stream.stream_id == nfr.stream.stream_id);
  CU_ASSERT(fr.stream.offset == nfr.stream.offset);
  CU_ASSERT(1 == nfr.stream.datacnt);
  CU_ASSERT(fr.stream.data[0].len == nfr.stream.data[0].len);
  CU_ASSERT(0 == memcmp(fr.stream.data[0].base, nfr.stream.data[0].base,
                        fr.stream.data[0].len));

  memset(&nfr, 0, sizeof(nfr));

  /* Fin + 32 bits Stream ID + 62 bits Offset + Data Length */
  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.fin = 1;
  fr.stream.stream_id = 0xf1f2f3f4u;
  fr.stream.offset = 0x31f2f3f4f5f6f7f8llu;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = strsize(data);
  fr.stream.data[0].base = (uint8_t *)data;

  framelen = 1 + 8 + 8 + 1 + 17;

  rv = ngtcp2_pkt_encode_stream_frame(buf, sizeof(buf), &fr.stream);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_stream_frame(&nfr.stream, buf, framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr.type == nfr.type);
  CU_ASSERT((NGTCP2_STREAM_FIN_BIT | NGTCP2_STREAM_OFF_BIT |
             NGTCP2_STREAM_LEN_BIT) == nfr.stream.flags);
  CU_ASSERT(fr.stream.fin == nfr.stream.fin);
  CU_ASSERT(fr.stream.stream_id == nfr.stream.stream_id);
  CU_ASSERT(fr.stream.offset == nfr.stream.offset);
  CU_ASSERT(1 == nfr.stream.datacnt);
  CU_ASSERT(fr.stream.data[0].len == nfr.stream.data[0].len);
  CU_ASSERT(0 == memcmp(fr.stream.data[0].base, nfr.stream.data[0].base,
                        fr.stream.data[0].len));

  /* Make sure that we check the length properly. */
  for (i = 1; i < framelen; ++i) {
    rv = ngtcp2_pkt_decode_stream_frame(&nfr.stream, buf, i);

    CU_ASSERT(NGTCP2_ERR_FRAME_ENCODING == rv);
  }

  memset(&nfr, 0, sizeof(nfr));

  /* NOBUF: Fin + 32 bits Stream ID + 62 bits Offset + Data Length */
  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.fin = 1;
  fr.stream.stream_id = 0xf1f2f3f4u;
  fr.stream.offset = 0x31f2f3f4f5f6f7f8llu;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = strsize(data);
  fr.stream.data[0].base = (uint8_t *)data;

  framelen = 1 + 8 + 8 + 1 + 17;

  rv = ngtcp2_pkt_encode_stream_frame(buf, framelen - 1, &fr.stream);

  CU_ASSERT(NGTCP2_ERR_NOBUF == rv);
}

void test_ngtcp2_pkt_encode_ack_frame(void) {
  uint8_t buf[256];
  ngtcp2_max_frame mfr, nmfr;
  ngtcp2_frame *fr = &mfr.fr, *nfr = &nmfr.fr;
  ngtcp2_ssize rv;
  size_t framelen;
  size_t i;
  ngtcp2_ack_range *ranges;

  /* 0 Num Blocks */
  fr->type = NGTCP2_FRAME_ACK;
  fr->ack.largest_ack = 0xf1f2f3f4llu;
  fr->ack.first_ack_range = 0;
  fr->ack.ack_delay = 0;
  fr->ack.rangecnt = 0;

  framelen = 1 + 8 + 1 + 1 + 1;

  rv = ngtcp2_pkt_encode_ack_frame(buf, sizeof(buf), &fr->ack);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_ack_frame(&nfr->ack, buf, framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr->type == nfr->type);
  CU_ASSERT(fr->ack.largest_ack == nfr->ack.largest_ack);
  CU_ASSERT(fr->ack.ack_delay == nfr->ack.ack_delay);
  CU_ASSERT(fr->ack.rangecnt == nfr->ack.rangecnt);

  memset(&nmfr, 0, sizeof(nmfr));

  /* 2 Num Blocks */
  fr->type = NGTCP2_FRAME_ACK;
  fr->ack.largest_ack = 0xf1f2f3f4llu;
  fr->ack.first_ack_range = 0xe1e2e3e4llu;
  fr->ack.ack_delay = 0xf1f2;
  fr->ack.rangecnt = 2;
  ranges = fr->ack.ranges;
  ranges[0].gap = 255;
  ranges[0].len = 0xd1d2d3d4llu;
  ranges[1].gap = 1;
  ranges[1].len = 0xd1d2d3d4llu;

  framelen = 1 + 8 + 4 + 1 + 8 + (2 + 8) + (1 + 8);

  rv = ngtcp2_pkt_encode_ack_frame(buf, sizeof(buf), &fr->ack);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_ack_frame(&nfr->ack, buf, framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr->type == nfr->type);
  CU_ASSERT(fr->ack.largest_ack == nfr->ack.largest_ack);
  CU_ASSERT(fr->ack.ack_delay == nfr->ack.ack_delay);
  CU_ASSERT(fr->ack.rangecnt == nfr->ack.rangecnt);

  for (i = 0; i < fr->ack.rangecnt; ++i) {
    CU_ASSERT(fr->ack.ranges[i].gap == nfr->ack.ranges[i].gap);
    CU_ASSERT(fr->ack.ranges[i].len == nfr->ack.ranges[i].len);
  }

  memset(&nmfr, 0, sizeof(nmfr));
}

void test_ngtcp2_pkt_encode_ack_ecn_frame(void) {
  uint8_t buf[256];
  ngtcp2_max_frame mfr, nmfr;
  ngtcp2_frame *fr = &mfr.fr, *nfr = &nmfr.fr;
  ngtcp2_ssize rv;
  size_t framelen;
  size_t i;
  ngtcp2_ack_range *ranges;

  /* 0 Num Blocks */
  fr->type = NGTCP2_FRAME_ACK_ECN;
  fr->ack.largest_ack = 0xf1f2f3f4llu;
  fr->ack.first_ack_range = 0;
  fr->ack.ack_delay = 0;
  fr->ack.rangecnt = 0;
  fr->ack.ecn.ect0 = 64;
  fr->ack.ecn.ect1 = 16384;
  fr->ack.ecn.ce = 1073741824;

  framelen = 1 + 8 + 1 + 1 + 1 + 2 + 4 + 8;

  rv = ngtcp2_pkt_encode_ack_frame(buf, sizeof(buf), &fr->ack);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_ack_frame(&nfr->ack, buf, framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr->type == nfr->type);
  CU_ASSERT(fr->ack.largest_ack == nfr->ack.largest_ack);
  CU_ASSERT(fr->ack.ack_delay == nfr->ack.ack_delay);
  CU_ASSERT(fr->ack.rangecnt == nfr->ack.rangecnt);
  CU_ASSERT(fr->ack.ecn.ect0 == nfr->ack.ecn.ect0);
  CU_ASSERT(fr->ack.ecn.ect1 == nfr->ack.ecn.ect1);
  CU_ASSERT(fr->ack.ecn.ce == nfr->ack.ecn.ce);

  memset(&nmfr, 0, sizeof(nmfr));

  /* 2 Num Blocks */
  fr->type = NGTCP2_FRAME_ACK_ECN;
  fr->ack.largest_ack = 0xf1f2f3f4llu;
  fr->ack.first_ack_range = 0xe1e2e3e4llu;
  fr->ack.ack_delay = 0xf1f2;
  fr->ack.rangecnt = 2;
  ranges = fr->ack.ranges;
  ranges[0].gap = 255;
  ranges[0].len = 0xd1d2d3d4llu;
  ranges[1].gap = 1;
  ranges[1].len = 0xd1d2d3d4llu;
  fr->ack.ecn.ect0 = 0;
  fr->ack.ecn.ect1 = 64;
  fr->ack.ecn.ce = 16384;

  framelen = 1 + 8 + 4 + 1 + 8 + (2 + 8) + (1 + 8) + 1 + 2 + 4;

  rv = ngtcp2_pkt_encode_ack_frame(buf, sizeof(buf), &fr->ack);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_ack_frame(&nfr->ack, buf, framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr->type == nfr->type);
  CU_ASSERT(fr->ack.largest_ack == nfr->ack.largest_ack);
  CU_ASSERT(fr->ack.ack_delay == nfr->ack.ack_delay);
  CU_ASSERT(fr->ack.rangecnt == nfr->ack.rangecnt);

  for (i = 0; i < fr->ack.rangecnt; ++i) {
    CU_ASSERT(fr->ack.ranges[i].gap == nfr->ack.ranges[i].gap);
    CU_ASSERT(fr->ack.ranges[i].len == nfr->ack.ranges[i].len);
  }

  CU_ASSERT(fr->ack.ecn.ect0 == nfr->ack.ecn.ect0);
  CU_ASSERT(fr->ack.ecn.ect1 == nfr->ack.ecn.ect1);
  CU_ASSERT(fr->ack.ecn.ce == nfr->ack.ecn.ce);

  memset(&nmfr, 0, sizeof(nmfr));
}

void test_ngtcp2_pkt_encode_reset_stream_frame(void) {
  uint8_t buf[32];
  ngtcp2_reset_stream fr, nfr;
  ngtcp2_ssize rv;
  size_t framelen = 1 + 4 + 4 + 8;

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.stream_id = 1000000007;
  fr.app_error_code = 0xe1e2;
  fr.final_size = 0x31f2f3f4f5f6f7f8llu;

  rv = ngtcp2_pkt_encode_reset_stream_frame(buf, sizeof(buf), &fr);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_reset_stream_frame(&nfr, buf, framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr.type == nfr.type);
  CU_ASSERT(fr.stream_id == nfr.stream_id);
  CU_ASSERT(fr.app_error_code == nfr.app_error_code);
  CU_ASSERT(fr.final_size == nfr.final_size);
}

void test_ngtcp2_pkt_encode_connection_close_frame(void) {
  uint8_t buf[2048];
  ngtcp2_frame fr, nfr;
  ngtcp2_ssize rv;
  size_t framelen;
  uint8_t reason[1024];

  memset(reason, 0xfa, sizeof(reason));

  /* no Reason Phrase */
  fr.type = NGTCP2_FRAME_CONNECTION_CLOSE;
  fr.connection_close.error_code = 0xf1f2u;
  fr.connection_close.frame_type = 255;
  fr.connection_close.reasonlen = 0;
  fr.connection_close.reason = NULL;

  framelen = 1 + 4 + 2 + 1;

  rv = ngtcp2_pkt_encode_connection_close_frame(buf, sizeof(buf),
                                                &fr.connection_close);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_connection_close_frame(&nfr.connection_close, buf,
                                                framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr.type == nfr.type);
  CU_ASSERT(fr.connection_close.error_code == nfr.connection_close.error_code);
  CU_ASSERT(fr.connection_close.reasonlen == nfr.connection_close.reasonlen);
  CU_ASSERT(fr.connection_close.reason == nfr.connection_close.reason);

  memset(&nfr, 0, sizeof(nfr));

  /* 1024 bytes Reason Phrase */
  fr.type = NGTCP2_FRAME_CONNECTION_CLOSE;
  fr.connection_close.error_code = 0xf3f4u;
  fr.connection_close.frame_type = 0;
  fr.connection_close.reasonlen = sizeof(reason);
  fr.connection_close.reason = reason;

  framelen = 1 + 4 + 1 + 2 + sizeof(reason);

  rv = ngtcp2_pkt_encode_connection_close_frame(buf, sizeof(buf),
                                                &fr.connection_close);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_connection_close_frame(&nfr.connection_close, buf,
                                                framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr.type == nfr.type);
  CU_ASSERT(fr.connection_close.error_code == nfr.connection_close.error_code);
  CU_ASSERT(fr.connection_close.reasonlen == nfr.connection_close.reasonlen);
  CU_ASSERT(0 == memcmp(reason, nfr.connection_close.reason, sizeof(reason)));

  memset(&nfr, 0, sizeof(nfr));
}

void test_ngtcp2_pkt_encode_connection_close_app_frame(void) {
  uint8_t buf[2048];
  ngtcp2_frame fr, nfr;
  ngtcp2_ssize rv;
  size_t framelen;
  uint8_t reason[1024];

  memset(reason, 0xfa, sizeof(reason));

  /* no Reason Phrase */
  fr.type = NGTCP2_FRAME_CONNECTION_CLOSE_APP;
  fr.connection_close.error_code = 0xf1f2u;
  fr.connection_close.frame_type = 0xff; /* This must be ignored. */
  fr.connection_close.reasonlen = 0;
  fr.connection_close.reason = NULL;

  framelen = 1 + 4 + 1;

  rv = ngtcp2_pkt_encode_connection_close_frame(buf, sizeof(buf),
                                                &fr.connection_close);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_connection_close_frame(&nfr.connection_close, buf,
                                                framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr.type == nfr.type);
  CU_ASSERT(fr.connection_close.error_code == nfr.connection_close.error_code);
  CU_ASSERT(0 == nfr.connection_close.frame_type);
  CU_ASSERT(fr.connection_close.reasonlen == nfr.connection_close.reasonlen);
  CU_ASSERT(fr.connection_close.reason == nfr.connection_close.reason);

  memset(&nfr, 0, sizeof(nfr));
}

void test_ngtcp2_pkt_encode_max_data_frame(void) {
  uint8_t buf[16];
  ngtcp2_max_data fr, nfr;
  ngtcp2_ssize rv;
  size_t framelen = 1 + 8;

  fr.type = NGTCP2_FRAME_MAX_DATA;
  fr.max_data = 0x31f2f3f4f5f6f7f8llu;

  rv = ngtcp2_pkt_encode_max_data_frame(buf, sizeof(buf), &fr);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_max_data_frame(&nfr, buf, framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr.type == nfr.type);
  CU_ASSERT(fr.max_data == nfr.max_data);
}

void test_ngtcp2_pkt_encode_max_stream_data_frame(void) {
  uint8_t buf[17];
  ngtcp2_max_stream_data fr, nfr;
  ngtcp2_ssize rv;
  size_t framelen = 1 + 8 + 8;

  fr.type = NGTCP2_FRAME_MAX_STREAM_DATA;
  fr.stream_id = 0xf1f2f3f4u;
  fr.max_stream_data = 0x35f6f7f8f9fafbfcllu;

  rv = ngtcp2_pkt_encode_max_stream_data_frame(buf, sizeof(buf), &fr);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_max_stream_data_frame(&nfr, buf, framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr.type == nfr.type);
  CU_ASSERT(fr.stream_id == nfr.stream_id);
  CU_ASSERT(fr.max_stream_data == nfr.max_stream_data);
}

void test_ngtcp2_pkt_encode_max_streams_frame(void) {
  uint8_t buf[16];
  ngtcp2_max_streams fr, nfr;
  ngtcp2_ssize rv;
  size_t framelen = 1 + 8;

  fr.type = NGTCP2_FRAME_MAX_STREAMS_BIDI;
  fr.max_streams = 0xf1f2f3f4u;

  rv = ngtcp2_pkt_encode_max_streams_frame(buf, sizeof(buf), &fr);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_max_streams_frame(&nfr, buf, framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr.type == nfr.type);
  CU_ASSERT(fr.max_streams == nfr.max_streams);
}

void test_ngtcp2_pkt_encode_ping_frame(void) {
  uint8_t buf[3];
  ngtcp2_ping fr, nfr;
  ngtcp2_ssize rv;
  size_t framelen;

  fr.type = NGTCP2_FRAME_PING;

  framelen = 1;

  rv = ngtcp2_pkt_encode_ping_frame(buf, sizeof(buf), &fr);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_ping_frame(&nfr, buf, framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr.type == nfr.type);
}

void test_ngtcp2_pkt_encode_data_blocked_frame(void) {
  uint8_t buf[9];
  ngtcp2_data_blocked fr, nfr;
  ngtcp2_ssize rv;
  size_t framelen = 1 + 8;

  fr.type = NGTCP2_FRAME_DATA_BLOCKED;
  fr.offset = 0x31f2f3f4f5f6f7f8llu;

  rv = ngtcp2_pkt_encode_data_blocked_frame(buf, sizeof(buf), &fr);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_data_blocked_frame(&nfr, buf, framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr.type == nfr.type);
  CU_ASSERT(fr.offset == nfr.offset);
}

void test_ngtcp2_pkt_encode_stream_data_blocked_frame(void) {
  uint8_t buf[17];
  ngtcp2_stream_data_blocked fr, nfr;
  ngtcp2_ssize rv;
  size_t framelen = 1 + 8 + 8;

  fr.type = NGTCP2_FRAME_STREAM_DATA_BLOCKED;
  fr.stream_id = 0xf1f2f3f4u;
  fr.offset = 0x35f6f7f8f9fafbfcllu;

  rv = ngtcp2_pkt_encode_stream_data_blocked_frame(buf, sizeof(buf), &fr);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_stream_data_blocked_frame(&nfr, buf, framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr.type == nfr.type);
  CU_ASSERT(fr.stream_id == nfr.stream_id);
  CU_ASSERT(fr.offset == nfr.offset);
}

void test_ngtcp2_pkt_encode_streams_blocked_frame(void) {
  uint8_t buf[9];
  ngtcp2_streams_blocked fr, nfr;
  ngtcp2_ssize rv;
  size_t framelen = 1 + 8;

  fr.type = NGTCP2_FRAME_STREAMS_BLOCKED_BIDI;
  fr.max_streams = 0xf1f2f3f4u;

  rv = ngtcp2_pkt_encode_streams_blocked_frame(buf, sizeof(buf), &fr);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_streams_blocked_frame(&nfr, buf, framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr.type == nfr.type);
  CU_ASSERT(fr.max_streams == nfr.max_streams);
}

void test_ngtcp2_pkt_encode_new_connection_id_frame(void) {
  uint8_t buf[256];
  ngtcp2_new_connection_id fr, nfr;
  ngtcp2_ssize rv;
  size_t framelen = 1 + 4 + 2 + 1 + 18 + NGTCP2_STATELESS_RESET_TOKENLEN;

  fr.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.seq = 1000000009;
  fr.retire_prior_to = 255;
  scid_init(&fr.cid);
  memset(fr.stateless_reset_token, 0xe1, sizeof(fr.stateless_reset_token));

  rv = ngtcp2_pkt_encode_new_connection_id_frame(buf, sizeof(buf), &fr);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_new_connection_id_frame(&nfr, buf, framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr.type == nfr.type);
  CU_ASSERT(fr.seq == nfr.seq);
  CU_ASSERT(ngtcp2_cid_eq(&fr.cid, &nfr.cid));
  CU_ASSERT(0 == memcmp(fr.stateless_reset_token, nfr.stateless_reset_token,
                        sizeof(fr.stateless_reset_token)));
}

void test_ngtcp2_pkt_encode_stop_sending_frame(void) {
  uint8_t buf[16];
  ngtcp2_stop_sending fr, nfr;
  ngtcp2_ssize rv;
  size_t framelen = 1 + 8 + 4;

  fr.type = NGTCP2_FRAME_STOP_SENDING;
  fr.stream_id = 0xf1f2f3f4u;
  fr.app_error_code = 0xe1e2u;

  rv = ngtcp2_pkt_encode_stop_sending_frame(buf, sizeof(buf), &fr);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_stop_sending_frame(&nfr, buf, framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr.type == nfr.type);
  CU_ASSERT(fr.stream_id == nfr.stream_id);
  CU_ASSERT(fr.app_error_code == nfr.app_error_code);
}

void test_ngtcp2_pkt_encode_path_challenge_frame(void) {
  uint8_t buf[9];
  ngtcp2_path_challenge fr, nfr;
  ngtcp2_ssize rv;
  size_t framelen = 1 + 8;
  size_t i;

  fr.type = NGTCP2_FRAME_PATH_CHALLENGE;
  for (i = 0; i < sizeof(fr.data); ++i) {
    fr.data[i] = (uint8_t)(i + 1);
  }

  rv = ngtcp2_pkt_encode_path_challenge_frame(buf, sizeof(buf), &fr);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_path_challenge_frame(&nfr, buf, framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr.type == nfr.type);
  CU_ASSERT(0 == memcmp(fr.data, nfr.data, sizeof(fr.data)));
}

void test_ngtcp2_pkt_encode_path_response_frame(void) {
  uint8_t buf[9];
  ngtcp2_path_response fr, nfr;
  ngtcp2_ssize rv;
  size_t framelen = 1 + 8;
  size_t i;

  fr.type = NGTCP2_FRAME_PATH_RESPONSE;
  for (i = 0; i < sizeof(fr.data); ++i) {
    fr.data[i] = (uint8_t)(i + 1);
  }

  rv = ngtcp2_pkt_encode_path_response_frame(buf, sizeof(buf), &fr);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_path_response_frame(&nfr, buf, framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr.type == nfr.type);
  CU_ASSERT(0 == memcmp(fr.data, nfr.data, sizeof(fr.data)));
}

void test_ngtcp2_pkt_encode_crypto_frame(void) {
  const uint8_t data[] = "0123456789abcdef1";
  uint8_t buf[256];
  ngtcp2_frame fr, nfr;
  ngtcp2_ssize rv;
  size_t framelen;

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.flags = 0;
  fr.stream.fin = 0;
  fr.stream.stream_id = 0;
  fr.stream.offset = 0x31f2f3f4f5f6f7f8llu;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = strsize(data);
  fr.stream.data[0].base = (uint8_t *)data;

  framelen = 1 + 8 + 1 + 17;

  rv = ngtcp2_pkt_encode_crypto_frame(buf, sizeof(buf), &fr.stream);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_crypto_frame(&nfr.stream, buf, framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr.type == nfr.type);
  CU_ASSERT(fr.stream.flags == nfr.stream.flags);
  CU_ASSERT(fr.stream.fin == nfr.stream.fin);
  CU_ASSERT(fr.stream.stream_id == nfr.stream.stream_id);
  CU_ASSERT(fr.stream.offset == nfr.stream.offset);
  CU_ASSERT(fr.stream.datacnt == nfr.stream.datacnt);
  CU_ASSERT(fr.stream.data[0].len == nfr.stream.data[0].len);
  CU_ASSERT(0 == memcmp(fr.stream.data[0].base, nfr.stream.data[0].base,
                        fr.stream.data[0].len));
}

void test_ngtcp2_pkt_encode_new_token_frame(void) {
  const uint8_t token[] = "0123456789abcdef2";
  uint8_t buf[256];
  ngtcp2_frame fr, nfr;
  ngtcp2_ssize rv;
  size_t framelen;

  fr.type = NGTCP2_FRAME_NEW_TOKEN;
  fr.new_token.token = (uint8_t *)token;
  fr.new_token.tokenlen = strsize(token);

  framelen = 1 + 1 + strsize(token);

  rv = ngtcp2_pkt_encode_new_token_frame(buf, sizeof(buf), &fr.new_token);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_new_token_frame(&nfr.new_token, buf, framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr.type == nfr.type);
  CU_ASSERT(fr.new_token.tokenlen == nfr.new_token.tokenlen);
  CU_ASSERT(0 == memcmp(fr.new_token.token, nfr.new_token.token,
                        fr.new_token.tokenlen));
}

void test_ngtcp2_pkt_encode_retire_connection_id_frame(void) {
  uint8_t buf[256];
  ngtcp2_frame fr, nfr;
  ngtcp2_ssize rv;
  size_t framelen;

  fr.type = NGTCP2_FRAME_RETIRE_CONNECTION_ID;
  fr.retire_connection_id.seq = 1000000007;

  framelen = 1 + ngtcp2_put_uvarintlen(fr.retire_connection_id.seq);

  rv = ngtcp2_pkt_encode_retire_connection_id_frame(buf, sizeof(buf),
                                                    &fr.retire_connection_id);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_retire_connection_id_frame(&nfr.retire_connection_id,
                                                    buf, framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr.type == nfr.type);
  CU_ASSERT(fr.retire_connection_id.seq == nfr.retire_connection_id.seq);
}

void test_ngtcp2_pkt_encode_handshake_done_frame(void) {
  uint8_t buf[16];
  ngtcp2_handshake_done fr, nfr;
  ngtcp2_ssize rv;
  size_t framelen = 1;

  fr.type = NGTCP2_FRAME_HANDSHAKE_DONE;

  rv = ngtcp2_pkt_encode_handshake_done_frame(buf, sizeof(buf), &fr);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_handshake_done_frame(&nfr, buf, framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr.type == nfr.type);
}

void test_ngtcp2_pkt_encode_datagram_frame(void) {
  const uint8_t data[] = "0123456789abcdef3";
  uint8_t buf[256];
  ngtcp2_frame fr, nfr;
  ngtcp2_ssize rv;
  size_t framelen;

  fr.type = NGTCP2_FRAME_DATAGRAM_LEN;
  fr.datagram.datacnt = 1;
  fr.datagram.data = fr.datagram.rdata;
  fr.datagram.rdata[0].len = strsize(data);
  fr.datagram.rdata[0].base = (uint8_t *)data;

  framelen = 1 + 1 + 17;

  rv = ngtcp2_pkt_encode_datagram_frame(buf, sizeof(buf), &fr.datagram);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_datagram_frame(&nfr.datagram, buf, framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr.type == nfr.type);
  CU_ASSERT(fr.datagram.datacnt == nfr.datagram.datacnt);
  CU_ASSERT(fr.datagram.data->len == nfr.datagram.data->len);
  CU_ASSERT(0 == memcmp(fr.datagram.data->base, nfr.datagram.data->base,
                        fr.datagram.data->len));

  memset(&nfr, 0, sizeof(nfr));

  /* Without length field */
  fr.type = NGTCP2_FRAME_DATAGRAM;
  fr.datagram.datacnt = 1;
  fr.datagram.data = fr.datagram.rdata;
  fr.datagram.rdata[0].len = strsize(data);
  fr.datagram.rdata[0].base = (uint8_t *)data;

  framelen = 1 + 17;

  rv = ngtcp2_pkt_encode_datagram_frame(buf, sizeof(buf), &fr.datagram);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_datagram_frame(&nfr.datagram, buf, framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr.type == nfr.type);
  CU_ASSERT(fr.datagram.datacnt == nfr.datagram.datacnt);
  CU_ASSERT(fr.datagram.data->len == nfr.datagram.data->len);
  CU_ASSERT(0 == memcmp(fr.datagram.data->base, nfr.datagram.data->base,
                        fr.datagram.data->len));

  memset(&nfr, 0, sizeof(nfr));

  /* Zero length data with length field */
  fr.type = NGTCP2_FRAME_DATAGRAM_LEN;
  fr.datagram.datacnt = 0;
  fr.datagram.data = NULL;

  framelen = 1 + 1;

  rv = ngtcp2_pkt_encode_datagram_frame(buf, sizeof(buf), &fr.datagram);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_datagram_frame(&nfr.datagram, buf, framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr.type == nfr.type);
  CU_ASSERT(fr.datagram.datacnt == nfr.datagram.datacnt);
  CU_ASSERT(NULL == nfr.datagram.data);

  /* Zero length data without length field */
  fr.type = NGTCP2_FRAME_DATAGRAM;
  fr.datagram.datacnt = 0;
  fr.datagram.data = NULL;

  framelen = 1;

  rv = ngtcp2_pkt_encode_datagram_frame(buf, sizeof(buf), &fr.datagram);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);

  rv = ngtcp2_pkt_decode_datagram_frame(&nfr.datagram, buf, framelen);

  CU_ASSERT((ngtcp2_ssize)framelen == rv);
  CU_ASSERT(fr.type == nfr.type);
  CU_ASSERT(fr.datagram.datacnt == nfr.datagram.datacnt);
  CU_ASSERT(NULL == nfr.datagram.data);
}

void test_ngtcp2_pkt_adjust_pkt_num(void) {
  CU_ASSERT(0xaa831f94llu ==
            ngtcp2_pkt_adjust_pkt_num(0xaa82f30ellu, 0x1f94, 2));

  CU_ASSERT(0xff == ngtcp2_pkt_adjust_pkt_num(0x0100, 0xff, 1));
  CU_ASSERT(0x01ff == ngtcp2_pkt_adjust_pkt_num(0x01ff, 0xff, 1));
  CU_ASSERT(0x0fff == ngtcp2_pkt_adjust_pkt_num(0x1000, 0xff, 1));
  CU_ASSERT(0x80 == ngtcp2_pkt_adjust_pkt_num(0x00, 0x80, 1));
  CU_ASSERT(0x3fffffffffffffabllu ==
            ngtcp2_pkt_adjust_pkt_num(NGTCP2_MAX_PKT_NUM, 0xab, 1));
  CU_ASSERT(0x4000000000000000llu ==
            ngtcp2_pkt_adjust_pkt_num(NGTCP2_MAX_PKT_NUM, 0x00, 1));
  CU_ASSERT(250 == ngtcp2_pkt_adjust_pkt_num(255, 250, 1));
  CU_ASSERT(8 == ngtcp2_pkt_adjust_pkt_num(50, 8, 1));
  CU_ASSERT(0 == ngtcp2_pkt_adjust_pkt_num(-1, 0, 1));
}

void test_ngtcp2_pkt_validate_ack(void) {
  int rv;
  ngtcp2_ack fr;

  /* too long first_ack_range */
  fr.largest_ack = 1;
  fr.first_ack_range = 2;
  fr.rangecnt = 0;

  rv = ngtcp2_pkt_validate_ack(&fr, 0);

  CU_ASSERT(NGTCP2_ERR_ACK_FRAME == rv);

  /* gap is too large */
  fr.largest_ack = 250;
  fr.first_ack_range = 1;
  fr.rangecnt = 1;
  fr.ranges[0].gap = 248;
  fr.ranges[0].len = 0;

  rv = ngtcp2_pkt_validate_ack(&fr, 0);

  CU_ASSERT(NGTCP2_ERR_ACK_FRAME == rv);

  /* too large range len */
  fr.largest_ack = 250;
  fr.first_ack_range = 0;
  fr.rangecnt = 1;
  fr.ranges[0].gap = 248;
  fr.ranges[0].len = 1;

  rv = ngtcp2_pkt_validate_ack(&fr, 0);

  CU_ASSERT(NGTCP2_ERR_ACK_FRAME == rv);

  /* first ack range contains packet number that is smaller than the
     minimum. */
  fr.largest_ack = 250;
  fr.first_ack_range = 0;
  fr.rangecnt = 0;

  rv = ngtcp2_pkt_validate_ack(&fr, 251);

  CU_ASSERT(NGTCP2_ERR_PROTO == rv);

  /* second ack range contains packet number that is smaller than the
     minimum. */
  fr.largest_ack = 250;
  fr.first_ack_range = 0;
  fr.rangecnt = 1;
  fr.ranges[0].gap = 0;
  fr.ranges[0].len = 0;

  rv = ngtcp2_pkt_validate_ack(&fr, 249);

  CU_ASSERT(NGTCP2_ERR_PROTO == rv);
}

void test_ngtcp2_pkt_write_stateless_reset(void) {
  uint8_t buf[256];
  ngtcp2_ssize spktlen;
  uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN];
  uint8_t rand[256];
  size_t i;
  uint8_t *p;
  size_t randlen;

  memset(rand, 0, sizeof(rand));
  for (i = 0; i < NGTCP2_STATELESS_RESET_TOKENLEN; ++i) {
    token[i] = (uint8_t)(i + 1);
  }

  spktlen = ngtcp2_pkt_write_stateless_reset(buf, sizeof(buf), token, rand,
                                             sizeof(rand));

  p = buf;

  CU_ASSERT(256 == spktlen);
  CU_ASSERT(0 == (*p & NGTCP2_HEADER_FORM_BIT));
  CU_ASSERT((*p & NGTCP2_FIXED_BIT_MASK));

  ++p;

  randlen = (size_t)(spktlen - (p - buf) - NGTCP2_STATELESS_RESET_TOKENLEN);

  CU_ASSERT(0 == memcmp(rand, p, randlen));

  p += randlen;

  CU_ASSERT(0 == memcmp(token, p, NGTCP2_STATELESS_RESET_TOKENLEN));

  p += NGTCP2_STATELESS_RESET_TOKENLEN;

  CU_ASSERT(spktlen == p - buf);

  /* Not enough buffer */
  spktlen = ngtcp2_pkt_write_stateless_reset(
      buf,
      NGTCP2_MIN_STATELESS_RESET_RANDLEN - 1 + NGTCP2_STATELESS_RESET_TOKENLEN,
      token, rand, sizeof(rand));

  CU_ASSERT(NGTCP2_ERR_NOBUF == spktlen);
}

void test_ngtcp2_pkt_write_retry(void) {
  uint8_t buf[256];
  ngtcp2_ssize spktlen;
  ngtcp2_cid scid, dcid, odcid;
  ngtcp2_pkt_hd nhd;
  uint8_t token[32];
  size_t i;
  ngtcp2_pkt_retry retry;
  ngtcp2_ssize nread;
  int rv;
  ngtcp2_crypto_aead aead = {0};
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  uint8_t tag[NGTCP2_RETRY_TAGLEN] = {0};

  scid_init(&scid);
  dcid_init(&dcid);
  rcid_init(&odcid);

  for (i = 0; i < sizeof(token); ++i) {
    token[i] = (uint8_t)i;
  }

  spktlen = ngtcp2_pkt_write_retry(buf, sizeof(buf), NGTCP2_PROTO_VER_V1, &dcid,
                                   &scid, &odcid, token, sizeof(token),
                                   null_retry_encrypt, &aead, &aead_ctx);

  CU_ASSERT(spktlen > 0);

  memset(&nhd, 0, sizeof(nhd));

  nread = ngtcp2_pkt_decode_hd_long(&nhd, buf, (size_t)spktlen);

  CU_ASSERT(nread > 0);
  CU_ASSERT(NGTCP2_PKT_RETRY == nhd.type);
  CU_ASSERT(NGTCP2_PROTO_VER_V1 == nhd.version);
  CU_ASSERT(ngtcp2_cid_eq(&dcid, &nhd.dcid));
  CU_ASSERT(ngtcp2_cid_eq(&scid, &nhd.scid));

  rv = ngtcp2_pkt_decode_retry(&retry, buf + nread, (size_t)(spktlen - nread));

  CU_ASSERT(0 == rv);
  CU_ASSERT(sizeof(token) == retry.tokenlen);
  CU_ASSERT(0 == memcmp(token, retry.token, sizeof(token)));
  CU_ASSERT(0 == memcmp(tag, retry.tag, sizeof(tag)));
}

void test_ngtcp2_pkt_write_version_negotiation(void) {
  uint8_t buf[256];
  ngtcp2_ssize spktlen;
  const uint32_t sv[] = {0xf1f2f3f4, 0x1f2f3f4f};
  const uint8_t *p;
  size_t i;
  ngtcp2_cid dcid, scid;
  uint32_t v;

  dcid_init(&dcid);
  scid_init(&scid);

  spktlen = ngtcp2_pkt_write_version_negotiation(
      buf, sizeof(buf), 133, dcid.data, dcid.datalen, scid.data, scid.datalen,
      sv, ngtcp2_arraylen(sv));

  CU_ASSERT((ngtcp2_ssize)(1 + 4 + 1 + dcid.datalen + 1 + scid.datalen +
                           ngtcp2_arraylen(sv) * 4) == spktlen);

  p = buf;

  CU_ASSERT((0xc0 | 133) == buf[0]);

  ++p;

  p = ngtcp2_get_uint32(&v, p);

  CU_ASSERT(0 == v);

  CU_ASSERT(dcid.datalen == *p);

  ++p;

  CU_ASSERT(0 == memcmp(dcid.data, p, dcid.datalen));

  p += dcid.datalen;

  CU_ASSERT(scid.datalen == *p);

  ++p;

  CU_ASSERT(0 == memcmp(scid.data, p, scid.datalen));

  p += scid.datalen;

  for (i = 0; i < ngtcp2_arraylen(sv); ++i) {
    p = ngtcp2_get_uint32(&v, p);

    CU_ASSERT(sv[i] == v);
  }
}

void test_ngtcp2_pkt_stream_max_datalen(void) {
  size_t len;

  len = ngtcp2_pkt_stream_max_datalen(63, 0, 0, 2);

  CU_ASSERT((size_t)-1 == len);

  len = ngtcp2_pkt_stream_max_datalen(63, 0, 0, 3);

  CU_ASSERT(0 == len);

  len = ngtcp2_pkt_stream_max_datalen(63, 0, 1, 3);

  CU_ASSERT(0 == len);

  len = ngtcp2_pkt_stream_max_datalen(63, 0, 1, 4);

  CU_ASSERT(1 == len);

  len = ngtcp2_pkt_stream_max_datalen(63, 1, 1, 4);

  CU_ASSERT(0 == len);

  len = ngtcp2_pkt_stream_max_datalen(63, 0, 63, 66);

  CU_ASSERT(63 == len);

  len = ngtcp2_pkt_stream_max_datalen(63, 0, 63, 65);

  CU_ASSERT(62 == len);

  len = ngtcp2_pkt_stream_max_datalen(63, 0, 1396, 1400);

  CU_ASSERT(1396 == len);

  len = ngtcp2_pkt_stream_max_datalen(63, 0, 1396, 1399);

  CU_ASSERT(1395 == len);

  len = ngtcp2_pkt_stream_max_datalen(63, 0, 1396, 9);

  CU_ASSERT(6 == len);

  len = ngtcp2_pkt_stream_max_datalen(63, 0, 16385, 16391);

  CU_ASSERT(16385 == len);

  len = ngtcp2_pkt_stream_max_datalen(63, 0, 16385, 16390);

  CU_ASSERT(16384 == len);

  len = ngtcp2_pkt_stream_max_datalen(63, 0, 1073741824, 1073741834);

  CU_ASSERT(1073741824 == len);

  len = ngtcp2_pkt_stream_max_datalen(63, 0, 1073741824, 1073741833);

  CU_ASSERT(1073741823 == len);

  len = ngtcp2_pkt_stream_max_datalen(63, 0, 16383, 16387);

  CU_ASSERT(16383 == len);
}
