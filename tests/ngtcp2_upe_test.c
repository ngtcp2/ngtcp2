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
#include "ngtcp2_upe_test.h"

#include <assert.h>

#include <CUnit/CUnit.h>

#include "ngtcp2_upe.h"
#include "ngtcp2_pkt.h"
#include "ngtcp2_conv.h"
#include "ngtcp2_test_helper.h"

void test_ngtcp2_upe_encode(void) {
  const uint8_t ro[256] = {0};
  uint8_t buf[1024];
  ngtcp2_pkt_hd hd, nhd;
  ngtcp2_frame s1 = {0}, s2 = {0}, ns;
  ngtcp2_upe upe;
  int rv;
  size_t pktlen;
  const uint8_t *out;
  ssize_t nread;

  hd.flags = NGTCP2_PKT_FLAG_LONG_FORM;
  hd.type = NGTCP2_PKT_CLIENT_INITIAL;
  hd.conn_id = 1000000009;
  hd.pkt_num = 1000000007;
  hd.version = 0xff;

  s1.type = NGTCP2_FRAME_STREAM;
  s1.stream.fin = 0;
  s1.stream.stream_id = 0x00;
  s1.stream.offset = 0x00;
  s1.stream.datalen = 123;
  s1.stream.data = ro;

  s2.type = NGTCP2_FRAME_STREAM;
  s2.stream.fin = 1;
  s2.stream.stream_id = 0x01;
  s2.stream.offset = 0x1000000009;
  s2.stream.datalen = 255;
  s2.stream.data = ro;

  ngtcp2_upe_init(&upe, buf, sizeof(buf));
  rv = ngtcp2_upe_encode_hd(&upe, &hd);

  CU_ASSERT(0 == rv);

  rv = ngtcp2_upe_encode_frame(&upe, &s1);

  CU_ASSERT(0 == rv);

  rv = ngtcp2_upe_encode_frame(&upe, &s2);

  CU_ASSERT(0 == rv);

  ngtcp2_upe_padding(&upe);

  pktlen = ngtcp2_upe_final(&upe, &out);

  CU_ASSERT(1024 == pktlen);
  CU_ASSERT(buf == out);

  /* Verify checksum */
  rv = ngtcp2_pkt_verify(out, pktlen);

  CU_ASSERT(0 == rv);

  pktlen -= NGTCP2_PKT_MDLEN;

  /* Let's decode packet */
  nread = ngtcp2_pkt_decode_hd_long(&nhd, out, pktlen);

  CU_ASSERT(NGTCP2_LONG_HEADERLEN == nread);
  CU_ASSERT(hd.flags == nhd.flags);
  CU_ASSERT(hd.type == nhd.type);
  CU_ASSERT(hd.conn_id == nhd.conn_id);
  CU_ASSERT(hd.pkt_num == nhd.pkt_num);
  CU_ASSERT(hd.version == nhd.version);

  out += nread;
  pktlen -= (size_t)nread;

  /* Read first STREAM frame */
  nread = ngtcp2_pkt_decode_frame(&ns, out, pktlen);

  CU_ASSERT(nread > 0);
  CU_ASSERT(s1.type == ns.type);
  CU_ASSERT(s1.stream.fin == ns.stream.fin);
  CU_ASSERT(s1.stream.stream_id == ns.stream.stream_id);
  CU_ASSERT(s1.stream.offset == ns.stream.offset);
  CU_ASSERT(s1.stream.datalen == ns.stream.datalen);

  out += nread;
  pktlen -= (size_t)nread;

  /* Read second STREAM frame */
  nread = ngtcp2_pkt_decode_frame(&ns, out, pktlen);

  CU_ASSERT(nread > 0);
  CU_ASSERT(s2.type == ns.type);
  CU_ASSERT(s2.stream.fin == ns.stream.fin);
  CU_ASSERT(s2.stream.stream_id == ns.stream.stream_id);
  CU_ASSERT(s2.stream.offset == ns.stream.offset);
  CU_ASSERT(s2.stream.datalen == ns.stream.datalen);

  out += nread;
  pktlen -= (size_t)nread;

  /* Read PADDING frames to the end */
  nread = ngtcp2_pkt_decode_frame(&ns, out, pktlen);

  CU_ASSERT(nread == (ssize_t)pktlen);
  CU_ASSERT(NGTCP2_FRAME_PADDING == ns.type);
  CU_ASSERT(pktlen == ns.padding.len);
}

void test_ngtcp2_upe_encode_version_negotiation(void) {
  ngtcp2_upe upe;
  const uint32_t sv[] = {0x01, 0x02, 0x03};
  uint8_t buf[256];
  ngtcp2_pkt_hd hd, nhd;
  int rv;
  const uint8_t *out;
  ssize_t spktlen;
  ssize_t nread;
  size_t i;

  ngtcp2_upe_init(&upe, buf, sizeof(buf));

  hd.flags = NGTCP2_PKT_FLAG_LONG_FORM;
  hd.type = NGTCP2_PKT_VERSION_NEGOTIATION;
  hd.conn_id = 1000000009;
  hd.pkt_num = 1000000007;
  hd.version = 0xff;

  rv = ngtcp2_upe_encode_hd(&upe, &hd);

  CU_ASSERT(0 == rv);

  spktlen = ngtcp2_upe_encode_version_negotiation(&upe, &out, sv, arraylen(sv));

  CU_ASSERT(spktlen > 0);

  nread = ngtcp2_pkt_decode_hd_long(&nhd, out, (size_t)spktlen);

  CU_ASSERT(NGTCP2_LONG_HEADERLEN == nread);

  out += nread;
  spktlen -= nread;

  CU_ASSERT(sizeof(sv) == (size_t)spktlen);

  for (i = 0; i < arraylen(sv); ++i) {
    uint32_t v = ngtcp2_get_uint32(out + sizeof(uint32_t) * i);
    CU_ASSERT(sv[i] == v);
  }
}
