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

#include <assert.h>

#include <CUnit/CUnit.h>

#include "ngtcp2_pkt.h"
#include "ngtcp2_test_helper.h"

void test_ngtcp2_pkt_decode_hd_long(void) {
  ngtcp2_pkt_hd hd, nhd;
  uint8_t buf[256];
  ssize_t rv;

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_LONG_FORM,
                     NGTCP2_PKT_VERSION_NEGOTIATION, 0xf1f2f3f4f5f6f7f8llu,
                     0xe1e2e3e4u, 0xd1d2d3d4u);

  rv = ngtcp2_pkt_encode_hd_long(buf, sizeof(buf), &hd);

  CU_ASSERT(NGTCP2_LONG_HEADERLEN == rv);

  rv = ngtcp2_pkt_decode_hd_long(&nhd, buf, NGTCP2_LONG_HEADERLEN);

  CU_ASSERT(NGTCP2_LONG_HEADERLEN == rv);
  CU_ASSERT(hd.flags == nhd.flags);
  CU_ASSERT(hd.conn_id == nhd.conn_id);
  CU_ASSERT(hd.pkt_num == nhd.pkt_num);
  CU_ASSERT(hd.version == nhd.version);
}

void test_ngtcp2_pkt_decode_hd_short(void) {
  ngtcp2_pkt_hd hd, nhd;
  uint8_t buf[256];
  ssize_t rv;
  size_t expectedlen;

  /* NGTCP2_PKT_03 */
  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_03,
                     0xf1f2f3f4f5f6f7f8llu, 0xe1e2e3e4u, 0xd1d2d3d4u);

  expectedlen = 5;

  rv = ngtcp2_pkt_encode_hd_short(buf, sizeof(buf), &hd);

  CU_ASSERT((ssize_t)expectedlen == rv);

  rv = ngtcp2_pkt_decode_hd_short(&nhd, buf, expectedlen);

  CU_ASSERT((ssize_t)expectedlen == rv);
  CU_ASSERT(hd.flags == nhd.flags);
  CU_ASSERT(0 == nhd.conn_id);
  CU_ASSERT(hd.pkt_num == nhd.pkt_num);
  CU_ASSERT(0 == nhd.version);

  /* NGTCP2_PKT_02 */
  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_02,
                     0xf1f2f3f4f5f6f7f8llu, 0xe1e2e3e4u, 0xd1d2d3d4u);

  expectedlen = 3;

  rv = ngtcp2_pkt_encode_hd_short(buf, sizeof(buf), &hd);

  CU_ASSERT((ssize_t)expectedlen == rv);

  rv = ngtcp2_pkt_decode_hd_short(&nhd, buf, expectedlen);

  CU_ASSERT((ssize_t)expectedlen == rv);
  CU_ASSERT(hd.flags == nhd.flags);
  CU_ASSERT(0 == nhd.conn_id);
  CU_ASSERT((hd.pkt_num & 0xffff) == nhd.pkt_num);
  CU_ASSERT(0 == nhd.version);

  /* NGTCP2_PKT_01 */
  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_01,
                     0xf1f2f3f4f5f6f7f8llu, 0xe1e2e3e4u, 0xd1d2d3d4u);

  expectedlen = 2;

  rv = ngtcp2_pkt_encode_hd_short(buf, sizeof(buf), &hd);

  CU_ASSERT((ssize_t)expectedlen == rv);

  rv = ngtcp2_pkt_decode_hd_short(&nhd, buf, expectedlen);

  CU_ASSERT((ssize_t)expectedlen == rv);
  CU_ASSERT(hd.flags == nhd.flags);
  CU_ASSERT(0 == nhd.conn_id);
  CU_ASSERT((hd.pkt_num & 0xff) == nhd.pkt_num);
  CU_ASSERT(0 == nhd.version);

  /* With connection ID, and Key Phase */
  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_CONN_ID | NGTCP2_PKT_FLAG_KEY_PHASE,
                     NGTCP2_PKT_03, 0xf1f2f3f4f5f6f7f8llu, 0xe1e2e3e4u,
                     0xd1d2d3d4u);

  expectedlen = 13;

  rv = ngtcp2_pkt_encode_hd_short(buf, sizeof(buf), &hd);

  CU_ASSERT((ssize_t)expectedlen == rv);

  rv = ngtcp2_pkt_decode_hd_short(&nhd, buf, expectedlen);

  CU_ASSERT((ssize_t)expectedlen == rv);
  CU_ASSERT(hd.flags == nhd.flags);
  CU_ASSERT(hd.conn_id == nhd.conn_id);
  CU_ASSERT(hd.pkt_num == nhd.pkt_num);
  CU_ASSERT(0 == nhd.version);
}

void test_ngtcp2_pkt_decode_stream_frame(void) {
  uint8_t buf[256];
  size_t buflen;
  ngtcp2_frame fm;
  ssize_t rv;
  size_t expectedlen;

  /* 32 bits Stream ID + 64 bits Offset + Data Length */
  buflen = ngtcp2_t_encode_stream_frame(buf, NGTCP2_STREAM_D_BIT, 0xf1f2f3f4u,
                                        0xf1f2f3f4f5f6f7f8llu, 0x14);

  expectedlen = 1 + 4 + 8 + 2 + 20;

  CU_ASSERT(expectedlen == buflen);

  rv = ngtcp2_pkt_decode_stream_frame(&fm.stream, buf, buflen);

  CU_ASSERT((ssize_t)expectedlen == rv);
  CU_ASSERT(0 == fm.stream.fin);
  CU_ASSERT(0xf1f2f3f4u == fm.stream.stream_id);
  CU_ASSERT(0xf1f2f3f4f5f6f7f8llu == fm.stream.offset);
  CU_ASSERT(0x14 == fm.stream.datalen);

  /* Cutting 1 bytes from the tail must cause invalid argument
     error */
  rv = ngtcp2_pkt_decode_stream_frame(&fm.stream, buf, buflen - 1);

  CU_ASSERT(NGTCP2_ERR_INVALID_ARGUMENT == rv);

  memset(&fm, 0, sizeof(fm));

  /* 24 bits Stream ID + 32 bits Offset + Data Length */
  buflen = ngtcp2_t_encode_stream_frame(buf, NGTCP2_STREAM_D_BIT, 0xf1f2f3,
                                        0xf1f2f3f4u, 0x14);

  expectedlen = 1 + 3 + 4 + 2 + 20;

  CU_ASSERT(expectedlen == buflen);

  rv = ngtcp2_pkt_decode_stream_frame(&fm.stream, buf, buflen);

  CU_ASSERT((ssize_t)expectedlen == rv);
  CU_ASSERT(0 == fm.stream.fin);
  CU_ASSERT(0xf1f2f3 == fm.stream.stream_id);
  CU_ASSERT(0xf1f2f3f4u == fm.stream.offset);
  CU_ASSERT(0x14 == fm.stream.datalen);

  /* Cutting 1 bytes from the tail must cause invalid argument
     error */
  rv = ngtcp2_pkt_decode_stream_frame(&fm.stream, buf, buflen - 1);

  CU_ASSERT(NGTCP2_ERR_INVALID_ARGUMENT == rv);

  memset(&fm, 0, sizeof(fm));

  /* 16 bits Stream ID + 16 bits Offset + Data Length */
  buflen = ngtcp2_t_encode_stream_frame(buf, NGTCP2_STREAM_D_BIT, 0xf1f2,
                                        0xf1f2, 0x14);

  expectedlen = 1 + 2 + 2 + 2 + 20;

  CU_ASSERT(expectedlen == buflen);

  rv = ngtcp2_pkt_decode_stream_frame(&fm.stream, buf, buflen);

  CU_ASSERT((ssize_t)expectedlen == rv);
  CU_ASSERT(0 == fm.stream.fin);
  CU_ASSERT(0xf1f2 == fm.stream.stream_id);
  CU_ASSERT(0xf1f2 == fm.stream.offset);
  CU_ASSERT(0x14 == fm.stream.datalen);

  /* Cutting 1 bytes from the tail must cause invalid argument
     error */
  rv = ngtcp2_pkt_decode_stream_frame(&fm.stream, buf, buflen - 1);

  CU_ASSERT(NGTCP2_ERR_INVALID_ARGUMENT == rv);

  memset(&fm, 0, sizeof(fm));

  /* 8 bits Stream ID + no Offset + Data Length */
  buflen =
      ngtcp2_t_encode_stream_frame(buf, NGTCP2_STREAM_D_BIT, 0xf1, 0x00, 0x14);

  expectedlen = 1 + 1 + 0 + 2 + 20;

  CU_ASSERT(expectedlen == buflen);

  rv = ngtcp2_pkt_decode_stream_frame(&fm.stream, buf, buflen);

  CU_ASSERT((ssize_t)expectedlen == rv);
  CU_ASSERT(0 == fm.stream.fin);
  CU_ASSERT(0xf1 == fm.stream.stream_id);
  CU_ASSERT(0x00 == fm.stream.offset);
  CU_ASSERT(0x14 == fm.stream.datalen);

  /* Cutting 1 bytes from the tail must cause invalid argument
     error */
  rv = ngtcp2_pkt_decode_stream_frame(&fm.stream, buf, buflen - 1);

  CU_ASSERT(NGTCP2_ERR_INVALID_ARGUMENT == rv);

  memset(&fm, 0, sizeof(fm));

  /* Fin bit set + no Data Length */
  buflen = ngtcp2_t_encode_stream_frame(buf, NGTCP2_STREAM_FIN_BIT, 0xf1f2f3f4u,
                                        0x00, 0x14);

  expectedlen = 1 + 4 + 20;

  CU_ASSERT(expectedlen == buflen);

  rv = ngtcp2_pkt_decode_stream_frame(&fm.stream, buf, buflen);

  CU_ASSERT((ssize_t)expectedlen == rv);
  CU_ASSERT(1 == fm.stream.fin);
  CU_ASSERT(0xf1f2f3f4u == fm.stream.stream_id);
  CU_ASSERT(0x00 == fm.stream.offset);
  CU_ASSERT(0x14 == fm.stream.datalen);

  memset(&fm, 0, sizeof(fm));
}

void test_ngtcp2_pkt_decode_ack_frame(void) {
  uint8_t buf[256];
  size_t buflen;
  ngtcp2_frame fm;
  ssize_t rv;
  size_t expectedlen;

  /* 48 bits Largest Acknowledged + No Num Blocks + 0 NumTS*/
  buflen = ngtcp2_t_encode_ack_frame(buf, 0xf1f2f3f4f5f6llu);

  expectedlen = 1 + 1 + 6 + 2 + 6;

  CU_ASSERT(expectedlen == buflen);

  rv = ngtcp2_pkt_decode_ack_frame(&fm.ack, buf, buflen);

  CU_ASSERT((ssize_t)expectedlen == rv);
  CU_ASSERT(0xf1f2f3f4f5f6llu == fm.ack.largest_ack);
}

void test_ngtcp2_pkt_decode_padding_frame(void) {
  uint8_t buf[256];
  ngtcp2_frame fm;
  ssize_t rv;
  size_t paddinglen = 31;

  memset(buf, 0, paddinglen);
  buf[paddinglen] = NGTCP2_FRAME_STREAM;

  rv = ngtcp2_pkt_decode_padding_frame(&fm.padding, buf, paddinglen + 1);

  CU_ASSERT((ssize_t)paddinglen == rv);
  CU_ASSERT((size_t)31 == fm.padding.len);
}

void test_ngtcp2_pkt_encode_stream_frame(void) {
  const uint8_t data[] = "0123456789abcdef0";
  uint8_t buf[256];
  ngtcp2_frame fm, nfm;
  ssize_t rv;
  size_t framelen;

  /* 32 bits Stream ID + 64 bits Offset + Data Length */
  fm.type = NGTCP2_FRAME_STREAM;
  fm.stream.fin = 0;
  fm.stream.stream_id = 0xf1f2f3f4u;
  fm.stream.offset = 0xf1f2f3f4f5f6f7f8llu;
  fm.stream.datalen = strsize(data);
  fm.stream.data = data;

  framelen = 1 + 4 + 8 + 2 + 17;

  rv = ngtcp2_pkt_encode_stream_frame(buf, sizeof(buf), &fm.stream);

  CU_ASSERT((ssize_t)framelen == rv);

  rv = ngtcp2_pkt_decode_stream_frame(&nfm.stream, buf, framelen);

  CU_ASSERT((ssize_t)framelen == rv);
  CU_ASSERT(fm.type == nfm.type);
  CU_ASSERT(0x1f == nfm.stream.flags);
  CU_ASSERT(fm.stream.fin == nfm.stream.fin);
  CU_ASSERT(fm.stream.stream_id == nfm.stream.stream_id);
  CU_ASSERT(fm.stream.offset == nfm.stream.offset);
  CU_ASSERT(fm.stream.datalen == nfm.stream.datalen);
  CU_ASSERT(0 == memcmp(fm.stream.data, nfm.stream.data, fm.stream.datalen));

  memset(&nfm, 0, sizeof(nfm));

  /* 24 bits Stream ID + 32 bits Offset + Data Length */
  fm.type = NGTCP2_FRAME_STREAM;
  fm.stream.fin = 0;
  fm.stream.stream_id = 0xf1f2f3;
  fm.stream.offset = 0xf1f2f3f4u;
  fm.stream.datalen = strsize(data);
  fm.stream.data = data;

  framelen = 1 + 3 + 4 + 2 + 17;

  rv = ngtcp2_pkt_encode_stream_frame(buf, sizeof(buf), &fm.stream);

  CU_ASSERT((ssize_t)framelen == rv);

  rv = ngtcp2_pkt_decode_stream_frame(&nfm.stream, buf, framelen);

  CU_ASSERT((ssize_t)framelen == rv);
  CU_ASSERT(fm.type == nfm.type);
  CU_ASSERT(0x15 == nfm.stream.flags);
  CU_ASSERT(fm.stream.fin == nfm.stream.fin);
  CU_ASSERT(fm.stream.stream_id == nfm.stream.stream_id);
  CU_ASSERT(fm.stream.offset = nfm.stream.offset);
  CU_ASSERT(fm.stream.datalen == nfm.stream.datalen);
  CU_ASSERT(0 == memcmp(fm.stream.data, nfm.stream.data, fm.stream.datalen));

  memset(&nfm, 0, sizeof(nfm));

  /* 16 bits Stream ID + 16 bits Offset + Data Length */
  fm.type = NGTCP2_FRAME_STREAM;
  fm.stream.fin = 0;
  fm.stream.stream_id = 0xf1f2;
  fm.stream.offset = 0xf1f2;
  fm.stream.datalen = strsize(data);
  fm.stream.data = data;

  framelen = 1 + 2 + 2 + 2 + 17;

  rv = ngtcp2_pkt_encode_stream_frame(buf, sizeof(buf), &fm.stream);

  CU_ASSERT((ssize_t)framelen == rv);

  rv = ngtcp2_pkt_decode_stream_frame(&nfm.stream, buf, framelen);

  CU_ASSERT((ssize_t)framelen == rv);
  CU_ASSERT(fm.type == nfm.type);
  CU_ASSERT(0x0b == nfm.stream.flags);
  CU_ASSERT(fm.stream.fin == nfm.stream.fin);
  CU_ASSERT(fm.stream.stream_id == nfm.stream.stream_id);
  CU_ASSERT(fm.stream.offset = nfm.stream.offset);
  CU_ASSERT(fm.stream.datalen == nfm.stream.datalen);
  CU_ASSERT(0 == memcmp(fm.stream.data, nfm.stream.data, fm.stream.datalen));

  memset(&nfm, 0, sizeof(nfm));

  /* 8 bits Stream ID + No Offset + Data Length */
  fm.type = NGTCP2_FRAME_STREAM;
  fm.stream.fin = 0;
  fm.stream.stream_id = 0xf1;
  fm.stream.offset = 0;
  fm.stream.datalen = strsize(data);
  fm.stream.data = data;

  framelen = 1 + 1 + 2 + 17;

  rv = ngtcp2_pkt_encode_stream_frame(buf, sizeof(buf), &fm.stream);

  CU_ASSERT((ssize_t)framelen == rv);

  rv = ngtcp2_pkt_decode_stream_frame(&nfm.stream, buf, framelen);

  CU_ASSERT((ssize_t)framelen == rv);
  CU_ASSERT(fm.type == nfm.type);
  CU_ASSERT(0x01 == nfm.stream.flags);
  CU_ASSERT(fm.stream.fin == nfm.stream.fin);
  CU_ASSERT(fm.stream.stream_id == nfm.stream.stream_id);
  CU_ASSERT(fm.stream.offset == nfm.stream.offset);
  CU_ASSERT(fm.stream.datalen == nfm.stream.datalen);
  CU_ASSERT(0 == memcmp(fm.stream.data, nfm.stream.data, fm.stream.datalen));

  memset(&nfm, 0, sizeof(nfm));

  /* Fin + 32 bits Stream ID + 64 bits Offset + Data Length */
  fm.type = NGTCP2_FRAME_STREAM;
  fm.stream.fin = 1;
  fm.stream.stream_id = 0xf1f2f3f4u;
  fm.stream.offset = 0xf1f2f3f4f5f6f7f8llu;
  fm.stream.datalen = strsize(data);
  fm.stream.data = data;

  framelen = 1 + 4 + 8 + 2 + 17;

  rv = ngtcp2_pkt_encode_stream_frame(buf, sizeof(buf), &fm.stream);

  CU_ASSERT((ssize_t)framelen == rv);

  rv = ngtcp2_pkt_decode_stream_frame(&nfm.stream, buf, framelen);

  CU_ASSERT((ssize_t)framelen == rv);
  CU_ASSERT(fm.type == nfm.type);
  CU_ASSERT(0x3f == nfm.stream.flags);
  CU_ASSERT(fm.stream.fin == nfm.stream.fin);
  CU_ASSERT(fm.stream.stream_id == nfm.stream.stream_id);
  CU_ASSERT(fm.stream.offset == nfm.stream.offset);
  CU_ASSERT(fm.stream.datalen == nfm.stream.datalen);
  CU_ASSERT(0 == memcmp(fm.stream.data, nfm.stream.data, fm.stream.datalen));

  memset(&nfm, 0, sizeof(nfm));

  /* NOBUF: Fin + 32 bits Stream ID + 64 bits Offset + Data Length */
  fm.type = NGTCP2_FRAME_STREAM;
  fm.stream.fin = 1;
  fm.stream.stream_id = 0xf1f2f3f4u;
  fm.stream.offset = 0xf1f2f3f4f5f6f7f8llu;
  fm.stream.datalen = strsize(data);
  fm.stream.data = data;

  framelen = 1 + 4 + 8 + 2 + 17;

  rv = ngtcp2_pkt_encode_stream_frame(buf, framelen - 1, &fm.stream);

  CU_ASSERT(NGTCP2_ERR_NOBUF == rv);
}
