/*
 * ngtcp2
 *
 * Copyright (c) 2024 ngtcp2 contributors
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
#include "ngtcp2_ppe_test.h"

#include <stdio.h>

#include "ngtcp2_ppe.h"
#include "ngtcp2_test_helper.h"

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_ppe_dgram_padding_size),
  munit_void_test(test_ngtcp2_ppe_padding_size),
  munit_test_end(),
};

const MunitSuite ppe_suite = {
  .prefix = "/ppe",
  .tests = tests,
};

static void set_padding_range(uint8_t *buf, size_t buflen, size_t offset,
                              size_t len) {
  memset(buf, 0xff, buflen);
  memset(buf + offset, 0, len);
}

void test_ngtcp2_ppe_dgram_padding_size(void) {
  ngtcp2_ppe ppe;
  ngtcp2_crypto_cc cc = {0};
  uint8_t buf[2048];
  uint8_t pkt[2048];

  cc.aead.max_overhead = NGTCP2_FAKE_AEAD_OVERHEAD;

  /* Add padding to make UDP datagram payload to
     NGTCP2_MAX_UDP_PAYLOAD_SIZE */
  ngtcp2_ppe_init(&ppe, buf, 1280, 0, &cc);
  ppe.buf.last += 917;

  set_padding_range(pkt, sizeof(pkt), 917, 267);
  memset(buf, 0xff, sizeof(buf));

  ngtcp2_ppe_dgram_padding(&ppe);

  assert_memory_equal(NGTCP2_MAX_UDP_PAYLOAD_SIZE, pkt, buf);

  /* UDP datagram payload is already NGTCP2_MAX_UDP_PAYLOAD_SIZE */
  ngtcp2_ppe_init(&ppe, buf, 1280, 0, &cc);
  ppe.buf.last += 1200;

  set_padding_range(pkt, sizeof(pkt), 0, 0);
  memset(buf, 0xff, sizeof(buf));

  ngtcp2_ppe_dgram_padding(&ppe);

  assert_memory_equal(NGTCP2_MAX_UDP_PAYLOAD_SIZE, pkt, buf);

  /* UDP datagram payload is already NGTCP2_MAX_UDP_PAYLOAD_SIZE
     because of the previous QUIC packet */
  ngtcp2_ppe_init(&ppe, buf + 889, 1280, 889, &cc);
  ppe.buf.last += 311;

  set_padding_range(pkt, sizeof(pkt), 0, 0);
  memset(buf, 0xff, sizeof(buf));

  ngtcp2_ppe_dgram_padding(&ppe);

  assert_memory_equal(NGTCP2_MAX_UDP_PAYLOAD_SIZE, pkt, buf);

  /* Buffer is smaller than requested size */
  ngtcp2_ppe_init(&ppe, buf + 111, 1280 - 111, 111, &cc);
  ppe.buf.last += 917;

  set_padding_range(pkt, sizeof(pkt), 1028, 236);
  memset(buf, 0xff, sizeof(buf));

  ngtcp2_ppe_dgram_padding_size(&ppe, 1400);

  assert_memory_equal(1280, pkt, buf);
}

void test_ngtcp2_ppe_padding_size(void) {
  ngtcp2_ppe ppe;
  ngtcp2_crypto_cc cc = {0};
  uint8_t buf[2048];
  uint8_t pkt[2048];

  cc.aead.max_overhead = NGTCP2_FAKE_AEAD_OVERHEAD;

  /* Add padding to make UDP datagram payload to
     NGTCP2_MAX_UDP_PAYLOAD_SIZE */
  ngtcp2_ppe_init(&ppe, buf, 1280, /* should be ignored */ 1, &cc);
  ppe.buf.last += 917;

  set_padding_range(pkt, sizeof(pkt), 917, 267);
  memset(buf, 0xff, sizeof(buf));

  ngtcp2_ppe_padding_size(&ppe, NGTCP2_MAX_UDP_PAYLOAD_SIZE);

  assert_memory_equal(NGTCP2_MAX_UDP_PAYLOAD_SIZE, pkt, buf);

  /* UDP datagram payload is already NGTCP2_MAX_UDP_PAYLOAD_SIZE */
  ngtcp2_ppe_init(&ppe, buf, 1280, /* should be ignored */ 111, &cc);
  ppe.buf.last += 1200;

  set_padding_range(pkt, sizeof(pkt), 0, 0);
  memset(buf, 0xff, sizeof(buf));

  ngtcp2_ppe_padding_size(&ppe, NGTCP2_MAX_UDP_PAYLOAD_SIZE);

  assert_memory_equal(NGTCP2_MAX_UDP_PAYLOAD_SIZE, pkt, buf);

  /* Buffer is smaller than requested size */
  ngtcp2_ppe_init(&ppe, buf, 1280, /* should be ignored*/ 111, &cc);
  ppe.buf.last += 917;

  set_padding_range(pkt, sizeof(pkt), 917, 347);
  memset(buf, 0xff, sizeof(buf));

  ngtcp2_ppe_padding_size(&ppe, 1400);

  assert_memory_equal(1280, pkt, buf);

  /* Add padding to ensure header protection sample */
  ngtcp2_ppe_init(&ppe, buf, 1280, /* should be ignored */ 1, &cc);
  ppe.buf.last += 5;
  ppe.pkt_num_offset = 4;

  set_padding_range(pkt, sizeof(pkt), 5, 3);
  memset(buf, 0xff, sizeof(buf));

  ngtcp2_ppe_padding_size(&ppe, 0);

  assert_memory_equal(NGTCP2_MAX_UDP_PAYLOAD_SIZE, pkt, buf);

  /* No need to add padding */
  ngtcp2_ppe_init(&ppe, buf, 1280, /* should be ignored */ 1, &cc);
  ppe.buf.last += 8;
  ppe.pkt_num_offset = 4;

  set_padding_range(pkt, sizeof(pkt), 0, 0);
  memset(buf, 0xff, sizeof(buf));

  ngtcp2_ppe_padding_size(&ppe, 0);

  assert_memory_equal(NGTCP2_MAX_UDP_PAYLOAD_SIZE, pkt, buf);
}
