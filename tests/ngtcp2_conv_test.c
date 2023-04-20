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
#include "ngtcp2_conv_test.h"

#include <stdio.h>

#include <CUnit/CUnit.h>

#include "ngtcp2_conv.h"
#include "ngtcp2_net.h"
#include "ngtcp2_test_helper.h"

void test_ngtcp2_get_varint(void) {
  uint8_t buf[256];
  const uint8_t *p;
  uint64_t n;
  int64_t s;

  /* 0 */
  n = 1;
  p = ngtcp2_put_uvarint(buf, 0);

  CU_ASSERT(1 == p - buf);

  p = ngtcp2_get_uvarint(&n, buf);

  CU_ASSERT(1 == p - buf);
  CU_ASSERT(0 == n);

  /* 63 */
  n = 0;
  p = ngtcp2_put_uvarint(buf, 63);

  CU_ASSERT(1 == p - buf);

  p = ngtcp2_get_uvarint(&n, buf);

  CU_ASSERT(1 == p - buf);
  CU_ASSERT(63 == n);

  /* 64 */
  n = 0;
  p = ngtcp2_put_uvarint(buf, 64);

  CU_ASSERT(2 == p - buf);

  p = ngtcp2_get_uvarint(&n, buf);

  CU_ASSERT(2 == p - buf);
  CU_ASSERT(64 == n);

  /* 16383 */
  n = 0;
  p = ngtcp2_put_uvarint(buf, 16383);

  CU_ASSERT(2 == p - buf);

  p = ngtcp2_get_uvarint(&n, buf);

  CU_ASSERT(2 == p - buf);
  CU_ASSERT(16383 == n);

  /* 16384 */
  n = 0;
  p = ngtcp2_put_uvarint(buf, 16384);

  CU_ASSERT(4 == p - buf);

  p = ngtcp2_get_uvarint(&n, buf);

  CU_ASSERT(4 == p - buf);
  CU_ASSERT(16384 == n);

  /* 1073741823 */
  n = 0;
  p = ngtcp2_put_uvarint(buf, 1073741823);

  CU_ASSERT(4 == p - buf);

  p = ngtcp2_get_uvarint(&n, buf);

  CU_ASSERT(4 == p - buf);
  CU_ASSERT(1073741823 == n);

  /* 1073741824 */
  n = 0;
  p = ngtcp2_put_uvarint(buf, 1073741824);

  CU_ASSERT(8 == p - buf);

  p = ngtcp2_get_uvarint(&n, buf);

  CU_ASSERT(8 == p - buf);
  CU_ASSERT(1073741824 == n);

  /* 4611686018427387903 */
  n = 0;
  p = ngtcp2_put_uvarint(buf, 4611686018427387903ULL);

  CU_ASSERT(8 == p - buf);

  p = ngtcp2_get_uvarint(&n, buf);

  CU_ASSERT(8 == p - buf);
  CU_ASSERT(4611686018427387903ULL == n);

  /* Check signed version */
  s = 0;
  p = ngtcp2_put_uvarint(buf, 4611686018427387903ULL);

  CU_ASSERT(8 == p - buf);

  p = ngtcp2_get_varint(&s, buf);

  CU_ASSERT(8 == p - buf);
  CU_ASSERT(4611686018427387903LL == s);
}

void test_ngtcp2_get_uvarintlen(void) {
  uint8_t c;

  c = 0x00;

  CU_ASSERT(1 == ngtcp2_get_uvarintlen(&c));

  c = 0x40;

  CU_ASSERT(2 == ngtcp2_get_uvarintlen(&c));

  c = 0x80;

  CU_ASSERT(4 == ngtcp2_get_uvarintlen(&c));

  c = 0xc0;

  CU_ASSERT(8 == ngtcp2_get_uvarintlen(&c));
}

void test_ngtcp2_get_uint64(void) {
  uint8_t buf[256];
  const uint8_t *p;
  uint64_t n;

  /* 0 */
  n = 1;
  p = ngtcp2_put_uint64be(buf, 0);

  CU_ASSERT(sizeof(n) == p - buf);

  p = ngtcp2_get_uint64(&n, buf);

  CU_ASSERT(sizeof(n) == p - buf);
  CU_ASSERT(0 == n);

  /* 12345678900 */
  n = 0;
  p = ngtcp2_put_uint64be(buf, 12345678900ULL);

  CU_ASSERT(sizeof(n) == p - buf);

  p = ngtcp2_get_uint64(&n, buf);

  CU_ASSERT(sizeof(n) == p - buf);
  CU_ASSERT(12345678900ULL == n);

  /* 18446744073709551615 */
  n = 0;
  p = ngtcp2_put_uint64be(buf, 18446744073709551615ULL);

  CU_ASSERT(sizeof(n) == p - buf);

  p = ngtcp2_get_uint64(&n, buf);

  CU_ASSERT(sizeof(n) == p - buf);
  CU_ASSERT(18446744073709551615ULL == n);
}

void test_ngtcp2_get_uint48(void) {
  uint8_t buf[256];
  const uint8_t *p;
  uint64_t n;

  /* 0 */
  n = 1;
  p = ngtcp2_put_uint48be(buf, 0);

  CU_ASSERT(6 == p - buf);

  p = ngtcp2_get_uint48(&n, buf);

  CU_ASSERT(6 == p - buf);
  CU_ASSERT(0 == n);

  /* 123456789 */
  n = 0;
  p = ngtcp2_put_uint48be(buf, 123456789);

  CU_ASSERT(6 == p - buf);

  p = ngtcp2_get_uint48(&n, buf);

  CU_ASSERT(6 == p - buf);
  CU_ASSERT(123456789 == n);

  /* 281474976710655 */
  n = 0;
  p = ngtcp2_put_uint48be(buf, 281474976710655ULL);

  CU_ASSERT(6 == p - buf);

  p = ngtcp2_get_uint48(&n, buf);

  CU_ASSERT(6 == p - buf);
  CU_ASSERT(281474976710655ULL == n);
}

void test_ngtcp2_get_uint32(void) {
  uint8_t buf[256];
  const uint8_t *p;
  uint32_t n;

  /* 0 */
  n = 1;
  p = ngtcp2_put_uint32be(buf, 0);

  CU_ASSERT(sizeof(n) == p - buf);

  p = ngtcp2_get_uint32(&n, buf);

  CU_ASSERT(sizeof(n) == p - buf);
  CU_ASSERT(0 == n);

  /* 123456 */
  n = 0;
  p = ngtcp2_put_uint32be(buf, 123456);

  CU_ASSERT(sizeof(n) == p - buf);

  p = ngtcp2_get_uint32(&n, buf);

  CU_ASSERT(sizeof(n) == p - buf);
  CU_ASSERT(123456 == n);

  /* 4294967295 */
  n = 0;
  p = ngtcp2_put_uint32be(buf, 4294967295UL);

  CU_ASSERT(sizeof(n) == p - buf);

  p = ngtcp2_get_uint32(&n, buf);

  CU_ASSERT(sizeof(n) == p - buf);
  CU_ASSERT(4294967295UL == n);
}

void test_ngtcp2_get_uint24(void) {
  uint8_t buf[256];
  const uint8_t *p;
  uint32_t n;

  /* 0 */
  n = 1;
  p = ngtcp2_put_uint24be(buf, 0);

  CU_ASSERT(3 == p - buf);

  p = ngtcp2_get_uint24(&n, buf);

  CU_ASSERT(3 == p - buf);
  CU_ASSERT(0 == n);

  /* 12345 */
  n = 0;
  p = ngtcp2_put_uint24be(buf, 12345);

  CU_ASSERT(3 == p - buf);

  p = ngtcp2_get_uint24(&n, buf);

  CU_ASSERT(3 == p - buf);
  CU_ASSERT(12345 == n);

  /* 16777215 */
  n = 0;
  p = ngtcp2_put_uint24be(buf, 16777215);

  CU_ASSERT(3 == p - buf);

  p = ngtcp2_get_uint24(&n, buf);

  CU_ASSERT(3 == p - buf);
  CU_ASSERT(16777215 == n);
}

void test_ngtcp2_get_uint16(void) {
  uint8_t buf[256];
  const uint8_t *p;
  uint16_t n;

  /* 0 */
  n = 1;
  p = ngtcp2_put_uint16be(buf, 0);

  CU_ASSERT(sizeof(n) == p - buf);

  p = ngtcp2_get_uint16(&n, buf);

  CU_ASSERT(sizeof(n) == p - buf);
  CU_ASSERT(0 == n);

  /* 1234 */
  n = 0;
  p = ngtcp2_put_uint16be(buf, 1234);

  CU_ASSERT(sizeof(n) == p - buf);

  p = ngtcp2_get_uint16(&n, buf);

  CU_ASSERT(sizeof(n) == p - buf);
  CU_ASSERT(1234 == n);

  /* 65535 */
  n = 0;
  p = ngtcp2_put_uint16be(buf, 65535);

  CU_ASSERT(sizeof(n) == p - buf);

  p = ngtcp2_get_uint16(&n, buf);

  CU_ASSERT(sizeof(n) == p - buf);
  CU_ASSERT(65535 == n);
}

void test_ngtcp2_get_uint16be(void) {
  uint8_t buf[256];
  const uint8_t *p;
  uint16_t n;

  /* 0 */
  n = 1;
  p = ngtcp2_put_uint16(buf, 0);

  CU_ASSERT(sizeof(n) == p - buf);

  p = ngtcp2_get_uint16be(&n, buf);

  CU_ASSERT(sizeof(n) == p - buf);
  CU_ASSERT(0 == n);

  /* 1234 */
  n = 0;
  p = ngtcp2_put_uint16(buf, ngtcp2_htons(1234));

  CU_ASSERT(sizeof(n) == p - buf);

  p = ngtcp2_get_uint16be(&n, buf);

  CU_ASSERT(sizeof(n) == p - buf);
  CU_ASSERT(1234 == ngtcp2_ntohs(n));

  /* 65535 */
  n = 0;
  p = ngtcp2_put_uint16(buf, 65535);

  CU_ASSERT(sizeof(n) == p - buf);

  p = ngtcp2_get_uint16be(&n, buf);

  CU_ASSERT(sizeof(n) == p - buf);
  CU_ASSERT(65535 == n);
}

void test_ngtcp2_put_uvarintlen(void) {
  CU_ASSERT(1 == ngtcp2_put_uvarintlen(0));
  CU_ASSERT(1 == ngtcp2_put_uvarintlen(63));
  CU_ASSERT(2 == ngtcp2_put_uvarintlen(64));
  CU_ASSERT(2 == ngtcp2_put_uvarintlen(16383));
  CU_ASSERT(4 == ngtcp2_put_uvarintlen(16384));
  CU_ASSERT(4 == ngtcp2_put_uvarintlen(1073741823));
  CU_ASSERT(8 == ngtcp2_put_uvarintlen(1073741824));
  CU_ASSERT(8 == ngtcp2_put_uvarintlen(4611686018427387903ULL));
}

void test_ngtcp2_nth_server_bidi_id(void) {
  CU_ASSERT(0 == ngtcp2_nth_server_bidi_id(0));
  CU_ASSERT(1 == ngtcp2_nth_server_bidi_id(1));
  CU_ASSERT(5 == ngtcp2_nth_server_bidi_id(2));
  CU_ASSERT(9 == ngtcp2_nth_server_bidi_id(3));
}

void test_ngtcp2_nth_server_uni_id(void) {
  CU_ASSERT(0 == ngtcp2_nth_server_uni_id(0));
  CU_ASSERT(3 == ngtcp2_nth_server_uni_id(1));
  CU_ASSERT(7 == ngtcp2_nth_server_uni_id(2));
  CU_ASSERT(11 == ngtcp2_nth_server_uni_id(3));
}

void test_ngtcp2_nth_client_bidi_id(void) {
  CU_ASSERT(0 == ngtcp2_nth_client_bidi_id(0));
  CU_ASSERT(0 == ngtcp2_nth_client_bidi_id(1));
  CU_ASSERT(4 == ngtcp2_nth_client_bidi_id(2));
  CU_ASSERT(8 == ngtcp2_nth_client_bidi_id(3));
}

void test_ngtcp2_nth_client_uni_id(void) {
  CU_ASSERT(0 == ngtcp2_nth_client_uni_id(0));
  CU_ASSERT(2 == ngtcp2_nth_client_uni_id(1));
  CU_ASSERT(6 == ngtcp2_nth_client_uni_id(2));
  CU_ASSERT(10 == ngtcp2_nth_client_uni_id(3));
}
