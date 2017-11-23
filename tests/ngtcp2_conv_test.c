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

#include <assert.h>

#include <CUnit/CUnit.h>

#include "ngtcp2_conv.h"
#include "ngtcp2_test_helper.h"

void test_ngtcp2_get_varint(void) {
  uint8_t buf[256];
  uint8_t *p;
  size_t nread;
  uint64_t n;

  /* 0 */
  n = 1;
  p = ngtcp2_put_varint(buf, 0);

  CU_ASSERT(1 == p - buf);

  n = ngtcp2_get_varint(&nread, buf);

  CU_ASSERT(1 == nread);
  CU_ASSERT(0 == n);

  /* 63 */
  n = 0;
  p = ngtcp2_put_varint(buf, 63);

  CU_ASSERT(1 == p - buf);

  n = ngtcp2_get_varint(&nread, buf);

  CU_ASSERT(1 == nread);
  CU_ASSERT(63 == n);

  /* 64 */
  n = 0;
  p = ngtcp2_put_varint(buf, 64);

  CU_ASSERT(2 == p - buf);

  n = ngtcp2_get_varint(&nread, buf);

  CU_ASSERT(2 == nread);
  CU_ASSERT(64 == n);

  /* 16383 */
  n = 0;
  p = ngtcp2_put_varint(buf, 16383);

  CU_ASSERT(2 == p - buf);

  n = ngtcp2_get_varint(&nread, buf);

  CU_ASSERT(2 == nread);
  CU_ASSERT(16383 == n);

  /* 16384 */
  n = 0;
  p = ngtcp2_put_varint(buf, 16384);

  CU_ASSERT(4 == p - buf);

  n = ngtcp2_get_varint(&nread, buf);

  CU_ASSERT(4 == nread);
  CU_ASSERT(16384 == n);

  /* 1073741823 */
  n = 0;
  p = ngtcp2_put_varint(buf, 1073741823);

  CU_ASSERT(4 == p - buf);

  n = ngtcp2_get_varint(&nread, buf);

  CU_ASSERT(4 == nread);
  CU_ASSERT(1073741823 == n);

  /* 1073741824 */
  n = 0;
  p = ngtcp2_put_varint(buf, 1073741824);

  CU_ASSERT(8 == p - buf);

  n = ngtcp2_get_varint(&nread, buf);

  CU_ASSERT(8 == nread);
  CU_ASSERT(1073741824 == n);

  /* 4611686018427387903 */
  n = 0;
  p = ngtcp2_put_varint(buf, 4611686018427387903ULL);

  CU_ASSERT(8 == p - buf);

  n = ngtcp2_get_varint(&nread, buf);

  CU_ASSERT(8 == nread);
  CU_ASSERT(4611686018427387903ULL == n);
}

void test_ngtcp2_get_varint_len(void) {
  uint8_t c;

  c = 0x00;

  CU_ASSERT(1 == ngtcp2_get_varint_len(&c));

  c = 0x40;

  CU_ASSERT(2 == ngtcp2_get_varint_len(&c));

  c = 0x80;

  CU_ASSERT(4 == ngtcp2_get_varint_len(&c));

  c = 0xc0;

  CU_ASSERT(8 == ngtcp2_get_varint_len(&c));
}

void test_ngtcp2_put_varint_len(void) {
  CU_ASSERT(1 == ngtcp2_put_varint_len(0));
  CU_ASSERT(1 == ngtcp2_put_varint_len(63));
  CU_ASSERT(2 == ngtcp2_put_varint_len(64));
  CU_ASSERT(2 == ngtcp2_put_varint_len(16383));
  CU_ASSERT(4 == ngtcp2_put_varint_len(16384));
  CU_ASSERT(4 == ngtcp2_put_varint_len(1073741823));
  CU_ASSERT(8 == ngtcp2_put_varint_len(1073741824));
  CU_ASSERT(8 == ngtcp2_put_varint_len(4611686018427387903ULL));
}
