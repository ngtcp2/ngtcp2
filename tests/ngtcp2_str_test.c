/*
 * ngtcp2
 *
 * Copyright (c) 2020 ngtcp2 contributors
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
#include "ngtcp2_str_test.h"

#include <stdio.h>

#include <CUnit/CUnit.h>

#include "ngtcp2_str.h"
#include "ngtcp2_test_helper.h"

void test_ngtcp2_encode_ipv4(void) {
  uint8_t buf[16];

  CU_ASSERT(0 == strcmp("192.168.0.1",
                        (const char *)ngtcp2_encode_ipv4(
                            buf, (const uint8_t *)"\xc0\xa8\x00\x01")));
  CU_ASSERT(0 ==
            strcmp("127.0.0.1", (const char *)ngtcp2_encode_ipv4(
                                    buf, (const uint8_t *)"\x7f\x00\x00\x01")));
}

void test_ngtcp2_encode_ipv6(void) {
  uint8_t buf[32 + 7 + 1];

  CU_ASSERT(
      0 ==
      strcmp("2001:db8::2:1",
             (const char *)ngtcp2_encode_ipv6(
                 buf, (const uint8_t *)"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00"
                                       "\x00\x00\x00\x00\x02\x00\x01")));
  CU_ASSERT(
      0 ==
      strcmp("2001:db8:0:1:1:1:1:1",
             (const char *)ngtcp2_encode_ipv6(
                 buf, (const uint8_t *)"\x20\x01\x0d\xb8\x00\x00\x00\x01\x00"
                                       "\x01\x00\x01\x00\x01\x00\x01")));
  CU_ASSERT(
      0 ==
      strcmp("2001:db8::1:0:0:1",
             (const char *)ngtcp2_encode_ipv6(
                 buf, (const uint8_t *)"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00"
                                       "\x01\x00\x00\x00\x00\x00\x01")));
  CU_ASSERT(
      0 ==
      strcmp("2001:db8::8:800:200c:417a",
             (const char *)ngtcp2_encode_ipv6(
                 buf, (const uint8_t *)"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00"
                                       "\x08\x08\x00\x20\x0C\x41\x7a")));
  CU_ASSERT(
      0 ==
      strcmp("ff01::101",
             (const char *)ngtcp2_encode_ipv6(
                 buf, (const uint8_t *)"\xff\x01\x00\x00\x00\x00\x00\x00\x00"
                                       "\x00\x00\x00\x00\x00\x01\x01")));
  CU_ASSERT(
      0 ==
      strcmp("::1",
             (const char *)ngtcp2_encode_ipv6(
                 buf, (const uint8_t *)"\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                       "\x00\x00\x00\x00\x00\x00\x01")));
  CU_ASSERT(
      0 ==
      strcmp("::",
             (const char *)ngtcp2_encode_ipv6(
                 buf, (const uint8_t *)"\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                       "\x00\x00\x00\x00\x00\x00\x00")));
}

void test_ngtcp2_get_bytes(void) {
  const uint8_t src[] = {'f', 'o', 'o', 'b', 'a', 'r'};
  uint8_t dest[256];

  CU_ASSERT(src + sizeof(src) == ngtcp2_get_bytes(dest, src, sizeof(src)));
  CU_ASSERT(0 == memcmp(src, dest, sizeof(src)));
}
