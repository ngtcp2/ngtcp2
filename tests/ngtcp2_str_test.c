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

#include "ngtcp2_str.h"
#include "ngtcp2_test_helper.h"

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_encode_ipv4),
  munit_void_test(test_ngtcp2_encode_ipv6),
  munit_void_test(test_ngtcp2_get_bytes),
  munit_void_test(test_ngtcp2_encode_uint),
  munit_void_test(test_ngtcp2_encode_hex),
  munit_test_end(),
};

const MunitSuite str_suite = {
  .prefix = "/str",
  .tests = tests,
};

void test_ngtcp2_encode_ipv4(void) {
  uint8_t buf[16];

  assert_string_equal(
    "192.168.0.1",
    (const char *)ngtcp2_encode_ipv4(buf, (const uint8_t *)"\xc0\xa8\x00\x01"));
  assert_string_equal("127.0.0.1", (const char *)ngtcp2_encode_ipv4(
                                     buf, (const uint8_t *)"\x7f\x00\x00\x01"));
}

void test_ngtcp2_encode_ipv6(void) {
  uint8_t buf[32 + 7 + 1];

  assert_string_equal("2001:db8::2:1",
                      (const char *)ngtcp2_encode_ipv6(
                        buf,
                        (const uint8_t *)"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00"
                                         "\x00\x00\x00\x00\x02\x00\x01"));
  assert_string_equal("2001:db8:0:1:1:1:1:1",
                      (const char *)ngtcp2_encode_ipv6(
                        buf,
                        (const uint8_t *)"\x20\x01\x0d\xb8\x00\x00\x00\x01\x00"
                                         "\x01\x00\x01\x00\x01\x00\x01"));
  assert_string_equal("2001:db8::1:0:0:1",
                      (const char *)ngtcp2_encode_ipv6(
                        buf,
                        (const uint8_t *)"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00"
                                         "\x01\x00\x00\x00\x00\x00\x01"));
  assert_string_equal("2001:db8::8:800:200c:417a",
                      (const char *)ngtcp2_encode_ipv6(
                        buf,
                        (const uint8_t *)"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00"
                                         "\x08\x08\x00\x20\x0C\x41\x7a"));
  assert_string_equal(
    "ff01::101", (const char *)ngtcp2_encode_ipv6(
                   buf, (const uint8_t *)"\xff\x01\x00\x00\x00\x00\x00\x00\x00"
                                         "\x00\x00\x00\x00\x00\x01\x01"));
  assert_string_equal(
    "::1", (const char *)ngtcp2_encode_ipv6(
             buf, (const uint8_t *)"\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                   "\x00\x00\x00\x00\x00\x00\x01"));
  assert_string_equal(
    "::", (const char *)ngtcp2_encode_ipv6(
            buf, (const uint8_t *)"\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                  "\x00\x00\x00\x00\x00\x00\x00"));
}

void test_ngtcp2_get_bytes(void) {
  const uint8_t src[] = {'f', 'o', 'o', 'b', 'a', 'r'};
  uint8_t dest[256];

  assert_ptr_equal(src + sizeof(src), ngtcp2_get_bytes(dest, src, sizeof(src)));
  assert_memory_equal(sizeof(src), src, dest);
}

void test_ngtcp2_encode_uint(void) {
  uint8_t dest[256];
  const char *nines[] = {
    "9",
    "99",
    "999",
    "9999",
    "99999",
    "999999",
    "9999999",
    "99999999",
    "999999999",
    "9999999999",
    "99999999999",
    "999999999999",
    "9999999999999",
    "99999999999999",
    "999999999999999",
    "9999999999999999",
    "99999999999999999",
    "999999999999999999",
    "9999999999999999999",
  };
  const char *tens[] = {
    "10",
    "100",
    "1000",
    "10000",
    "100000",
    "1000000",
    "10000000",
    "100000000",
    "1000000000",
    "10000000000",
    "100000000000",
    "1000000000000",
    "10000000000000",
    "100000000000000",
    "1000000000000000",
    "10000000000000000",
    "100000000000000000",
    "1000000000000000000",
    "10000000000000000000",
  };
  uint64_t n;
  size_t i;

  *ngtcp2_encode_uint(dest, 0) = '\0';

  assert_string_equal("0", (const char *)dest);

  *ngtcp2_encode_uint(dest, 1) = '\0';

  assert_string_equal("1", (const char *)dest);

  n = 9;

  for (i = 0; i < ngtcp2_arraylen(nines); ++i, n = n * 10 + 9) {
    *ngtcp2_encode_uint(dest, n) = '\0';

    assert_string_equal(nines[i], (const char *)dest);
  }

  n = 10;

  for (i = 0; i < ngtcp2_arraylen(tens); ++i, n *= 10) {
    *ngtcp2_encode_uint(dest, n) = '\0';

    assert_string_equal(tens[i], (const char *)dest);
  }

  *ngtcp2_encode_uint(dest, UINT64_MAX) = '\0';

  assert_string_equal("18446744073709551615", (const char *)dest);
}

void test_ngtcp2_encode_hex(void) {
  uint8_t dest[256];

  {
    *ngtcp2_encode_hex(dest, NULL, 0) = '\0';

    assert_string_equal("", (const char *)dest);
  }

  {
    const uint8_t s[] = "\xde\xad\xbe\xef";

    *ngtcp2_encode_hex(dest, s, sizeof(s) - 1) = '\0';

    assert_string_equal("deadbeef", (const char *)dest);
  }
}
