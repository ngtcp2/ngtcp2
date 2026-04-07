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
#include "ngtcp2_net.h"
#include "ngtcp2_test_helper.h"

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_encode_ipv4),
  munit_void_test(test_ngtcp2_encode_ipv6),
  munit_void_test(test_ngtcp2_get_bytes),
  munit_void_test(test_ngtcp2_encode_uint),
  munit_void_test(test_ngtcp2_encode_hex),
  munit_void_test(test_ngtcp2_encode_uint_hex),
  munit_void_test(test_ngtcp2_encode_uint_hexlen),
  munit_test_end(),
};

const MunitSuite str_suite = {
  .prefix = "/str",
  .tests = tests,
};

void test_ngtcp2_encode_ipv4(void) {
  uint8_t buf[16];
  ngtcp2_in_addr addr;

  addr = (ngtcp2_in_addr){
    .s_addr = ngtcp2_htonl(0xC0A80001),
  };

  *ngtcp2_encode_ipv4(buf, &addr) = '\0';

  assert_string_equal("192.168.0.1", (const char *)buf);

  addr = (ngtcp2_in_addr){
    .s_addr = ngtcp2_htonl(0x7F000001),
  };

  *ngtcp2_encode_ipv4(buf, &addr) = '\0';

  assert_string_equal("127.0.0.1", (const char *)buf);
}

void test_ngtcp2_encode_ipv6(void) {
  uint8_t buf[32 + 7 + 1];
  ngtcp2_in6_addr addr;

  addr = (ngtcp2_in6_addr){
    .s6_addr = {0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x02, 0x00, 0x01},
  };

  *ngtcp2_encode_ipv6(buf, &addr) = '\0';

  assert_string_equal("2001:db8::2:1", (const char *)buf);

  addr = (ngtcp2_in6_addr){
    .s6_addr = {0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
                0x00, 0x01, 0x00, 0x01, 0x00, 0x01},
  };

  *ngtcp2_encode_ipv6(buf, &addr) = '\0';

  assert_string_equal("2001:db8:0:1:1:1:1:1", (const char *)buf);

  addr = (ngtcp2_in6_addr){
    .s6_addr = {0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
  };

  *ngtcp2_encode_ipv6(buf, &addr) = '\0';

  assert_string_equal("2001:db8::1:0:0:1", (const char *)buf);

  addr = (ngtcp2_in6_addr){
    .s6_addr = {0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
                0x08, 0x00, 0x20, 0x0C, 0x41, 0x7A},
  };

  *ngtcp2_encode_ipv6(buf, &addr) = '\0';

  assert_string_equal("2001:db8::8:800:200c:417a", (const char *)buf);

  addr = (ngtcp2_in6_addr){
    .s6_addr = {0xFF, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x01, 0x01},
  };

  *ngtcp2_encode_ipv6(buf, &addr) = '\0';

  assert_string_equal("ff01::101", (const char *)buf);

  addr = (ngtcp2_in6_addr){
    .s6_addr = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
  };

  *ngtcp2_encode_ipv6(buf, &addr) = '\0';

  assert_string_equal("::1", (const char *)buf);

  addr = (ngtcp2_in6_addr){};

  *ngtcp2_encode_ipv6(buf, &addr) = '\0';

  assert_string_equal("::", (const char *)buf);
}

void test_ngtcp2_get_bytes(void) {
  static const uint8_t src[] = {'f', 'o', 'o', 'b', 'a', 'r'};
  uint8_t dest[256];

  assert_ptr_equal(src + sizeof(src), ngtcp2_get_bytes(dest, src, sizeof(src)));
  assert_memory_equal(sizeof(src), src, dest);
}

void test_ngtcp2_encode_uint(void) {
  uint8_t dest[256];
  static const char *nines[] = {
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
  static const char *tens[] = {
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
  assert_size(1, ==, ngtcp2_encode_uintlen(0));

  *ngtcp2_encode_uint(dest, 1) = '\0';

  assert_string_equal("1", (const char *)dest);
  assert_size(1, ==, ngtcp2_encode_uintlen(1));

  n = 9;

  for (i = 0; i < ngtcp2_arraylen(nines); ++i, n = n * 10 + 9) {
    *ngtcp2_encode_uint(dest, n) = '\0';

    assert_string_equal(nines[i], (const char *)dest);
    assert_size(strlen(nines[i]), ==, ngtcp2_encode_uintlen(n));
  }

  n = 10;

  for (i = 0; i < ngtcp2_arraylen(tens); ++i, n *= 10) {
    *ngtcp2_encode_uint(dest, n) = '\0';

    assert_string_equal(tens[i], (const char *)dest);
    assert_size(strlen(tens[i]), ==, ngtcp2_encode_uintlen(n));
  }

  *ngtcp2_encode_uint(dest, UINT64_MAX) = '\0';

  assert_string_equal("18446744073709551615", (const char *)dest);
  assert_size(strlen("18446744073709551615"), ==,
              ngtcp2_encode_uintlen(UINT64_MAX));
}

void test_ngtcp2_encode_hex(void) {
  uint8_t dest[256];

  {
    *ngtcp2_encode_hex(dest, NULL, 0) = '\0';

    assert_string_equal("", (const char *)dest);
  }

  {
    static const uint8_t s[] = "\xDE\xAD\xBE\xEF";

    *ngtcp2_encode_hex(dest, s, ngtcp2_strlen_lit(s)) = '\0';

    assert_string_equal("deadbeef", (const char *)dest);
  }
}

void test_ngtcp2_encode_uint_hex(void) {
  uint8_t dest[256];

  {
    *ngtcp2_encode_uint_hex(dest, 0x0) = '\0';

    assert_string_equal("0", (const char *)dest);
  }

  {
    *ngtcp2_encode_uint_hex(dest, 0x1) = '\0';

    assert_string_equal("1", (const char *)dest);
  }

  {
    *ngtcp2_encode_uint_hex(dest, 0xF) = '\0';

    assert_string_equal("f", (const char *)dest);
  }

  {
    *ngtcp2_encode_uint_hex(dest, 0x1F) = '\0';

    assert_string_equal("1f", (const char *)dest);
  }

  {
    *ngtcp2_encode_uint_hex(dest, 0xE0F) = '\0';

    assert_string_equal("e0f", (const char *)dest);
  }

  {
    *ngtcp2_encode_uint_hex(dest, 0xBADCACE) = '\0';

    assert_string_equal("badcace", (const char *)dest);
  }

  {
    *ngtcp2_encode_uint_hex(dest, 0xDEADBEEFBAADCACEULL) = '\0';

    assert_string_equal("deadbeefbaadcace", (const char *)dest);
  }
}

void test_ngtcp2_encode_uint_hexlen(void) {
  assert_size(1, ==, ngtcp2_encode_uint_hexlen(0x0));
  assert_size(1, ==, ngtcp2_encode_uint_hexlen(0x1));
  assert_size(1, ==, ngtcp2_encode_uint_hexlen(0xF));
  assert_size(2, ==, ngtcp2_encode_uint_hexlen(0x1F));
  assert_size(3, ==, ngtcp2_encode_uint_hexlen(0xE0F));
  assert_size(7, ==, ngtcp2_encode_uint_hexlen(0xBADCACE));
  assert_size(16, ==, ngtcp2_encode_uint_hexlen(0xDEADBEEFBAADCACEULL));
}
