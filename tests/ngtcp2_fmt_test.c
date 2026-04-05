/*
 * ngtcp2
 *
 * Copyright (c) 2026 ngtcp2 contributors
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
#include "ngtcp2_fmt_test.h"

#include <stdio.h>
#include <limits.h>

#include "ngtcp2_fmt.h"
#include "ngtcp2_net.h"
#include "ngtcp2_test_helper.h"

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_fmt_format),
  munit_test_end(),
};

const MunitSuite fmt_suite = {
  .prefix = "/fmt",
  .tests = tests,
};

void test_ngtcp2_fmt_format(void) {
  char buf[1024];
  size_t nwrite;

  /* integral */
  {
    ngtcp2_fmt_format(buf, &nwrite, "[", (uint64_t)UINT64_MAX, "]");

    assert_string_equal("[18446744073709551615]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", (uint32_t)UINT32_MAX, "]");

    assert_string_equal("[4294967295]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", (uint16_t)UINT16_MAX, "]");

    assert_string_equal("[65535]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", (uint8_t)UINT8_MAX, "]");

    assert_string_equal("[255]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", (int64_t)INT64_MIN, "]");

    assert_string_equal("[-9223372036854775808]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", (int32_t)INT32_MIN, "]");

    assert_string_equal("[-2147483648]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", (int16_t)INT16_MIN, "]");

    assert_string_equal("[-32768]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", 0, "]");

    assert_string_equal("[0]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  /* char */
  {
    ngtcp2_fmt_format(buf, &nwrite, "[", (char)'f', (char)'o', (char)'o', "]");

    assert_string_equal("[foo]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  /* const char * */
  {
    const char *s = "foo bar";

    ngtcp2_fmt_format(buf, &nwrite, "[", s, "]");

    assert_string_equal("[foo bar]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  /* char * */
  {
    char s[] = "foo bar";

    ngtcp2_fmt_format(buf, &nwrite, "[", s, "]");

    assert_string_equal("[foo bar]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  /* ngtcp2_cid */
  {
    ngtcp2_cid cid = {
      .datalen = 4,
      .data = {0xBA, 0xAD, 0xCA, 0xCE},
    };

    ngtcp2_fmt_format(buf, &nwrite, "[", &cid, "]");

    assert_string_equal("[baadcace]", buf);
    assert_size(strlen(buf), ==, nwrite);

    ngtcp2_fmt_format(buf, &nwrite, "[", (const ngtcp2_cid *)&cid, "]");

    assert_string_equal("[baadcace]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  /* ngtcp2_in_addr */
  {
    ngtcp2_in_addr addr = {
      .s_addr = ngtcp2_htonl(0xBAADCACE),
    };

    ngtcp2_fmt_format(buf, &nwrite, "[", &addr, "]");

    assert_string_equal("[186.173.202.206]", buf);
    assert_size(strlen(buf), ==, nwrite);

    ngtcp2_fmt_format(buf, &nwrite, "[", (const ngtcp2_in_addr *)&addr, "]");

    assert_string_equal("[186.173.202.206]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  /* ngtcp2_in6_addr */
  {
    ngtcp2_in6_addr addr = {
      .s6_addr = {0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
                  0x08, 0x00, 0x20, 0x0C, 0x41, 0x7A},
    };

    ngtcp2_fmt_format(buf, &nwrite, "[", &addr, "]");

    assert_string_equal("[2001:db8::8:800:200c:417a]", buf);
    assert_size(strlen(buf), ==, nwrite);

    ngtcp2_fmt_format(buf, &nwrite, "[", (const ngtcp2_in6_addr *)&addr, "]");

    assert_string_equal("[2001:db8::8:800:200c:417a]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  /* uintw */
  {
    ngtcp2_fmt_format(buf, &nwrite, "[", uintw(0, 7), "]");

    assert_string_equal("[0000000]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", uintw(35, 7), "]");

    assert_string_equal("[0000035]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", uintw(1000000007, 9), "]");

    assert_string_equal("[1000000007]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", uintw(1000000007, 10), "]");

    assert_string_equal("[1000000007]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  /* hex */
  {
    ngtcp2_fmt_format(buf, &nwrite, "[", hex(0xDEADBEEF), "]");

    assert_string_equal("[deadbeef]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", hex((uint64_t)UINT64_MAX), "]");

    assert_string_equal("[ffffffffffffffff]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", hex((uint32_t)UINT32_MAX), "]");

    assert_string_equal("[ffffffff]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", hex((uint16_t)UINT16_MAX), "]");

    assert_string_equal("[ffff]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", hex((uint8_t)UINT8_MAX), "]");

    assert_string_equal("[ff]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", hex((int64_t)INT64_MIN), "]");

    assert_string_equal("[8000000000000000]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", hex((int32_t)INT32_MIN), "]");

    assert_string_equal("[80000000]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", hex((int16_t)INT16_MIN), "]");

    assert_string_equal("[8000]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", hex((int8_t)INT8_MIN), "]");

    assert_string_equal("[80]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", hex((char)INT8_MIN), "]");

    assert_string_equal("[80]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  /* hexw */
  {
    ngtcp2_fmt_format(buf, &nwrite, "[", hexw(0xDEADBEEF, 9), "]");

    assert_string_equal("[0deadbeef]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", hexw(0xDEADBEEF, 8), "]");

    assert_string_equal("[deadbeef]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", hexw(0xDEADBEEF, 7), "]");

    assert_string_equal("[deadbeef]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", hexw(0xDEADBEEF, 0), "]");

    assert_string_equal("[deadbeef]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", hexw((uint64_t)UINT64_MAX, 17), "]");

    assert_string_equal("[0ffffffffffffffff]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", hexw((uint32_t)UINT32_MAX, 9), "]");

    assert_string_equal("[0ffffffff]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", hexw((uint16_t)UINT16_MAX, 5), "]");

    assert_string_equal("[0ffff]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", hexw((uint8_t)UINT8_MAX, 3), "]");

    assert_string_equal("[0ff]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", hexw((int64_t)INT64_MIN, 17), "]");

    assert_string_equal("[08000000000000000]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", hexw((int32_t)INT32_MIN, 9), "]");

    assert_string_equal("[080000000]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", hexw((int16_t)INT16_MIN, 5), "]");

    assert_string_equal("[08000]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", hexw((int8_t)INT8_MIN, 3), "]");

    assert_string_equal("[080]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  {
    ngtcp2_fmt_format(buf, &nwrite, "[", hexw((char)INT8_MIN, 3), "]");

    assert_string_equal("[080]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  /* bhex, lbhex */
  {
    uint8_t b[] = {0xBA, 0xAD, 0xF0, 0x0D};

    ngtcp2_fmt_format(buf, &nwrite, "[", bhex(b, sizeof(b)), "]");

    assert_string_equal("[baadf00d]", buf);
    assert_size(strlen(buf), ==, nwrite);

    ngtcp2_fmt_format(buf, &nwrite, "[", bhex((const uint8_t *)b, sizeof(b)),
                      "]");

    assert_string_equal("[baadf00d]", buf);
    assert_size(strlen(buf), ==, nwrite);

    ngtcp2_fmt_format(buf, &nwrite, "[", lbhex(b), "]");

    assert_string_equal("[baadf00d]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  /* ascii */
  {
    uint8_t b[] = {'F', 0x00, 0x20, 'a', '1', 0x7F};

    ngtcp2_fmt_format(buf, &nwrite, "[", ascii(b, sizeof(b)), "]");

    assert_string_equal("[F. a1.]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }

  /* stringify */
  {
    ngtcp2_fmt_format(buf, &nwrite, "[", stringify(NGTCP2_MAX_UDP_PAYLOAD_SIZE),
                      "]");

    assert_string_equal("[1200]", buf);
    assert_size(strlen(buf), ==, nwrite);
  }
}
