/*
 * ngtcp2
 *
 * Copyright (c) 2025 ngtcp2 contributors
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
#include "ngtcp2_addr_test.h"

#include <stdio.h>

#include "ngtcp2_addr.h"
#include "ngtcp2_test_helper.h"

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_addr_eq),
  munit_void_test(test_ngtcp2_addr_cmp),
  munit_void_test(test_ngtcp2_addr_empty),
  munit_test_end(),
};

const MunitSuite addr_suite = {
  .prefix = "/addr",
  .tests = tests,
};

void test_ngtcp2_addr_eq(void) {
  ngtcp2_addr a, b;

  {
    ngtcp2_sockaddr_in saa, sab;

    saa.sin_family = NGTCP2_AF_INET;
    sab.sin_family = NGTCP2_AF_INET;
    memcpy(&saa.sin_addr, "1234", sizeof(saa.sin_addr));
    memcpy(&sab.sin_addr, "1234", sizeof(sab.sin_addr));
    saa.sin_port = 100;
    sab.sin_port = 100;

    ngtcp2_addr_init(&a, (const ngtcp2_sockaddr *)&saa, sizeof(saa));
    ngtcp2_addr_init(&b, (const ngtcp2_sockaddr *)&sab, sizeof(sab));

    assert_true(ngtcp2_addr_eq(&a, &b));

    saa.sin_port = 99;

    assert_false(ngtcp2_addr_eq(&a, &b));

    memcpy(&saa.sin_addr, "1235", sizeof(saa.sin_addr));
    saa.sin_port = 100;

    assert_false(ngtcp2_addr_eq(&a, &b));
  }

  {
    ngtcp2_sockaddr_in6 saa, sab;

    saa.sin6_family = NGTCP2_AF_INET6;
    sab.sin6_family = NGTCP2_AF_INET6;
    memcpy(&saa.sin6_addr, "1234123412341234", sizeof(saa.sin6_addr));
    memcpy(&sab.sin6_addr, "1234123412341234", sizeof(sab.sin6_addr));
    saa.sin6_port = 100;
    sab.sin6_port = 100;

    ngtcp2_addr_init(&a, (const ngtcp2_sockaddr *)&saa, sizeof(saa));
    ngtcp2_addr_init(&b, (const ngtcp2_sockaddr *)&sab, sizeof(sab));

    assert_true(ngtcp2_addr_eq(&a, &b));

    saa.sin6_port = 99;

    assert_false(ngtcp2_addr_eq(&a, &b));

    memcpy(&saa.sin6_addr, "1235123412351234", sizeof(saa.sin6_addr));
    saa.sin6_port = 100;

    assert_false(ngtcp2_addr_eq(&a, &b));
  }

  {
    ngtcp2_sockaddr_in saa = {0};
    ngtcp2_sockaddr_in6 sab = {0};

    saa.sin_family = NGTCP2_AF_INET;
    sab.sin6_family = NGTCP2_AF_INET6;

    ngtcp2_addr_init(&a, (const ngtcp2_sockaddr *)&saa, sizeof(saa));
    ngtcp2_addr_init(&b, (const ngtcp2_sockaddr *)&sab, sizeof(sab));

    assert_false(ngtcp2_addr_eq(&a, &b));
  }
}

void test_ngtcp2_addr_cmp(void) {
  ngtcp2_addr a, b;

  {
    ngtcp2_sockaddr_in saa, sab;

    saa.sin_family = NGTCP2_AF_INET;
    sab.sin_family = NGTCP2_AF_INET;
    memcpy(&saa.sin_addr, "1234", sizeof(saa.sin_addr));
    memcpy(&sab.sin_addr, "1234", sizeof(sab.sin_addr));
    saa.sin_port = 100;
    sab.sin_port = 100;

    ngtcp2_addr_init(&a, (const ngtcp2_sockaddr *)&saa, sizeof(saa));
    ngtcp2_addr_init(&b, (const ngtcp2_sockaddr *)&sab, sizeof(sab));

    assert_uint32(NGTCP2_ADDR_CMP_FLAG_NONE, ==, ngtcp2_addr_cmp(&a, &b));

    saa.sin_port = 99;

    assert_uint32(NGTCP2_ADDR_CMP_FLAG_PORT, ==, ngtcp2_addr_cmp(&a, &b));

    memcpy(&saa.sin_addr, "1235", sizeof(saa.sin_addr));

    assert_uint32(NGTCP2_ADDR_CMP_FLAG_ADDR | NGTCP2_ADDR_CMP_FLAG_PORT, ==,
                  ngtcp2_addr_cmp(&a, &b));

    saa.sin_port = 100;

    assert_uint32(NGTCP2_ADDR_CMP_FLAG_ADDR, ==, ngtcp2_addr_cmp(&a, &b));
  }

  {
    ngtcp2_sockaddr_in6 saa, sab;

    saa.sin6_family = NGTCP2_AF_INET6;
    sab.sin6_family = NGTCP2_AF_INET6;
    memcpy(&saa.sin6_addr, "1234123412341234", sizeof(saa.sin6_addr));
    memcpy(&sab.sin6_addr, "1234123412341234", sizeof(sab.sin6_addr));
    saa.sin6_port = 100;
    sab.sin6_port = 100;

    ngtcp2_addr_init(&a, (const ngtcp2_sockaddr *)&saa, sizeof(saa));
    ngtcp2_addr_init(&b, (const ngtcp2_sockaddr *)&sab, sizeof(sab));

    assert_uint32(NGTCP2_ADDR_CMP_FLAG_NONE, ==, ngtcp2_addr_cmp(&a, &b));

    saa.sin6_port = 99;

    assert_uint32(NGTCP2_ADDR_CMP_FLAG_PORT, ==, ngtcp2_addr_cmp(&a, &b));

    memcpy(&saa.sin6_addr, "1235123412351234", sizeof(saa.sin6_addr));

    assert_uint32(NGTCP2_ADDR_CMP_FLAG_ADDR | NGTCP2_ADDR_CMP_FLAG_PORT, ==,
                  ngtcp2_addr_cmp(&a, &b));

    saa.sin6_port = 100;

    assert_uint32(NGTCP2_ADDR_CMP_FLAG_ADDR, ==, ngtcp2_addr_cmp(&a, &b));
  }

  {
    ngtcp2_sockaddr_in saa = {0};
    ngtcp2_sockaddr_in6 sab = {0};

    saa.sin_family = NGTCP2_AF_INET;
    sab.sin6_family = NGTCP2_AF_INET6;

    ngtcp2_addr_init(&a, (const ngtcp2_sockaddr *)&saa, sizeof(saa));
    ngtcp2_addr_init(&b, (const ngtcp2_sockaddr *)&sab, sizeof(sab));

    assert_uint32(NGTCP2_ADDR_CMP_FLAG_FAMILY, ==, ngtcp2_addr_cmp(&a, &b));
  }
}

void test_ngtcp2_addr_empty(void) {
  ngtcp2_addr a = {
    .addrlen = 1,
  };
  ngtcp2_addr b = {0};

  assert_false(ngtcp2_addr_empty(&a));
  assert_true(ngtcp2_addr_empty(&b));
}
