/*
 * ngtcp2
 *
 * Copyright (c) 2023 ngtcp2 contributors
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
#include "ngtcp2_cc_test.h"

#include <stdio.h>
#include <assert.h>

#include "ngtcp2_cc.h"
#include "ngtcp2_test_helper.h"

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_cbrt),
  munit_test_end(),
};

const MunitSuite cc_suite = {
  .prefix = "/cc",
  .tests = tests,
};

void test_ngtcp2_cbrt(void) {
  uint64_t n;
  uint64_t i;

  for (i = 1; i <= 2642245; ++i) {
    n = i * i * i;

    assert_uint64(i, ==, ngtcp2_cbrt(n));
    assert_uint64(i - 1, ==, ngtcp2_cbrt(n - 1));
  }

  assert_uint64(2642245, ==, ngtcp2_cbrt(UINT64_MAX));
  assert_uint64(0, ==, ngtcp2_cbrt(0));
}
