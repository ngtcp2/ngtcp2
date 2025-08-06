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
#include "ngtcp2_pcg_test.h"

#include <stdio.h>

#include "ngtcp2_pcg.h"
#include "ngtcp2_test_helper.h"

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_pcg32),
  munit_test_end(),
};

const MunitSuite pcg_suite = {
  .prefix = "/pcg",
  .tests = tests,
};

void test_ngtcp2_pcg32(void) {
  ngtcp2_pcg32 pcg;

  ngtcp2_pcg32_init(&pcg, 0xdeadbeef);

  assert_uint32(3283094731, ==, ngtcp2_pcg32_rand(&pcg));
  assert_uint32(3888927911, ==, ngtcp2_pcg32_rand(&pcg));

  assert_uint32(12, ==, ngtcp2_pcg32_rand_n(&pcg, 100));
  assert_uint32(58, ==, ngtcp2_pcg32_rand_n(&pcg, 100));
  assert_uint32(1, ==, ngtcp2_pcg32_rand_n(&pcg, 2));
  assert_uint32(0, ==, ngtcp2_pcg32_rand_n(&pcg, 1));
}
