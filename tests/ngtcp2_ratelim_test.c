/*
 * ngtcp2
 *
 * Copyright (c) 2025 ngtcp2 contributors
 * Copyright (c) 2023 nghttp2 contributors
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
#include "ngtcp2_ratelim_test.h"

#include <stdio.h>

#include "munit.h"

#include "ngtcp2_ratelim.h"
#include "ngtcp2_test_helper.h"

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_ratelim_drain),
  munit_test_end(),
};

const MunitSuite ratelim_suite = {
  "/ratelim", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE,
};

void test_ngtcp2_ratelim_drain(void) {
  ngtcp2_ratelim rlim;
  ngtcp2_tstamp ts = 0;
  int rv;

  ngtcp2_ratelim_init(&rlim, 1000, 33, ts);

  assert_uint64(1000, ==, rlim.tokens);
  assert_uint64(1000, ==, rlim.burst);
  assert_uint64(33, ==, rlim.rate);
  assert_uint64(0, ==, rlim.ts);

  rv = ngtcp2_ratelim_drain(&rlim, 100, ts);

  assert_int(0, ==, rv);
  assert_uint64(900, ==, rlim.tokens);

  ts += NGTCP2_SECONDS;
  rv = ngtcp2_ratelim_drain(&rlim, 10, ts);

  assert_int(0, ==, rv);
  assert_uint64(923, ==, rlim.tokens);

  ts += 100 * NGTCP2_MILLISECONDS;
  rv = ngtcp2_ratelim_drain(&rlim, 5, ts);

  assert_int(0, ==, rv);
  assert_uint64(921, ==, rlim.tokens);
  assert_uint64(300000000, ==, rlim.carry);

  ts += 500 * NGTCP2_MILLISECONDS;
  rv = ngtcp2_ratelim_drain(&rlim, 5, ts);

  assert_int(0, ==, rv);
  assert_uint64(932, ==, rlim.tokens);
  assert_uint64(800000000, ==, rlim.carry);

  ts += 400 * NGTCP2_MILLISECONDS;
  rv = ngtcp2_ratelim_drain(&rlim, 1, ts);

  assert_int(0, ==, rv);
  assert_uint64(945, ==, rlim.tokens);
  assert_uint64(0, ==, rlim.carry);

  rv = ngtcp2_ratelim_drain(&rlim, 946, ts);

  assert_int(-1, ==, rv);

  rv = ngtcp2_ratelim_drain(&rlim, 945, ts);

  assert_int(0, ==, rv);
  assert_uint64(0, ==, rlim.tokens);
  assert_uint64(0, ==, rlim.carry);

  ts += 30400 * NGTCP2_MILLISECONDS;

  rv = ngtcp2_ratelim_drain(&rlim, 0, ts);

  assert_int(0, ==, rv);
  assert_uint64(1000, ==, rlim.tokens);
  assert_uint64(0, ==, rlim.carry);

  /* Overflow */
  ngtcp2_ratelim_init(&rlim, UINT64_MAX - 1, UINT64_MAX, ts);

  assert_uint64(UINT64_MAX - 1, ==, rlim.tokens);
  assert_uint64(UINT64_MAX - 1, ==, rlim.burst);
  assert_uint64(UINT64_MAX, ==, rlim.rate);
  assert_uint64(ts, ==, rlim.ts);

  ts += 2;

  rv = ngtcp2_ratelim_drain(&rlim, 1, ts);

  assert_int(0, ==, rv);
  assert_uint64(UINT64_MAX - 2, ==, rlim.tokens);
}
