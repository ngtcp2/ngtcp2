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
#include "ngtcp2_tstamp_test.h"

#include <stdio.h>

#include "ngtcp2_tstamp.h"
#include "ngtcp2_test_helper.h"

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_tstamp_elapsed),
  munit_test_end(),
};

const MunitSuite tstamp_suite = {
  "/tstamp", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE,
};

void test_ngtcp2_tstamp_elapsed(void) {
  assert_false(ngtcp2_tstamp_elapsed(UINT64_MAX, 0, 0));
  assert_false(ngtcp2_tstamp_not_elapsed(UINT64_MAX, 0, 0));

  assert_false(ngtcp2_tstamp_elapsed(1, UINT64_MAX - 1, UINT64_MAX - 1));
  assert_true(ngtcp2_tstamp_not_elapsed(1, UINT64_MAX - 1, UINT64_MAX - 1));

  assert_true(ngtcp2_tstamp_elapsed(1, UINT64_MAX - 2, UINT64_MAX - 1));
  assert_false(ngtcp2_tstamp_not_elapsed(1, UINT64_MAX - 2, UINT64_MAX - 1));

  assert_false(ngtcp2_tstamp_elapsed(2, UINT64_MAX - 1, UINT64_MAX - 1));
  assert_true(ngtcp2_tstamp_not_elapsed(2, UINT64_MAX - 1, UINT64_MAX - 1));

  assert_false(ngtcp2_tstamp_elapsed(0, UINT64_MAX, UINT64_MAX - 1));
  assert_true(ngtcp2_tstamp_not_elapsed(0, UINT64_MAX, UINT64_MAX - 1));
}
