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
#include "ngtcp2_macro_test.h"

#include <stdio.h>
#include <limits.h>

#include "ngtcp2_macro.h"
#include "ngtcp2_test_helper.h"

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_max),
  munit_void_test(test_ngtcp2_min),
  munit_test_end(),
};

const MunitSuite macro_suite = {
  .prefix = "/macro",
  .tests = tests,
};

void test_ngtcp2_max(void) {
  /* unsigned */
  assert_uint64(UINT64_MAX, ==, ngtcp2_max(0, UINT64_MAX));
  assert_uint32(UINT32_MAX, ==, ngtcp2_max(0, UINT32_MAX));
  assert_uint16(UINT16_MAX, ==, ngtcp2_max(0, (uint16_t)UINT16_MAX));
  assert_uint8(UINT8_MAX, ==, ngtcp2_max(0, (uint8_t)UINT8_MAX));
  /* signed */
  assert_int64(INT64_MAX, ==, ngtcp2_max(INT64_MAX, INT64_MIN));
  assert_int32(INT32_MAX, ==, ngtcp2_max(INT32_MAX, INT32_MIN));
  assert_int16(INT16_MAX, ==,
               ngtcp2_max((int16_t)INT16_MAX, (int16_t)INT16_MIN));
  assert_int8(INT8_MAX, ==, ngtcp2_max((int8_t)INT8_MAX, (int8_t)INT8_MIN));
}

void test_ngtcp2_min(void) {
  /* unsigned */
  assert_uint64(0, ==, ngtcp2_min(0, UINT64_MAX));
  assert_uint32(0, ==, ngtcp2_min(0, UINT32_MAX));
  assert_uint16(0, ==, ngtcp2_min(0, (uint16_t)UINT16_MAX));
  assert_uint8(0, ==, ngtcp2_min(0, (uint8_t)UINT8_MAX));
  /* signed */
  assert_int64(INT64_MIN, ==, ngtcp2_min(INT64_MAX, INT64_MIN));
  assert_int32(INT32_MIN, ==, ngtcp2_min(INT32_MAX, INT32_MIN));
  assert_int16(INT16_MIN, ==,
               ngtcp2_min((int16_t)INT16_MAX, (int16_t)INT16_MIN));
  assert_int8(INT8_MIN, ==, ngtcp2_min((int8_t)INT8_MAX, (int8_t)INT8_MIN));
}
