/*
 * ngtcp2
 *
 * Copyright (c) 2018 ngtcp2 contributors
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
#include "ngtcp2_gaptr_test.h"

#include <stdio.h>

#include "ngtcp2_gaptr.h"
#include "ngtcp2_test_helper.h"
#include "ngtcp2_mem.h"

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_gaptr_push),
  munit_void_test(test_ngtcp2_gaptr_is_pushed),
  munit_void_test(test_ngtcp2_gaptr_drop_first_gap),
  munit_void_test(test_ngtcp2_gaptr_get_first_gap_after),
  munit_test_end(),
};

const MunitSuite gaptr_suite = {
  "/gaptr", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE,
};

void test_ngtcp2_gaptr_push(void) {
  ngtcp2_gaptr gaptr;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_ksl_it it;
  ngtcp2_range r;
  int rv;
  size_t i;

  ngtcp2_gaptr_init(&gaptr, mem);

  rv = ngtcp2_gaptr_push(&gaptr, 0, 1);

  assert_int(0, ==, rv);

  it = ngtcp2_ksl_begin(&gaptr.gap);
  r = *(ngtcp2_range *)ngtcp2_ksl_it_key(&it);

  assert_uint64(1, ==, r.begin);
  assert_uint64(UINT64_MAX, ==, r.end);

  rv = ngtcp2_gaptr_push(&gaptr, 12389, 133);

  assert_int(0, ==, rv);

  it = ngtcp2_ksl_begin(&gaptr.gap);
  r = *(ngtcp2_range *)ngtcp2_ksl_it_key(&it);

  assert_uint64(1, ==, r.begin);
  assert_uint64(12389, ==, r.end);

  ngtcp2_ksl_it_next(&it);
  r = *(ngtcp2_range *)ngtcp2_ksl_it_key(&it);

  assert_uint64(12389 + 133, ==, r.begin);
  assert_uint64(UINT64_MAX, ==, r.end);

  for (i = 0; i < 2; ++i) {
    rv = ngtcp2_gaptr_push(&gaptr, 1, 12389);

    assert_int(0, ==, rv);

    it = ngtcp2_ksl_begin(&gaptr.gap);
    r = *(ngtcp2_range *)ngtcp2_ksl_it_key(&it);

    assert_uint64(12389 + 133, ==, r.begin);
    assert_uint64(UINT64_MAX, ==, r.end);
  }

  rv = ngtcp2_gaptr_push(&gaptr, 12389 + 133 - 1, 2);

  assert_int(0, ==, rv);

  it = ngtcp2_ksl_begin(&gaptr.gap);
  r = *(ngtcp2_range *)ngtcp2_ksl_it_key(&it);

  assert_uint64(12389 + 133 + 1, ==, r.begin);
  assert_uint64(UINT64_MAX, ==, r.end);

  ngtcp2_gaptr_free(&gaptr);
}

void test_ngtcp2_gaptr_is_pushed(void) {
  ngtcp2_gaptr gaptr;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  int rv;

  ngtcp2_gaptr_init(&gaptr, mem);

  rv = ngtcp2_gaptr_push(&gaptr, 1000000007, 1009);

  assert_int(0, ==, rv);
  assert_true(ngtcp2_gaptr_is_pushed(&gaptr, 1000000007, 1009));
  assert_false(ngtcp2_gaptr_is_pushed(&gaptr, 1000000007, 1010));

  ngtcp2_gaptr_free(&gaptr);
}

void test_ngtcp2_gaptr_drop_first_gap(void) {
  ngtcp2_gaptr gaptr;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  int rv;

  ngtcp2_gaptr_init(&gaptr, mem);

  rv = ngtcp2_gaptr_push(&gaptr, 113245, 12);

  assert_int(0, ==, rv);

  ngtcp2_gaptr_drop_first_gap(&gaptr);

  assert_true(ngtcp2_gaptr_is_pushed(&gaptr, 0, 1));
  assert_uint64(113245 + 12, ==, ngtcp2_gaptr_first_gap_offset(&gaptr));

  ngtcp2_gaptr_free(&gaptr);
}

void test_ngtcp2_gaptr_get_first_gap_after(void) {
  ngtcp2_gaptr gaptr;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  int rv;
  ngtcp2_range r;

  ngtcp2_gaptr_init(&gaptr, mem);

  rv = ngtcp2_gaptr_push(&gaptr, 100, 1);

  assert_int(0, ==, rv);

  rv = ngtcp2_gaptr_push(&gaptr, 101, 1);

  assert_int(0, ==, rv);

  rv = ngtcp2_gaptr_push(&gaptr, 102, 1);

  assert_int(0, ==, rv);

  rv = ngtcp2_gaptr_push(&gaptr, 104, 1);

  assert_int(0, ==, rv);

  r = ngtcp2_gaptr_get_first_gap_after(&gaptr, 99);

  assert_uint64(0, ==, r.begin);
  assert_uint64(100, ==, r.end);

  r = ngtcp2_gaptr_get_first_gap_after(&gaptr, 100);

  assert_uint64(103, ==, r.begin);
  assert_uint64(104, ==, r.end);

  r = ngtcp2_gaptr_get_first_gap_after(&gaptr, 102);

  assert_uint64(103, ==, r.begin);
  assert_uint64(104, ==, r.end);

  r = ngtcp2_gaptr_get_first_gap_after(&gaptr, 103);

  assert_uint64(103, ==, r.begin);
  assert_uint64(104, ==, r.end);

  r = ngtcp2_gaptr_get_first_gap_after(&gaptr, UINT64_MAX - 1);

  assert_uint64(105, ==, r.begin);
  assert_uint64(UINT64_MAX, ==, r.end);

  ngtcp2_gaptr_free(&gaptr);
}
