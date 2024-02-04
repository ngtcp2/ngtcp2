/*
 * ngtcp2
 *
 * Copyright (c) 2017 ngtcp2 contributors
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
#include "ngtcp2_idtr_test.h"

#include <stdio.h>

#include "ngtcp2_idtr.h"
#include "ngtcp2_test_helper.h"
#include "ngtcp2_mem.h"

static const MunitTest tests[] = {
    munit_void_test(test_ngtcp2_idtr_open),
    munit_test_end(),
};

const MunitSuite idtr_suite = {
    "/idtr", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE,
};

static int64_t stream_id_from_id(uint64_t id) { return (int64_t)(id * 4); }

void test_ngtcp2_idtr_open(void) {
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_idtr idtr;
  int rv;
  ngtcp2_ksl_it it;
  ngtcp2_range key;

  ngtcp2_idtr_init(&idtr, 0, mem);

  rv = ngtcp2_idtr_open(&idtr, stream_id_from_id(0));

  assert_int(0, ==, rv);

  it = ngtcp2_ksl_begin(&idtr.gap.gap);
  key = *(ngtcp2_range *)ngtcp2_ksl_it_key(&it);

  assert_uint64(1, ==, key.begin);
  assert_uint64(UINT64_MAX, ==, key.end);

  rv = ngtcp2_idtr_open(&idtr, stream_id_from_id(1000000007));

  assert_int(0, ==, rv);

  it = ngtcp2_ksl_begin(&idtr.gap.gap);
  key = *(ngtcp2_range *)ngtcp2_ksl_it_key(&it);

  assert_uint64(1, ==, key.begin);
  assert_uint64(1000000007, ==, key.end);

  ngtcp2_ksl_it_next(&it);
  key = *(ngtcp2_range *)ngtcp2_ksl_it_key(&it);

  assert_uint64(1000000008, ==, key.begin);
  assert_uint64(UINT64_MAX, ==, key.end);

  rv = ngtcp2_idtr_open(&idtr, stream_id_from_id(0));

  assert_int(NGTCP2_ERR_STREAM_IN_USE, ==, rv);

  rv = ngtcp2_idtr_open(&idtr, stream_id_from_id(1000000007));

  assert_int(NGTCP2_ERR_STREAM_IN_USE, ==, rv);

  ngtcp2_idtr_free(&idtr);
}
