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
#include "ngtcp2_wf_test.h"

#include <stdio.h>
#include <assert.h>

#include "ngtcp2_wf.h"
#include "ngtcp2_test_helper.h"

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_wf_update),
  munit_test_end(),
};

const MunitSuite wf_suite = {
  .prefix = "/wf",
  .tests = tests,
};

void test_ngtcp2_wf_update(void) {
  ngtcp2_wf wf;

  ngtcp2_wf_init(&wf, 8);
  ngtcp2_wf_update(&wf, 100, 0);

  assert_uint64(100, ==, wf.samples[0].value);
  assert_uint64(0, ==, wf.samples[0].ts);
  assert_uint64(100, ==, wf.samples[1].value);
  assert_uint64(0, ==, wf.samples[1].ts);
  assert_uint64(100, ==, wf.samples[2].value);
  assert_uint64(0, ==, wf.samples[2].ts);
  assert_uint64(100, ==, ngtcp2_wf_get_best(&wf));

  /* A quarter of window has not passed.  New sample which is not the
     best is discarded. */
  ngtcp2_wf_update(&wf, 90, 1);

  assert_uint64(100, ==, wf.samples[0].value);
  assert_uint64(0, ==, wf.samples[0].ts);
  assert_uint64(100, ==, wf.samples[1].value);
  assert_uint64(0, ==, wf.samples[1].ts);
  assert_uint64(100, ==, wf.samples[2].value);
  assert_uint64(0, ==, wf.samples[2].ts);
  assert_uint64(100, ==, ngtcp2_wf_get_best(&wf));

  /* A quarter of the window has passed without a better sample. */
  ngtcp2_wf_update(&wf, 90, 3);

  assert_uint64(100, ==, wf.samples[0].value);
  assert_uint64(0, ==, wf.samples[0].ts);
  assert_uint64(90, ==, wf.samples[1].value);
  assert_uint64(3, ==, wf.samples[1].ts);
  assert_uint64(90, ==, wf.samples[2].value);
  assert_uint64(3, ==, wf.samples[2].ts);
  assert_uint64(100, ==, ngtcp2_wf_get_best(&wf));

  /* A half of the window has passed without a better sample. */
  ngtcp2_wf_update(&wf, 80, 8);

  assert_uint64(100, ==, wf.samples[0].value);
  assert_uint64(0, ==, wf.samples[0].ts);
  assert_uint64(90, ==, wf.samples[1].value);
  assert_uint64(3, ==, wf.samples[1].ts);
  assert_uint64(80, ==, wf.samples[2].value);
  assert_uint64(8, ==, wf.samples[2].ts);
  assert_uint64(100, ==, ngtcp2_wf_get_best(&wf));

  /* The best sample has expired. */
  ngtcp2_wf_update(&wf, 70, 9);

  assert_uint64(90, ==, wf.samples[0].value);
  assert_uint64(3, ==, wf.samples[0].ts);
  assert_uint64(80, ==, wf.samples[1].value);
  assert_uint64(8, ==, wf.samples[1].ts);
  assert_uint64(70, ==, wf.samples[2].value);
  assert_uint64(9, ==, wf.samples[2].ts);
  assert_uint64(90, ==, ngtcp2_wf_get_best(&wf));

  /* Update third estimate. */
  ngtcp2_wf_update(&wf, 75, 9);

  assert_uint64(90, ==, wf.samples[0].value);
  assert_uint64(3, ==, wf.samples[0].ts);
  assert_uint64(80, ==, wf.samples[1].value);
  assert_uint64(8, ==, wf.samples[1].ts);
  assert_uint64(75, ==, wf.samples[2].value);
  assert_uint64(9, ==, wf.samples[2].ts);
  assert_uint64(90, ==, ngtcp2_wf_get_best(&wf));

  /* Update second and third samples. */
  ngtcp2_wf_update(&wf, 85, 9);

  assert_uint64(90, ==, wf.samples[0].value);
  assert_uint64(3, ==, wf.samples[0].ts);
  assert_uint64(85, ==, wf.samples[1].value);
  assert_uint64(9, ==, wf.samples[1].ts);
  assert_uint64(85, ==, wf.samples[2].value);
  assert_uint64(9, ==, wf.samples[2].ts);
  assert_uint64(90, ==, ngtcp2_wf_get_best(&wf));

  /* Update all samples because new sample is the best estimate. */
  ngtcp2_wf_update(&wf, 100, 10);

  assert_uint64(100, ==, wf.samples[0].value);
  assert_uint64(10, ==, wf.samples[0].ts);
  assert_uint64(100, ==, wf.samples[1].value);
  assert_uint64(10, ==, wf.samples[1].ts);
  assert_uint64(100, ==, wf.samples[2].value);
  assert_uint64(10, ==, wf.samples[2].ts);
  assert_uint64(100, ==, ngtcp2_wf_get_best(&wf));
}
