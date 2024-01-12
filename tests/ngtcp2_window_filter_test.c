/*
 * ngtcp2
 *
 * Copyright (c) 2024 ngtcp2 contributors
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
#include "ngtcp2_window_filter_test.h"

#include <stdio.h>
#include <assert.h>

#include <CUnit/CUnit.h>

#include "ngtcp2_window_filter.h"
#include "ngtcp2_test_helper.h"

void test_ngtcp2_window_filter_update(void) {
  ngtcp2_window_filter wf;

  ngtcp2_window_filter_init(&wf, 8);
  ngtcp2_window_filter_update(&wf, 100, 0);

  CU_ASSERT(100 == wf.estimates[0].sample);
  CU_ASSERT(0 == wf.estimates[0].time);
  CU_ASSERT(100 == wf.estimates[1].sample);
  CU_ASSERT(0 == wf.estimates[1].time);
  CU_ASSERT(100 == wf.estimates[2].sample);
  CU_ASSERT(0 == wf.estimates[2].time);
  CU_ASSERT(100 == ngtcp2_window_filter_get_best(&wf));

  /* A quarter of window has not passed.  New sample which is not the
     best is discarded. */
  ngtcp2_window_filter_update(&wf, 90, 1);

  CU_ASSERT(100 == wf.estimates[0].sample);
  CU_ASSERT(0 == wf.estimates[0].time);
  CU_ASSERT(100 == wf.estimates[1].sample);
  CU_ASSERT(0 == wf.estimates[1].time);
  CU_ASSERT(100 == wf.estimates[2].sample);
  CU_ASSERT(0 == wf.estimates[2].time);
  CU_ASSERT(100 == ngtcp2_window_filter_get_best(&wf));

  /* A quarter of the window has passed without a better sample. */
  ngtcp2_window_filter_update(&wf, 90, 3);

  CU_ASSERT(100 == wf.estimates[0].sample);
  CU_ASSERT(0 == wf.estimates[0].time);
  CU_ASSERT(90 == wf.estimates[1].sample);
  CU_ASSERT(3 == wf.estimates[1].time);
  CU_ASSERT(90 == wf.estimates[2].sample);
  CU_ASSERT(3 == wf.estimates[2].time);
  CU_ASSERT(100 == ngtcp2_window_filter_get_best(&wf));

  /* A half of the window has passed without a better sample. */
  ngtcp2_window_filter_update(&wf, 80, 8);

  CU_ASSERT(100 == wf.estimates[0].sample);
  CU_ASSERT(0 == wf.estimates[0].time);
  CU_ASSERT(90 == wf.estimates[1].sample);
  CU_ASSERT(3 == wf.estimates[1].time);
  CU_ASSERT(80 == wf.estimates[2].sample);
  CU_ASSERT(8 == wf.estimates[2].time);
  CU_ASSERT(100 == ngtcp2_window_filter_get_best(&wf));

  /* The best sample has expired. */
  ngtcp2_window_filter_update(&wf, 70, 9);

  CU_ASSERT(90 == wf.estimates[0].sample);
  CU_ASSERT(3 == wf.estimates[0].time);
  CU_ASSERT(80 == wf.estimates[1].sample);
  CU_ASSERT(8 == wf.estimates[1].time);
  CU_ASSERT(70 == wf.estimates[2].sample);
  CU_ASSERT(9 == wf.estimates[2].time);
  CU_ASSERT(90 == ngtcp2_window_filter_get_best(&wf));

  /* Update third estimate. */
  ngtcp2_window_filter_update(&wf, 75, 9);

  CU_ASSERT(90 == wf.estimates[0].sample);
  CU_ASSERT(3 == wf.estimates[0].time);
  CU_ASSERT(80 == wf.estimates[1].sample);
  CU_ASSERT(8 == wf.estimates[1].time);
  CU_ASSERT(75 == wf.estimates[2].sample);
  CU_ASSERT(9 == wf.estimates[2].time);
  CU_ASSERT(90 == ngtcp2_window_filter_get_best(&wf));

  /* Update second and third estimates. */
  ngtcp2_window_filter_update(&wf, 85, 9);

  CU_ASSERT(90 == wf.estimates[0].sample);
  CU_ASSERT(3 == wf.estimates[0].time);
  CU_ASSERT(85 == wf.estimates[1].sample);
  CU_ASSERT(9 == wf.estimates[1].time);
  CU_ASSERT(85 == wf.estimates[2].sample);
  CU_ASSERT(9 == wf.estimates[2].time);
  CU_ASSERT(90 == ngtcp2_window_filter_get_best(&wf));

  /* Update all estimates because new sample is the best estimate. */
  ngtcp2_window_filter_update(&wf, 100, 10);

  CU_ASSERT(100 == wf.estimates[0].sample);
  CU_ASSERT(10 == wf.estimates[0].time);
  CU_ASSERT(100 == wf.estimates[1].sample);
  CU_ASSERT(10 == wf.estimates[1].time);
  CU_ASSERT(100 == wf.estimates[2].sample);
  CU_ASSERT(10 == wf.estimates[2].time);
  CU_ASSERT(100 == ngtcp2_window_filter_get_best(&wf));
}
