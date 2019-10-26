/*
 * ngtcp2
 *
 * Copyright (c) 2019 ngtcp2 contributors
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
#include "ngtcp2_pipeack_test.h"

#include <CUnit/CUnit.h>

#include "ngtcp2_pipeack.h"
#include "ngtcp2_test_helper.h"

void test_ngtcp2_pipeack_update(void) {
  ngtcp2_pipeack pipeack;
  ngtcp2_pipeack_sample *sample;
  ngtcp2_tstamp ts;
  ngtcp2_rcvry_stat rcs;

  rcs.smoothed_rtt = 50 * NGTCP2_MILLISECONDS;

  ts = 9 * NGTCP2_MILLISECONDS;
  ngtcp2_pipeack_init(&pipeack, ts);

  CU_ASSERT(1 == pipeack.len);
  CU_ASSERT(UINT64_MAX == pipeack.value);

  /* after 1 RTT */
  ts = 9 * NGTCP2_MILLISECONDS + 50 * NGTCP2_MILLISECONDS;
  ngtcp2_pipeack_update(&pipeack, 6000, &rcs, ts);

  CU_ASSERT(1 == pipeack.len);

  sample = &pipeack.samples[pipeack.pos];

  CU_ASSERT(6000 == sample->value);

  /* after another 1 RTT */
  ts = 9 * NGTCP2_MILLISECONDS + 50 * NGTCP2_MILLISECONDS * 2;
  ngtcp2_pipeack_update(&pipeack, 999, &rcs, ts);

  CU_ASSERT(1 == pipeack.len);

  sample = &pipeack.samples[pipeack.pos];

  CU_ASSERT(6000 == sample->value);

  /* pipeACK measurement period is over */
  /* 150ms is passed */
  ts = 9 * NGTCP2_MILLISECONDS + 250 * NGTCP2_MILLISECONDS;
  ngtcp2_pipeack_update(&pipeack, 3000, &rcs, ts);

  CU_ASSERT(2 == pipeack.len);

  ngtcp2_pipeack_update_value(&pipeack, &rcs, ts);

  CU_ASSERT(2 == pipeack.len);
  CU_ASSERT(6000 == pipeack.value);

  /* another pipeACK measurement period is over */
  /* 250ms is passed */
  ts = 9 * NGTCP2_MILLISECONDS + 250 * NGTCP2_MILLISECONDS * 2;
  ngtcp2_pipeack_update(&pipeack, 1500, &rcs, ts);

  CU_ASSERT(3 == pipeack.len);

  ngtcp2_pipeack_update_value(&pipeack, &rcs, ts);

  CU_ASSERT(3 == pipeack.len);
  CU_ASSERT(6000 == pipeack.value);

  /* yet another pipeACK measurement period is over */
  /* 250ms is passed */
  ts = 9 * NGTCP2_MILLISECONDS + 250 * NGTCP2_MILLISECONDS * 3;
  ngtcp2_pipeack_update(&pipeack, 9000, &rcs, ts);

  CU_ASSERT(4 == pipeack.len);

  ngtcp2_pipeack_update_value(&pipeack, &rcs, ts);

  CU_ASSERT(4 == pipeack.len);
  CU_ASSERT(6000 == pipeack.value);

  /* Drop the first measurement. */
  ts = 9 * NGTCP2_MILLISECONDS + 250 * NGTCP2_MILLISECONDS * 4;
  ngtcp2_pipeack_update_value(&pipeack, &rcs, ts);

  CU_ASSERT(3 == pipeack.len);
  CU_ASSERT(1800 == pipeack.value);

  /* Measurement which is not completed does not participate pipeACK
     computation. */
  ts = 0;
  ngtcp2_pipeack_init(&pipeack, ts);
  ngtcp2_pipeack_update(&pipeack, 1000, &rcs, 10 * NGTCP2_MILLISECONDS);
  ngtcp2_pipeack_update_value(&pipeack, &rcs, ts);

  CU_ASSERT(1 == pipeack.len);
  CU_ASSERT(UINT64_MAX == pipeack.value);
}
