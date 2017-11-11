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

#include <CUnit/CUnit.h>

#include "ngtcp2_idtr.h"
#include "ngtcp2_test_helper.h"
#include "ngtcp2_mem.h"

static uint64_t stream_id_from_id(uint64_t id) { return id * 4; }

void test_ngtcp2_idtr_open(void) {
  ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_idtr idtr;
  int rv;
  ngtcp2_idtr_gap *g;

  rv = ngtcp2_idtr_init(&idtr, 0, mem);

  CU_ASSERT(0 == rv);

  rv = ngtcp2_idtr_open(&idtr, stream_id_from_id(0));

  CU_ASSERT(0 == rv);
  CU_ASSERT(1 == idtr.gap->range.begin);
  CU_ASSERT(UINT64_MAX == idtr.gap->range.end);
  CU_ASSERT(NULL == idtr.gap->next);

  rv = ngtcp2_idtr_open(&idtr, stream_id_from_id(1000000007));

  CU_ASSERT(0 == rv);

  g = idtr.gap;

  CU_ASSERT(1 == idtr.gap->range.begin);
  CU_ASSERT(1000000007 == g->range.end);

  g = g->next;

  CU_ASSERT(1000000008 == g->range.begin);
  CU_ASSERT(UINT64_MAX == g->range.end);
  CU_ASSERT(NULL == g->next);

  rv = ngtcp2_idtr_open(&idtr, stream_id_from_id(0));

  CU_ASSERT(NGTCP2_ERR_STREAM_IN_USE == rv);

  rv = ngtcp2_idtr_open(&idtr, stream_id_from_id(1000000007));

  CU_ASSERT(NGTCP2_ERR_STREAM_IN_USE == rv);

  ngtcp2_idtr_free(&idtr);
}
