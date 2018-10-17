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

#include <CUnit/CUnit.h>

#include "ngtcp2_gaptr.h"
#include "ngtcp2_test_helper.h"
#include "ngtcp2_mem.h"

void test_ngtcp2_gaptr_push(void) {
  ngtcp2_gaptr gaptr;
  ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_psl_it it;
  const ngtcp2_range *key;
  int rv;
  size_t i;

  ngtcp2_gaptr_init(&gaptr, mem);

  it = ngtcp2_psl_begin(&gaptr.gap);
  key = ngtcp2_psl_it_range(&it);

  CU_ASSERT(0 == key->begin);
  CU_ASSERT(UINT64_MAX == key->end);

  rv = ngtcp2_gaptr_push(&gaptr, 0, 1);

  CU_ASSERT(0 == rv);

  it = ngtcp2_psl_begin(&gaptr.gap);
  key = ngtcp2_psl_it_range(&it);

  CU_ASSERT(1 == key->begin);
  CU_ASSERT(UINT64_MAX == key->end);

  rv = ngtcp2_gaptr_push(&gaptr, 12389, 133);

  CU_ASSERT(0 == rv);

  it = ngtcp2_psl_begin(&gaptr.gap);
  key = ngtcp2_psl_it_range(&it);

  CU_ASSERT(1 == key->begin);
  CU_ASSERT(12389 == key->end);

  ngtcp2_psl_it_next(&it);
  key = ngtcp2_psl_it_range(&it);

  CU_ASSERT(12389 + 133 == key->begin);
  CU_ASSERT(UINT64_MAX == key->end);

  for (i = 0; i < 2; ++i) {
    rv = ngtcp2_gaptr_push(&gaptr, 1, 12389);

    CU_ASSERT(0 == rv);

    it = ngtcp2_psl_begin(&gaptr.gap);
    key = ngtcp2_psl_it_range(&it);

    CU_ASSERT(12389 + 133 == key->begin);
    CU_ASSERT(UINT64_MAX == key->end);
  }

  rv = ngtcp2_gaptr_push(&gaptr, 12389 + 133 - 1, 2);

  CU_ASSERT(0 == rv);

  it = ngtcp2_psl_begin(&gaptr.gap);
  key = ngtcp2_psl_it_range(&it);

  CU_ASSERT(12389 + 133 + 1 == key->begin);
  CU_ASSERT(UINT64_MAX == key->end);

  ngtcp2_gaptr_free(&gaptr);
}
