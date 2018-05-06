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
#include "ngtcp2_psl_test.h"

#include <CUnit/CUnit.h>

#include "ngtcp2_psl.h"
#include "ngtcp2_test_helper.h"

void test_ngtcp2_psl_insert(void) {
  static const ngtcp2_range keys[] = {
      {10, 11}, {3, 4}, {8, 9},   {11, 12}, {16, 17}, {12, 13},
      {1, 2},   {5, 6}, {4, 5},   {0, 1},   {13, 14}, {7, 8},
      {9, 10},  {2, 3}, {14, 15}, {6, 7},   {15, 16}};
  ngtcp2_psl psl;
  ngtcp2_mem *mem = ngtcp2_mem_default();
  size_t i;
  const ngtcp2_range *pr;
  ngtcp2_range r;
  ngtcp2_psl_it it;

  ngtcp2_psl_init(&psl, mem);

  for (i = 0; i < arraylen(keys); ++i) {
    ngtcp2_psl_insert(&psl, NULL, &keys[i], NULL);
    it = ngtcp2_psl_lower_bound(&psl, &keys[i]);

    CU_ASSERT(ngtcp2_range_eq(&keys[i], ngtcp2_psl_it_range(&it)));
  }

  for (i = 0; i < arraylen(keys); ++i) {
    ngtcp2_psl_remove(&psl, &keys[i]);
    it = ngtcp2_psl_lower_bound(&psl, &keys[i]);
    pr = ngtcp2_psl_it_range(&it);

    CU_ASSERT(keys[i].end <= pr->begin);
  }

  ngtcp2_psl_free(&psl);

  /* check the case that the right end range is removed */
  ngtcp2_psl_init(&psl, mem);

  for (i = 0; i < 16; ++i) {
    ngtcp2_range_init(&r, i, i + 1);
    ngtcp2_psl_insert(&psl, NULL, &r, NULL);
  }

  /* Removing [7, 8) requires relocation */
  ngtcp2_range_init(&r, 7, 8);
  it = ngtcp2_psl_remove(&psl, &r);
  pr = ngtcp2_psl_it_range(&it);

  CU_ASSERT(8 == pr->begin);
  CU_ASSERT(9 == pr->end);

  it = ngtcp2_psl_lower_bound(&psl, &r);
  pr = ngtcp2_psl_it_range(&it);

  CU_ASSERT(8 == pr->begin);
  CU_ASSERT(9 == pr->end);

  pr = &psl.head->nodes[0].range;

  CU_ASSERT(6 == pr->begin);
  CU_ASSERT(7 == pr->end);

  ngtcp2_psl_free(&psl);

  /* check merge node (head) */
  ngtcp2_psl_init(&psl, mem);

  for (i = 0; i < 15; ++i) {
    ngtcp2_range_init(&r, i, i + 1);
    ngtcp2_psl_insert(&psl, NULL, &r, NULL);
  }

  /* Removing these 2 nodes kicks merging 2 nodes under head */
  ngtcp2_range_init(&r, 6, 7);
  ngtcp2_psl_remove(&psl, &r);

  ngtcp2_range_init(&r, 5, 6);
  ngtcp2_psl_remove(&psl, &r);

  CU_ASSERT(14 == psl.head->n);

  ngtcp2_psl_free(&psl);

  /* check merge node (non head) */
  ngtcp2_psl_init(&psl, mem);

  for (i = 0; i < 15 + 8; ++i) {
    ngtcp2_range_init(&r, i, i + 1);
    ngtcp2_psl_insert(&psl, NULL, &r, NULL);
  }

  /* Removing these 2 nodes kicks merging 2 nodes */
  ngtcp2_range_init(&r, 6, 7);
  ngtcp2_psl_remove(&psl, &r);

  ngtcp2_range_init(&r, 5, 6);
  ngtcp2_psl_remove(&psl, &r);

  CU_ASSERT(2 == psl.head->n);
  CU_ASSERT(14 == psl.head->nodes[0].blk->n);
  CU_ASSERT(8 == psl.head->nodes[1].blk->n);

  ngtcp2_psl_free(&psl);
}
