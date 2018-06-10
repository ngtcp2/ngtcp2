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
#include "ngtcp2_ksl_test.h"

#include <CUnit/CUnit.h>

#include "ngtcp2_ksl.h"
#include "ngtcp2_test_helper.h"

static int less(int64_t lhs, int64_t rhs) { return lhs < rhs; }

void test_ngtcp2_ksl_insert(void) {
  static const int64_t keys[] = {10, 3,  8, 11, 16, 12, 1, 5, 4,
                                 0,  13, 7, 9,  2,  14, 6, 15};
  ngtcp2_ksl ksl;
  ngtcp2_mem *mem = ngtcp2_mem_default();
  size_t i;
  ngtcp2_ksl_it it;
  int64_t key;

  ngtcp2_ksl_init(&ksl, less, INT64_MAX, mem);

  for (i = 0; i < arraylen(keys); ++i) {
    ngtcp2_ksl_insert(&ksl, NULL, keys[i], NULL);
    it = ngtcp2_ksl_lower_bound(&ksl, keys[i]);

    CU_ASSERT(keys[i] == ngtcp2_ksl_it_key(&it));
  }

  for (i = 0; i < arraylen(keys); ++i) {
    ngtcp2_ksl_remove(&ksl, keys[i]);
    it = ngtcp2_ksl_lower_bound(&ksl, keys[i]);
    key = ngtcp2_ksl_it_key(&it);

    CU_ASSERT(keys[i] < key);
  }

  ngtcp2_ksl_free(&ksl);

  /* check the case that the right end range is removed */
  ngtcp2_ksl_init(&ksl, less, INT64_MAX, mem);

  for (i = 0; i < 16; ++i) {
    ngtcp2_ksl_insert(&ksl, NULL, (int64_t)i, NULL);
  }

  /* Removing 7 requires relocation.  It merges 2 nodes into 1 node
     which becomes new head and a leaf. */
  it = ngtcp2_ksl_remove(&ksl, 7);

  CU_ASSERT(8 == ngtcp2_ksl_it_key(&it));

  it = ngtcp2_ksl_lower_bound(&ksl, 8);

  CU_ASSERT(8 == ngtcp2_ksl_it_key(&it));
  CU_ASSERT(8 == ksl.head->nodes[0].key);

  ngtcp2_ksl_free(&ksl);

  /* Check the case that the relocation merges 2 nodes into 1 node
     which is head, but not a leaf. */
  ngtcp2_ksl_init(&ksl, less, INT64_MAX, mem);

  for (i = 0; i < 120; ++i) {
    ngtcp2_ksl_insert(&ksl, NULL, (int64_t)i, NULL);
  }

  it = ngtcp2_ksl_remove(&ksl, 63);

  CU_ASSERT(64 == ngtcp2_ksl_it_key(&it));

  it = ngtcp2_ksl_lower_bound(&ksl, 63);

  CU_ASSERT(64 == ngtcp2_ksl_it_key(&it));

  ngtcp2_ksl_free(&ksl);

  /* check merge node (head) */
  ngtcp2_ksl_init(&ksl, less, INT64_MAX, mem);

  for (i = 0; i < 15; ++i) {
    ngtcp2_ksl_insert(&ksl, NULL, (int64_t)i, NULL);
  }

  /* Removing these 2 nodes kicks merging 2 nodes under head */
  ngtcp2_ksl_remove(&ksl, 6);
  ngtcp2_ksl_remove(&ksl, 7);

  CU_ASSERT(14 == ksl.head->n);

  ngtcp2_ksl_free(&ksl);

  /* check merge node (non head) */
  ngtcp2_ksl_init(&ksl, less, INT64_MAX, mem);

  for (i = 0; i < 15 + 8; ++i) {
    ngtcp2_ksl_insert(&ksl, NULL, (int64_t)i, NULL);
  }

  /* Removing these 2 nodes kicks merging 2 nodes */
  ngtcp2_ksl_remove(&ksl, 6);
  ngtcp2_ksl_remove(&ksl, 5);

  CU_ASSERT(2 == ksl.head->n);
  CU_ASSERT(14 == ksl.head->nodes[0].blk->n);
  CU_ASSERT(8 == ksl.head->nodes[1].blk->n);

  ngtcp2_ksl_free(&ksl);
}
