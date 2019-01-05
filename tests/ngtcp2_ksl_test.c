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

static int less(const ngtcp2_ksl_key *lhs, const ngtcp2_ksl_key *rhs) {
  return lhs->i < rhs->i;
}

static ngtcp2_ksl_key inf_key = {INT64_MAX};

void test_ngtcp2_ksl_insert(void) {
  static const int64_t keys[] = {10, 3,  8, 11, 16, 12, 1, 5, 4,
                                 0,  13, 7, 9,  2,  14, 6, 15};
  ngtcp2_ksl ksl;
  ngtcp2_mem *mem = ngtcp2_mem_default();
  size_t i;
  ngtcp2_ksl_it it;
  ngtcp2_ksl_key key;

  ngtcp2_ksl_init(&ksl, less, &inf_key, mem);

  for (i = 0; i < arraylen(keys); ++i) {
    ngtcp2_ksl_insert(&ksl, NULL, (const ngtcp2_ksl_key *)&keys[i], NULL);
    it = ngtcp2_ksl_lower_bound(&ksl, (const ngtcp2_ksl_key *)&keys[i]);

    CU_ASSERT(keys[i] == ngtcp2_ksl_it_key(&it).i);
  }

  for (i = 0; i < arraylen(keys); ++i) {
    ngtcp2_ksl_remove(&ksl, NULL, (const ngtcp2_ksl_key *)&keys[i]);
    it = ngtcp2_ksl_lower_bound(&ksl, (const ngtcp2_ksl_key *)&keys[i]);
    key = ngtcp2_ksl_it_key(&it);

    CU_ASSERT(keys[i] < key.i);
  }

  ngtcp2_ksl_free(&ksl);

  /* check the case that the right end range is removed */
  ngtcp2_ksl_init(&ksl, less, &inf_key, mem);

  for (i = 0; i < 16; ++i) {
    ngtcp2_ksl_insert(&ksl, NULL, ngtcp2_ksl_key_i(&key, (int64_t)i), NULL);
  }

  /* Removing 7 requires relocation.  It merges 2 nodes into 1 node
     which becomes new head and a leaf. */
  ngtcp2_ksl_remove(&ksl, &it, ngtcp2_ksl_key_i(&key, 7));

  CU_ASSERT(8 == ngtcp2_ksl_it_key(&it).i);

  it = ngtcp2_ksl_lower_bound(&ksl, ngtcp2_ksl_key_i(&key, 8));

  CU_ASSERT(8 == ngtcp2_ksl_it_key(&it).i);
  CU_ASSERT(8 == ksl.head->nodes[0].key.i);

  ngtcp2_ksl_free(&ksl);

  /* Check the case that the relocation merges 2 nodes into 1 node
     which is head, but not a leaf. */
  ngtcp2_ksl_init(&ksl, less, &inf_key, mem);

  for (i = 0; i < 120; ++i) {
    ngtcp2_ksl_insert(&ksl, NULL, ngtcp2_ksl_key_i(&key, (int64_t)i), NULL);
  }

  ngtcp2_ksl_remove(&ksl, &it, ngtcp2_ksl_key_i(&key, 63));

  CU_ASSERT(64 == ngtcp2_ksl_it_key(&it).i);

  it = ngtcp2_ksl_lower_bound(&ksl, ngtcp2_ksl_key_i(&key, 63));

  CU_ASSERT(64 == ngtcp2_ksl_it_key(&it).i);

  ngtcp2_ksl_free(&ksl);

  /* check merge node (head) */
  ngtcp2_ksl_init(&ksl, less, &inf_key, mem);

  for (i = 0; i < 15; ++i) {
    ngtcp2_ksl_insert(&ksl, NULL, ngtcp2_ksl_key_i(&key, (int64_t)i), NULL);
  }

  /* Removing these 3 nodes kicks merging 2 nodes under head */
  ngtcp2_ksl_remove(&ksl, NULL, ngtcp2_ksl_key_i(&key, 6));
  ngtcp2_ksl_remove(&ksl, NULL, ngtcp2_ksl_key_i(&key, 7));
  ngtcp2_ksl_remove(&ksl, NULL, ngtcp2_ksl_key_i(&key, 8));

  CU_ASSERT(13 == ksl.head->n);

  ngtcp2_ksl_free(&ksl);

  /* check merge node (non head) */
  ngtcp2_ksl_init(&ksl, less, &inf_key, mem);

  for (i = 0; i < 15 + 8; ++i) {
    ngtcp2_ksl_insert(&ksl, NULL, ngtcp2_ksl_key_i(&key, (int64_t)i), NULL);
  }

  /* Removing these 3 nodes kicks merging 2 nodes */
  ngtcp2_ksl_remove(&ksl, NULL, ngtcp2_ksl_key_i(&key, 6));
  ngtcp2_ksl_remove(&ksl, NULL, ngtcp2_ksl_key_i(&key, 5));
  ngtcp2_ksl_remove(&ksl, NULL, ngtcp2_ksl_key_i(&key, 8));

  CU_ASSERT(2 == ksl.head->n);
  CU_ASSERT(13 == ksl.head->nodes[0].blk->n);
  CU_ASSERT(8 == ksl.head->nodes[1].blk->n);

  ngtcp2_ksl_free(&ksl);

  /* Iterate backwards */
  ngtcp2_ksl_init(&ksl, less, &inf_key, mem);

  /* split nodes */
  for (i = 0; i < 100; ++i) {
    ngtcp2_ksl_insert(&ksl, NULL, ngtcp2_ksl_key_i(&key, (int64_t)i), NULL);
  }

  /* merge nodes */
  for (i = 0; i < 50; ++i) {
    ngtcp2_ksl_remove(&ksl, NULL, ngtcp2_ksl_key_i(&key, (int64_t)i));
  }

  i = 99;
  for (it = ngtcp2_ksl_end(&ksl); !ngtcp2_ksl_it_begin(&it);) {
    ngtcp2_ksl_it_prev(&it);

    CU_ASSERT((int64_t)i-- == ngtcp2_ksl_it_key(&it).i);
  }

  /* head only */
  for (i = 50; i < 88; ++i) {
    ngtcp2_ksl_remove(&ksl, NULL, ngtcp2_ksl_key_i(&key, (int64_t)i));
  }

  i = 99;
  for (it = ngtcp2_ksl_end(&ksl); !ngtcp2_ksl_it_begin(&it);) {
    ngtcp2_ksl_it_prev(&it);

    CU_ASSERT((int64_t)i-- == ngtcp2_ksl_it_key(&it).i);
  }

  ngtcp2_ksl_free(&ksl);

  /* Split head on removal */
  ngtcp2_ksl_init(&ksl, less, &inf_key, mem);

  for (i = 0; i < 7609; ++i) {
    ngtcp2_ksl_insert(&ksl, NULL, ngtcp2_ksl_key_i(&key, (int64_t)i), NULL);
  }

  ngtcp2_ksl_remove(&ksl, NULL, ngtcp2_ksl_key_i(&key, 999));

  CU_ASSERT(2 == ksl.head->n);

  ngtcp2_ksl_free(&ksl);

  /* Split block which is not head on removal */
  ngtcp2_ksl_init(&ksl, less, &inf_key, mem);

  for (i = 0; i < 22; ++i) {
    ngtcp2_ksl_insert(&ksl, NULL, ngtcp2_ksl_key_i(&key, (int64_t)i), NULL);
  }

  CU_ASSERT(2 == ksl.head->n);

  ngtcp2_ksl_remove(&ksl, NULL, ngtcp2_ksl_key_i(&key, 21));

  CU_ASSERT(3 == ksl.head->n);

  ngtcp2_ksl_free(&ksl);

  /* shift_right */
  ngtcp2_ksl_init(&ksl, less, &inf_key, mem);

  for (i = 1; i < 1500; i += 100) {
    ngtcp2_ksl_insert(&ksl, NULL, ngtcp2_ksl_key_i(&key, (int64_t)i), NULL);
  }

  ngtcp2_ksl_remove(&ksl, NULL, ngtcp2_ksl_key_i(&key, 1401));
  ngtcp2_ksl_remove(&ksl, NULL, ngtcp2_ksl_key_i(&key, 1301));

  CU_ASSERT(701 == ksl.head->nodes[1].blk->nodes[0].key.i);

  ngtcp2_ksl_free(&ksl);

  /* shift_left */
  ngtcp2_ksl_init(&ksl, less, &inf_key, mem);

  for (i = 0; i < 15; ++i) {
    ngtcp2_ksl_insert(&ksl, NULL, ngtcp2_ksl_key_i(&key, (int64_t)i), NULL);
  }

  ngtcp2_ksl_remove(&ksl, NULL, ngtcp2_ksl_key_i(&key, 6));
  ngtcp2_ksl_remove(&ksl, NULL, ngtcp2_ksl_key_i(&key, 5));

  CU_ASSERT(8 ==
            ksl.head->nodes[0].blk->nodes[ksl.head->nodes[0].blk->n - 1].key.i);

  ngtcp2_ksl_free(&ksl);

  /* Merge 2 nodes into head which is not a leaf on relocation */
  ngtcp2_ksl_init(&ksl, less, &inf_key, mem);

  for (i = 0; i < 130; ++i) {
    ngtcp2_ksl_insert(&ksl, NULL, ngtcp2_ksl_key_i(&key, (int64_t)i), NULL);
  }

  for (i = 116; i <= 129; ++i) {
    ngtcp2_ksl_remove(&ksl, NULL, ngtcp2_ksl_key_i(&key, (int64_t)i));
  }

  CU_ASSERT(2 == ksl.head->n);

  ngtcp2_ksl_remove(&ksl, NULL, ngtcp2_ksl_key_i(&key, 55));

  CU_ASSERT(14 == ksl.head->n);

  ngtcp2_ksl_free(&ksl);
}

void test_ngtcp2_ksl_clear(void) {
  ngtcp2_ksl ksl;
  ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_ksl_it it;
  size_t i;
  ngtcp2_ksl_key key;

  ngtcp2_ksl_init(&ksl, less, &inf_key, mem);

  for (i = 0; i < 100; ++i) {
    ngtcp2_ksl_insert(&ksl, NULL, ngtcp2_ksl_key_i(&key, (int64_t)i), NULL);
  }

  ngtcp2_ksl_clear(&ksl);

  CU_ASSERT(0 == ngtcp2_ksl_len(&ksl));

  it = ngtcp2_ksl_begin(&ksl);

  CU_ASSERT(ngtcp2_ksl_it_end(&it));

  it = ngtcp2_ksl_end(&ksl);

  CU_ASSERT(ngtcp2_ksl_it_end(&it));

  ngtcp2_ksl_free(&ksl);
}
