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

#include <stdio.h>

#include "ngtcp2_ksl.h"
#include "ngtcp2_test_helper.h"

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_ksl_insert),
  munit_void_test(test_ngtcp2_ksl_clear),
  munit_void_test(test_ngtcp2_ksl_range),
  munit_void_test(test_ngtcp2_ksl_update_key_range),
  munit_void_test(test_ngtcp2_ksl_dup),
  munit_void_test(test_ngtcp2_ksl_remove_hint),
  munit_test_end(),
};

const MunitSuite ksl_suite = {
  "/ksl", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE,
};

static int less(const ngtcp2_ksl_key *lhs, const ngtcp2_ksl_key *rhs) {
  return *(int64_t *)lhs < *(int64_t *)rhs;
}

void test_ngtcp2_ksl_insert(void) {
  static const int64_t keys[] = {10, 3,  8, 11, 16, 12, 1, 5, 4,
                                 0,  13, 7, 9,  2,  14, 6, 15};
  ngtcp2_ksl ksl;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  size_t i;
  ngtcp2_ksl_it it;
  int64_t k;

  ngtcp2_ksl_init(&ksl, less, sizeof(int64_t), mem);

  for (i = 0; i < ngtcp2_arraylen(keys); ++i) {
    assert_int(0, ==, ngtcp2_ksl_insert(&ksl, NULL, &keys[i], NULL));
    it = ngtcp2_ksl_lower_bound(&ksl, &keys[i]);

    assert_int64(keys[i], ==, *(int64_t *)ngtcp2_ksl_it_key(&it));
  }

  for (i = 0; i < ngtcp2_arraylen(keys); ++i) {
    assert_int(0, ==, ngtcp2_ksl_remove(&ksl, NULL, &keys[i]));
    it = ngtcp2_ksl_lower_bound(&ksl, &keys[i]);
    if (!ngtcp2_ksl_it_end(&it)) {
      assert_int64(keys[i], <, *(int64_t *)ngtcp2_ksl_it_key(&it));
    }
  }

  ngtcp2_ksl_free(&ksl);

  /* check the case that the right end range is removed */
  ngtcp2_ksl_init(&ksl, less, sizeof(int64_t), mem);

  for (i = 0; i < 32; ++i) {
    k = (int64_t)i;
    assert_int(0, ==, ngtcp2_ksl_insert(&ksl, NULL, &k, NULL));
  }

  /* Removing 15 which is the last node in a blk. */
  k = 15;
  assert_int(0, ==, ngtcp2_ksl_remove(&ksl, &it, &k));

  assert_int64(16, ==, *(int64_t *)ngtcp2_ksl_it_key(&it));

  /* Insert 15 again works */
  assert_int(0, ==, ngtcp2_ksl_insert(&ksl, NULL, &k, NULL));

  k = 15;
  it = ngtcp2_ksl_lower_bound(&ksl, &k);

  assert_int64(15, ==, *(int64_t *)ngtcp2_ksl_it_key(&it));

  ngtcp2_ksl_free(&ksl);

  /* Check the case that the intermediate node contains smaller key
     than ancestor node.  Make sure that inserting key larger than
     that still works.*/
  ngtcp2_ksl_init(&ksl, less, sizeof(int64_t), mem);

  for (i = 0; i < 760; ++i) {
    k = (int64_t)i;
    assert_int(0, ==, ngtcp2_ksl_insert(&ksl, NULL, &k, NULL));
  }

  k = 255;
  assert_int(0, ==, ngtcp2_ksl_remove(&ksl, NULL, &k));
  k = 254;
  assert_int(0, ==, ngtcp2_ksl_remove(&ksl, NULL, &k));
  k = 253;
  assert_int(0, ==, ngtcp2_ksl_remove(&ksl, NULL, &k));

  k = 253;
  assert_int(0, ==, ngtcp2_ksl_insert(&ksl, NULL, &k, NULL));
  it = ngtcp2_ksl_lower_bound(&ksl, &k);

  assert_int64(253, ==, *(int64_t *)ngtcp2_ksl_it_key(&it));

  ngtcp2_ksl_free(&ksl);

  /* check merge node (head) */
  ngtcp2_ksl_init(&ksl, less, sizeof(int64_t), mem);

  for (i = 0; i < 32; ++i) {
    k = (int64_t)i;
    assert_int(0, ==, ngtcp2_ksl_insert(&ksl, NULL, &k, NULL));
  }

  /* Removing these 3 nodes kicks merging 2 nodes under head */
  k = 15;
  assert_int(0, ==, ngtcp2_ksl_remove(&ksl, NULL, &k));
  k = 14;
  assert_int(0, ==, ngtcp2_ksl_remove(&ksl, NULL, &k));
  k = 13;
  assert_int(0, ==, ngtcp2_ksl_remove(&ksl, NULL, &k));

  assert_size(29, ==, ksl.head->n);

  ngtcp2_ksl_free(&ksl);

  /* check merge node (non head) */
  ngtcp2_ksl_init(&ksl, less, sizeof(int64_t), mem);

  for (i = 0; i < 32 + 18; ++i) {
    k = (int64_t)i;
    assert_int(0, ==, ngtcp2_ksl_insert(&ksl, NULL, &k, NULL));
  }

  /* Removing these 3 nodes kicks merging 2 nodes */
  k = 15;
  assert_int(0, ==, ngtcp2_ksl_remove(&ksl, NULL, &k));
  k = 14;
  assert_int(0, ==, ngtcp2_ksl_remove(&ksl, NULL, &k));
  k = 13;
  assert_int(0, ==, ngtcp2_ksl_remove(&ksl, NULL, &k));

  assert_size(2, ==, ksl.head->n);
  assert_size(29, ==, ngtcp2_ksl_nth_node(&ksl, ksl.head, 0)->blk->n);
  assert_size(18, ==, ngtcp2_ksl_nth_node(&ksl, ksl.head, 1)->blk->n);

  ngtcp2_ksl_free(&ksl);

  /* Iterate backwards */
  ngtcp2_ksl_init(&ksl, less, sizeof(int64_t), mem);

  /* split nodes */
  for (i = 0; i < 100; ++i) {
    k = (int64_t)i;
    assert_int(0, ==, ngtcp2_ksl_insert(&ksl, NULL, &k, NULL));
  }

  /* merge nodes */
  for (i = 0; i < 50; ++i) {
    k = (int64_t)i;
    assert_int(0, ==, ngtcp2_ksl_remove(&ksl, NULL, &k));
  }

  i = 99;
  for (it = ngtcp2_ksl_end(&ksl); !ngtcp2_ksl_it_begin(&it);) {
    ngtcp2_ksl_it_prev(&it);

    assert_int64((int64_t)i--, ==, *(int64_t *)ngtcp2_ksl_it_key(&it));
  }

  /* head only */
  for (i = 50; i < 88; ++i) {
    k = (int64_t)i;
    assert_int(0, ==, ngtcp2_ksl_remove(&ksl, NULL, &k));
  }

  i = 99;
  for (it = ngtcp2_ksl_end(&ksl); !ngtcp2_ksl_it_begin(&it);) {
    ngtcp2_ksl_it_prev(&it);

    assert_int64((int64_t)i--, ==, *(int64_t *)ngtcp2_ksl_it_key(&it));
  }

  ngtcp2_ksl_free(&ksl);
}

void test_ngtcp2_ksl_clear(void) {
  ngtcp2_ksl ksl;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_ksl_it it;
  size_t i;
  int64_t k;

  ngtcp2_ksl_init(&ksl, less, sizeof(int64_t), mem);

  for (i = 0; i < 100; ++i) {
    k = (int64_t)i;
    assert_int(0, ==, ngtcp2_ksl_insert(&ksl, NULL, &k, NULL));
  }

  ngtcp2_ksl_clear(&ksl);

  assert_size(0, ==, ngtcp2_ksl_len(&ksl));

  it = ngtcp2_ksl_begin(&ksl);

  assert_true(ngtcp2_ksl_it_end(&it));

  it = ngtcp2_ksl_end(&ksl);

  assert_true(ngtcp2_ksl_it_end(&it));

  ngtcp2_ksl_free(&ksl);
}

void test_ngtcp2_ksl_range(void) {
  static const ngtcp2_range keys[] = {
    {10, 11},   {3, 4},     {8, 9},     {11, 12},   {16, 17},   {12, 13},
    {1, 2},     {5, 6},     {4, 5},     {0, 1},     {13, 14},   {7, 8},
    {9, 10},    {2, 3},     {14, 15},   {6, 7},     {15, 16},   {17, 18},
    {18, 19},   {19, 20},   {20, 21},   {202, 203}, {203, 204}, {204, 205},
    {205, 206}, {206, 207}, {207, 208}, {208, 209}, {209, 210}, {210, 211},
    {211, 212}, {212, 213}, {213, 214}, {214, 215}, {215, 216}};
  ngtcp2_ksl ksl;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  size_t i;
  ngtcp2_range r;
  ngtcp2_ksl_it it;
  ngtcp2_ksl_node *node;

  ngtcp2_ksl_init(&ksl, ngtcp2_ksl_range_compar, sizeof(ngtcp2_range), mem);

  for (i = 0; i < ngtcp2_arraylen(keys); ++i) {
    assert_int(0, ==, ngtcp2_ksl_insert(&ksl, NULL, &keys[i], NULL));
    it = ngtcp2_ksl_lower_bound_compar(&ksl, &keys[i],
                                       ngtcp2_ksl_range_exclusive_compar);
    r = *(ngtcp2_range *)ngtcp2_ksl_it_key(&it);

    assert_true(ngtcp2_range_eq(&keys[i], &r));
  }

  for (i = 0; i < ngtcp2_arraylen(keys); ++i) {
    assert_int(0, ==, ngtcp2_ksl_remove(&ksl, NULL, &keys[i]));
    it = ngtcp2_ksl_lower_bound_compar(&ksl, &keys[i],
                                       ngtcp2_ksl_range_exclusive_compar);

    if (!ngtcp2_ksl_it_end(&it)) {
      r = *(ngtcp2_range *)ngtcp2_ksl_it_key(&it);

      assert_uint64(keys[i].end, <=, r.begin);
    }
  }

  ngtcp2_ksl_free(&ksl);

  /* check merge node (head) */
  ngtcp2_ksl_init(&ksl, ngtcp2_ksl_range_compar, sizeof(ngtcp2_range), mem);

  for (i = 0; i < 32; ++i) {
    ngtcp2_range_init(&r, i, i + 1);
    assert_int(0, ==, ngtcp2_ksl_insert(&ksl, NULL, &r, NULL));
  }

  /* Removing these 3 nodes kicks merging 2 nodes under head */
  ngtcp2_range_init(&r, 13, 14);
  assert_int(0, ==, ngtcp2_ksl_remove(&ksl, NULL, &r));

  ngtcp2_range_init(&r, 14, 15);
  assert_int(0, ==, ngtcp2_ksl_remove(&ksl, NULL, &r));

  ngtcp2_range_init(&r, 15, 16);
  assert_int(0, ==, ngtcp2_ksl_remove(&ksl, NULL, &r));

  assert_size(29, ==, ksl.head->n);

  ngtcp2_ksl_free(&ksl);

  /* check merge node (non head) */
  ngtcp2_ksl_init(&ksl, ngtcp2_ksl_range_compar, sizeof(ngtcp2_range), mem);

  for (i = 0; i < 32 + 18; ++i) {
    ngtcp2_range_init(&r, i, i + 1);
    assert_int(0, ==, ngtcp2_ksl_insert(&ksl, NULL, &r, NULL));
  }

  /* Removing these 3 nodes kicks merging 2 nodes */
  ngtcp2_range_init(&r, 13, 14);
  assert_int(0, ==, ngtcp2_ksl_remove(&ksl, NULL, &r));

  ngtcp2_range_init(&r, 14, 15);
  assert_int(0, ==, ngtcp2_ksl_remove(&ksl, NULL, &r));

  ngtcp2_range_init(&r, 15, 16);
  assert_int(0, ==, ngtcp2_ksl_remove(&ksl, NULL, &r));

  assert_size(2, ==, ksl.head->n);
  assert_size(29, ==, ngtcp2_ksl_nth_node(&ksl, ksl.head, 0)->blk->n);
  assert_size(18, ==, ngtcp2_ksl_nth_node(&ksl, ksl.head, 1)->blk->n);

  ngtcp2_ksl_free(&ksl);

  /* shift_left */
  ngtcp2_ksl_init(&ksl, ngtcp2_ksl_range_compar, sizeof(ngtcp2_range), mem);

  for (i = 1; i < 6400; i += 100) {
    ngtcp2_range_init(&r, i, i + 1);
    assert_int(0, ==, ngtcp2_ksl_insert(&ksl, NULL, &r, NULL));
  }

  ngtcp2_range_init(&r, 1501, 1502);
  assert_int(0, ==, ngtcp2_ksl_remove(&ksl, NULL, &r));
  ngtcp2_range_init(&r, 1401, 1402);
  assert_int(0, ==, ngtcp2_ksl_remove(&ksl, NULL, &r));

  r = *(ngtcp2_range *)(void *)ngtcp2_ksl_nth_node(
         &ksl, ngtcp2_ksl_nth_node(&ksl, ksl.head, 1)->blk, 0)
         ->key;

  assert_uint64(1701, ==, r.begin);

  ngtcp2_ksl_free(&ksl);

  /* shift_right */
  ngtcp2_ksl_init(&ksl, ngtcp2_ksl_range_compar, sizeof(ngtcp2_range), mem);

  for (i = 0; i < 32; ++i) {
    ngtcp2_range_init(&r, i, i + 1);
    assert_int(0, ==, ngtcp2_ksl_insert(&ksl, NULL, &r, NULL));
  }

  ngtcp2_range_init(&r, 17, 18);
  assert_int(0, ==, ngtcp2_ksl_remove(&ksl, NULL, &r));
  ngtcp2_range_init(&r, 16, 17);
  assert_int(0, ==, ngtcp2_ksl_remove(&ksl, NULL, &r));

  node = ngtcp2_ksl_nth_node(&ksl, ksl.head, 0);
  r = *(ngtcp2_range *)(void *)ngtcp2_ksl_nth_node(&ksl, node->blk,
                                                   node->blk->n - 1)
         ->key;

  assert_uint64(14, ==, r.begin);

  ngtcp2_ksl_free(&ksl);
}

void test_ngtcp2_ksl_update_key_range(void) {
  static ngtcp2_range ranges[] = {
    {0, 5},     {10, 15},   {20, 25},   {30, 35},   {40, 45},   {50, 55},
    {60, 65},   {70, 75},   {80, 85},   {90, 95},   {100, 105}, {110, 115},
    {120, 125}, {130, 135}, {140, 145}, {150, 155}, {160, 165}, {170, 175}};
  ngtcp2_ksl ksl;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  size_t i;
  ngtcp2_range r;
  ngtcp2_ksl_it it;

  ngtcp2_ksl_init(&ksl, ngtcp2_ksl_range_compar, sizeof(ngtcp2_range), mem);

  for (i = 0; i < ngtcp2_arraylen(ranges); ++i) {
    assert_int(0, ==, ngtcp2_ksl_insert(&ksl, NULL, &ranges[i], NULL));
  }

  r.begin = 70;
  r.end = 72;
  ngtcp2_ksl_update_key(&ksl, &ranges[7], &r);

  r.begin = 73;
  r.end = 74;
  assert_int(0, ==, ngtcp2_ksl_insert(&ksl, NULL, &r, NULL));

  r.begin = 74;
  r.end = 75;
  assert_int(0, ==, ngtcp2_ksl_insert(&ksl, NULL, &r, NULL));

  r.begin = 74;
  r.end = 75;
  it =
    ngtcp2_ksl_lower_bound_compar(&ksl, &r, ngtcp2_ksl_range_exclusive_compar);

  r = *(ngtcp2_range *)ngtcp2_ksl_it_key(&it);

  assert_uint64(74, ==, r.begin);
  assert_uint64(75, ==, r.end);

  ngtcp2_ksl_free(&ksl);
}

static void shuffle(int64_t *a, size_t n) {
  size_t i, j;
  int64_t t;

  for (i = n - 1; i >= 1; --i) {
    j = (size_t)((double)(i + 1) * rand() / (RAND_MAX + 1.0));
    t = a[j];
    a[j] = a[i];
    a[i] = t;
  }
}

void test_ngtcp2_ksl_dup(void) {
  static int64_t keys[16000];
  size_t i, j;
  ngtcp2_ksl ksl;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_ksl_it it;

  for (i = 0; i < ngtcp2_arraylen(keys); ++i) {
    keys[i] = (int64_t)i;
  }

  for (j = 0; j < 10; ++j) {
    ngtcp2_ksl_init(&ksl, less, sizeof(int64_t), mem);

    shuffle(keys, ngtcp2_arraylen(keys));

    for (i = 0; i < ngtcp2_arraylen(keys); ++i) {
      assert_int(0, ==, ngtcp2_ksl_insert(&ksl, NULL, &keys[i], NULL));
      assert_int(NGTCP2_ERR_INVALID_ARGUMENT, ==,
                 ngtcp2_ksl_insert(&ksl, NULL, &keys[i], NULL));

      it = ngtcp2_ksl_lower_bound(&ksl, &keys[i]);

      assert_int64(keys[i], ==, *(int64_t *)ngtcp2_ksl_it_key(&it));
    }

    shuffle(keys, ngtcp2_arraylen(keys));

    for (i = 0; i < ngtcp2_arraylen(keys); ++i) {
      assert_int(0, ==, ngtcp2_ksl_remove(&ksl, NULL, &keys[i]));

      it = ngtcp2_ksl_begin(&ksl);

      assert_int(NGTCP2_ERR_INVALID_ARGUMENT, ==,
                 ngtcp2_ksl_remove(&ksl, &it, &keys[i]));
      assert_true(ngtcp2_ksl_it_end(&it));

      it = ngtcp2_ksl_lower_bound(&ksl, &keys[i]);

      assert_true(ngtcp2_ksl_it_end(&it) ||
                  keys[i] < *(int64_t *)ngtcp2_ksl_it_key(&it));

      assert_int(0, ==, ngtcp2_ksl_insert(&ksl, NULL, &keys[i], NULL));

      it = ngtcp2_ksl_begin(&ksl);

      assert_int(NGTCP2_ERR_INVALID_ARGUMENT, ==,
                 ngtcp2_ksl_insert(&ksl, &it, &keys[i], NULL));
      assert_true(ngtcp2_ksl_it_end(&it));

      it = ngtcp2_ksl_lower_bound(&ksl, &keys[i]);
      assert_int64(keys[i], ==, *(int64_t *)ngtcp2_ksl_it_key(&it));
    }

    ngtcp2_ksl_free(&ksl);
  }
}

void test_ngtcp2_ksl_remove_hint(void) {
  static int64_t keys[16000];
  ngtcp2_ksl ksl;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_ksl_it it;
  size_t i, j;

  for (i = 0; i < ngtcp2_arraylen(keys); ++i) {
    keys[i] = (int64_t)i;
  }

  for (j = 0; j < 10; ++j) {
    ngtcp2_ksl_init(&ksl, less, sizeof(int64_t), mem);

    shuffle(keys, ngtcp2_arraylen(keys));

    for (i = 0; i < ngtcp2_arraylen(keys); ++i) {
      assert_int(0, ==, ngtcp2_ksl_insert(&ksl, NULL, &keys[i], NULL));
    }

    shuffle(keys, ngtcp2_arraylen(keys));

    for (i = 0; i < ngtcp2_arraylen(keys); ++i) {
      it = ngtcp2_ksl_lower_bound(&ksl, &keys[i]);

      assert_false(ngtcp2_ksl_it_end(&it));
      assert_int64(keys[i], ==, *(int64_t *)ngtcp2_ksl_it_key(&it));
      assert_int(0, ==, ngtcp2_ksl_remove_hint(&ksl, &it, &it, &keys[i]));

      it = ngtcp2_ksl_lower_bound(&ksl, &keys[i]);

      assert_true(ngtcp2_ksl_it_end(&it) ||
                  keys[i] != *(int64_t *)ngtcp2_ksl_it_key(&it));
      assert_size(ngtcp2_arraylen(keys) - i - 1, ==, ngtcp2_ksl_len(&ksl));
    }

    ngtcp2_ksl_free(&ksl);
  }
}
