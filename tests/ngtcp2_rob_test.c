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
#include "ngtcp2_rob_test.h"

#include <CUnit/CUnit.h>

#include "ngtcp2_rob.h"
#include "ngtcp2_test_helper.h"
#include "ngtcp2_mem.h"

void test_ngtcp2_rob_push(void) {
  ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_rob rob;
  int rv;
  uint8_t data[256];
  ngtcp2_rob_gap *g;

  /* Check range overlapping */
  ngtcp2_rob_init(&rob, 64, mem);

  rv = ngtcp2_rob_push(&rob, 34567, data, 145);

  CU_ASSERT(0 == rv);

  g = rob.gap;

  CU_ASSERT(0 == g->range.begin);
  CU_ASSERT(34567 == g->range.end);

  g = g->next;

  CU_ASSERT(34567 + 145 == g->range.begin);
  CU_ASSERT(UINT64_MAX == g->range.end);
  CU_ASSERT(NULL == g->next);

  rv = ngtcp2_rob_push(&rob, 34565, data, 1);

  CU_ASSERT(0 == rv);

  g = rob.gap;

  CU_ASSERT(0 == g->range.begin);
  CU_ASSERT(34565 == g->range.end);

  g = g->next;

  CU_ASSERT(34566 == g->range.begin);
  CU_ASSERT(34567 == g->range.end);

  rv = ngtcp2_rob_push(&rob, 34563, data, 1);

  CU_ASSERT(0 == rv);

  g = rob.gap;

  CU_ASSERT(0 == g->range.begin);
  CU_ASSERT(34563 == g->range.end);

  g = g->next;

  CU_ASSERT(34564 == g->range.begin);
  CU_ASSERT(34565 == g->range.end);

  rv = ngtcp2_rob_push(&rob, 34561, data, 151);

  CU_ASSERT(0 == rv);

  g = rob.gap;

  CU_ASSERT(0 == g->range.begin);
  CU_ASSERT(34561 == g->range.end);

  g = g->next;

  CU_ASSERT(34567 + 145 == g->range.begin);
  CU_ASSERT(UINT64_MAX == g->range.end);
  CU_ASSERT(NULL == g->next);

  ngtcp2_rob_free(&rob);

  /* Check removing prefix */
  ngtcp2_rob_init(&rob, 64, mem);

  rv = ngtcp2_rob_push(&rob, 0, data, 123);

  CU_ASSERT(0 == rv);

  g = rob.gap;

  CU_ASSERT(123 == g->range.begin);
  CU_ASSERT(UINT64_MAX == g->range.end);
  CU_ASSERT(NULL == g->next);

  ngtcp2_rob_free(&rob);

  /* Check removing suffix */
  ngtcp2_rob_init(&rob, 64, mem);

  rv = ngtcp2_rob_push(&rob, UINT64_MAX - 123, data, 123);

  CU_ASSERT(0 == rv);

  g = rob.gap;

  CU_ASSERT(0 == g->range.begin);
  CU_ASSERT(UINT64_MAX - 123 == g->range.end);
  CU_ASSERT(NULL == g->next);

  ngtcp2_rob_free(&rob);
}

void test_ngtcp2_rob_data_at(void) {
  ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_rob rob;
  int rv;
  uint8_t data[256];
  size_t i;
  const uint8_t *p;
  size_t len;
  ngtcp2_rob_data *d;

  for (i = 0; i < sizeof(data); ++i) {
    data[i] = (uint8_t)i;
  }

  ngtcp2_rob_init(&rob, 16, mem);

  rv = ngtcp2_rob_push(&rob, 3, &data[3], 13);

  CU_ASSERT(0 == rv);

  len = ngtcp2_rob_data_at(&rob, &p, 0);

  CU_ASSERT(0 == len);

  rv = ngtcp2_rob_push(&rob, 0, &data[0], 3);

  CU_ASSERT(0 == rv);

  len = ngtcp2_rob_data_at(&rob, &p, 0);

  CU_ASSERT(16 == len);

  for (i = 0; i < len; ++i) {
    CU_ASSERT((uint8_t)i == *(p + i));
  }

  ngtcp2_rob_pop(&rob, 0, len);

  rv = ngtcp2_rob_push(&rob, 16, &data[16], 5);

  CU_ASSERT(0 == rv);

  len = ngtcp2_rob_data_at(&rob, &p, 16);

  CU_ASSERT(5 == len);

  for (i = 16; i < len; ++i) {
    CU_ASSERT((uint8_t)i == *(p + i));
  }

  ngtcp2_rob_free(&rob);

  /* Verify the case where data spans over multiple chunks */
  ngtcp2_rob_init(&rob, 16, mem);

  rv = ngtcp2_rob_push(&rob, 0, &data[0], 47);

  CU_ASSERT(0 == rv);

  len = ngtcp2_rob_data_at(&rob, &p, 0);

  CU_ASSERT(16 == len);

  ngtcp2_rob_pop(&rob, 0, len);
  len = ngtcp2_rob_data_at(&rob, &p, 16);

  CU_ASSERT(16 == len);

  ngtcp2_rob_pop(&rob, 16, len);
  len = ngtcp2_rob_data_at(&rob, &p, 32);

  CU_ASSERT(15 == len);

  ngtcp2_rob_pop(&rob, 32, len);
  ngtcp2_rob_free(&rob);

  /* Verify the case where new offset comes before the existing
     chunk */
  ngtcp2_rob_init(&rob, 16, mem);

  rv = ngtcp2_rob_push(&rob, 17, &data[17], 2);

  CU_ASSERT(0 == rv);

  len = ngtcp2_rob_data_at(&rob, &p, 0);

  CU_ASSERT(0 == len);

  rv = ngtcp2_rob_push(&rob, 0, &data[0], 3);

  CU_ASSERT(0 == rv);

  len = ngtcp2_rob_data_at(&rob, &p, 0);

  CU_ASSERT(3 == len);

  ngtcp2_rob_pop(&rob, 0, len);

  len = ngtcp2_rob_data_at(&rob, &p, 3);

  CU_ASSERT(0 == len);

  ngtcp2_rob_free(&rob);

  /* Verify the case where new offset comes after the existing
     chunk */
  ngtcp2_rob_init(&rob, 16, mem);

  rv = ngtcp2_rob_push(&rob, 0, &data[0], 3);

  CU_ASSERT(0 == rv);

  rv = ngtcp2_rob_push(&rob, 16, &data[16], 32);

  CU_ASSERT(0 == rv);

  d = rob.data->next;

  CU_ASSERT(16 == d->offset);

  d = d->next;

  CU_ASSERT(32 == d->offset);
  CU_ASSERT(NULL == d->next);

  ngtcp2_rob_free(&rob);

  /* Severely scattered data */
  ngtcp2_rob_init(&rob, 16, mem);

  for (i = 0; i < sizeof(data); i += 2) {
    rv = ngtcp2_rob_push(&rob, i, &data[i], 1);

    CU_ASSERT(0 == rv);
  }

  for (i = 1; i < sizeof(data); i += 2) {
    rv = ngtcp2_rob_push(&rob, i, &data[i], 1);

    CU_ASSERT(0 == rv);
  }

  for (i = 0; i < sizeof(data) / 16; ++i) {
    len = ngtcp2_rob_data_at(&rob, &p, i * 16);

    CU_ASSERT(16 == len);

    ngtcp2_rob_pop(&rob, i * 16, len);
  }

  CU_ASSERT(256 == rob.gap->range.begin);
  CU_ASSERT(NULL == rob.data);

  ngtcp2_rob_free(&rob);

  /* Verify the case where chunk is reused if it is not fully used */
  ngtcp2_rob_init(&rob, 16, mem);

  rv = ngtcp2_rob_push(&rob, 0, &data[0], 5);

  CU_ASSERT(0 == rv);

  len = ngtcp2_rob_data_at(&rob, &p, 0);

  CU_ASSERT(5 == len);

  ngtcp2_rob_pop(&rob, 0, len);

  rv = ngtcp2_rob_push(&rob, 2, &data[2], 8);

  CU_ASSERT(0 == rv);

  len = ngtcp2_rob_data_at(&rob, &p, 5);

  CU_ASSERT(5 == len);

  ngtcp2_rob_pop(&rob, 5, len);

  ngtcp2_rob_free(&rob);

  /* Verify the case where 2nd push covers already processed region */
  ngtcp2_rob_init(&rob, 16, mem);

  rv = ngtcp2_rob_push(&rob, 0, &data[0], 16);

  CU_ASSERT(0 == rv);

  len = ngtcp2_rob_data_at(&rob, &p, 0);

  CU_ASSERT(16 == len);

  ngtcp2_rob_pop(&rob, 0, len);

  rv = ngtcp2_rob_push(&rob, 0, &data[0], 32);

  CU_ASSERT(0 == rv);

  len = ngtcp2_rob_data_at(&rob, &p, 16);

  CU_ASSERT(16 == len);

  ngtcp2_rob_pop(&rob, 16, len);

  ngtcp2_rob_free(&rob);
}

void test_ngtcp2_rob_remove_prefix(void) {
  ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_rob rob;
  uint8_t data[256];
  int rv;

  /* Removing data which spans multiple chunks */
  ngtcp2_rob_init(&rob, 16, mem);

  rv = ngtcp2_rob_push(&rob, 1, &data[1], 32);

  CU_ASSERT(0 == rv);

  ngtcp2_rob_remove_prefix(&rob, 33);

  CU_ASSERT(33 == rob.gap->range.begin);
  CU_ASSERT(32 == rob.data->offset);

  ngtcp2_rob_free(&rob);

  /* Remove an entire gap */
  ngtcp2_rob_init(&rob, 16, mem);

  rv = ngtcp2_rob_push(&rob, 1, &data[1], 3);

  CU_ASSERT(0 == rv);

  rv = ngtcp2_rob_push(&rob, 5, &data[5], 2);

  CU_ASSERT(0 == rv);

  ngtcp2_rob_remove_prefix(&rob, 16);

  CU_ASSERT(16 == rob.gap->range.begin);
  CU_ASSERT(NULL == rob.gap->next);

  ngtcp2_rob_free(&rob);
}
