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
#include "ngtcp2_acktr_test.h"

#include <CUnit/CUnit.h>

#include "ngtcp2_acktr.h"
#include "ngtcp2_test_helper.h"

void test_ngtcp2_acktr_add(void) {
  ngtcp2_acktr acktr;
  ngtcp2_acktr_entry ents[] = {
      {NULL, 1, 1000}, {NULL, 5, 1001}, {NULL, 7, 1002}, {NULL, 4, 1003},
      {NULL, 6, 1004}, {NULL, 2, 1005}, {NULL, 3, 1006},
  };
  uint64_t max_pkt_num[] = {1, 5, 7, 7, 7, 7, 7};
  ngtcp2_acktr_entry *ent;
  size_t i;
  int rv;

  ngtcp2_acktr_init(&acktr);

  for (i = 0; i < arraylen(ents); ++i) {
    rv = ngtcp2_acktr_add(&acktr, &ents[i]);

    CU_ASSERT(0 == rv);

    ent = ngtcp2_acktr_get(&acktr);

    CU_ASSERT(max_pkt_num[i] == ent->pkt_num);
  }

  for (i = 0; i < arraylen(ents); ++i) {
    ent = ngtcp2_acktr_get(&acktr);
    ngtcp2_acktr_remove(&acktr, ent);

    ent = ngtcp2_acktr_get(&acktr);

    if (i != arraylen(ents) - 1) {
      CU_ASSERT(arraylen(ents) - i - 1 == ent->pkt_num);
    } else {
      CU_ASSERT(NULL == ent);
    }
  }

  ngtcp2_acktr_free(&acktr);

  /* Check duplicates */
  ngtcp2_acktr_init(&acktr);

  rv = ngtcp2_acktr_add(&acktr, &ents[0]);

  CU_ASSERT(0 == rv);

  rv = ngtcp2_acktr_add(&acktr, &ents[0]);

  CU_ASSERT(NGTCP2_ERR_PROTO == rv);

  ngtcp2_acktr_free(&acktr);
}
