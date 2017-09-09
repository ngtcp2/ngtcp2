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
      {NULL, NULL, 1, 1000}, {NULL, NULL, 5, 1001}, {NULL, NULL, 7, 1002},
      {NULL, NULL, 4, 1003}, {NULL, NULL, 6, 1004}, {NULL, NULL, 2, 1005},
      {NULL, NULL, 3, 1006},
  };
  uint64_t max_pkt_num[] = {1, 5, 7, 7, 7, 7, 7};
  ngtcp2_acktr_entry **pent;
  size_t i;
  int rv;
  ngtcp2_mem *mem = ngtcp2_mem_default();

  ngtcp2_acktr_init(&acktr, mem);

  for (i = 0; i < arraylen(ents); ++i) {
    rv = ngtcp2_acktr_add(&acktr, &ents[i], 1);

    CU_ASSERT(0 == rv);

    pent = ngtcp2_acktr_get(&acktr);

    CU_ASSERT(max_pkt_num[i] == (*pent)->pkt_num);
  }

  for (i = 0; i < arraylen(ents); ++i) {
    ngtcp2_acktr_pop(&acktr);

    pent = ngtcp2_acktr_get(&acktr);

    if (i != arraylen(ents) - 1) {
      CU_ASSERT(arraylen(ents) - i - 1 == (*pent)->pkt_num);
    } else {
      CU_ASSERT(NULL == *pent);
    }
  }

  ngtcp2_acktr_free(&acktr);

  /* Check duplicates */
  ngtcp2_acktr_init(&acktr, mem);

  rv = ngtcp2_acktr_add(&acktr, &ents[0], 1);

  CU_ASSERT(0 == rv);

  rv = ngtcp2_acktr_add(&acktr, &ents[0], 1);

  CU_ASSERT(NGTCP2_ERR_PROTO == rv);

  ngtcp2_acktr_free(&acktr);
}

void test_ngtcp2_acktr_eviction(void) {
  ngtcp2_acktr acktr;
  ngtcp2_mem *mem = ngtcp2_mem_default();
  size_t i;
  ngtcp2_acktr_entry *ent, *next;
  const size_t extra = 17;

  ngtcp2_acktr_init(&acktr, mem);

  for (i = 0; i < NGTCP2_ACKTR_MAX_ENT + extra; ++i) {
    ngtcp2_acktr_entry_new(&ent, i, 0, mem);
    ngtcp2_acktr_add(&acktr, ent, 1);
  }

  CU_ASSERT(NGTCP2_ACKTR_MAX_ENT == acktr.nack);
  CU_ASSERT(NULL != acktr.ent);

  for (ent = acktr.ent; ent; ent = ent->next) {
    CU_ASSERT(ent == *ent->pprev);
  }

  for (i = 0, ent = acktr.ent; ent; ++i) {
    next = ent->next;

    CU_ASSERT(NGTCP2_ACKTR_MAX_ENT + extra - i - 1 == ent->pkt_num);

    ngtcp2_acktr_entry_del(ent, mem);
    ent = next;
  }

  ngtcp2_acktr_free(&acktr);

  /* Invert insertion order */
  ngtcp2_acktr_init(&acktr, mem);

  for (i = NGTCP2_ACKTR_MAX_ENT + extra; i > 0; --i) {
    ngtcp2_acktr_entry_new(&ent, i - 1, 0, mem);
    ngtcp2_acktr_add(&acktr, ent, 1);
  }

  CU_ASSERT(NGTCP2_ACKTR_MAX_ENT == acktr.nack);
  CU_ASSERT(NULL != acktr.ent);

  for (ent = acktr.ent; ent; ent = ent->next) {
    CU_ASSERT(ent == *ent->pprev);
  }

  for (i = 0, ent = acktr.ent; ent; ++i) {
    next = ent->next;

    CU_ASSERT(NGTCP2_ACKTR_MAX_ENT + extra - i - 1 == ent->pkt_num);

    ngtcp2_acktr_entry_del(ent, mem);
    ent = next;
  }

  ngtcp2_acktr_free(&acktr);
}

void test_ngtcp2_acktr_forget(void) {
  ngtcp2_acktr acktr;
  ngtcp2_mem *mem = ngtcp2_mem_default();
  size_t i;
  ngtcp2_acktr_entry *ent;

  ngtcp2_acktr_init(&acktr, mem);

  for (i = 0; i < 7; ++i) {
    ngtcp2_acktr_entry_new(&ent, i, 0, mem);
    ngtcp2_acktr_add(&acktr, ent, 1);
  }

  CU_ASSERT(7 == acktr.nack);

  ngtcp2_acktr_forget(&acktr, acktr.ent->next->next->next);

  CU_ASSERT(3 == acktr.nack);
  CU_ASSERT(NULL == acktr.ent->next->next->next);
  CU_ASSERT(acktr.ent->next->next == acktr.tail);

  ngtcp2_acktr_forget(&acktr, acktr.ent);

  CU_ASSERT(0 == acktr.nack);
  CU_ASSERT(NULL == acktr.ent);
  CU_ASSERT(NULL == acktr.tail);

  ngtcp2_acktr_free(&acktr);
}

void test_ngtcp2_acktr_recv_ack(void) {
  ngtcp2_acktr acktr;
  ngtcp2_mem *mem = ngtcp2_mem_default();
  size_t i;
  ngtcp2_ack fr;
  uint64_t pkt_nums[] = {
      4500, 4499, 4497, 4496, 4494, 4493, 4491, 4490, 4488, 4487,
  };
  ngtcp2_acktr_entry *ent;

  ngtcp2_acktr_init(&acktr, mem);

  for (i = 0; i < arraylen(pkt_nums); ++i) {
    ngtcp2_acktr_entry_new(&ent, pkt_nums[i], 1, mem);
    ngtcp2_acktr_add(&acktr, ent, 1);
  }

  fr.type = NGTCP2_FRAME_ACK;
  fr.largest_ack = 4500;
  fr.ack_delay = 0;
  fr.first_ack_blklen = 1;
  fr.num_blks = 2;
  fr.blks[0].gap = 5;
  fr.blks[0].blklen = 2;
  fr.blks[1].gap = 1;
  fr.blks[1].blklen = 1;

  ngtcp2_acktr_add_ack(&acktr, 999, &fr, 0);
  ngtcp2_acktr_add_ack(&acktr, 998, &fr, 0);

  fr.type = NGTCP2_FRAME_ACK;
  fr.largest_ack = 999;
  fr.ack_delay = 0;
  fr.first_ack_blklen = 0;
  fr.num_blks = 0;

  ngtcp2_acktr_recv_ack(&acktr, &fr, 0);

  CU_ASSERT(0 == ngtcp2_ringbuf_len(&acktr.acks));
  CU_ASSERT(5 == acktr.nack);

  ent = acktr.ent;

  CU_ASSERT(4497 == ent->pkt_num);
  ent = ent->next;
  CU_ASSERT(4496 == ent->pkt_num);
  ent = ent->next;
  CU_ASSERT(4490 == ent->pkt_num);
  ent = ent->next;
  CU_ASSERT(4488 == ent->pkt_num);
  ent = ent->next;
  CU_ASSERT(4487 == ent->pkt_num);

  ngtcp2_acktr_free(&acktr);
}
