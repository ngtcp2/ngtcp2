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
  ngtcp2_acktr_entry *ents[7];
  uint64_t max_pkt_num[] = {1, 5, 7, 7, 7, 7, 7};
  ngtcp2_acktr_entry *ent;
  ngtcp2_ksl_it it;
  size_t i;
  int rv;
  ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_log log;

  ngtcp2_log_init(&log, NULL, NULL, 0, NULL);
  ngtcp2_acktr_init(&acktr, &log, mem);

  ngtcp2_acktr_entry_new(&ents[0], 1, 1000, mem);
  ngtcp2_acktr_entry_new(&ents[1], 5, 1001, mem);
  ngtcp2_acktr_entry_new(&ents[2], 7, 1002, mem);
  ngtcp2_acktr_entry_new(&ents[3], 4, 1003, mem);
  ngtcp2_acktr_entry_new(&ents[4], 6, 1004, mem);
  ngtcp2_acktr_entry_new(&ents[5], 2, 1005, mem);
  ngtcp2_acktr_entry_new(&ents[6], 3, 1006, mem);

  for (i = 0; i < arraylen(ents); ++i) {
    rv = ngtcp2_acktr_add(&acktr, ents[i], 1, 999);

    CU_ASSERT(0 == rv);

    it = ngtcp2_acktr_get(&acktr);
    ent = ngtcp2_ksl_it_get(&it);

    CU_ASSERT(max_pkt_num[i] == ent->pkt_num);
  }

  for (i = 0; i < arraylen(ents); ++i) {
    it = ngtcp2_acktr_get(&acktr);
    ent = ngtcp2_ksl_it_get(&it);
    ngtcp2_ksl_remove(&acktr.ents, NULL, (int64_t)ent->pkt_num);
    ngtcp2_acktr_entry_del(ent, mem);

    it = ngtcp2_acktr_get(&acktr);

    if (i != arraylen(ents) - 1) {
      ent = ngtcp2_ksl_it_get(&it);

      CU_ASSERT(arraylen(ents) - i - 1 == ent->pkt_num);
    } else {
      CU_ASSERT(ngtcp2_ksl_it_end(&it));
    }
  }

  ngtcp2_acktr_free(&acktr);

  /* Check duplicates */
  ngtcp2_acktr_init(&acktr, &log, mem);
  ngtcp2_acktr_entry_new(&ents[0], 1, 1000, mem);

  rv = ngtcp2_acktr_add(&acktr, ents[0], 1, 999);

  CU_ASSERT(0 == rv);

  rv = ngtcp2_acktr_add(&acktr, ents[0], 1, 1003);

  CU_ASSERT(NGTCP2_ERR_INVALID_ARGUMENT == rv);

  ngtcp2_acktr_free(&acktr);
}

void test_ngtcp2_acktr_eviction(void) {
  ngtcp2_acktr acktr;
  ngtcp2_mem *mem = ngtcp2_mem_default();
  size_t i;
  ngtcp2_acktr_entry *ent;
  const size_t extra = 17;
  ngtcp2_log log;
  ngtcp2_ksl_it it;

  ngtcp2_log_init(&log, NULL, NULL, 0, NULL);
  ngtcp2_acktr_init(&acktr, &log, mem);

  for (i = 0; i < NGTCP2_ACKTR_MAX_ENT + extra; ++i) {
    ngtcp2_acktr_entry_new(&ent, i, 0, mem);
    ngtcp2_acktr_add(&acktr, ent, 1, 999 + i);
  }

  CU_ASSERT(NGTCP2_ACKTR_MAX_ENT == ngtcp2_ksl_len(&acktr.ents));

  for (i = 0, it = ngtcp2_acktr_get(&acktr); !ngtcp2_ksl_it_end(&it);
       ++i, ngtcp2_ksl_it_next(&it)) {
    ent = ngtcp2_ksl_it_get(&it);

    CU_ASSERT(NGTCP2_ACKTR_MAX_ENT + extra - i - 1 == ent->pkt_num);
  }

  ngtcp2_acktr_free(&acktr);

  /* Invert insertion order */
  ngtcp2_acktr_init(&acktr, &log, mem);

  for (i = NGTCP2_ACKTR_MAX_ENT + extra; i > 0; --i) {
    ngtcp2_acktr_entry_new(&ent, i - 1, 0, mem);
    ngtcp2_acktr_add(&acktr, ent, 1, 999 + i);
  }

  CU_ASSERT(NGTCP2_ACKTR_MAX_ENT == ngtcp2_ksl_len(&acktr.ents));

  for (i = 0, it = ngtcp2_acktr_get(&acktr); !ngtcp2_ksl_it_end(&it);
       ++i, ngtcp2_ksl_it_next(&it)) {
    ent = ngtcp2_ksl_it_get(&it);

    CU_ASSERT(NGTCP2_ACKTR_MAX_ENT + extra - i - 1 == ent->pkt_num);
  }

  ngtcp2_acktr_free(&acktr);
}

void test_ngtcp2_acktr_forget(void) {
  ngtcp2_acktr acktr;
  ngtcp2_mem *mem = ngtcp2_mem_default();
  size_t i;
  ngtcp2_acktr_entry *ent;
  ngtcp2_log log;
  ngtcp2_ksl_it it;

  ngtcp2_log_init(&log, NULL, NULL, 0, NULL);
  ngtcp2_acktr_init(&acktr, &log, mem);

  for (i = 0; i < 7; ++i) {
    ngtcp2_acktr_entry_new(&ent, i, 0, mem);
    ngtcp2_acktr_add(&acktr, ent, 1, 999 + i);
  }

  CU_ASSERT(7 == ngtcp2_ksl_len(&acktr.ents));

  it = ngtcp2_acktr_get(&acktr);
  ngtcp2_ksl_it_next(&it);
  ngtcp2_ksl_it_next(&it);
  ngtcp2_ksl_it_next(&it);
  ent = ngtcp2_ksl_it_get(&it);
  ngtcp2_acktr_forget(&acktr, ent);

  CU_ASSERT(3 == ngtcp2_ksl_len(&acktr.ents));

  it = ngtcp2_acktr_get(&acktr);
  ent = ngtcp2_ksl_it_get(&it);

  CU_ASSERT(6 == ent->pkt_num);

  ngtcp2_ksl_it_next(&it);
  ent = ngtcp2_ksl_it_get(&it);

  CU_ASSERT(5 == ent->pkt_num);

  ngtcp2_ksl_it_next(&it);
  ent = ngtcp2_ksl_it_get(&it);

  CU_ASSERT(4 == ent->pkt_num);

  it = ngtcp2_acktr_get(&acktr);
  ent = ngtcp2_ksl_it_get(&it);

  ngtcp2_acktr_forget(&acktr, ent);

  CU_ASSERT(0 == ngtcp2_ksl_len(&acktr.ents));

  ngtcp2_acktr_free(&acktr);
}

void test_ngtcp2_acktr_recv_ack(void) {
  ngtcp2_acktr acktr;
  ngtcp2_mem *mem = ngtcp2_mem_default();
  size_t i;
  ngtcp2_ack *fr, ackfr;
  uint64_t rpkt_nums[] = {
      4500, 4499, 4497, 4496, 4494, 4493, 4491, 4490, 4488, 4487, 4483,
  };
  ngtcp2_acktr_entry *ent;
  uint64_t pkt_num;
  ngtcp2_ack_blk *blks;
  ngtcp2_log log;
  ngtcp2_ksl_it it;

  ngtcp2_log_init(&log, NULL, NULL, 0, NULL);
  ngtcp2_acktr_init(&acktr, &log, mem);

  for (i = 0; i < arraylen(rpkt_nums); ++i) {
    ngtcp2_acktr_entry_new(&ent, rpkt_nums[i], 1, mem);
    ngtcp2_acktr_add(&acktr, ent, 1, 999 + i);
  }

  for (pkt_num = 998; pkt_num <= 999; ++pkt_num) {
    fr = ngtcp2_mem_malloc(mem, sizeof(ngtcp2_max_frame));
    fr->type = NGTCP2_FRAME_ACK;
    fr->largest_ack = 4500;
    fr->ack_delay = 0;
    fr->first_ack_blklen = 1; /* 4499 */
    fr->num_blks = 3;
    blks = fr->blks;
    blks[0].gap = 4;    /* 4498, (4497), (4496), 4495, (4494) */
    blks[0].blklen = 2; /* (4493), 4492, (4491) */
    blks[1].gap = 1;    /* (4490), 4489 */
    blks[1].blklen = 1; /* (4488), (4487) */
    blks[2].gap = 3;    /* 4486, 4485, 4484, (4483) */
    blks[2].blklen = 1; /* 4482, 4481 */

    ngtcp2_acktr_add_ack(&acktr, pkt_num, fr, 1000000009, 0 /* ack_only */);
  }

  ackfr.type = NGTCP2_FRAME_ACK;
  ackfr.largest_ack = 999;
  ackfr.ack_delay = 0;
  ackfr.first_ack_blklen = 0;
  ackfr.num_blks = 0;

  ngtcp2_acktr_recv_ack(&acktr, &ackfr, NULL, 1000000009);

  CU_ASSERT(0 == ngtcp2_ringbuf_len(&acktr.acks));
  CU_ASSERT(5 == ngtcp2_ksl_len(&acktr.ents));

  it = ngtcp2_acktr_get(&acktr);
  ent = ngtcp2_ksl_it_get(&it);

  CU_ASSERT(4497 == ent->pkt_num);

  ngtcp2_ksl_it_next(&it);
  ent = ngtcp2_ksl_it_get(&it);

  CU_ASSERT(4496 == ent->pkt_num);

  ngtcp2_ksl_it_next(&it);
  ent = ngtcp2_ksl_it_get(&it);

  CU_ASSERT(4494 == ent->pkt_num);

  ngtcp2_ksl_it_next(&it);
  ent = ngtcp2_ksl_it_get(&it);

  CU_ASSERT(4490 == ent->pkt_num);

  ngtcp2_ksl_it_next(&it);
  ent = ngtcp2_ksl_it_get(&it);

  CU_ASSERT(4483 == ent->pkt_num);

  ngtcp2_acktr_free(&acktr);
}
