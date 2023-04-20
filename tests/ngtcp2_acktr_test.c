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

#include <stdio.h>

#include <CUnit/CUnit.h>

#include "ngtcp2_acktr.h"
#include "ngtcp2_test_helper.h"

void test_ngtcp2_acktr_add(void) {
  const int64_t pkt_nums[] = {1, 5, 7, 6, 2, 3};
  ngtcp2_acktr acktr;
  ngtcp2_acktr_entry *ent;
  ngtcp2_ksl_it it;
  size_t i;
  int rv;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_log log;

  ngtcp2_log_init(&log, NULL, NULL, 0, NULL);
  ngtcp2_acktr_init(&acktr, &log, mem);

  for (i = 0; i < ngtcp2_arraylen(pkt_nums); ++i) {
    rv = ngtcp2_acktr_add(&acktr, pkt_nums[i], 1, 999);

    CU_ASSERT(0 == rv);
  }

  it = ngtcp2_acktr_get(&acktr);
  ent = ngtcp2_ksl_it_get(&it);

  CU_ASSERT(7 == ent->pkt_num);
  CU_ASSERT(3 == ent->len);

  ngtcp2_ksl_it_next(&it);
  ent = ngtcp2_ksl_it_get(&it);

  CU_ASSERT(3 == ent->pkt_num);
  CU_ASSERT(3 == ent->len);

  ngtcp2_ksl_it_next(&it);

  CU_ASSERT(ngtcp2_ksl_it_end(&it));

  ngtcp2_acktr_free(&acktr);

  /* Check all conditions */

  /* The lower bound returns the one beyond of the last entry.  The
     added packet number extends the first entry. */
  ngtcp2_acktr_init(&acktr, &log, mem);

  ngtcp2_acktr_add(&acktr, 1, 1, 100);
  ngtcp2_acktr_add(&acktr, 0, 1, 101);

  CU_ASSERT(1 == ngtcp2_ksl_len(&acktr.ents));

  it = ngtcp2_acktr_get(&acktr);
  ent = ngtcp2_ksl_it_get(&it);

  CU_ASSERT(1 == ent->pkt_num);
  CU_ASSERT(2 == ent->len);
  CU_ASSERT(100 == ent->tstamp);

  ngtcp2_acktr_free(&acktr);

  /* The entry is the first one and adding a packet number extends it
     to the forward. */
  ngtcp2_acktr_init(&acktr, &log, mem);

  ngtcp2_acktr_add(&acktr, 0, 1, 100);
  ngtcp2_acktr_add(&acktr, 1, 1, 101);

  CU_ASSERT(1 == ngtcp2_ksl_len(&acktr.ents));

  it = ngtcp2_acktr_get(&acktr);
  ent = ngtcp2_ksl_it_get(&it);

  CU_ASSERT(1 == ent->pkt_num);
  CU_ASSERT(2 == ent->len);
  CU_ASSERT(101 == ent->tstamp);

  ngtcp2_acktr_free(&acktr);

  /* The adding entry merges the existing 2 entries. */
  ngtcp2_acktr_init(&acktr, &log, mem);

  ngtcp2_acktr_add(&acktr, 0, 1, 100);
  ngtcp2_acktr_add(&acktr, 2, 1, 101);
  ngtcp2_acktr_add(&acktr, 3, 1, 102);

  CU_ASSERT(2 == ngtcp2_ksl_len(&acktr.ents));

  ngtcp2_acktr_add(&acktr, 1, 1, 103);

  CU_ASSERT(1 == ngtcp2_ksl_len(&acktr.ents));

  it = ngtcp2_acktr_get(&acktr);
  ent = ngtcp2_ksl_it_get(&it);

  CU_ASSERT(3 == ent->pkt_num);
  CU_ASSERT(4 == ent->len);
  CU_ASSERT(102 == ent->tstamp);

  ngtcp2_acktr_free(&acktr);

  /* Adding entry does not merge the existing 2 entries.  It extends
     the last entry. */
  ngtcp2_acktr_init(&acktr, &log, mem);

  ngtcp2_acktr_add(&acktr, 0, 1, 100);
  ngtcp2_acktr_add(&acktr, 3, 1, 101);
  ngtcp2_acktr_add(&acktr, 4, 1, 102);

  CU_ASSERT(2 == ngtcp2_ksl_len(&acktr.ents));

  ngtcp2_acktr_add(&acktr, 1, 1, 103);

  CU_ASSERT(2 == ngtcp2_ksl_len(&acktr.ents));

  it = ngtcp2_acktr_get(&acktr);
  ent = ngtcp2_ksl_it_get(&it);

  CU_ASSERT(4 == ent->pkt_num);
  CU_ASSERT(2 == ent->len);
  CU_ASSERT(102 == ent->tstamp);

  ngtcp2_ksl_it_next(&it);
  ent = ngtcp2_ksl_it_get(&it);

  CU_ASSERT(1 == ent->pkt_num);
  CU_ASSERT(2 == ent->len);
  CU_ASSERT(103 == ent->tstamp);

  ngtcp2_acktr_free(&acktr);

  /* Adding entry does not merge the existing 2 entries.  It extends
     the first entry. */
  ngtcp2_acktr_init(&acktr, &log, mem);

  ngtcp2_acktr_add(&acktr, 0, 1, 100);
  ngtcp2_acktr_add(&acktr, 3, 1, 101);
  ngtcp2_acktr_add(&acktr, 4, 1, 102);

  CU_ASSERT(2 == ngtcp2_ksl_len(&acktr.ents));

  ngtcp2_acktr_add(&acktr, 2, 1, 103);

  CU_ASSERT(2 == ngtcp2_ksl_len(&acktr.ents));

  it = ngtcp2_acktr_get(&acktr);
  ent = ngtcp2_ksl_it_get(&it);

  CU_ASSERT(4 == ent->pkt_num);
  CU_ASSERT(3 == ent->len);
  CU_ASSERT(102 == ent->tstamp);

  ngtcp2_ksl_it_next(&it);
  ent = ngtcp2_ksl_it_get(&it);

  CU_ASSERT(0 == ent->pkt_num);
  CU_ASSERT(1 == ent->len);
  CU_ASSERT(100 == ent->tstamp);

  ngtcp2_acktr_free(&acktr);

  /* The added packet number does not extend any entries. */
  ngtcp2_acktr_init(&acktr, &log, mem);

  ngtcp2_acktr_add(&acktr, 0, 1, 0);
  ngtcp2_acktr_add(&acktr, 4, 1, 0);
  ngtcp2_acktr_add(&acktr, 2, 1, 0);

  CU_ASSERT(3 == ngtcp2_ksl_len(&acktr.ents));

  ngtcp2_acktr_free(&acktr);
}

void test_ngtcp2_acktr_eviction(void) {
  ngtcp2_acktr acktr;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  size_t i;
  ngtcp2_acktr_entry *ent;
  const size_t extra = 17;
  ngtcp2_log log;
  ngtcp2_ksl_it it;

  ngtcp2_log_init(&log, NULL, NULL, 0, NULL);
  ngtcp2_acktr_init(&acktr, &log, mem);

  for (i = 0; i < NGTCP2_ACKTR_MAX_ENT + extra; ++i) {
    ngtcp2_acktr_add(&acktr, (int64_t)(i * 2), 1, 999 + i);
  }

  CU_ASSERT(NGTCP2_ACKTR_MAX_ENT == ngtcp2_ksl_len(&acktr.ents));

  for (i = 0, it = ngtcp2_acktr_get(&acktr); !ngtcp2_ksl_it_end(&it);
       ++i, ngtcp2_ksl_it_next(&it)) {
    ent = ngtcp2_ksl_it_get(&it);

    CU_ASSERT((int64_t)((NGTCP2_ACKTR_MAX_ENT + extra - 1) * 2 - i * 2) ==
              ent->pkt_num);
  }

  ngtcp2_acktr_free(&acktr);

  /* Invert insertion order */
  ngtcp2_acktr_init(&acktr, &log, mem);

  for (i = NGTCP2_ACKTR_MAX_ENT + extra; i > 0; --i) {
    ngtcp2_acktr_add(&acktr, (int64_t)((i - 1) * 2), 1, 999 + i);
  }

  CU_ASSERT(NGTCP2_ACKTR_MAX_ENT == ngtcp2_ksl_len(&acktr.ents));

  for (i = 0, it = ngtcp2_acktr_get(&acktr); !ngtcp2_ksl_it_end(&it);
       ++i, ngtcp2_ksl_it_next(&it)) {
    ent = ngtcp2_ksl_it_get(&it);

    CU_ASSERT((int64_t)((NGTCP2_ACKTR_MAX_ENT + extra - 1) * 2 - i * 2) ==
              ent->pkt_num);
  }

  ngtcp2_acktr_free(&acktr);
}

void test_ngtcp2_acktr_forget(void) {
  ngtcp2_acktr acktr;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  size_t i;
  ngtcp2_acktr_entry *ent;
  ngtcp2_log log;
  ngtcp2_ksl_it it;

  ngtcp2_log_init(&log, NULL, NULL, 0, NULL);
  ngtcp2_acktr_init(&acktr, &log, mem);

  for (i = 0; i < 7; ++i) {
    ngtcp2_acktr_add(&acktr, (int64_t)(i * 2), 1, 999 + i);
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

  CU_ASSERT(12 == ent->pkt_num);

  ngtcp2_ksl_it_next(&it);
  ent = ngtcp2_ksl_it_get(&it);

  CU_ASSERT(10 == ent->pkt_num);

  ngtcp2_ksl_it_next(&it);
  ent = ngtcp2_ksl_it_get(&it);

  CU_ASSERT(8 == ent->pkt_num);

  it = ngtcp2_acktr_get(&acktr);
  ent = ngtcp2_ksl_it_get(&it);

  ngtcp2_acktr_forget(&acktr, ent);

  CU_ASSERT(0 == ngtcp2_ksl_len(&acktr.ents));

  ngtcp2_acktr_free(&acktr);
}

void test_ngtcp2_acktr_recv_ack(void) {
  ngtcp2_acktr acktr;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  size_t i;
  ngtcp2_ack ackfr;
  int64_t rpkt_nums[] = {
      4500, 4499, 4497, 4496, 4494, 4493, 4491, 4490, 4488, 4487, 4483,
  };
  /*
     4500 4499
     4497 4496
     4494 4493
     4491 4490
     4488 4487
     4483
  */
  ngtcp2_acktr_entry *ent;
  ngtcp2_log log;
  ngtcp2_ksl_it it;

  ngtcp2_log_init(&log, NULL, NULL, 0, NULL);
  ngtcp2_acktr_init(&acktr, &log, mem);

  for (i = 0; i < ngtcp2_arraylen(rpkt_nums); ++i) {
    ngtcp2_acktr_add(&acktr, rpkt_nums[i], 1, 999 + i);
  }

  CU_ASSERT(6 == ngtcp2_ksl_len(&acktr.ents));

  ngtcp2_acktr_add_ack(&acktr, 998, 4497);
  ngtcp2_acktr_add_ack(&acktr, 999, 4499);

  ackfr.type = NGTCP2_FRAME_ACK;
  ackfr.largest_ack = 998;
  ackfr.ack_delay = 0;
  ackfr.first_ack_range = 0;
  ackfr.rangecnt = 0;

  ngtcp2_acktr_recv_ack(&acktr, &ackfr);

  CU_ASSERT(1 == ngtcp2_ringbuf_len(&acktr.acks));
  CU_ASSERT(1 == ngtcp2_ksl_len(&acktr.ents));

  it = ngtcp2_ksl_begin(&acktr.ents);
  ent = ngtcp2_ksl_it_get(&it);

  CU_ASSERT(4500 == ent->pkt_num);
  CU_ASSERT(2 == ent->len);

  ackfr.type = NGTCP2_FRAME_ACK;
  ackfr.largest_ack = 999;
  ackfr.ack_delay = 0;
  ackfr.first_ack_range = 0;
  ackfr.rangecnt = 0;

  ngtcp2_acktr_recv_ack(&acktr, &ackfr);

  CU_ASSERT(0 == ngtcp2_ringbuf_len(&acktr.acks));
  CU_ASSERT(1 == ngtcp2_ksl_len(&acktr.ents));

  it = ngtcp2_ksl_begin(&acktr.ents);
  ent = ngtcp2_ksl_it_get(&it);

  CU_ASSERT(4500 == ent->pkt_num);
  CU_ASSERT(1 == ent->len);

  ngtcp2_acktr_free(&acktr);
}
