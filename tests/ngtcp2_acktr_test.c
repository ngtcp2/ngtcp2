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

#include "ngtcp2_acktr.h"
#include "ngtcp2_test_helper.h"

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_acktr_add),
  munit_void_test(test_ngtcp2_acktr_eviction),
  munit_void_test(test_ngtcp2_acktr_forget),
  munit_void_test(test_ngtcp2_acktr_recv_ack),
  munit_void_test(test_ngtcp2_acktr_create_ack_frame),
  munit_void_test(test_ngtcp2_acktr_free),
  munit_test_end(),
};

const MunitSuite acktr_suite = {
  .prefix = "/acktr",
  .tests = tests,
};

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

    assert_int(0, ==, rv);
  }

  it = ngtcp2_acktr_get(&acktr);
  ent = ngtcp2_ksl_it_get(&it);

  assert_int64(7, ==, ent->pkt_num);
  assert_size(3, ==, ent->len);

  ngtcp2_ksl_it_next(&it);
  ent = ngtcp2_ksl_it_get(&it);

  assert_int64(3, ==, ent->pkt_num);
  assert_size(3, ==, ent->len);

  ngtcp2_ksl_it_next(&it);

  assert_true(ngtcp2_ksl_it_end(&it));

  ngtcp2_acktr_free(&acktr);

  /* Check all conditions */

  /* The lower bound returns the one beyond of the last entry.  The
     added packet number extends the first entry. */
  ngtcp2_acktr_init(&acktr, &log, mem);

  ngtcp2_acktr_add(&acktr, 1, 1, 100);
  ngtcp2_acktr_add(&acktr, 0, 1, 101);

  assert_size(1, ==, ngtcp2_ksl_len(&acktr.ents));

  it = ngtcp2_acktr_get(&acktr);
  ent = ngtcp2_ksl_it_get(&it);

  assert_int64(1, ==, ent->pkt_num);
  assert_size(2, ==, ent->len);
  assert_uint64(100, ==, ent->tstamp);

  ngtcp2_acktr_free(&acktr);

  /* The entry is the first one and adding a packet number extends it
     to the forward. */
  ngtcp2_acktr_init(&acktr, &log, mem);

  ngtcp2_acktr_add(&acktr, 0, 1, 100);
  ngtcp2_acktr_add(&acktr, 1, 1, 101);

  assert_size(1, ==, ngtcp2_ksl_len(&acktr.ents));

  it = ngtcp2_acktr_get(&acktr);
  ent = ngtcp2_ksl_it_get(&it);

  assert_int64(1, ==, ent->pkt_num);
  assert_size(2, ==, ent->len);
  assert_uint64(101, ==, ent->tstamp);

  ngtcp2_acktr_free(&acktr);

  /* The adding entry merges the existing 2 entries. */
  ngtcp2_acktr_init(&acktr, &log, mem);

  ngtcp2_acktr_add(&acktr, 0, 1, 100);
  ngtcp2_acktr_add(&acktr, 2, 1, 101);
  ngtcp2_acktr_add(&acktr, 3, 1, 102);

  assert_size(2, ==, ngtcp2_ksl_len(&acktr.ents));

  ngtcp2_acktr_add(&acktr, 1, 1, 103);

  assert_size(1, ==, ngtcp2_ksl_len(&acktr.ents));

  it = ngtcp2_acktr_get(&acktr);
  ent = ngtcp2_ksl_it_get(&it);

  assert_int64(3, ==, ent->pkt_num);
  assert_size(4, ==, ent->len);
  assert_uint64(102, ==, ent->tstamp);

  ngtcp2_acktr_free(&acktr);

  /* Adding entry does not merge the existing 2 entries.  It extends
     the last entry. */
  ngtcp2_acktr_init(&acktr, &log, mem);

  ngtcp2_acktr_add(&acktr, 0, 1, 100);
  ngtcp2_acktr_add(&acktr, 3, 1, 101);
  ngtcp2_acktr_add(&acktr, 4, 1, 102);

  assert_size(2, ==, ngtcp2_ksl_len(&acktr.ents));

  ngtcp2_acktr_add(&acktr, 1, 1, 103);

  assert_size(2, ==, ngtcp2_ksl_len(&acktr.ents));

  it = ngtcp2_acktr_get(&acktr);
  ent = ngtcp2_ksl_it_get(&it);

  assert_int64(4, ==, ent->pkt_num);
  assert_size(2, ==, ent->len);
  assert_uint64(102, ==, ent->tstamp);

  ngtcp2_ksl_it_next(&it);
  ent = ngtcp2_ksl_it_get(&it);

  assert_int64(1, ==, ent->pkt_num);
  assert_size(2, ==, ent->len);
  assert_uint64(103, ==, ent->tstamp);

  ngtcp2_acktr_free(&acktr);

  /* Adding entry does not merge the existing 2 entries.  It extends
     the first entry. */
  ngtcp2_acktr_init(&acktr, &log, mem);

  ngtcp2_acktr_add(&acktr, 0, 1, 100);
  ngtcp2_acktr_add(&acktr, 3, 1, 101);
  ngtcp2_acktr_add(&acktr, 4, 1, 102);

  assert_size(2, ==, ngtcp2_ksl_len(&acktr.ents));

  ngtcp2_acktr_add(&acktr, 2, 1, 103);

  assert_size(2, ==, ngtcp2_ksl_len(&acktr.ents));

  it = ngtcp2_acktr_get(&acktr);
  ent = ngtcp2_ksl_it_get(&it);

  assert_int64(4, ==, ent->pkt_num);
  assert_size(3, ==, ent->len);
  assert_uint64(102, ==, ent->tstamp);

  ngtcp2_ksl_it_next(&it);
  ent = ngtcp2_ksl_it_get(&it);

  assert_int64(0, ==, ent->pkt_num);
  assert_size(1, ==, ent->len);
  assert_uint64(100, ==, ent->tstamp);

  ngtcp2_acktr_free(&acktr);

  /* The added packet number does not extend any entries. */
  ngtcp2_acktr_init(&acktr, &log, mem);

  ngtcp2_acktr_add(&acktr, 0, 1, 0);
  ngtcp2_acktr_add(&acktr, 4, 1, 0);
  ngtcp2_acktr_add(&acktr, 2, 1, 0);

  assert_size(3, ==, ngtcp2_ksl_len(&acktr.ents));

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

  assert_size(NGTCP2_ACKTR_MAX_ENT, ==, ngtcp2_ksl_len(&acktr.ents));

  for (i = 0, it = ngtcp2_acktr_get(&acktr); !ngtcp2_ksl_it_end(&it);
       ++i, ngtcp2_ksl_it_next(&it)) {
    ent = ngtcp2_ksl_it_get(&it);

    assert_int64((int64_t)((NGTCP2_ACKTR_MAX_ENT + extra - 1) * 2 - i * 2), ==,
                 ent->pkt_num);
  }

  ngtcp2_acktr_free(&acktr);

  /* Invert insertion order */
  ngtcp2_acktr_init(&acktr, &log, mem);

  for (i = NGTCP2_ACKTR_MAX_ENT + extra; i > 0; --i) {
    ngtcp2_acktr_add(&acktr, (int64_t)((i - 1) * 2), 1, 999 + i);
  }

  assert_size(NGTCP2_ACKTR_MAX_ENT, ==, ngtcp2_ksl_len(&acktr.ents));

  for (i = 0, it = ngtcp2_acktr_get(&acktr); !ngtcp2_ksl_it_end(&it);
       ++i, ngtcp2_ksl_it_next(&it)) {
    ent = ngtcp2_ksl_it_get(&it);

    assert_int64((int64_t)((NGTCP2_ACKTR_MAX_ENT + extra - 1) * 2 - i * 2), ==,
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

  assert_size(7, ==, ngtcp2_ksl_len(&acktr.ents));

  it = ngtcp2_acktr_get(&acktr);
  ngtcp2_ksl_it_next(&it);
  ngtcp2_ksl_it_next(&it);
  ngtcp2_ksl_it_next(&it);
  ent = ngtcp2_ksl_it_get(&it);
  ngtcp2_acktr_forget(&acktr, ent);

  assert_size(3, ==, ngtcp2_ksl_len(&acktr.ents));

  it = ngtcp2_acktr_get(&acktr);
  ent = ngtcp2_ksl_it_get(&it);

  assert_int64(12, ==, ent->pkt_num);

  ngtcp2_ksl_it_next(&it);
  ent = ngtcp2_ksl_it_get(&it);

  assert_int64(10, ==, ent->pkt_num);

  ngtcp2_ksl_it_next(&it);
  ent = ngtcp2_ksl_it_get(&it);

  assert_int64(8, ==, ent->pkt_num);

  it = ngtcp2_acktr_get(&acktr);
  ent = ngtcp2_ksl_it_get(&it);

  ngtcp2_acktr_forget(&acktr, ent);

  assert_size(0, ==, ngtcp2_ksl_len(&acktr.ents));

  ngtcp2_acktr_free(&acktr);
}

void test_ngtcp2_acktr_recv_ack(void) {
  ngtcp2_acktr acktr;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  size_t i;
  ngtcp2_max_frame mfr;
  ngtcp2_ack *ackfr = &mfr.fr.ack;
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

  assert_size(6, ==, ngtcp2_ksl_len(&acktr.ents));

  ngtcp2_acktr_add_ack(&acktr, 998, 4497);
  ngtcp2_acktr_add_ack(&acktr, 999, 4499);

  ackfr->type = NGTCP2_FRAME_ACK;
  ackfr->largest_ack = 998;
  ackfr->ack_delay = 0;
  ackfr->first_ack_range = 0;
  ackfr->rangecnt = 0;

  ngtcp2_acktr_recv_ack(&acktr, ackfr);

  assert_size(1, ==, ngtcp2_ringbuf_len(&acktr.acks.rb));
  assert_size(1, ==, ngtcp2_ksl_len(&acktr.ents));

  it = ngtcp2_ksl_begin(&acktr.ents);
  ent = ngtcp2_ksl_it_get(&it);

  assert_int64(4500, ==, ent->pkt_num);
  assert_size(2, ==, ent->len);

  ackfr->type = NGTCP2_FRAME_ACK;
  ackfr->largest_ack = 999;
  ackfr->ack_delay = 0;
  ackfr->first_ack_range = 0;
  ackfr->rangecnt = 0;

  ngtcp2_acktr_recv_ack(&acktr, ackfr);

  assert_size(0, ==, ngtcp2_ringbuf_len(&acktr.acks.rb));
  assert_size(1, ==, ngtcp2_ksl_len(&acktr.ents));

  it = ngtcp2_ksl_begin(&acktr.ents);
  ent = ngtcp2_ksl_it_get(&it);

  assert_int64(4500, ==, ent->pkt_num);
  assert_size(1, ==, ent->len);

  ngtcp2_acktr_free(&acktr);

  /* Multiple ack ranges */
  ngtcp2_acktr_init(&acktr, &log, mem);

  /* [0, 2, 4, 6, 8] */
  for (i = 0; i < 5; ++i) {
    ngtcp2_acktr_add(&acktr, (int64_t)i * 2, 0, 0);
  }

  ngtcp2_acktr_add_ack(&acktr, 999, 4);
  ngtcp2_acktr_add_ack(&acktr, 1004, 8);
  ngtcp2_acktr_add_ack(&acktr, 1006, 8);

  ackfr->type = NGTCP2_FRAME_ACK;
  ackfr->largest_ack = 1005;
  ackfr->ack_delay = 0;
  ackfr->first_ack_range = 0;
  ackfr->rangecnt = 3;
  /* [1003] */
  ackfr->ranges[0].gap = 0;
  ackfr->ranges[0].len = 0;
  /* [1000, 999] */
  ackfr->ranges[1].gap = 1;
  ackfr->ranges[1].len = 1;
  /* [995] */
  ackfr->ranges[2].gap = 2;
  ackfr->ranges[2].len = 0;

  ngtcp2_acktr_recv_ack(&acktr, &mfr.fr.ack);

  assert_size(2, ==, ngtcp2_ringbuf_len(&acktr.acks.rb));
  assert_size(2, ==, ngtcp2_ksl_len(&acktr.ents));

  it = ngtcp2_ksl_begin(&acktr.ents);
  ent = ngtcp2_ksl_it_get(&it);

  assert_int64(8, ==, ent->pkt_num);

  ngtcp2_ksl_it_next(&it);
  ent = ngtcp2_ksl_it_get(&it);

  assert_int64(6, ==, ent->pkt_num);

  /* Doing it again does not change the state */
  ngtcp2_acktr_recv_ack(&acktr, &mfr.fr.ack);

  assert_size(2, ==, ngtcp2_ringbuf_len(&acktr.acks.rb));
  assert_size(2, ==, ngtcp2_ksl_len(&acktr.ents));

  ngtcp2_acktr_free(&acktr);
}

void test_ngtcp2_acktr_create_ack_frame(void) {
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_log log;
  ngtcp2_acktr acktr;
  ngtcp2_max_frame mfr;
  ngtcp2_frame *fr;
  ngtcp2_pkt_info pi = {0};
  size_t i;

  ngtcp2_log_init(&log, NULL, NULL, 0, NULL);

  /* Nothing to acknowledge */
  ngtcp2_acktr_init(&acktr, &log, mem);

  ngtcp2_acktr_add(&acktr, 0, 1, 0);
  ngtcp2_acktr_add_ack(&acktr, 1000, 0);

  mfr.fr.ack.type = NGTCP2_FRAME_ACK;
  mfr.fr.ack.ack_delay = 0;
  mfr.fr.ack.largest_ack = 1000;
  mfr.fr.ack.first_ack_range = 0;
  mfr.fr.ack.rangecnt = 0;

  ngtcp2_acktr_recv_ack(&acktr, &mfr.fr.ack);

  assert_uint64(0, ==, acktr.first_unacked_ts);
  assert_null(
    ngtcp2_acktr_create_ack_frame(&acktr, &mfr.fr, NGTCP2_PKT_1RTT, 0, 0, 0));
  assert_uint64(UINT64_MAX, ==, acktr.first_unacked_ts);

  ngtcp2_acktr_free(&acktr);

  /* With ECN counts */
  ngtcp2_acktr_init(&acktr, &log, mem);

  ngtcp2_acktr_add(&acktr, 1000000007, 1, 5 * NGTCP2_MILLISECONDS);

  pi.ecn = NGTCP2_ECN_ECT_0;

  ngtcp2_acktr_increase_ecn_counts(&acktr, &pi);

  pi.ecn = NGTCP2_ECN_ECT_1;

  ngtcp2_acktr_increase_ecn_counts(&acktr, &pi);
  ngtcp2_acktr_increase_ecn_counts(&acktr, &pi);

  pi.ecn = NGTCP2_ECN_CE;

  ngtcp2_acktr_increase_ecn_counts(&acktr, &pi);
  ngtcp2_acktr_increase_ecn_counts(&acktr, &pi);
  ngtcp2_acktr_increase_ecn_counts(&acktr, &pi);

  fr = ngtcp2_acktr_create_ack_frame(&acktr, &mfr.fr, NGTCP2_PKT_1RTT,
                                     30 * NGTCP2_MILLISECONDS,
                                     25 * NGTCP2_MILLISECONDS, 2);

  assert_not_null(fr);
  assert_uint64(NGTCP2_FRAME_ACK_ECN, ==, fr->type);
  assert_uint64(1, ==, fr->ack.ecn.ect0);
  assert_uint64(2, ==, fr->ack.ecn.ect1);
  assert_uint64(3, ==, fr->ack.ecn.ce);
  assert_int64(1000000007, ==, fr->ack.largest_ack);
  assert_uint64(0, ==, fr->ack.first_ack_range);
  assert_size(0, ==, fr->ack.rangecnt);
  assert_uint64(6250, ==, fr->ack.ack_delay);

  ngtcp2_acktr_free(&acktr);

  /* Remove extraneous entries */
  ngtcp2_acktr_init(&acktr, &log, mem);

  for (i = 0; i < NGTCP2_MAX_ACK_RANGES + 2; ++i) {
    ngtcp2_acktr_add(&acktr, (int64_t)i * 2, 1, 0);
  }

  assert_size(NGTCP2_ACKTR_MAX_ENT, ==, ngtcp2_ksl_len(&acktr.ents));

  fr = ngtcp2_acktr_create_ack_frame(&acktr, &mfr.fr, NGTCP2_PKT_1RTT,
                                     30 * NGTCP2_MILLISECONDS,
                                     30 * NGTCP2_MILLISECONDS, 0);

  assert_not_null(fr);
  assert_int64(2 * (NGTCP2_MAX_ACK_RANGES + 1), ==, fr->ack.largest_ack);
  assert_uint64(0, ==, fr->ack.first_ack_range);
  assert_size(NGTCP2_MAX_ACK_RANGES, ==, fr->ack.rangecnt);
  assert_size(NGTCP2_MAX_ACK_RANGES + 1, ==, ngtcp2_ksl_len(&acktr.ents));

  ngtcp2_acktr_free(&acktr);

  /* Acknowledging packet whose packet number is less than largest
     packet number by 1. */
  ngtcp2_acktr_init(&acktr, &log, mem);

  for (i = 0; i < NGTCP2_MAX_ACK_RANGES + 2; ++i) {
    ngtcp2_acktr_add(&acktr, (int64_t)i * 2, 1, 0);
  }

  ++acktr.max_pkt_num;

  assert_size(NGTCP2_ACKTR_MAX_ENT, ==, ngtcp2_ksl_len(&acktr.ents));

  fr = ngtcp2_acktr_create_ack_frame(&acktr, &mfr.fr, NGTCP2_PKT_1RTT,
                                     30 * NGTCP2_MILLISECONDS,
                                     30 * NGTCP2_MILLISECONDS, 0);

  assert_not_null(fr);
  assert_int64(2 * (NGTCP2_MAX_ACK_RANGES + 1) + 1, ==, fr->ack.largest_ack);
  assert_uint64(1, ==, fr->ack.first_ack_range);
  assert_size(NGTCP2_MAX_ACK_RANGES, ==, fr->ack.rangecnt);
  assert_size(NGTCP2_MAX_ACK_RANGES + 1, ==, ngtcp2_ksl_len(&acktr.ents));

  ngtcp2_acktr_free(&acktr);

  /* Acknowledging packet whose packet number is less than largest
     packet number by 2. */
  ngtcp2_acktr_init(&acktr, &log, mem);

  for (i = 0; i < NGTCP2_MAX_ACK_RANGES + 2; ++i) {
    ngtcp2_acktr_add(&acktr, (int64_t)i * 2, 1, 0);
  }

  acktr.max_pkt_num += 2;

  assert_size(NGTCP2_ACKTR_MAX_ENT, ==, ngtcp2_ksl_len(&acktr.ents));

  fr = ngtcp2_acktr_create_ack_frame(&acktr, &mfr.fr, NGTCP2_PKT_1RTT,
                                     30 * NGTCP2_MILLISECONDS,
                                     30 * NGTCP2_MILLISECONDS, 0);

  assert_not_null(fr);
  assert_int64(2 * (NGTCP2_MAX_ACK_RANGES + 1) + 2, ==, fr->ack.largest_ack);
  assert_uint64(0, ==, fr->ack.first_ack_range);
  assert_size(NGTCP2_MAX_ACK_RANGES, ==, fr->ack.rangecnt);
  assert_size(NGTCP2_MAX_ACK_RANGES + 1, ==, ngtcp2_ksl_len(&acktr.ents));

  ngtcp2_acktr_free(&acktr);
}

void test_ngtcp2_acktr_free(void) { ngtcp2_acktr_free(NULL); }
