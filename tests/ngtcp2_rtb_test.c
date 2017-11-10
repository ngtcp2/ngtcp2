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
#include "ngtcp2_rtb_test.h"

#include <CUnit/CUnit.h>

#include "ngtcp2_rtb.h"
#include "ngtcp2_test_helper.h"
#include "ngtcp2_mem.h"
#include "ngtcp2_pkt.h"

void test_ngtcp2_rtb_add(void) {
  ngtcp2_rtb rtb;
  ngtcp2_rtb_entry *ent;
  int rv;
  ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_pkt_hd hd;

  ngtcp2_rtb_init(&rtb, mem);

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_01, 1000000009,
                     1000000007, NGTCP2_PROTO_VER_MAX);

  rv = ngtcp2_rtb_entry_new(&ent, &hd, NULL, 10, 100, 0, NGTCP2_RTB_FLAG_NONE,
                            mem);

  CU_ASSERT(0 == rv);

  rv = ngtcp2_rtb_add(&rtb, ent);

  CU_ASSERT(0 == rv);

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_02, 1000000009,
                     1000000008, NGTCP2_PROTO_VER_MAX);

  rv = ngtcp2_rtb_entry_new(&ent, &hd, NULL, 9, 100, 0, NGTCP2_RTB_FLAG_NONE,
                            mem);

  CU_ASSERT(0 == rv);

  rv = ngtcp2_rtb_add(&rtb, ent);

  CU_ASSERT(0 == rv);

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_03, 1000000009,
                     1000000009, NGTCP2_PROTO_VER_MAX);

  rv = ngtcp2_rtb_entry_new(&ent, &hd, NULL, 11, 100, 0, NGTCP2_RTB_FLAG_NONE,
                            mem);

  CU_ASSERT(0 == rv);

  rv = ngtcp2_rtb_add(&rtb, ent);

  CU_ASSERT(0 == rv);

  ent = ngtcp2_rtb_top(&rtb);

  /* Check the top of the queue */
  CU_ASSERT(1000000008 == ent->hd.pkt_num);

  ngtcp2_rtb_pop(&rtb);
  ngtcp2_rtb_entry_del(ent, mem);
  ent = ngtcp2_rtb_top(&rtb);

  CU_ASSERT(1000000007 == ent->hd.pkt_num);

  ngtcp2_rtb_pop(&rtb);
  ngtcp2_rtb_entry_del(ent, mem);
  ent = ngtcp2_rtb_top(&rtb);

  CU_ASSERT(1000000009 == ent->hd.pkt_num);

  ngtcp2_rtb_pop(&rtb);
  ngtcp2_rtb_entry_del(ent, mem);

  CU_ASSERT(NULL == ngtcp2_rtb_top(&rtb));

  ngtcp2_rtb_free(&rtb);
}

static void add_rtb_entry_range(ngtcp2_rtb *rtb, uint64_t base_pkt_num,
                                size_t len, ngtcp2_mem *mem) {
  ngtcp2_pkt_hd hd;
  ngtcp2_rtb_entry *ent;
  uint64_t i;
  int rv;

  for (i = base_pkt_num; i < base_pkt_num + len; ++i) {
    ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_01, 1, i,
                       NGTCP2_PROTO_VER_MAX);
    ngtcp2_rtb_entry_new(&ent, &hd, NULL, 0, 100, 0, NGTCP2_RTB_FLAG_NONE, mem);
    rv = ngtcp2_rtb_add(rtb, ent);

    CU_ASSERT(0 == rv);
  }
}

static void setup_rtb_fixture(ngtcp2_rtb *rtb, ngtcp2_mem *mem) {
  /* 100, ..., 154 */
  add_rtb_entry_range(rtb, 100, 55, mem);
  /* 180, ..., 184 */
  add_rtb_entry_range(rtb, 180, 5, mem);
  /* 440, ..., 446 */
  add_rtb_entry_range(rtb, 440, 7, mem);
}

static void assert_rtb_entry_not_found(ngtcp2_rtb *rtb, uint64_t pkt_num) {
  ngtcp2_rtb_entry *ent;

  for (ent = rtb->head; ent; ent = ent->next) {
    CU_ASSERT(ent->hd.pkt_num != pkt_num);
  }
}

void test_ngtcp2_rtb_recv_ack(void) {
  ngtcp2_rtb rtb;
  ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_max_frame mfr;
  ngtcp2_ack *fr = &mfr.ackfr.ack;
  ngtcp2_ack_blk *blks;

  /* no ack block */
  ngtcp2_rtb_init(&rtb, mem);
  setup_rtb_fixture(&rtb, mem);

  CU_ASSERT(67 == ngtcp2_pq_size(&rtb.pq));

  fr->largest_ack = 446;
  fr->first_ack_blklen = 1;
  fr->num_blks = 0;

  ngtcp2_rtb_recv_ack(&rtb, fr, 0, NULL);

  CU_ASSERT(65 == ngtcp2_pq_size(&rtb.pq));
  assert_rtb_entry_not_found(&rtb, 446);
  assert_rtb_entry_not_found(&rtb, 445);

  ngtcp2_rtb_free(&rtb);

  /* with ack block */
  ngtcp2_rtb_init(&rtb, mem);
  setup_rtb_fixture(&rtb, mem);

  fr->largest_ack = 441;
  fr->first_ack_blklen = 3; /* (441), (440), 439, 438 */
  fr->num_blks = 2;
  blks = fr->blks;
  blks[0].gap = 253;
  blks[0].blklen = 0; /* (183) */
  blks[1].gap = 1;    /* 182, 181 */
  blks[1].blklen = 1; /* (180), 179 */

  ngtcp2_rtb_recv_ack(&rtb, fr, 0, NULL);

  CU_ASSERT(63 == ngtcp2_pq_size(&rtb.pq));
  CU_ASSERT(441 == rtb.largest_acked);
  assert_rtb_entry_not_found(&rtb, 441);
  assert_rtb_entry_not_found(&rtb, 440);
  assert_rtb_entry_not_found(&rtb, 183);
  assert_rtb_entry_not_found(&rtb, 180);

  ngtcp2_rtb_free(&rtb);

  /* gap+blklen points to pkt_num 0 */
  ngtcp2_rtb_init(&rtb, mem);
  add_rtb_entry_range(&rtb, 0, 1, mem);

  fr->largest_ack = 250;
  fr->first_ack_blklen = 0;
  fr->num_blks = 1;
  fr->blks[0].gap = 248;
  fr->blks[0].blklen = 0;

  ngtcp2_rtb_recv_ack(&rtb, fr, 0, NULL);

  assert_rtb_entry_not_found(&rtb, 0);

  ngtcp2_rtb_free(&rtb);

  /* pkt_num = 0 (first ack block) */
  ngtcp2_rtb_init(&rtb, mem);
  add_rtb_entry_range(&rtb, 0, 1, mem);

  fr->largest_ack = 0;
  fr->first_ack_blklen = 0;
  fr->num_blks = 0;

  ngtcp2_rtb_recv_ack(&rtb, fr, 0, NULL);

  assert_rtb_entry_not_found(&rtb, 0);

  ngtcp2_rtb_free(&rtb);

  /* pkt_num = 0 */
  ngtcp2_rtb_init(&rtb, mem);
  add_rtb_entry_range(&rtb, 0, 1, mem);

  fr->largest_ack = 2;
  fr->first_ack_blklen = 0;
  fr->num_blks = 1;
  fr->blks[0].gap = 0;
  fr->blks[0].blklen = 0;

  ngtcp2_rtb_recv_ack(&rtb, fr, 0, NULL);

  assert_rtb_entry_not_found(&rtb, 0);

  ngtcp2_rtb_free(&rtb);

  /* unprotected ack cannot ack protected packet */
  ngtcp2_rtb_init(&rtb, mem);
  add_rtb_entry_range(&rtb, 0, 1, mem);

  fr->largest_ack = 0;
  fr->first_ack_blklen = 0;
  fr->num_blks = 0;

  ngtcp2_rtb_recv_ack(&rtb, fr, 1, NULL);

  CU_ASSERT(1 == ngtcp2_pq_size(&rtb.pq));

  ngtcp2_rtb_free(&rtb);

  /* unprotected ack cannot ack protected packet with blks */
  ngtcp2_rtb_init(&rtb, mem);
  add_rtb_entry_range(&rtb, 0, 1, mem);

  fr->largest_ack = 3;
  fr->first_ack_blklen = 0;
  fr->num_blks = 1;
  fr->blks[0].gap = 1;
  fr->blks[0].blklen = 0;

  ngtcp2_rtb_recv_ack(&rtb, fr, 1, NULL);

  CU_ASSERT(1 == ngtcp2_pq_size(&rtb.pq));

  ngtcp2_rtb_free(&rtb);
}
