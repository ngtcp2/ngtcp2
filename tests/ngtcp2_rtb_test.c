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

#include <stdio.h>
#include <assert.h>

#include "ngtcp2_rtb.h"
#include "ngtcp2_test_helper.h"
#include "ngtcp2_mem.h"
#include "ngtcp2_pkt.h"
#include "ngtcp2_frame_chain.h"

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_rtb_add),
  munit_void_test(test_ngtcp2_rtb_recv_ack),
  munit_void_test(test_ngtcp2_rtb_lost_pkt_ts),
  munit_void_test(test_ngtcp2_rtb_remove_expired_lost_pkt),
  munit_void_test(test_ngtcp2_rtb_remove_excessive_lost_pkt),
  munit_test_end(),
};

const MunitSuite rtb_suite = {
  .prefix = "/rtb",
  .tests = tests,
};

static void conn_stat_init(ngtcp2_conn_stat *cstat) {
  memset(cstat, 0, sizeof(*cstat));
  cstat->max_tx_udp_payload_size = NGTCP2_MAX_UDP_PAYLOAD_SIZE;
}

void test_ngtcp2_rtb_add(void) {
  ngtcp2_rtb rtb;
  ngtcp2_rtb_entry *ent;
  int rv;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_pkt_hd hd;
  ngtcp2_log log;
  ngtcp2_cid dcid;
  ngtcp2_ksl_it it;
  ngtcp2_conn_stat cstat;
  ngtcp2_cc_reno cc;
  ngtcp2_rst rst;
  ngtcp2_objalloc frc_objalloc;
  ngtcp2_objalloc rtb_entry_objalloc;

  ngtcp2_objalloc_init(&frc_objalloc, 1024, mem);
  ngtcp2_objalloc_init(&rtb_entry_objalloc, 1024, mem);

  dcid_init(&dcid);
  conn_stat_init(&cstat);
  ngtcp2_rst_init(&rst);
  ngtcp2_log_init(&log, NULL, NULL, 0, NULL);
  ngtcp2_cc_reno_init(&cc, &log);
  ngtcp2_rtb_init(&rtb, &rst, &cc.cc, 0, &log, NULL, &rtb_entry_objalloc,
                  &frc_objalloc, mem);

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_1RTT, &dcid, NULL,
                     1000000007, 1, NGTCP2_PROTO_VER_V1);

  rv = ngtcp2_rtb_entry_objalloc_new(
    &ent, &hd, NULL, 10, 0, NGTCP2_RTB_ENTRY_FLAG_NONE, &rtb_entry_objalloc);

  assert_int(0, ==, rv);

  ngtcp2_rtb_add(&rtb, ent, &cstat);

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_1RTT, &dcid, NULL,
                     1000000008, 2, NGTCP2_PROTO_VER_V1);

  rv = ngtcp2_rtb_entry_objalloc_new(
    &ent, &hd, NULL, 9, 0, NGTCP2_RTB_ENTRY_FLAG_NONE, &rtb_entry_objalloc);

  assert_int(0, ==, rv);

  ngtcp2_rtb_add(&rtb, ent, &cstat);

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_1RTT, &dcid, NULL,
                     1000000009, 4, NGTCP2_PROTO_VER_V1);

  rv = ngtcp2_rtb_entry_objalloc_new(
    &ent, &hd, NULL, 11, 0, NGTCP2_RTB_ENTRY_FLAG_NONE, &rtb_entry_objalloc);

  assert_int(0, ==, rv);

  ngtcp2_rtb_add(&rtb, ent, &cstat);

  it = ngtcp2_rtb_head(&rtb);
  ent = ngtcp2_ksl_it_get(&it);

  /* Check the top of the queue */
  assert_int64(1000000009, ==, ent->hd.pkt_num);

  ngtcp2_ksl_it_next(&it);
  ent = ngtcp2_ksl_it_get(&it);

  assert_int64(1000000008, ==, ent->hd.pkt_num);

  ngtcp2_ksl_it_next(&it);
  ent = ngtcp2_ksl_it_get(&it);

  assert_int64(1000000007, ==, ent->hd.pkt_num);

  ngtcp2_ksl_it_next(&it);

  assert_true(ngtcp2_ksl_it_end(&it));

  ngtcp2_rtb_free(&rtb);

  ngtcp2_objalloc_free(&rtb_entry_objalloc);
  ngtcp2_objalloc_free(&frc_objalloc);
}

static void add_rtb_entry_range_with_flags(ngtcp2_rtb *rtb,
                                           int64_t base_pkt_num, size_t len,
                                           uint16_t flags,
                                           ngtcp2_conn_stat *cstat,
                                           ngtcp2_objalloc *objalloc) {
  ngtcp2_pkt_hd hd;
  ngtcp2_rtb_entry *ent;
  size_t i;
  ngtcp2_cid dcid;

  dcid_init(&dcid);

  for (i = 0; i < len; ++i) {
    ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_1RTT, &dcid, NULL,
                       base_pkt_num + (int64_t)i, 1, NGTCP2_PROTO_VER_V1);
    ngtcp2_rtb_entry_objalloc_new(&ent, &hd, NULL, 0, 0, flags, objalloc);
    ngtcp2_rtb_add(rtb, ent, cstat);
  }
}

static void add_rtb_entry_range(ngtcp2_rtb *rtb, int64_t base_pkt_num,
                                size_t len, ngtcp2_conn_stat *cstat,
                                ngtcp2_objalloc *objalloc) {
  add_rtb_entry_range_with_flags(rtb, base_pkt_num, len,
                                 NGTCP2_RTB_ENTRY_FLAG_NONE, cstat, objalloc);
}

static void setup_rtb_fixture(ngtcp2_rtb *rtb, ngtcp2_conn_stat *cstat,
                              ngtcp2_objalloc *objalloc) {
  /* 100, ..., 154 */
  add_rtb_entry_range(rtb, 100, 55, cstat, objalloc);
  /* 180, ..., 184 */
  add_rtb_entry_range(rtb, 180, 5, cstat, objalloc);
  /* 440, ..., 446 */
  add_rtb_entry_range(rtb, 440, 7, cstat, objalloc);
}

static void assert_rtb_entry_not_found(ngtcp2_rtb *rtb, int64_t pkt_num) {
  ngtcp2_ksl_it it = ngtcp2_rtb_head(rtb);
  ngtcp2_rtb_entry *ent;

  for (; !ngtcp2_ksl_it_end(&it); ngtcp2_ksl_it_next(&it)) {
    ent = ngtcp2_ksl_it_get(&it);
    assert_int64(ent->hd.pkt_num, !=, pkt_num);
  }
}

void test_ngtcp2_rtb_recv_ack(void) {
  ngtcp2_rtb rtb;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_max_frame mfr;
  ngtcp2_ack *fr = &mfr.ackfr.ack;
  ngtcp2_ack_range *ranges;
  ngtcp2_log log;
  ngtcp2_conn_stat cstat;
  ngtcp2_cc_reno cc;
  ngtcp2_pkt_hd hd;
  ngtcp2_ssize num_acked;
  ngtcp2_rst rst;
  ngtcp2_objalloc frc_objalloc;
  ngtcp2_objalloc rtb_entry_objalloc;
  ngtcp2_pktns pktns = {0};

  ngtcp2_objalloc_init(&frc_objalloc, 1024, mem);
  ngtcp2_objalloc_init(&rtb_entry_objalloc, 1024, mem);

  ngtcp2_log_init(&log, NULL, NULL, 0, NULL);
  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_1RTT, NULL, NULL, 0,
                     1, NGTCP2_PROTO_VER_V1);
  pktns.id = NGTCP2_PKTNS_ID_HANDSHAKE;

  /* no ack block */
  conn_stat_init(&cstat);
  ngtcp2_rst_init(&rst);
  ngtcp2_cc_reno_init(&cc, &log);
  ngtcp2_rtb_init(&rtb, &rst, &cc.cc, 0, &log, NULL, &rtb_entry_objalloc,
                  &frc_objalloc, mem);
  setup_rtb_fixture(&rtb, &cstat, &rtb_entry_objalloc);

  assert_size(67, ==, ngtcp2_ksl_len(&rtb.ents));

  fr->largest_ack = 446;
  fr->first_ack_range = 1;
  fr->rangecnt = 0;

  num_acked =
    ngtcp2_rtb_recv_ack(&rtb, fr, &cstat, NULL, &pktns, 1000000009, 1000000009);

  assert_ptrdiff(2, ==, num_acked);
  assert_size(65, ==, ngtcp2_ksl_len(&rtb.ents));
  assert_rtb_entry_not_found(&rtb, 446);
  assert_rtb_entry_not_found(&rtb, 445);

  ngtcp2_rtb_free(&rtb);

  /* with ack block */
  conn_stat_init(&cstat);
  ngtcp2_cc_reno_init(&cc, &log);
  ngtcp2_rtb_init(&rtb, &rst, &cc.cc, 0, &log, NULL, &rtb_entry_objalloc,
                  &frc_objalloc, mem);
  setup_rtb_fixture(&rtb, &cstat, &rtb_entry_objalloc);

  fr->largest_ack = 441;
  fr->first_ack_range = 3; /* (441), (440), 439, 438 */
  fr->rangecnt = 2;
  ranges = fr->ranges;
  ranges[0].gap = 253;
  ranges[0].len = 0; /* (183) */
  ranges[1].gap = 1; /* 182, 181 */
  ranges[1].len = 1; /* (180), 179 */

  num_acked =
    ngtcp2_rtb_recv_ack(&rtb, fr, &cstat, NULL, &pktns, 1000000009, 1000000009);

  assert_ptrdiff(4, ==, num_acked);
  assert_size(63, ==, ngtcp2_ksl_len(&rtb.ents));
  assert_int64(441, ==, rtb.largest_acked_tx_pkt_num);
  assert_rtb_entry_not_found(&rtb, 441);
  assert_rtb_entry_not_found(&rtb, 440);
  assert_rtb_entry_not_found(&rtb, 183);
  assert_rtb_entry_not_found(&rtb, 180);

  ngtcp2_rtb_free(&rtb);

  /* gap+len points to pkt_num 0 */
  conn_stat_init(&cstat);
  ngtcp2_cc_reno_init(&cc, &log);
  ngtcp2_rtb_init(&rtb, &rst, &cc.cc, 0, &log, NULL, &rtb_entry_objalloc,
                  &frc_objalloc, mem);
  add_rtb_entry_range(&rtb, 0, 1, &cstat, &rtb_entry_objalloc);

  fr->largest_ack = 250;
  fr->first_ack_range = 0;
  fr->rangecnt = 1;
  fr->ranges[0].gap = 248;
  fr->ranges[0].len = 0;

  num_acked =
    ngtcp2_rtb_recv_ack(&rtb, fr, &cstat, NULL, &pktns, 1000000009, 1000000009);

  assert_ptrdiff(1, ==, num_acked);
  assert_rtb_entry_not_found(&rtb, 0);

  ngtcp2_rtb_free(&rtb);

  /* pkt_num = 0 (first ack block) */
  conn_stat_init(&cstat);
  ngtcp2_cc_reno_init(&cc, &log);
  ngtcp2_rtb_init(&rtb, &rst, &cc.cc, 0, &log, NULL, &rtb_entry_objalloc,
                  &frc_objalloc, mem);
  add_rtb_entry_range(&rtb, 0, 1, &cstat, &rtb_entry_objalloc);

  fr->largest_ack = 0;
  fr->first_ack_range = 0;
  fr->rangecnt = 0;

  num_acked =
    ngtcp2_rtb_recv_ack(&rtb, fr, &cstat, NULL, &pktns, 1000000009, 1000000009);

  assert_ptrdiff(1, ==, num_acked);
  assert_rtb_entry_not_found(&rtb, 0);

  ngtcp2_rtb_free(&rtb);

  /* pkt_num = 0 */
  conn_stat_init(&cstat);
  ngtcp2_cc_reno_init(&cc, &log);
  ngtcp2_rtb_init(&rtb, &rst, &cc.cc, 0, &log, NULL, &rtb_entry_objalloc,
                  &frc_objalloc, mem);
  add_rtb_entry_range(&rtb, 0, 1, &cstat, &rtb_entry_objalloc);

  fr->largest_ack = 2;
  fr->first_ack_range = 0;
  fr->rangecnt = 1;
  fr->ranges[0].gap = 0;
  fr->ranges[0].len = 0;

  num_acked =
    ngtcp2_rtb_recv_ack(&rtb, fr, &cstat, NULL, &pktns, 1000000009, 1000000009);

  assert_ptrdiff(1, ==, num_acked);
  assert_rtb_entry_not_found(&rtb, 0);

  ngtcp2_rtb_free(&rtb);

  /* acknowledging skipped packet number in the first block */
  conn_stat_init(&cstat);
  ngtcp2_cc_reno_init(&cc, &log);
  ngtcp2_rtb_init(&rtb, &rst, &cc.cc, 0, &log, NULL, &rtb_entry_objalloc,
                  &frc_objalloc, mem);
  add_rtb_entry_range_with_flags(&rtb, 0, 1, NGTCP2_RTB_ENTRY_FLAG_SKIP, &cstat,
                                 &rtb_entry_objalloc);

  fr->largest_ack = 0;
  fr->first_ack_range = 0;
  fr->rangecnt = 0;

  num_acked =
    ngtcp2_rtb_recv_ack(&rtb, fr, &cstat, NULL, &pktns, 1000000009, 1000000009);

  assert_ptrdiff(NGTCP2_ERR_PROTO, ==, num_acked);

  ngtcp2_rtb_free(&rtb);

  /* acknowledging skipped packet number in the second block */
  conn_stat_init(&cstat);
  ngtcp2_cc_reno_init(&cc, &log);
  ngtcp2_rtb_init(&rtb, &rst, &cc.cc, 0, &log, NULL, &rtb_entry_objalloc,
                  &frc_objalloc, mem);
  add_rtb_entry_range_with_flags(&rtb, 0, 1, NGTCP2_RTB_ENTRY_FLAG_SKIP, &cstat,
                                 &rtb_entry_objalloc);

  fr->largest_ack = 2;
  fr->first_ack_range = 0;
  fr->rangecnt = 1;
  fr->ranges[0].gap = 0;
  fr->ranges[0].len = 0;

  num_acked =
    ngtcp2_rtb_recv_ack(&rtb, fr, &cstat, NULL, &pktns, 1000000009, 1000000009);

  assert_ptrdiff(NGTCP2_ERR_PROTO, ==, num_acked);

  ngtcp2_rtb_free(&rtb);

  ngtcp2_objalloc_free(&rtb_entry_objalloc);
  ngtcp2_objalloc_free(&frc_objalloc);
}

void test_ngtcp2_rtb_lost_pkt_ts(void) {
  ngtcp2_rtb rtb;
  ngtcp2_log log;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_cc_reno cc;
  ngtcp2_rst rst;
  ngtcp2_conn_stat cstat;
  ngtcp2_ksl_it it;
  ngtcp2_rtb_entry *ent;
  ngtcp2_objalloc frc_objalloc;
  ngtcp2_objalloc rtb_entry_objalloc;

  ngtcp2_objalloc_init(&frc_objalloc, 1024, mem);
  ngtcp2_objalloc_init(&rtb_entry_objalloc, 1024, mem);

  ngtcp2_log_init(&log, NULL, NULL, 0, NULL);

  conn_stat_init(&cstat);
  ngtcp2_rst_init(&rst);
  ngtcp2_cc_reno_init(&cc, &log);
  ngtcp2_rtb_init(&rtb, &rst, &cc.cc, 0, &log, NULL, &rtb_entry_objalloc,
                  &frc_objalloc, mem);

  add_rtb_entry_range(&rtb, 0, 1, &cstat, &rtb_entry_objalloc);

  assert_uint64(UINT64_MAX, ==, ngtcp2_rtb_lost_pkt_ts(&rtb));

  it = ngtcp2_ksl_end(&rtb.ents);
  ngtcp2_ksl_it_prev(&it);
  ent = ngtcp2_ksl_it_get(&it);
  ent->flags |= NGTCP2_RTB_ENTRY_FLAG_LOST_RETRANSMITTED;
  ent->lost_ts = 16777217;

  assert_uint64(16777217, ==, ngtcp2_rtb_lost_pkt_ts(&rtb));

  ngtcp2_rtb_free(&rtb);

  ngtcp2_objalloc_free(&rtb_entry_objalloc);
  ngtcp2_objalloc_free(&frc_objalloc);
}

void test_ngtcp2_rtb_remove_expired_lost_pkt(void) {
  ngtcp2_rtb rtb;
  ngtcp2_log log;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_cc_reno cc;
  ngtcp2_rst rst;
  ngtcp2_conn_stat cstat;
  ngtcp2_ksl_it it;
  ngtcp2_rtb_entry *ent;
  size_t i;
  ngtcp2_objalloc frc_objalloc;
  ngtcp2_objalloc rtb_entry_objalloc;

  ngtcp2_objalloc_init(&frc_objalloc, 1024, mem);
  ngtcp2_objalloc_init(&rtb_entry_objalloc, 1024, mem);

  ngtcp2_log_init(&log, NULL, NULL, 0, NULL);

  conn_stat_init(&cstat);
  ngtcp2_rst_init(&rst);
  ngtcp2_cc_reno_init(&cc, &log);
  ngtcp2_rtb_init(&rtb, &rst, &cc.cc, 0, &log, NULL, &rtb_entry_objalloc,
                  &frc_objalloc, mem);

  add_rtb_entry_range_with_flags(&rtb, 0, 1, NGTCP2_RTB_ENTRY_FLAG_PMTUD_PROBE,
                                 &cstat, &rtb_entry_objalloc);
  add_rtb_entry_range(&rtb, 1, 6, &cstat, &rtb_entry_objalloc);

  it = ngtcp2_ksl_end(&rtb.ents);

  for (i = 0; i < 5; ++i) {
    ngtcp2_ksl_it_prev(&it);
    ent = ngtcp2_ksl_it_get(&it);
    ent->flags |= NGTCP2_RTB_ENTRY_FLAG_LOST_RETRANSMITTED;
    ent->lost_ts = 16777217 + i;
    ++rtb.num_lost_pkts;
  }

  ++rtb.num_lost_ignore_pkts;

  assert_size(5, ==, rtb.num_lost_pkts);
  assert_size(1, ==, rtb.num_lost_ignore_pkts);

  ngtcp2_rtb_remove_expired_lost_pkt(&rtb, 1, 16777219);

  assert_size(5, ==, ngtcp2_ksl_len(&rtb.ents));
  assert_size(3, ==, rtb.num_lost_pkts);
  assert_size(0, ==, rtb.num_lost_ignore_pkts);

  ngtcp2_rtb_remove_expired_lost_pkt(&rtb, 1, 16777222);

  assert_size(2, ==, ngtcp2_ksl_len(&rtb.ents));
  assert_size(0, ==, rtb.num_lost_pkts);
  assert_size(0, ==, rtb.num_lost_ignore_pkts);

  ngtcp2_rtb_free(&rtb);

  ngtcp2_objalloc_free(&rtb_entry_objalloc);
  ngtcp2_objalloc_free(&frc_objalloc);
}

void test_ngtcp2_rtb_remove_excessive_lost_pkt(void) {
  ngtcp2_rtb rtb;
  ngtcp2_log log;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_cc_reno cc;
  ngtcp2_rst rst;
  ngtcp2_conn_stat cstat;
  ngtcp2_ksl_it it;
  ngtcp2_rtb_entry *ent;
  size_t i;
  ngtcp2_objalloc frc_objalloc;
  ngtcp2_objalloc rtb_entry_objalloc;

  ngtcp2_objalloc_init(&frc_objalloc, 1024, mem);
  ngtcp2_objalloc_init(&rtb_entry_objalloc, 1024, mem);

  ngtcp2_log_init(&log, NULL, NULL, 0, NULL);

  conn_stat_init(&cstat);
  ngtcp2_rst_init(&rst);
  ngtcp2_cc_reno_init(&cc, &log);
  ngtcp2_rtb_init(&rtb, &rst, &cc.cc, 0, &log, NULL, &rtb_entry_objalloc,
                  &frc_objalloc, mem);

  add_rtb_entry_range_with_flags(&rtb, 0, 1, NGTCP2_RTB_ENTRY_FLAG_PMTUD_PROBE,
                                 &cstat, &rtb_entry_objalloc);
  add_rtb_entry_range(&rtb, 1, 6, &cstat, &rtb_entry_objalloc);

  it = ngtcp2_ksl_end(&rtb.ents);

  for (i = 0; i < 5; ++i) {
    ngtcp2_ksl_it_prev(&it);
    ent = ngtcp2_ksl_it_get(&it);
    ent->flags |= NGTCP2_RTB_ENTRY_FLAG_LOST_RETRANSMITTED;
    ent->lost_ts = 16777217;
    ++rtb.num_lost_pkts;
  }

  ++rtb.num_lost_ignore_pkts;

  assert_size(5, ==, rtb.num_lost_pkts);
  assert_size(1, ==, rtb.num_lost_ignore_pkts);

  ngtcp2_rtb_remove_excessive_lost_pkt(&rtb, 2);

  assert_size(4, ==, ngtcp2_ksl_len(&rtb.ents));
  assert_size(2, ==, rtb.num_lost_pkts);
  assert_size(0, ==, rtb.num_lost_ignore_pkts);

  ngtcp2_rtb_free(&rtb);

  ngtcp2_objalloc_free(&rtb_entry_objalloc);
  ngtcp2_objalloc_free(&frc_objalloc);
}
