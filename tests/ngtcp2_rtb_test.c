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
#include "ngtcp2_bbr.h"

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_rtb_add),
  munit_void_test(test_ngtcp2_rtb_recv_ack),
  munit_void_test(test_ngtcp2_rtb_lost_pkt_ts),
  munit_void_test(test_ngtcp2_rtb_remove_expired_lost_pkt),
  munit_void_test(test_ngtcp2_rtb_remove_excessive_lost_pkt),
  munit_void_test(test_ngtcp2_rtb_bbr_spurious_loss),
  munit_void_test(test_ngtcp2_rtb_bbr_ecn),
  munit_void_test(test_ngtcp2_rtb_bbr_rtt),
  munit_void_test(test_ngtcp2_rtb_bbr_recovery_exit),
  munit_void_test(test_ngtcp2_rtb_bbr_startup_high_loss),
  munit_test_end(),
};

const MunitSuite rtb_suite = {
  .prefix = "/rtb",
  .tests = tests,
};

static void conn_stat_init(ngtcp2_conn_stat *cstat) {
  *cstat = (ngtcp2_conn_stat){
    .cwnd = 10 * NGTCP2_MAX_UDP_PAYLOAD_SIZE,
    .max_tx_udp_payload_size = NGTCP2_MAX_UDP_PAYLOAD_SIZE,
  };
}

void test_ngtcp2_rtb_add(void) {
  ngtcp2_rtb rtb;
  ngtcp2_rtb_entry *ent;
  int rv;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_pkt_hd hd;
  ngtcp2_log log;
  static const ngtcp2_cid dcid = make_dcid();
  ngtcp2_ksl_it it;
  ngtcp2_conn_stat cstat;
  ngtcp2_cc_reno cc;
  ngtcp2_rst rst;
  ngtcp2_objalloc frc_objalloc;
  ngtcp2_objalloc rtb_entry_objalloc;

  ngtcp2_objalloc_init(&frc_objalloc, 1024, mem);
  ngtcp2_objalloc_init(&rtb_entry_objalloc, 1024, mem);

  conn_stat_init(&cstat);
  ngtcp2_rst_init(&rst);
  ngtcp2_log_init(&log, NULL, NULL, NULL, NULL, 0, NULL);
  ngtcp2_cc_reno_init(&cc, &log, &cstat);
  ngtcp2_rtb_init(&rtb, &rst, &cc.cc, 0, &log, NULL, &rtb_entry_objalloc,
                  &frc_objalloc, mem);

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_1RTT, &dcid, NULL,
                     1000000007, 1, NGTCP2_PROTO_VER_V1);

  rv = ngtcp2_rtb_entry_objalloc_new(
    &ent, &hd, NULL, 10, 0, NGTCP2_RTB_ENTRY_FLAG_NONE, &rtb_entry_objalloc);

  assert_int(0, ==, rv);

  ngtcp2_rtb_add(&rtb, ent, &cstat, /* has_retained_lost_pkts = */ 0);

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_1RTT, &dcid, NULL,
                     1000000008, 2, NGTCP2_PROTO_VER_V1);

  rv = ngtcp2_rtb_entry_objalloc_new(
    &ent, &hd, NULL, 9, 0, NGTCP2_RTB_ENTRY_FLAG_NONE, &rtb_entry_objalloc);

  assert_int(0, ==, rv);

  ngtcp2_rtb_add(&rtb, ent, &cstat, /* has_retained_lost_pkts = */ 0);

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_1RTT, &dcid, NULL,
                     1000000009, 4, NGTCP2_PROTO_VER_V1);

  rv = ngtcp2_rtb_entry_objalloc_new(
    &ent, &hd, NULL, 11, 0, NGTCP2_RTB_ENTRY_FLAG_NONE, &rtb_entry_objalloc);

  assert_int(0, ==, rv);

  ngtcp2_rtb_add(&rtb, ent, &cstat, /* has_retained_lost_pkts = */ 0);

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
  static const ngtcp2_cid dcid = make_dcid();

  for (i = 0; i < len; ++i) {
    ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_1RTT, &dcid, NULL,
                       base_pkt_num + (int64_t)i, 1, NGTCP2_PROTO_VER_V1);
    ngtcp2_rtb_entry_objalloc_new(&ent, &hd, NULL, 0, 0, flags, objalloc);
    ngtcp2_rtb_add(rtb, ent, cstat, /* has_retained_lost_pkts = */ 0);
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
  ngtcp2_ack_range ack_ranges[NGTCP2_MAX_ACK_RANGES];
  ngtcp2_ack fr;
  ngtcp2_log log;
  ngtcp2_conn_stat cstat;
  ngtcp2_cc_reno cc;
  ngtcp2_pkt_hd hd;
  ngtcp2_rtb_entry *ent;
  ngtcp2_ssize num_acked;
  ngtcp2_rst rst;
  ngtcp2_objalloc frc_objalloc;
  ngtcp2_objalloc rtb_entry_objalloc;
  ngtcp2_pktns pktns = {0};

  ngtcp2_objalloc_init(&frc_objalloc, 1024, mem);
  ngtcp2_objalloc_init(&rtb_entry_objalloc, 1024, mem);

  ngtcp2_log_init(&log, NULL, NULL, NULL, NULL, 0, NULL);
  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_1RTT, NULL, NULL, 0,
                     1, NGTCP2_PROTO_VER_V1);
  pktns.id = NGTCP2_PKTNS_ID_HANDSHAKE;

  /* no ack block */
  conn_stat_init(&cstat);
  ngtcp2_rst_init(&rst);
  ngtcp2_cc_reno_init(&cc, &log, &cstat);
  ngtcp2_rtb_init(&rtb, &rst, &cc.cc, 0, &log, NULL, &rtb_entry_objalloc,
                  &frc_objalloc, mem);
  setup_rtb_fixture(&rtb, &cstat, &rtb_entry_objalloc);

  assert_size(67, ==, ngtcp2_ksl_len(&rtb.ents));

  fr = (ngtcp2_ack){
    .largest_ack = 446,
    .first_ack_range = 1,
  };

  num_acked = ngtcp2_rtb_recv_ack(&rtb, &fr, &cstat, NULL, &pktns, 1000000009,
                                  1000000009);

  assert_ptrdiff(2, ==, num_acked);
  assert_size(65, ==, ngtcp2_ksl_len(&rtb.ents));
  assert_rtb_entry_not_found(&rtb, 446);
  assert_rtb_entry_not_found(&rtb, 445);

  ngtcp2_rtb_free(&rtb);

  /* with ack block */
  conn_stat_init(&cstat);
  ngtcp2_cc_reno_init(&cc, &log, &cstat);
  ngtcp2_rtb_init(&rtb, &rst, &cc.cc, 0, &log, NULL, &rtb_entry_objalloc,
                  &frc_objalloc, mem);
  setup_rtb_fixture(&rtb, &cstat, &rtb_entry_objalloc);

  fr = (ngtcp2_ack){
    .largest_ack = 441,
    .first_ack_range = 3, /* (441), (440), 439, 438 */
    .rangecnt = 2,
    .ranges = ack_ranges,
  };
  ack_ranges[0] = (ngtcp2_ack_range){
    .gap = 253, /* (183) */
  };
  ack_ranges[1] = (ngtcp2_ack_range){
    .gap = 1, /* 182, 181 */
    .len = 1, /* (180), 179 */
  };

  num_acked = ngtcp2_rtb_recv_ack(&rtb, &fr, &cstat, NULL, &pktns, 1000000009,
                                  1000000009);

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
  ngtcp2_cc_reno_init(&cc, &log, &cstat);
  ngtcp2_rtb_init(&rtb, &rst, &cc.cc, 0, &log, NULL, &rtb_entry_objalloc,
                  &frc_objalloc, mem);
  add_rtb_entry_range(&rtb, 0, 1, &cstat, &rtb_entry_objalloc);

  fr = (ngtcp2_ack){
    .largest_ack = 250,
    .rangecnt = 1,
    .ranges = ack_ranges,
  };
  ack_ranges[0] = (ngtcp2_ack_range){
    .gap = 248,
  };

  num_acked = ngtcp2_rtb_recv_ack(&rtb, &fr, &cstat, NULL, &pktns, 1000000009,
                                  1000000009);

  assert_ptrdiff(1, ==, num_acked);
  assert_rtb_entry_not_found(&rtb, 0);

  ngtcp2_rtb_free(&rtb);

  /* pkt_num = 0 (first ack block) */
  conn_stat_init(&cstat);
  ngtcp2_cc_reno_init(&cc, &log, &cstat);
  ngtcp2_rtb_init(&rtb, &rst, &cc.cc, 0, &log, NULL, &rtb_entry_objalloc,
                  &frc_objalloc, mem);
  add_rtb_entry_range(&rtb, 0, 1, &cstat, &rtb_entry_objalloc);

  fr = (ngtcp2_ack){0};

  num_acked = ngtcp2_rtb_recv_ack(&rtb, &fr, &cstat, NULL, &pktns, 1000000009,
                                  1000000009);

  assert_ptrdiff(1, ==, num_acked);
  assert_rtb_entry_not_found(&rtb, 0);

  ngtcp2_rtb_free(&rtb);

  /* pkt_num = 0 */
  conn_stat_init(&cstat);
  ngtcp2_cc_reno_init(&cc, &log, &cstat);
  ngtcp2_rtb_init(&rtb, &rst, &cc.cc, 0, &log, NULL, &rtb_entry_objalloc,
                  &frc_objalloc, mem);
  add_rtb_entry_range(&rtb, 0, 1, &cstat, &rtb_entry_objalloc);

  fr = (ngtcp2_ack){
    .largest_ack = 2,
    .rangecnt = 1,
    .ranges = ack_ranges,
  };
  ack_ranges[0] = (ngtcp2_ack_range){0};

  num_acked = ngtcp2_rtb_recv_ack(&rtb, &fr, &cstat, NULL, &pktns, 1000000009,
                                  1000000009);

  assert_ptrdiff(1, ==, num_acked);
  assert_rtb_entry_not_found(&rtb, 0);

  ngtcp2_rtb_free(&rtb);

  /* acknowledging skipped packet number in the first block */
  conn_stat_init(&cstat);
  ngtcp2_cc_reno_init(&cc, &log, &cstat);
  ngtcp2_rtb_init(&rtb, &rst, &cc.cc, 0, &log, NULL, &rtb_entry_objalloc,
                  &frc_objalloc, mem);
  add_rtb_entry_range_with_flags(&rtb, 0, 1, NGTCP2_RTB_ENTRY_FLAG_SKIP, &cstat,
                                 &rtb_entry_objalloc);

  fr = (ngtcp2_ack){0};

  num_acked = ngtcp2_rtb_recv_ack(&rtb, &fr, &cstat, NULL, &pktns, 1000000009,
                                  1000000009);

  assert_ptrdiff(NGTCP2_ERR_PROTO, ==, num_acked);

  ngtcp2_rtb_free(&rtb);

  /* acknowledging skipped packet number in the second block */
  conn_stat_init(&cstat);
  ngtcp2_cc_reno_init(&cc, &log, &cstat);
  ngtcp2_rtb_init(&rtb, &rst, &cc.cc, 0, &log, NULL, &rtb_entry_objalloc,
                  &frc_objalloc, mem);
  add_rtb_entry_range_with_flags(&rtb, 0, 1, NGTCP2_RTB_ENTRY_FLAG_SKIP, &cstat,
                                 &rtb_entry_objalloc);

  fr = (ngtcp2_ack){
    .largest_ack = 2,
    .rangecnt = 1,
    .ranges = ack_ranges,
  };
  ack_ranges[0] = (ngtcp2_ack_range){0};

  num_acked = ngtcp2_rtb_recv_ack(&rtb, &fr, &cstat, NULL, &pktns, 1000000009,
                                  1000000009);

  assert_ptrdiff(NGTCP2_ERR_PROTO, ==, num_acked);

  ngtcp2_rtb_free(&rtb);

  /* acknowledging packet sent after the packet containing ACK frame
     is received in the first block */
  conn_stat_init(&cstat);
  ngtcp2_cc_reno_init(&cc, &log, &cstat);
  ngtcp2_rtb_init(&rtb, &rst, &cc.cc, 0, &log, NULL, &rtb_entry_objalloc,
                  &frc_objalloc, mem);
  ngtcp2_rtb_entry_objalloc_new(&ent, &hd, NULL, 1000000010, 0,
                                NGTCP2_RTB_ENTRY_FLAG_NONE,
                                &rtb_entry_objalloc);
  ngtcp2_rtb_add(&rtb, ent, &cstat, /* has_retained_lost_pkts = */ 0);

  fr = (ngtcp2_ack){0};

  num_acked = ngtcp2_rtb_recv_ack(&rtb, &fr, &cstat, NULL, &pktns, 1000000009,
                                  1000000011);

  assert_ptrdiff(NGTCP2_ERR_PROTO, ==, num_acked);

  ngtcp2_rtb_free(&rtb);

  /* acknowledging packet sent after the packet containing ACK frame
     is received in the second block */
  conn_stat_init(&cstat);
  ngtcp2_cc_reno_init(&cc, &log, &cstat);
  ngtcp2_rtb_init(&rtb, &rst, &cc.cc, 0, &log, NULL, &rtb_entry_objalloc,
                  &frc_objalloc, mem);
  ngtcp2_rtb_entry_objalloc_new(&ent, &hd, NULL, 1000000010, 0,
                                NGTCP2_RTB_ENTRY_FLAG_NONE,
                                &rtb_entry_objalloc);
  ngtcp2_rtb_add(&rtb, ent, &cstat, /* has_retained_lost_pkts = */ 0);

  fr = (ngtcp2_ack){
    .largest_ack = 2,
    .rangecnt = 1,
    .ranges = ack_ranges,
  };
  ack_ranges[0] = (ngtcp2_ack_range){0};

  num_acked = ngtcp2_rtb_recv_ack(&rtb, &fr, &cstat, NULL, &pktns, 1000000009,
                                  1000000011);

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

  ngtcp2_log_init(&log, NULL, NULL, NULL, NULL, 0, NULL);

  conn_stat_init(&cstat);
  ngtcp2_rst_init(&rst);
  ngtcp2_cc_reno_init(&cc, &log, &cstat);
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

  ngtcp2_log_init(&log, NULL, NULL, NULL, NULL, 0, NULL);

  conn_stat_init(&cstat);
  ngtcp2_rst_init(&rst);
  ngtcp2_cc_reno_init(&cc, &log, &cstat);
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

  ngtcp2_rtb_remove_expired_lost_pkt(&rtb, 1, &cstat, 16777219);

  assert_size(5, ==, ngtcp2_ksl_len(&rtb.ents));
  assert_size(3, ==, rtb.num_lost_pkts);
  assert_size(0, ==, rtb.num_lost_ignore_pkts);

  ngtcp2_rtb_remove_expired_lost_pkt(&rtb, 1, &cstat, 16777222);

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

  ngtcp2_log_init(&log, NULL, NULL, NULL, NULL, 0, NULL);

  conn_stat_init(&cstat);
  ngtcp2_rst_init(&rst);
  ngtcp2_cc_reno_init(&cc, &log, &cstat);
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

  ngtcp2_rtb_remove_excessive_lost_pkt(&rtb, 2, &cstat, 16777222);

  assert_size(4, ==, ngtcp2_ksl_len(&rtb.ents));
  assert_size(2, ==, rtb.num_lost_pkts);
  assert_size(0, ==, rtb.num_lost_ignore_pkts);

  ngtcp2_rtb_free(&rtb);

  ngtcp2_objalloc_free(&rtb_entry_objalloc);
  ngtcp2_objalloc_free(&frc_objalloc);
}

typedef enum bbr_loss_resolution {
  BBR_LOSS_ACKED,
  BBR_LOSS_ACKED_WITH_NEW_LOSS,
  BBR_LOSS_EXPIRED,
  BBR_LOSS_EVICTED,
  BBR_LOSS_DISCARDED,
} bbr_loss_resolution;

static void add_bbr_test_pkt(ngtcp2_conn *conn, ngtcp2_pktns *pktns,
                             int64_t pkt_num, ngtcp2_tstamp ts,
                             uint16_t flags) {
  ngtcp2_pkt_hd hd;
  ngtcp2_rtb_entry *ent;
  uint8_t type = pktns->id == NGTCP2_PKTNS_ID_HANDSHAKE ? NGTCP2_PKT_HANDSHAKE
                                                        : NGTCP2_PKT_1RTT;

  ngtcp2_pkt_hd_init(&hd, 0, type, NULL, NULL, pkt_num, 1, 0);
  assert_int(0, ==,
             ngtcp2_rtb_entry_objalloc_new(&ent, &hd, NULL, ts, 1200, flags,
                                           &conn->rtb_entry_objalloc));
  assert_int(0, ==, ngtcp2_rtb_add(&pktns->rtb, ent, &conn->cstat, 0));

  if (flags & NGTCP2_RTB_ENTRY_FLAG_ECN) {
    ++pktns->tx.ecn.ect0;
  }
}

static void init_bbr_test_conn(ngtcp2_conn *conn, ngtcp2_cc_bbr *bbr,
                               ngtcp2_pcg32 *pcg) {
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_conn_stat *cstat = &conn->cstat;

  ngtcp2_objalloc_init(&conn->frc_objalloc, 1024, mem);
  ngtcp2_objalloc_init(&conn->rtb_entry_objalloc, 1024, mem);
  conn_stat_init(cstat);
  cstat->congestion_recovery_start_ts = UINT64_MAX;
  cstat->first_rtt_sample_ts = UINT64_MAX;
  cstat->smoothed_rtt = 10 * NGTCP2_MILLISECONDS;
  conn->handshake_confirmed_ts = UINT64_MAX;
  ngtcp2_rst_init(&conn->rst);
  ngtcp2_log_init(&conn->log, NULL, NULL, NULL, NULL, 0, NULL);
  ngtcp2_pcg32_init(pcg, 0);
  ngtcp2_cc_bbr_init(bbr, &conn->log, cstat, &conn->rst, 0, pcg);
  conn->pktns.id = NGTCP2_PKTNS_ID_APPLICATION;
  ngtcp2_rtb_init(&conn->pktns.rtb, &conn->rst, &bbr->cc, 0, &conn->log, NULL,
                  &conn->rtb_entry_objalloc, &conn->frc_objalloc, mem);
}

static void free_bbr_test_conn(ngtcp2_conn *conn) {
  ngtcp2_rtb_free(&conn->pktns.rtb);
  ngtcp2_objalloc_free(&conn->rtb_entry_objalloc);
  ngtcp2_objalloc_free(&conn->frc_objalloc);
}

static void check_bbr_spurious_loss(bbr_loss_resolution resolution,
                                    int plateau) {
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_conn conn = {0};
  ngtcp2_pktns hs = {
    .id = NGTCP2_PKTNS_ID_HANDSHAKE,
  };
  ngtcp2_pktns *app = &conn.pktns;
  ngtcp2_conn_stat *cstat = &conn.cstat;
  ngtcp2_cc_bbr bbr;
  ngtcp2_pcg32 pcg;
  ngtcp2_ack ack = {
    .type = NGTCP2_FRAME_ACK,
  };
  ngtcp2_tstamp loss_ts = 20 * NGTCP2_MILLISECONDS;
  ngtcp2_tstamp ack_ts = 21 * NGTCP2_MILLISECONDS;

  init_bbr_test_conn(&conn, &bbr, &pcg);
  ngtcp2_rtb_init(&hs.rtb, &conn.rst, &bbr.cc, 0, &conn.log, NULL,
                  &conn.rtb_entry_objalloc, &conn.frc_objalloc, mem);

  if (plateau) {
    bbr.full_bw = 1000000;
    bbr.full_bw_count = 2;
  } else {
    bbr.state = NGTCP2_BBR_STATE_PROBE_BW_UP;
    bbr.full_bw_reached = 1;
    bbr.check_probe_loss = 1;
  }

  add_bbr_test_pkt(&conn, &hs, 0, 0, 0);
  add_bbr_test_pkt(&conn, app, 0, 0, 0);

  hs.rtb.largest_acked_tx_pkt_num = app->rtb.largest_acked_tx_pkt_num = 3;

  assert_int(0, ==,
             ngtcp2_rtb_detect_lost_pkt(&hs.rtb, &conn, &hs, cstat, loss_ts));
  assert_int(0, ==,
             ngtcp2_rtb_detect_lost_pkt(&app->rtb, &conn, app, cstat, loss_ts));
  assert_size(2, ==, conn.rst.loss_recovery_pending);
  assert_true(bbr.in_loss_recovery);

  if (plateau) {
    assert_uint(NGTCP2_BBR_STATE_NONE, ==, bbr.undo_state);
  } else {
    assert_uint(NGTCP2_BBR_STATE_PROBE_BW_DOWN, ==, bbr.state);
    assert_uint(NGTCP2_BBR_STATE_PROBE_BW_UP, ==, bbr.undo_state);
  }

  switch (resolution) {
  case BBR_LOSS_ACKED_WITH_NEW_LOSS:
  case BBR_LOSS_ACKED:
    assert_int64(
      1, ==,
      ngtcp2_rtb_recv_ack(&hs.rtb, &ack, cstat, &conn, &hs, ack_ts, ack_ts));
    assert_true(bbr.in_loss_recovery);
    assert_size(1, ==, conn.rst.loss_recovery_pending);
    break;
  case BBR_LOSS_EXPIRED:
    ngtcp2_rtb_remove_expired_lost_pkt(&hs.rtb, ack_ts - loss_ts, cstat,
                                       ack_ts);
    break;
  case BBR_LOSS_EVICTED:
    ngtcp2_rtb_remove_excessive_lost_pkt(&hs.rtb, 0, cstat, ack_ts);
    break;
  case BBR_LOSS_DISCARDED:
    ngtcp2_rtb_free(&hs.rtb);
    break;
  }

  if (plateau) {
    assert_uint(NGTCP2_BBR_STATE_STARTUP, !=, bbr.state);
    assert_true(bbr.full_bw_reached);
  }

  if (resolution == BBR_LOSS_ACKED_WITH_NEW_LOSS) {
    /* The ACK for packet 0 also declares packet 1 lost. */
    add_bbr_test_pkt(&conn, app, 1, ack_ts, 0);
    ack_ts += 20 * NGTCP2_MILLISECONDS;
  }

  assert_int64(
    1, ==,
    ngtcp2_rtb_recv_ack(&app->rtb, &ack, cstat, &conn, app, ack_ts, ack_ts));

  if (resolution == BBR_LOSS_ACKED_WITH_NEW_LOSS) {
    assert_true(bbr.in_loss_recovery);
    assert_true(conn.rst.loss_recovery_undo);
    assert_size(1, ==, conn.rst.loss_recovery_pending);

    /* An ACK for a later transmission ends ordinary recovery. */
    add_bbr_test_pkt(&conn, app, 4, ack_ts, 0);
    ack.largest_ack = 4;
    ++ack_ts;

    assert_int64(
      1, ==,
      ngtcp2_rtb_recv_ack(&app->rtb, &ack, cstat, &conn, app, ack_ts, ack_ts));
    assert_false(bbr.in_loss_recovery);
    assert_true(conn.rst.loss_recovery_undo);

    /* The late ACK for packet 1 completes the proof. */
    ack.largest_ack = 1;
    ++ack_ts;

    assert_int64(
      1, ==,
      ngtcp2_rtb_recv_ack(&app->rtb, &ack, cstat, &conn, app, ack_ts, ack_ts));
  }

  assert_false(conn.rst.loss_recovery_undo);

  if (resolution == BBR_LOSS_ACKED ||
      resolution == BBR_LOSS_ACKED_WITH_NEW_LOSS) {
    assert_false(bbr.in_loss_recovery);
    assert_uint64(UINT64_MAX, ==, bbr.inflight_longterm);
    if (plateau) {
      assert_uint(NGTCP2_BBR_STATE_STARTUP, !=, bbr.state);
      assert_true(bbr.full_bw_reached);
    } else if (resolution == BBR_LOSS_ACKED) {
      assert_uint(NGTCP2_BBR_STATE_PROBE_BW_REFILL, ==, bbr.state);
    }
  } else {
    assert_true(bbr.in_loss_recovery);
    assert_uint64(UINT64_MAX, !=, bbr.inflight_longterm);
  }

  if (resolution != BBR_LOSS_DISCARDED) {
    ngtcp2_rtb_free(&hs.rtb);
  }

  free_bbr_test_conn(&conn);
}

void test_ngtcp2_rtb_bbr_spurious_loss(void) {
  check_bbr_spurious_loss(BBR_LOSS_ACKED, 1);
  check_bbr_spurious_loss(BBR_LOSS_ACKED, 0);
  check_bbr_spurious_loss(BBR_LOSS_ACKED_WITH_NEW_LOSS, 0);
  check_bbr_spurious_loss(BBR_LOSS_EXPIRED, 0);
  check_bbr_spurious_loss(BBR_LOSS_EVICTED, 0);
  check_bbr_spurious_loss(BBR_LOSS_DISCARDED, 0);
}

static void check_bbr_ecn_only(ngtcp2_bbr_state state) {
  ngtcp2_conn conn = {0};
  ngtcp2_pktns *app = &conn.pktns;
  ngtcp2_conn_stat *cstat = &conn.cstat;
  ngtcp2_cc_bbr bbr;
  ngtcp2_pcg32 pcg;
  ngtcp2_ack ack = {
    .type = NGTCP2_FRAME_ACK_ECN,
    .ecn.ce = 1,
  };
  ngtcp2_tstamp ack_ts = 20 * NGTCP2_MILLISECONDS;
  uint64_t cap;

  init_bbr_test_conn(&conn, &bbr, &pcg);
  bbr.state = state;
  bbr.full_bw_reached = state == NGTCP2_BBR_STATE_PROBE_BW_UP;
  cap = cstat->cwnd * 7 / 10;

  add_bbr_test_pkt(&conn, app, 0, 0, NGTCP2_RTB_ENTRY_FLAG_ECN);
  add_bbr_test_pkt(&conn, app, 1, NGTCP2_MILLISECONDS,
                   NGTCP2_RTB_ENTRY_FLAG_ECN);

  assert_int64(
    1, ==,
    ngtcp2_rtb_recv_ack(&app->rtb, &ack, cstat, &conn, app, ack_ts, ack_ts));
  assert_uint64(cap, ==, cstat->cwnd);
  assert_uint64(cap, ==, bbr.inflight_shortterm);
  assert_uint(state, ==, bbr.state);
  assert_false(bbr.in_loss_recovery);
  assert_size(0, ==, bbr.loss_events_in_round);

  /* Feedback for a packet sent before the first backoff. */
  ++ack.largest_ack;
  ++ack.ecn.ce;
  ++ack_ts;

  assert_int64(
    1, ==,
    ngtcp2_rtb_recv_ack(&app->rtb, &ack, cstat, &conn, app, ack_ts, ack_ts));
  assert_uint64(cap, ==, cstat->cwnd);

  /* Feedback for a packet sent after the first backoff. */
  add_bbr_test_pkt(&conn, app, 2, ack_ts, NGTCP2_RTB_ENTRY_FLAG_ECN);
  ++ack.largest_ack;
  ++ack.ecn.ce;
  ack_ts += 10 * NGTCP2_MILLISECONDS;

  assert_int64(
    1, ==,
    ngtcp2_rtb_recv_ack(&app->rtb, &ack, cstat, &conn, app, ack_ts, ack_ts));
  cap = cap * 7 / 10;
  assert_uint64(cap, ==, cstat->cwnd);

  /* When the largest ACKed packet is untracked, pace backoffs by RTT. */
  ++app->tx.ecn.ect0;
  ++ack.largest_ack;
  ++ack.ecn.ce;
  ++ack_ts;
  assert_int64(
    0, ==,
    ngtcp2_rtb_recv_ack(&app->rtb, &ack, cstat, &conn, app, ack_ts, ack_ts));
  assert_uint64(cap, ==, cstat->cwnd);

  ++app->tx.ecn.ect0;
  ++ack.largest_ack;
  ++ack.ecn.ce;
  ack_ts += cstat->smoothed_rtt;

  assert_int64(
    0, ==,
    ngtcp2_rtb_recv_ack(&app->rtb, &ack, cstat, &conn, app, ack_ts, ack_ts));
  assert_uint64(4 * cstat->max_tx_udp_payload_size, ==, cstat->cwnd);

  free_bbr_test_conn(&conn);
}

static void check_bbr_ecn_with_loss(void) {
  ngtcp2_conn conn = {0};
  ngtcp2_pktns *app = &conn.pktns;
  ngtcp2_conn_stat *cstat = &conn.cstat;
  ngtcp2_cc_bbr bbr;
  ngtcp2_pcg32 pcg;
  ngtcp2_ack ack = {
    .type = NGTCP2_FRAME_ACK_ECN,
    .largest_ack = 3,
    .ecn.ce = 1,
  };
  ngtcp2_tstamp ack_ts = 20 * NGTCP2_MILLISECONDS;
  uint64_t cap;

  init_bbr_test_conn(&conn, &bbr, &pcg);
  cap = cstat->cwnd * 7 / 10;
  add_bbr_test_pkt(&conn, app, 0, 0, 0);
  add_bbr_test_pkt(&conn, app, 3, NGTCP2_MILLISECONDS,
                   NGTCP2_RTB_ENTRY_FLAG_ECN);

  assert_int64(
    1, ==,
    ngtcp2_rtb_recv_ack(&app->rtb, &ack, cstat, &conn, app, ack_ts, ack_ts));
  assert_size(1, ==, app->rtb.num_lost_pkts);
  assert_true(bbr.in_loss_recovery);
  assert_uint64(cap, ==, cstat->cwnd);
  assert_false(conn.rst.loss_recovery_undo);

  /* The late ACK proves the loss was spurious, but the CE cap remains. */
  ack.largest_ack = 0;
  ++ack_ts;

  assert_int64(
    1, ==,
    ngtcp2_rtb_recv_ack(&app->rtb, &ack, cstat, &conn, app, ack_ts, ack_ts));
  assert_size(0, ==, app->rtb.num_lost_pkts);
  assert_uint64(cap, ==, cstat->cwnd);
  assert_uint64(cap, ==, bbr.inflight_shortterm);

  free_bbr_test_conn(&conn);
}

void test_ngtcp2_rtb_bbr_ecn(void) {
  check_bbr_ecn_only(NGTCP2_BBR_STATE_STARTUP);
  check_bbr_ecn_only(NGTCP2_BBR_STATE_PROBE_BW_UP);
  check_bbr_ecn_with_loss();
}

void test_ngtcp2_rtb_bbr_rtt(void) {
  ngtcp2_conn conn = {0};
  ngtcp2_pktns *app = &conn.pktns;
  ngtcp2_conn_stat *cstat = &conn.cstat;
  ngtcp2_cc_bbr bbr;
  ngtcp2_pcg32 pcg;
  ngtcp2_ack_range range = {.len = 1};
  ngtcp2_ack ack = {
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = 14,
  };
  ngtcp2_tstamp ts = 20 * NGTCP2_MILLISECONDS;

  init_bbr_test_conn(&conn, &bbr, &pcg);
  cstat->min_rtt = UINT64_MAX;
  add_bbr_test_pkt(&conn, app, 10, 9 * NGTCP2_MILLISECONDS,
                   NGTCP2_RTB_ENTRY_FLAG_ACK_ELICITING);
  add_bbr_test_pkt(&conn, app, 11, 9500 * NGTCP2_MICROSECONDS,
                   NGTCP2_RTB_ENTRY_FLAG_ACK_ELICITING);
  add_bbr_test_pkt(&conn, app, 13, 9750 * NGTCP2_MICROSECONDS, 0);
  add_bbr_test_pkt(&conn, app, 14, 10 * NGTCP2_MILLISECONDS, 0);

  assert_int64(1, ==,
               ngtcp2_rtb_recv_ack(&app->rtb, &ack, cstat, &conn, app, ts, ts));
  assert_uint64(UINT64_MAX, ==, bbr.min_rtt);
  assert_uint64(UINT64_MAX, ==, cstat->min_rtt);

  /* Packet 14 was already acknowledged and packet 13 is not
     ACK-eliciting.  BBR samples packet 11 in the next ACK range. */
  ack.first_ack_range = 1;
  ack.rangecnt = 1;
  ack.ranges = &range;
  ts = 24 * NGTCP2_MILLISECONDS;

  assert_int64(3, ==,
               ngtcp2_rtb_recv_ack(&app->rtb, &ack, cstat, &conn, app, ts, ts));
  assert_uint64(14500 * NGTCP2_MICROSECONDS, ==, bbr.min_rtt);
  assert_uint64(UINT64_MAX, ==, cstat->min_rtt);

  /* QUIC samples packet 16 while BBR samples packet 15. */
  add_bbr_test_pkt(&conn, app, 15, 30 * NGTCP2_MILLISECONDS,
                   NGTCP2_RTB_ENTRY_FLAG_ACK_ELICITING);
  add_bbr_test_pkt(&conn, app, 16, 31 * NGTCP2_MILLISECONDS, 0);
  ack.largest_ack = 16;
  ack.rangecnt = 0;
  ts = 38 * NGTCP2_MILLISECONDS;

  assert_int64(2, ==,
               ngtcp2_rtb_recv_ack(&app->rtb, &ack, cstat, &conn, app, ts, ts));
  assert_uint64(8 * NGTCP2_MILLISECONDS, ==, bbr.min_rtt);
  assert_uint64(7 * NGTCP2_MILLISECONDS, ==, cstat->latest_rtt);

  free_bbr_test_conn(&conn);
}

void test_ngtcp2_rtb_bbr_recovery_exit(void) {
  ngtcp2_conn conn = {0};
  ngtcp2_pktns *app = &conn.pktns;
  ngtcp2_conn_stat *cstat = &conn.cstat;
  ngtcp2_cc_bbr bbr;
  ngtcp2_pcg32 pcg;
  ngtcp2_ack ack = {
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = 3,
  };
  ngtcp2_tstamp ts = 20 * NGTCP2_MILLISECONDS;

  init_bbr_test_conn(&conn, &bbr, &pcg);
  add_bbr_test_pkt(&conn, app, 0, 0, NGTCP2_RTB_ENTRY_FLAG_ACK_ELICITING);
  add_bbr_test_pkt(&conn, app, 1, 10 * NGTCP2_MILLISECONDS,
                   NGTCP2_RTB_ENTRY_FLAG_ACK_ELICITING);
  add_bbr_test_pkt(&conn, app, 3, 11 * NGTCP2_MILLISECONDS,
                   NGTCP2_RTB_ENTRY_FLAG_ACK_ELICITING);

  /* Acknowledging packet 3 declares packet 0 lost and starts recovery. */
  assert_int64(1, ==,
               ngtcp2_rtb_recv_ack(&app->rtb, &ack, cstat, &conn, app, ts, ts));
  assert_size(1, ==, app->rtb.num_lost_pkts);
  assert_true(bbr.in_loss_recovery);

  /* Packet 1 was sent before recovery and cannot end it. */
  ack.largest_ack = 1;
  ts = 21 * NGTCP2_MILLISECONDS;

  assert_int64(1, ==,
               ngtcp2_rtb_recv_ack(&app->rtb, &ack, cstat, &conn, app, ts, ts));
  assert_true(bbr.in_loss_recovery);

  /* Packet 4 was sent during recovery.  Packet 5 is untracked. */
  add_bbr_test_pkt(&conn, app, 4, 22 * NGTCP2_MILLISECONDS, 0);
  ack.largest_ack = 5;
  ack.first_ack_range = 1;
  ts = 32 * NGTCP2_MILLISECONDS;

  assert_int64(1, ==,
               ngtcp2_rtb_recv_ack(&app->rtb, &ack, cstat, &conn, app, ts, ts));
  assert_size(1, ==, app->rtb.num_lost_pkts);
  assert_false(bbr.in_loss_recovery);
  assert_uint64(UINT64_MAX, ==, bbr.round_count_at_recovery);

  free_bbr_test_conn(&conn);
}

static void check_bbr_startup_high_loss(ngtcp2_tstamp sent_ts,
                                        ngtcp2_bbr_state expected_state) {
  ngtcp2_conn conn = {0};
  ngtcp2_conn_stat *cstat = &conn.cstat;
  ngtcp2_cc_bbr bbr;
  ngtcp2_pcg32 pcg;
  ngtcp2_cc_ack ack = {
    .bytes_delivered = 1200,
    .pkt_delivered = 10000,
    .largest_pkt_sent_ts = sent_ts,
    .latest_acked_pkt_sent_ts = sent_ts,
    .rtt = 10 * NGTCP2_MILLISECONDS,
    .latest_rtt = 10 * NGTCP2_MILLISECONDS,
  };

  init_bbr_test_conn(&conn, &bbr, &pcg);
  bbr.cc.congestion_event(&bbr.cc, cstat, 80 * NGTCP2_MILLISECONDS, &ack,
                          100 * NGTCP2_MILLISECONDS);

  assert_true(bbr.in_loss_recovery);

  /* A loss-round boundary with enough loss events and a 5% loss rate. */
  bbr.loss_round_delivered = ack.pkt_delivered;
  bbr.loss_events_in_round = 6;
  bbr.min_rtt = ack.latest_rtt;
  conn.rst.delivered = ack.pkt_delivered + ack.bytes_delivered;
  conn.rst.rs.prior_delivered = ack.pkt_delivered;
  conn.rst.rs.delivered = ack.bytes_delivered;
  conn.rst.rs.lost = 1200;
  conn.rst.rs.tx_in_flight = 24000;
  cstat->delivery_rate_sec = 120000;
  cstat->bytes_in_flight = 9600;
  cstat->send_quantum = 2400;

  bbr.cc.on_ack_recv(&bbr.cc, cstat, &ack, sent_ts + ack.latest_rtt);

  assert_true(bbr.loss_round_start);
  assert_uint(expected_state, ==, bbr.state);
  assert_int(expected_state == NGTCP2_BBR_STATE_STARTUP, ==,
             bbr.in_loss_recovery);

  free_bbr_test_conn(&conn);
}

void test_ngtcp2_rtb_bbr_startup_high_loss(void) {
  check_bbr_startup_high_loss(91 * NGTCP2_MILLISECONDS,
                              NGTCP2_BBR_STATE_STARTUP);
  check_bbr_startup_high_loss(100 * NGTCP2_MILLISECONDS,
                              NGTCP2_BBR_STATE_STARTUP);
  check_bbr_startup_high_loss(101 * NGTCP2_MILLISECONDS,
                              NGTCP2_BBR_STATE_DRAIN);
}
