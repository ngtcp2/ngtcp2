/*
 * ngtcp2
 *
 * Copyright (c) 2025 ngtcp2 contributors
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
#include "ngtcp2_conn_info_test.h"

#include <stdio.h>

#include "ngtcp2_conn_info.h"
#include "ngtcp2_test_helper.h"

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_conn_info_init),
  munit_test_end(),
};

const MunitSuite conn_info_suite = {
  .prefix = "/conn_info",
  .tests = tests,
};

void test_ngtcp2_conn_info_init(void) {
  ngtcp2_conn_stat cstat = {
    .latest_rtt = 101 * NGTCP2_MILLISECONDS,
    .min_rtt = 77 * NGTCP2_MILLISECONDS,
    .smoothed_rtt = 85 * NGTCP2_MILLISECONDS,
    .rttvar = 23 * NGTCP2_MILLISECONDS,
    .cwnd = 163840,
    .ssthresh = 190000,
    .bytes_in_flight = 94587,
    .pkt_sent = 101,
    .bytes_sent = 1000000007,
    .pkt_recv = 152345,
    .bytes_recv = 1000000009,
    .pkt_lost = 454666,
    .bytes_lost = 4891244,
    .ping_recv = 90001,
  };
  ngtcp2_conn_info *dest, destbuf = {0};
  size_t destlen =
    offsetof(ngtcp2_conn_info, bytes_in_flight) + sizeof(dest->bytes_in_flight);

  dest = malloc(destlen);

  ngtcp2_conn_info_init_versioned(NGTCP2_CONN_INFO_V1, dest, &cstat);

  memcpy(&destbuf, dest, destlen);
  free(dest);

  assert_uint64(cstat.latest_rtt, ==, destbuf.latest_rtt);
  assert_uint64(cstat.min_rtt, ==, destbuf.min_rtt);
  assert_uint64(cstat.smoothed_rtt, ==, destbuf.smoothed_rtt);
  assert_uint64(cstat.rttvar, ==, destbuf.rttvar);
  assert_uint64(cstat.cwnd, ==, destbuf.cwnd);
  assert_uint64(cstat.ssthresh, ==, destbuf.ssthresh);
  assert_uint64(cstat.bytes_in_flight, ==, destbuf.bytes_in_flight);
  assert_uint64(0, ==, destbuf.pkt_sent);
  assert_uint64(0, ==, destbuf.bytes_sent);
  assert_uint64(0, ==, destbuf.pkt_recv);
  assert_uint64(0, ==, destbuf.bytes_recv);
  assert_uint64(0, ==, destbuf.pkt_lost);
  assert_uint64(0, ==, destbuf.bytes_lost);
  assert_uint64(0, ==, destbuf.ping_recv);

  memset(&destbuf, 0, sizeof(destbuf));

  ngtcp2_conn_info_init_versioned(NGTCP2_CONN_INFO_VERSION, &destbuf, &cstat);

  assert_uint64(cstat.latest_rtt, ==, destbuf.latest_rtt);
  assert_uint64(cstat.min_rtt, ==, destbuf.min_rtt);
  assert_uint64(cstat.smoothed_rtt, ==, destbuf.smoothed_rtt);
  assert_uint64(cstat.rttvar, ==, destbuf.rttvar);
  assert_uint64(cstat.cwnd, ==, destbuf.cwnd);
  assert_uint64(cstat.ssthresh, ==, destbuf.ssthresh);
  assert_uint64(cstat.bytes_in_flight, ==, destbuf.bytes_in_flight);
  assert_uint64(cstat.pkt_sent, ==, destbuf.pkt_sent);
  assert_uint64(cstat.bytes_sent, ==, destbuf.bytes_sent);
  assert_uint64(cstat.pkt_recv, ==, destbuf.pkt_recv);
  assert_uint64(cstat.bytes_recv, ==, destbuf.bytes_recv);
  assert_uint64(cstat.pkt_lost, ==, destbuf.pkt_lost);
  assert_uint64(cstat.bytes_lost, ==, destbuf.bytes_lost);
  assert_uint64(cstat.ping_recv, ==, destbuf.ping_recv);
}
