/*
 * ngtcp2
 *
 * Copyright (c) 2018 ngtcp2 contributors
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
#ifndef NGTCP2_BBR_H
#define NGTCP2_BBR_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <ngtcp2/ngtcp2.h>

#define BBR_BTL_BW_FILTER_LEN 10

/*
 * ngtcp2_bbr_cc is BBR congestion controller, described in
 * https://tools.ietf.org/html/draft-cardwell-iccrg-bbr-congestion-control-00
 */
typedef struct ngtcp2_bbr_cc {
  ngtcp2_cc_base ccb;

  struct {
    /* BBR's estimated bottleneck bandwidth available to the
       transport flow, estimated from the maximum delivery rate sample in a
       sliding window. */
    uint64_t btl_bw;
    /* The max filter used to estimate BBR.BtlBw. */
    uint64_t btl_bw_filter[BBR_BTL_BW_FILTER_LEN];
    /* BBR's estimated two-way round-trip propagation delay of
       the path, estimated from the windowed minimum recent round-trip delay
       sample. */
    uint64_t rt_prop;
    /* The dynamic gain factor used to scale the estimated BDP to produce a
       congestion window (cwnd). */
    double cwnd_gain;
    uint64_t cycle_index;
    uint64_t cycle_stamp;
    /* A boolean that records whether BBR estimates that it has ever fully
       utilized its available bandwidth ("filled the pipe"). */
    uint64_t filled_pipe;
    uint64_t full_bw;
    uint64_t full_bw_count;
    uint64_t idle_restart;
    uint64_t idle_start;
    /* TODO: FIXME: what's the usage of delivered? */
    uint64_t delivered;
    /* packet.delivered value denoting the end of a packet-timed round trip. */
    uint64_t next_round_delivered;
    /* The dynamic gain factor used to scale BBR.BtlBw to
           produce BBR.pacing_rate. */
    double pacing_gain;
    /* The current pacing rate for a BBR flow,
       which controls inter-packet spacing. */
    double pacing_rate;
    uint64_t packet_conservation;
    uint64_t prior_cwnd;
    uint64_t probe_rtt_done_stamp;
    uint64_t probe_rtt_round_done;
    /* Count of packet-timed round trips. */
    uint64_t round_count;
    /* A boolean that BBR sets to true once per packet-timed round trip,
       on ACKs that advance BBR.round_count. */
    uint64_t round_start;
    uint64_t rtprop_expired;
    /* The wall clock time at which the current BBR.RTProp
       sample was obtained. */
    uint64_t rtprop_stamp;
    /* The maximum size of a data aggregate scheduled and
       transmitted together. */
    uint64_t send_quantum;
    uint64_t state;
    /* target_cwnd is the upper bound on the volume of data BBR
       allows in flight. */
    uint64_t target_cwnd;
  } bbr;
  uint64_t packets_lost;
  uint64_t prior_inflight;
  uint64_t next_send_time;
} ngtcp2_bbr_cc;

int ngtcp2_cc_bbr_cc_init(ngtcp2_cc *cc, ngtcp2_log *log,
                          ngtcp2_tstamp initial_ts, const ngtcp2_mem *mem);

void ngtcp2_cc_bbr_cc_free(ngtcp2_cc *cc, const ngtcp2_mem *mem);

void ngtcp2_bbr_cc_init(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp initial_ts,
                        ngtcp2_log *log);

void ngtcp2_bbr_cc_free(ngtcp2_bbr_cc *cc);

void ngtcp2_cc_bbr_cc_on_pkt_acked(ngtcp2_cc *cc, ngtcp2_conn_stat *cstat,
                                   const ngtcp2_cc_pkt *pkt, ngtcp2_tstamp ts);

void ngtcp2_cc_bbr_cc_congestion_event(ngtcp2_cc *cc, ngtcp2_conn_stat *cstat,
                                       ngtcp2_tstamp ts_sent, ngtcp2_tstamp ts);

void ngtcp2_cc_bbr_cc_on_spurious_congestion(ngtcp2_cc *ccx,
                                             ngtcp2_conn_stat *cstat,
                                             ngtcp2_tstamp ts);

void ngtcp2_cc_bbr_cc_on_persistent_congestion(ngtcp2_cc *cc,
                                               ngtcp2_conn_stat *cstat,
                                               ngtcp2_tstamp ts);

void ngtcp2_cc_bbr_cc_on_ack_recv(ngtcp2_cc *cc, ngtcp2_conn_stat *cstat,
                                  ngtcp2_tstamp ts);

void ngtcp2_cc_bbr_cc_on_pkt_sent(ngtcp2_cc *cc, ngtcp2_conn_stat *cstat,
                                  const ngtcp2_cc_pkt *pkt);

void ngtcp2_cc_bbr_cc_new_rtt_sample(ngtcp2_cc *cc, ngtcp2_conn_stat *cstat,
                                     ngtcp2_tstamp ts);

void ngtcp2_cc_bbr_cc_reset(ngtcp2_cc *cc);

void ngtcp2_cc_bbr_cc_event(ngtcp2_cc *cc, ngtcp2_conn_stat *cstat,
                            ngtcp2_cc_event_type event, ngtcp2_tstamp ts);

int ngtcp2_cc_bbr_cc_on_pace_time_to_send(ngtcp2_cc *ccx, ngtcp2_tstamp ts);

#endif /* NGTCP2_CC_H */
