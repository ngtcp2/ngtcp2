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
#include "ngtcp2_cc.h"

#include <assert.h>

#include "ngtcp2_log.h"
#include "ngtcp2_macro.h"
#include "ngtcp2_mem.h"
#include "ngtcp2_rcvry.h"

ngtcp2_cc_pkt *ngtcp2_cc_pkt_init(ngtcp2_cc_pkt *pkt, int64_t pkt_num,
                                  size_t pktlen, ngtcp2_tstamp ts_sent) {
  pkt->pkt_num = pkt_num;
  pkt->pktlen = pktlen;
  pkt->ts_sent = ts_sent;

  return pkt;
}

void ngtcp2_reno_cc_init(ngtcp2_reno_cc *cc, ngtcp2_log *log) {
  cc->ccb.log = log;
  cc->max_delivery_rate = 0.;
  cc->target_cwnd = 0;
}

void ngtcp2_reno_cc_free(ngtcp2_reno_cc *cc) { (void)cc; }

int ngtcp2_cc_reno_cc_init(ngtcp2_cc *cc, ngtcp2_log *log,
                           const ngtcp2_mem *mem) {
  ngtcp2_reno_cc *reno_cc;

  reno_cc = ngtcp2_mem_calloc(mem, 1, sizeof(ngtcp2_reno_cc));
  if (reno_cc == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  ngtcp2_reno_cc_init(reno_cc, log);

  cc->ccb = &reno_cc->ccb;
  cc->on_pkt_acked = ngtcp2_cc_reno_cc_on_pkt_acked;
  cc->congestion_event = ngtcp2_cc_reno_cc_congestion_event;
  cc->on_persistent_congestion = ngtcp2_cc_reno_cc_on_persistent_congestion;
  cc->on_ack_recv = ngtcp2_cc_reno_cc_on_ack_recv;

  return 0;
}

void ngtcp2_cc_reno_cc_free(ngtcp2_cc *cc, const ngtcp2_mem *mem) {
  ngtcp2_reno_cc *reno_cc = ngtcp2_struct_of(cc->ccb, ngtcp2_reno_cc, ccb);

  ngtcp2_reno_cc_free(reno_cc);
  ngtcp2_mem_free(mem, reno_cc);
}

static int in_congestion_recovery(const ngtcp2_conn_stat *cstat,
                                  ngtcp2_tstamp sent_time) {
  return sent_time <= cstat->congestion_recovery_start_ts;
}

void ngtcp2_cc_reno_cc_on_pkt_acked(ngtcp2_cc *ccx, ngtcp2_conn_stat *cstat,
                                    const ngtcp2_cc_pkt *pkt,
                                    ngtcp2_tstamp ts) {
  ngtcp2_reno_cc *cc = ngtcp2_struct_of(ccx->ccb, ngtcp2_reno_cc, ccb);
  (void)ts;

  if (in_congestion_recovery(cstat, pkt->ts_sent)) {
    return;
  }

  if (cc->target_cwnd && cstat->cwnd >= cc->target_cwnd) {
    return;
  }

  if (cstat->cwnd < cstat->ssthresh) {
    cstat->cwnd += pkt->pktlen;
    ngtcp2_log_info(cc->ccb.log, NGTCP2_LOG_EVENT_RCV,
                    "pkn=%" PRId64 " acked, slow start cwnd=%" PRIu64,
                    pkt->pkt_num, cstat->cwnd);
    return;
  }

  cstat->cwnd += cstat->max_packet_size * pkt->pktlen / cstat->cwnd;
}

void ngtcp2_cc_reno_cc_congestion_event(ngtcp2_cc *ccx, ngtcp2_conn_stat *cstat,
                                        ngtcp2_tstamp ts_sent,
                                        ngtcp2_tstamp ts) {
  ngtcp2_reno_cc *cc = ngtcp2_struct_of(ccx->ccb, ngtcp2_reno_cc, ccb);
  uint64_t min_cwnd;

  if (in_congestion_recovery(cstat, ts_sent)) {
    return;
  }

  cstat->congestion_recovery_start_ts = ts;
  cstat->cwnd >>= NGTCP2_LOSS_REDUCTION_FACTOR_BITS;
  min_cwnd = 2 * cstat->max_packet_size;
  cstat->cwnd = ngtcp2_max(cstat->cwnd, min_cwnd);
  cstat->ssthresh = cstat->cwnd;

  ngtcp2_log_info(cc->ccb.log, NGTCP2_LOG_EVENT_RCV,
                  "reduce cwnd because of packet loss cwnd=%" PRIu64,
                  cstat->cwnd);
}

void ngtcp2_cc_reno_cc_on_persistent_congestion(ngtcp2_cc *ccx,
                                                ngtcp2_conn_stat *cstat,
                                                ngtcp2_tstamp ts) {
  (void)ccx;
  (void)ts;

  cstat->cwnd = 2 * cstat->max_packet_size;
}

void ngtcp2_cc_reno_cc_on_ack_recv(ngtcp2_cc *ccx, ngtcp2_conn_stat *cstat,
                                   ngtcp2_tstamp ts) {
  ngtcp2_reno_cc *cc = ngtcp2_struct_of(ccx->ccb, ngtcp2_reno_cc, ccb);
  uint64_t target_cwnd, min_cwnd;
  (void)ts;

  /* TODO Use sliding window for min rtt measurement */
  /* TODO Use sliding window */
  cc->max_delivery_rate =
      ngtcp2_max(cc->max_delivery_rate, cstat->delivery_rate);

  if (cstat->min_rtt != UINT64_MAX && cc->max_delivery_rate > 1e-9) {
    target_cwnd =
        (uint64_t)(2.89 * cc->max_delivery_rate * (double)cstat->min_rtt);
    min_cwnd = 2 * cstat->max_packet_size;
    cc->target_cwnd = ngtcp2_max(min_cwnd, target_cwnd);

    ngtcp2_log_info(
        cc->ccb.log, NGTCP2_LOG_EVENT_RCV,
        "target_cwnd=%" PRIu64 " max_delivery_rate=%.02f min_rtt=%" PRIu64,
        cc->target_cwnd, cc->max_delivery_rate * 1000000000, cstat->min_rtt);
  }
}

void ngtcp2_cubic_cc_init(ngtcp2_cubic_cc *cc, ngtcp2_log *log) {
  cc->ccb.log = log;
  cc->max_delivery_rate = 0.;
  cc->target_cwnd = 0;
  cc->k = 0;
  cc->w_last_max = 0;
  cc->w_tcp = 0;
  cc->epoch_start = 0;
  cc->origin_point = 0;
}

void ngtcp2_cubic_cc_free(ngtcp2_cubic_cc *cc) { (void)cc; }

int ngtcp2_cc_cubic_cc_init(ngtcp2_cc *cc, ngtcp2_log *log,
                            const ngtcp2_mem *mem) {
  ngtcp2_cubic_cc *cubic_cc;

  cubic_cc = ngtcp2_mem_calloc(mem, 1, sizeof(ngtcp2_cubic_cc));
  if (cubic_cc == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  ngtcp2_cubic_cc_init(cubic_cc, log);

  cc->ccb = &cubic_cc->ccb;
  cc->on_pkt_acked = ngtcp2_cc_cubic_cc_on_pkt_acked;
  cc->congestion_event = ngtcp2_cc_cubic_cc_congestion_event;
  cc->on_persistent_congestion = ngtcp2_cc_cubic_cc_on_persistent_congestion;
  cc->on_ack_recv = ngtcp2_cc_cubic_cc_on_ack_recv;
  cc->event = ngtcp2_cc_cubic_cc_event;

  return 0;
}

void ngtcp2_cc_cubic_cc_free(ngtcp2_cc *cc, const ngtcp2_mem *mem) {
  ngtcp2_cubic_cc *cubic_cc = ngtcp2_struct_of(cc->ccb, ngtcp2_cubic_cc, ccb);

  ngtcp2_cubic_cc_free(cubic_cc);
  ngtcp2_mem_free(mem, cubic_cc);
}

static uint64_t ngtcp2_cbrt(uint64_t n) {
  int d = __builtin_clzll(n);
  uint64_t a = 1ULL << ((64 - d) / 3 + 1);
  int i;
  for (i = 0; a * a * a > n; ++i) {
    a = (2 * a + n / a / a) / 3;
  }
  return a;
}

void ngtcp2_cc_cubic_cc_on_pkt_acked(ngtcp2_cc *ccx, ngtcp2_conn_stat *cstat,
                                     const ngtcp2_cc_pkt *pkt,
                                     ngtcp2_tstamp ts) {
  ngtcp2_cubic_cc *cc = ngtcp2_struct_of(ccx->ccb, ngtcp2_cubic_cc, ccb);
  ngtcp2_duration t, min_rtt;
  uint64_t target, cwnd;
  int64_t d;
  (void)ts;

  if (in_congestion_recovery(cstat, pkt->ts_sent)) {
    return;
  }

  if (cc->target_cwnd && cstat->cwnd >= cc->target_cwnd) {
    return;
  }

  if (cstat->cwnd < cstat->ssthresh) {
    /* slow-start */
    cstat->cwnd += pkt->pktlen;
    ngtcp2_log_info(cc->ccb.log, NGTCP2_LOG_EVENT_RCV,
                    "pkn=%" PRId64 " acked, slow start cwnd=%" PRIu64,
                    pkt->pkt_num, cstat->cwnd);
    return;
  }

  /* congestion avoidance */

  if (cc->epoch_start == 0) {
    cc->epoch_start = ts;
    if (cstat->cwnd < cc->w_last_max) {
      cc->k = ngtcp2_cbrt((cc->w_last_max - cstat->cwnd) * 10 / 4 /
                          cstat->max_packet_size);
      cc->origin_point = cc->w_last_max;
    } else {
      cc->k = 0;
      cc->origin_point = cstat->cwnd;
    }

    cc->w_tcp = cstat->cwnd;

    ngtcp2_log_info(cc->ccb.log, NGTCP2_LOG_EVENT_RCV,
                    "cubic-ca epoch_start=%" PRIu64 " k=%" PRIu64
                    " origin_point=%" PRIu64,
                    cc->epoch_start, cc->k, cc->origin_point);
  }

  min_rtt = cstat->min_rtt == UINT64_MAX ? NGTCP2_DEFAULT_INITIAL_RTT
                                         : cstat->min_rtt;

  t = ts + min_rtt - cc->epoch_start;
  d = (int64_t)((t << 8) / NGTCP2_SECONDS) - (int64_t)(cc->k << 4);
  target = (uint64_t)((int64_t)cc->origin_point +
                      (int64_t)cstat->max_packet_size *
                          ((((d * d) >> 4) * d) >> 8) * 4 / 10);
  cwnd = cstat->cwnd;

  if (target > cstat->cwnd) {
    cstat->cwnd +=
        cstat->max_packet_size * (target - cstat->cwnd) / cstat->cwnd;
  } else {
    /* TODO too small, no increment at all */
    cstat->cwnd += cstat->max_packet_size / (100 * cstat->cwnd);
  }

  cc->w_tcp += cstat->max_packet_size * pkt->pktlen * 9 / 17 / cwnd;

  if (cc->w_tcp > cwnd && cc->w_tcp > target) {
    cstat->cwnd = cwnd + cstat->max_packet_size * (cc->w_tcp - cwnd) / cwnd;
  }

  ngtcp2_log_info(cc->ccb.log, NGTCP2_LOG_EVENT_RCV,
                  "pkn=%" PRId64 " acked, cubic-ca cwnd=%" PRIu64 " t=%" PRIu64
                  " d=%" PRId64 " target=%" PRIu64 " w_tcp=%" PRIu64,
                  pkt->pkt_num, cstat->cwnd, t, d, target, cc->w_tcp);
}

void ngtcp2_cc_cubic_cc_congestion_event(ngtcp2_cc *ccx,
                                         ngtcp2_conn_stat *cstat,
                                         ngtcp2_tstamp ts_sent,
                                         ngtcp2_tstamp ts) {
  ngtcp2_cubic_cc *cc = ngtcp2_struct_of(ccx->ccb, ngtcp2_cubic_cc, ccb);
  uint64_t min_cwnd;

  if (in_congestion_recovery(cstat, ts_sent)) {
    return;
  }

  cstat->congestion_recovery_start_ts = ts;

  cc->epoch_start = 0;
  if (cstat->cwnd < cc->w_last_max) {
    cc->w_last_max = cstat->cwnd * 17 / 10 / 2;
  } else {
    cc->w_last_max = cstat->cwnd;
  }

  min_cwnd = 2 * cstat->max_packet_size;
  cstat->ssthresh = cstat->cwnd * 7 / 10;
  cstat->ssthresh = ngtcp2_max(cstat->ssthresh, min_cwnd);
  cstat->cwnd = cstat->ssthresh;

  ngtcp2_log_info(cc->ccb.log, NGTCP2_LOG_EVENT_RCV,
                  "reduce cwnd because of packet loss cwnd=%" PRIu64,
                  cstat->cwnd);
}

void ngtcp2_cc_cubic_cc_on_persistent_congestion(ngtcp2_cc *ccx,
                                                 ngtcp2_conn_stat *cstat,
                                                 ngtcp2_tstamp ts) {
  (void)ccx;
  (void)ts;

  cstat->cwnd = 2 * cstat->max_packet_size;
}

void ngtcp2_cc_cubic_cc_on_ack_recv(ngtcp2_cc *ccx, ngtcp2_conn_stat *cstat,
                                    ngtcp2_tstamp ts) {
  ngtcp2_cubic_cc *cc = ngtcp2_struct_of(ccx->ccb, ngtcp2_cubic_cc, ccb);
  uint64_t target_cwnd, min_cwnd;
  (void)ts;

  /* TODO Use sliding window for min rtt measurement */
  /* TODO Use sliding window */
  cc->max_delivery_rate =
      ngtcp2_max(cc->max_delivery_rate, cstat->delivery_rate);

  if (cstat->min_rtt != UINT64_MAX && cc->max_delivery_rate > 1e-9) {
    target_cwnd =
        (uint64_t)(2.89 * cc->max_delivery_rate * (double)cstat->min_rtt);

    min_cwnd = 2 * cstat->max_packet_size;
    cc->target_cwnd = ngtcp2_max(min_cwnd, target_cwnd);

    ngtcp2_log_info(
        cc->ccb.log, NGTCP2_LOG_EVENT_RCV,
        "target_cwnd=%" PRIu64 " max_delivery_rate=%.02f min_rtt=%" PRIu64,
        cc->target_cwnd, cc->max_delivery_rate * 1000000000, cstat->min_rtt);
  }
}

void ngtcp2_cc_cubic_cc_event(ngtcp2_cc *ccx, ngtcp2_conn_stat *cstat,
                              ngtcp2_cc_event_type event, ngtcp2_tstamp ts) {
  ngtcp2_cubic_cc *cc = ngtcp2_struct_of(ccx->ccb, ngtcp2_cubic_cc, ccb);
  ngtcp2_tstamp last_ts;

  if (event != NGTCP2_CC_EVENT_TYPE_TX_START || cc->epoch_start == 0) {
    return;
  }

  last_ts = cstat->last_tx_pkt_ts[NGTCP2_PKTNS_ID_APP];
  if (last_ts == UINT64_MAX) {
    return;
  }

  assert(ts >= last_ts);

  cc->epoch_start += ts - last_ts;
}
