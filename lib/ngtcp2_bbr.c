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
 * the following conditions
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
#include "ngtcp2_bbr.h"

#include <assert.h>

#if defined(_MSC_VER)
#  include <intrin.h>
#endif

#include "ngtcp2_log.h"
#include "ngtcp2_macro.h"
#include "ngtcp2_mem.h"
#include "ngtcp2_rcvry.h"

#define BBRGainCycleLen 8
static const double pacing_gain_cycle[BBRGainCycleLen] = {5 / 4, 3 / 4, 1, 1,
                                                       1,     1,     1, 1};
#define BBRHighGain 2.89
#define ProbeRTTDuration (200*NGTCP2_MILLISECONDS)
#define RTpropFilterLen (10*NGTCP2_SECONDS)
#define MSS 1500
#define BBRMinPipeCwnd (4*MSS)
#define InitialCwnd (10*MSS)

typedef enum {
  Startup = 0,
  Drain = 1,
  ProbeBW = 2,
  ProbeRTT = 3,
} BBRState;

void BBROnConnectionInit(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp initial_ts);
void BBRUpdateOnACK(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                    const ngtcp2_cc_pkt *pkt, ngtcp2_tstamp ts);
void BBRUpdateModelAndState(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                            const ngtcp2_cc_pkt *pkt, ngtcp2_tstamp ts);
void BBRUpdateControlParameters(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat);
void BBROnTransmit(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat);
void BBRInitRoundCounting(ngtcp2_bbr_cc *bbr_cc);
void BBRUpdateRound(ngtcp2_bbr_cc *bbr_cc, const ngtcp2_cc_pkt *pkt);
void BBRUpdateBtlBw(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                    const ngtcp2_cc_pkt *pkt);
void BBRUpdateRTprop(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                     ngtcp2_tstamp ts);
void BBRInitPacingRate(ngtcp2_bbr_cc *bbr_cc);
void BBRSetPacingRateWithGain(ngtcp2_bbr_cc *bbr_cc, uint64_t pacing_gain);
void BBRSetPacingRate(ngtcp2_bbr_cc *bbr_cc);
void BBRSetSendQuantum(ngtcp2_bbr_cc *bbr_cc);
void BBRUpdateTargetCwnd(ngtcp2_bbr_cc *bbr_cc);
void BBRModulateCwndForRecovery(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat);
uint64_t BBRSaveCwnd(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat);
void BBRRestoreCwnd(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat);
void BBRModulateCwndForProbeRTT(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat);
void BBRSetCwnd(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat);
void BBRInit(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp initial_ts);
void BBREnterStartup(ngtcp2_bbr_cc *bbr_cc);
void BBRInitFullPipe(ngtcp2_bbr_cc *bbr_cc);
void BBRCheckFullPipe(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                      const ngtcp2_cc_pkt *pkt);
void BBREnterDrain(ngtcp2_bbr_cc *bbr_cc);
void BBRCheckDrain(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                   ngtcp2_tstamp ts);
void BBREnterProbeBW(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp ts);
void BBRCheckCyclePhase(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp ts);
void BBRAdvanceCyclePhase(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp ts);
int BBRIsNextCyclePhase(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp ts);
void BBRHandleRestartFromIdle(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat);
void BBRCheckProbeRTT(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                      ngtcp2_tstamp ts);
void BBREnterProbeRTT(ngtcp2_bbr_cc *bbr_cc);
void BBRHandleProbeRTT(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                       ngtcp2_tstamp ts);
void BBRExitProbeRTT(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp ts);

static void bbr_cc_reset(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp initial_ts) {
  BBROnConnectionInit(bbr_cc, initial_ts);
}

void ngtcp2_bbr_cc_init(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp initial_ts,
                        ngtcp2_log *log) {
  bbr_cc->ccb.log = log;
  bbr_cc_reset(bbr_cc, initial_ts);
}

void ngtcp2_bbr_cc_free(ngtcp2_bbr_cc *bbr_cc) { (void)bbr_cc; }

int ngtcp2_cc_bbr_cc_init(ngtcp2_cc *cc, ngtcp2_log *log,
                          ngtcp2_tstamp initial_ts, const ngtcp2_mem *mem) {
  ngtcp2_bbr_cc *bbr_cc;

  bbr_cc = ngtcp2_mem_calloc(mem, 1, sizeof(ngtcp2_bbr_cc));
  if (bbr_cc == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  ngtcp2_bbr_cc_init(bbr_cc, initial_ts, log);

  cc->ccb = &bbr_cc->ccb;
  cc->on_pkt_acked = ngtcp2_cc_bbr_cc_on_pkt_acked;
  cc->congestion_event = ngtcp2_cc_bbr_cc_congestion_event;
  cc->on_spurious_congestion = ngtcp2_cc_bbr_cc_on_spurious_congestion;
  cc->on_persistent_congestion = ngtcp2_cc_bbr_cc_on_persistent_congestion;
  cc->on_ack_recv = ngtcp2_cc_bbr_cc_on_ack_recv;
  cc->on_pkt_sent = ngtcp2_cc_bbr_cc_on_pkt_sent;
  cc->new_rtt_sample = ngtcp2_cc_bbr_cc_new_rtt_sample;
  cc->reset = ngtcp2_cc_bbr_cc_reset;
  cc->event = ngtcp2_cc_bbr_cc_event;

  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_RCV, "bbr cc init");

  return 0;
}

void ngtcp2_cc_bbr_cc_free(ngtcp2_cc *cc, const ngtcp2_mem *mem) {
  ngtcp2_bbr_cc *bbr_cc = ngtcp2_struct_of(cc->ccb, ngtcp2_bbr_cc, ccb);

  ngtcp2_bbr_cc_free(bbr_cc);
  ngtcp2_mem_free(mem, bbr_cc);
}

void ngtcp2_cc_bbr_cc_on_pkt_acked(ngtcp2_cc *ccx, ngtcp2_conn_stat *cstat,
                                   const ngtcp2_cc_pkt *pkt, ngtcp2_tstamp ts) {
  ngtcp2_bbr_cc *bbr_cc = ngtcp2_struct_of(ccx->ccb, ngtcp2_bbr_cc, ccb);
  bbr_cc->packets_delivered += pkt->pktlen;

  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_RCV,
                  "bbr cc pkn=%" PRId64 " acked, slow start cwnd=%" PRIu64,
                  pkt->pkt_num, cstat->cwnd);

  BBRUpdateOnACK(bbr_cc, cstat, pkt, ts);
  bbr_cc->prior_inflight = cstat->bytes_in_flight;
}

void ngtcp2_cc_bbr_cc_congestion_event(ngtcp2_cc *ccx, ngtcp2_conn_stat *cstat,
                                       ngtcp2_tstamp ts_sent,
                                       ngtcp2_tstamp ts) {
  ngtcp2_bbr_cc *bbr_cc = ngtcp2_struct_of(ccx->ccb, ngtcp2_bbr_cc, ccb);

  bbr_cc->BBR.prior_cwnd = BBRSaveCwnd(bbr_cc, cstat);
  cstat->cwnd =
      cstat->bytes_in_flight + ngtcp2_max(bbr_cc->packets_delivered, 1);
  bbr_cc->BBR.packet_conservation = 1;
}

void ngtcp2_cc_bbr_cc_on_spurious_congestion(ngtcp2_cc *ccx,
                                             ngtcp2_conn_stat *cstat,
                                             ngtcp2_tstamp ts) {
  ngtcp2_bbr_cc *bbr_cc = ngtcp2_struct_of(ccx->ccb, ngtcp2_bbr_cc, ccb);
}

void ngtcp2_cc_bbr_cc_on_persistent_congestion(ngtcp2_cc *ccx,
                                               ngtcp2_conn_stat *cstat,
                                               ngtcp2_tstamp ts) {}

void ngtcp2_cc_bbr_cc_on_ack_recv(ngtcp2_cc *ccx, ngtcp2_conn_stat *cstat,
                                  ngtcp2_tstamp ts) {
  ngtcp2_bbr_cc *bbr_cc = ngtcp2_struct_of(ccx->ccb, ngtcp2_bbr_cc, ccb);
}

void ngtcp2_cc_bbr_cc_on_pkt_sent(ngtcp2_cc *ccx, ngtcp2_conn_stat *cstat,
                                  const ngtcp2_cc_pkt *pkt) {
  ngtcp2_bbr_cc *bbr_cc = ngtcp2_struct_of(ccx->ccb, ngtcp2_bbr_cc, ccb);
  BBROnTransmit(bbr_cc, cstat);
}

void ngtcp2_cc_bbr_cc_new_rtt_sample(ngtcp2_cc *ccx, ngtcp2_conn_stat *cstat,
                                     ngtcp2_tstamp ts) {
  ngtcp2_bbr_cc *bbr_cc = ngtcp2_struct_of(ccx->ccb, ngtcp2_bbr_cc, ccb);
}

void ngtcp2_cc_bbr_cc_reset(ngtcp2_cc *ccx) {
  ngtcp2_bbr_cc *bbr_cc = ngtcp2_struct_of(ccx->ccb, ngtcp2_bbr_cc, ccb);
  bbr_cc_reset(bbr_cc, 0);
}

void ngtcp2_cc_bbr_cc_event(ngtcp2_cc *ccx, ngtcp2_conn_stat *cstat,
                            ngtcp2_cc_event_type event, ngtcp2_tstamp ts) {
  ngtcp2_bbr_cc *bbr_cc = ngtcp2_struct_of(ccx->ccb, ngtcp2_bbr_cc, ccb);
}

void BBROnConnectionInit(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp initial_ts) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  BBRInit(bbr_cc, initial_ts);
}

void BBRUpdateOnACK(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                    const ngtcp2_cc_pkt *pkt, ngtcp2_tstamp ts) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  BBRUpdateModelAndState(bbr_cc, cstat, pkt, ts);
  BBRUpdateControlParameters(bbr_cc, cstat);
}

void BBRUpdateModelAndState(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                            const ngtcp2_cc_pkt *pkt, ngtcp2_tstamp ts) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  BBRUpdateBtlBw(bbr_cc, cstat, pkt);
  BBRCheckCyclePhase(bbr_cc, ts);
  BBRCheckFullPipe(bbr_cc, cstat, pkt);
  BBRCheckDrain(bbr_cc, cstat, ts);
  BBRUpdateRTprop(bbr_cc, cstat, ts);
  BBRCheckProbeRTT(bbr_cc, cstat, ts);
}

void BBRUpdateControlParameters(ngtcp2_bbr_cc *bbr_cc,
                                ngtcp2_conn_stat *cstat) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  BBRSetPacingRate(bbr_cc);
  BBRSetSendQuantum(bbr_cc);
  BBRSetCwnd(bbr_cc, cstat);
}

void BBROnTransmit(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  BBRHandleRestartFromIdle(bbr_cc, cstat);
}

void BBRInitRoundCounting(ngtcp2_bbr_cc *bbr_cc) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  bbr_cc->BBR.next_round_delivered = 0;
  bbr_cc->BBR.round_start = 0;
  bbr_cc->BBR.round_count = 0;
}

void BBRUpdateRound(ngtcp2_bbr_cc *bbr_cc, const ngtcp2_cc_pkt *pkt) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  bbr_cc->BBR.delivered += pkt->pktlen;
  if (pkt->delivered >= bbr_cc->BBR.next_round_delivered) {
    bbr_cc->BBR.next_round_delivered = bbr_cc->BBR.delivered;
    bbr_cc->BBR.round_count++;
    bbr_cc->BBR.round_start = 1;
  } else {
    bbr_cc->BBR.round_start = 0;
  }
}

void BBRUpdateBtlBw(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                    const ngtcp2_cc_pkt *pkt) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  BBRUpdateRound(bbr_cc, pkt);
  if (cstat->delivery_rate_sec >= bbr_cc->BBR.BtlBw || !pkt->is_app_limited) {
    int i;
    for (i = 0; i < BtlBwFilterLen - 1; ++i) {
      double bw = bbr_cc->BBR.BtlBwFilter[i];
      bbr_cc->BBR.BtlBwFilter[i + 1] = bw;
      bbr_cc->BBR.BtlBw = ngtcp2_max(bw, bbr_cc->BBR.BtlBw);
    }
    bbr_cc->BBR.BtlBwFilter[0] = cstat->delivery_rate_sec;
    bbr_cc->BBR.BtlBw = ngtcp2_max(cstat->delivery_rate_sec, bbr_cc->BBR.BtlBw);
  }
}

void BBRUpdateRTprop(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                     ngtcp2_tstamp ts) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  bbr_cc->BBR.rtprop_expired = ts > bbr_cc->BBR.rtprop_stamp + RTpropFilterLen;
  if (cstat->latest_rtt >= 0 &&
      (cstat->latest_rtt <= bbr_cc->BBR.RTprop || bbr_cc->BBR.rtprop_expired)) {
    bbr_cc->BBR.RTprop = cstat->latest_rtt;
    ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE,
                    "BBR Trace # RTprop=%lu", bbr_cc->BBR.RTprop);
    bbr_cc->BBR.rtprop_stamp = ts;
  }
}

void BBRInitPacingRate(ngtcp2_bbr_cc *bbr_cc) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  uint64_t nominal_bandwidth = InitialCwnd / (1 * NGTCP2_MILLISECONDS);
  bbr_cc->BBR.pacing_rate = bbr_cc->BBR.pacing_gain * nominal_bandwidth;
}

void BBRSetPacingRateWithGain(ngtcp2_bbr_cc *bbr_cc, uint64_t pacing_gain) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  uint64_t rate = pacing_gain * bbr_cc->BBR.BtlBw;
  if (bbr_cc->BBR.filled_pipe || rate > bbr_cc->BBR.pacing_rate) {
    bbr_cc->BBR.pacing_rate = rate;
  }
}

void BBRSetPacingRate(ngtcp2_bbr_cc *bbr_cc) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  BBRSetPacingRateWithGain(bbr_cc, bbr_cc->BBR.pacing_gain);
}

void BBRSetSendQuantum(ngtcp2_bbr_cc *bbr_cc) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  if (bbr_cc->BBR.pacing_rate < 1.2 * 1024 * 1024) {
    bbr_cc->BBR.send_quantum = 1 * MSS;
  } else if (bbr_cc->BBR.pacing_rate < 24 * 1024 * 1024) {
    bbr_cc->BBR.send_quantum = 2 * MSS;
  } else {
    bbr_cc->BBR.send_quantum = ngtcp2_min(
        bbr_cc->BBR.pacing_rate * 1 * NGTCP2_MILLISECONDS, 64 * 1024 * 8);
  }
}

uint64_t BBRInflight(ngtcp2_bbr_cc *bbr_cc, uint64_t gain) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  if (bbr_cc->BBR.RTprop == UINT64_MAX) {
    return InitialCwnd; /* no valid RTT samples yet */
  }
  uint64_t quanta = 3 * bbr_cc->BBR.send_quantum;
  uint64_t estimated_bdp =
      bbr_cc->BBR.BtlBw * bbr_cc->BBR.RTprop / NGTCP2_SECONDS;
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE,
                  "BBR Trace # send_quantum=%lu, BtlBw=%lu, RTprop=%lu, "
                  "gain=%u, estimated_bdp=%u",
                  bbr_cc->BBR.send_quantum, bbr_cc->BBR.BtlBw,
                  bbr_cc->BBR.RTprop, gain, estimated_bdp);
  return gain * estimated_bdp + quanta;
}

void BBRUpdateTargetCwnd(ngtcp2_bbr_cc *bbr_cc) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  bbr_cc->BBR.target_cwnd = BBRInflight(bbr_cc, bbr_cc->BBR.cwnd_gain);
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE,
                  "BBR Trace # target_cwnd=%lu", bbr_cc->BBR.target_cwnd);
}

void BBRModulateCwndForRecovery(ngtcp2_bbr_cc *bbr_cc,
                                ngtcp2_conn_stat *cstat) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  if (bbr_cc->packets_lost > 0) {
    cstat->cwnd = ngtcp2_max(cstat->cwnd - bbr_cc->packets_lost, 1);
  }

  if (bbr_cc->BBR.packet_conservation) {
    cstat->cwnd = ngtcp2_max(cstat->cwnd, cstat->bytes_in_flight +
                                              bbr_cc->packets_delivered);
  }
}

uint64_t BBRSaveCwnd(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  if (!bbr_cc->BBR.packet_conservation && bbr_cc->BBR.state != ProbeRTT) {
    return cstat->cwnd;
  } else {
    return ngtcp2_max(bbr_cc->BBR.prior_cwnd, cstat->cwnd);
  }
}
void BBRRestoreCwnd(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  cstat->cwnd = ngtcp2_max(cstat->cwnd, bbr_cc->BBR.prior_cwnd);
}

void BBRModulateCwndForProbeRTT(ngtcp2_bbr_cc *bbr_cc,
                                ngtcp2_conn_stat *cstat) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  if (bbr_cc->BBR.state == ProbeRTT) {
    cstat->cwnd = ngtcp2_min(cstat->cwnd, BBRMinPipeCwnd);
  }
}

void BBRSetCwnd(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  BBRUpdateTargetCwnd(bbr_cc);
  BBRModulateCwndForRecovery(bbr_cc, cstat);
  if (!bbr_cc->BBR.packet_conservation) {
    if (bbr_cc->BBR.filled_pipe) {
      cstat->cwnd = ngtcp2_min(cstat->cwnd + bbr_cc->packets_delivered,
                               bbr_cc->BBR.target_cwnd);
      ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE,
                      "BBR Trace # %s:%d", __func__, __LINE__);
    } else if (cstat->cwnd < bbr_cc->BBR.target_cwnd ||
               bbr_cc->BBR.delivered < InitialCwnd) {
      cstat->cwnd = cstat->cwnd + bbr_cc->packets_delivered;
      ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE,
                      "BBR Trace # %s:%d", __func__, __LINE__);
    }

    ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE,
                    "BBR Trace # cwnd=%u", cstat->cwnd);
    cstat->cwnd = ngtcp2_max(cstat->cwnd, BBRMinPipeCwnd);
  }
  BBRModulateCwndForProbeRTT(bbr_cc, cstat);
}

void BBRInit(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp initial_ts) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  int i;
  for (i = 0; i < BtlBwFilterLen; ++i) {
    bbr_cc->BBR.BtlBwFilter[i] = 0;
  }
  bbr_cc->BBR.RTprop = UINT64_MAX;
  bbr_cc->BBR.rtprop_stamp = initial_ts;
  bbr_cc->BBR.probe_rtt_done_stamp = 0;
  bbr_cc->BBR.probe_rtt_round_done = 0;
  bbr_cc->BBR.packet_conservation = 0;
  bbr_cc->BBR.prior_cwnd = 0;
  bbr_cc->BBR.idle_restart = 0;

  bbr_cc->packets_delivered = 0;
  bbr_cc->packets_lost = 0;
  bbr_cc->prior_inflight = 0;

  BBRInitRoundCounting(bbr_cc);
  BBRInitFullPipe(bbr_cc);
  BBRInitPacingRate(bbr_cc);
  BBREnterStartup(bbr_cc);
}

void BBREnterStartup(ngtcp2_bbr_cc *bbr_cc) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  bbr_cc->BBR.state = Startup;
  bbr_cc->BBR.pacing_gain = BBRHighGain;
  bbr_cc->BBR.cwnd_gain = BBRHighGain;
}

void BBRInitFullPipe(ngtcp2_bbr_cc *bbr_cc) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  bbr_cc->BBR.filled_pipe = 0;
  bbr_cc->BBR.full_bw = 0;
  bbr_cc->BBR.full_bw_count = 0;
}

void BBRCheckFullPipe(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                      const ngtcp2_cc_pkt *pkt) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  if (bbr_cc->BBR.filled_pipe || !bbr_cc->BBR.round_start ||
      pkt->is_app_limited) {
    return; // no need to check for a full pipe now
  }
  if (bbr_cc->BBR.BtlBw >=
      bbr_cc->BBR.full_bw * 1.25) {          // bbr_cc->BBR.BtlBw still growing?
    bbr_cc->BBR.full_bw = bbr_cc->BBR.BtlBw; // record new baseline level
    bbr_cc->BBR.full_bw_count = 0;
    return;
  }
  bbr_cc->BBR.full_bw_count++; // another round w/o much growth
  if (bbr_cc->BBR.full_bw_count >= 3) {
    bbr_cc->BBR.filled_pipe = 1;
  }
}

void BBREnterDrain(ngtcp2_bbr_cc *bbr_cc) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  bbr_cc->BBR.state = Drain;
  bbr_cc->BBR.pacing_gain = 1 / BBRHighGain; // pace slowly
  bbr_cc->BBR.cwnd_gain = BBRHighGain;       // maintain cwnd
}

void BBRCheckDrain(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                   ngtcp2_tstamp ts) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  if (bbr_cc->BBR.state == Startup && bbr_cc->BBR.filled_pipe) {
    BBREnterDrain(bbr_cc);
  }

  if (bbr_cc->BBR.state == Drain &&
      cstat->bytes_in_flight <= BBRInflight(bbr_cc, 1.0)) {
    BBREnterProbeBW(bbr_cc, ts); // we estimate queue is drained
  }
}

void BBREnterProbeBW(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp ts) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  bbr_cc->BBR.state = ProbeBW;
  bbr_cc->BBR.pacing_gain = 1;
  bbr_cc->BBR.cwnd_gain = 2;
  bbr_cc->BBR.cycle_index = BBRGainCycleLen - 1 - (random() % 7);
  BBRAdvanceCyclePhase(bbr_cc, ts);
}

void BBRCheckCyclePhase(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp ts) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  if (bbr_cc->BBR.state == ProbeBW && BBRIsNextCyclePhase(bbr_cc, ts)) {
    BBRAdvanceCyclePhase(bbr_cc, ts);
  }
}

void BBRAdvanceCyclePhase(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp ts) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  bbr_cc->BBR.cycle_stamp = ts;
  bbr_cc->BBR.cycle_index = (bbr_cc->BBR.cycle_index + 1) % BBRGainCycleLen;
  bbr_cc->BBR.pacing_gain = pacing_gain_cycle[bbr_cc->BBR.cycle_index];
}

int BBRIsNextCyclePhase(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp ts) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  int is_full_length = (ts - bbr_cc->BBR.cycle_stamp) > bbr_cc->BBR.RTprop;
  if (bbr_cc->BBR.pacing_gain == 1) {
    return is_full_length;
  }
  if (bbr_cc->BBR.pacing_gain > 1) {
    return is_full_length && (bbr_cc->packets_lost > 0 ||
                              bbr_cc->prior_inflight >=
                                  BBRInflight(bbr_cc, bbr_cc->BBR.pacing_gain));
  } else {
    return is_full_length || bbr_cc->prior_inflight <= BBRInflight(bbr_cc, 1);
  }
}

void BBRHandleRestartFromIdle(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  if (cstat->bytes_in_flight == 0 && cstat->app_limited) {
    bbr_cc->BBR.idle_start = 1;
    if (bbr_cc->BBR.state == ProbeBW) {
      BBRSetPacingRateWithGain(bbr_cc, 1);
    }
  }
}

void BBRCheckProbeRTT(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                      ngtcp2_tstamp ts) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  if (bbr_cc->BBR.state != ProbeRTT && bbr_cc->BBR.rtprop_expired &&
      !bbr_cc->BBR.idle_restart) {
    BBREnterProbeRTT(bbr_cc);
    BBRSaveCwnd(bbr_cc, cstat);
    bbr_cc->BBR.probe_rtt_done_stamp = 0;
  }
  if (bbr_cc->BBR.state == ProbeRTT) {
    BBRHandleProbeRTT(bbr_cc, cstat, ts);
  }
  bbr_cc->BBR.idle_restart = 0;
}

void BBREnterProbeRTT(ngtcp2_bbr_cc *bbr_cc) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  bbr_cc->BBR.state = ProbeRTT;
  bbr_cc->BBR.pacing_gain = 1;
  bbr_cc->BBR.cwnd_gain = 1;
}

void BBRHandleProbeRTT(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                       ngtcp2_tstamp ts) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  /* Ignore low rate samples during ProbeRTT: */
  if (bbr_cc->BBR.probe_rtt_done_stamp == 0 &&
      cstat->bytes_in_flight <= BBRMinPipeCwnd) {
    bbr_cc->BBR.probe_rtt_done_stamp = ts + ProbeRTTDuration;
    bbr_cc->BBR.probe_rtt_round_done = 0;
    bbr_cc->BBR.next_round_delivered = bbr_cc->BBR.delivered;
  } else if (bbr_cc->BBR.probe_rtt_done_stamp != 0) {
    if (bbr_cc->BBR.round_start) {
      bbr_cc->BBR.probe_rtt_round_done = 1;
    }
    if (bbr_cc->BBR.probe_rtt_round_done &&
        ts > bbr_cc->BBR.probe_rtt_done_stamp) {
      bbr_cc->BBR.rtprop_stamp = ts;
      BBRRestoreCwnd(bbr_cc, cstat);
      BBRExitProbeRTT(bbr_cc, ts);
    }
  }
}

void BBRExitProbeRTT(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp ts) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE, "BBR Trace # %s:%d",
                  __func__, __LINE__);
  if (bbr_cc->BBR.filled_pipe) {
    BBREnterProbeBW(bbr_cc, ts);
  } else {
    BBREnterStartup(bbr_cc);
  }
}
