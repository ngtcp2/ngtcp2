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

#define BBR_GAIN_CYCLE_LEN 8
static const double pacing_gain_cycle[BBR_GAIN_CYCLE_LEN] = {1.25, 0.75, 1, 1,
                                                             1,    1,    1, 1};
#define BBR_HIGH_GAIN 2.89
#define BBR_PROBE_RTT_DURATION (200 * NGTCP2_MILLISECONDS)
#define RTPROP_FILTER_LEN (10 * NGTCP2_SECONDS)
#define BBR_MSS 1500
#define BBR_MIN_PIPE_CWND (4 * BBR_MSS)
#define BBR_INITIAL_CWND (10 * BBR_MSS)

typedef enum {
  BBR_STATE_STARTUP = 0,
  BBR_STATE_DRAIN = 1,
  BBR_STATE_PROBE_BW = 2,
  BBR_STATE_PROBE_RTT = 3,
} bbr_state;

void bbr_on_connection_init(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp initial_ts);
void bbr_update_on_ack(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                       const ngtcp2_cc_pkt *pkt, ngtcp2_tstamp ts);
void bbr_update_model_and_state(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                                const ngtcp2_cc_pkt *pkt, ngtcp2_tstamp ts);
void bbr_update_control_paramters(ngtcp2_bbr_cc *bbr_cc,
                                  ngtcp2_conn_stat *cstat);
void bbr_on_transmit(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat);
void bbr_init_round_counting(ngtcp2_bbr_cc *bbr_cc);
void bbr_update_round(ngtcp2_bbr_cc *bbr_cc, const ngtcp2_cc_pkt *pkt);
void bbr_update_btl_bw(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                       const ngtcp2_cc_pkt *pkt);
void bbr_update_rtprop(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                       ngtcp2_tstamp ts);
void bbr_init_pacing_rate(ngtcp2_bbr_cc *bbr_cc);
void bbr_set_pacing_rate_with_gain(ngtcp2_bbr_cc *bbr_cc, uint64_t pacing_gain);
void bbr_set_pacing_rate(ngtcp2_bbr_cc *bbr_cc);
void bbr_set_send_quantum(ngtcp2_bbr_cc *bbr_cc);
void bbr_update_target_cwnd(ngtcp2_bbr_cc *bbr_cc);
void bbr_modulate_cwnd_for_recovery(ngtcp2_bbr_cc *bbr_cc,
                                    ngtcp2_conn_stat *cstat);
uint64_t bbr_save_cwnd(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat);
void bbr_restore_cwnd(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat);
void bbr_modulate_cwnd_for_probe_rtt(ngtcp2_bbr_cc *bbr_cc,
                                     ngtcp2_conn_stat *cstat);
void bbr_set_cwnd(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat);
void bbr_init(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp initial_ts);
void bbr_enter_startup(ngtcp2_bbr_cc *bbr_cc);
void bbr_initFullPipe(ngtcp2_bbr_cc *bbr_cc);
void bbr_check_full_pipe(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                         const ngtcp2_cc_pkt *pkt);
void bbr_enter_drain(ngtcp2_bbr_cc *bbr_cc);
void bbr_check_drain(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                     ngtcp2_tstamp ts);
void bbr_enter_probe_bw(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp ts);
void bbr_check_cycle_phase(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp ts);
void bbr_advance_cycle_phase(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp ts);
int bbr_is_next_cycle_phase(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp ts);
void bbr_handle_restart_from_idle(ngtcp2_bbr_cc *bbr_cc,
                                  ngtcp2_conn_stat *cstat);
void bbr_check_probe_rtt(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                         ngtcp2_tstamp ts);
void bbr_enter_probe_rtt(ngtcp2_bbr_cc *bbr_cc);
void bbr_handle_probe_rtt(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                          ngtcp2_tstamp ts);
void bbr_exit_probe_rtt(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp ts);

static void bbr_cc_reset(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp initial_ts) {
  bbr_on_connection_init(bbr_cc, initial_ts);
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
  cc->on_pace_time_to_send = ngtcp2_cc_bbr_cc_on_pace_time_to_send;

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

  bbr_update_on_ack(bbr_cc, cstat, pkt, ts);
  bbr_cc->prior_inflight = cstat->bytes_in_flight;
}

void ngtcp2_cc_bbr_cc_congestion_event(ngtcp2_cc *ccx, ngtcp2_conn_stat *cstat,
                                       ngtcp2_tstamp ts_sent,
                                       ngtcp2_tstamp ts) {
  ngtcp2_bbr_cc *bbr_cc = ngtcp2_struct_of(ccx->ccb, ngtcp2_bbr_cc, ccb);

  /* TODO: FIXME:
     Is there any loss recovery/congest recovery callback function?
     Curently we ignore the congetion event in bbr.
     The code blew no run currently, just a hint to process. */
  int retransmit_timeout = 0;
  int fast_recovery = 0;
  if (retransmit_timeout) {
    bbr_cc->bbr.prior_cwnd = bbr_save_cwnd(bbr_cc, cstat);
    cstat->cwnd = 1 * BBR_MSS;
  } else if (fast_recovery) {
    bbr_cc->bbr.prior_cwnd = bbr_save_cwnd(bbr_cc, cstat);
    cstat->cwnd =
        cstat->bytes_in_flight + ngtcp2_max(cstat->delivered, 1 * BBR_MSS);
    bbr_cc->bbr.packet_conservation = 1;
  }
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
  bbr_on_transmit(bbr_cc, cstat);

  /* Calculate next send time by currently pacing rate. */
  if (bbr_cc->bbr.pacing_rate > 0) {
    bbr_cc->next_send_time =
        pkt->ts_sent + pkt->pktlen / bbr_cc->bbr.pacing_rate;
  }
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

int ngtcp2_cc_bbr_cc_on_pace_time_to_send(ngtcp2_cc *ccx, ngtcp2_tstamp ts) {
  ngtcp2_bbr_cc *bbr_cc = ngtcp2_struct_of(ccx->ccb, ngtcp2_bbr_cc, ccb);
  return ts >= bbr_cc->next_send_time;
}

void bbr_on_connection_init(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp initial_ts) {
  bbr_init(bbr_cc, initial_ts);
}

void bbr_update_on_ack(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                       const ngtcp2_cc_pkt *pkt, ngtcp2_tstamp ts) {
  bbr_update_model_and_state(bbr_cc, cstat, pkt, ts);
  bbr_update_control_paramters(bbr_cc, cstat);
}

void bbr_update_model_and_state(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                                const ngtcp2_cc_pkt *pkt, ngtcp2_tstamp ts) {
  bbr_update_btl_bw(bbr_cc, cstat, pkt);
  bbr_check_cycle_phase(bbr_cc, ts);
  bbr_check_full_pipe(bbr_cc, cstat, pkt);
  bbr_check_drain(bbr_cc, cstat, ts);
  bbr_update_rtprop(bbr_cc, cstat, ts);
  bbr_check_probe_rtt(bbr_cc, cstat, ts);
}

void bbr_update_control_paramters(ngtcp2_bbr_cc *bbr_cc,
                                  ngtcp2_conn_stat *cstat) {
  bbr_set_pacing_rate(bbr_cc);
  bbr_set_send_quantum(bbr_cc);
  bbr_set_cwnd(bbr_cc, cstat);
}

void bbr_on_transmit(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat) {
  bbr_handle_restart_from_idle(bbr_cc, cstat);
}

void bbr_init_round_counting(ngtcp2_bbr_cc *bbr_cc) {
  bbr_cc->bbr.next_round_delivered = 0;
  bbr_cc->bbr.round_start = 0;
  bbr_cc->bbr.round_count = 0;
}

void bbr_update_round(ngtcp2_bbr_cc *bbr_cc, const ngtcp2_cc_pkt *pkt) {
  /* TODO: FIXME: bbr.delivered and pkt->delivered is samples in different
   * modules. */
  bbr_cc->bbr.delivered += pkt->pktlen;
  if (pkt->delivered >= bbr_cc->bbr.next_round_delivered) {
    bbr_cc->bbr.next_round_delivered = bbr_cc->bbr.delivered;
    bbr_cc->bbr.round_count++;
    bbr_cc->bbr.round_start = 1;
  } else {
    bbr_cc->bbr.round_start = 0;
  }
}

void bbr_update_btl_bw(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                       const ngtcp2_cc_pkt *pkt) {
  bbr_update_round(bbr_cc, pkt);
  if (cstat->delivery_rate_sec >= bbr_cc->bbr.btl_bw || !pkt->is_app_limited) {
    int i = 0;
    for (; i < BBR_BTL_BW_FILTER_LEN - 1; ++i) {
      double bw = bbr_cc->bbr.btl_bw_filter[i];
      bbr_cc->bbr.btl_bw_filter[i + 1] = bw;
      bbr_cc->bbr.btl_bw = ngtcp2_max(bw, bbr_cc->bbr.btl_bw);
    }
    bbr_cc->bbr.btl_bw_filter[0] = cstat->delivery_rate_sec;
    bbr_cc->bbr.btl_bw =
        ngtcp2_max(cstat->delivery_rate_sec, bbr_cc->bbr.btl_bw);
  }
}

void bbr_update_rtprop(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                       ngtcp2_tstamp ts) {
  bbr_cc->bbr.rtprop_expired =
      ts > bbr_cc->bbr.rtprop_stamp + RTPROP_FILTER_LEN;
  if (cstat->latest_rtt >= 0 && (cstat->latest_rtt <= bbr_cc->bbr.rt_prop ||
                                 bbr_cc->bbr.rtprop_expired)) {
    ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE,
                    "bbr probe min rtt or expired, rt_prop=%" PRIu64
                    ", rtprop_expired=%" PRIu64,
                    bbr_cc->bbr.rt_prop, bbr_cc->bbr.rtprop_expired);
    bbr_cc->bbr.rt_prop = cstat->latest_rtt;
    bbr_cc->bbr.rtprop_stamp = ts;
  }
}

void bbr_init_pacing_rate(ngtcp2_bbr_cc *bbr_cc) {
  double nominal_bandwidth = BBR_INITIAL_CWND / (1 * NGTCP2_MILLISECONDS);
  bbr_cc->bbr.pacing_rate = bbr_cc->bbr.pacing_gain * nominal_bandwidth;
}

void bbr_set_pacing_rate_with_gain(ngtcp2_bbr_cc *bbr_cc,
                                   uint64_t pacing_gain) {
  double rate = pacing_gain * bbr_cc->bbr.btl_bw;
  if (bbr_cc->bbr.filled_pipe || rate > bbr_cc->bbr.pacing_rate) {
    bbr_cc->bbr.pacing_rate = rate;
  }
}

void bbr_set_pacing_rate(ngtcp2_bbr_cc *bbr_cc) {
  bbr_set_pacing_rate_with_gain(bbr_cc, bbr_cc->bbr.pacing_gain);
}

void bbr_set_send_quantum(ngtcp2_bbr_cc *bbr_cc) {
  if (bbr_cc->bbr.pacing_rate < 1.2 * 1024 * 1024) {
    bbr_cc->bbr.send_quantum = 1 * BBR_MSS;
  } else if (bbr_cc->bbr.pacing_rate < 24 * 1024 * 1024) {
    bbr_cc->bbr.send_quantum = 2 * BBR_MSS;
  } else {
    bbr_cc->bbr.send_quantum = ngtcp2_min(
        bbr_cc->bbr.pacing_rate * 1 * NGTCP2_MILLISECONDS, 64 * 1024 * 8);
  }
}

uint64_t bbr_inflight(ngtcp2_bbr_cc *bbr_cc, uint64_t gain) {
  if (bbr_cc->bbr.rt_prop == UINT64_MAX) {
    /* no valid RTT samples yet */
    return BBR_INITIAL_CWND;
  }
  uint64_t quanta = 3 * bbr_cc->bbr.send_quantum;
  double estimated_bdp =
      bbr_cc->bbr.btl_bw * bbr_cc->bbr.rt_prop / NGTCP2_SECONDS;
  return gain * estimated_bdp + quanta;
}

void bbr_update_target_cwnd(ngtcp2_bbr_cc *bbr_cc) {
  bbr_cc->bbr.target_cwnd = bbr_inflight(bbr_cc, bbr_cc->bbr.cwnd_gain);
}

void bbr_modulate_cwnd_for_recovery(ngtcp2_bbr_cc *bbr_cc,
                                    ngtcp2_conn_stat *cstat) {
  if (bbr_cc->packets_lost > 0) {
    cstat->cwnd = ngtcp2_max(cstat->cwnd - bbr_cc->packets_lost, 1 * BBR_MSS);
  }

  if (bbr_cc->bbr.packet_conservation) {
    cstat->cwnd =
        ngtcp2_max(cstat->cwnd, cstat->bytes_in_flight + cstat->delivered);
  }
}

uint64_t bbr_save_cwnd(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat) {
  if (!bbr_cc->bbr.packet_conservation &&
      bbr_cc->bbr.state != BBR_STATE_PROBE_RTT) {
    return cstat->cwnd;
  } else {
    return ngtcp2_max(bbr_cc->bbr.prior_cwnd, cstat->cwnd);
  }
}
void bbr_restore_cwnd(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat) {
  cstat->cwnd = ngtcp2_max(cstat->cwnd, bbr_cc->bbr.prior_cwnd);
}

void bbr_modulate_cwnd_for_probe_rtt(ngtcp2_bbr_cc *bbr_cc,
                                     ngtcp2_conn_stat *cstat) {
  if (bbr_cc->bbr.state == BBR_STATE_PROBE_RTT) {
    cstat->cwnd = ngtcp2_min(cstat->cwnd, BBR_MIN_PIPE_CWND);
  }
}

void bbr_set_cwnd(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat) {
  bbr_update_target_cwnd(bbr_cc);
  bbr_modulate_cwnd_for_recovery(bbr_cc, cstat);
  if (!bbr_cc->bbr.packet_conservation) {
    if (bbr_cc->bbr.filled_pipe) {
      cstat->cwnd =
          ngtcp2_min(cstat->cwnd + cstat->delivered, bbr_cc->bbr.target_cwnd);
    } else if (cstat->cwnd < bbr_cc->bbr.target_cwnd ||
               bbr_cc->bbr.delivered < BBR_INITIAL_CWND) {
      cstat->cwnd = cstat->cwnd + cstat->delivered;
    }
    cstat->cwnd = ngtcp2_max(cstat->cwnd, BBR_MIN_PIPE_CWND);
  }
  bbr_modulate_cwnd_for_probe_rtt(bbr_cc, cstat);
}

void bbr_init(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp initial_ts) {
  bbr_cc->bbr.btl_bw = 0;
  int i;
  for (i = 0; i < BBR_BTL_BW_FILTER_LEN; ++i) {
    bbr_cc->bbr.btl_bw_filter[i] = 0;
  }
  bbr_cc->bbr.rt_prop = UINT64_MAX;
  bbr_cc->bbr.rtprop_stamp = initial_ts;
  bbr_cc->bbr.probe_rtt_done_stamp = 0;
  bbr_cc->bbr.probe_rtt_round_done = 0;
  bbr_cc->bbr.packet_conservation = 0;
  bbr_cc->bbr.prior_cwnd = 0;
  bbr_cc->bbr.idle_restart = 0;

  bbr_cc->packets_lost = 0;
  bbr_cc->prior_inflight = 0;
  bbr_cc->next_send_time = 0;

  bbr_init_round_counting(bbr_cc);
  bbr_initFullPipe(bbr_cc);
  bbr_init_pacing_rate(bbr_cc);
  bbr_enter_startup(bbr_cc);
}

void bbr_enter_startup(ngtcp2_bbr_cc *bbr_cc) {
  bbr_cc->bbr.state = BBR_STATE_STARTUP;
  bbr_cc->bbr.pacing_gain = BBR_HIGH_GAIN;
  bbr_cc->bbr.cwnd_gain = BBR_HIGH_GAIN;
}

void bbr_initFullPipe(ngtcp2_bbr_cc *bbr_cc) {
  bbr_cc->bbr.filled_pipe = 0;
  bbr_cc->bbr.full_bw = 0;
  bbr_cc->bbr.full_bw_count = 0;
}

void bbr_check_full_pipe(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                         const ngtcp2_cc_pkt *pkt) {
  if (bbr_cc->bbr.filled_pipe || !bbr_cc->bbr.round_start ||
      pkt->is_app_limited) {
    /* no need to check for a full pipe now. */
    return;
  }
  /* bbr_cc->bbr.btl_bw still growing? */
  if (bbr_cc->bbr.btl_bw >= bbr_cc->bbr.full_bw * 1.25) {
    /* record new baseline level */
    bbr_cc->bbr.full_bw = bbr_cc->bbr.btl_bw;
    bbr_cc->bbr.full_bw_count = 0;
    return;
  }
  /* another round w/o much growth */
  bbr_cc->bbr.full_bw_count++;
  if (bbr_cc->bbr.full_bw_count >= 3) {
    bbr_cc->bbr.filled_pipe = 1;
    ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE,
                    "bbr filled pipe, btl_bw=%" PRIu64, bbr_cc->bbr.btl_bw);
  }
}

void bbr_enter_drain(ngtcp2_bbr_cc *bbr_cc) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE,
                  "bbr enter drain state, btl_bw=%" PRIu64, bbr_cc->bbr.btl_bw);
  bbr_cc->bbr.state = BBR_STATE_DRAIN;
  /* pace slowly */
  bbr_cc->bbr.pacing_gain = 1 / BBR_HIGH_GAIN;
  /* maintain cwnd */
  bbr_cc->bbr.cwnd_gain = BBR_HIGH_GAIN;
}

void bbr_check_drain(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                     ngtcp2_tstamp ts) {
  if (bbr_cc->bbr.state == BBR_STATE_STARTUP && bbr_cc->bbr.filled_pipe) {
    bbr_enter_drain(bbr_cc);
  }

  if (bbr_cc->bbr.state == BBR_STATE_DRAIN &&
      cstat->bytes_in_flight <= bbr_inflight(bbr_cc, 1.0)) {
    ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE,
                    "bbr enter probe bw state form drain state, btlbw=%" PRIu64
                    ", rt_prop=%" PRIu64,
                    bbr_cc->bbr.btl_bw, bbr_cc->bbr.rt_prop);
    /* we estimate queue is drained */
    bbr_enter_probe_bw(bbr_cc, ts);
  }
}

void bbr_enter_probe_bw(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp ts) {
  bbr_cc->bbr.state = BBR_STATE_PROBE_BW;
  bbr_cc->bbr.pacing_gain = 1;
  bbr_cc->bbr.cwnd_gain = 2;
  bbr_cc->bbr.cycle_index = BBR_GAIN_CYCLE_LEN - 1 - (random() % 7);
  bbr_advance_cycle_phase(bbr_cc, ts);
}

void bbr_check_cycle_phase(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp ts) {
  if (bbr_cc->bbr.state == BBR_STATE_PROBE_BW &&
      bbr_is_next_cycle_phase(bbr_cc, ts)) {
    bbr_advance_cycle_phase(bbr_cc, ts);
  }
}

void bbr_advance_cycle_phase(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp ts) {
  bbr_cc->bbr.cycle_stamp = ts;
  bbr_cc->bbr.cycle_index = (bbr_cc->bbr.cycle_index + 1) % BBR_GAIN_CYCLE_LEN;
  bbr_cc->bbr.pacing_gain = pacing_gain_cycle[bbr_cc->bbr.cycle_index];
}

int bbr_is_next_cycle_phase(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp ts) {
  int is_full_length = (ts - bbr_cc->bbr.cycle_stamp) > bbr_cc->bbr.rt_prop;
  if (bbr_cc->bbr.pacing_gain == 1) {
    return is_full_length;
  }
  if (bbr_cc->bbr.pacing_gain > 1) {
    return is_full_length &&
           (bbr_cc->packets_lost > 0 ||
            bbr_cc->prior_inflight >=
                bbr_inflight(bbr_cc, bbr_cc->bbr.pacing_gain));
  } else {
    return is_full_length || bbr_cc->prior_inflight <= bbr_inflight(bbr_cc, 1);
  }
}

void bbr_handle_restart_from_idle(ngtcp2_bbr_cc *bbr_cc,
                                  ngtcp2_conn_stat *cstat) {
  if (cstat->bytes_in_flight == 0 && cstat->app_limited) {

    ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE,
                    "bbr restart from idle");
    bbr_cc->bbr.idle_start = 1;
    if (bbr_cc->bbr.state == BBR_STATE_PROBE_BW) {
      bbr_set_pacing_rate_with_gain(bbr_cc, 1);
    }
  }
}

void bbr_check_probe_rtt(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                         ngtcp2_tstamp ts) {
  if (bbr_cc->bbr.state != BBR_STATE_PROBE_RTT && bbr_cc->bbr.rtprop_expired &&
      !bbr_cc->bbr.idle_restart) {

    bbr_enter_probe_rtt(bbr_cc);
    bbr_save_cwnd(bbr_cc, cstat);
    bbr_cc->bbr.probe_rtt_done_stamp = 0;
  }
  if (bbr_cc->bbr.state == BBR_STATE_PROBE_RTT) {
    bbr_handle_probe_rtt(bbr_cc, cstat, ts);
  }
  bbr_cc->bbr.idle_restart = 0;
}

void bbr_enter_probe_rtt(ngtcp2_bbr_cc *bbr_cc) {
  ngtcp2_log_info(bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE,
                  "bbr enter probe rtt state, btlbw=%" PRIu64
                  ", rt_prop=%" PRIu64,
                  bbr_cc->bbr.btl_bw, bbr_cc->bbr.rt_prop);
  bbr_cc->bbr.state = BBR_STATE_PROBE_RTT;
  bbr_cc->bbr.pacing_gain = 1;
  bbr_cc->bbr.cwnd_gain = 1;
}

void bbr_handle_probe_rtt(ngtcp2_bbr_cc *bbr_cc, ngtcp2_conn_stat *cstat,
                          ngtcp2_tstamp ts) {
  /* Ignore low rate samples during BBR_STATE_PROBE_RTT. */
  if (bbr_cc->bbr.probe_rtt_done_stamp == 0 &&
      cstat->bytes_in_flight <= BBR_MIN_PIPE_CWND) {
    bbr_cc->bbr.probe_rtt_done_stamp = ts + BBR_PROBE_RTT_DURATION;
    bbr_cc->bbr.probe_rtt_round_done = 0;
    bbr_cc->bbr.next_round_delivered = bbr_cc->bbr.delivered;
  } else if (bbr_cc->bbr.probe_rtt_done_stamp != 0) {
    if (bbr_cc->bbr.round_start) {
      bbr_cc->bbr.probe_rtt_round_done = 1;
    }
    if (bbr_cc->bbr.probe_rtt_round_done &&
        ts > bbr_cc->bbr.probe_rtt_done_stamp) {
      bbr_cc->bbr.rtprop_stamp = ts;
      bbr_restore_cwnd(bbr_cc, cstat);
      bbr_exit_probe_rtt(bbr_cc, ts);
    }
  }
}

void bbr_exit_probe_rtt(ngtcp2_bbr_cc *bbr_cc, ngtcp2_tstamp ts) {
  if (bbr_cc->bbr.filled_pipe) {
    ngtcp2_log_info(
        bbr_cc->ccb.log, NGTCP2_LOG_EVENT_NONE,
        "bbr enter probe bw state form probe rtt state, btlbw=%" PRIu64
        ", rt_prop=%" PRIu64,
        bbr_cc->bbr.btl_bw, bbr_cc->bbr.rt_prop);
    bbr_enter_probe_bw(bbr_cc, ts);
  } else {
    bbr_enter_startup(bbr_cc);
  }
}
