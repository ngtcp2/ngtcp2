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
#ifndef NGTCP2_WAVE_H
#define NGTCP2_WAVE_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#include <ngtcp2/ngtcp2.h>

#include "ngtcp2_cc.h"

typedef struct burst_stats {
    uint64_t send_time;             // Timestamp of when this burst is sent [ns]
    uint64_t send_burst_size;       // Size of the burst sent [bytes]
    uint64_t first_ack_time;        // Timestamp of the first ACK of a Burst [ns]
    uint64_t last_ack_time;         // Timestamp of the last ACK of a Burst [ns]
    uint64_t ack_num;               // Number of ACKs received
    uint64_t acked_bytes;           // Number of ACKed bytes for a Burst [bytes]
    uint64_t cumulative_ack_rtt;    // Sum of RTTs of packets of a Burst [ns]
    uint64_t pilot_rtt;             // RTT of the first packet sent [ns]
    struct burst_stats * previous;  // Pointer to the previous burst sent
    struct burst_stats * next;      // Pointer to the next burst sent
} burst_stats;

/*
 * ngtcp2_cc_wave is Wave congestion controller, described in:
 * [1] https://doi.org/10.1016/j.comnet.2016.11.002
 * [2] https://doi.org/10.1016/j.comnet.2020.107633
 */
typedef struct ngtcp2_cc_wave {
    ngtcp2_cc cc;
    uint64_t default_burst_size;           // Default burst size [bytes]
    uint64_t tx_time;                      // Transmission timer [ns]
    uint64_t beta;                         // Threshold for Adj. Mode [ns]
    uint64_t min_rtt;                      // Min RTT since last Adj. Mode [ns]
    uint64_t avg_rtt;                      // Avg RTT since last Adj. Mode [ns]
    uint64_t alpha;                        // EWMA filter parameter
    uint64_t ack_count;                    // Number of ACK Received
    uint64_t ack_data;                     // Size of ACK-ed Data [bytes]
    burst_stats * bursts;                  // List of bursts sent
} ngtcp2_cc_wave;

void ngtcp2_cc_wave_init(ngtcp2_cc_wave *cc,
                         ngtcp2_log *log,
                         ngtcp2_conn_stat *cstat);

#endif /* !defined(NGTCP2_WAVE_H) */
