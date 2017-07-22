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
#ifndef DEBUG_H
#define DEBUG_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif // HAVE_CONFIG_H

// For travis and PRIu64
#define __STDC_FORMAT_MACROS
#include <cinttypes>

#include <chrono>

#include <ngtcp2/ngtcp2.h>

namespace ngtcp2 {

namespace debug {

void reset_timestamp();

std::chrono::microseconds timestamp();

void set_color_output(bool f);

void print_timestamp();

int send_pkt(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd, void *user_data);

int send_frame(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
               const ngtcp2_frame *fr, void *user_data);

int recv_pkt(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd, void *user_data);

int recv_frame(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
               const ngtcp2_frame *fr, void *user_data);

int handshake_completed(ngtcp2_conn *conn, void *user_data);

int recv_version_negotiation(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                             const uint32_t *sv, size_t nsv, void *user_data);

void print_transport_params(const ngtcp2_transport_params *params, int type);

bool packet_lost(double prob);

void print_stream_data(uint32_t stream_id, const uint8_t *data, size_t datalen);

} // namespace debug

} // namespace ngtcp2

#endif // DEBUG_H
