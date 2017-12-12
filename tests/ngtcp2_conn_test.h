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
#ifndef NGTCP2_CONN_TEST_H
#define NGTCP2_CONN_TEST_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

void test_ngtcp2_conn_stream_open_close(void);
void test_ngtcp2_conn_stream_rx_flow_control(void);
void test_ngtcp2_conn_stream_rx_flow_control_error(void);
void test_ngtcp2_conn_stream_tx_flow_control(void);
void test_ngtcp2_conn_rx_flow_control(void);
void test_ngtcp2_conn_rx_flow_control_error(void);
void test_ngtcp2_conn_tx_flow_control(void);
void test_ngtcp2_conn_shutdown_stream_write(void);
void test_ngtcp2_conn_recv_rst_stream(void);
void test_ngtcp2_conn_recv_stop_sending(void);
void test_ngtcp2_conn_recv_conn_id_omitted(void);
void test_ngtcp2_conn_short_pkt_type(void);
void test_ngtcp2_conn_recv_stateless_reset(void);
void test_ngtcp2_conn_recv_server_stateless_retry(void);
void test_ngtcp2_conn_recv_delayed_handshake_pkt(void);
void test_ngtcp2_conn_recv_max_stream_id(void);
void test_ngtcp2_conn_handshake_error(void);
void test_ngtcp2_conn_retransmit_protected(void);
void test_ngtcp2_conn_send_max_stream_data(void);
void test_ngtcp2_conn_recv_stream_data(void);
void test_ngtcp2_conn_recv_ping(void);
void test_ngtcp2_conn_recv_max_stream_data(void);
void test_ngtcp2_conn_send_early_data(void);
void test_ngtcp2_conn_recv_early_data(void);

#endif /* NGTCP2_CONN_TEST_H */
