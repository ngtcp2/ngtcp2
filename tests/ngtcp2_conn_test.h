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
#  include <config.h>
#endif /* HAVE_CONFIG_H */

void init_static_path(void);

void test_ngtcp2_conn_stream_open_close(void);
void test_ngtcp2_conn_stream_rx_flow_control(void);
void test_ngtcp2_conn_stream_rx_flow_control_error(void);
void test_ngtcp2_conn_stream_tx_flow_control(void);
void test_ngtcp2_conn_rx_flow_control(void);
void test_ngtcp2_conn_rx_flow_control_error(void);
void test_ngtcp2_conn_tx_flow_control(void);
void test_ngtcp2_conn_shutdown_stream_write(void);
void test_ngtcp2_conn_shutdown_stream_read(void);
void test_ngtcp2_conn_recv_reset_stream(void);
void test_ngtcp2_conn_recv_stop_sending(void);
void test_ngtcp2_conn_recv_stream_data_blocked(void);
void test_ngtcp2_conn_recv_data_blocked(void);
void test_ngtcp2_conn_recv_conn_id_omitted(void);
void test_ngtcp2_conn_short_pkt_type(void);
void test_ngtcp2_conn_recv_stateless_reset(void);
void test_ngtcp2_conn_recv_retry(void);
void test_ngtcp2_conn_recv_delayed_handshake_pkt(void);
void test_ngtcp2_conn_recv_max_streams(void);
void test_ngtcp2_conn_handshake(void);
void test_ngtcp2_conn_handshake_error(void);
void test_ngtcp2_conn_retransmit_protected(void);
void test_ngtcp2_conn_send_max_stream_data(void);
void test_ngtcp2_conn_recv_stream_data(void);
void test_ngtcp2_conn_recv_ping(void);
void test_ngtcp2_conn_recv_max_stream_data(void);
void test_ngtcp2_conn_send_early_data(void);
void test_ngtcp2_conn_recv_early_data(void);
void test_ngtcp2_conn_recv_compound_pkt(void);
void test_ngtcp2_conn_pkt_payloadlen(void);
void test_ngtcp2_conn_writev_stream(void);
void test_ngtcp2_conn_writev_datagram(void);
void test_ngtcp2_conn_recv_datagram(void);
void test_ngtcp2_conn_recv_new_connection_id(void);
void test_ngtcp2_conn_recv_retire_connection_id(void);
void test_ngtcp2_conn_server_path_validation(void);
void test_ngtcp2_conn_client_connection_migration(void);
void test_ngtcp2_conn_recv_path_challenge(void);
void test_ngtcp2_conn_key_update(void);
void test_ngtcp2_conn_crypto_buffer_exceeded(void);
void test_ngtcp2_conn_handshake_probe(void);
void test_ngtcp2_conn_handshake_loss(void);
void test_ngtcp2_conn_probe(void);
void test_ngtcp2_conn_recv_client_initial_retry(void);
void test_ngtcp2_conn_recv_client_initial_token(void);
void test_ngtcp2_conn_get_active_dcid(void);
void test_ngtcp2_conn_recv_version_negotiation(void);
void test_ngtcp2_conn_send_initial_token(void);
void test_ngtcp2_conn_set_remote_transport_params(void);
void test_ngtcp2_conn_write_connection_close(void);
void test_ngtcp2_conn_write_application_close(void);
void test_ngtcp2_conn_rtb_reclaim_on_pto(void);
void test_ngtcp2_conn_rtb_reclaim_on_pto_datagram(void);
void test_ngtcp2_conn_validate_ecn(void);
void test_ngtcp2_conn_path_validation(void);
void test_ngtcp2_conn_early_data_sync_stream_data_limit(void);
void test_ngtcp2_conn_tls_early_data_rejected(void);
void test_ngtcp2_conn_keep_alive(void);
void test_ngtcp2_conn_retire_stale_bound_dcid(void);
void test_ngtcp2_conn_get_scid(void);
void test_ngtcp2_conn_stream_close(void);
void test_ngtcp2_conn_buffer_pkt(void);
void test_ngtcp2_conn_handshake_timeout(void);
void test_ngtcp2_conn_get_ccerr(void);
void test_ngtcp2_conn_version_negotiation(void);
void test_ngtcp2_conn_server_negotiate_version(void);
void test_ngtcp2_conn_pmtud_loss(void);
void test_ngtcp2_conn_amplification(void);
void test_ngtcp2_conn_encode_0rtt_transport_params(void);
void test_ngtcp2_conn_create_ack_frame(void);
void test_ngtcp2_conn_grease_quic_bit(void);
void test_ngtcp2_conn_send_stream_data_blocked(void);
void test_ngtcp2_conn_send_data_blocked(void);
void test_ngtcp2_conn_send_new_connection_id(void);
void test_ngtcp2_conn_persistent_congestion(void);
void test_ngtcp2_conn_new_failmalloc(void);
void test_ngtcp2_accept(void);
void test_ngtcp2_select_version(void);
void test_ngtcp2_pkt_write_connection_close(void);

#endif /* NGTCP2_CONN_TEST_H */
