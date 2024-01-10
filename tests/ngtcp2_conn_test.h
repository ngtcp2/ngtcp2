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
#endif /* defined(HAVE_CONFIG_H) */

#define MUNIT_ENABLE_ASSERT_ALIASES

#include "munit.h"

void init_static_path(void);

extern const MunitSuite conn_suite;

munit_void_test_decl(test_ngtcp2_conn_stream_open_close)
munit_void_test_decl(test_ngtcp2_conn_stream_rx_flow_control)
munit_void_test_decl(test_ngtcp2_conn_stream_rx_flow_control_error)
munit_void_test_decl(test_ngtcp2_conn_stream_tx_flow_control)
munit_void_test_decl(test_ngtcp2_conn_rx_flow_control)
munit_void_test_decl(test_ngtcp2_conn_rx_flow_control_error)
munit_void_test_decl(test_ngtcp2_conn_tx_flow_control)
munit_void_test_decl(test_ngtcp2_conn_shutdown_stream_write)
munit_void_test_decl(test_ngtcp2_conn_shutdown_stream_read)
munit_void_test_decl(test_ngtcp2_conn_recv_reset_stream)
munit_void_test_decl(test_ngtcp2_conn_recv_stop_sending)
munit_void_test_decl(test_ngtcp2_conn_recv_stream_data_blocked)
munit_void_test_decl(test_ngtcp2_conn_recv_data_blocked)
munit_void_test_decl(test_ngtcp2_conn_recv_conn_id_omitted)
munit_void_test_decl(test_ngtcp2_conn_short_pkt_type)
munit_void_test_decl(test_ngtcp2_conn_recv_stateless_reset)
munit_void_test_decl(test_ngtcp2_conn_recv_retry)
munit_void_test_decl(test_ngtcp2_conn_recv_delayed_handshake_pkt)
munit_void_test_decl(test_ngtcp2_conn_recv_max_streams)
munit_void_test_decl(test_ngtcp2_conn_handshake)
munit_void_test_decl(test_ngtcp2_conn_handshake_error)
munit_void_test_decl(test_ngtcp2_conn_retransmit_protected)
munit_void_test_decl(test_ngtcp2_conn_send_max_stream_data)
munit_void_test_decl(test_ngtcp2_conn_recv_stream_data)
munit_void_test_decl(test_ngtcp2_conn_recv_ping)
munit_void_test_decl(test_ngtcp2_conn_recv_max_stream_data)
munit_void_test_decl(test_ngtcp2_conn_send_early_data)
munit_void_test_decl(test_ngtcp2_conn_recv_early_data)
munit_void_test_decl(test_ngtcp2_conn_recv_compound_pkt)
munit_void_test_decl(test_ngtcp2_conn_pkt_payloadlen)
munit_void_test_decl(test_ngtcp2_conn_writev_stream)
munit_void_test_decl(test_ngtcp2_conn_writev_datagram)
munit_void_test_decl(test_ngtcp2_conn_recv_datagram)
munit_void_test_decl(test_ngtcp2_conn_recv_new_connection_id)
munit_void_test_decl(test_ngtcp2_conn_recv_retire_connection_id)
munit_void_test_decl(test_ngtcp2_conn_server_path_validation)
munit_void_test_decl(test_ngtcp2_conn_client_connection_migration)
munit_void_test_decl(test_ngtcp2_conn_recv_path_challenge)
munit_void_test_decl(test_ngtcp2_conn_key_update)
munit_void_test_decl(test_ngtcp2_conn_crypto_buffer_exceeded)
munit_void_test_decl(test_ngtcp2_conn_handshake_probe)
munit_void_test_decl(test_ngtcp2_conn_handshake_loss)
munit_void_test_decl(test_ngtcp2_conn_probe)
munit_void_test_decl(test_ngtcp2_conn_recv_client_initial_retry)
munit_void_test_decl(test_ngtcp2_conn_recv_client_initial_token)
munit_void_test_decl(test_ngtcp2_conn_get_active_dcid)
munit_void_test_decl(test_ngtcp2_conn_recv_version_negotiation)
munit_void_test_decl(test_ngtcp2_conn_send_initial_token)
munit_void_test_decl(test_ngtcp2_conn_set_remote_transport_params)
munit_void_test_decl(test_ngtcp2_conn_write_connection_close)
munit_void_test_decl(test_ngtcp2_conn_write_application_close)
munit_void_test_decl(test_ngtcp2_conn_rtb_reclaim_on_pto)
munit_void_test_decl(test_ngtcp2_conn_rtb_reclaim_on_pto_datagram)
munit_void_test_decl(test_ngtcp2_conn_validate_ecn)
munit_void_test_decl(test_ngtcp2_conn_path_validation)
munit_void_test_decl(test_ngtcp2_conn_early_data_sync_stream_data_limit)
munit_void_test_decl(test_ngtcp2_conn_tls_early_data_rejected)
munit_void_test_decl(test_ngtcp2_conn_keep_alive)
munit_void_test_decl(test_ngtcp2_conn_retire_stale_bound_dcid)
munit_void_test_decl(test_ngtcp2_conn_get_scid)
munit_void_test_decl(test_ngtcp2_conn_stream_close)
munit_void_test_decl(test_ngtcp2_conn_buffer_pkt)
munit_void_test_decl(test_ngtcp2_conn_handshake_timeout)
munit_void_test_decl(test_ngtcp2_conn_get_ccerr)
munit_void_test_decl(test_ngtcp2_conn_version_negotiation)
munit_void_test_decl(test_ngtcp2_conn_server_negotiate_version)
munit_void_test_decl(test_ngtcp2_conn_pmtud_loss)
munit_void_test_decl(test_ngtcp2_conn_amplification)
munit_void_test_decl(test_ngtcp2_conn_encode_0rtt_transport_params)
munit_void_test_decl(test_ngtcp2_conn_create_ack_frame)
munit_void_test_decl(test_ngtcp2_conn_grease_quic_bit)
munit_void_test_decl(test_ngtcp2_conn_send_stream_data_blocked)
munit_void_test_decl(test_ngtcp2_conn_send_data_blocked)
munit_void_test_decl(test_ngtcp2_conn_send_new_connection_id)
munit_void_test_decl(test_ngtcp2_conn_persistent_congestion)
munit_void_test_decl(test_ngtcp2_conn_ack_padding)
munit_void_test_decl(test_ngtcp2_conn_super_small_rtt)
munit_void_test_decl(test_ngtcp2_conn_ack_freq_out_of_order_pkt)
munit_void_test_decl(test_ngtcp2_conn_send_ack_frequency)
munit_void_test_decl(test_ngtcp2_conn_recv_immediate_ack)
munit_void_test_decl(test_ngtcp2_conn_new_failmalloc)
munit_void_test_decl(test_ngtcp2_conn_post_handshake_failmalloc)
munit_void_test_decl(test_ngtcp2_accept)
munit_void_test_decl(test_ngtcp2_select_version)
munit_void_test_decl(test_ngtcp2_pkt_write_connection_close)
munit_void_test_decl(test_ngtcp2_ccerr_set_liberr)

#endif /* !defined(NGTCP2_CONN_TEST_H) */
