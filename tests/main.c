/*
 * ngtcp2
 *
 * Copyright (c) 2016 ngtcp2 contributors
 * Copyright (c) 2012 nghttp2 contributors
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
#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <string.h>
#include <CUnit/Basic.h>
/* include test cases' include files here */
#include "ngtcp2_pkt_test.h"
#include "ngtcp2_range_test.h"
#include "ngtcp2_rob_test.h"
#include "ngtcp2_rtb_test.h"
#include "ngtcp2_acktr_test.h"
#include "ngtcp2_crypto_test.h"
#include "ngtcp2_idtr_test.h"
#include "ngtcp2_conn_test.h"
#include "ngtcp2_ringbuf_test.h"
#include "ngtcp2_conv_test.h"
#include "ngtcp2_ksl_test.h"
#include "ngtcp2_map_test.h"
#include "ngtcp2_gaptr_test.h"
#include "ngtcp2_vec_test.h"
#include "ngtcp2_strm_test.h"
#include "ngtcp2_pv_test.h"
#include "ngtcp2_pmtud_test.h"
#include "ngtcp2_str_test.h"
#include "ngtcp2_tstamp_test.h"
#include "ngtcp2_conversion_test.h"
#include "ngtcp2_qlog_test.h"

static int init_suite1(void) { return 0; }

static int clean_suite1(void) { return 0; }

int main(void) {
  CU_pSuite pSuite = NULL;
  unsigned int num_tests_failed;

  /* initialize the CUnit test registry */
  if (CUE_SUCCESS != CU_initialize_registry())
    return (int)CU_get_error();

  /* add a suite to the registry */
  pSuite = CU_add_suite("libngtcp2_TestSuite", init_suite1, clean_suite1);
  if (NULL == pSuite) {
    CU_cleanup_registry();
    return (int)CU_get_error();
  }

  init_static_path();

  /* add the tests to the suite */
  if (!CU_add_test(pSuite, "pkt_decode_version_cid",
                   test_ngtcp2_pkt_decode_version_cid) ||
      !CU_add_test(pSuite, "pkt_decode_hd_long",
                   test_ngtcp2_pkt_decode_hd_long) ||
      !CU_add_test(pSuite, "pkt_decode_hd_short",
                   test_ngtcp2_pkt_decode_hd_short) ||
      !CU_add_test(pSuite, "pkt_decode_frame", test_ngtcp2_pkt_decode_frame) ||
      !CU_add_test(pSuite, "pkt_decode_stream_frame",
                   test_ngtcp2_pkt_decode_stream_frame) ||
      !CU_add_test(pSuite, "pkt_decode_ack_frame",
                   test_ngtcp2_pkt_decode_ack_frame) ||
      !CU_add_test(pSuite, "pkt_decode_padding_frame",
                   test_ngtcp2_pkt_decode_padding_frame) ||
      !CU_add_test(pSuite, "pkt_encode_stream_frame",
                   test_ngtcp2_pkt_encode_stream_frame) ||
      !CU_add_test(pSuite, "pkt_encode_ack_frame",
                   test_ngtcp2_pkt_encode_ack_frame) ||
      !CU_add_test(pSuite, "pkt_encode_ack_ecn_frame",
                   test_ngtcp2_pkt_encode_ack_ecn_frame) ||
      !CU_add_test(pSuite, "pkt_encode_reset_stream_frame",
                   test_ngtcp2_pkt_encode_reset_stream_frame) ||
      !CU_add_test(pSuite, "pkt_encode_connection_close_frame",
                   test_ngtcp2_pkt_encode_connection_close_frame) ||
      !CU_add_test(pSuite, "pkt_encode_connection_close_app_frame",
                   test_ngtcp2_pkt_encode_connection_close_app_frame) ||
      !CU_add_test(pSuite, "pkt_encode_max_data_frame",
                   test_ngtcp2_pkt_encode_max_data_frame) ||
      !CU_add_test(pSuite, "pkt_encode_max_stream_data_frame",
                   test_ngtcp2_pkt_encode_max_stream_data_frame) ||
      !CU_add_test(pSuite, "pkt_encode_max_streams_frame",
                   test_ngtcp2_pkt_encode_max_streams_frame) ||
      !CU_add_test(pSuite, "pkt_encode_ping_frame",
                   test_ngtcp2_pkt_encode_ping_frame) ||
      !CU_add_test(pSuite, "pkt_encode_data_blocked_frame",
                   test_ngtcp2_pkt_encode_data_blocked_frame) ||
      !CU_add_test(pSuite, "pkt_encode_stream_data_blocked_frame",
                   test_ngtcp2_pkt_encode_stream_data_blocked_frame) ||
      !CU_add_test(pSuite, "pkt_encode_streams_blocked_frame",
                   test_ngtcp2_pkt_encode_streams_blocked_frame) ||
      !CU_add_test(pSuite, "pkt_encode_new_connection_id_frame",
                   test_ngtcp2_pkt_encode_new_connection_id_frame) ||
      !CU_add_test(pSuite, "pkt_encode_stop_sending_frame",
                   test_ngtcp2_pkt_encode_stop_sending_frame) ||
      !CU_add_test(pSuite, "pkt_encode_path_challenge_frame",
                   test_ngtcp2_pkt_encode_path_challenge_frame) ||
      !CU_add_test(pSuite, "pkt_encode_path_response_frame",
                   test_ngtcp2_pkt_encode_path_response_frame) ||
      !CU_add_test(pSuite, "pkt_encode_crypto_frame",
                   test_ngtcp2_pkt_encode_crypto_frame) ||
      !CU_add_test(pSuite, "pkt_encode_new_token_frame",
                   test_ngtcp2_pkt_encode_new_token_frame) ||
      !CU_add_test(pSuite, "pkt_encode_retire_connection_id",
                   test_ngtcp2_pkt_encode_retire_connection_id_frame) ||
      !CU_add_test(pSuite, "pkt_encode_handshake_done",
                   test_ngtcp2_pkt_encode_handshake_done_frame) ||
      !CU_add_test(pSuite, "pkt_encode_datagram_frame",
                   test_ngtcp2_pkt_encode_datagram_frame) ||
      !CU_add_test(pSuite, "pkt_adjust_pkt_num",
                   test_ngtcp2_pkt_adjust_pkt_num) ||
      !CU_add_test(pSuite, "pkt_validate_ack", test_ngtcp2_pkt_validate_ack) ||
      !CU_add_test(pSuite, "pkt_write_stateless_reset",
                   test_ngtcp2_pkt_write_stateless_reset) ||
      !CU_add_test(pSuite, "pkt_write_retry", test_ngtcp2_pkt_write_retry) ||
      !CU_add_test(pSuite, "pkt_write_version_negotiation",
                   test_ngtcp2_pkt_write_version_negotiation) ||
      !CU_add_test(pSuite, "pkt_stream_max_datalen",
                   test_ngtcp2_pkt_stream_max_datalen) ||
      !CU_add_test(pSuite, "get_varint", test_ngtcp2_get_varint) ||
      !CU_add_test(pSuite, "get_uvarintlen", test_ngtcp2_get_uvarintlen) ||
      !CU_add_test(pSuite, "put_uvarintlen", test_ngtcp2_put_uvarintlen) ||
      !CU_add_test(pSuite, "get_uint64", test_ngtcp2_get_uint64) ||
      !CU_add_test(pSuite, "get_uint48", test_ngtcp2_get_uint48) ||
      !CU_add_test(pSuite, "get_uint32", test_ngtcp2_get_uint32) ||
      !CU_add_test(pSuite, "get_uint24", test_ngtcp2_get_uint24) ||
      !CU_add_test(pSuite, "get_uint16", test_ngtcp2_get_uint16) ||
      !CU_add_test(pSuite, "get_uint16be", test_ngtcp2_get_uint16be) ||
      !CU_add_test(pSuite, "nth_server_bidi_id",
                   test_ngtcp2_nth_server_bidi_id) ||
      !CU_add_test(pSuite, "nth_server_uni_id",
                   test_ngtcp2_nth_server_uni_id) ||
      !CU_add_test(pSuite, "nth_client_bidi_id",
                   test_ngtcp2_nth_client_bidi_id) ||
      !CU_add_test(pSuite, "nth_client_uni_id",
                   test_ngtcp2_nth_client_uni_id) ||
      !CU_add_test(pSuite, "range_intersect", test_ngtcp2_range_intersect) ||
      !CU_add_test(pSuite, "range_cut", test_ngtcp2_range_cut) ||
      !CU_add_test(pSuite, "range_not_after", test_ngtcp2_range_not_after) ||
      !CU_add_test(pSuite, "ksl_insert", test_ngtcp2_ksl_insert) ||
      !CU_add_test(pSuite, "ksl_clear", test_ngtcp2_ksl_clear) ||
      !CU_add_test(pSuite, "ksl_range", test_ngtcp2_ksl_range) ||
      !CU_add_test(pSuite, "ksl_update_key_range",
                   test_ngtcp2_ksl_update_key_range) ||
      !CU_add_test(pSuite, "ksl_dup", test_ngtcp2_ksl_dup) ||
      !CU_add_test(pSuite, "ksl_remove_hint", test_ngtcp2_ksl_remove_hint) ||
      !CU_add_test(pSuite, "rob_push", test_ngtcp2_rob_push) ||
      !CU_add_test(pSuite, "rob_push_random", test_ngtcp2_rob_push_random) ||
      !CU_add_test(pSuite, "rob_data_at", test_ngtcp2_rob_data_at) ||
      !CU_add_test(pSuite, "rob_remove_prefix",
                   test_ngtcp2_rob_remove_prefix) ||
      !CU_add_test(pSuite, "acktr_add", test_ngtcp2_acktr_add) ||
      !CU_add_test(pSuite, "acktr_eviction", test_ngtcp2_acktr_eviction) ||
      !CU_add_test(pSuite, "acktr_forget", test_ngtcp2_acktr_forget) ||
      !CU_add_test(pSuite, "acktr_recv_ack", test_ngtcp2_acktr_recv_ack) ||
      !CU_add_test(pSuite, "transport_params_encode",
                   test_ngtcp2_transport_params_encode) ||
      !CU_add_test(pSuite, "transport_params_decode_new",
                   test_ngtcp2_transport_params_decode_new) ||
      !CU_add_test(pSuite, "rtb_add", test_ngtcp2_rtb_add) ||
      !CU_add_test(pSuite, "rtb_recv_ack", test_ngtcp2_rtb_recv_ack) ||
      !CU_add_test(pSuite, "rtb_lost_pkt_ts", test_ngtcp2_rtb_lost_pkt_ts) ||
      !CU_add_test(pSuite, "rtb_remove_expired_lost_pkt",
                   test_ngtcp2_rtb_remove_expired_lost_pkt) ||
      !CU_add_test(pSuite, "rtb_remove_excessive_lost_pkt",
                   test_ngtcp2_rtb_remove_excessive_lost_pkt) ||
      !CU_add_test(pSuite, "idtr_open", test_ngtcp2_idtr_open) ||
      !CU_add_test(pSuite, "ringbuf_push_front",
                   test_ngtcp2_ringbuf_push_front) ||
      !CU_add_test(pSuite, "ringbuf_pop_front",
                   test_ngtcp2_ringbuf_pop_front) ||
      !CU_add_test(pSuite, "conn_stream_open_close",
                   test_ngtcp2_conn_stream_open_close) ||
      !CU_add_test(pSuite, "conn_stream_rx_flow_control",
                   test_ngtcp2_conn_stream_rx_flow_control) ||
      !CU_add_test(pSuite, "conn_stream_rx_flow_control_error",
                   test_ngtcp2_conn_stream_rx_flow_control_error) ||
      !CU_add_test(pSuite, "conn_stream_tx_flow_control",
                   test_ngtcp2_conn_stream_tx_flow_control) ||
      !CU_add_test(pSuite, "conn_rx_flow_control",
                   test_ngtcp2_conn_rx_flow_control) ||
      !CU_add_test(pSuite, "conn_rx_flow_control_error",
                   test_ngtcp2_conn_rx_flow_control_error) ||
      !CU_add_test(pSuite, "conn_tx_flow_control",
                   test_ngtcp2_conn_tx_flow_control) ||
      !CU_add_test(pSuite, "conn_shutdown_stream_write",
                   test_ngtcp2_conn_shutdown_stream_write) ||
      !CU_add_test(pSuite, "conn_recv_reset_stream",
                   test_ngtcp2_conn_recv_reset_stream) ||
      !CU_add_test(pSuite, "conn_recv_stop_sending",
                   test_ngtcp2_conn_recv_stop_sending) ||
      !CU_add_test(pSuite, "conn_recv_stream_data_blocked",
                   test_ngtcp2_conn_recv_stream_data_blocked) ||
      !CU_add_test(pSuite, "conn_recv_data_blocked",
                   test_ngtcp2_conn_recv_data_blocked) ||
      !CU_add_test(pSuite, "conn_recv_conn_id_omitted",
                   test_ngtcp2_conn_recv_conn_id_omitted) ||
      !CU_add_test(pSuite, "conn_short_pkt_type",
                   test_ngtcp2_conn_short_pkt_type) ||
      !CU_add_test(pSuite, "conn_recv_stateless_reset",
                   test_ngtcp2_conn_recv_stateless_reset) ||
      !CU_add_test(pSuite, "conn_recv_retry", test_ngtcp2_conn_recv_retry) ||
      !CU_add_test(pSuite, "conn_recv_delayed_handshake_pkt",
                   test_ngtcp2_conn_recv_delayed_handshake_pkt) ||
      !CU_add_test(pSuite, "conn_recv_max_streams",
                   test_ngtcp2_conn_recv_max_streams) ||
      !CU_add_test(pSuite, "conn_handshake", test_ngtcp2_conn_handshake) ||
      !CU_add_test(pSuite, "conn_handshake_error",
                   test_ngtcp2_conn_handshake_error) ||
      !CU_add_test(pSuite, "conn_retransmit_protected",
                   test_ngtcp2_conn_retransmit_protected) ||
      !CU_add_test(pSuite, "conn_send_max_stream_data",
                   test_ngtcp2_conn_send_max_stream_data) ||
      !CU_add_test(pSuite, "conn_recv_stream_data",
                   test_ngtcp2_conn_recv_stream_data) ||
      !CU_add_test(pSuite, "conn_recv_ping", test_ngtcp2_conn_recv_ping) ||
      !CU_add_test(pSuite, "conn_recv_max_stream_data",
                   test_ngtcp2_conn_recv_max_stream_data) ||
      !CU_add_test(pSuite, "conn_send_early_data",
                   test_ngtcp2_conn_send_early_data) ||
      !CU_add_test(pSuite, "conn_recv_early_data",
                   test_ngtcp2_conn_recv_early_data) ||
      !CU_add_test(pSuite, "conn_recv_compound_pkt",
                   test_ngtcp2_conn_recv_compound_pkt) ||
      !CU_add_test(pSuite, "conn_pkt_payloadlen",
                   test_ngtcp2_conn_pkt_payloadlen) ||
      !CU_add_test(pSuite, "conn_writev_stream",
                   test_ngtcp2_conn_writev_stream) ||
      !CU_add_test(pSuite, "conn_writev_datagram",
                   test_ngtcp2_conn_writev_datagram) ||
      !CU_add_test(pSuite, "conn_recv_datagram",
                   test_ngtcp2_conn_recv_datagram) ||
      !CU_add_test(pSuite, "conn_recv_new_connection_id",
                   test_ngtcp2_conn_recv_new_connection_id) ||
      !CU_add_test(pSuite, "conn_recv_retire_connection_id",
                   test_ngtcp2_conn_recv_retire_connection_id) ||
      !CU_add_test(pSuite, "conn_server_path_validation",
                   test_ngtcp2_conn_server_path_validation) ||
      !CU_add_test(pSuite, "conn_client_connection_migration",
                   test_ngtcp2_conn_client_connection_migration) ||
      !CU_add_test(pSuite, "conn_recv_path_challenge",
                   test_ngtcp2_conn_recv_path_challenge) ||
      !CU_add_test(pSuite, "conn_key_update", test_ngtcp2_conn_key_update) ||
      !CU_add_test(pSuite, "conn_crypto_buffer_exceeded",
                   test_ngtcp2_conn_crypto_buffer_exceeded) ||
      !CU_add_test(pSuite, "conn_handshake_probe",
                   test_ngtcp2_conn_handshake_probe) ||
      !CU_add_test(pSuite, "conn_handshake_loss",
                   test_ngtcp2_conn_handshake_loss) ||
      !CU_add_test(pSuite, "conn_probe", test_ngtcp2_conn_probe) ||
      !CU_add_test(pSuite, "conn_recv_client_initial_retry",
                   test_ngtcp2_conn_recv_client_initial_retry) ||
      !CU_add_test(pSuite, "conn_recv_client_initial_token",
                   test_ngtcp2_conn_recv_client_initial_token) ||
      !CU_add_test(pSuite, "conn_get_active_dcid",
                   test_ngtcp2_conn_get_active_dcid) ||
      !CU_add_test(pSuite, "conn_recv_version_negotiation",
                   test_ngtcp2_conn_recv_version_negotiation) ||
      !CU_add_test(pSuite, "conn_send_initial_token",
                   test_ngtcp2_conn_send_initial_token) ||
      !CU_add_test(pSuite, "conn_set_remote_transport_params",
                   test_ngtcp2_conn_set_remote_transport_params) ||
      !CU_add_test(pSuite, "conn_write_connection_close",
                   test_ngtcp2_conn_write_connection_close) ||
      !CU_add_test(pSuite, "conn_write_application_close",
                   test_ngtcp2_conn_write_application_close) ||
      !CU_add_test(pSuite, "conn_rtb_reclaim_on_pto",
                   test_ngtcp2_conn_rtb_reclaim_on_pto) ||
      !CU_add_test(pSuite, "conn_rtb_reclaim_on_pto_datagram",
                   test_ngtcp2_conn_rtb_reclaim_on_pto_datagram) ||
      !CU_add_test(pSuite, "conn_validate_ecn",
                   test_ngtcp2_conn_validate_ecn) ||
      !CU_add_test(pSuite, "conn_path_validation",
                   test_ngtcp2_conn_path_validation) ||
      !CU_add_test(pSuite, "conn_early_data_sync_stream_data_limit",
                   test_ngtcp2_conn_early_data_sync_stream_data_limit) ||
      !CU_add_test(pSuite, "conn_tls_early_data_rejected",
                   test_ngtcp2_conn_tls_early_data_rejected) ||
      !CU_add_test(pSuite, "conn_keep_alive", test_ngtcp2_conn_keep_alive) ||
      !CU_add_test(pSuite, "conn_retire_stale_bound_dcid",
                   test_ngtcp2_conn_retire_stale_bound_dcid) ||
      !CU_add_test(pSuite, "conn_get_scid", test_ngtcp2_conn_get_scid) ||
      !CU_add_test(pSuite, "conn_stream_close",
                   test_ngtcp2_conn_stream_close) ||
      !CU_add_test(pSuite, "conn_buffer_pkt", test_ngtcp2_conn_buffer_pkt) ||
      !CU_add_test(pSuite, "conn_handshake_timeout",
                   test_ngtcp2_conn_handshake_timeout) ||
      !CU_add_test(pSuite, "conn_get_ccerr", test_ngtcp2_conn_get_ccerr) ||
      !CU_add_test(pSuite, "conn_version_negotiation",
                   test_ngtcp2_conn_version_negotiation) ||
      !CU_add_test(pSuite, "conn_server_negotiate_version",
                   test_ngtcp2_conn_server_negotiate_version) ||
      !CU_add_test(pSuite, "conn_pmtud_loss", test_ngtcp2_conn_pmtud_loss) ||
      !CU_add_test(pSuite, "conn_amplification",
                   test_ngtcp2_conn_amplification) ||
      !CU_add_test(pSuite, "conn_encode_0rtt_transport_params",
                   test_ngtcp2_conn_encode_0rtt_transport_params) ||
      !CU_add_test(pSuite, "conn_create_ack_frame",
                   test_ngtcp2_conn_create_ack_frame) ||
      !CU_add_test(pSuite, "conn_grease_quic_bit",
                   test_ngtcp2_conn_grease_quic_bit) ||
      !CU_add_test(pSuite, "conn_send_stream_data_blocked",
                   test_ngtcp2_conn_send_stream_data_blocked) ||
      !CU_add_test(pSuite, "conn_send_data_blocked",
                   test_ngtcp2_conn_send_data_blocked) ||
      !CU_add_test(pSuite, "conn_send_new_connection_id",
                   test_ngtcp2_conn_send_new_connection_id) ||
      !CU_add_test(pSuite, "conn_new_failmalloc",
                   test_ngtcp2_conn_new_failmalloc) ||
      !CU_add_test(pSuite, "accept", test_ngtcp2_accept) ||
      !CU_add_test(pSuite, "select_version", test_ngtcp2_select_version) ||
      !CU_add_test(pSuite, "pkt_write_connection_close",
                   test_ngtcp2_pkt_write_connection_close) ||
      !CU_add_test(pSuite, "map", test_ngtcp2_map) ||
      !CU_add_test(pSuite, "map_functional", test_ngtcp2_map_functional) ||
      !CU_add_test(pSuite, "map_each_free", test_ngtcp2_map_each_free) ||
      !CU_add_test(pSuite, "map_clear", test_ngtcp2_map_clear) ||
      !CU_add_test(pSuite, "gaptr_push", test_ngtcp2_gaptr_push) ||
      !CU_add_test(pSuite, "gaptr_is_pushed", test_ngtcp2_gaptr_is_pushed) ||
      !CU_add_test(pSuite, "gaptr_drop_first_gap",
                   test_ngtcp2_gaptr_drop_first_gap) ||
      !CU_add_test(pSuite, "gaptr_get_first_gep_after",
                   test_ngtcp2_gaptr_get_first_gap_after) ||
      !CU_add_test(pSuite, "vec_split", test_ngtcp2_vec_split) ||
      !CU_add_test(pSuite, "vec_merge", test_ngtcp2_vec_merge) ||
      !CU_add_test(pSuite, "vec_len_varint", test_ngtcp2_vec_len_varint) ||
      !CU_add_test(pSuite, "strm_streamfrq_pop",
                   test_ngtcp2_strm_streamfrq_pop) ||
      !CU_add_test(pSuite, "strm_streamfrq_unacked_offset",
                   test_ngtcp2_strm_streamfrq_unacked_offset) ||
      !CU_add_test(pSuite, "strm_streamfrq_unacked_pop",
                   test_ngtcp2_strm_streamfrq_unacked_pop) ||
      !CU_add_test(pSuite, "pv_add_entry", test_ngtcp2_pv_add_entry) ||
      !CU_add_test(pSuite, "pv_validate", test_ngtcp2_pv_validate) ||
      !CU_add_test(pSuite, "pmtud_probe", test_ngtcp2_pmtud_probe) ||
      !CU_add_test(pSuite, "encode_ipv4", test_ngtcp2_encode_ipv4) ||
      !CU_add_test(pSuite, "encode_ipv6", test_ngtcp2_encode_ipv6) ||
      !CU_add_test(pSuite, "get_bytes", test_ngtcp2_get_bytes) ||
      !CU_add_test(pSuite, "tstamp_elapsed", test_ngtcp2_tstamp_elapsed) ||
      !CU_add_test(pSuite, "transport_params_convert_to_latest",
                   test_ngtcp2_transport_params_convert_to_latest) ||
      !CU_add_test(pSuite, "transport_params_convert_to_old",
                   test_ngtcp2_transport_params_convert_to_old) ||
      !CU_add_test(pSuite, "qlog_write_frame", test_ngtcp2_qlog_write_frame)) {
    CU_cleanup_registry();
    return (int)CU_get_error();
  }

  /* Run all tests using the CUnit Basic interface */
  CU_basic_set_mode(CU_BRM_VERBOSE);
  CU_basic_run_tests();
  num_tests_failed = CU_get_number_of_tests_failed();
  CU_cleanup_registry();
  if (CU_get_error() == CUE_SUCCESS) {
    return (int)num_tests_failed;
  } else {
    printf("CUnit Error: %s\n", CU_get_error_msg());
    return (int)CU_get_error();
  }
}
