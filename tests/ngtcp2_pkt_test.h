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
#ifndef NGTCP2_PKT_TEST_H
#define NGTCP2_PKT_TEST_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

void test_ngtcp2_pkt_decode_version_cid(void);
void test_ngtcp2_pkt_decode_hd_long(void);
void test_ngtcp2_pkt_decode_hd_short(void);
void test_ngtcp2_pkt_decode_frame(void);
void test_ngtcp2_pkt_decode_stream_frame(void);
void test_ngtcp2_pkt_decode_ack_frame(void);
void test_ngtcp2_pkt_decode_padding_frame(void);
void test_ngtcp2_pkt_encode_stream_frame(void);
void test_ngtcp2_pkt_encode_ack_frame(void);
void test_ngtcp2_pkt_encode_ack_ecn_frame(void);
void test_ngtcp2_pkt_encode_reset_stream_frame(void);
void test_ngtcp2_pkt_encode_connection_close_frame(void);
void test_ngtcp2_pkt_encode_connection_close_app_frame(void);
void test_ngtcp2_pkt_encode_application_close_frame(void);
void test_ngtcp2_pkt_encode_max_data_frame(void);
void test_ngtcp2_pkt_encode_max_stream_data_frame(void);
void test_ngtcp2_pkt_encode_max_streams_frame(void);
void test_ngtcp2_pkt_encode_ping_frame(void);
void test_ngtcp2_pkt_encode_data_blocked_frame(void);
void test_ngtcp2_pkt_encode_stream_data_blocked_frame(void);
void test_ngtcp2_pkt_encode_streams_blocked_frame(void);
void test_ngtcp2_pkt_encode_new_connection_id_frame(void);
void test_ngtcp2_pkt_encode_stop_sending_frame(void);
void test_ngtcp2_pkt_encode_path_challenge_frame(void);
void test_ngtcp2_pkt_encode_path_response_frame(void);
void test_ngtcp2_pkt_encode_crypto_frame(void);
void test_ngtcp2_pkt_encode_new_token_frame(void);
void test_ngtcp2_pkt_encode_retire_connection_id_frame(void);
void test_ngtcp2_pkt_encode_handshake_done_frame(void);
void test_ngtcp2_pkt_encode_datagram_frame(void);
void test_ngtcp2_pkt_adjust_pkt_num(void);
void test_ngtcp2_pkt_validate_ack(void);
void test_ngtcp2_pkt_write_stateless_reset(void);
void test_ngtcp2_pkt_write_retry(void);
void test_ngtcp2_pkt_write_version_negotiation(void);
void test_ngtcp2_pkt_stream_max_datalen(void);

#endif /* NGTCP2_PKT_TEST_H */
