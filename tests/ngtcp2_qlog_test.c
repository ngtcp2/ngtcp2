/*
 * ngtcp2
 *
 * Copyright (c) 2023 ngtcp2 contributors
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
#include "ngtcp2_qlog_test.h"

#include <stdio.h>

#include "ngtcp2_qlog.h"
#include "ngtcp2_net.h"
#include "ngtcp2_test_helper.h"

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_qlog_write_frame),
  munit_void_test(test_ngtcp2_qlog_parameters_set_transport_params),
  munit_void_test(test_ngtcp2_qlog_metrics_updated),
  munit_void_test(test_ngtcp2_qlog_pkt_lost),
  munit_void_test(test_ngtcp2_qlog_retry_pkt_received),
  munit_void_test(test_ngtcp2_qlog_stateless_reset_pkt_received),
  munit_void_test(test_ngtcp2_qlog_version_negotiation_pkt_received),
  munit_test_end(),
};

const MunitSuite qlog_suite = {
  .prefix = "/qlog",
  .tests = tests,
};

static void qlog_write(void *user_data, uint32_t flags, const void *data,
                       size_t datalen) {
  uint8_t *buf = user_data;
  (void)flags;

  memcpy(buf, data, datalen);
  buf[datalen] = '\0';
}

void test_ngtcp2_qlog_write_frame(void) {
  ngtcp2_qlog qlog;
  uint8_t buf[1024];
  ngtcp2_ack_range ack_ranges[NGTCP2_MAX_ACK_RANGES];
  ngtcp2_vec datav;
  ngtcp2_frame fr;

  ngtcp2_qlog_init(&qlog, qlog_write, 0, NULL);
  ngtcp2_buf_init(&qlog.buf, buf, sizeof(buf));

  {
    fr.padding = (ngtcp2_padding){
      .type = NGTCP2_FRAME_PADDING,
      .len = 122,
    };

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"padding\"},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr.ping = (ngtcp2_ping){
      .type = NGTCP2_FRAME_PING,
    };

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"ping\"},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr.ack = (ngtcp2_ack){
      .type = NGTCP2_FRAME_ACK,
      .ack_delay_unscaled = 31 * NGTCP2_MILLISECONDS,
      .largest_ack = 1000000007,
    };

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal(
      "{\"frame_type\":\"ack\",\"ack_delay\":31,\"acked_ranges\":[["
      "1000000007]]},",
      (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr.ack = (ngtcp2_ack){
      .type = NGTCP2_FRAME_ACK,
      .ack_delay_unscaled = 31 * NGTCP2_MILLISECONDS,
      .largest_ack = 1000000007,
      .first_ack_range = 11,
      .rangecnt = 1,
      .ranges = ack_ranges,
    };
    ack_ranges[0] = (ngtcp2_ack_range){
      .gap = 17,
      .len = 73,
    };

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal(
      "{\"frame_type\":\"ack\",\"ack_delay\":31,\"acked_ranges\":[["
      "999999996,1000000007],[999999904,999999977]]},",
      (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr.ack = (ngtcp2_ack){
      .type = NGTCP2_FRAME_ACK,
      .ack_delay_unscaled = 31 * NGTCP2_MILLISECONDS,
      .largest_ack = 1000000007,
      .first_ack_range = 11,
      .rangecnt = 2,
      .ranges = ack_ranges,
    };
    ack_ranges[0] = (ngtcp2_ack_range){
      .gap = 17,
      .len = 73,
    };
    ack_ranges[1] = (ngtcp2_ack_range){0};

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal(
      "{\"frame_type\":\"ack\",\"ack_delay\":31,\"acked_ranges\":[["
      "999999996,1000000007],[999999904,999999977],[999999902]]},",
      (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr.ack = (ngtcp2_ack){
      .type = NGTCP2_FRAME_ACK_ECN,
      .ack_delay_unscaled = 31 * NGTCP2_MILLISECONDS,
      .largest_ack = 1000000007,
      .ecn =
        {
          .ect1 = 678912,
          .ect0 = 892363,
          .ce = 956923,
        },
    };

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal(
      "{\"frame_type\":\"ack\",\"ack_delay\":31,\"acked_ranges\":[["
      "1000000007]],\"ect1\":678912,\"ect0\":892363,\"ce\":956923},",
      (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr.reset_stream = (ngtcp2_reset_stream){
      .type = NGTCP2_FRAME_RESET_STREAM,
      .stream_id = 1000000009,
      .app_error_code = 761111,
      .final_size = 1000000007,
    };

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal(
      "{\"frame_type\":\"reset_stream\",\"stream_id\":1000000009,"
      "\"error_code\":761111,\"final_size\":1000000007},",
      (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr.stop_sending = (ngtcp2_stop_sending){
      .type = NGTCP2_FRAME_STOP_SENDING,
      .stream_id = 1000000009,
      .app_error_code = 3119999,
    };

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"stop_sending\",\"stream_id\":"
                        "1000000009,\"error_code\":3119999},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr.stream = (ngtcp2_stream){
      .type = NGTCP2_FRAME_CRYPTO,
      .offset = 65000011,
      .datacnt = 1,
      .data = &datav,
    };
    datav = (ngtcp2_vec){
      .len = 111187,
    };

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"crypto\",\"offset\":65000011,"
                        "\"length\":111187},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr.new_token = (ngtcp2_new_token){
      .type = NGTCP2_FRAME_NEW_TOKEN,
      .tokenlen = 8,
      .token = (uint8_t *)"\x12\x34\x56\x78\x9A\xBC\xDE\xF0",
    };

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"new_token\",\"length\":8,"
                        "\"token\":{\"data\":\"123456789abcdef0\"}},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr.stream = (ngtcp2_stream){
      .type = NGTCP2_FRAME_STREAM,
      .fin = 1,
      .stream_id = 1000000007,
      .offset = 1000000009,
      .datacnt = 1,
      .data = &datav,
    };
    datav = (ngtcp2_vec){
      .len = 8888888,
    };

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal(
      "{\"frame_type\":\"stream\",\"stream_id\":1000000007,"
      "\"offset\":1000000009,\"length\":8888888,\"fin\":true},",
      (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr.stream = (ngtcp2_stream){
      .type = NGTCP2_FRAME_STREAM,
      .stream_id = 1000000007,
      .offset = 1000000009,
      .datacnt = 1,
      .data = &datav,
    };
    datav = (ngtcp2_vec){
      .len = 8888888,
    };

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"stream\",\"stream_id\":1000000007,"
                        "\"offset\":1000000009,\"length\":8888888},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr.max_data = (ngtcp2_max_data){
      .type = NGTCP2_FRAME_MAX_DATA,
      .max_data = 89624231,
    };

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"max_data\",\"maximum\":89624231},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr.max_stream_data = (ngtcp2_max_stream_data){
      .type = NGTCP2_FRAME_MAX_STREAM_DATA,
      .stream_id = 1000000009,
      .max_stream_data = 3479131413562775697,
    };

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"max_stream_data\",\"stream_id\":"
                        "1000000009,\"maximum\":3479131413562775697},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr.max_streams = (ngtcp2_max_streams){
      .type = NGTCP2_FRAME_MAX_STREAMS_BIDI,
      .max_streams = 3947405932436725448,
    };

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"max_streams\",\"stream_type\":"
                        "\"bidirectional\",\"maximum\":3947405932436725448},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr.max_streams = (ngtcp2_max_streams){
      .type = NGTCP2_FRAME_MAX_STREAMS_UNI,
      .max_streams = 2650981103699753174,
    };

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"max_streams\",\"stream_type\":"
                        "\"unidirectional\",\"maximum\":2650981103699753174},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr.data_blocked = (ngtcp2_data_blocked){
      .type = NGTCP2_FRAME_DATA_BLOCKED,
      .offset = 141245489541204826,
    };

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal(
      "{\"frame_type\":\"data_blocked\",\"limit\":141245489541204826},",
      (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr.stream_data_blocked = (ngtcp2_stream_data_blocked){
      .type = NGTCP2_FRAME_STREAM_DATA_BLOCKED,
      .stream_id = 1000000007,
      .offset = 3510083742766371473,
    };

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"stream_data_blocked\",\"stream_"
                        "id\":1000000007,\"limit\":3510083742766371473},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr.streams_blocked = (ngtcp2_streams_blocked){
      .type = NGTCP2_FRAME_STREAMS_BLOCKED_BIDI,
      .max_streams = 267807966110011001,
    };

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"streams_blocked\",\"stream_type\":"
                        "\"bidirectional\",\"limit\":267807966110011001},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr.streams_blocked = (ngtcp2_streams_blocked){
      .type = NGTCP2_FRAME_STREAMS_BLOCKED_UNI,
      .max_streams = 4147150966951874727,
    };

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"streams_blocked\",\"stream_type\":"
                        "\"unidirectional\",\"limit\":4147150966951874727},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr.new_connection_id = (ngtcp2_new_connection_id){
      .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
      .seq = 2322933918954521341,
      .retire_prior_to = 353598537829135415,
      .cid =
        {
          .datalen = 8,
          .data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
        },
      .token =
        {
          .data = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
                   0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x10},
        },
    };

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal(
      "{\"frame_type\":\"new_connection_id\",\"sequence_number\":"
      "2322933918954521341,\"retire_prior_to\":353598537829135415,"
      "\"connection_id_length\":8,\"connection_id\":"
      "\"0102030405060708\",\"stateless_reset_token\":{\"data\":"
      "\"1112131415161718191a1b1c1d1e1f10\"}},",
      (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr.retire_connection_id = (ngtcp2_retire_connection_id){
      .type = NGTCP2_FRAME_RETIRE_CONNECTION_ID,
      .seq = 923246273261945495,
    };

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"retire_connection_id\","
                        "\"sequence_number\":923246273261945495},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr.path_challenge = (ngtcp2_path_challenge){
      .type = NGTCP2_FRAME_PATH_CHALLENGE,
      .data =
        {
          .data = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
        },
    };

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"path_challenge\",\"data\":"
                        "\"1122334455667788\"},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr.path_response = (ngtcp2_path_response){
      .type = NGTCP2_FRAME_PATH_RESPONSE,
      .data =
        {
          .data = {0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99},
        },
    };

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"path_response\",\"data\":"
                        "\"2233445566778899\"},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr.connection_close = (ngtcp2_connection_close){
      .type = NGTCP2_FRAME_CONNECTION_CLOSE,
      .error_code = 3270540419184339176,
    };

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal(
      "{\"frame_type\":\"connection_close\",\"error_space\":"
      "\"transport\",\"error_code\":3270540419184339176,\"raw_"
      "error_code\":3270540419184339176},",
      (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr.connection_close = (ngtcp2_connection_close){
      .type = NGTCP2_FRAME_CONNECTION_CLOSE_APP,
      .error_code = 1069447711149177103,
    };

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"connection_close\",\"error_space\":"
                        "\"application\",\"error_code\":1069447711149177103,"
                        "\"raw_error_code\":1069447711149177103},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr.handshake_done = (ngtcp2_handshake_done){
      .type = NGTCP2_FRAME_HANDSHAKE_DONE,
    };

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"handshake_done\"},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr.datagram = (ngtcp2_datagram){
      .type = NGTCP2_FRAME_DATAGRAM,
      .datacnt = 1,
      .data = &datav,
    };
    datav = (ngtcp2_vec){
      .len = 1301458,
    };

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"datagram\",\"length\":1301458},",
                        (const char *)qlog.buf.begin);
  }
}

void test_ngtcp2_qlog_parameters_set_transport_params(void) {
  ngtcp2_qlog qlog;
  uint8_t buf[4096];
  ngtcp2_transport_params params;

  ngtcp2_qlog_init(&qlog, qlog_write, 0, buf);
  qlog.last_ts = 18446744073709551615ULL;

  params = (ngtcp2_transport_params){
    .preferred_addr =
      {
        .cid =
          {
            .data = {0xFF, 0xFE, 0xC0, 0x98},
            .datalen = NGTCP2_MAX_CIDLEN,
          },
        .ipv4 =
          {
            .sin_port = ngtcp2_htons(UINT16_MAX),
            .sin_addr.s_addr = ngtcp2_htonl(0xDEADF00D),
          },
        .ipv6 =
          {
            .sin6_port = ngtcp2_htons(UINT16_MAX),
          },
        .ipv4_present = 1,
        .ipv6_present = 1,
        .stateless_reset_token = {0xDD, 0xC1, 0xB9, 0x91, 0xDA, 0xB6, 0x00,
                                  0x67, 0xE5, 0x91, 0x49, 0xEF, 0x0E, 0x2F,
                                  0x53, 0x23},
      },
    .original_dcid =
      {
        .data = {0x17, 0x42, 0xB4, 0x90, 0x37, 0x00, 0x95, 0x0A},
        .datalen = NGTCP2_MAX_CIDLEN,
      },
    .initial_scid =
      {
        .data = {0x78, 0x7E, 0x47, 0xB6, 0xF2, 0xAE, 0x4B, 0xB6},
        .datalen = NGTCP2_MAX_CIDLEN,
      },
    .retry_scid =
      {
        .data = {0x14, 0x13, 0x21, 0xA0, 0x88, 0x65, 0x2A, 0x0C},
        .datalen = NGTCP2_MAX_CIDLEN,
      },
    .initial_max_stream_data_bidi_local = NGTCP2_MAX_VARINT,
    .initial_max_stream_data_bidi_remote = NGTCP2_MAX_VARINT,
    .initial_max_stream_data_uni = NGTCP2_MAX_VARINT,
    .initial_max_data = NGTCP2_MAX_VARINT,
    .initial_max_streams_bidi = NGTCP2_MAX_VARINT,
    .initial_max_streams_uni = NGTCP2_MAX_VARINT,
    .max_idle_timeout = NGTCP2_MAX_VARINT,
    .max_udp_payload_size = NGTCP2_MAX_VARINT,
    .active_connection_id_limit = NGTCP2_MAX_VARINT,
    .ack_delay_exponent = NGTCP2_MAX_VARINT,
    .max_ack_delay = NGTCP2_MAX_VARINT,
    .max_datagram_frame_size = NGTCP2_MAX_VARINT,
    .stateless_reset_token_present = 1,
    .disable_active_migration = 1,
    .original_dcid_present = 1,
    .initial_scid_present = 1,
    .retry_scid_present = 1,
    .preferred_addr_present = 1,
    .stateless_reset_token = {0xEE, 0x58, 0x92, 0x91, 0x6F, 0xDE, 0x87, 0xDC,
                              0x64, 0xC1, 0x04, 0xAB, 0x32, 0xFE, 0xC6, 0x25},
    .grease_quic_bit = 1,
  };

  memcpy(&params.preferred_addr.ipv6.sin6_addr,
         (uint8_t[]){0x5F, 0x6E, 0xEF, 0x1A, 0xDA, 0x56, 0x4F, 0x62, 0xE4, 0xDE,
                     0xA0, 0x76, 0x9B, 0x21, 0xC6, 0x2B},
         sizeof(params.preferred_addr.ipv6.sin6_addr));

  ngtcp2_qlog_parameters_set_transport_params(&qlog, &params, /* server = */ 0,
                                              NGTCP2_QLOG_SIDE_REMOTE);

  assert_string_equal(
    "\x1E{\"time\":18446744073709,\"name\":\"transport:parameters_set\","
    "\"data\":{\"owner\":\"remote\","
    "\"initial_source_connection_id\":"
    "\"787e47b6f2ae4bb6000000000000000000000000\","
    "\"original_destination_connection_id\":"
    "\"1742b4903700950a000000000000000000000000\","
    "\"retry_source_connection_id\":"
    "\"141321a088652a0c000000000000000000000000\","
    "\"stateless_reset_token\":{\"data\":\"ee5892916fde87dc64c104ab32fec625\"},"
    "\"disable_active_migration\":true,"
    "\"max_idle_timeout\":4611686018427,"
    "\"max_udp_payload_size\":4611686018427387903,"
    "\"ack_delay_exponent\":4611686018427387903,"
    "\"max_ack_delay\":4611686018427,"
    "\"active_connection_id_limit\":4611686018427387903,"
    "\"initial_max_data\":4611686018427387903,"
    "\"initial_max_stream_data_bidi_local\":4611686018427387903,"
    "\"initial_max_stream_data_bidi_remote\":4611686018427387903,"
    "\"initial_max_stream_data_uni\":4611686018427387903,"
    "\"initial_max_streams_bidi\":4611686018427387903,"
    "\"initial_max_streams_uni\":4611686018427387903,"
    "\"preferred_address\":{"
    "\"ip_v4\":\"deadf00d\","
    "\"port_v4\":65535,"
    "\"ip_v6\":\"5f6eef1ada564f62e4dea0769b21c62b\","
    "\"port_v6\":65535,"
    "\"connection_id\":\"fffec09800000000000000000000000000000000\","
    "\"stateless_reset_token\":{\"data\":\"ddc1b991dab60067e59149ef0e2f5323\"}}"
    ","
    "\"max_datagram_frame_size\":4611686018427387903,"
    "\"grease_quic_bit\":true}}\n",
    (const char *)buf);
}

void test_ngtcp2_qlog_metrics_updated(void) {
  ngtcp2_qlog qlog;
  uint8_t buf[1024];
  ngtcp2_conn_stat cstat = {
    .latest_rtt = UINT64_MAX,
    .min_rtt = UINT64_MAX - 1,
    .smoothed_rtt = UINT64_MAX,
    .rttvar = UINT64_MAX,
    /* To fit size_t in 32 bit systems */
    .pto_count = UINT32_MAX,
    .cwnd = UINT64_MAX,
    .ssthresh = UINT64_MAX - 1,
    .bytes_in_flight = UINT64_MAX,
  };

  ngtcp2_qlog_init(&qlog, qlog_write, 0, buf);
  qlog.last_ts = 18446744073709551615ULL;

  ngtcp2_qlog_metrics_updated(&qlog, &cstat);
  assert_string_equal(
    "\x1E{\"time\":18446744073709,"
    "\"name\":\"recovery:metrics_updated\",\"data\":{"
    "\"min_rtt\":18446744073709,\"smoothed_rtt\":18446744073709,"
    "\"latest_rtt\":18446744073709,\"rtt_variance\":18446744073709,"
    "\"pto_count\":4294967295,"
    "\"congestion_window\":18446744073709551615,"
    "\"bytes_in_flight\":18446744073709551615,"
    "\"ssthresh\":18446744073709551614}}\n",
    (const char *)buf);
}

void test_ngtcp2_qlog_pkt_lost(void) {
  ngtcp2_qlog qlog;
  uint8_t buf[2048];
  ngtcp2_rtb_entry ent = {
    .hd =
      {
        .pkt_num = NGTCP2_MAX_VARINT,
        .type = NGTCP2_PKT_HANDSHAKE,
        .flags = NGTCP2_PKT_FLAG_LONG_FORM,
      },
  };

  ngtcp2_qlog_init(&qlog, qlog_write, 0, buf);
  qlog.last_ts = 18446744073709551615ULL;

  ngtcp2_qlog_pkt_lost(&qlog, &ent);

  assert_string_equal(
    "\x1E{\"time\":18446744073709,\"name\":\"recovery:packet_lost\","
    "\"data\":{\"header\":{"
    "\"packet_type\":\"handshake\",\"packet_number\":4611686018427387903}}}\n",
    (const char *)buf);
}

void test_ngtcp2_qlog_retry_pkt_received(void) {
  ngtcp2_qlog qlog;
  uint8_t buf[1024];
  ngtcp2_pkt_hd hd = {
    .type = NGTCP2_PKT_RETRY,
    .flags = NGTCP2_PKT_FLAG_LONG_FORM,
  };
  ngtcp2_pkt_retry retry = {
    .token = (uint8_t *)"\xDE\xAD\xBE\xEF",
    .tokenlen = 4,
  };

  ngtcp2_qlog_init(&qlog, qlog_write, 0, buf);
  qlog.last_ts = 18446744073709551615ULL;

  ngtcp2_qlog_retry_pkt_received(&qlog, &hd, &retry);

  assert_string_equal(
    "\x1E{\"time\":18446744073709,\"name\":\"transport:packet_received\","
    "\"data\":{\"header\":{\"packet_type\":\"retry\",\"packet_number\":0},"
    "\"retry_token\":{\"data\":\"deadbeef\"}}}\n",
    (const char *)buf);
}

void test_ngtcp2_qlog_stateless_reset_pkt_received(void) {
  ngtcp2_qlog qlog;
  uint8_t buf[256];
  ngtcp2_pkt_stateless_reset2 sr = {
    .token =
      {
        .data = {0xF1, 0xE2, 0xD3, 0xC4, 0xB5, 0xA6, 0x07, 0x98, 0x89, 0x70,
                 0x6A, 0x5B, 0x4C, 0x3D, 0x2E, 0x1F},
      },
  };

  ngtcp2_qlog_init(&qlog, qlog_write, 0, buf);
  qlog.last_ts = 18446744073709551615ULL;

  ngtcp2_qlog_stateless_reset_pkt_received(&qlog, &sr);

  assert_string_equal(
    "\x1E{\"time\":18446744073709,\"name\":\"transport:packet_received\","
    "\"data\":{\"header\":{"
    "\"packet_type\":\"stateless_reset\",\"packet_number\":0},"
    "\"stateless_reset_token\":\"f1e2d3c4b5a6079889706a5b4c3d2e1f\"}}\n",
    (const char *)buf);
}

void test_ngtcp2_qlog_version_negotiation_pkt_received(void) {
  ngtcp2_qlog qlog;
  uint8_t buf[512];
  ngtcp2_pkt_hd hd = {
    .type = NGTCP2_PKT_VERSION_NEGOTIATION,
  };
  uint32_t versions[] = {
    0xBADDCAFE,
    0xDEADBEEF,
    0xFACEFEED,
    0xBAADF00D,
  };

  ngtcp2_qlog_init(&qlog, qlog_write, 0, buf);
  qlog.last_ts = 18446744073709551615ULL;

  ngtcp2_qlog_version_negotiation_pkt_received(&qlog, &hd, versions,
                                               ngtcp2_arraylen(versions));

  assert_string_equal(
    "\x1E{\"time\":18446744073709,\"name\":\"transport:packet_received\","
    "\"data\":{\"header\":{"
    "\"packet_type\":\"version_negotiation\",\"packet_number\":0},"
    "\"supported_versions\":["
    "\"baddcafe\",\"deadbeef\",\"facefeed\",\"baadf00d\"]}}\n",
    (const char *)buf);
}
