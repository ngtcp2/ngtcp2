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
  munit_void_test(test_ngtcp2_qlog_write_start_end),
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

static void null_qlog_write(void *user_data, uint32_t flags, const void *data,
                            size_t datalen) {
  uint8_t *buf = user_data;
  (void)flags;

  if (buf == NULL) {
    return;
  }

  memcpy(buf, data, datalen);
  buf[datalen] = '\0';
}

void test_ngtcp2_qlog_write_start_end(void) {
  ngtcp2_qlog qlog;
  uint8_t qbuf[1024], buf[1024];
  ngtcp2_pkt_hd hd;

  /* 1RTT packet */
  hd = (ngtcp2_pkt_hd){
    .pkt_num = 912,
    .type = NGTCP2_PKT_1RTT,
  };

  ngtcp2_qlog_init(&qlog, null_qlog_write, 0, buf);
  ngtcp2_buf_init(&qlog.buf, qbuf, sizeof(qbuf));

  qlog.last_ts = 999 * NGTCP2_MILLISECONDS;
  ngtcp2_qlog_pkt_received_start(&qlog);
  ngtcp2_qlog_pkt_received_end(&qlog, &hd, 1414);

  assert_string_equal(
    "\x1e{\"time\":999,\"name\":\"quic:packet_received\","
    "\"data\":{\"frames\":[],"
    "\"header\":{\"packet_type\":\"1RTT\",\"packet_number\":912},"
    "\"raw\":{\"length\":1414}}}\n",
    (const char *)buf);

  /* initial */
  hd = (ngtcp2_pkt_hd){
    .pkt_num = 1000000007,
    .type = NGTCP2_PKT_INITIAL,
    .flags = NGTCP2_PKT_FLAG_LONG_FORM,
  };

  ngtcp2_qlog_pkt_received_start(&qlog);
  ngtcp2_qlog_pkt_received_end(&qlog, &hd, 1200);

  assert_string_equal(
    "\x1e{\"time\":999,\"name\":\"quic:packet_received\","
    "\"data\":{\"frames\":[],"
    "\"header\":{\"packet_type\":\"initial\",\"packet_number\":1000000007},"
    "\"raw\":{\"length\":1200}}}\n",
    (const char *)buf);

  /* initial with token */
  hd = (ngtcp2_pkt_hd){
    .pkt_num = 1000000007,
    .type = NGTCP2_PKT_INITIAL,
    .token = (const uint8_t *)"\xde\xad\xbe\xef",
    .tokenlen = 4,
    .flags = NGTCP2_PKT_FLAG_LONG_FORM,
  };

  ngtcp2_qlog_pkt_received_start(&qlog);
  ngtcp2_qlog_pkt_received_end(&qlog, &hd, 1200);

  assert_string_equal(
    "\x1e{\"time\":999,\"name\":\"quic:packet_received\","
    "\"data\":{\"frames\":[],"
    "\"header\":{\"packet_type\":\"initial\",\"packet_number\":1000000007,"
    "\"token\":{\"raw\":{\"data\":\"deadbeef\"}}},"
    "\"raw\":{\"length\":1200}}}\n",
    (const char *)buf);

  /* handshake */
  hd = (ngtcp2_pkt_hd){
    .pkt_num = 1000000007,
    .type = NGTCP2_PKT_HANDSHAKE,
    .flags = NGTCP2_PKT_FLAG_LONG_FORM,
  };

  ngtcp2_qlog_pkt_received_start(&qlog);
  ngtcp2_qlog_pkt_received_end(&qlog, &hd, 1200);

  assert_string_equal(
    "\x1e{\"time\":999,\"name\":\"quic:packet_received\","
    "\"data\":{\"frames\":[],"
    "\"header\":{\"packet_type\":\"handshake\",\"packet_number\":1000000007},"
    "\"raw\":{\"length\":1200}}}\n",
    (const char *)buf);

  /* 0RTT */
  hd = (ngtcp2_pkt_hd){
    .pkt_num = 1000000007,
    .type = NGTCP2_PKT_0RTT,
    .flags = NGTCP2_PKT_FLAG_LONG_FORM,
  };

  ngtcp2_qlog_pkt_received_start(&qlog);
  ngtcp2_qlog_pkt_received_end(&qlog, &hd, 1200);

  assert_string_equal(
    "\x1e{\"time\":999,\"name\":\"quic:packet_received\","
    "\"data\":{\"frames\":[],"
    "\"header\":{\"packet_type\":\"0RTT\",\"packet_number\":1000000007},"
    "\"raw\":{\"length\":1200}}}\n",
    (const char *)buf);

  /* unknown packet type */
  hd = (ngtcp2_pkt_hd){
    .type = 255,
  };

  ngtcp2_qlog_pkt_received_start(&qlog);
  ngtcp2_qlog_pkt_received_end(&qlog, &hd, 1200);

  assert_string_equal("\x1e{\"time\":999,\"name\":\"quic:packet_received\","
                      "\"data\":{\"frames\":[],"
                      "\"header\":{\"packet_type\":\"unknown\"},"
                      "\"raw\":{\"length\":1200}}}\n",
                      (const char *)buf);
}

void test_ngtcp2_qlog_write_frame(void) {
  ngtcp2_qlog qlog;
  uint8_t buf[1024];
  ngtcp2_ack_range ack_ranges[NGTCP2_MAX_ACK_RANGES];
  ngtcp2_vec datav;
  ngtcp2_frame fr;

  ngtcp2_qlog_init(&qlog, null_qlog_write, 0, NULL);
  ngtcp2_buf_init(&qlog.buf, buf, sizeof(buf));

  {
    fr.padding = (ngtcp2_padding){
      .type = NGTCP2_FRAME_PADDING,
      .len = 122,
    };

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal(
      "{\"frame_type\":\"padding\",\"raw\":{\"payload_length\":122}},",
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
      "{\"frame_type\":\"reset_stream\",\"error\":\"unknown\","
      "\"stream_id\":1000000009,\"error_code\":761111,"
      "\"final_size\":1000000007},",
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

    assert_string_equal(
      "{\"frame_type\":\"stop_sending\",\"error\":\"unknown\","
      "\"stream_id\":1000000009,\"error_code\":3119999},",
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

    assert_string_equal(
      "{\"frame_type\":\"crypto\",\"raw\":{\"length\":111187},"
      "\"offset\":65000011},",
      (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr.new_token = (ngtcp2_new_token){
      .type = NGTCP2_FRAME_NEW_TOKEN,
      .tokenlen = 8,
      .token = (uint8_t *)"\x12\x34\x56\x78\x9a\xbc\xde\xf0",
    };

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"new_token\",\"token\":{\"raw\":{"
                        "\"length\":8,\"data\":\"123456789abcdef0\"}}},",
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
      "{\"frame_type\":\"stream\",\"raw\":{\"length\":8888888},"
      "\"stream_id\":1000000007,\"offset\":1000000009,\"fin\":true},",
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

    assert_string_equal(
      "{\"frame_type\":\"stream\",\"raw\":{\"length\":8888888},"
      "\"stream_id\":1000000007,\"offset\":1000000009},",
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
    };
    ngtcp2_cid_init(&fr.new_connection_id.cid,
                    (const uint8_t *)"\x01\x02\x03\x04\x05\x06\x07\x08", 8);
    memcpy(fr.new_connection_id.stateless_reset_token,
           "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x10",
           NGTCP2_STATELESS_RESET_TOKENLEN);

    ngtcp2_qlog_write_frame(&qlog, &fr);
    *qlog.buf.last = '\0';

    assert_string_equal(
      "{\"frame_type\":\"new_connection_id\",\"sequence_number\":"
      "2322933918954521341,\"retire_prior_to\":353598537829135415,"
      "\"connection_id_length\":8,"
      "\"connection_id\":\"0102030405060708\","
      "\"stateless_reset_token\":\"1112131415161718191a1b1c1d1e1f10\"},",
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
    };
    memcpy(fr.path_challenge.data, "\x11\x22\x33\x44\x55\x66\x77\x88",
           NGTCP2_PATH_CHALLENGE_DATALEN);

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
    };
    memcpy(fr.path_challenge.data, "\x22\x33\x44\x55\x66\x77\x88\x99",
           NGTCP2_PATH_CHALLENGE_DATALEN);

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

    assert_string_equal("{\"frame_type\":\"connection_close\","
                        "\"error_space\":\"transport\",\"error\":\"unknown\","
                        "\"error_code\":3270540419184339176},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr->connection_close = (ngtcp2_connection_close){
      .type = NGTCP2_FRAME_CONNECTION_CLOSE,
      .error_code = NGTCP2_TRANSPORT_PARAMETER_ERROR,
    };

    ngtcp2_qlog_write_frame(&qlog, fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"connection_close\","
                        "\"error_space\":\"transport\","
                        "\"error\":\"transport_parameter_error\"},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    fr->connection_close = (ngtcp2_connection_close){
      .type = NGTCP2_FRAME_CONNECTION_CLOSE,
      .error_code = NGTCP2_CRYPTO_ERROR | 0xec,
    };

    ngtcp2_qlog_write_frame(&qlog, fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"connection_close\","
                        "\"error_space\":\"transport\","
                        "\"error\":\"crypto_error_0x1ec\"},",
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

    assert_string_equal("{\"frame_type\":\"connection_close\","
                        "\"error_space\":\"application\",\"error\":\"unknown\","
                        "\"error_code\":1069447711149177103},",
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

    assert_string_equal(
      "{\"frame_type\":\"datagram\",\"raw\":{\"length\":1301458}},",
      (const char *)qlog.buf.begin);
  }
}

#ifndef NGTCP2_USE_GENERIC_SOCKADDR
typedef struct in6_addr ngtcp2_in6_addr;
#endif /* !defined(NGTCP2_USE_GENERIC_SOCKADDR) */

void test_ngtcp2_qlog_parameters_set_transport_params(void) {
  ngtcp2_qlog qlog;
  uint8_t buf[1024];
  ngtcp2_transport_params params;
  ngtcp2_in6_addr v6addr;

  memcpy(&v6addr,
         (uint8_t[]){0x5f, 0x6e, 0xef, 0x1a, 0xda, 0x56, 0x4f, 0x62, 0xe4, 0xde,
                     0xa0, 0x76, 0x9b, 0x21, 0xc6, 0x2b},
         sizeof(v6addr));

  ngtcp2_qlog_init(&qlog, null_qlog_write, 0, buf);
  ngtcp2_buf_init(&qlog.buf, buf, sizeof(buf));

  params = (ngtcp2_transport_params){
    .preferred_addr =
      {
        .cid =
          {
            .data = {0xff, 0xfe, 0xc0, 0x98},
            .datalen = 4,
          },
        .ipv4 =
          {
            .sin_port = ngtcp2_htons(50258),
            .sin_addr.s_addr = ngtcp2_htonl(0xdeadf00d),
          },
        .ipv6 =
          {
            .sin6_port = ngtcp2_htons(10046),
            .sin6_addr = v6addr,
          },
        .ipv4_present = 1,
        .ipv6_present = 1,
        .stateless_reset_token = {0xdd, 0xc1, 0xb9, 0x91, 0xda, 0xb6, 0x00,
                                  0x67, 0xe5, 0x91, 0x49, 0xef, 0x0e, 0x2f,
                                  0x53, 0x23},
      },
    .original_dcid =
      {
        .data = {0x17, 0x42, 0xb4, 0x90, 0x37, 0x00, 0x95, 0x0a},
        .datalen = 8,
      },
    .initial_scid =
      {
        .data = {0x78, 0x7e, 0x47, 0xb6, 0xf2, 0xae, 0x4b, 0xb6},
        .datalen = 8,
      },
    .retry_scid =
      {
        .data = {0x14, 0x13, 0x21, 0xa0, 0x88, 0x65, 0x2a, 0x0c},
        .datalen = 8,
      },
    .initial_max_stream_data_bidi_local = 937233,
    .initial_max_stream_data_bidi_remote = 32322,
    .initial_max_stream_data_uni = 112,
    .initial_max_data = 893223,
    .initial_max_streams_bidi = 3232399,
    .initial_max_streams_uni = 99993232,
    .max_idle_timeout = 122 * NGTCP2_SECONDS,
    .max_udp_payload_size = 65527,
    .active_connection_id_limit = 88710,
    .ack_delay_exponent = 7123,
    .max_ack_delay = 276 * NGTCP2_MILLISECONDS,
    .max_datagram_frame_size = 678,
    .stateless_reset_token_present = 1,
    .disable_active_migration = 1,
    .original_dcid_present = 1,
    .initial_scid_present = 1,
    .retry_scid_present = 1,
    .preferred_addr_present = 1,
    .stateless_reset_token = {0xee, 0x58, 0x92, 0x91, 0x6f, 0xde, 0x87, 0xdc,
                              0x64, 0xc1, 0x04, 0xab, 0x32, 0xfe, 0xc6, 0x25},
    .grease_quic_bit = 1,
  };

  ngtcp2_qlog_parameters_set_transport_params(&qlog, &params,
                                              NGTCP2_QLOG_INITIATOR_LOCAL);

  assert_string_equal(
    "\x1e{\"time\":0,\"name\":\"quic:parameters_set\","
    "\"data\":{\"initiator\":\"local\","
    "\"initial_source_connection_id\":\"787e47b6f2ae4bb6\","
    "\"original_destination_connection_id\":\"1742b4903700950a\","
    "\"retry_source_connection_id\":\"141321a088652a0c\","
    "\"stateless_reset_token\":\"ee5892916fde87dc64c104ab32fec625\","
    "\"disable_active_migration\":true,"
    "\"max_idle_timeout\":122000,"
    "\"max_udp_payload_size\":65527,"
    "\"ack_delay_exponent\":7123,"
    "\"max_ack_delay\":276,"
    "\"active_connection_id_limit\":88710,"
    "\"initial_max_data\":893223,"
    "\"initial_max_stream_data_bidi_local\":937233,"
    "\"initial_max_stream_data_bidi_remote\":32322,"
    "\"initial_max_stream_data_uni\":112,"
    "\"initial_max_streams_bidi\":3232399,"
    "\"initial_max_streams_uni\":99993232,"
    "\"preferred_address\":{"
    "\"connection_id\":\"fffec098\","
    "\"stateless_reset_token\":\"ddc1b991dab60067e59149ef0e2f5323\","
    "\"ip_v4\":\"deadf00d\","
    "\"port_v4\":50258,"
    "\"ip_v6\":\"5f6eef1ada564f62e4dea0769b21c62b\","
    "\"port_v6\":10046},"
    "\"max_datagram_frame_size\":678,"
    "\"grease_quic_bit\":true}}\n",
    (const char *)buf);

  /* Check minimum settings.  Note we always write initial_scid
     because it is a required field. */
  params.stateless_reset_token_present = 0;
  params.original_dcid_present = 0;
  params.retry_scid_present = 0;
  params.preferred_addr_present = 0;

  ngtcp2_qlog_parameters_set_transport_params(&qlog, &params,
                                              NGTCP2_QLOG_INITIATOR_REMOTE);

  assert_string_equal("\x1e{\"time\":0,\"name\":\"quic:parameters_set\","
                      "\"data\":{\"initiator\":\"remote\","
                      "\"initial_source_connection_id\":\"787e47b6f2ae4bb6\","
                      "\"disable_active_migration\":true,"
                      "\"max_idle_timeout\":122000,"
                      "\"max_udp_payload_size\":65527,"
                      "\"ack_delay_exponent\":7123,"
                      "\"max_ack_delay\":276,"
                      "\"active_connection_id_limit\":88710,"
                      "\"initial_max_data\":893223,"
                      "\"initial_max_stream_data_bidi_local\":937233,"
                      "\"initial_max_stream_data_bidi_remote\":32322,"
                      "\"initial_max_stream_data_uni\":112,"
                      "\"initial_max_streams_bidi\":3232399,"
                      "\"initial_max_streams_uni\":99993232,"
                      "\"max_datagram_frame_size\":678,"
                      "\"grease_quic_bit\":true}}\n",
                      (const char *)buf);

  /* Preferred address with IPv4 only */
  params.preferred_addr_present = 1;
  params.preferred_addr = (ngtcp2_preferred_addr){
    .cid =
      {
        .data = {0xff, 0xfe, 0xc0, 0x98},
        .datalen = 4,
      },
    .ipv4 =
      {
        .sin_port = ngtcp2_htons(50258),
        .sin_addr.s_addr = ngtcp2_htonl(0xdeadf00d),
      },
    .ipv4_present = 1,
    .stateless_reset_token = {0xdd, 0xc1, 0xb9, 0x91, 0xda, 0xb6, 0x00, 0x67,
                              0xe5, 0x91, 0x49, 0xef, 0x0e, 0x2f, 0x53, 0x23},
  };

  ngtcp2_qlog_parameters_set_transport_params(&qlog, &params,
                                              NGTCP2_QLOG_INITIATOR_REMOTE);

  assert_string_equal(
    "\x1e{\"time\":0,\"name\":\"quic:parameters_set\","
    "\"data\":{\"initiator\":\"remote\","
    "\"initial_source_connection_id\":\"787e47b6f2ae4bb6\","
    "\"disable_active_migration\":true,"
    "\"max_idle_timeout\":122000,"
    "\"max_udp_payload_size\":65527,"
    "\"ack_delay_exponent\":7123,"
    "\"max_ack_delay\":276,"
    "\"active_connection_id_limit\":88710,"
    "\"initial_max_data\":893223,"
    "\"initial_max_stream_data_bidi_local\":937233,"
    "\"initial_max_stream_data_bidi_remote\":32322,"
    "\"initial_max_stream_data_uni\":112,"
    "\"initial_max_streams_bidi\":3232399,"
    "\"initial_max_streams_uni\":99993232,"
    "\"preferred_address\":{"
    "\"connection_id\":\"fffec098\","
    "\"stateless_reset_token\":\"ddc1b991dab60067e59149ef0e2f5323\","
    "\"ip_v4\":\"deadf00d\","
    "\"port_v4\":50258},"
    "\"max_datagram_frame_size\":678,"
    "\"grease_quic_bit\":true}}\n",
    (const char *)buf);

  /* Preferred address with IPv6 only */
  params.preferred_addr_present = 1;
  params.preferred_addr = (ngtcp2_preferred_addr){
    .cid =
      {
        .data = {0xff, 0xfe, 0xc0, 0x98},
        .datalen = 4,
      },
    .ipv6 =
      {
        .sin6_port = ngtcp2_htons(10046),
        .sin6_addr = v6addr,
      },
    .ipv6_present = 1,
    .stateless_reset_token = {0xdd, 0xc1, 0xb9, 0x91, 0xda, 0xb6, 0x00, 0x67,
                              0xe5, 0x91, 0x49, 0xef, 0x0e, 0x2f, 0x53, 0x23},
  };

  ngtcp2_qlog_parameters_set_transport_params(&qlog, &params,
                                              NGTCP2_QLOG_INITIATOR_REMOTE);

  assert_string_equal(
    "\x1e{\"time\":0,\"name\":\"quic:parameters_set\","
    "\"data\":{\"initiator\":\"remote\","
    "\"initial_source_connection_id\":\"787e47b6f2ae4bb6\","
    "\"disable_active_migration\":true,"
    "\"max_idle_timeout\":122000,"
    "\"max_udp_payload_size\":65527,"
    "\"ack_delay_exponent\":7123,"
    "\"max_ack_delay\":276,"
    "\"active_connection_id_limit\":88710,"
    "\"initial_max_data\":893223,"
    "\"initial_max_stream_data_bidi_local\":937233,"
    "\"initial_max_stream_data_bidi_remote\":32322,"
    "\"initial_max_stream_data_uni\":112,"
    "\"initial_max_streams_bidi\":3232399,"
    "\"initial_max_streams_uni\":99993232,"
    "\"preferred_address\":{"
    "\"connection_id\":\"fffec098\","
    "\"stateless_reset_token\":\"ddc1b991dab60067e59149ef0e2f5323\","
    "\"ip_v6\":\"5f6eef1ada564f62e4dea0769b21c62b\","
    "\"port_v6\":10046},"
    "\"max_datagram_frame_size\":678,"
    "\"grease_quic_bit\":true}}\n",
    (const char *)buf);
}

void test_ngtcp2_qlog_metrics_updated(void) {
  ngtcp2_qlog qlog;
  uint8_t buf[1024];
  ngtcp2_conn_stat cstat = {
    .latest_rtt = 100 * NGTCP2_MILLISECONDS,
    .min_rtt = 989 * NGTCP2_MILLISECONDS,
    .smoothed_rtt = 413 * NGTCP2_MILLISECONDS,
    .rttvar = 8 * NGTCP2_SECONDS,
    .pto_count = 11111,
    .cwnd = 7234623,
    .ssthresh = 39463294372,
    .bytes_in_flight = 612,
  };

  ngtcp2_qlog_init(&qlog, null_qlog_write, 0, buf);
  ngtcp2_buf_init(&qlog.buf, buf, sizeof(buf));

  ngtcp2_qlog_metrics_updated(&qlog, &cstat);

  assert_string_equal(
    "\x1e{\"time\":0,\"name\":\"quic:recovery_metrics_updated\",\"data\":{"
    "\"min_rtt\":989,\"smoothed_rtt\":413,\"latest_rtt\":100,"
    "\"rtt_variance\":8000,\"pto_count\":11111,\"congestion_window\":7234623,"
    "\"bytes_in_flight\":612,\"ssthresh\":39463294372}}\n",
    (const char *)buf);
}

void test_ngtcp2_qlog_pkt_lost(void) {
  ngtcp2_qlog qlog;
  uint8_t buf[1024];
  ngtcp2_rtb_entry ent = {
    .hd =
      {
        .pkt_num = NGTCP2_MAX_VARINT - 1,
        .type = NGTCP2_PKT_HANDSHAKE,
        .flags = NGTCP2_PKT_FLAG_LONG_FORM,
      },
  };

  ngtcp2_qlog_init(&qlog, null_qlog_write, 0, buf);
  ngtcp2_buf_init(&qlog.buf, buf, sizeof(buf));

  ngtcp2_qlog_pkt_lost(&qlog, &ent);

  assert_string_equal(
    "\x1e{\"time\":0,\"name\":\"quic:packet_lost\",\"data\":{\"header\":{"
    "\"packet_type\":\"handshake\",\"packet_number\":4611686018427387902}}}\n",
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
    .token = (uint8_t *)"\xde\xad\xbe\xef",
    .tokenlen = 4,
  };

  ngtcp2_qlog_init(&qlog, null_qlog_write, 0, buf);
  ngtcp2_buf_init(&qlog.buf, buf, sizeof(buf));

  ngtcp2_qlog_retry_pkt_received(&qlog, &hd, &retry);

  assert_string_equal(
    "\x1e{\"time\":0,\"name\":\"quic:packet_received\",\"data\":{\"header\":{"
    "\"packet_type\":\"retry\",\"token\":{\"raw\":{\"data\":\"deadbeef\"}}}}}"
    "\n",
    (const char *)buf);
}

void test_ngtcp2_qlog_stateless_reset_pkt_received(void) {
  ngtcp2_qlog qlog;
  uint8_t buf[1024];
  ngtcp2_pkt_stateless_reset sr = {
    .stateless_reset_token = {0xf1, 0xe2, 0xd3, 0xc4, 0xb5, 0xa6, 0x07, 0x98,
                              0x89, 0x70, 0x6a, 0x5b, 0x4c, 0x3d, 0x2e, 0x1f},
  };

  ngtcp2_qlog_init(&qlog, null_qlog_write, 0, buf);
  ngtcp2_buf_init(&qlog.buf, buf, sizeof(buf));

  ngtcp2_qlog_stateless_reset_pkt_received(&qlog, &sr);

  assert_string_equal(
    "\x1e{\"time\":0,\"name\":\"quic:packet_received\",\"data\":{\"header\":{"
    "\"packet_type\":\"stateless_reset\"},"
    "\"stateless_reset_token\":\"f1e2d3c4b5a6079889706a5b4c3d2e1f\"}}\n",
    (const char *)buf);
}

void test_ngtcp2_qlog_version_negotiation_pkt_received(void) {
  ngtcp2_qlog qlog;
  uint8_t buf[1024];
  ngtcp2_pkt_hd hd = {
    .type = NGTCP2_PKT_VERSION_NEGOTIATION,
  };
  uint32_t versions[] = {
    0xbaddcafe,
    0xdeadbeef,
    0xfacefeed,
    0xbaadf00d,
  };

  ngtcp2_qlog_init(&qlog, null_qlog_write, 0, buf);
  ngtcp2_buf_init(&qlog.buf, buf, sizeof(buf));

  ngtcp2_qlog_version_negotiation_pkt_received(&qlog, &hd, versions,
                                               ngtcp2_arraylen(versions));

  assert_string_equal(
    "\x1e{\"time\":0,\"name\":\"quic:packet_received\",\"data\":{\"header\":{"
    "\"packet_type\":\"version_negotiation\"},\"supported_versions\":["
    "\"baddcafe\",\"deadbeef\",\"facefeed\",\"baadf00d\"]}}\n",
    (const char *)buf);
}
