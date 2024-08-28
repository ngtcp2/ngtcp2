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
#include "ngtcp2_test_helper.h"

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_qlog_write_frame),
  munit_test_end(),
};

const MunitSuite qlog_suite = {
  "/qlog", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE,
};

static void null_qlog_write(void *user_data, uint32_t flags, const void *data,
                            size_t datalen) {
  (void)user_data;
  (void)flags;
  (void)data;
  (void)datalen;
}

void test_ngtcp2_qlog_write_frame(void) {
  ngtcp2_qlog qlog;
  uint8_t buf[1024];
  struct {
    ngtcp2_frame fr;
    ngtcp2_ack_range extra_ranges[2];
  } exfr;
  ngtcp2_frame *fr = &exfr.fr;

  ngtcp2_qlog_init(&qlog, null_qlog_write, 0, NULL);
  ngtcp2_buf_init(&qlog.buf, buf, sizeof(buf));

  {
    memset(&exfr, 0, sizeof(exfr));

    fr->padding.type = NGTCP2_FRAME_PADDING;
    fr->padding.len = 122;

    ngtcp2_qlog_write_frame(&qlog, fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"padding\"},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    memset(&exfr, 0, sizeof(exfr));

    fr->type = NGTCP2_FRAME_PING;

    ngtcp2_qlog_write_frame(&qlog, fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"ping\"},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    memset(&exfr, 0, sizeof(exfr));

    fr->type = NGTCP2_FRAME_ACK;
    fr->ack.ack_delay_unscaled = 31 * NGTCP2_MILLISECONDS;
    fr->ack.largest_ack = 1000000007;

    ngtcp2_qlog_write_frame(&qlog, fr);
    *qlog.buf.last = '\0';

    assert_string_equal(
      "{\"frame_type\":\"ack\",\"ack_delay\":31,\"acked_ranges\":[["
      "1000000007]]},",
      (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    memset(&exfr, 0, sizeof(exfr));

    fr->type = NGTCP2_FRAME_ACK;
    fr->ack.ack_delay_unscaled = 31 * NGTCP2_MILLISECONDS;
    fr->ack.largest_ack = 1000000007;
    fr->ack.first_ack_range = 11;
    fr->ack.rangecnt = 1;
    fr->ack.ranges[0].gap = 17;
    fr->ack.ranges[0].len = 73;

    ngtcp2_qlog_write_frame(&qlog, fr);
    *qlog.buf.last = '\0';

    assert_string_equal(
      "{\"frame_type\":\"ack\",\"ack_delay\":31,\"acked_ranges\":[["
      "999999996,1000000007],[999999904,999999977]]},",
      (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    memset(&exfr, 0, sizeof(exfr));

    fr->type = NGTCP2_FRAME_ACK;
    fr->ack.ack_delay_unscaled = 31 * NGTCP2_MILLISECONDS;
    fr->ack.largest_ack = 1000000007;
    fr->ack.first_ack_range = 11;
    fr->ack.rangecnt = 2;
    fr->ack.ranges[0].gap = 17;
    fr->ack.ranges[0].len = 73;

    ngtcp2_qlog_write_frame(&qlog, fr);
    *qlog.buf.last = '\0';

    assert_string_equal(
      "{\"frame_type\":\"ack\",\"ack_delay\":31,\"acked_ranges\":[["
      "999999996,1000000007],[999999904,999999977],[999999902]]},",
      (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    memset(&exfr, 0, sizeof(exfr));

    fr->type = NGTCP2_FRAME_ACK_ECN;
    fr->ack.ack_delay_unscaled = 31 * NGTCP2_MILLISECONDS;
    fr->ack.largest_ack = 1000000007;
    fr->ack.ecn.ect1 = 678912;
    fr->ack.ecn.ect0 = 892363;
    fr->ack.ecn.ce = 956923;

    ngtcp2_qlog_write_frame(&qlog, fr);
    *qlog.buf.last = '\0';

    assert_string_equal(
      "{\"frame_type\":\"ack\",\"ack_delay\":31,\"acked_ranges\":[["
      "1000000007]],\"ect1\":678912,\"ect0\":892363,\"ce\":956923},",
      (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    memset(&exfr, 0, sizeof(exfr));

    fr->type = NGTCP2_FRAME_RESET_STREAM;
    fr->reset_stream.stream_id = 1000000009;
    fr->reset_stream.app_error_code = 761111;
    fr->reset_stream.final_size = 1000000007;

    ngtcp2_qlog_write_frame(&qlog, fr);
    *qlog.buf.last = '\0';

    assert_string_equal(
      "{\"frame_type\":\"reset_stream\",\"stream_id\":1000000009,"
      "\"error_code\":761111,\"final_size\":1000000007},",
      (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    memset(&exfr, 0, sizeof(exfr));

    fr->type = NGTCP2_FRAME_STOP_SENDING;
    fr->stop_sending.stream_id = 1000000009;
    fr->stop_sending.app_error_code = 3119999;

    ngtcp2_qlog_write_frame(&qlog, fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"stop_sending\",\"stream_id\":"
                        "1000000009,\"error_code\":3119999},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    memset(&exfr, 0, sizeof(exfr));

    fr->type = NGTCP2_FRAME_CRYPTO;
    fr->stream.offset = 65000011;
    fr->stream.datacnt = 1;
    fr->stream.data[0].len = 111187;

    ngtcp2_qlog_write_frame(&qlog, fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"crypto\",\"offset\":65000011,"
                        "\"length\":111187},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    memset(&exfr, 0, sizeof(exfr));

    fr->type = NGTCP2_FRAME_NEW_TOKEN;
    fr->new_token.tokenlen = 8;
    fr->new_token.token = (uint8_t *)"\x12\x34\x56\x78\x9a\xbc\xde\xf0";

    ngtcp2_qlog_write_frame(&qlog, fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"new_token\",\"length\":8,"
                        "\"token\":{\"data\":\"123456789abcdef0\"}},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    memset(&exfr, 0, sizeof(exfr));

    fr->type = NGTCP2_FRAME_STREAM;
    fr->stream.stream_id = 1000000007;
    fr->stream.offset = 1000000009;
    fr->stream.datacnt = 1;
    fr->stream.data[0].len = 8888888;
    fr->stream.fin = 1;

    ngtcp2_qlog_write_frame(&qlog, fr);
    *qlog.buf.last = '\0';

    assert_string_equal(
      "{\"frame_type\":\"stream\",\"stream_id\":1000000007,"
      "\"offset\":1000000009,\"length\":8888888,\"fin\":true},",
      (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    memset(&exfr, 0, sizeof(exfr));

    fr->type = NGTCP2_FRAME_STREAM;
    fr->stream.stream_id = 1000000007;
    fr->stream.offset = 1000000009;
    fr->stream.datacnt = 1;
    fr->stream.data[0].len = 8888888;

    ngtcp2_qlog_write_frame(&qlog, fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"stream\",\"stream_id\":1000000007,"
                        "\"offset\":1000000009,\"length\":8888888},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    memset(&exfr, 0, sizeof(exfr));

    fr->type = NGTCP2_FRAME_MAX_DATA;
    fr->max_data.max_data = 89624231;

    ngtcp2_qlog_write_frame(&qlog, fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"max_data\",\"maximum\":89624231},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    memset(&exfr, 0, sizeof(exfr));

    fr->type = NGTCP2_FRAME_MAX_STREAM_DATA;
    fr->max_stream_data.stream_id = 1000000009;
    fr->max_stream_data.max_stream_data = 3479131413562775697;

    ngtcp2_qlog_write_frame(&qlog, fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"max_stream_data\",\"stream_id\":"
                        "1000000009,\"maximum\":3479131413562775697},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    memset(&exfr, 0, sizeof(exfr));

    fr->type = NGTCP2_FRAME_MAX_STREAMS_BIDI;
    fr->max_streams.max_streams = 3947405932436725448;

    ngtcp2_qlog_write_frame(&qlog, fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"max_streams\",\"stream_type\":"
                        "\"bidirectional\",\"maximum\":3947405932436725448},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    memset(&exfr, 0, sizeof(exfr));

    fr->type = NGTCP2_FRAME_MAX_STREAMS_UNI;
    fr->max_streams.max_streams = 2650981103699753174;

    ngtcp2_qlog_write_frame(&qlog, fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"max_streams\",\"stream_type\":"
                        "\"unidirectional\",\"maximum\":2650981103699753174},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    memset(&exfr, 0, sizeof(exfr));

    fr->type = NGTCP2_FRAME_DATA_BLOCKED;
    fr->data_blocked.offset = 141245489541204826;

    ngtcp2_qlog_write_frame(&qlog, fr);
    *qlog.buf.last = '\0';

    assert_string_equal(
      "{\"frame_type\":\"data_blocked\",\"limit\":141245489541204826},",
      (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    memset(&exfr, 0, sizeof(exfr));

    fr->type = NGTCP2_FRAME_STREAM_DATA_BLOCKED;
    fr->stream_data_blocked.stream_id = 1000000007;
    fr->stream_data_blocked.offset = 3510083742766371473;

    ngtcp2_qlog_write_frame(&qlog, fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"stream_data_blocked\",\"stream_"
                        "id\":1000000007,\"limit\":3510083742766371473},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    memset(&exfr, 0, sizeof(exfr));

    fr->type = NGTCP2_FRAME_STREAMS_BLOCKED_BIDI;
    fr->streams_blocked.max_streams = 267807966110011001;

    ngtcp2_qlog_write_frame(&qlog, fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"streams_blocked\",\"stream_type\":"
                        "\"bidirectional\",\"limit\":267807966110011001},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    memset(&exfr, 0, sizeof(exfr));

    fr->type = NGTCP2_FRAME_STREAMS_BLOCKED_UNI;
    fr->streams_blocked.max_streams = 4147150966951874727;

    ngtcp2_qlog_write_frame(&qlog, fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"streams_blocked\",\"stream_type\":"
                        "\"unidirectional\",\"limit\":4147150966951874727},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    memset(&exfr, 0, sizeof(exfr));

    fr->type = NGTCP2_FRAME_NEW_CONNECTION_ID;
    fr->new_connection_id.seq = 2322933918954521341;
    fr->new_connection_id.retire_prior_to = 353598537829135415;
    ngtcp2_cid_init(&fr->new_connection_id.cid,
                    (const uint8_t *)"\x01\x02\x03\x04\x05\x06\x07\x08", 8);
    memcpy(fr->new_connection_id.stateless_reset_token,
           "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x10",
           NGTCP2_STATELESS_RESET_TOKENLEN);

    ngtcp2_qlog_write_frame(&qlog, fr);
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
    memset(&exfr, 0, sizeof(exfr));

    fr->type = NGTCP2_FRAME_RETIRE_CONNECTION_ID;
    fr->retire_connection_id.seq = 923246273261945495;

    ngtcp2_qlog_write_frame(&qlog, fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"retire_connection_id\","
                        "\"sequence_number\":923246273261945495},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    memset(&exfr, 0, sizeof(exfr));

    fr->type = NGTCP2_FRAME_PATH_CHALLENGE;
    memcpy(fr->path_challenge.data, "\x11\x22\x33\x44\x55\x66\x77\x88",
           NGTCP2_PATH_CHALLENGE_DATALEN);

    ngtcp2_qlog_write_frame(&qlog, fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"path_challenge\",\"data\":"
                        "\"1122334455667788\"},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    memset(&exfr, 0, sizeof(exfr));

    fr->type = NGTCP2_FRAME_PATH_RESPONSE;
    memcpy(fr->path_challenge.data, "\x22\x33\x44\x55\x66\x77\x88\x99",
           NGTCP2_PATH_CHALLENGE_DATALEN);

    ngtcp2_qlog_write_frame(&qlog, fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"path_response\",\"data\":"
                        "\"2233445566778899\"},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    memset(&exfr, 0, sizeof(exfr));

    fr->type = NGTCP2_FRAME_CONNECTION_CLOSE;
    fr->connection_close.error_code = 3270540419184339176;

    ngtcp2_qlog_write_frame(&qlog, fr);
    *qlog.buf.last = '\0';

    assert_string_equal(
      "{\"frame_type\":\"connection_close\",\"error_space\":"
      "\"transport\",\"error_code\":3270540419184339176,\"raw_"
      "error_code\":3270540419184339176},",
      (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    memset(&exfr, 0, sizeof(exfr));

    fr->type = NGTCP2_FRAME_CONNECTION_CLOSE_APP;
    fr->connection_close.error_code = 1069447711149177103;

    ngtcp2_qlog_write_frame(&qlog, fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"connection_close\",\"error_space\":"
                        "\"application\",\"error_code\":1069447711149177103,"
                        "\"raw_error_code\":1069447711149177103},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    memset(&exfr, 0, sizeof(exfr));

    fr->type = NGTCP2_FRAME_HANDSHAKE_DONE;

    ngtcp2_qlog_write_frame(&qlog, fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"handshake_done\"},",
                        (const char *)qlog.buf.begin);
  }

  ngtcp2_buf_reset(&qlog.buf);

  {
    memset(&exfr, 0, sizeof(exfr));

    fr->type = NGTCP2_FRAME_DATAGRAM;
    fr->datagram.datacnt = 1;
    fr->datagram.data = fr->datagram.rdata;
    fr->datagram.rdata[0].len = 1301458;

    ngtcp2_qlog_write_frame(&qlog, fr);
    *qlog.buf.last = '\0';

    assert_string_equal("{\"frame_type\":\"datagram\",\"length\":1301458},",
                        (const char *)qlog.buf.begin);
  }
}
