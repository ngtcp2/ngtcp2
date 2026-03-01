/*
 * ngtcp2
 *
 * Copyright (c) 2026 ngtcp2 contributors
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
#include "ngtcp2_log_test.h"

#include <stdio.h>

#include "ngtcp2_log.h"
#include "ngtcp2_conv.h"
#include "ngtcp2_net.h"
#include "ngtcp2_test_helper.h"

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_log_info),
  munit_void_test(test_ngtcp2_log_infof),
  munit_void_test(test_ngtcp2_log_pkt_lost),
  munit_void_test(test_ngtcp2_log_pkt_hd),
  munit_void_test(test_ngtcp2_log_rx_vn),
  munit_void_test(test_ngtcp2_log_rx_sr),
  munit_void_test(test_ngtcp2_log_fr),
  munit_void_test(test_ngtcp2_log_remote_tp),
  munit_test_end(),
};

const MunitSuite log_suite = {
  .prefix = "/log",
  .tests = tests,
};

static uint8_t null_data[4096];

typedef struct log_data {
  char buf[4096];
  const char *expected[256];
  size_t idx;
} log_data;

static void log_printf(void *user_data, const char *format, ...) {
  log_data *ld = user_data;
  int nwrite;
  va_list ap;

  va_start(ap, format);

  nwrite = vsnprintf(ld->buf, sizeof(ld->buf), format, ap);

  va_end(ap);

  assert_int(nwrite, >=, 0);
  assert_size((size_t)nwrite, <, sizeof(ld->buf));
  assert_size(ngtcp2_arraylen(ld->expected), >, ld->idx);
  assert_not_null(ld->expected[ld->idx]);
  assert_string_equal(ld->expected[ld->idx], ld->buf);

  ++ld->idx;
}

static void log_init(ngtcp2_log *log, log_data *ld) {
  ngtcp2_cid scid = {
    .datalen = 4,
    .data = {0xDE, 0xAD, 0xBE, 0xEF},
  };

  ngtcp2_log_init(log, &scid, log_printf, 0, ld);
  log->last_ts = NGTCP2_SECONDS + 123 * NGTCP2_MILLISECONDS;
}

void test_ngtcp2_log_info(void) {
  log_data ld;
  ngtcp2_log log;

  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef con message without formatting directive",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_info(&log, NGTCP2_LOG_EVENT_CON,
                  "message without formatting directive");

  assert_null(ld.expected[ld.idx]);
}

void test_ngtcp2_log_infof(void) {
  log_data ld;
  ngtcp2_log log;

  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef con message with formatting directive 888",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_infof(&log, NGTCP2_LOG_EVENT_CON, "message %s formatting %s %d",
                   "with", "directive", 888);

  assert_null(ld.expected[ld.idx]);
}

void test_ngtcp2_log_pkt_lost(void) {
  log_data ld;
  ngtcp2_log log;

  /* Initial */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef ldc pkn=1000000009 lost type=Initial "
        "sent_ts=333000000",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_pkt_lost(&log, 1000000009, NGTCP2_PKT_INITIAL,
                      NGTCP2_PKT_FLAG_LONG_FORM, 333 * NGTCP2_MILLISECONDS);

  assert_null(ld.expected[ld.idx]);

  /* Handshake */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef ldc pkn=1000000009 lost type=Handshake "
        "sent_ts=333000000",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_pkt_lost(&log, 1000000009, NGTCP2_PKT_HANDSHAKE,
                      NGTCP2_PKT_FLAG_LONG_FORM, 333 * NGTCP2_MILLISECONDS);

  assert_null(ld.expected[ld.idx]);

  /* Retry */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef ldc pkn=1000000009 lost type=Retry "
        "sent_ts=333000000",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_pkt_lost(&log, 1000000009, NGTCP2_PKT_RETRY,
                      NGTCP2_PKT_FLAG_LONG_FORM, 333 * NGTCP2_MILLISECONDS);

  assert_null(ld.expected[ld.idx]);

  /* 0RTT */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef ldc pkn=1000000009 lost type=0RTT "
        "sent_ts=333000000",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_pkt_lost(&log, 1000000009, NGTCP2_PKT_0RTT,
                      NGTCP2_PKT_FLAG_LONG_FORM, 333 * NGTCP2_MILLISECONDS);

  assert_null(ld.expected[ld.idx]);

  /* 1RTT */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef ldc pkn=1000000009 lost type=1RTT "
        "sent_ts=333000000",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_pkt_lost(&log, 1000000009, NGTCP2_PKT_1RTT, NGTCP2_PKT_FLAG_NONE,
                      333 * NGTCP2_MILLISECONDS);

  assert_null(ld.expected[ld.idx]);
}

void test_ngtcp2_log_pkt_hd(void) {
  log_data ld;
  ngtcp2_log log;
  const ngtcp2_cid dcid = {
    .datalen = 4,
    .data = {0xBA, 0xAD, 0xF0, 0x0D},
  };
  const ngtcp2_cid scid = {
    .datalen = 4,
    .data = {0xBE, 0xEF, 0xCA, 0xCE},
  };

  /* Long */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef pkt rx pkn=1000000009 dcid=0xbaadf00d "
        "scid=0xbeefcace version=0x00000001 type=Initial len=333",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_pkt_hd(&log, &(ngtcp2_pkt_hd){
                               .dcid = dcid,
                               .scid = scid,
                               .pkt_num = 1000000009,
                               .len = 333,
                               .version = NGTCP2_PROTO_VER_V1,
                               .type = NGTCP2_PKT_INITIAL,
                               .flags = NGTCP2_PKT_FLAG_LONG_FORM,
                             });

  assert_null(ld.expected[ld.idx]);

  /* Short */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef pkt tx pkn=1000000009 dcid=0xbaadf00d type=1RTT "
        "k=0",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_tx_pkt_hd(&log, &(ngtcp2_pkt_hd){
                               .dcid = dcid,
                               .pkt_num = 1000000009,
                               .type = NGTCP2_PKT_1RTT,
                             });

  assert_null(ld.expected[ld.idx]);

  /* Short with key phase bit set */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef pkt tx pkn=1000000009 dcid=0xbaadf00d type=1RTT "
        "k=1",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_tx_pkt_hd(&log, &(ngtcp2_pkt_hd){
                               .dcid = dcid,
                               .pkt_num = 1000000009,
                               .type = NGTCP2_PKT_1RTT,
                               .flags = NGTCP2_PKT_FLAG_KEY_PHASE,
                             });

  assert_null(ld.expected[ld.idx]);
}

void test_ngtcp2_log_rx_vn(void) {
  log_data ld;
  ngtcp2_log log;
  const uint32_t sv[] = {
    0x1,
    0x2,
    0xEEFFEEFF,
  };

  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef pkt rx 1000000009 VN v=0x00000001",
        "I00001123 0xdeadbeef pkt rx 1000000009 VN v=0x00000002",
        "I00001123 0xdeadbeef pkt rx 1000000009 VN v=0xeeffeeff",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_vn(&log,
                   &(ngtcp2_pkt_hd){
                     .pkt_num = 1000000009,
                     .type = NGTCP2_PKT_VERSION_NEGOTIATION,
                   },
                   sv, ngtcp2_arraylen(sv));

  assert_null(ld.expected[ld.idx]);
}

void test_ngtcp2_log_rx_sr(void) {
  log_data ld;
  ngtcp2_log log;

  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef pkt rx 0 SR "
        "token=0xbaadcacedeadf00ddeadbeefbaadcace randlen=19",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_sr(
    &log, &(ngtcp2_pkt_stateless_reset2){
            .token =
              {
                .data = {0xBA, 0xAD, 0xCA, 0xCE, 0xDE, 0xAD, 0xF0, 0x0D, 0xDE,
                         0xAD, 0xBE, 0xEF, 0xBA, 0xAD, 0xCA, 0xCE},
              },
            .randlen = 19,
          });

  assert_null(ld.expected[ld.idx]);
}

void test_ngtcp2_log_fr(void) {
  log_data ld;
  ngtcp2_log log;
  const ngtcp2_pkt_hd hd = {
    .dcid =
      {
        .datalen = 4,
        .data = {0xBA, 0xAD, 0xF0, 0x0D},
      },
    .pkt_num = 778,
    .type = NGTCP2_PKT_1RTT,
  };
  ngtcp2_vec data[] = {
    {
      .base = null_data,
      .len = 123,
    },
  };
  ngtcp2_ack_range ranges[] = {
    {
      .len = 1,
    },
    {
      .gap = 1,
      .len = 1000000000,
    },
  };
  uint8_t token[] = {
    0xE1, 0xDD, 0xAA, 0x00, 0x33, 0x99, 0xAA, 0x11, 0xE1, 0xDD, 0xAA,
    0x00, 0x33, 0x99, 0xAA, 0x11, 0xE1, 0xDD, 0xAA, 0x00, 0x33, 0x99,
    0xAA, 0x11, 0xE1, 0xDD, 0xAA, 0x00, 0x33, 0x99, 0xAA, 0x11, 0xE1,
    0xDD, 0xAA, 0x00, 0x33, 0x99, 0xAA, 0x11, 0xE1, 0xDD, 0xAA, 0x00,
    0x33, 0x99, 0xAA, 0x11, 0xE1, 0xDD, 0xAA, 0x00, 0x33, 0x99, 0xAA,
    0x11, 0xE1, 0xDD, 0xAA, 0x00, 0x33, 0x99, 0xAA, 0x11,
  };
  uint8_t token_long[] = {
    0xE1, 0xDD, 0xAA, 0x00, 0x33, 0x99, 0xAA, 0x11, 0xE1, 0xDD, 0xAA,
    0x00, 0x33, 0x99, 0xAA, 0x11, 0xE1, 0xDD, 0xAA, 0x00, 0x33, 0x99,
    0xAA, 0x11, 0xE1, 0xDD, 0xAA, 0x00, 0x33, 0x99, 0xAA, 0x11, 0xE1,
    0xDD, 0xAA, 0x00, 0x33, 0x99, 0xAA, 0x11, 0xE1, 0xDD, 0xAA, 0x00,
    0x33, 0x99, 0xAA, 0x11, 0xE1, 0xDD, 0xAA, 0x00, 0x33, 0x99, 0xAA,
    0x11, 0xE1, 0xDD, 0xAA, 0x00, 0x33, 0x99, 0xAA, 0x11, 0xFF,
  };
  uint8_t reason[257] = {0};

  memcpy(reason + sizeof(reason) - ngtcp2_strlen_lit("this is the reason") - 2,
         "this is the reason", ngtcp2_strlen_lit("this is the reason"));

  /* STREAM (fin and uni) */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef frm rx 778 1RTT STREAM(0x09) id=0x3b9aca07 fin=1 "
        "offset=4852383 len=123 uni=1",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_fr(&log, &hd,
                   &(ngtcp2_frame){.stream = {
                                     .type = NGTCP2_FRAME_STREAM,
                                     .flags = NGTCP2_STREAM_FIN_BIT,
                                     .fin = 1,
                                     .stream_id = 1000000007,
                                     .offset = 4852383,
                                     .datacnt = ngtcp2_arraylen(data),
                                     .data = data,
                                   }});

  assert_null(ld.expected[ld.idx]);

  /* STREAM (bidi) */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef frm tx 778 1RTT STREAM(0x08) id=0x3b9aca09 fin=0 "
        "offset=4852383 len=123 uni=0",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_tx_fr(&log, &hd,
                   &(ngtcp2_frame){.stream = {
                                     .type = NGTCP2_FRAME_STREAM,
                                     .stream_id = 1000000009,
                                     .offset = 4852383,
                                     .datacnt = ngtcp2_arraylen(data),
                                     .data = data,
                                   }});

  assert_null(ld.expected[ld.idx]);

  /* ACK (without ranges) */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef frm rx 778 1RTT ACK(0x02) largest_ack=1000000007 "
        "ack_delay=456(333) ack_range_count=0",
        "I00001123 0xdeadbeef frm rx 778 1RTT ACK(0x02) "
        "range=[1000000007..1000000006] len=1",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_fr(
    &log, &hd,
    &(ngtcp2_frame){.ack = {
                      .type = NGTCP2_FRAME_ACK,
                      .largest_ack = 1000000007,
                      .ack_delay_unscaled = 456 * NGTCP2_MILLISECONDS,
                      .ack_delay = 333,
                      .first_ack_range = 1,
                    }});

  assert_null(ld.expected[ld.idx]);

  /* ACK (with ranges) */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef frm rx 778 1RTT ACK(0x02) largest_ack=1000000007 "
        "ack_delay=456(333) ack_range_count=2",
        "I00001123 0xdeadbeef frm rx 778 1RTT ACK(0x02) "
        "range=[1000000007..1000000006] len=1",
        "I00001123 0xdeadbeef frm rx 778 1RTT ACK(0x02) "
        "range=[1000000004..1000000003] gap=0 len=1",
        "I00001123 0xdeadbeef frm rx 778 1RTT ACK(0x02) "
        "range=[1000000000..0] gap=1 len=1000000000",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_fr(
    &log, &hd,
    &(ngtcp2_frame){.ack = {
                      .type = NGTCP2_FRAME_ACK,
                      .largest_ack = 1000000007,
                      .ack_delay_unscaled = 456 * NGTCP2_MILLISECONDS,
                      .ack_delay = 333,
                      .first_ack_range = 1,
                      .rangecnt = ngtcp2_arraylen(ranges),
                      .ranges = ranges,
                    }});

  assert_null(ld.expected[ld.idx]);

  /* ACK (with ECN) */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef frm rx 778 1RTT ACK(0x03) largest_ack=1000000007 "
        "ack_delay=456(333) ack_range_count=0",
        "I00001123 0xdeadbeef frm rx 778 1RTT ACK(0x03) "
        "range=[1000000007..1000000006] len=1",
        "I00001123 0xdeadbeef frm rx 778 1RTT ACK(0x03) "
        "ect0=1 ect1=0 ce=11223835",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_fr(
    &log, &hd,
    &(ngtcp2_frame){.ack = {
                      .type = NGTCP2_FRAME_ACK_ECN,
                      .largest_ack = 1000000007,
                      .ack_delay_unscaled = 456 * NGTCP2_MILLISECONDS,
                      .ack_delay = 333,
                      .ecn =
                        {
                          .ect0 = 1,
                          .ce = 11223835,
                        },
                      .first_ack_range = 1,
                    }});

  assert_null(ld.expected[ld.idx]);

  /* PADDING */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef frm rx 778 1RTT PADDING(0x00) len=99999",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_fr(&log, &hd,
                   &(ngtcp2_frame){
                     .padding =
                       {
                         .type = NGTCP2_FRAME_PADDING,
                         .len = 99999,
                       },
                   });

  assert_null(ld.expected[ld.idx]);

  /* RESET_STREAM */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef frm rx 778 1RTT RESET_STREAM(0x04) id=0x3b9aca09 "
        "app_error_code=(unknown)(0x66e2311a) final_size=1000000007",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_fr(&log, &hd,
                   &(ngtcp2_frame){
                     .reset_stream =
                       {
                         .type = NGTCP2_FRAME_RESET_STREAM,
                         .stream_id = 1000000009,
                         .app_error_code = 0x66E2311A,
                         .final_size = 1000000007,
                       },
                   });

  assert_null(ld.expected[ld.idx]);

  /* CONNECTION_CLOSE (transport) */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef frm rx 778 1RTT CONNECTION_CLOSE(0x1c) "
        "error_code=CONNECTION_REFUSED(0x2) frame_type=0x4 reason_len=0 "
        "reason=[]",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_fr(&log, &hd,
                   &(ngtcp2_frame){
                     .connection_close =
                       {
                         .type = NGTCP2_FRAME_CONNECTION_CLOSE,
                         .error_code = NGTCP2_CONNECTION_REFUSED,
                         .frame_type = NGTCP2_FRAME_RESET_STREAM,
                       },
                   });

  assert_null(ld.expected[ld.idx]);

  /* CONNECTION_CLOSE (transport with reason) */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef frm rx 778 1RTT CONNECTION_CLOSE(0x1c) "
        "error_code=CONNECTION_REFUSED(0x2) frame_type=0x4 reason_len=257 "
        "reason=[.."
        "......................................................................"
        "......................................................................"
        "......................................................................"
        ".........................this is the reason]",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_fr(&log, &hd,
                   &(ngtcp2_frame){
                     .connection_close =
                       {
                         .type = NGTCP2_FRAME_CONNECTION_CLOSE,
                         .error_code = NGTCP2_CONNECTION_REFUSED,
                         .frame_type = NGTCP2_FRAME_RESET_STREAM,
                         .reasonlen = sizeof(reason),
                         .reason = reason,
                       },
                   });

  assert_null(ld.expected[ld.idx]);

  /* CONNECTION_CLOSE (application) */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef frm rx 778 1RTT CONNECTION_CLOSE(0x1d) "
        "error_code=(unknown)(0x2) frame_type=0x0 reason_len=0 "
        "reason=[]",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_fr(&log, &hd,
                   &(ngtcp2_frame){
                     .connection_close =
                       {
                         .type = NGTCP2_FRAME_CONNECTION_CLOSE_APP,
                         .error_code = NGTCP2_CONNECTION_REFUSED,
                       },
                   });

  assert_null(ld.expected[ld.idx]);

  /* MAX_DATA */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef frm rx 778 1RTT MAX_DATA(0x10) "
        "max_data=1000000007",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_fr(&log, &hd,
                   &(ngtcp2_frame){
                     .max_data =
                       {
                         .type = NGTCP2_FRAME_MAX_DATA,
                         .max_data = 1000000007,
                       },
                   });

  assert_null(ld.expected[ld.idx]);

  /* MAX_STREAM_DATA */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef frm rx 778 1RTT MAX_STREAM_DATA(0x11) "
        "id=0x3b9aca09 max_stream_data=1000000007",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_fr(&log, &hd,
                   &(ngtcp2_frame){
                     .max_stream_data =
                       {
                         .type = NGTCP2_FRAME_MAX_STREAM_DATA,
                         .stream_id = 1000000009,
                         .max_stream_data = 1000000007,
                       },
                   });

  assert_null(ld.expected[ld.idx]);

  /* MAX_STREAMS (bidi) */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef frm rx 778 1RTT MAX_STREAMS(0x12) "
        "max_streams=1000000007",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_fr(&log, &hd,
                   &(ngtcp2_frame){
                     .max_streams =
                       {
                         .type = NGTCP2_FRAME_MAX_STREAMS_BIDI,
                         .max_streams = 1000000007,
                       },
                   });

  assert_null(ld.expected[ld.idx]);

  /* MAX_STREAMS (uni) */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef frm rx 778 1RTT MAX_STREAMS(0x13) "
        "max_streams=1000000007",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_fr(&log, &hd,
                   &(ngtcp2_frame){
                     .max_streams =
                       {
                         .type = NGTCP2_FRAME_MAX_STREAMS_UNI,
                         .max_streams = 1000000007,
                       },
                   });

  assert_null(ld.expected[ld.idx]);

  /* PING */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef frm rx 778 1RTT PING(0x01)",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_fr(&log, &hd,
                   &(ngtcp2_frame){
                     .ping =
                       {
                         .type = NGTCP2_FRAME_PING,
                       },
                   });

  assert_null(ld.expected[ld.idx]);

  /* DATA_BLOCKED */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef frm rx 778 1RTT DATA_BLOCKED(0x14) "
        "offset=1000000007",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_fr(&log, &hd,
                   &(ngtcp2_frame){
                     .data_blocked =
                       {
                         .type = NGTCP2_FRAME_DATA_BLOCKED,
                         .offset = 1000000007,
                       },
                   });

  assert_null(ld.expected[ld.idx]);

  /* STREAM_DATA_BLOCKED */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef frm rx 778 1RTT STREAM_DATA_BLOCKED(0x15) "
        "id=0x3b9aca09 offset=1000000007",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_fr(&log, &hd,
                   &(ngtcp2_frame){
                     .stream_data_blocked =
                       {
                         .type = NGTCP2_FRAME_STREAM_DATA_BLOCKED,
                         .stream_id = 1000000009,
                         .offset = 1000000007,
                       },
                   });

  assert_null(ld.expected[ld.idx]);

  /* STREAMS_BLOCKED (bidi) */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef frm rx 778 1RTT STREAMS_BLOCKED(0x16) "
        "max_streams=1000000007",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_fr(&log, &hd,
                   &(ngtcp2_frame){
                     .streams_blocked =
                       {
                         .type = NGTCP2_FRAME_STREAMS_BLOCKED_BIDI,
                         .max_streams = 1000000007,
                       },
                   });

  assert_null(ld.expected[ld.idx]);

  /* STREAMS_BLOCKED (uni) */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef frm rx 778 1RTT STREAMS_BLOCKED(0x17) "
        "max_streams=1000000007",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_fr(&log, &hd,
                   &(ngtcp2_frame){
                     .streams_blocked =
                       {
                         .type = NGTCP2_FRAME_STREAMS_BLOCKED_UNI,
                         .max_streams = 1000000007,
                       },
                   });

  assert_null(ld.expected[ld.idx]);

  /* NEW_CONNECTION_ID */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef frm rx 778 1RTT NEW_CONNECTION_ID(0x18) "
        "seq=999 cid=0xbeeff00d retire_prior_to=677433 "
        "stateless_reset_token=0xdeadbeefbaadf00dbaadcacebeefcace",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_fr(
    &log, &hd,
    &(ngtcp2_frame){
      .new_connection_id =
        {
          .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
          .seq = 999,
          .cid =
            {
              .datalen = 4,
              .data = {0xBE, 0xEF, 0xF0, 0x0D},
            },
          .retire_prior_to = 677433,
          .token =
            {
              .data = {0xDE, 0xAD, 0xBE, 0xEF, 0xBA, 0xAD, 0xF0, 0x0D, 0xBA,
                       0xAD, 0xCA, 0xCE, 0xBE, 0xEF, 0xCA, 0xCE},
            },
        },
    });

  assert_null(ld.expected[ld.idx]);

  /* STOP_SENDING */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef frm rx 778 1RTT STOP_SENDING(0x05) "
        "id=0x3b9aca09 app_error_code=(unknown)(0xf)",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_fr(&log, &hd,
                   &(ngtcp2_frame){
                     .stop_sending =
                       {
                         .type = NGTCP2_FRAME_STOP_SENDING,
                         .stream_id = 1000000009,
                         .app_error_code = 0xF,
                       },
                   });

  assert_null(ld.expected[ld.idx]);

  /* PATH_CHALLENGE */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef frm rx 778 1RTT PATH_CHALLENGE(0x1a) "
        "data=0xdeadbeefbaadcace",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_fr(
    &log, &hd,
    &(ngtcp2_frame){
      .path_challenge =
        {
          .type = NGTCP2_FRAME_PATH_CHALLENGE,
          .data = {0xDE, 0xAD, 0xBE, 0xEF, 0xBA, 0xAD, 0xCA, 0xCE},
        },
    });

  assert_null(ld.expected[ld.idx]);

  /* PATH_RESPONSE */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef frm rx 778 1RTT PATH_RESPONSE(0x1b) "
        "data=0xdeadbeefbaadf00d",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_fr(
    &log, &hd,
    &(ngtcp2_frame){
      .path_response =
        {
          .type = NGTCP2_FRAME_PATH_RESPONSE,
          .data = {0xDE, 0xAD, 0xBE, 0xEF, 0xBA, 0xAD, 0xF0, 0x0D},
        },
    });

  assert_null(ld.expected[ld.idx]);

  /* CRYPTO */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef frm rx 778 1RTT CRYPTO(0x06) offset=352556 "
        "len=123",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_fr(&log, &hd,
                   &(ngtcp2_frame){.stream = {
                                     .type = NGTCP2_FRAME_CRYPTO,
                                     .offset = 352556,
                                     .datacnt = ngtcp2_arraylen(data),
                                     .data = data,
                                   }});

  assert_null(ld.expected[ld.idx]);

  /* NEW_TOKEN */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef frm rx 778 1RTT NEW_TOKEN(0x07) "
        "token="
        "0xe1ddaa003399aa11e1ddaa003399aa11e1ddaa003399aa11e1ddaa003399aa11e1dd"
        "aa003399aa11e1ddaa003399aa11e1ddaa003399aa11e1ddaa003399aa11 len=64",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_fr(&log, &hd,
                   &(ngtcp2_frame){.new_token = {
                                     .type = NGTCP2_FRAME_NEW_TOKEN,
                                     .token = token,
                                     .tokenlen = sizeof(token),
                                   }});

  assert_null(ld.expected[ld.idx]);

  /* NEW_TOKEN (tokenlen > 64) */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef frm rx 778 1RTT NEW_TOKEN(0x07) "
        "token="
        "0xe1ddaa003399aa11e1ddaa003399aa11e1ddaa003399aa11e1ddaa003399aa11e1dd"
        "aa003399aa11e1ddaa003399aa11e1ddaa003399aa11e1ddaa003399aa11* len=65",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_fr(&log, &hd,
                   &(ngtcp2_frame){.new_token = {
                                     .type = NGTCP2_FRAME_NEW_TOKEN,
                                     .token = token_long,
                                     .tokenlen = sizeof(token_long),
                                   }});

  assert_null(ld.expected[ld.idx]);

  /* RETIRE_CONNECTION_ID */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef frm rx 778 1RTT RETIRE_CONNECTION_ID(0x19) "
        "seq=1000000007",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_fr(&log, &hd,
                   &(ngtcp2_frame){.retire_connection_id = {
                                     .type = NGTCP2_FRAME_RETIRE_CONNECTION_ID,
                                     .seq = 1000000007,
                                   }});

  assert_null(ld.expected[ld.idx]);

  /* HANDSHAKE_DONE */
  ld = (log_data){
    .expected = {"I00001123 0xdeadbeef frm rx 778 1RTT HANDSHAKE_DONE(0x1e)"},
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_fr(&log, &hd,
                   &(ngtcp2_frame){.handshake_done = {
                                     .type = NGTCP2_FRAME_HANDSHAKE_DONE,
                                   }});

  assert_null(ld.expected[ld.idx]);

  /* DATAGRAM */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef frm rx 778 1RTT DATAGRAM(0x30) len=123",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_rx_fr(&log, &hd,
                   &(ngtcp2_frame){.datagram = {
                                     .type = NGTCP2_FRAME_DATAGRAM,
                                     .datacnt = ngtcp2_arraylen(data),
                                     .data = data,
                                   }});

  assert_null(ld.expected[ld.idx]);
}

#if defined(NGTCP2_USE_GENERIC_SOCKADDR) && defined(s6_addr)
#  undef s6_addr
#endif /* defined(NGTCP2_USE_GENERIC_SOCKADDR) && defined(s6_addr) */

void test_ngtcp2_log_remote_tp(void) {
  log_data ld;
  ngtcp2_log log;
  uint8_t available_versions[sizeof(uint32_t) * 3];
  size_t i;

  for (i = 0; i < sizeof(available_versions); i += sizeof(uint32_t)) {
    ngtcp2_put_uint32be(&available_versions[i], (uint32_t)(0xFF000000U + i));
  }

  /* Fully filled transport parameters */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "stateless_reset_token=0xdeadbeefbaadf00dbaadcacebeefcace",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "preferred_address.ipv4_addr=186.173.202.206",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "preferred_address.ipv4_port=11732",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "preferred_address.ipv6_addr=dead:beef:baad:f00d:baad:cace:beef:cafe",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "preferred_address.ipv6_port=63111",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "preferred_address.cid=0xbeefcafe",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "preferred_address.stateless_reset_token="
        "0xdeadbeefbaadf00dbaadcacebeeff00d",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "original_destination_connection_id=0xcafebeef02ef",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "retry_source_connection_id=0xf00dcafe01",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "initial_source_connection_id=0xbaadbeef039a2b",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "initial_max_stream_data_bidi_local=1000000007",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "initial_max_stream_data_bidi_remote=961748941",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "initial_max_stream_data_uni=982451653",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "initial_max_data=1000000009",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "initial_max_streams_bidi=908",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "initial_max_streams_uni=16383",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "max_idle_timeout=16363",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "max_udp_payload_size=1200",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "ack_delay_exponent=20",
        "I00001123 0xdeadbeef cry remote transport_parameters max_ack_delay=63",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "active_connection_id_limit=1073741824",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "disable_active_migration=1",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "max_datagram_frame_size=63",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "grease_quic_bit=1",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "version_information.chosen_version=0x00000001",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "version_information.available_versions[0]=0xff000000",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "version_information.available_versions[1]=0xff000004",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "version_information.available_versions[2]=0xff000008",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_remote_tp(
    &log,
    &(ngtcp2_transport_params){
      .initial_max_stream_data_bidi_local = 1000000007,
      .initial_max_stream_data_bidi_remote = 961748941,
      .initial_max_stream_data_uni = 982451653,
      .initial_max_data = 1000000009,
      .initial_max_streams_bidi = 908,
      .initial_max_streams_uni = 16383,
      .max_idle_timeout = 16363 * NGTCP2_MILLISECONDS,
      .max_udp_payload_size = 1200,
      .stateless_reset_token_present = 1,
      .stateless_reset_token = {0xDE, 0xAD, 0xBE, 0xEF, 0xBA, 0xAD, 0xF0, 0x0D,
                                0xBA, 0xAD, 0xCA, 0xCE, 0xBE, 0xEF, 0xCA, 0xCE},
      .ack_delay_exponent = 20,
      .preferred_addr_present = 1,
      .preferred_addr =
        {
          .cid =
            {
              .datalen = 4,
              .data = {0xBE, 0xEF, 0xCA, 0xFE},
            },
          .ipv4 =
            {
              .sin_family = NGTCP2_AF_INET,
              .sin_addr =
                {
                  .s_addr = ngtcp2_htonl(0xBAADCACE),
                },
              .sin_port = ngtcp2_htons(11732),
            },
          .ipv4_present = 1,
          .ipv6 =
            {
              .sin6_family = NGTCP2_AF_INET6,
              .sin6_addr =
                {
                  .s6_addr = {0xDE, 0xAD, 0xBE, 0xEF, 0xBA, 0xAD, 0xF0, 0x0D,
                              0xBA, 0xAD, 0xCA, 0xCE, 0xBE, 0xEF, 0xCA, 0xFE},
                },
              .sin6_port = ngtcp2_htons(63111),
            },
          .ipv6_present = 1,
          .stateless_reset_token = {0xDE, 0xAD, 0xBE, 0xEF, 0xBA, 0xAD, 0xF0,
                                    0x0D, 0xBA, 0xAD, 0xCA, 0xCE, 0xBE, 0xEF,
                                    0xF0, 0x0D},
        },
      .disable_active_migration = 1,
      .max_ack_delay = 63 * NGTCP2_MILLISECONDS,
      .retry_scid =
        {
          .datalen = 5,
          .data = {0xF0, 0x0D, 0xCA, 0xFE, 0x01},
        },
      .retry_scid_present = 1,
      .original_dcid =
        {
          .datalen = 6,
          .data = {0xCA, 0xFE, 0xBE, 0xEF, 0x02, 0xEF},
        },
      .original_dcid_present = 1,
      .initial_scid =
        {
          .datalen = 7,
          .data = {0xBA, 0xAD, 0xBE, 0xEF, 0x03, 0x9A, 0x2B},
        },
      .initial_scid_present = 1,
      .active_connection_id_limit = 1073741824,
      .max_datagram_frame_size = 63,
      .grease_quic_bit = 1,
      .version_info =
        {
          .chosen_version = NGTCP2_PROTO_VER_V1,
          .available_versions = available_versions,
          .available_versionslen = ngtcp2_arraylen(available_versions),
        },
      .version_info_present = 1,
    });

  assert_null(ld.expected[ld.idx]);

  /* Minimum transport parameters */
  ld = (log_data){
    .expected =
      {
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "initial_max_stream_data_bidi_local=1000000007",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "initial_max_stream_data_bidi_remote=961748941",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "initial_max_stream_data_uni=982451653",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "initial_max_data=1000000009",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "initial_max_streams_bidi=908",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "initial_max_streams_uni=16383",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "max_idle_timeout=16363",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "max_udp_payload_size=1200",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "ack_delay_exponent=20",
        "I00001123 0xdeadbeef cry remote transport_parameters max_ack_delay=63",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "active_connection_id_limit=1073741824",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "disable_active_migration=1",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "max_datagram_frame_size=63",
        "I00001123 0xdeadbeef cry remote transport_parameters "
        "grease_quic_bit=1",
      },
  };

  log_init(&log, &ld);

  ngtcp2_log_remote_tp(&log, &(ngtcp2_transport_params){
                               .initial_max_stream_data_bidi_local = 1000000007,
                               .initial_max_stream_data_bidi_remote = 961748941,
                               .initial_max_stream_data_uni = 982451653,
                               .initial_max_data = 1000000009,
                               .initial_max_streams_bidi = 908,
                               .initial_max_streams_uni = 16383,
                               .max_idle_timeout = 16363 * NGTCP2_MILLISECONDS,
                               .max_udp_payload_size = 1200,
                               .ack_delay_exponent = 20,
                               .disable_active_migration = 1,
                               .max_ack_delay = 63 * NGTCP2_MILLISECONDS,
                               .active_connection_id_limit = 1073741824,
                               .max_datagram_frame_size = 63,
                               .grease_quic_bit = 1,
                             });

  assert_null(ld.expected[ld.idx]);
}
