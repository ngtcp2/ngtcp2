/*
 * ngtcp2
 *
 * Copyright (c) 2024 ngtcp2 contributors
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
#include "ngtcp2_settings_test.h"

#include <stdio.h>

#include "ngtcp2_settings.h"
#include "ngtcp2_test_helper.h"

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_settings_convert_to_latest),
  munit_void_test(test_ngtcp2_settings_convert_to_old),
  munit_test_end(),
};

const MunitSuite settings_suite = {
  "/settings", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE,
};

static void qlog_write(void *user_data, uint32_t flags, const void *data,
                       size_t datalen) {
  (void)user_data;
  (void)flags;
  (void)data;
  (void)datalen;
}

static void log_printf(void *user_data, const char *format, ...) {
  (void)user_data;
  (void)format;
}

static uint8_t token[] = "token";
static int rand_ctx;
static uint32_t preferred_versions[] = {518522897, 103325514, 932403068};
static uint32_t available_versions[] = {534114833, 797700084, 96134021,
                                        55039145};
static uint16_t pmtud_probes[] = {65466, 47820, 27776};

void test_ngtcp2_settings_convert_to_latest(void) {
  ngtcp2_settings *src, srcbuf, settingsbuf;
  const ngtcp2_settings *dest;
  size_t v1len;

  ngtcp2_settings_default_versioned(NGTCP2_SETTINGS_V1, &srcbuf);

  srcbuf.qlog_write = qlog_write;
  srcbuf.cc_algo = NGTCP2_CC_ALGO_CUBIC;
  srcbuf.initial_ts = 10000000007;
  srcbuf.initial_rtt = 911852349;
  srcbuf.log_printf = log_printf;
  srcbuf.max_tx_udp_payload_size = 9999;
  srcbuf.token = token;
  srcbuf.tokenlen = sizeof(token);
  srcbuf.token_type = NGTCP2_TOKEN_TYPE_RETRY;
  srcbuf.rand_ctx.native_handle = &rand_ctx;
  srcbuf.max_window = 235386122;
  srcbuf.max_stream_window = 812304706;
  srcbuf.ack_thresh = 845485835;
  srcbuf.no_tx_udp_payload_size_shaping = 1;
  srcbuf.handshake_timeout = 264345836;
  srcbuf.preferred_versions = preferred_versions;
  srcbuf.preferred_versionslen = ngtcp2_arraylen(preferred_versions);
  srcbuf.available_versions = available_versions;
  srcbuf.available_versionslen = ngtcp2_arraylen(available_versions);
  srcbuf.original_version = 767521389;
  srcbuf.no_pmtud = 1;
  srcbuf.initial_pkt_num = 918608434;

  v1len = ngtcp2_settingslen_version(NGTCP2_SETTINGS_V1);

  src = malloc(v1len);

  memcpy(src, &srcbuf, v1len);

  dest = ngtcp2_settings_convert_to_latest(&settingsbuf,
                                           NGTCP2_TRANSPORT_PARAMS_V1, src);

  free(src);

  assert_ptr_equal(dest, &settingsbuf);
  assert_ptr_equal(srcbuf.qlog_write, dest->qlog_write);
  assert_enum(ngtcp2_cc_algo, srcbuf.cc_algo, ==, dest->cc_algo);
  assert_uint64(srcbuf.initial_ts, ==, dest->initial_ts);
  assert_uint64(srcbuf.initial_rtt, ==, dest->initial_rtt);
  assert_ptr_equal(srcbuf.log_printf, dest->log_printf);
  assert_size(srcbuf.max_tx_udp_payload_size, ==,
              dest->max_tx_udp_payload_size);
  assert_ptr_equal(srcbuf.token, dest->token);
  assert_size(srcbuf.tokenlen, ==, dest->tokenlen);
  assert_enum(ngtcp2_token_type, srcbuf.token_type, ==, dest->token_type);
  assert_ptr_equal(srcbuf.rand_ctx.native_handle, dest->rand_ctx.native_handle);
  assert_uint64(srcbuf.max_window, ==, dest->max_window);
  assert_uint64(srcbuf.max_stream_window, ==, dest->max_stream_window);
  assert_size(srcbuf.ack_thresh, ==, dest->ack_thresh);
  assert_uint8(srcbuf.no_tx_udp_payload_size_shaping, ==,
               dest->no_tx_udp_payload_size_shaping);
  assert_uint64(srcbuf.handshake_timeout, ==, dest->handshake_timeout);
  assert_ptr_equal(srcbuf.preferred_versions, dest->preferred_versions);
  assert_size(srcbuf.preferred_versionslen, ==, dest->preferred_versionslen);
  assert_ptr_equal(srcbuf.available_versions, dest->available_versions);
  assert_size(srcbuf.available_versionslen, ==, dest->available_versionslen);
  assert_uint32(srcbuf.original_version, ==, dest->original_version);
  assert_uint8(srcbuf.no_pmtud, ==, dest->no_pmtud);
  assert_uint32(srcbuf.initial_pkt_num, ==, dest->initial_pkt_num);
  assert_null(dest->pmtud_probes);
  assert_size(0, ==, dest->pmtud_probeslen);
}

void test_ngtcp2_settings_convert_to_old(void) {
  ngtcp2_settings src, *dest, destbuf;
  size_t v1len;

  v1len = ngtcp2_settingslen_version(NGTCP2_SETTINGS_V1);

  dest = malloc(v1len);

  ngtcp2_settings_default(&src);
  src.qlog_write = qlog_write;
  src.cc_algo = NGTCP2_CC_ALGO_CUBIC;
  src.initial_ts = 10000000007;
  src.initial_rtt = 911852349;
  src.log_printf = log_printf;
  src.max_tx_udp_payload_size = 9999;
  src.token = token;
  src.tokenlen = sizeof(token);
  src.token_type = NGTCP2_TOKEN_TYPE_RETRY;
  src.rand_ctx.native_handle = &rand_ctx;
  src.max_window = 235386122;
  src.max_stream_window = 812304706;
  src.ack_thresh = 845485835;
  src.no_tx_udp_payload_size_shaping = 1;
  src.handshake_timeout = 264345836;
  src.preferred_versions = preferred_versions;
  src.preferred_versionslen = ngtcp2_arraylen(preferred_versions);
  src.available_versions = available_versions;
  src.available_versionslen = ngtcp2_arraylen(available_versions);
  src.original_version = 767521389;
  src.no_pmtud = 1;
  src.initial_pkt_num = 918608434;
  src.pmtud_probes = pmtud_probes;
  src.pmtud_probeslen = ngtcp2_arraylen(pmtud_probes);

  ngtcp2_settings_convert_to_old(NGTCP2_SETTINGS_V1, dest, &src);

  memset(&destbuf, 0, sizeof(destbuf));
  memcpy(&destbuf, dest, v1len);

  free(dest);

  assert_ptr_equal(src.qlog_write, destbuf.qlog_write);
  assert_enum(ngtcp2_cc_algo, src.cc_algo, ==, destbuf.cc_algo);
  assert_uint64(src.initial_ts, ==, destbuf.initial_ts);
  assert_uint64(src.initial_rtt, ==, destbuf.initial_rtt);
  assert_ptr_equal(src.log_printf, destbuf.log_printf);
  assert_size(src.max_tx_udp_payload_size, ==, destbuf.max_tx_udp_payload_size);
  assert_ptr_equal(src.token, destbuf.token);
  assert_size(src.tokenlen, ==, destbuf.tokenlen);
  assert_enum(ngtcp2_token_type, src.token_type, ==, destbuf.token_type);
  assert_ptr_equal(src.rand_ctx.native_handle, destbuf.rand_ctx.native_handle);
  assert_uint64(src.max_window, ==, destbuf.max_window);
  assert_uint64(src.max_stream_window, ==, destbuf.max_stream_window);
  assert_size(src.ack_thresh, ==, destbuf.ack_thresh);
  assert_uint8(src.no_tx_udp_payload_size_shaping, ==,
               destbuf.no_tx_udp_payload_size_shaping);
  assert_uint64(src.handshake_timeout, ==, destbuf.handshake_timeout);
  assert_ptr_equal(src.preferred_versions, destbuf.preferred_versions);
  assert_size(src.preferred_versionslen, ==, destbuf.preferred_versionslen);
  assert_ptr_equal(src.available_versions, destbuf.available_versions);
  assert_size(src.available_versionslen, ==, destbuf.available_versionslen);
  assert_uint32(src.original_version, ==, destbuf.original_version);
  assert_uint8(src.no_pmtud, ==, destbuf.no_pmtud);
  assert_uint32(src.initial_pkt_num, ==, destbuf.initial_pkt_num);
  assert_null(destbuf.pmtud_probes);
  assert_size(0, ==, destbuf.pmtud_probeslen);
}
