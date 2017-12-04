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
#include "ngtcp2_crypto_test.h"

#include <assert.h>

#include <CUnit/CUnit.h>

#include "ngtcp2_crypto.h"
#include "ngtcp2_test_helper.h"

void test_ngtcp2_encode_transport_params(void) {
  ngtcp2_transport_params params, nparams;
  uint8_t buf[256];
  ssize_t nwrite;
  int rv;
  size_t i;

  /* CH, required parameters only */
  params.v.ch.initial_version = 0xe1e2e3e4u;
  params.initial_max_stream_data = 1000000007;
  params.initial_max_data = 1000000009;
  params.initial_max_stream_id_bidi = 0;
  params.initial_max_stream_id_uni = 0;
  params.idle_timeout = 0xd1d2;
  params.omit_connection_id = 0;
  params.max_packet_size = NGTCP2_MAX_PKT_SIZE;
  params.ack_delay_exponent = NGTCP2_DEFAULT_ACK_DELAY_EXPONENT;

  nwrite = ngtcp2_encode_transport_params(
      buf, sizeof(buf), NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, &params);

  CU_ASSERT(4 /* initial_version */ + 2 + 8 * 2 + 6 == nwrite);

  rv = ngtcp2_decode_transport_params(
      &nparams, NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, buf, (size_t)nwrite);

  CU_ASSERT(0 == rv);
  CU_ASSERT(params.v.ch.initial_version == nparams.v.ch.initial_version);
  CU_ASSERT(params.initial_max_stream_data == nparams.initial_max_stream_data);
  CU_ASSERT(params.initial_max_data == nparams.initial_max_data);
  CU_ASSERT(params.initial_max_stream_id_bidi ==
            nparams.initial_max_stream_id_bidi);
  CU_ASSERT(params.idle_timeout == nparams.idle_timeout);
  CU_ASSERT(params.omit_connection_id == nparams.omit_connection_id);
  CU_ASSERT(params.max_packet_size == nparams.max_packet_size);
  CU_ASSERT(params.ack_delay_exponent == nparams.ack_delay_exponent);

  memset(&nparams, 0, sizeof(nparams));

  /* EE, required parameters only */
  params.v.ee.negotiated_version = 0xf1f2f3f4u;
  params.v.ee.supported_versions[0] = 0xd1d2d3d4u;
  params.v.ee.supported_versions[1] = 0xe1e2e3e4u;
  params.v.ee.supported_versions[2] = 0xf1f2f3f4u;
  params.v.ee.len = 3;
  params.initial_max_stream_data = 1000000007;
  params.initial_max_data = 1000000009;
  params.initial_max_stream_id_bidi = 0;
  params.initial_max_stream_id_uni = 0;
  params.idle_timeout = 0xd1d2;
  params.omit_connection_id = 0;
  params.max_packet_size = NGTCP2_MAX_PKT_SIZE;
  memset(params.stateless_reset_token, 0xf1,
         sizeof(params.stateless_reset_token));
  params.ack_delay_exponent = NGTCP2_DEFAULT_ACK_DELAY_EXPONENT;

  nwrite = ngtcp2_encode_transport_params(
      buf, sizeof(buf), NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS,
      &params);

  CU_ASSERT(4 /* negotiated_version */ + 1 +
                4 * 3 /* supported_versions and its length */ + 2 + 8 * 2 + 6 +
                20 ==
            nwrite);

  rv = ngtcp2_decode_transport_params(
      &nparams, NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, buf,
      (size_t)nwrite);

  CU_ASSERT(0 == rv);
  CU_ASSERT(params.v.ee.negotiated_version == nparams.v.ee.negotiated_version);
  CU_ASSERT(params.v.ee.len == nparams.v.ee.len);
  for (i = 0; i < 3; ++i) {
    CU_ASSERT(params.v.ee.supported_versions[i] ==
              nparams.v.ee.supported_versions[i]);
  }
  CU_ASSERT(params.initial_max_stream_data == nparams.initial_max_stream_data);
  CU_ASSERT(params.initial_max_data == nparams.initial_max_data);
  CU_ASSERT(params.initial_max_stream_id_bidi ==
            nparams.initial_max_stream_id_bidi);
  CU_ASSERT(params.idle_timeout == nparams.idle_timeout);
  CU_ASSERT(params.omit_connection_id == nparams.omit_connection_id);
  CU_ASSERT(params.max_packet_size == nparams.max_packet_size);
  CU_ASSERT(0 == memcmp(params.stateless_reset_token,
                        nparams.stateless_reset_token,
                        sizeof(params.stateless_reset_token)));
  CU_ASSERT(params.ack_delay_exponent == nparams.ack_delay_exponent);

  memset(&nparams, 0, sizeof(nparams));

  /* CH, all parameters */
  params.v.ch.initial_version = 0xe1e2e3e4u;
  params.initial_max_stream_data = 1000000007;
  params.initial_max_data = 1000000009;
  params.initial_max_stream_id_bidi = 909;
  params.initial_max_stream_id_uni = 911;
  params.idle_timeout = 0xd1d2;
  params.omit_connection_id = 1;
  params.max_packet_size = 1400;
  params.ack_delay_exponent = 20;

  nwrite = ngtcp2_encode_transport_params(
      buf, sizeof(buf), NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, &params);

  CU_ASSERT(4 /* initial_version */ + 2 + 8 * 4 + 6 + 4 + 6 + 5 == nwrite);

  rv = ngtcp2_decode_transport_params(
      &nparams, NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, buf, (size_t)nwrite);

  CU_ASSERT(0 == rv);
  CU_ASSERT(params.initial_max_stream_data == nparams.initial_max_stream_data);
  CU_ASSERT(params.initial_max_data == nparams.initial_max_data);
  CU_ASSERT(params.initial_max_stream_id_bidi ==
            nparams.initial_max_stream_id_bidi);
  CU_ASSERT(params.initial_max_stream_id_uni ==
            nparams.initial_max_stream_id_uni);
  CU_ASSERT(params.idle_timeout == nparams.idle_timeout);
  CU_ASSERT(params.omit_connection_id == nparams.omit_connection_id);
  CU_ASSERT(params.max_packet_size == nparams.max_packet_size);
  CU_ASSERT(params.ack_delay_exponent == nparams.ack_delay_exponent);

  memset(&nparams, 0, sizeof(nparams));

  /* NST, all parameters */
  params.initial_max_stream_data = 1000000007;
  params.initial_max_data = 1000000009;
  params.initial_max_stream_id_bidi = 908;
  params.initial_max_stream_id_uni = 910;
  params.idle_timeout = 0xd1d2;
  params.omit_connection_id = 1;
  params.max_packet_size = 1400;
  memset(params.stateless_reset_token, 0xf1,
         sizeof(params.stateless_reset_token));
  params.ack_delay_exponent = 20;

  nwrite = ngtcp2_encode_transport_params(
      buf, sizeof(buf), NGTCP2_TRANSPORT_PARAMS_TYPE_NEW_SESSION_TICKET,
      &params);

  CU_ASSERT(2 + 8 * 4 + 6 + 4 + 6 + 20 + 5 == nwrite);

  rv = ngtcp2_decode_transport_params(
      &nparams, NGTCP2_TRANSPORT_PARAMS_TYPE_NEW_SESSION_TICKET, buf,
      (size_t)nwrite);

  CU_ASSERT(0 == rv);
  CU_ASSERT(params.initial_max_stream_data == nparams.initial_max_stream_data);
  CU_ASSERT(params.initial_max_data == nparams.initial_max_data);
  CU_ASSERT(params.initial_max_stream_id_bidi ==
            nparams.initial_max_stream_id_bidi);
  CU_ASSERT(params.initial_max_stream_id_uni ==
            nparams.initial_max_stream_id_uni);
  CU_ASSERT(params.idle_timeout == nparams.idle_timeout);
  CU_ASSERT(params.omit_connection_id == nparams.omit_connection_id);
  CU_ASSERT(params.max_packet_size == nparams.max_packet_size);
  CU_ASSERT(0 == memcmp(params.stateless_reset_token,
                        nparams.stateless_reset_token,
                        sizeof(params.stateless_reset_token)));
  CU_ASSERT(params.ack_delay_exponent == nparams.ack_delay_exponent);

  memset(&nparams, 0, sizeof(nparams));

  /* NST, The last param is omit_connection_id */
  params.initial_max_stream_data = 1000000007;
  params.initial_max_data = 1000000009;
  params.initial_max_stream_id_bidi = 908;
  params.initial_max_stream_id_uni = 0;
  params.idle_timeout = 0xd1d2;
  params.omit_connection_id = 1;
  params.max_packet_size = NGTCP2_MAX_PKT_SIZE;
  memset(params.stateless_reset_token, 0xf1,
         sizeof(params.stateless_reset_token));
  params.ack_delay_exponent = NGTCP2_DEFAULT_ACK_DELAY_EXPONENT;

  nwrite = ngtcp2_encode_transport_params(
      buf, sizeof(buf), NGTCP2_TRANSPORT_PARAMS_TYPE_NEW_SESSION_TICKET,
      &params);

  CU_ASSERT(2 + 8 * 3 + 6 + 4 + 20 == nwrite);

  rv = ngtcp2_decode_transport_params(
      &nparams, NGTCP2_TRANSPORT_PARAMS_TYPE_NEW_SESSION_TICKET, buf,
      (size_t)nwrite);

  CU_ASSERT(0 == rv);
  CU_ASSERT(params.initial_max_stream_data == nparams.initial_max_stream_data);
  CU_ASSERT(params.initial_max_data == nparams.initial_max_data);
  CU_ASSERT(params.initial_max_stream_id_bidi ==
            nparams.initial_max_stream_id_bidi);
  CU_ASSERT(params.idle_timeout == nparams.idle_timeout);
  CU_ASSERT(params.omit_connection_id == nparams.omit_connection_id);
  CU_ASSERT(params.max_packet_size == NGTCP2_MAX_PKT_SIZE);
  CU_ASSERT(0 == memcmp(params.stateless_reset_token,
                        nparams.stateless_reset_token,
                        sizeof(params.stateless_reset_token)));

  memset(&nparams, 0, sizeof(nparams));

  /* CH, Data is too short to decode */
  params.v.ch.initial_version = 0xe1e2e3e4u;
  params.initial_max_stream_data = 1000000007;
  params.initial_max_data = 1000000009;
  params.initial_max_stream_id_bidi = 909;
  params.initial_max_stream_id_uni = 0;
  params.idle_timeout = 0xd1d2;
  params.omit_connection_id = 1;
  params.max_packet_size = 1200;
  params.ack_delay_exponent = 20;

  nwrite = ngtcp2_encode_transport_params(
      buf, sizeof(buf), NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, &params);

  for (i = 0; i < (size_t)nwrite; ++i) {
    rv = ngtcp2_decode_transport_params(
        &nparams, NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, buf, i);

    CU_ASSERT(NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM == rv);
  }

  memset(&nparams, 0, sizeof(nparams));

  /* CH, Buffer is too short to encode */
  params.v.ch.initial_version = 0xe1e2e3e4u;
  params.initial_max_stream_data = 1000000007;
  params.initial_max_data = 1000000009;
  params.initial_max_stream_id_bidi = 909;
  params.initial_max_stream_id_uni = 0;
  params.idle_timeout = 0xd1d2;
  params.omit_connection_id = 1;
  params.max_packet_size = 1200;
  params.ack_delay_exponent = 20;

  for (i = 0; i < 4 /* initial_version */ + 2 + 8 * 3 + 6 + 4 + 6 + 5; ++i) {
    nwrite = ngtcp2_encode_transport_params(
        buf, i, NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, &params);

    CU_ASSERT(NGTCP2_ERR_NOBUF == nwrite);
  }
  nwrite = ngtcp2_encode_transport_params(
      buf, i, NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, &params);

  CU_ASSERT((ssize_t)i == nwrite);

  /* EE, Buffer is too short to encode */
  params.v.ee.negotiated_version = 0xf1f2f3f4u;
  params.v.ee.supported_versions[0] = 0xd1d2d3d4u;
  params.v.ee.supported_versions[1] = 0xe1e2e3e4u;
  params.v.ee.supported_versions[2] = 0xf1f2f3f4u;
  params.v.ee.len = 3;
  params.initial_max_stream_data = 1000000007;
  params.initial_max_data = 1000000009;
  params.initial_max_stream_id_bidi = 908;
  params.initial_max_stream_id_uni = 0;
  params.idle_timeout = 0xd1d2;
  params.omit_connection_id = 1;
  params.max_packet_size = 1200;
  memset(params.stateless_reset_token, 0xf1,
         sizeof(params.stateless_reset_token));
  params.ack_delay_exponent = 20;

  for (i = 0; i < 4 /* negotiated_version */ + 1 +
                      4 * 3 /* supported_versions and its length */ + 2 +
                      8 * 3 + 6 + 4 + 6 + 20 + 5;
       ++i) {
    nwrite = ngtcp2_encode_transport_params(
        buf, i, NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, &params);

    CU_ASSERT(NGTCP2_ERR_NOBUF == nwrite);
  }
  nwrite = ngtcp2_encode_transport_params(
      buf, i, NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, &params);

  CU_ASSERT((ssize_t)i == nwrite);
}
