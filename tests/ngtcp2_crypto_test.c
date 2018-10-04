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
#include "ngtcp2_cid.h"
#include "ngtcp2_test_helper.h"

void test_ngtcp2_encode_transport_params(void) {
  ngtcp2_transport_params params, nparams;
  uint8_t buf[512];
  ssize_t nwrite;
  int rv;
  size_t i;
  ngtcp2_cid ocid;

  dcid_init(&ocid);

  memset(&params, 0, sizeof(params));
  memset(&nparams, 0, sizeof(nparams));

  /* CH, required parameters only */
  params.v.ch.initial_version = 0xe1e2e3e4u;
  params.idle_timeout = 0xd1d2;
  params.max_packet_size = NGTCP2_MAX_PKT_SIZE;
  params.ack_delay_exponent = NGTCP2_DEFAULT_ACK_DELAY_EXPONENT;

  nwrite = ngtcp2_encode_transport_params(
      buf, sizeof(buf), NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, &params);

  CU_ASSERT(4 /* initial_version */ + 2 + 6 == nwrite);

  rv = ngtcp2_decode_transport_params(
      &nparams, NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, buf, (size_t)nwrite);

  CU_ASSERT(0 == rv);
  CU_ASSERT(params.v.ch.initial_version == nparams.v.ch.initial_version);
  CU_ASSERT(params.initial_max_stream_data_bidi_local ==
            nparams.initial_max_stream_data_bidi_local);
  CU_ASSERT(params.initial_max_stream_data_bidi_remote ==
            nparams.initial_max_stream_data_bidi_remote);
  CU_ASSERT(params.initial_max_stream_data_uni ==
            nparams.initial_max_stream_data_uni);
  CU_ASSERT(params.initial_max_data == nparams.initial_max_data);
  CU_ASSERT(params.initial_max_bidi_streams ==
            nparams.initial_max_bidi_streams);
  CU_ASSERT(params.initial_max_uni_streams == nparams.initial_max_uni_streams);
  CU_ASSERT(params.idle_timeout == nparams.idle_timeout);
  CU_ASSERT(params.max_packet_size == nparams.max_packet_size);
  CU_ASSERT(params.ack_delay_exponent == nparams.ack_delay_exponent);
  CU_ASSERT(params.stateless_reset_token_present ==
            nparams.stateless_reset_token_present);
  CU_ASSERT(params.disable_migration == nparams.disable_migration);

  memset(&params, 0, sizeof(params));
  memset(&nparams, 0, sizeof(nparams));

  /* EE, required parameters only */
  params.v.ee.negotiated_version = 0xf1f2f3f4u;
  params.v.ee.supported_versions[0] = 0xd1d2d3d4u;
  params.v.ee.supported_versions[1] = 0xe1e2e3e4u;
  params.v.ee.supported_versions[2] = 0xf1f2f3f4u;
  params.v.ee.len = 3;
  params.idle_timeout = 0xd1d2;
  params.max_packet_size = NGTCP2_MAX_PKT_SIZE;
  params.ack_delay_exponent = NGTCP2_DEFAULT_ACK_DELAY_EXPONENT;

  nwrite = ngtcp2_encode_transport_params(
      buf, sizeof(buf), NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS,
      &params);

  CU_ASSERT(4 /* negotiated_version */ + 1 +
                4 * 3 /* supported_versions and its length */ + 2 + 6 ==
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
  CU_ASSERT(params.initial_max_stream_data_bidi_local ==
            nparams.initial_max_stream_data_bidi_local);
  CU_ASSERT(params.initial_max_stream_data_bidi_remote ==
            nparams.initial_max_stream_data_bidi_remote);
  CU_ASSERT(params.initial_max_stream_data_uni ==
            nparams.initial_max_stream_data_uni);
  CU_ASSERT(params.initial_max_data == nparams.initial_max_data);
  CU_ASSERT(params.initial_max_bidi_streams ==
            nparams.initial_max_bidi_streams);
  CU_ASSERT(params.initial_max_uni_streams == nparams.initial_max_uni_streams);
  CU_ASSERT(params.idle_timeout == nparams.idle_timeout);
  CU_ASSERT(params.max_packet_size == nparams.max_packet_size);
  CU_ASSERT(params.stateless_reset_token_present ==
            nparams.stateless_reset_token_present);
  CU_ASSERT(params.ack_delay_exponent == nparams.ack_delay_exponent);
  CU_ASSERT(params.disable_migration == nparams.disable_migration);

  memset(&params, 0, sizeof(params));
  memset(&nparams, 0, sizeof(nparams));

  /* CH, all parameters */
  params.v.ch.initial_version = 0xe1e2e3e4u;
  params.initial_max_stream_data_bidi_local = 1000000007;
  params.initial_max_stream_data_bidi_remote = 961748941;
  params.initial_max_stream_data_uni = 982451653;
  params.initial_max_data = 1000000009;
  params.initial_max_bidi_streams = 909;
  params.initial_max_uni_streams = 911;
  params.idle_timeout = 0xd1d2;
  params.max_packet_size = 1400;
  params.ack_delay_exponent = 20;
  params.disable_migration = 1;

  for (i = 0; i < 4 /* initial_version */ + 2 + 8 * 4 + 6 * 2 + 6 + 6 + 5 + 4;
       ++i) {
    nwrite = ngtcp2_encode_transport_params(
        buf, i, NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, &params);

    CU_ASSERT(NGTCP2_ERR_NOBUF == nwrite);
  }
  nwrite = ngtcp2_encode_transport_params(
      buf, i, NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, &params);

  CU_ASSERT((ssize_t)i == nwrite);

  for (i = 0; (ssize_t)i < nwrite; ++i) {
    rv = ngtcp2_decode_transport_params(
        &nparams, NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, buf, i);

    CU_ASSERT(NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM == rv);
  }

  rv = ngtcp2_decode_transport_params(
      &nparams, NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, buf, (size_t)nwrite);

  CU_ASSERT(0 == rv);
  CU_ASSERT(params.initial_max_stream_data_bidi_local ==
            nparams.initial_max_stream_data_bidi_local);
  CU_ASSERT(params.initial_max_stream_data_bidi_remote ==
            nparams.initial_max_stream_data_bidi_remote);
  CU_ASSERT(params.initial_max_stream_data_uni ==
            nparams.initial_max_stream_data_uni);
  CU_ASSERT(params.initial_max_data == nparams.initial_max_data);
  CU_ASSERT(params.initial_max_bidi_streams ==
            nparams.initial_max_bidi_streams);
  CU_ASSERT(params.initial_max_uni_streams == nparams.initial_max_uni_streams);
  CU_ASSERT(params.idle_timeout == nparams.idle_timeout);
  CU_ASSERT(params.max_packet_size == nparams.max_packet_size);
  CU_ASSERT(params.ack_delay_exponent == nparams.ack_delay_exponent);
  CU_ASSERT(params.disable_migration == nparams.disable_migration);

  memset(&params, 0, sizeof(params));
  memset(&nparams, 0, sizeof(nparams));

  /* EE, all parameters */
  params.v.ee.negotiated_version = 0xf1f2f3f4u;
  params.v.ee.supported_versions[0] = 0xd1d2d3d4u;
  params.v.ee.supported_versions[1] = 0xe1e2e3e4u;
  params.v.ee.supported_versions[2] = 0xf1f2f3f4u;
  params.v.ee.len = 3;
  params.initial_max_stream_data_bidi_local = 1000000007;
  params.initial_max_stream_data_bidi_remote = 961748941;
  params.initial_max_stream_data_uni = 982451653;
  params.initial_max_data = 1000000009;
  params.initial_max_bidi_streams = 908;
  params.initial_max_uni_streams = 16384;
  params.idle_timeout = 0xd1d2;
  params.max_packet_size = 1200;
  params.stateless_reset_token_present = 1;
  memset(params.stateless_reset_token, 0xf1,
         sizeof(params.stateless_reset_token));
  params.ack_delay_exponent = 20;
  params.preferred_address.ip_version = NGTCP2_IP_VERSION_6;
  params.preferred_address.ip_addresslen = 255;
  memset(params.preferred_address.ip_address, 0xe1,
         params.preferred_address.ip_addresslen);
  params.preferred_address.port = 63111;
  scid_init(&params.preferred_address.cid);
  memset(params.preferred_address.stateless_reset_token, 0xd1,
         sizeof(params.preferred_address.stateless_reset_token));
  params.disable_migration = 1;
  params.original_connection_id_present = 1;
  params.original_connection_id = ocid;

  for (i = 0;
       i < 4 /* negotiated_version */ + 1 +
               4 * 3 /* supported_versions and its length */ + 2 + 8 * 4 +
               6 * 2 + 6 + 6 + 20 + 5 +
               (4 + 1 + 1 + 255 + 2 + 1 + params.preferred_address.cid.datalen +
                NGTCP2_STATELESS_RESET_TOKENLEN) +
               4 + 4 + params.original_connection_id.datalen;
       ++i) {
    nwrite = ngtcp2_encode_transport_params(
        buf, i, NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, &params);

    CU_ASSERT(NGTCP2_ERR_NOBUF == nwrite);
  }
  nwrite = ngtcp2_encode_transport_params(
      buf, i, NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, &params);

  CU_ASSERT((ssize_t)i == nwrite);

  for (i = 0; (ssize_t)i < nwrite; ++i) {
    rv = ngtcp2_decode_transport_params(
        &nparams, NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, buf, i);

    CU_ASSERT(rv == NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM);
  }

  rv = ngtcp2_decode_transport_params(
      &nparams, NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, buf,
      (size_t)nwrite);

  CU_ASSERT(0 == rv);
  CU_ASSERT(params.initial_max_stream_data_bidi_local ==
            nparams.initial_max_stream_data_bidi_local);
  CU_ASSERT(params.initial_max_stream_data_bidi_remote ==
            nparams.initial_max_stream_data_bidi_remote);
  CU_ASSERT(params.initial_max_stream_data_uni ==
            nparams.initial_max_stream_data_uni);
  CU_ASSERT(params.initial_max_data == nparams.initial_max_data);
  CU_ASSERT(params.initial_max_bidi_streams ==
            nparams.initial_max_bidi_streams);
  CU_ASSERT(params.initial_max_uni_streams == nparams.initial_max_uni_streams);
  CU_ASSERT(params.idle_timeout == nparams.idle_timeout);
  CU_ASSERT(params.max_packet_size == nparams.max_packet_size);
  CU_ASSERT(0 == memcmp(params.stateless_reset_token,
                        nparams.stateless_reset_token,
                        sizeof(params.stateless_reset_token)));
  CU_ASSERT(params.ack_delay_exponent == nparams.ack_delay_exponent);
  CU_ASSERT(params.preferred_address.ip_version ==
            nparams.preferred_address.ip_version);
  CU_ASSERT(params.preferred_address.ip_addresslen ==
            nparams.preferred_address.ip_addresslen);
  CU_ASSERT(0 == memcmp(params.preferred_address.ip_address,
                        nparams.preferred_address.ip_address,
                        params.preferred_address.ip_addresslen));
  CU_ASSERT(params.preferred_address.port == nparams.preferred_address.port);
  CU_ASSERT(ngtcp2_cid_eq(&params.preferred_address.cid,
                          &nparams.preferred_address.cid));
  CU_ASSERT(0 ==
            memcmp(params.preferred_address.stateless_reset_token,
                   nparams.preferred_address.stateless_reset_token,
                   sizeof(params.preferred_address.stateless_reset_token)));
  CU_ASSERT(params.disable_migration == nparams.disable_migration);
  CU_ASSERT(params.original_connection_id_present ==
            nparams.original_connection_id_present);
  CU_ASSERT(ngtcp2_cid_eq(&params.original_connection_id,
                          &nparams.original_connection_id));
}
