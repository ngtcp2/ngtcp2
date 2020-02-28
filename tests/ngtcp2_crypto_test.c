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

#include <CUnit/CUnit.h>

#include "ngtcp2_crypto.h"
#include "ngtcp2_cid.h"
#include "ngtcp2_conv.h"
#include "ngtcp2_test_helper.h"

static size_t varint_paramlen(ngtcp2_transport_param_id id, uint64_t value) {
  size_t valuelen = ngtcp2_put_varint_len(value);
  return ngtcp2_put_varint_len(id) + ngtcp2_put_varint_len(valuelen) + valuelen;
}

void test_ngtcp2_encode_transport_params(void) {
  ngtcp2_transport_params params, nparams;
  uint8_t buf[512];
  ngtcp2_ssize nwrite;
  int rv;
  size_t i;
  ngtcp2_cid ocid;

  dcid_init(&ocid);

  memset(&params, 0, sizeof(params));
  memset(&nparams, 0, sizeof(nparams));

  /* CH, required parameters only */
  params.max_packet_size = NGTCP2_MAX_PKT_SIZE;
  params.ack_delay_exponent = NGTCP2_DEFAULT_ACK_DELAY_EXPONENT;
  params.max_ack_delay = NGTCP2_DEFAULT_MAX_ACK_DELAY;

  nwrite = ngtcp2_encode_transport_params(
      buf, sizeof(buf), NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, &params);

  CU_ASSERT(0 == nwrite);

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
  CU_ASSERT(params.initial_max_streams_bidi ==
            nparams.initial_max_streams_bidi);
  CU_ASSERT(params.initial_max_streams_uni == nparams.initial_max_streams_uni);
  CU_ASSERT(params.max_idle_timeout == nparams.max_idle_timeout);
  CU_ASSERT(params.max_packet_size == nparams.max_packet_size);
  CU_ASSERT(params.ack_delay_exponent == nparams.ack_delay_exponent);
  CU_ASSERT(params.stateless_reset_token_present ==
            nparams.stateless_reset_token_present);
  CU_ASSERT(params.disable_active_migration ==
            nparams.disable_active_migration);
  CU_ASSERT(params.max_ack_delay == nparams.max_ack_delay);

  memset(&params, 0, sizeof(params));
  memset(&nparams, 0, sizeof(nparams));

  /* EE, required parameters only */
  params.max_packet_size = NGTCP2_MAX_PKT_SIZE;
  params.ack_delay_exponent = NGTCP2_DEFAULT_ACK_DELAY_EXPONENT;
  params.max_ack_delay = NGTCP2_DEFAULT_MAX_ACK_DELAY;

  nwrite = ngtcp2_encode_transport_params(
      buf, sizeof(buf), NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS,
      &params);

  CU_ASSERT(0 == nwrite);

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
  CU_ASSERT(params.initial_max_streams_bidi ==
            nparams.initial_max_streams_bidi);
  CU_ASSERT(params.initial_max_streams_uni == nparams.initial_max_streams_uni);
  CU_ASSERT(params.max_idle_timeout == nparams.max_idle_timeout);
  CU_ASSERT(params.max_packet_size == nparams.max_packet_size);
  CU_ASSERT(params.stateless_reset_token_present ==
            nparams.stateless_reset_token_present);
  CU_ASSERT(params.ack_delay_exponent == nparams.ack_delay_exponent);
  CU_ASSERT(params.disable_active_migration ==
            nparams.disable_active_migration);
  CU_ASSERT(params.max_ack_delay == nparams.max_ack_delay);

  memset(&params, 0, sizeof(params));
  memset(&nparams, 0, sizeof(nparams));

  /* CH, all parameters */
  params.initial_max_stream_data_bidi_local = 1000000007;
  params.initial_max_stream_data_bidi_remote = 961748941;
  params.initial_max_stream_data_uni = 982451653;
  params.initial_max_data = 1000000009;
  params.initial_max_streams_bidi = 909;
  params.initial_max_streams_uni = 911;
  params.max_idle_timeout = 1023 * NGTCP2_MILLISECONDS;
  params.max_packet_size = 1400;
  params.ack_delay_exponent = 20;
  params.disable_active_migration = 1;
  params.max_ack_delay = 59 * NGTCP2_MILLISECONDS;
  params.active_connection_id_limit = 1000000007;

  for (i = 0;
       i <
       varint_paramlen(
           NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
           params.initial_max_stream_data_bidi_local) +
           varint_paramlen(
               NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
               params.initial_max_stream_data_bidi_remote) +
           varint_paramlen(NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI,
                           params.initial_max_stream_data_uni) +
           varint_paramlen(NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_DATA,
                           params.initial_max_data) +
           varint_paramlen(NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI,
                           params.initial_max_streams_bidi) +
           varint_paramlen(NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI,
                           params.initial_max_streams_uni) +
           varint_paramlen(NGTCP2_TRANSPORT_PARAM_MAX_IDLE_TIMEOUT,
                           params.max_idle_timeout / NGTCP2_MILLISECONDS) +
           varint_paramlen(NGTCP2_TRANSPORT_PARAM_MAX_PACKET_SIZE,
                           params.max_packet_size) +
           varint_paramlen(NGTCP2_TRANSPORT_PARAM_ACK_DELAY_EXPONENT,
                           params.ack_delay_exponent) +
           (ngtcp2_put_varint_len(
                NGTCP2_TRANSPORT_PARAM_DISABLE_ACTIVE_MIGRATION) +
            ngtcp2_put_varint_len(0)) +
           varint_paramlen(NGTCP2_TRANSPORT_PARAM_MAX_ACK_DELAY,
                           params.max_ack_delay / NGTCP2_MILLISECONDS) +
           varint_paramlen(NGTCP2_TRANSPORT_PARAM_ACTIVE_CONNECTION_ID_LIMIT,
                           params.active_connection_id_limit);
       ++i) {
    nwrite = ngtcp2_encode_transport_params(
        buf, i, NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, &params);
    CU_ASSERT(NGTCP2_ERR_NOBUF == nwrite);
  }
  nwrite = ngtcp2_encode_transport_params(
      buf, i, NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, &params);

  CU_ASSERT((ngtcp2_ssize)i == nwrite);

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
  CU_ASSERT(params.initial_max_streams_bidi ==
            nparams.initial_max_streams_bidi);
  CU_ASSERT(params.initial_max_streams_uni == nparams.initial_max_streams_uni);
  CU_ASSERT(params.max_idle_timeout == nparams.max_idle_timeout);
  CU_ASSERT(params.max_packet_size == nparams.max_packet_size);
  CU_ASSERT(params.ack_delay_exponent == nparams.ack_delay_exponent);
  CU_ASSERT(params.disable_active_migration ==
            nparams.disable_active_migration);
  CU_ASSERT(params.max_ack_delay == nparams.max_ack_delay);
  CU_ASSERT(params.active_connection_id_limit ==
            nparams.active_connection_id_limit);

  memset(&params, 0, sizeof(params));
  memset(&nparams, 0, sizeof(nparams));

  /* EE, all parameters */
  params.initial_max_stream_data_bidi_local = 1000000007;
  params.initial_max_stream_data_bidi_remote = 961748941;
  params.initial_max_stream_data_uni = 982451653;
  params.initial_max_data = 1000000009;
  params.initial_max_streams_bidi = 908;
  params.initial_max_streams_uni = 16383;
  params.max_idle_timeout = 16363 * NGTCP2_MILLISECONDS;
  params.max_packet_size = 1200;
  params.stateless_reset_token_present = 1;
  memset(params.stateless_reset_token, 0xf1,
         sizeof(params.stateless_reset_token));
  params.ack_delay_exponent = 20;
  params.preferred_address_present = 1;
  memset(params.preferred_address.ipv4_addr, 0,
         sizeof(params.preferred_address.ipv4_addr));
  params.preferred_address.ipv4_port = 0;
  memset(params.preferred_address.ipv6_addr, 0xe1,
         sizeof(params.preferred_address.ipv6_addr));
  params.preferred_address.ipv6_port = 63111;
  scid_init(&params.preferred_address.cid);
  memset(params.preferred_address.stateless_reset_token, 0xd1,
         sizeof(params.preferred_address.stateless_reset_token));
  params.disable_active_migration = 1;
  params.max_ack_delay = 63 * NGTCP2_MILLISECONDS;
  params.original_connection_id_present = 1;
  params.original_connection_id = ocid;
  params.active_connection_id_limit = 1073741824;

  for (i = 0;
       i <
       varint_paramlen(
           NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
           params.initial_max_stream_data_bidi_local) +
           varint_paramlen(
               NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
               params.initial_max_stream_data_bidi_remote) +
           varint_paramlen(NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI,
                           params.initial_max_stream_data_uni) +
           varint_paramlen(NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_DATA,
                           params.initial_max_data) +
           varint_paramlen(NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI,
                           params.initial_max_streams_bidi) +
           varint_paramlen(NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI,
                           params.initial_max_streams_uni) +
           varint_paramlen(NGTCP2_TRANSPORT_PARAM_MAX_IDLE_TIMEOUT,
                           params.max_idle_timeout / NGTCP2_MILLISECONDS) +
           varint_paramlen(NGTCP2_TRANSPORT_PARAM_MAX_PACKET_SIZE,
                           params.max_packet_size) +
           varint_paramlen(NGTCP2_TRANSPORT_PARAM_ACK_DELAY_EXPONENT,
                           params.ack_delay_exponent) +
           (ngtcp2_put_varint_len(
                NGTCP2_TRANSPORT_PARAM_DISABLE_ACTIVE_MIGRATION) +
            ngtcp2_put_varint_len(0)) +
           varint_paramlen(NGTCP2_TRANSPORT_PARAM_MAX_ACK_DELAY,
                           params.max_ack_delay / NGTCP2_MILLISECONDS) +
           varint_paramlen(NGTCP2_TRANSPORT_PARAM_ACTIVE_CONNECTION_ID_LIMIT,
                           params.active_connection_id_limit) +
           (ngtcp2_put_varint_len(
                NGTCP2_TRANSPORT_PARAM_STATELESS_RESET_TOKEN) +
            ngtcp2_put_varint_len(NGTCP2_STATELESS_RESET_TOKENLEN) +
            NGTCP2_STATELESS_RESET_TOKENLEN) +
           (ngtcp2_put_varint_len(NGTCP2_TRANSPORT_PARAM_PREFERRED_ADDRESS) +
            ngtcp2_put_varint_len(4 + 2 + 16 + 2 + 1 +
                                  params.preferred_address.cid.datalen +
                                  NGTCP2_STATELESS_RESET_TOKENLEN) +
            4 + 2 + 16 + 2 + 1 + params.preferred_address.cid.datalen +
            NGTCP2_STATELESS_RESET_TOKENLEN) +
           (ngtcp2_put_varint_len(
                NGTCP2_TRANSPORT_PARAM_ORIGINAL_CONNECTION_ID) +
            ngtcp2_put_varint_len(params.original_connection_id.datalen) +
            params.original_connection_id.datalen);
       ++i) {
    nwrite = ngtcp2_encode_transport_params(
        buf, i, NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, &params);

    CU_ASSERT(NGTCP2_ERR_NOBUF == nwrite);
  }
  nwrite = ngtcp2_encode_transport_params(
      buf, i, NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, &params);

  CU_ASSERT((ngtcp2_ssize)i == nwrite);

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
  CU_ASSERT(params.initial_max_streams_bidi ==
            nparams.initial_max_streams_bidi);
  CU_ASSERT(params.initial_max_streams_uni == nparams.initial_max_streams_uni);
  CU_ASSERT(params.max_idle_timeout == nparams.max_idle_timeout);
  CU_ASSERT(params.max_packet_size == nparams.max_packet_size);
  CU_ASSERT(0 == memcmp(params.stateless_reset_token,
                        nparams.stateless_reset_token,
                        sizeof(params.stateless_reset_token)));
  CU_ASSERT(params.ack_delay_exponent == nparams.ack_delay_exponent);
  CU_ASSERT(params.preferred_address_present ==
            nparams.preferred_address_present);
  CU_ASSERT(0 == memcmp(params.preferred_address.ipv4_addr,
                        nparams.preferred_address.ipv4_addr,
                        sizeof(params.preferred_address.ipv4_addr)));
  CU_ASSERT(params.preferred_address.ipv4_port ==
            nparams.preferred_address.ipv4_port);
  CU_ASSERT(0 == memcmp(params.preferred_address.ipv6_addr,
                        nparams.preferred_address.ipv6_addr,
                        sizeof(params.preferred_address.ipv6_addr)));
  CU_ASSERT(params.preferred_address.ipv6_port ==
            nparams.preferred_address.ipv6_port);
  CU_ASSERT(ngtcp2_cid_eq(&params.preferred_address.cid,
                          &nparams.preferred_address.cid));
  CU_ASSERT(0 ==
            memcmp(params.preferred_address.stateless_reset_token,
                   nparams.preferred_address.stateless_reset_token,
                   sizeof(params.preferred_address.stateless_reset_token)));
  CU_ASSERT(params.disable_active_migration ==
            nparams.disable_active_migration);
  CU_ASSERT(params.max_ack_delay == nparams.max_ack_delay);
  CU_ASSERT(params.original_connection_id_present ==
            nparams.original_connection_id_present);
  CU_ASSERT(ngtcp2_cid_eq(&params.original_connection_id,
                          &nparams.original_connection_id));
  CU_ASSERT(params.active_connection_id_limit ==
            nparams.active_connection_id_limit);
}
