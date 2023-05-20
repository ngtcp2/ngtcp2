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

#include <stdio.h>

#include <CUnit/CUnit.h>

#include "ngtcp2_crypto.h"
#include "ngtcp2_cid.h"
#include "ngtcp2_conv.h"
#include "ngtcp2_net.h"
#include "ngtcp2_test_helper.h"

static size_t varint_paramlen(ngtcp2_transport_param_id id, uint64_t value) {
  size_t valuelen = ngtcp2_put_uvarintlen(value);
  return ngtcp2_put_uvarintlen(id) + ngtcp2_put_uvarintlen(valuelen) + valuelen;
}

void test_ngtcp2_transport_params_encode(void) {
  ngtcp2_transport_params params, nparams;
  uint8_t buf[512];
  ngtcp2_ssize nwrite;
  int rv;
  size_t i, len;
  ngtcp2_cid rcid, scid, dcid;
  uint8_t available_versions[sizeof(uint32_t) * 3];
  ngtcp2_sockaddr_in6 *sa_in6;

  rcid_init(&rcid);
  scid_init(&scid);
  dcid_init(&dcid);

  memset(&params, 0, sizeof(params));
  memset(&nparams, 0, sizeof(nparams));

  for (i = 0; i < sizeof(available_versions); i += sizeof(uint32_t)) {
    ngtcp2_put_uint32be(&available_versions[i], (uint32_t)(0xff000000u + i));
  }

  params.initial_max_stream_data_bidi_local = 1000000007;
  params.initial_max_stream_data_bidi_remote = 961748941;
  params.initial_max_stream_data_uni = 982451653;
  params.initial_max_data = 1000000009;
  params.initial_max_streams_bidi = 908;
  params.initial_max_streams_uni = 16383;
  params.max_idle_timeout = 16363 * NGTCP2_MILLISECONDS;
  params.max_udp_payload_size = 1200;
  params.stateless_reset_token_present = 1;
  memset(params.stateless_reset_token, 0xf1,
         sizeof(params.stateless_reset_token));
  params.ack_delay_exponent = 20;
  params.preferred_addr_present = 1;
  params.preferred_addr.ipv4_present = 0;
  sa_in6 = &params.preferred_addr.ipv6;
  sa_in6->sin6_family = AF_INET6;
  memset(&sa_in6->sin6_addr, 0xe1, sizeof(sa_in6->sin6_addr));
  sa_in6->sin6_port = ngtcp2_htons(63111);
  params.preferred_addr.ipv6_present = 1;
  scid_init(&params.preferred_addr.cid);
  memset(params.preferred_addr.stateless_reset_token, 0xd1,
         sizeof(params.preferred_addr.stateless_reset_token));
  params.disable_active_migration = 1;
  params.max_ack_delay = 63 * NGTCP2_MILLISECONDS;
  params.retry_scid_present = 1;
  params.retry_scid = rcid;
  params.original_dcid = dcid;
  params.original_dcid_present = 1;
  params.initial_scid = scid;
  params.initial_scid_present = 1;
  params.active_connection_id_limit = 1073741824;
  params.max_datagram_frame_size = 63;
  params.grease_quic_bit = 1;
  params.version_info.chosen_version = NGTCP2_PROTO_VER_V1;
  params.version_info.available_versions = available_versions;
  params.version_info.available_versionslen =
      ngtcp2_arraylen(available_versions);
  params.version_info_present = 1;

  len =
      varint_paramlen(NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
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
      varint_paramlen(NGTCP2_TRANSPORT_PARAM_MAX_UDP_PAYLOAD_SIZE,
                      params.max_udp_payload_size) +
      varint_paramlen(NGTCP2_TRANSPORT_PARAM_ACK_DELAY_EXPONENT,
                      params.ack_delay_exponent) +
      (ngtcp2_put_uvarintlen(NGTCP2_TRANSPORT_PARAM_DISABLE_ACTIVE_MIGRATION) +
       ngtcp2_put_uvarintlen(0)) +
      varint_paramlen(NGTCP2_TRANSPORT_PARAM_MAX_ACK_DELAY,
                      params.max_ack_delay / NGTCP2_MILLISECONDS) +
      varint_paramlen(NGTCP2_TRANSPORT_PARAM_ACTIVE_CONNECTION_ID_LIMIT,
                      params.active_connection_id_limit) +
      (ngtcp2_put_uvarintlen(NGTCP2_TRANSPORT_PARAM_STATELESS_RESET_TOKEN) +
       ngtcp2_put_uvarintlen(NGTCP2_STATELESS_RESET_TOKENLEN) +
       NGTCP2_STATELESS_RESET_TOKENLEN) +
      (ngtcp2_put_uvarintlen(NGTCP2_TRANSPORT_PARAM_PREFERRED_ADDRESS) +
       ngtcp2_put_uvarintlen(4 + 2 + 16 + 2 + 1 +
                             params.preferred_addr.cid.datalen +
                             NGTCP2_STATELESS_RESET_TOKENLEN) +
       4 + 2 + 16 + 2 + 1 + params.preferred_addr.cid.datalen +
       NGTCP2_STATELESS_RESET_TOKENLEN) +
      (ngtcp2_put_uvarintlen(
           NGTCP2_TRANSPORT_PARAM_RETRY_SOURCE_CONNECTION_ID) +
       ngtcp2_put_uvarintlen(params.retry_scid.datalen) +
       params.retry_scid.datalen) +
      (ngtcp2_put_uvarintlen(
           NGTCP2_TRANSPORT_PARAM_ORIGINAL_DESTINATION_CONNECTION_ID) +
       ngtcp2_put_uvarintlen(params.original_dcid.datalen) +
       params.original_dcid.datalen) +
      (ngtcp2_put_uvarintlen(
           NGTCP2_TRANSPORT_PARAM_INITIAL_SOURCE_CONNECTION_ID) +
       ngtcp2_put_uvarintlen(params.initial_scid.datalen) +
       params.initial_scid.datalen) +
      varint_paramlen(NGTCP2_TRANSPORT_PARAM_MAX_DATAGRAM_FRAME_SIZE,
                      params.max_datagram_frame_size) +
      (ngtcp2_put_uvarintlen(NGTCP2_TRANSPORT_PARAM_GREASE_QUIC_BIT) +
       ngtcp2_put_uvarintlen(0)) +
      (ngtcp2_put_uvarintlen(NGTCP2_TRANSPORT_PARAM_VERSION_INFORMATION) +
       ngtcp2_put_uvarintlen(sizeof(params.version_info.chosen_version) +
                             params.version_info.available_versionslen) +
       sizeof(params.version_info.chosen_version) +
       params.version_info.available_versionslen);

  nwrite = ngtcp2_transport_params_encode(NULL, 0, &params);

  CU_ASSERT((ngtcp2_ssize)len == nwrite);

  for (i = 0; i < len; ++i) {
    nwrite = ngtcp2_transport_params_encode(buf, i, &params);

    CU_ASSERT(NGTCP2_ERR_NOBUF == nwrite);
  }
  nwrite = ngtcp2_transport_params_encode(buf, i, &params);

  CU_ASSERT((ngtcp2_ssize)i == nwrite);

  rv = ngtcp2_transport_params_decode(&nparams, buf, (size_t)nwrite);

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
  CU_ASSERT(params.max_udp_payload_size == nparams.max_udp_payload_size);
  CU_ASSERT(0 == memcmp(params.stateless_reset_token,
                        nparams.stateless_reset_token,
                        sizeof(params.stateless_reset_token)));
  CU_ASSERT(params.ack_delay_exponent == nparams.ack_delay_exponent);
  CU_ASSERT(params.preferred_addr_present == nparams.preferred_addr_present);
  CU_ASSERT(0 == memcmp(&params.preferred_addr.ipv4,
                        &nparams.preferred_addr.ipv4,
                        sizeof(params.preferred_addr.ipv4)));
  CU_ASSERT(params.preferred_addr.ipv4_present ==
            nparams.preferred_addr.ipv4_present);
  CU_ASSERT(0 == memcmp(&params.preferred_addr.ipv6,
                        &nparams.preferred_addr.ipv6,
                        sizeof(params.preferred_addr.ipv6)));
  CU_ASSERT(params.preferred_addr.ipv6_present ==
            nparams.preferred_addr.ipv6_present);
  CU_ASSERT(
      ngtcp2_cid_eq(&params.preferred_addr.cid, &nparams.preferred_addr.cid));
  CU_ASSERT(0 == memcmp(params.preferred_addr.stateless_reset_token,
                        nparams.preferred_addr.stateless_reset_token,
                        sizeof(params.preferred_addr.stateless_reset_token)));
  CU_ASSERT(params.disable_active_migration ==
            nparams.disable_active_migration);
  CU_ASSERT(params.max_ack_delay == nparams.max_ack_delay);
  CU_ASSERT(params.retry_scid_present == nparams.retry_scid_present);
  CU_ASSERT(ngtcp2_cid_eq(&params.retry_scid, &nparams.retry_scid));
  CU_ASSERT(ngtcp2_cid_eq(&params.initial_scid, &nparams.initial_scid));
  CU_ASSERT(params.initial_scid_present == nparams.initial_scid_present);
  CU_ASSERT(ngtcp2_cid_eq(&params.original_dcid, &nparams.original_dcid));
  CU_ASSERT(params.original_dcid_present == nparams.original_dcid_present);
  CU_ASSERT(params.active_connection_id_limit ==
            nparams.active_connection_id_limit);
  CU_ASSERT(params.max_datagram_frame_size == nparams.max_datagram_frame_size);
  CU_ASSERT(params.grease_quic_bit == nparams.grease_quic_bit);
  CU_ASSERT(params.version_info_present == nparams.version_info_present);
  CU_ASSERT(params.version_info.chosen_version ==
            nparams.version_info.chosen_version);
  CU_ASSERT(0 == memcmp(params.version_info.available_versions,
                        nparams.version_info.available_versions,
                        params.version_info.available_versionslen));
}

void test_ngtcp2_transport_params_decode_new(void) {
  ngtcp2_transport_params params, *nparams;
  uint8_t buf[512];
  ngtcp2_ssize nwrite;
  int rv;
  size_t i, len;
  ngtcp2_cid rcid, scid, dcid;
  uint8_t available_versions[sizeof(uint32_t) * 3];
  ngtcp2_sockaddr_in *sa_in;

  rcid_init(&rcid);
  scid_init(&scid);
  dcid_init(&dcid);

  memset(&params, 0, sizeof(params));
  memset(&nparams, 0, sizeof(nparams));

  for (i = 0; i < sizeof(available_versions); i += sizeof(uint32_t)) {
    ngtcp2_put_uint32be(&available_versions[i], (uint32_t)(0xff000000u + i));
  }

  params.initial_max_stream_data_bidi_local = 1000000007;
  params.initial_max_stream_data_bidi_remote = 961748941;
  params.initial_max_stream_data_uni = 982451653;
  params.initial_max_data = 1000000009;
  params.initial_max_streams_bidi = 908;
  params.initial_max_streams_uni = 16383;
  params.max_idle_timeout = 16363 * NGTCP2_MILLISECONDS;
  params.max_udp_payload_size = 1200;
  params.stateless_reset_token_present = 1;
  memset(params.stateless_reset_token, 0xf1,
         sizeof(params.stateless_reset_token));
  params.ack_delay_exponent = 20;
  params.preferred_addr_present = 1;
  sa_in = &params.preferred_addr.ipv4;
  sa_in->sin_family = AF_INET;
  memset(&sa_in->sin_addr, 0xf1, sizeof(sa_in->sin_addr));
  sa_in->sin_port = ngtcp2_htons(11732);
  params.preferred_addr.ipv4_present = 1;
  params.preferred_addr.ipv6_present = 0;
  scid_init(&params.preferred_addr.cid);
  memset(params.preferred_addr.stateless_reset_token, 0xd1,
         sizeof(params.preferred_addr.stateless_reset_token));
  params.disable_active_migration = 1;
  params.max_ack_delay = 63 * NGTCP2_MILLISECONDS;
  params.retry_scid_present = 1;
  params.retry_scid = rcid;
  params.original_dcid = dcid;
  params.original_dcid_present = 1;
  params.initial_scid = scid;
  params.initial_scid_present = 1;
  params.active_connection_id_limit = 1073741824;
  params.max_datagram_frame_size = 63;
  params.grease_quic_bit = 1;
  params.version_info.chosen_version = NGTCP2_PROTO_VER_V1;
  params.version_info.available_versions = available_versions;
  params.version_info.available_versionslen =
      ngtcp2_arraylen(available_versions);
  params.version_info_present = 1;

  len =
      varint_paramlen(NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
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
      varint_paramlen(NGTCP2_TRANSPORT_PARAM_MAX_UDP_PAYLOAD_SIZE,
                      params.max_udp_payload_size) +
      varint_paramlen(NGTCP2_TRANSPORT_PARAM_ACK_DELAY_EXPONENT,
                      params.ack_delay_exponent) +
      (ngtcp2_put_uvarintlen(NGTCP2_TRANSPORT_PARAM_DISABLE_ACTIVE_MIGRATION) +
       ngtcp2_put_uvarintlen(0)) +
      varint_paramlen(NGTCP2_TRANSPORT_PARAM_MAX_ACK_DELAY,
                      params.max_ack_delay / NGTCP2_MILLISECONDS) +
      varint_paramlen(NGTCP2_TRANSPORT_PARAM_ACTIVE_CONNECTION_ID_LIMIT,
                      params.active_connection_id_limit) +
      (ngtcp2_put_uvarintlen(NGTCP2_TRANSPORT_PARAM_STATELESS_RESET_TOKEN) +
       ngtcp2_put_uvarintlen(NGTCP2_STATELESS_RESET_TOKENLEN) +
       NGTCP2_STATELESS_RESET_TOKENLEN) +
      (ngtcp2_put_uvarintlen(NGTCP2_TRANSPORT_PARAM_PREFERRED_ADDRESS) +
       ngtcp2_put_uvarintlen(4 + 2 + 16 + 2 + 1 +
                             params.preferred_addr.cid.datalen +
                             NGTCP2_STATELESS_RESET_TOKENLEN) +
       4 + 2 + 16 + 2 + 1 + params.preferred_addr.cid.datalen +
       NGTCP2_STATELESS_RESET_TOKENLEN) +
      (ngtcp2_put_uvarintlen(
           NGTCP2_TRANSPORT_PARAM_RETRY_SOURCE_CONNECTION_ID) +
       ngtcp2_put_uvarintlen(params.retry_scid.datalen) +
       params.retry_scid.datalen) +
      (ngtcp2_put_uvarintlen(
           NGTCP2_TRANSPORT_PARAM_ORIGINAL_DESTINATION_CONNECTION_ID) +
       ngtcp2_put_uvarintlen(params.original_dcid.datalen) +
       params.original_dcid.datalen) +
      (ngtcp2_put_uvarintlen(
           NGTCP2_TRANSPORT_PARAM_INITIAL_SOURCE_CONNECTION_ID) +
       ngtcp2_put_uvarintlen(params.initial_scid.datalen) +
       params.initial_scid.datalen) +
      varint_paramlen(NGTCP2_TRANSPORT_PARAM_MAX_DATAGRAM_FRAME_SIZE,
                      params.max_datagram_frame_size) +
      (ngtcp2_put_uvarintlen(NGTCP2_TRANSPORT_PARAM_GREASE_QUIC_BIT) +
       ngtcp2_put_uvarintlen(0)) +
      (ngtcp2_put_uvarintlen(NGTCP2_TRANSPORT_PARAM_VERSION_INFORMATION) +
       ngtcp2_put_uvarintlen(sizeof(params.version_info.chosen_version) +
                             params.version_info.available_versionslen) +
       sizeof(params.version_info.chosen_version) +
       params.version_info.available_versionslen);

  nwrite = ngtcp2_transport_params_encode(buf, sizeof(buf), &params);

  CU_ASSERT((ngtcp2_ssize)len == nwrite);

  rv = ngtcp2_transport_params_decode_new(&nparams, buf, (size_t)nwrite, NULL);

  CU_ASSERT(0 == rv);
  CU_ASSERT(params.initial_max_stream_data_bidi_local ==
            nparams->initial_max_stream_data_bidi_local);
  CU_ASSERT(params.initial_max_stream_data_bidi_remote ==
            nparams->initial_max_stream_data_bidi_remote);
  CU_ASSERT(params.initial_max_stream_data_uni ==
            nparams->initial_max_stream_data_uni);
  CU_ASSERT(params.initial_max_data == nparams->initial_max_data);
  CU_ASSERT(params.initial_max_streams_bidi ==
            nparams->initial_max_streams_bidi);
  CU_ASSERT(params.initial_max_streams_uni == nparams->initial_max_streams_uni);
  CU_ASSERT(params.max_idle_timeout == nparams->max_idle_timeout);
  CU_ASSERT(params.max_udp_payload_size == nparams->max_udp_payload_size);
  CU_ASSERT(0 == memcmp(params.stateless_reset_token,
                        nparams->stateless_reset_token,
                        sizeof(params.stateless_reset_token)));
  CU_ASSERT(params.ack_delay_exponent == nparams->ack_delay_exponent);
  CU_ASSERT(params.preferred_addr_present == nparams->preferred_addr_present);
  CU_ASSERT(0 == memcmp(&params.preferred_addr.ipv4,
                        &nparams->preferred_addr.ipv4,
                        sizeof(params.preferred_addr.ipv4)));
  CU_ASSERT(params.preferred_addr.ipv4_present ==
            nparams->preferred_addr.ipv4_present);
  CU_ASSERT(0 == memcmp(&params.preferred_addr.ipv6,
                        &nparams->preferred_addr.ipv6,
                        sizeof(params.preferred_addr.ipv6)));
  CU_ASSERT(params.preferred_addr.ipv6_present ==
            nparams->preferred_addr.ipv6_present);
  CU_ASSERT(
      ngtcp2_cid_eq(&params.preferred_addr.cid, &nparams->preferred_addr.cid));
  CU_ASSERT(0 == memcmp(params.preferred_addr.stateless_reset_token,
                        nparams->preferred_addr.stateless_reset_token,
                        sizeof(params.preferred_addr.stateless_reset_token)));
  CU_ASSERT(params.disable_active_migration ==
            nparams->disable_active_migration);
  CU_ASSERT(params.max_ack_delay == nparams->max_ack_delay);
  CU_ASSERT(params.retry_scid_present == nparams->retry_scid_present);
  CU_ASSERT(ngtcp2_cid_eq(&params.retry_scid, &nparams->retry_scid));
  CU_ASSERT(ngtcp2_cid_eq(&params.initial_scid, &nparams->initial_scid));
  CU_ASSERT(params.initial_scid_present == nparams->initial_scid_present);
  CU_ASSERT(ngtcp2_cid_eq(&params.original_dcid, &nparams->original_dcid));
  CU_ASSERT(params.original_dcid_present == nparams->original_dcid_present);
  CU_ASSERT(params.active_connection_id_limit ==
            nparams->active_connection_id_limit);
  CU_ASSERT(params.max_datagram_frame_size == nparams->max_datagram_frame_size);
  CU_ASSERT(params.grease_quic_bit == nparams->grease_quic_bit);
  CU_ASSERT(params.version_info_present == nparams->version_info_present);
  CU_ASSERT(params.version_info.chosen_version ==
            nparams->version_info.chosen_version);
  CU_ASSERT(0 == memcmp(params.version_info.available_versions,
                        nparams->version_info.available_versions,
                        params.version_info.available_versionslen));

  ngtcp2_transport_params_del(nparams, NULL);
}
