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
#include "ngtcp2_transport_params_test.h"

#include <stdio.h>

#include "ngtcp2_transport_params.h"
#include "ngtcp2_cid.h"
#include "ngtcp2_conv.h"
#include "ngtcp2_net.h"
#include "ngtcp2_test_helper.h"

static const MunitTest tests[] = {
    munit_void_test(test_ngtcp2_transport_params_encode),
    munit_void_test(test_ngtcp2_transport_params_decode_new),
    munit_void_test(test_ngtcp2_transport_params_convert_to_latest),
    munit_void_test(test_ngtcp2_transport_params_convert_to_old),
    munit_test_end(),
};

const MunitSuite transport_params_suite = {
    "/transport_params", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE,
};

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
  sa_in6->sin6_family = NGTCP2_AF_INET6;
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

  assert_ptrdiff((ngtcp2_ssize)len, ==, nwrite);

  for (i = 0; i < len; ++i) {
    nwrite = ngtcp2_transport_params_encode(buf, i, &params);

    assert_ptrdiff(NGTCP2_ERR_NOBUF, ==, nwrite);
  }
  nwrite = ngtcp2_transport_params_encode(buf, i, &params);

  assert_ptrdiff((ngtcp2_ssize)i, ==, nwrite);

  rv = ngtcp2_transport_params_decode(&nparams, buf, (size_t)nwrite);

  assert_int(0, ==, rv);
  assert_uint64(params.initial_max_stream_data_bidi_local, ==,
                nparams.initial_max_stream_data_bidi_local);
  assert_uint64(params.initial_max_stream_data_bidi_remote, ==,
                nparams.initial_max_stream_data_bidi_remote);
  assert_uint64(params.initial_max_stream_data_uni, ==,
                nparams.initial_max_stream_data_uni);
  assert_uint64(params.initial_max_data, ==, nparams.initial_max_data);
  assert_uint64(params.initial_max_streams_bidi, ==,
                nparams.initial_max_streams_bidi);
  assert_uint64(params.initial_max_streams_uni, ==,
                nparams.initial_max_streams_uni);
  assert_uint64(params.max_idle_timeout, ==, nparams.max_idle_timeout);
  assert_uint64(params.max_udp_payload_size, ==, nparams.max_udp_payload_size);
  assert_memory_equal(sizeof(params.stateless_reset_token),
                      params.stateless_reset_token,
                      nparams.stateless_reset_token);
  assert_uint64(params.ack_delay_exponent, ==, nparams.ack_delay_exponent);
  assert_uint8(params.preferred_addr_present, ==,
               nparams.preferred_addr_present);
  assert_memory_equal(sizeof(params.preferred_addr.ipv4),
                      &params.preferred_addr.ipv4,
                      &nparams.preferred_addr.ipv4);
  assert_uint8(params.preferred_addr.ipv4_present, ==,
               nparams.preferred_addr.ipv4_present);
  assert_memory_equal(sizeof(params.preferred_addr.ipv6),
                      &params.preferred_addr.ipv6,
                      &nparams.preferred_addr.ipv6);
  assert_uint8(params.preferred_addr.ipv6_present, ==,
               nparams.preferred_addr.ipv6_present);
  assert_true(
      ngtcp2_cid_eq(&params.preferred_addr.cid, &nparams.preferred_addr.cid));
  assert_memory_equal(sizeof(params.preferred_addr.stateless_reset_token),
                      params.preferred_addr.stateless_reset_token,
                      nparams.preferred_addr.stateless_reset_token);
  assert_uint8(params.disable_active_migration, ==,
               nparams.disable_active_migration);
  assert_uint64(params.max_ack_delay, ==, nparams.max_ack_delay);
  assert_uint8(params.retry_scid_present, ==, nparams.retry_scid_present);
  assert_true(ngtcp2_cid_eq(&params.retry_scid, &nparams.retry_scid));
  assert_true(ngtcp2_cid_eq(&params.initial_scid, &nparams.initial_scid));
  assert_uint8(params.initial_scid_present, ==, nparams.initial_scid_present);
  assert_true(ngtcp2_cid_eq(&params.original_dcid, &nparams.original_dcid));
  assert_uint8(params.original_dcid_present, ==, nparams.original_dcid_present);
  assert_uint64(params.active_connection_id_limit, ==,
                nparams.active_connection_id_limit);
  assert_uint64(params.max_datagram_frame_size, ==,
                nparams.max_datagram_frame_size);
  assert_uint8(params.grease_quic_bit, ==, nparams.grease_quic_bit);
  assert_uint8(params.version_info_present, ==, nparams.version_info_present);
  assert_uint32(params.version_info.chosen_version, ==,
                nparams.version_info.chosen_version);
  assert_memory_equal(params.version_info.available_versionslen,
                      params.version_info.available_versions,
                      nparams.version_info.available_versions);
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
  sa_in->sin_family = NGTCP2_AF_INET;
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

  assert_ptrdiff((ngtcp2_ssize)len, ==, nwrite);

  rv = ngtcp2_transport_params_decode_new(&nparams, buf, (size_t)nwrite, NULL);

  assert_int(0, ==, rv);
  assert_uint64(params.initial_max_stream_data_bidi_local, ==,
                nparams->initial_max_stream_data_bidi_local);
  assert_uint64(params.initial_max_stream_data_bidi_remote, ==,
                nparams->initial_max_stream_data_bidi_remote);
  assert_uint64(params.initial_max_stream_data_uni, ==,
                nparams->initial_max_stream_data_uni);
  assert_uint64(params.initial_max_data, ==, nparams->initial_max_data);
  assert_uint64(params.initial_max_streams_bidi, ==,
                nparams->initial_max_streams_bidi);
  assert_uint64(params.initial_max_streams_uni, ==,
                nparams->initial_max_streams_uni);
  assert_uint64(params.max_idle_timeout, ==, nparams->max_idle_timeout);
  assert_uint64(params.max_udp_payload_size, ==, nparams->max_udp_payload_size);
  assert_memory_equal(sizeof(params.stateless_reset_token),
                      params.stateless_reset_token,
                      nparams->stateless_reset_token);
  assert_uint64(params.ack_delay_exponent, ==, nparams->ack_delay_exponent);
  assert_uint8(params.preferred_addr_present, ==,
               nparams->preferred_addr_present);
  assert_memory_equal(sizeof(params.preferred_addr.ipv4),
                      &params.preferred_addr.ipv4,
                      &nparams->preferred_addr.ipv4);
  assert_uint8(params.preferred_addr.ipv4_present, ==,
               nparams->preferred_addr.ipv4_present);
  assert_memory_equal(sizeof(params.preferred_addr.ipv6),
                      &params.preferred_addr.ipv6,
                      &nparams->preferred_addr.ipv6);
  assert_uint8(params.preferred_addr.ipv6_present, ==,
               nparams->preferred_addr.ipv6_present);
  assert_true(
      ngtcp2_cid_eq(&params.preferred_addr.cid, &nparams->preferred_addr.cid));
  assert_memory_equal(sizeof(params.preferred_addr.stateless_reset_token),
                      params.preferred_addr.stateless_reset_token,
                      nparams->preferred_addr.stateless_reset_token);
  assert_uint8(params.disable_active_migration, ==,
               nparams->disable_active_migration);
  assert_uint64(params.max_ack_delay, ==, nparams->max_ack_delay);
  assert_uint8(params.retry_scid_present, ==, nparams->retry_scid_present);
  assert_true(ngtcp2_cid_eq(&params.retry_scid, &nparams->retry_scid));
  assert_true(ngtcp2_cid_eq(&params.initial_scid, &nparams->initial_scid));
  assert_uint8(params.initial_scid_present, ==, nparams->initial_scid_present);
  assert_true(ngtcp2_cid_eq(&params.original_dcid, &nparams->original_dcid));
  assert_uint8(params.original_dcid_present, ==,
               nparams->original_dcid_present);
  assert_uint64(params.active_connection_id_limit, ==,
                nparams->active_connection_id_limit);
  assert_uint64(params.max_datagram_frame_size, ==,
                nparams->max_datagram_frame_size);
  assert_uint8(params.grease_quic_bit, ==, nparams->grease_quic_bit);
  assert_uint8(params.version_info_present, ==, nparams->version_info_present);
  assert_uint32(params.version_info.chosen_version, ==,
                nparams->version_info.chosen_version);
  assert_memory_equal(params.version_info.available_versionslen,
                      params.version_info.available_versions,
                      nparams->version_info.available_versions);

  ngtcp2_transport_params_del(nparams, NULL);
}

void test_ngtcp2_transport_params_convert_to_latest(void) {
  ngtcp2_transport_params *src, srcbuf, paramsbuf;
  const ngtcp2_transport_params *dest;
  size_t v1len;
  ngtcp2_cid rcid, scid, dcid;
  uint8_t available_versions[sizeof(uint32_t) * 3];
  ngtcp2_sockaddr_in6 *sa_in6;

  rcid_init(&rcid);
  scid_init(&scid);
  dcid_init(&dcid);

  ngtcp2_transport_params_default_versioned(NGTCP2_TRANSPORT_PARAMS_V1,
                                            &srcbuf);

  srcbuf.initial_max_stream_data_bidi_local = 1000000007;
  srcbuf.initial_max_stream_data_bidi_remote = 961748941;
  srcbuf.initial_max_stream_data_uni = 982451653;
  srcbuf.initial_max_data = 1000000009;
  srcbuf.initial_max_streams_bidi = 908;
  srcbuf.initial_max_streams_uni = 16383;
  srcbuf.max_idle_timeout = 16363 * NGTCP2_MILLISECONDS;
  srcbuf.max_udp_payload_size = 1200;
  srcbuf.stateless_reset_token_present = 1;
  memset(srcbuf.stateless_reset_token, 0xf1,
         sizeof(srcbuf.stateless_reset_token));
  srcbuf.ack_delay_exponent = 20;
  srcbuf.preferred_addr_present = 1;
  srcbuf.preferred_addr.ipv4_present = 0;
  sa_in6 = &srcbuf.preferred_addr.ipv6;
  sa_in6->sin6_family = NGTCP2_AF_INET6;
  memset(&sa_in6->sin6_addr, 0xe1, sizeof(sa_in6->sin6_addr));
  sa_in6->sin6_port = ngtcp2_htons(63111);
  srcbuf.preferred_addr.ipv6_present = 1;
  scid_init(&srcbuf.preferred_addr.cid);
  memset(srcbuf.preferred_addr.stateless_reset_token, 0xd1,
         sizeof(srcbuf.preferred_addr.stateless_reset_token));
  srcbuf.disable_active_migration = 1;
  srcbuf.max_ack_delay = 63 * NGTCP2_MILLISECONDS;
  srcbuf.retry_scid_present = 1;
  srcbuf.retry_scid = rcid;
  srcbuf.original_dcid = dcid;
  srcbuf.initial_scid = scid;
  srcbuf.active_connection_id_limit = 1073741824;
  srcbuf.max_datagram_frame_size = 63;
  srcbuf.grease_quic_bit = 1;
  srcbuf.version_info.chosen_version = NGTCP2_PROTO_VER_V1;
  srcbuf.version_info.available_versions = available_versions;
  srcbuf.version_info.available_versionslen =
      ngtcp2_arraylen(available_versions);
  srcbuf.version_info_present = 1;

  v1len = sizeof(srcbuf);

  src = malloc(v1len);

  memcpy(src, &srcbuf, v1len);

  dest = ngtcp2_transport_params_convert_to_latest(
      &paramsbuf, NGTCP2_TRANSPORT_PARAMS_V1, src);

  assert_ptr_equal(dest, src);
  assert_uint64(srcbuf.initial_max_stream_data_bidi_local, ==,
                dest->initial_max_stream_data_bidi_local);
  assert_uint64(srcbuf.initial_max_stream_data_bidi_remote, ==,
                dest->initial_max_stream_data_bidi_remote);
  assert_uint64(srcbuf.initial_max_stream_data_uni, ==,
                dest->initial_max_stream_data_uni);
  assert_uint64(srcbuf.initial_max_data, ==, dest->initial_max_data);
  assert_uint64(srcbuf.initial_max_streams_bidi, ==,
                dest->initial_max_streams_bidi);
  assert_uint64(srcbuf.initial_max_streams_uni, ==,
                dest->initial_max_streams_uni);
  assert_uint64(srcbuf.max_idle_timeout, ==, dest->max_idle_timeout);
  assert_uint64(srcbuf.max_udp_payload_size, ==, dest->max_udp_payload_size);
  assert_memory_equal(sizeof(srcbuf.stateless_reset_token),
                      srcbuf.stateless_reset_token,
                      dest->stateless_reset_token);
  assert_uint64(srcbuf.ack_delay_exponent, ==, dest->ack_delay_exponent);
  assert_uint8(srcbuf.preferred_addr_present, ==, dest->preferred_addr_present);
  assert_memory_equal(sizeof(srcbuf.preferred_addr.ipv4),
                      &srcbuf.preferred_addr.ipv4, &dest->preferred_addr.ipv4);
  assert_uint8(srcbuf.preferred_addr.ipv4_present, ==,
               dest->preferred_addr.ipv4_present);
  assert_memory_equal(sizeof(srcbuf.preferred_addr.ipv6),
                      &srcbuf.preferred_addr.ipv6, &dest->preferred_addr.ipv6);
  assert_uint8(srcbuf.preferred_addr.ipv6_present, ==,
               dest->preferred_addr.ipv6_present);
  assert_true(
      ngtcp2_cid_eq(&srcbuf.preferred_addr.cid, &dest->preferred_addr.cid));
  assert_memory_equal(sizeof(srcbuf.preferred_addr.stateless_reset_token),
                      srcbuf.preferred_addr.stateless_reset_token,
                      dest->preferred_addr.stateless_reset_token);
  assert_uint8(srcbuf.disable_active_migration, ==,
               dest->disable_active_migration);
  assert_uint64(srcbuf.max_ack_delay, ==, dest->max_ack_delay);
  assert_uint8(srcbuf.retry_scid_present, ==, dest->retry_scid_present);
  assert_true(ngtcp2_cid_eq(&srcbuf.retry_scid, &dest->retry_scid));
  assert_true(ngtcp2_cid_eq(&srcbuf.initial_scid, &dest->initial_scid));
  assert_true(ngtcp2_cid_eq(&srcbuf.original_dcid, &dest->original_dcid));
  assert_uint64(srcbuf.active_connection_id_limit, ==,
                dest->active_connection_id_limit);
  assert_uint64(srcbuf.max_datagram_frame_size, ==,
                dest->max_datagram_frame_size);
  assert_uint8(srcbuf.grease_quic_bit, ==, dest->grease_quic_bit);
  assert_uint8(srcbuf.version_info_present, ==, dest->version_info_present);
  assert_uint32(srcbuf.version_info.chosen_version, ==,
                dest->version_info.chosen_version);
  assert_memory_equal(srcbuf.version_info.available_versionslen,
                      srcbuf.version_info.available_versions,
                      dest->version_info.available_versions);

  free(src);
}

void test_ngtcp2_transport_params_convert_to_old(void) {}
