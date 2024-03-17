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
#include "ngtcp2_conn_test.h"

#include <stdio.h>
#include <assert.h>

#include "ngtcp2_conn.h"
#include "ngtcp2_test_helper.h"
#include "ngtcp2_mem.h"
#include "ngtcp2_pkt.h"
#include "ngtcp2_cid.h"
#include "ngtcp2_conv.h"
#include "ngtcp2_vec.h"
#include "ngtcp2_rcvry.h"
#include "ngtcp2_addr.h"
#include "ngtcp2_net.h"
#include "ngtcp2_tstamp.h"
#include "ngtcp2_transport_params.h"
#include "ngtcp2_frame_chain.h"

static const MunitTest tests[] = {
    munit_void_test(test_ngtcp2_conn_stream_open_close),
    munit_void_test(test_ngtcp2_conn_stream_rx_flow_control),
    munit_void_test(test_ngtcp2_conn_stream_rx_flow_control_error),
    munit_void_test(test_ngtcp2_conn_stream_tx_flow_control),
    munit_void_test(test_ngtcp2_conn_rx_flow_control),
    munit_void_test(test_ngtcp2_conn_rx_flow_control_error),
    munit_void_test(test_ngtcp2_conn_tx_flow_control),
    munit_void_test(test_ngtcp2_conn_shutdown_stream_write),
    munit_void_test(test_ngtcp2_conn_shutdown_stream_read),
    munit_void_test(test_ngtcp2_conn_recv_reset_stream),
    munit_void_test(test_ngtcp2_conn_recv_stop_sending),
    munit_void_test(test_ngtcp2_conn_recv_stream_data_blocked),
    munit_void_test(test_ngtcp2_conn_recv_data_blocked),
    munit_void_test(test_ngtcp2_conn_recv_conn_id_omitted),
    munit_void_test(test_ngtcp2_conn_short_pkt_type),
    munit_void_test(test_ngtcp2_conn_recv_stateless_reset),
    munit_void_test(test_ngtcp2_conn_recv_retry),
    munit_void_test(test_ngtcp2_conn_recv_delayed_handshake_pkt),
    munit_void_test(test_ngtcp2_conn_recv_max_streams),
    munit_void_test(test_ngtcp2_conn_handshake),
    munit_void_test(test_ngtcp2_conn_handshake_error),
    munit_void_test(test_ngtcp2_conn_retransmit_protected),
    munit_void_test(test_ngtcp2_conn_send_max_stream_data),
    munit_void_test(test_ngtcp2_conn_recv_stream_data),
    munit_void_test(test_ngtcp2_conn_recv_ping),
    munit_void_test(test_ngtcp2_conn_recv_max_stream_data),
    munit_void_test(test_ngtcp2_conn_send_early_data),
    munit_void_test(test_ngtcp2_conn_recv_early_data),
    munit_void_test(test_ngtcp2_conn_recv_compound_pkt),
    munit_void_test(test_ngtcp2_conn_pkt_payloadlen),
    munit_void_test(test_ngtcp2_conn_writev_stream),
    munit_void_test(test_ngtcp2_conn_writev_datagram),
    munit_void_test(test_ngtcp2_conn_recv_datagram),
    munit_void_test(test_ngtcp2_conn_recv_new_connection_id),
    munit_void_test(test_ngtcp2_conn_recv_retire_connection_id),
    munit_void_test(test_ngtcp2_conn_server_path_validation),
    munit_void_test(test_ngtcp2_conn_client_connection_migration),
    munit_void_test(test_ngtcp2_conn_recv_path_challenge),
    munit_void_test(test_ngtcp2_conn_key_update),
    munit_void_test(test_ngtcp2_conn_crypto_buffer_exceeded),
    munit_void_test(test_ngtcp2_conn_handshake_probe),
    munit_void_test(test_ngtcp2_conn_handshake_loss),
    munit_void_test(test_ngtcp2_conn_probe),
    munit_void_test(test_ngtcp2_conn_recv_client_initial_retry),
    munit_void_test(test_ngtcp2_conn_recv_client_initial_token),
    munit_void_test(test_ngtcp2_conn_get_active_dcid),
    munit_void_test(test_ngtcp2_conn_recv_version_negotiation),
    munit_void_test(test_ngtcp2_conn_send_initial_token),
    munit_void_test(test_ngtcp2_conn_set_remote_transport_params),
    munit_void_test(test_ngtcp2_conn_write_connection_close),
    munit_void_test(test_ngtcp2_conn_write_application_close),
    munit_void_test(test_ngtcp2_conn_rtb_reclaim_on_pto),
    munit_void_test(test_ngtcp2_conn_rtb_reclaim_on_pto_datagram),
    munit_void_test(test_ngtcp2_conn_validate_ecn),
    munit_void_test(test_ngtcp2_conn_path_validation),
    munit_void_test(test_ngtcp2_conn_early_data_sync_stream_data_limit),
    munit_void_test(test_ngtcp2_conn_tls_early_data_rejected),
    munit_void_test(test_ngtcp2_conn_keep_alive),
    munit_void_test(test_ngtcp2_conn_retire_stale_bound_dcid),
    munit_void_test(test_ngtcp2_conn_get_scid),
    munit_void_test(test_ngtcp2_conn_stream_close),
    munit_void_test(test_ngtcp2_conn_buffer_pkt),
    munit_void_test(test_ngtcp2_conn_handshake_timeout),
    munit_void_test(test_ngtcp2_conn_get_ccerr),
    munit_void_test(test_ngtcp2_conn_version_negotiation),
    munit_void_test(test_ngtcp2_conn_server_negotiate_version),
    munit_void_test(test_ngtcp2_conn_pmtud_loss),
    munit_void_test(test_ngtcp2_conn_amplification),
    munit_void_test(test_ngtcp2_conn_encode_0rtt_transport_params),
    munit_void_test(test_ngtcp2_conn_create_ack_frame),
    munit_void_test(test_ngtcp2_conn_grease_quic_bit),
    munit_void_test(test_ngtcp2_conn_send_stream_data_blocked),
    munit_void_test(test_ngtcp2_conn_send_data_blocked),
    munit_void_test(test_ngtcp2_conn_send_new_connection_id),
    munit_void_test(test_ngtcp2_conn_persistent_congestion),
    munit_void_test(test_ngtcp2_conn_new_failmalloc),
    munit_void_test(test_ngtcp2_accept),
    munit_void_test(test_ngtcp2_select_version),
    munit_void_test(test_ngtcp2_pkt_write_connection_close),
    munit_void_test(test_ngtcp2_ccerr_set_liberr),
    munit_test_end(),
};

const MunitSuite conn_suite = {
    "/conn", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE,
};

static void qlog_write(void *user_data, uint32_t flags, const void *data,
                       size_t datalen) {
  (void)user_data;
  (void)flags;
  (void)data;
  (void)datalen;
}

static int null_encrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                        const ngtcp2_crypto_aead_ctx *aead_ctx,
                        const uint8_t *plaintext, size_t plaintextlen,
                        const uint8_t *nonce, size_t noncelen,
                        const uint8_t *aad, size_t aadlen) {
  (void)dest;
  (void)aead;
  (void)aead_ctx;
  (void)plaintext;
  (void)plaintextlen;
  (void)nonce;
  (void)noncelen;
  (void)aad;
  (void)aadlen;

  if (plaintextlen && plaintext != dest) {
    memcpy(dest, plaintext, plaintextlen);
  }
  memset(dest + plaintextlen, 0, NGTCP2_FAKE_AEAD_OVERHEAD);

  return 0;
}

static int null_decrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                        const ngtcp2_crypto_aead_ctx *aead_ctx,
                        const uint8_t *ciphertext, size_t ciphertextlen,
                        const uint8_t *nonce, size_t noncelen,
                        const uint8_t *aad, size_t aadlen) {
  (void)dest;
  (void)aead;
  (void)aead_ctx;
  (void)ciphertext;
  (void)nonce;
  (void)noncelen;
  (void)aad;
  (void)aadlen;
  assert(ciphertextlen >= NGTCP2_FAKE_AEAD_OVERHEAD);
  memmove(dest, ciphertext, ciphertextlen - NGTCP2_FAKE_AEAD_OVERHEAD);
  return 0;
}

static int fail_decrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                        const ngtcp2_crypto_aead_ctx *aead_ctx,
                        const uint8_t *ciphertext, size_t ciphertextlen,
                        const uint8_t *nonce, size_t noncelen,
                        const uint8_t *aad, size_t aadlen) {
  (void)dest;
  (void)aead;
  (void)aead_ctx;
  (void)ciphertext;
  (void)ciphertextlen;
  (void)nonce;
  (void)noncelen;
  (void)aad;
  (void)aadlen;
  return NGTCP2_ERR_DECRYPT;
}

static int null_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                        const ngtcp2_crypto_cipher_ctx *hp_ctx,
                        const uint8_t *sample) {
  (void)hp;
  (void)hp_ctx;
  (void)sample;
  memcpy(dest, NGTCP2_FAKE_HP_MASK, sizeof(NGTCP2_FAKE_HP_MASK) - 1);
  return 0;
}

static int get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                 uint8_t *token, size_t cidlen,
                                 void *user_data) {
  (void)user_data;
  memset(cid->data, 0, cidlen);
  cid->data[0] = (uint8_t)(conn->scid.last_seq + 1);
  cid->datalen = cidlen;
  memset(token, 0, NGTCP2_STATELESS_RESET_TOKENLEN);
  return 0;
}

static uint8_t null_secret[32];
static uint8_t null_iv[16];
static uint8_t null_data[4096];

static ngtcp2_crypto_km null_ckm = {
    {NULL, 0}, {0}, {null_iv, sizeof(null_iv)},
    -1,        0,   NGTCP2_CRYPTO_KM_FLAG_NONE,
};

static ngtcp2_path_storage null_path;
static ngtcp2_path_storage new_path;
static ngtcp2_path_storage new_nat_path;

static ngtcp2_pkt_info null_pi;

void init_static_path(void) {
  path_init(&null_path, 0, 0, 0, 0);
  path_init(&new_path, 1, 0, 2, 0);
  path_init(&new_nat_path, 0, 0, 0, 1);
}

static ngtcp2_vec *null_datav(ngtcp2_vec *datav, size_t len) {
  datav->base = null_data;
  datav->len = len;
  return datav;
}

static void init_crypto_ctx(ngtcp2_crypto_ctx *ctx) {
  memset(ctx, 0, sizeof(*ctx));
  ctx->aead.max_overhead = NGTCP2_FAKE_AEAD_OVERHEAD;
  ctx->max_encryption = 9999;
  ctx->max_decryption_failure = 8888;
}

static void init_initial_crypto_ctx(ngtcp2_crypto_ctx *ctx) {
  memset(ctx, 0, sizeof(*ctx));
  ctx->aead.max_overhead = NGTCP2_INITIAL_AEAD_OVERHEAD;
  ctx->max_encryption = 9999;
  ctx->max_decryption_failure = 8888;
}

typedef struct {
  uint64_t pkt_num;
  /* stream_data is intended to store the arguments passed in
     recv_stream_data callback. */
  struct {
    int64_t stream_id;
    uint32_t flags;
    size_t datalen;
  } stream_data;
  struct {
    uint32_t flags;
    const uint8_t *data;
    size_t datalen;
    uint64_t dgram_id;
  } datagram;
  struct {
    uint32_t flags;
    int64_t stream_id;
    uint64_t app_error_code;
  } stream_close;
} my_user_data;

static int client_initial(ngtcp2_conn *conn, void *user_data) {
  (void)user_data;

  ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL,
                                 null_data, 217);

  return 0;
}

static int client_initial_early_data(ngtcp2_conn *conn, void *user_data) {
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  ngtcp2_crypto_ctx crypto_ctx;

  (void)user_data;

  ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL,
                                 null_data, 217);

  init_crypto_ctx(&crypto_ctx);

  ngtcp2_conn_set_0rtt_crypto_ctx(conn, &crypto_ctx);
  ngtcp2_conn_install_0rtt_key(conn, &aead_ctx, null_iv, sizeof(null_iv),
                               &hp_ctx);

  return 0;
}

static int client_initial_large_crypto_early_data(ngtcp2_conn *conn,
                                                  void *user_data) {
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  ngtcp2_crypto_ctx crypto_ctx;

  (void)user_data;

  /* Initial CRYPTO data which is larger than a typical single
     datagram. */
  ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL,
                                 null_data, 1500);

  init_crypto_ctx(&crypto_ctx);

  ngtcp2_conn_set_0rtt_crypto_ctx(conn, &crypto_ctx);
  ngtcp2_conn_install_0rtt_key(conn, &aead_ctx, null_iv, sizeof(null_iv),
                               &hp_ctx);

  return 0;
}

static int recv_client_initial_no_remote_transport_params(
    ngtcp2_conn *conn, const ngtcp2_cid *dcid, void *user_data) {
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  ngtcp2_crypto_ctx ctx;

  (void)dcid;
  (void)user_data;

  init_initial_crypto_ctx(&ctx);

  ngtcp2_conn_set_initial_crypto_ctx(conn, &ctx);
  ngtcp2_conn_install_initial_key(conn, &aead_ctx, null_iv, &hp_ctx, &aead_ctx,
                                  null_iv, &hp_ctx, sizeof(null_iv));

  init_crypto_ctx(&ctx);

  ngtcp2_conn_set_crypto_ctx(conn, &ctx);
  conn->negotiated_version = conn->client_chosen_version;
  ngtcp2_conn_install_rx_handshake_key(conn, &aead_ctx, null_iv,
                                       sizeof(null_iv), &hp_ctx);
  ngtcp2_conn_install_tx_handshake_key(conn, &aead_ctx, null_iv,
                                       sizeof(null_iv), &hp_ctx);

  return 0;
}

static int recv_client_initial(ngtcp2_conn *conn, const ngtcp2_cid *dcid,
                               void *user_data) {
  ngtcp2_transport_params params;
  int rv;

  recv_client_initial_no_remote_transport_params(conn, dcid, user_data);

  ngtcp2_transport_params_default(&params);
  params.initial_scid = conn->dcid.current.cid;
  params.initial_scid_present = 1;

  rv = ngtcp2_conn_set_remote_transport_params(conn, &params);

  assert_int(0, ==, rv);

  return 0;
}

static int recv_client_initial_early(ngtcp2_conn *conn, const ngtcp2_cid *dcid,
                                     void *user_data) {
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  ngtcp2_crypto_ctx ctx;

  recv_client_initial(conn, dcid, user_data);

  init_crypto_ctx(&ctx);

  ngtcp2_conn_set_0rtt_crypto_ctx(conn, &ctx);
  ngtcp2_conn_install_0rtt_key(conn, &aead_ctx, null_iv, sizeof(null_iv),
                               &hp_ctx);

  return 0;
}

static int recv_crypto_data(ngtcp2_conn *conn,
                            ngtcp2_encryption_level encryption_level,
                            uint64_t offset, const uint8_t *data,
                            size_t datalen, void *user_data) {
  (void)conn;
  (void)encryption_level;
  (void)offset;
  (void)data;
  (void)datalen;
  (void)user_data;
  return 0;
}

static int recv_crypto_data_server_early_data(
    ngtcp2_conn *conn, ngtcp2_encryption_level encryption_level,
    uint64_t offset, const uint8_t *data, size_t datalen, void *user_data) {
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};

  (void)offset;
  (void)encryption_level;
  (void)data;
  (void)datalen;
  (void)user_data;

  assert(conn->server);

  ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL,
                                 null_data, 179);

  ngtcp2_conn_install_tx_key(conn, null_secret, sizeof(null_secret), &aead_ctx,
                             null_iv, sizeof(null_iv), &hp_ctx);

  conn->callbacks.recv_crypto_data = recv_crypto_data;

  return 0;
}

static int recv_crypto_data_client_handshake(
    ngtcp2_conn *conn, ngtcp2_encryption_level encryption_level,
    uint64_t offset, const uint8_t *data, size_t datalen, void *user_data) {
  int rv;
  ngtcp2_transport_params params;
  const ngtcp2_early_transport_params *early_params;
  ngtcp2_crypto_ctx crypto_ctx;
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  (void)offset;
  (void)data;
  (void)datalen;
  (void)user_data;

  switch (encryption_level) {
  case NGTCP2_ENCRYPTION_LEVEL_INITIAL:
    init_crypto_ctx(&crypto_ctx);
    ngtcp2_conn_set_crypto_ctx(conn, &crypto_ctx);

    ngtcp2_conn_install_rx_handshake_key(conn, &aead_ctx, null_iv,
                                         sizeof(null_iv), &hp_ctx);
    ngtcp2_conn_install_tx_handshake_key(conn, &aead_ctx, null_iv,
                                         sizeof(null_iv), &hp_ctx);

    return 0;
  case NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE:
    if (conn->flags & NGTCP2_CONN_FLAG_TLS_HANDSHAKE_COMPLETED) {
      return 0;
    }

    early_params = &conn->early.transport_params;

    memset(&params, 0, sizeof(params));
    ngtcp2_cid_init(&params.initial_scid, conn->dcid.current.cid.data,
                    conn->dcid.current.cid.datalen);
    params.initial_scid_present = 1;
    ngtcp2_cid_init(&params.original_dcid, conn->rcid.data, conn->rcid.datalen);
    params.original_dcid_present = 1;
    params.max_udp_payload_size = 1200;
    params.initial_max_stream_data_bidi_local =
        early_params->initial_max_stream_data_bidi_local;
    params.initial_max_stream_data_bidi_remote = ngtcp2_max(
        100 * 1024, early_params->initial_max_stream_data_bidi_remote);
    params.initial_max_stream_data_uni =
        early_params->initial_max_stream_data_uni;
    params.initial_max_streams_bidi =
        ngtcp2_max(1, early_params->initial_max_streams_bidi);
    params.initial_max_streams_uni =
        ngtcp2_max(1, early_params->initial_max_streams_uni);
    params.initial_max_data =
        ngtcp2_max(100 * 1024, early_params->initial_max_data);
    params.active_connection_id_limit =
        ngtcp2_max(2, early_params->active_connection_id_limit);
    params.max_datagram_frame_size = early_params->max_datagram_frame_size;

    rv = ngtcp2_conn_set_remote_transport_params(conn, &params);

    assert_int(0, ==, rv);

    ngtcp2_conn_install_rx_key(conn, null_secret, sizeof(null_secret),
                               &aead_ctx, null_iv, sizeof(null_iv), &hp_ctx);
    ngtcp2_conn_install_tx_key(conn, null_secret, sizeof(null_secret),
                               &aead_ctx, null_iv, sizeof(null_iv), &hp_ctx);

    rv = ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,
                                        null_data, 57);

    assert_int(0, ==, rv);

    ngtcp2_conn_tls_handshake_completed(conn);

    return 0;
  default:
    return 0;
  }
}

static int update_key(ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
                      ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
                      ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
                      const uint8_t *current_rx_secret,
                      const uint8_t *current_tx_secret, size_t secretlen,
                      void *user_data) {
  (void)conn;
  (void)current_rx_secret;
  (void)current_tx_secret;
  (void)user_data;
  (void)secretlen;

  assert(sizeof(null_secret) == secretlen);

  memset(rx_secret, 0xff, sizeof(null_secret));
  memset(tx_secret, 0xff, sizeof(null_secret));
  rx_aead_ctx->native_handle = NULL;
  memset(rx_iv, 0xff, sizeof(null_iv));
  tx_aead_ctx->native_handle = NULL;
  memset(tx_iv, 0xff, sizeof(null_iv));

  return 0;
}

static int recv_crypto_handshake_error(ngtcp2_conn *conn,
                                       ngtcp2_encryption_level encryption_level,
                                       uint64_t offset, const uint8_t *data,
                                       size_t datalen, void *user_data) {
  (void)conn;
  (void)encryption_level;
  (void)offset;
  (void)data;
  (void)datalen;
  (void)user_data;
  return NGTCP2_ERR_CRYPTO;
}

static int recv_crypto_fatal_alert_generated(
    ngtcp2_conn *conn, ngtcp2_encryption_level encryption_level,
    uint64_t offset, const uint8_t *data, size_t datalen, void *user_data) {
  (void)conn;
  (void)encryption_level;
  (void)offset;
  (void)data;
  (void)datalen;
  (void)user_data;
  return NGTCP2_ERR_CRYPTO;
}

static int recv_crypto_data_server(ngtcp2_conn *conn,
                                   ngtcp2_encryption_level encryption_level,
                                   uint64_t offset, const uint8_t *data,
                                   size_t datalen, void *user_data) {
  (void)offset;
  (void)data;
  (void)datalen;
  (void)user_data;

  ngtcp2_conn_submit_crypto_data(conn,
                                 encryption_level ==
                                         NGTCP2_ENCRYPTION_LEVEL_INITIAL
                                     ? NGTCP2_ENCRYPTION_LEVEL_INITIAL
                                     : NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,
                                 null_data, 218);

  return 0;
}

static int recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                            int64_t stream_id, uint64_t offset,
                            const uint8_t *data, size_t datalen,
                            void *user_data, void *stream_user_data) {
  my_user_data *ud = user_data;
  (void)conn;
  (void)offset;
  (void)data;
  (void)stream_user_data;

  if (ud) {
    ud->stream_data.stream_id = stream_id;
    ud->stream_data.flags = flags;
    ud->stream_data.datalen = datalen;
  }

  return 0;
}

static int
recv_stream_data_shutdown_stream_read(ngtcp2_conn *conn, uint32_t flags,
                                      int64_t stream_id, uint64_t offset,
                                      const uint8_t *data, size_t datalen,
                                      void *user_data, void *stream_user_data) {
  int rv;

  recv_stream_data(conn, flags, stream_id, offset, data, datalen, user_data,
                   stream_user_data);

  rv = ngtcp2_conn_shutdown_stream_read(conn, 0, stream_id, NGTCP2_APP_ERR01);
  if (rv != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int stream_close(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                        uint64_t app_error_code, void *user_data,
                        void *stream_user_data) {
  my_user_data *ud = user_data;
  (void)conn;
  (void)stream_user_data;

  if (ud) {
    ud->stream_close.flags = flags;
    ud->stream_close.stream_id = stream_id;
    ud->stream_close.app_error_code = app_error_code;
  }

  return 0;
}

static int recv_retry(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                      void *user_data) {
  (void)conn;
  (void)hd;
  (void)user_data;
  return 0;
}

static void genrand(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx) {
  (void)rand_ctx;

  memset(dest, 0, destlen);
}

static int recv_datagram(ngtcp2_conn *conn, uint32_t flags, const uint8_t *data,
                         size_t datalen, void *user_data) {
  my_user_data *ud = user_data;
  (void)conn;
  (void)flags;

  if (ud) {
    ud->datagram.flags = flags;
    ud->datagram.data = data;
    ud->datagram.datalen = datalen;
  }

  return 0;
}

static int ack_datagram(ngtcp2_conn *conn, uint64_t dgram_id, void *user_data) {
  my_user_data *ud = user_data;
  (void)conn;

  if (ud) {
    ud->datagram.dgram_id = dgram_id;
  }

  return 0;
}

static int get_path_challenge_data(ngtcp2_conn *conn, uint8_t *data,
                                   void *user_data) {
  (void)conn;
  (void)user_data;

  memset(data, 0, NGTCP2_PATH_CHALLENGE_DATALEN);

  return 0;
}

static int version_negotiation(ngtcp2_conn *conn, uint32_t version,
                               const ngtcp2_cid *client_dcid, void *user_data) {
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  (void)client_dcid;
  (void)user_data;

  ngtcp2_conn_install_vneg_initial_key(conn, version, &aead_ctx, null_iv,
                                       &hp_ctx, &aead_ctx, null_iv, &hp_ctx,
                                       sizeof(null_iv));

  return 0;
}

static void delete_crypto_aead_ctx(ngtcp2_conn *conn,
                                   ngtcp2_crypto_aead_ctx *aead_ctx,
                                   void *user_data) {
  (void)conn;
  (void)aead_ctx;
  (void)user_data;
}

static void delete_crypto_cipher_ctx(ngtcp2_conn *conn,
                                     ngtcp2_crypto_cipher_ctx *cipher_ctx,
                                     void *user_data) {
  (void)conn;
  (void)cipher_ctx;
  (void)user_data;
}

static const uint16_t pmtud_probes[] = {1300, 1400, 1260};

static void server_default_settings(ngtcp2_settings *settings) {
  ngtcp2_settings_default(settings);
  settings->log_printf = NULL;
  settings->initial_ts = 0;
  settings->initial_rtt = NGTCP2_DEFAULT_INITIAL_RTT;
  settings->max_tx_udp_payload_size = 2048;
  settings->no_tx_udp_payload_size_shaping = 1;
  settings->handshake_timeout = 10 * NGTCP2_SECONDS;
  settings->pmtud_probes = pmtud_probes;
  settings->pmtud_probeslen = ngtcp2_arraylen(pmtud_probes);
}

static void server_default_transport_params(ngtcp2_transport_params *params) {
  size_t i;

  ngtcp2_transport_params_default(params);
  params->original_dcid_present = 1;
  params->initial_max_stream_data_bidi_local = 65535;
  params->initial_max_stream_data_bidi_remote = 65535;
  params->initial_max_stream_data_uni = 65535;
  params->initial_max_data = 128 * 1024;
  params->initial_max_streams_bidi = 3;
  params->initial_max_streams_uni = 2;
  params->max_idle_timeout = 60 * NGTCP2_SECONDS;
  params->stateless_reset_token_present = 1;
  params->active_connection_id_limit = 8;
  for (i = 0; i < NGTCP2_STATELESS_RESET_TOKENLEN; ++i) {
    params->stateless_reset_token[i] = (uint8_t)i;
  }
}

static void server_default_callbacks(ngtcp2_callbacks *cb) {
  memset(cb, 0, sizeof(*cb));
  cb->recv_client_initial = recv_client_initial;
  cb->recv_crypto_data = recv_crypto_data_server;
  cb->decrypt = null_decrypt;
  cb->encrypt = null_encrypt;
  cb->hp_mask = null_hp_mask;
  cb->rand = genrand;
  cb->get_new_connection_id = get_new_connection_id;
  cb->update_key = update_key;
  cb->delete_crypto_aead_ctx = delete_crypto_aead_ctx;
  cb->delete_crypto_cipher_ctx = delete_crypto_cipher_ctx;
  cb->get_path_challenge_data = get_path_challenge_data;
  cb->version_negotiation = version_negotiation;
}

static void server_early_callbacks(ngtcp2_callbacks *cb) {
  server_default_callbacks(cb);

  cb->recv_client_initial = recv_client_initial_early;
  cb->recv_crypto_data = recv_crypto_data_server_early_data;
}

static void client_default_settings(ngtcp2_settings *settings) {
  ngtcp2_settings_default(settings);
  settings->log_printf = NULL;
  settings->initial_ts = 0;
  settings->initial_rtt = NGTCP2_DEFAULT_INITIAL_RTT;
  settings->max_tx_udp_payload_size = 2048;
  settings->no_tx_udp_payload_size_shaping = 1;
}

static void client_default_transport_params(ngtcp2_transport_params *params) {
  ngtcp2_transport_params_default(params);
  params->initial_max_stream_data_bidi_local = 65535;
  params->initial_max_stream_data_bidi_remote = 65535;
  params->initial_max_stream_data_uni = 65535;
  params->initial_max_data = 128 * 1024;
  params->initial_max_streams_bidi = 0;
  params->initial_max_streams_uni = 2;
  params->max_idle_timeout = 60 * NGTCP2_SECONDS;
  params->stateless_reset_token_present = 0;
  params->active_connection_id_limit = 8;
}

static void client_default_callbacks(ngtcp2_callbacks *cb) {
  memset(cb, 0, sizeof(*cb));
  cb->client_initial = client_initial;
  cb->recv_crypto_data = recv_crypto_data;
  cb->decrypt = null_decrypt;
  cb->encrypt = null_encrypt;
  cb->hp_mask = null_hp_mask;
  cb->recv_retry = recv_retry;
  cb->rand = genrand;
  cb->get_new_connection_id = get_new_connection_id;
  cb->update_key = update_key;
  cb->delete_crypto_aead_ctx = delete_crypto_aead_ctx;
  cb->delete_crypto_cipher_ctx = delete_crypto_cipher_ctx;
  cb->get_path_challenge_data = get_path_challenge_data;
  cb->version_negotiation = version_negotiation;
}

static void client_early_callbacks(ngtcp2_callbacks *cb) {
  client_default_callbacks(cb);

  cb->client_initial = client_initial_early_data;
}

static void conn_set_scid_used(ngtcp2_conn *conn) {
  ngtcp2_scid *scid;
  ngtcp2_ksl_it it;
  int rv;
  (void)rv;

  assert(1 + (conn->local.transport_params.preferred_addr_present != 0) ==
         ngtcp2_ksl_len(&conn->scid.set));

  it = ngtcp2_ksl_begin(&conn->scid.set);
  scid = ngtcp2_ksl_it_get(&it);
  scid->flags |= NGTCP2_SCID_FLAG_USED;

  assert(NGTCP2_PQ_BAD_INDEX == scid->pe.index);

  rv = ngtcp2_pq_push(&conn->scid.used, &scid->pe);

  assert(0 == rv);
}

static void
setup_default_server_settings(ngtcp2_conn **pconn, const ngtcp2_path *path,
                              const ngtcp2_settings *settings,
                              const ngtcp2_transport_params *params) {
  ngtcp2_callbacks cb;
  ngtcp2_cid dcid, scid;
  ngtcp2_transport_params remote_params;
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  ngtcp2_crypto_ctx crypto_ctx;

  dcid_init(&dcid);
  scid_init(&scid);

  init_crypto_ctx(&crypto_ctx);

  server_default_callbacks(&cb);

  ngtcp2_conn_server_new(pconn, &dcid, &scid, path, NGTCP2_PROTO_VER_V1, &cb,
                         settings, params,
                         /* mem = */ NULL, NULL);
  ngtcp2_conn_set_initial_crypto_ctx(*pconn, &crypto_ctx);
  ngtcp2_conn_install_initial_key(*pconn, &aead_ctx, null_iv, &hp_ctx,
                                  &aead_ctx, null_iv, &hp_ctx, sizeof(null_iv));
  ngtcp2_conn_set_crypto_ctx(*pconn, &crypto_ctx);
  ngtcp2_conn_install_rx_handshake_key(*pconn, &aead_ctx, null_iv,
                                       sizeof(null_iv), &hp_ctx);
  ngtcp2_conn_install_tx_handshake_key(*pconn, &aead_ctx, null_iv,
                                       sizeof(null_iv), &hp_ctx);
  ngtcp2_conn_install_rx_key(*pconn, null_secret, sizeof(null_secret),
                             &aead_ctx, null_iv, sizeof(null_iv), &hp_ctx);
  ngtcp2_conn_install_tx_key(*pconn, null_secret, sizeof(null_secret),
                             &aead_ctx, null_iv, sizeof(null_iv), &hp_ctx);

  ngtcp2_conn_discard_initial_state(*pconn, 0);
  /* handshake pktns is not discarded here because it is referenced in
     a test. */

  (*pconn)->state = NGTCP2_CS_POST_HANDSHAKE;
  (*pconn)->flags |= NGTCP2_CONN_FLAG_INITIAL_PKT_PROCESSED |
                     NGTCP2_CONN_FLAG_TLS_HANDSHAKE_COMPLETED |
                     NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED |
                     NGTCP2_CONN_FLAG_HANDSHAKE_CONFIRMED;
  (*pconn)->dcid.current.flags |= NGTCP2_DCID_FLAG_PATH_VALIDATED;
  conn_set_scid_used(*pconn);
  memset(&remote_params, 0, sizeof(remote_params));
  remote_params.initial_max_stream_data_bidi_local = 64 * 1024;
  remote_params.initial_max_stream_data_bidi_remote = 64 * 1024;
  remote_params.initial_max_stream_data_uni = 64 * 1024;
  remote_params.initial_max_streams_bidi = 0;
  remote_params.initial_max_streams_uni = 1;
  remote_params.initial_max_data = 64 * 1024;
  remote_params.active_connection_id_limit = 8;
  remote_params.max_udp_payload_size = NGTCP2_DEFAULT_MAX_RECV_UDP_PAYLOAD_SIZE;
  ngtcp2_transport_params_copy_new(&(*pconn)->remote.transport_params,
                                   &remote_params, (*pconn)->mem);
  (*pconn)->local.bidi.max_streams = remote_params.initial_max_streams_bidi;
  (*pconn)->local.uni.max_streams = remote_params.initial_max_streams_uni;
  (*pconn)->tx.max_offset = remote_params.initial_max_data;
  (*pconn)->negotiated_version = (*pconn)->client_chosen_version;
  (*pconn)->pktns.rtb.persistent_congestion_start_ts = 0;
}

static void setup_default_server(ngtcp2_conn **pconn) {
  ngtcp2_settings settings;
  ngtcp2_transport_params params;

  server_default_settings(&settings);
  server_default_transport_params(&params);

  setup_default_server_settings(pconn, &null_path.path, &settings, &params);
}

static void
setup_default_client_settings(ngtcp2_conn **pconn, const ngtcp2_path *path,
                              const ngtcp2_settings *settings,
                              const ngtcp2_transport_params *params) {
  ngtcp2_callbacks cb;
  ngtcp2_cid dcid, scid;
  ngtcp2_transport_params remote_params;
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  ngtcp2_crypto_ctx crypto_ctx;

  dcid_init(&dcid);
  scid_init(&scid);

  init_crypto_ctx(&crypto_ctx);

  client_default_callbacks(&cb);

  ngtcp2_conn_client_new(pconn, &dcid, &scid, path, NGTCP2_PROTO_VER_V1, &cb,
                         settings, params,
                         /* mem = */ NULL, NULL);
  ngtcp2_conn_set_crypto_ctx(*pconn, &crypto_ctx);
  ngtcp2_conn_install_rx_handshake_key(*pconn, &aead_ctx, null_iv,
                                       sizeof(null_iv), &hp_ctx);
  ngtcp2_conn_install_tx_handshake_key(*pconn, &aead_ctx, null_iv,
                                       sizeof(null_iv), &hp_ctx);
  ngtcp2_conn_install_rx_key(*pconn, null_secret, sizeof(null_secret),
                             &aead_ctx, null_iv, sizeof(null_iv), &hp_ctx);
  ngtcp2_conn_install_tx_key(*pconn, null_secret, sizeof(null_secret),
                             &aead_ctx, null_iv, sizeof(null_iv), &hp_ctx);
  (*pconn)->state = NGTCP2_CS_POST_HANDSHAKE;
  (*pconn)->flags |= NGTCP2_CONN_FLAG_INITIAL_PKT_PROCESSED |
                     NGTCP2_CONN_FLAG_TLS_HANDSHAKE_COMPLETED |
                     NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED |
                     NGTCP2_CONN_FLAG_HANDSHAKE_CONFIRMED;
  (*pconn)->dcid.current.flags |= NGTCP2_DCID_FLAG_PATH_VALIDATED;
  conn_set_scid_used(*pconn);
  memset(&remote_params, 0, sizeof(remote_params));
  remote_params.initial_max_stream_data_bidi_local = 64 * 1024;
  remote_params.initial_max_stream_data_bidi_remote = 64 * 1024;
  remote_params.initial_max_stream_data_uni = 64 * 1024;
  remote_params.initial_max_streams_bidi = 1;
  remote_params.initial_max_streams_uni = 1;
  remote_params.initial_max_data = 64 * 1024;
  remote_params.active_connection_id_limit = 8;
  remote_params.max_udp_payload_size = NGTCP2_DEFAULT_MAX_RECV_UDP_PAYLOAD_SIZE;
  ngtcp2_transport_params_copy_new(&(*pconn)->remote.transport_params,
                                   &remote_params, (*pconn)->mem);
  (*pconn)->local.bidi.max_streams = remote_params.initial_max_streams_bidi;
  (*pconn)->local.uni.max_streams = remote_params.initial_max_streams_uni;
  (*pconn)->tx.max_offset = remote_params.initial_max_data;
  (*pconn)->negotiated_version = (*pconn)->client_chosen_version;

  (*pconn)->dcid.current.flags |= NGTCP2_DCID_FLAG_TOKEN_PRESENT;
  memset((*pconn)->dcid.current.token, 0xf1, NGTCP2_STATELESS_RESET_TOKENLEN);
  (*pconn)->pktns.rtb.persistent_congestion_start_ts = 0;
}

static void setup_default_client(ngtcp2_conn **pconn) {
  ngtcp2_settings settings;
  ngtcp2_transport_params params;

  client_default_settings(&settings);
  client_default_transport_params(&params);

  setup_default_client_settings(pconn, &null_path.path, &settings, &params);
}

static void
setup_handshake_server_settings(ngtcp2_conn **pconn, const ngtcp2_path *path,
                                const ngtcp2_settings *settings,
                                const ngtcp2_transport_params *params) {
  ngtcp2_callbacks cb;
  ngtcp2_cid dcid, scid;

  dcid_init(&dcid);
  scid_init(&scid);

  server_default_callbacks(&cb);

  ngtcp2_conn_server_new(pconn, &dcid, &scid, path, NGTCP2_PROTO_VER_V1, &cb,
                         settings, params,
                         /* mem = */ NULL, NULL);
}

static void setup_handshake_server(ngtcp2_conn **pconn) {
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  uint32_t preferred_versions[] = {
      NGTCP2_PROTO_VER_V2,
      NGTCP2_PROTO_VER_V1,
  };

  server_default_settings(&settings);
  server_default_transport_params(&params);

  settings.preferred_versions = preferred_versions;
  settings.preferred_versionslen = ngtcp2_arraylen(preferred_versions);

  setup_handshake_server_settings(pconn, &null_path.path, &settings, &params);
}

static void setup_handshake_client_version(ngtcp2_conn **pconn,
                                           uint32_t client_chosen_version) {
  ngtcp2_callbacks cb;
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  ngtcp2_cid rcid, scid;
  ngtcp2_crypto_aead retry_aead = {0, NGTCP2_FAKE_AEAD_OVERHEAD};
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  ngtcp2_crypto_ctx crypto_ctx;
  uint32_t preferred_versions[] = {
      NGTCP2_PROTO_VER_V2,
      NGTCP2_PROTO_VER_V1,
  };
  uint32_t available_versions[] = {
      NGTCP2_PROTO_VER_V1,
      NGTCP2_PROTO_VER_V2,
  };

  rcid_init(&rcid);
  scid_init(&scid);

  init_initial_crypto_ctx(&crypto_ctx);

  client_default_callbacks(&cb);
  client_default_settings(&settings);
  client_default_transport_params(&params);

  settings.preferred_versions = preferred_versions;
  settings.preferred_versionslen = ngtcp2_arraylen(preferred_versions);

  settings.available_versions = available_versions;
  settings.available_versionslen = ngtcp2_arraylen(available_versions);

  ngtcp2_conn_client_new(pconn, &rcid, &scid, &null_path.path,
                         client_chosen_version, &cb, &settings, &params,
                         /* mem = */ NULL, NULL);
  ngtcp2_conn_set_initial_crypto_ctx(*pconn, &crypto_ctx);
  ngtcp2_conn_install_initial_key(*pconn, &aead_ctx, null_iv, &hp_ctx,
                                  &aead_ctx, null_iv, &hp_ctx, sizeof(null_iv));
  ngtcp2_conn_set_retry_aead(*pconn, &retry_aead, &aead_ctx);
}

static void setup_handshake_client(ngtcp2_conn **pconn) {
  setup_handshake_client_version(pconn, NGTCP2_PROTO_VER_V1);
}

static void setup_early_server(ngtcp2_conn **pconn) {
  ngtcp2_callbacks cb;
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  ngtcp2_cid dcid, scid;

  dcid_init(&dcid);
  scid_init(&scid);

  server_early_callbacks(&cb);
  server_default_settings(&settings);
  server_default_transport_params(&params);

  ngtcp2_conn_server_new(pconn, &dcid, &scid, &null_path.path,
                         NGTCP2_PROTO_VER_V1, &cb, &settings, &params,
                         /* mem = */ NULL, NULL);
}

static void setup_early_client_scid(ngtcp2_conn **pconn,
                                    const ngtcp2_cid *scid) {
  ngtcp2_callbacks cb;
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  ngtcp2_cid rcid;
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  ngtcp2_crypto_ctx crypto_ctx;

  rcid_init(&rcid);

  init_initial_crypto_ctx(&crypto_ctx);

  client_early_callbacks(&cb);
  client_default_settings(&settings);
  client_default_transport_params(&params);

  ngtcp2_conn_client_new(pconn, &rcid, scid, &null_path.path,
                         NGTCP2_PROTO_VER_V1, &cb, &settings, &params,
                         /* mem = */ NULL, NULL);
  ngtcp2_conn_set_initial_crypto_ctx(*pconn, &crypto_ctx);
  ngtcp2_conn_install_initial_key(*pconn, &aead_ctx, null_iv, &hp_ctx,
                                  &aead_ctx, null_iv, &hp_ctx, sizeof(null_iv));

  memset(&params, 0, sizeof(params));
  params.initial_max_stream_data_bidi_local = 64 * 1024;
  params.initial_max_stream_data_bidi_remote = 64 * 1024;
  params.initial_max_stream_data_uni = 64 * 1024;
  params.initial_max_streams_bidi = 1;
  params.initial_max_streams_uni = 1;
  params.initial_max_data = 64 * 1024;
  params.active_connection_id_limit = 8;

  ngtcp2_conn_set_0rtt_remote_transport_params(*pconn, &params);
}

static void setup_early_client(ngtcp2_conn **pconn) {
  ngtcp2_cid scid;

  scid_init(&scid);

  setup_early_client_scid(pconn, &scid);
}

void test_ngtcp2_conn_stream_open_close(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  int rv;
  ngtcp2_frame fr;
  ngtcp2_strm *strm;
  int64_t stream_id;

  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 17;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, 4);

  assert_uint32(NGTCP2_STRM_FLAG_NONE, ==, strm->flags);

  fr.stream.fin = 1;
  fr.stream.offset = 17;
  fr.stream.datacnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 2, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 2);

  assert_int(0, ==, rv);
  assert_uint32(NGTCP2_STRM_FLAG_SHUT_RD, ==, strm->flags);
  assert_uint64(fr.stream.offset, ==, strm->rx.last_offset);
  assert_uint64(fr.stream.offset, ==, ngtcp2_strm_rx_offset(strm));

  spktlen =
      ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                               NGTCP2_WRITE_STREAM_FLAG_FIN, 4, NULL, 0, 3);

  assert_ptrdiff(0, <, spktlen);

  strm = ngtcp2_conn_find_stream(conn, 4);

  assert_not_null(strm);

  /* Open a remote unidirectional stream */
  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 2;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 19;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 3, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 3);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, 2);

  assert_uint32((NGTCP2_STRM_FLAG_SHUT_WR | NGTCP2_STRM_FLAG_FIN_ACKED), ==,
                strm->flags);
  assert_uint64(fr.stream.data[0].len, ==, strm->rx.last_offset);
  assert_uint64(fr.stream.data[0].len, ==, ngtcp2_strm_rx_offset(strm));

  /* Open a local unidirectional stream */
  rv = ngtcp2_conn_open_uni_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);
  assert_int64(3, ==, stream_id);

  rv = ngtcp2_conn_open_uni_stream(conn, &stream_id, NULL);

  assert_int(NGTCP2_ERR_STREAM_ID_BLOCKED, ==, rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_stream_rx_flow_control(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  int rv;
  ngtcp2_frame fr;
  ngtcp2_strm *strm;
  size_t i;
  int64_t stream_id;

  setup_default_server(&conn);

  conn->local.transport_params.initial_max_stream_data_bidi_remote = 2047;

  for (i = 0; i < 3; ++i) {
    stream_id = (int64_t)(i * 4);
    fr.type = NGTCP2_FRAME_STREAM;
    fr.stream.flags = 0;
    fr.stream.stream_id = stream_id;
    fr.stream.fin = 0;
    fr.stream.offset = 0;
    fr.stream.datacnt = 1;
    fr.stream.data[0].len = 1024;
    fr.stream.data[0].base = null_data;

    pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, (int64_t)i, &fr, 1,
                       conn->pktns.crypto.rx.ckm);
    rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

    assert_int(0, ==, rv);

    strm = ngtcp2_conn_find_stream(conn, stream_id);

    assert_not_null(strm);

    rv = ngtcp2_conn_extend_max_stream_offset(conn, stream_id,
                                              fr.stream.data[0].len);

    assert_int(0, ==, rv);
  }

  assert_size(3, ==, ngtcp2_pq_size(&conn->tx.strmq));

  strm = ngtcp2_conn_find_stream(conn, 0);

  assert_true(ngtcp2_strm_is_tx_queued(strm));

  strm = ngtcp2_conn_find_stream(conn, 4);

  assert_true(ngtcp2_strm_is_tx_queued(strm));

  strm = ngtcp2_conn_find_stream(conn, 8);

  assert_true(ngtcp2_strm_is_tx_queued(strm));

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), 2);

  assert_ptrdiff(0, <, spktlen);
  assert_true(ngtcp2_pq_empty(&conn->tx.strmq));

  for (i = 0; i < 3; ++i) {
    stream_id = (int64_t)(i * 4);
    strm = ngtcp2_conn_find_stream(conn, stream_id);

    assert_uint64(2047 + 1024, ==, strm->rx.max_offset);
  }

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_stream_rx_flow_control_error(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  int rv;
  ngtcp2_frame fr;

  setup_default_server(&conn);

  conn->local.transport_params.initial_max_stream_data_bidi_remote = 1023;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1024;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(NGTCP2_ERR_FLOW_CONTROL, ==, rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_stream_tx_flow_control(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  int rv;
  ngtcp2_frame fr;
  ngtcp2_strm *strm;
  ngtcp2_ssize nwrite;
  int64_t stream_id;

  setup_default_client(&conn);

  conn->remote.transport_params->initial_max_stream_data_bidi_remote = 2047;

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);
  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf),
                                     &nwrite, NGTCP2_WRITE_STREAM_FLAG_NONE,
                                     stream_id, null_data, 1024, 1);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(1024, ==, nwrite);
  assert_uint64(1024, ==, strm->tx.offset);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf),
                                     &nwrite, NGTCP2_WRITE_STREAM_FLAG_NONE,
                                     stream_id, null_data, 1024, 2);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(1023, ==, nwrite);
  assert_uint64(2047, ==, strm->tx.offset);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf),
                                     &nwrite, NGTCP2_WRITE_STREAM_FLAG_NONE,
                                     stream_id, null_data, 1024, 3);

  assert_ptrdiff(NGTCP2_ERR_STREAM_DATA_BLOCKED, ==, spktlen);

  /* We can write 0 length STREAM frame */
  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf),
                                     &nwrite, NGTCP2_WRITE_STREAM_FLAG_NONE,
                                     stream_id, null_data, 0, 3);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(0, ==, nwrite);
  assert_uint64(2047, ==, strm->tx.offset);

  fr.type = NGTCP2_FRAME_MAX_STREAM_DATA;
  fr.max_stream_data.stream_id = stream_id;
  fr.max_stream_data.max_stream_data = 2048;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 4);

  assert_int(0, ==, rv);
  assert_uint64(2048, ==, strm->tx.max_offset);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf),
                                     &nwrite, NGTCP2_WRITE_STREAM_FLAG_NONE,
                                     stream_id, null_data, 1024, 5);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(1, ==, nwrite);
  assert_uint64(2048, ==, strm->tx.offset);

  ngtcp2_conn_del(conn);

  /* CWND left is round up to the maximum UDP packet size */
  setup_default_client(&conn);

  conn->cstat.cwnd = 1;

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf),
                                     &nwrite, NGTCP2_WRITE_STREAM_FLAG_FIN,
                                     stream_id, null_data, 1024, 1);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(1024, ==, nwrite);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_rx_flow_control(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  int rv;
  ngtcp2_frame fr;

  setup_default_server(&conn);

  conn->local.transport_params.initial_max_data = 1024;
  conn->rx.window = 1024;
  conn->rx.max_offset = 1024;
  conn->rx.unsent_max_offset = 1024;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1023;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(0, ==, rv);

  ngtcp2_conn_extend_max_offset(conn, 1023);

  assert_uint64(1024 + 1023, ==, conn->rx.unsent_max_offset);
  assert_uint64(1024, ==, conn->rx.max_offset);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 1023;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 2, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 2);

  assert_int(0, ==, rv);

  ngtcp2_conn_extend_max_offset(conn, 1);

  assert_uint64(2048, ==, conn->rx.unsent_max_offset);
  assert_uint64(1024, ==, conn->rx.max_offset);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), 3);

  assert_ptrdiff(0, <, spktlen);
  assert_uint64(2048, ==, conn->rx.max_offset);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_rx_flow_control_error(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  int rv;
  ngtcp2_frame fr;

  setup_default_server(&conn);

  conn->local.transport_params.initial_max_data = 1024;
  conn->rx.window = 1024;
  conn->rx.max_offset = 1024;
  conn->rx.unsent_max_offset = 1024;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1025;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(NGTCP2_ERR_FLOW_CONTROL, ==, rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_tx_flow_control(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  int rv;
  ngtcp2_frame fr;
  ngtcp2_ssize nwrite;
  int64_t stream_id;

  setup_default_client(&conn);

  conn->remote.transport_params->initial_max_data = 2048;
  conn->tx.max_offset = 2048;

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf),
                                     &nwrite, NGTCP2_WRITE_STREAM_FLAG_NONE,
                                     stream_id, null_data, 1024, 1);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(1024, ==, nwrite);
  assert_uint64(1024, ==, conn->tx.offset);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf),
                                     &nwrite, NGTCP2_WRITE_STREAM_FLAG_NONE,
                                     stream_id, null_data, 1023, 2);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(1023, ==, nwrite);
  assert_uint64(1024 + 1023, ==, conn->tx.offset);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf),
                                     &nwrite, NGTCP2_WRITE_STREAM_FLAG_NONE,
                                     stream_id, null_data, 1024, 3);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(1, ==, nwrite);
  assert_uint64(2048, ==, conn->tx.offset);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf),
                                     &nwrite, NGTCP2_WRITE_STREAM_FLAG_NONE,
                                     stream_id, null_data, 1024, 4);

  assert_ptrdiff(0, ==, spktlen);
  assert_ptrdiff(-1, ==, nwrite);

  fr.type = NGTCP2_FRAME_MAX_DATA;
  fr.max_data.max_data = 3072;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 5);

  assert_int(0, ==, rv);
  assert_uint64(3072, ==, conn->tx.max_offset);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf),
                                     &nwrite, NGTCP2_WRITE_STREAM_FLAG_NONE,
                                     stream_id, null_data, 1024, 5);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(1024, ==, nwrite);
  assert_uint64(3072, ==, conn->tx.offset);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_shutdown_stream_write(void) {
  ngtcp2_conn *conn;
  int rv;
  ngtcp2_frame_chain *frc;
  uint8_t buf[2048];
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_strm *strm;
  int64_t stream_id;
  ngtcp2_ksl_it it;
  ngtcp2_rtb_entry *ent;

  /* Stream not found */
  setup_default_server(&conn);

  rv = ngtcp2_conn_shutdown_stream_write(conn, 0, 4, NGTCP2_APP_ERR01);

  assert_int(0, ==, rv);

  ngtcp2_conn_del(conn);

  /* Check final_size */
  setup_default_client(&conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                           NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id, null_data,
                           1239, 1);
  rv = ngtcp2_conn_shutdown_stream_write(conn, 0, stream_id, NGTCP2_APP_ERR01);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  assert_not_null(strm);
  assert_uint64(NGTCP2_APP_ERR01, ==, strm->app_error_code);
  assert_uint64(NGTCP2_APP_ERR01, ==, strm->tx.reset_stream_app_error_code);
  assert_true(strm->flags & NGTCP2_STRM_FLAG_SEND_RESET_STREAM);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), 2);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);

  assert_false(ngtcp2_ksl_it_end(&it));

  ent = ngtcp2_ksl_it_get(&it);
  frc = ent->frc;

  assert_int64(stream_id, ==, frc->fr.reset_stream.stream_id);
  assert_uint64(NGTCP2_APP_ERR01, ==, frc->fr.reset_stream.app_error_code);
  assert_uint64(1239, ==, frc->fr.reset_stream.final_size);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = stream_id;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR02;
  fr.reset_stream.final_size = 100;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 890, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 2);

  assert_int(0, ==, rv);
  assert_not_null(ngtcp2_conn_find_stream(conn, stream_id));

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = conn->pktns.tx.last_pkt_num;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 899, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 2);

  assert_int(0, ==, rv);
  assert_null(ngtcp2_conn_find_stream(conn, stream_id));

  ngtcp2_conn_del(conn);

  /* Check that stream is closed when RESET_STREAM is acknowledged */
  setup_default_client(&conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = stream_id;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 119, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(0, ==, rv);
  assert_not_null(ngtcp2_conn_find_stream(conn, stream_id));

  rv = ngtcp2_conn_shutdown_stream_write(conn, 0, stream_id, NGTCP2_APP_ERR01);

  assert_int(0, ==, rv);
  assert_not_null(ngtcp2_conn_find_stream(conn, stream_id));

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), 2);

  assert_ptrdiff(0, <, spktlen);

  /* Incoming FIN does not close stream */
  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.fin = 1;
  fr.stream.offset = 0;
  fr.stream.datacnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 121, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 2);

  assert_int(0, ==, rv);
  assert_not_null(ngtcp2_conn_find_stream(conn, stream_id));

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = conn->pktns.tx.last_pkt_num;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 332, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 3);

  assert_int(0, ==, rv);
  assert_null(ngtcp2_conn_find_stream(conn, stream_id));

  ngtcp2_conn_del(conn);

  /* RESET_STREAM is not sent if all tx data are acknowledged */
  setup_default_client(&conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_FIN, stream_id,
                                     null_data, 0, 3);

  assert_ptrdiff(0, <, spktlen);

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = conn->pktns.tx.last_pkt_num;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 999, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 7);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_shutdown_stream_write(conn, 0, stream_id, NGTCP2_APP_ERR01);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  assert_false(strm->flags & NGTCP2_STRM_FLAG_RESET_STREAM);

  spktlen =
      ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                               NGTCP2_WRITE_STREAM_FLAG_FIN, -1, NULL, 0, 11);

  assert_ptrdiff(0, ==, spktlen);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_shutdown_stream_read(void) {
  ngtcp2_conn *conn;
  int64_t stream_id;
  int rv;
  ngtcp2_strm *strm;
  uint8_t buf[2048];
  ngtcp2_ssize spktlen;
  ngtcp2_ksl_it it;
  ngtcp2_rtb_entry *ent;
  ngtcp2_frame_chain *frc;
  ngtcp2_frame fr;
  ngtcp2_tstamp t = 0;
  size_t pktlen;

  /* Stream not found */
  setup_default_server(&conn);

  rv = ngtcp2_conn_shutdown_stream_read(conn, 0, 4, NGTCP2_APP_ERR01);

  assert_int(0, ==, rv);

  ngtcp2_conn_del(conn);

  /* Do not multiple STOP_SENDINGs */
  setup_default_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  rv = ngtcp2_conn_shutdown_stream_read(conn, 0, stream_id, NGTCP2_APP_ERR01);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  assert_not_null(strm);
  assert_uint64(NGTCP2_APP_ERR01, ==, strm->app_error_code);
  assert_uint64(NGTCP2_APP_ERR01, ==, strm->tx.stop_sending_app_error_code);
  assert_true(strm->flags & NGTCP2_STRM_FLAG_STOP_SENDING);
  assert_true(strm->flags & NGTCP2_STRM_FLAG_SEND_STOP_SENDING);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);

  assert_false(ngtcp2_ksl_it_end(&it));

  ent = ngtcp2_ksl_it_get(&it);
  frc = ent->frc;

  assert_int64(stream_id, ==, frc->fr.stop_sending.stream_id);
  assert_uint64(NGTCP2_APP_ERR01, ==, frc->fr.stop_sending.app_error_code);
  assert_null(frc->next);

  rv = ngtcp2_conn_shutdown_stream_read(conn, 0, stream_id, NGTCP2_APP_ERR02);

  assert_int(0, ==, rv);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);

  assert_false(ngtcp2_ksl_it_end(&it));

  ent = ngtcp2_ksl_it_get(&it);
  frc = ent->frc;

  assert_int64(stream_id, ==, frc->fr.stop_sending.stream_id);
  assert_uint64(NGTCP2_APP_ERR01, ==, frc->fr.stop_sending.app_error_code);
  assert_null(frc->next);

  ngtcp2_conn_del(conn);

  /* Do not send STOP_SENDING if RESET_STREAM has been received */
  setup_default_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = stream_id;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR01;
  fr.reset_stream.final_size = 1;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_shutdown_stream_read(conn, 0, stream_id, NGTCP2_APP_ERR02);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  assert_uint64(NGTCP2_APP_ERR01, ==, strm->app_error_code);
  assert_true(strm->flags & NGTCP2_STRM_FLAG_RESET_STREAM_RECVED);
  assert_false(strm->flags & NGTCP2_STRM_FLAG_STOP_SENDING);
  assert_false(strm->flags & NGTCP2_STRM_FLAG_SEND_STOP_SENDING);

  ngtcp2_conn_del(conn);

  /* Do not send STOP_SENDING if all data has been received */
  setup_default_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = stream_id;
  fr.stream.fin = 1;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 77;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_shutdown_stream_read(conn, 0, stream_id, NGTCP2_APP_ERR01);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  assert_uint64(NGTCP2_APP_ERR01, ==, strm->app_error_code);
  assert_false(strm->flags & NGTCP2_STRM_FLAG_STOP_SENDING);
  assert_false(strm->flags & NGTCP2_STRM_FLAG_SEND_STOP_SENDING);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_reset_stream(void) {
  ngtcp2_conn *conn;
  int rv;
  uint8_t buf[2048];
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_strm *strm;
  int64_t stream_id;

  /* Receive RESET_STREAM */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 955;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(0, ==, rv);

  ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                           NGTCP2_WRITE_STREAM_FLAG_NONE, 4, null_data, 354, 2);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 4;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR02;
  fr.reset_stream.final_size = 955;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 2, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 3);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, 4);

  assert_true(strm->flags & NGTCP2_STRM_FLAG_SHUT_RD);
  assert_true(strm->flags & NGTCP2_STRM_FLAG_RESET_STREAM_RECVED);

  ngtcp2_conn_del(conn);

  /* Receive RESET_STREAM after sending STOP_SENDING */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 955;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(0, ==, rv);

  ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                           NGTCP2_WRITE_STREAM_FLAG_NONE, 4, null_data, 354, 2);
  ngtcp2_conn_shutdown_stream_read(conn, 0, 4, NGTCP2_APP_ERR01);
  ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), 3);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 4;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR02;
  fr.reset_stream.final_size = 955;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 2, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 4);

  assert_int(0, ==, rv);
  assert_not_null(ngtcp2_conn_find_stream(conn, 4));

  ngtcp2_conn_del(conn);

  /* Receive RESET_STREAM after sending RESET_STREAM */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 955;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(0, ==, rv);

  ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                           NGTCP2_WRITE_STREAM_FLAG_NONE, 4, null_data, 354, 2);
  ngtcp2_conn_shutdown_stream_write(conn, 0, 4, NGTCP2_APP_ERR01);
  ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), 3);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 4;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR02;
  fr.reset_stream.final_size = 955;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 2, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 4);

  assert_int(0, ==, rv);
  assert_not_null(ngtcp2_conn_find_stream(conn, 4));

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = conn->pktns.tx.last_pkt_num;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 3, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 5);

  assert_int(0, ==, rv);
  assert_null(ngtcp2_conn_find_stream(conn, 4));

  ngtcp2_conn_del(conn);

  /* Receive RESET_STREAM after receiving STOP_SENDING */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 955;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(0, ==, rv);

  ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                           NGTCP2_WRITE_STREAM_FLAG_NONE, 4, null_data, 354, 2);

  fr.type = NGTCP2_FRAME_STOP_SENDING;
  fr.stop_sending.stream_id = 4;
  fr.stop_sending.app_error_code = NGTCP2_APP_ERR01;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 2, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 3);

  assert_int(0, ==, rv);
  assert_not_null(ngtcp2_conn_find_stream(conn, 4));

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), 4);

  assert_ptrdiff(0, <, spktlen);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 4;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR02;
  fr.reset_stream.final_size = 955;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 3, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 4);

  assert_int(0, ==, rv);
  assert_not_null(ngtcp2_conn_find_stream(conn, 4));

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = conn->pktns.tx.last_pkt_num;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 4, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 5);

  assert_int(0, ==, rv);
  assert_null(ngtcp2_conn_find_stream(conn, 4));

  ngtcp2_conn_del(conn);

  /* final_size in RESET_STREAM exceeds the already received offset */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 955;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(0, ==, rv);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 4;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR02;
  fr.reset_stream.final_size = 954;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 2, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 2);

  assert_int(NGTCP2_ERR_FINAL_SIZE, ==, rv);

  ngtcp2_conn_del(conn);

  /* final_size in RESET_STREAM differs from the final offset which
     STREAM frame with fin indicated. */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 1;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 955;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(0, ==, rv);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 4;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR02;
  fr.reset_stream.final_size = 956;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 2, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 2);

  assert_int(NGTCP2_ERR_FINAL_SIZE, ==, rv);

  ngtcp2_conn_del(conn);

  /* RESET_STREAM against local stream which has not been initiated. */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 1;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR01;
  fr.reset_stream.final_size = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(NGTCP2_ERR_STREAM_STATE, ==, rv);

  ngtcp2_conn_del(conn);

  /* RESET_STREAM against remote stream which has not been initiated */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 0;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR01;
  fr.reset_stream.final_size = 1999;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, 0);

  assert_uint64(1999, ==, strm->rx.last_offset);
  assert_true(strm->flags & NGTCP2_STRM_FLAG_RESET_STREAM_RECVED);
  assert_uint64(3, ==, conn->remote.bidi.unsent_max_streams);

  ngtcp2_conn_del(conn);

  /* RESET_STREAM against remote stream which is larger than allowed
     maximum */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 16;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR01;
  fr.reset_stream.final_size = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(NGTCP2_ERR_STREAM_LIMIT, ==, rv);

  ngtcp2_conn_del(conn);

  /* RESET_STREAM against remote stream which is allowed, and no
     ngtcp2_strm object has been created */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 4;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR01;
  fr.reset_stream.final_size = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(0, ==, rv);
  assert_true(
      ngtcp2_idtr_is_open(&conn->remote.bidi.idtr, fr.reset_stream.stream_id));

  ngtcp2_conn_del(conn);

  /* RESET_STREAM against remote stream which is allowed, and no
     ngtcp2_strm object has been created, and final_size violates
     connection-level flow control. */
  setup_default_server(&conn);

  conn->local.transport_params.initial_max_stream_data_bidi_remote = 1 << 21;

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 4;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR01;
  fr.reset_stream.final_size = 1 << 20;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(NGTCP2_ERR_FLOW_CONTROL, ==, rv);

  ngtcp2_conn_del(conn);

  /* RESET_STREAM against remote stream which is allowed, and no
      ngtcp2_strm object has been created, and final_size violates
      stream-level flow control. */
  setup_default_server(&conn);

  conn->rx.max_offset = 1 << 21;

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 4;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR01;
  fr.reset_stream.final_size = 1 << 20;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(NGTCP2_ERR_FLOW_CONTROL, ==, rv);

  ngtcp2_conn_del(conn);

  /* final_size in RESET_STREAM violates connection-level flow
     control */
  setup_default_server(&conn);

  conn->local.transport_params.initial_max_stream_data_bidi_remote = 1 << 21;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 955;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(0, ==, rv);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 4;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR02;
  fr.reset_stream.final_size = 1024 * 1024;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 2, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 2);

  assert_int(NGTCP2_ERR_FLOW_CONTROL, ==, rv);

  ngtcp2_conn_del(conn);

  /* final_size in RESET_STREAM violates stream-level flow control */
  setup_default_server(&conn);

  conn->rx.max_offset = 1 << 21;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 955;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(0, ==, rv);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 4;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR02;
  fr.reset_stream.final_size = 1024 * 1024;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 2, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 2);

  assert_int(NGTCP2_ERR_FLOW_CONTROL, ==, rv);

  ngtcp2_conn_del(conn);

  /* Receiving RESET_STREAM for a local unidirectional stream is a
     protocol violation. */
  setup_default_server(&conn);

  rv = ngtcp2_conn_open_uni_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = stream_id;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR02;
  fr.reset_stream.final_size = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(NGTCP2_ERR_PROTO, ==, rv);

  ngtcp2_conn_del(conn);

  /* RESET_STREAM extends connection window including buffered data */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 1;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 955;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(0, ==, rv);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 4;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR02;
  fr.reset_stream.final_size = 1024;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 2, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 2);

  assert_int(0, ==, rv);
  assert_uint64(1024, ==, conn->rx.offset);
  assert_uint64(128 * 1024 + 1024, ==, conn->rx.unsent_max_offset);

  /* Receiving same RESET_STREAM does not increase rx offsets. */
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 3);

  assert_int(0, ==, rv);
  assert_uint64(1024, ==, conn->rx.offset);
  assert_uint64(128 * 1024 + 1024, ==, conn->rx.unsent_max_offset);

  ngtcp2_conn_del(conn);

  /* Verify that connection window is properly updated when
     RESET_STREAM is received after sending STOP_SENDING */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 1;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 955;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(0, ==, rv);

  ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                           NGTCP2_WRITE_STREAM_FLAG_NONE, 4, null_data, 354, 2);
  ngtcp2_conn_shutdown_stream_read(conn, 0, 4, NGTCP2_APP_ERR01);
  ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), 3);

  assert_uint64(128 * 1024 + 956, ==, conn->rx.unsent_max_offset);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 4;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR02;
  fr.reset_stream.final_size = 957;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 2, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 4);

  assert_int(0, ==, rv);
  assert_not_null(ngtcp2_conn_find_stream(conn, 4));
  assert_uint64(128 * 1024 + 956 + 1, ==, conn->rx.unsent_max_offset);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_stop_sending(void) {
  ngtcp2_conn *conn;
  int rv;
  uint8_t buf[2048];
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_strm *strm;
  ngtcp2_tstamp t = 0;
  int64_t pkt_num = 0;
  ngtcp2_frame_chain *frc;
  int64_t stream_id;
  ngtcp2_ksl_it it;
  ngtcp2_rtb_entry *ent;

  /* Receive STOP_SENDING */
  setup_default_client(&conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                           NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id, null_data,
                           333, ++t);

  fr.type = NGTCP2_FRAME_STOP_SENDING;
  fr.stop_sending.stream_id = stream_id;
  fr.stop_sending.app_error_code = NGTCP2_APP_ERR01;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  assert_true(strm->flags & NGTCP2_STRM_FLAG_SHUT_WR);
  assert_true(strm->flags & NGTCP2_STRM_FLAG_STOP_SENDING_RECVED);
  assert_true(strm->flags & NGTCP2_STRM_FLAG_RESET_STREAM);
  assert_true(strm->flags & NGTCP2_STRM_FLAG_SEND_RESET_STREAM);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);

  assert_false(ngtcp2_ksl_it_end(&it));

  ent = ngtcp2_ksl_it_get(&it);
  frc = ent->frc;

  assert_uint64(NGTCP2_FRAME_RESET_STREAM, ==, frc->fr.type);
  assert_uint64(NGTCP2_APP_ERR01, ==, frc->fr.reset_stream.app_error_code);
  assert_uint64(333, ==, frc->fr.reset_stream.final_size);

  /* Make sure that receiving duplicated STOP_SENDING does not trigger
     another RESET_STREAM. */
  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  assert_true(strm->flags & NGTCP2_STRM_FLAG_SHUT_WR);
  assert_true(strm->flags & NGTCP2_STRM_FLAG_RESET_STREAM);
  assert_false(strm->flags & NGTCP2_STRM_FLAG_SEND_RESET_STREAM);

  ngtcp2_conn_del(conn);

  /* Receive STOP_SENDING after receiving RESET_STREAM */
  setup_default_client(&conn);

  t = 0;

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                           NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id, null_data,
                           333, ++t);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = stream_id;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR01;
  fr.reset_stream.final_size = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  fr.type = NGTCP2_FRAME_STOP_SENDING;
  fr.stop_sending.stream_id = stream_id;
  fr.stop_sending.app_error_code = NGTCP2_APP_ERR01;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_not_null(ngtcp2_conn_find_stream(conn, stream_id));

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);

  assert_false(ngtcp2_ksl_it_end(&it));

  ent = ngtcp2_ksl_it_get(&it);
  frc = ent->frc;

  assert_uint64(NGTCP2_FRAME_RESET_STREAM, ==, frc->fr.type);
  assert_uint64(NGTCP2_APP_ERR01, ==, frc->fr.reset_stream.app_error_code);
  assert_uint64(333, ==, frc->fr.reset_stream.final_size);

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = conn->pktns.tx.last_pkt_num;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_null(ngtcp2_conn_find_stream(conn, stream_id));

  ngtcp2_conn_del(conn);

  /* STOP_SENDING against remote bidirectional stream which has not
     been initiated. */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STOP_SENDING;
  fr.stop_sending.stream_id = 0;
  fr.stop_sending.app_error_code = NGTCP2_APP_ERR01;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, 0);

  assert_not_null(strm);
  assert_true(strm->flags & NGTCP2_STRM_FLAG_SHUT_WR);

  ngtcp2_conn_del(conn);

  /* STOP_SENDING against local bidirectional stream which has not
     been initiated. */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STOP_SENDING;
  fr.stop_sending.stream_id = 1;
  fr.stop_sending.app_error_code = NGTCP2_APP_ERR01;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(NGTCP2_ERR_STREAM_STATE, ==, rv);

  ngtcp2_conn_del(conn);

  /* Receiving STOP_SENDING for a local unidirectional stream */
  setup_default_server(&conn);

  rv = ngtcp2_conn_open_uni_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  fr.type = NGTCP2_FRAME_STOP_SENDING;
  fr.stop_sending.stream_id = stream_id;
  fr.stop_sending.app_error_code = NGTCP2_APP_ERR01;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  assert_true(strm->flags & NGTCP2_STRM_FLAG_SEND_RESET_STREAM);

  ngtcp2_conn_del(conn);

  /* STOP_SENDING against local unidirectional stream which has not
     been initiated. */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STOP_SENDING;
  fr.stop_sending.stream_id = 3;
  fr.stop_sending.app_error_code = NGTCP2_APP_ERR01;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(NGTCP2_ERR_STREAM_STATE, ==, rv);

  ngtcp2_conn_del(conn);

  /* STOP_SENDING against local bidirectional stream in Data Sent
     state.  Because all data have been acknowledged, and FIN is sent,
     RESET_STREAM is not necessary. */
  setup_default_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_FIN, stream_id,
                                     null_data, 1, 1);

  assert_ptrdiff(0, <, spktlen);

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = conn->pktns.tx.last_pkt_num;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 0, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(0, ==, rv);

  fr.type = NGTCP2_FRAME_STOP_SENDING;
  fr.stop_sending.stream_id = stream_id;
  fr.stop_sending.app_error_code = NGTCP2_APP_ERR01;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(0, ==, rv);
  assert_null(conn->pktns.tx.frq);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_stream_data_blocked(void) {
  ngtcp2_conn *conn;
  int rv;
  uint8_t buf[2048];
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_strm *strm;
  ngtcp2_tstamp t = 0;
  int64_t pkt_num = 0;
  int64_t stream_id;
  ngtcp2_settings settings;
  ngtcp2_transport_params params;

  /* Receive STREAM_DATA_BLOCKED to locally initiated stream. */
  setup_default_client(&conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  fr.type = NGTCP2_FRAME_STREAM_DATA_BLOCKED;
  fr.stream_data_blocked.stream_id = stream_id;
  fr.stream_data_blocked.offset = 65535;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  assert_uint64(65535, ==, strm->rx.last_offset);
  assert_uint64(65535, ==, conn->rx.offset);

  ngtcp2_conn_del(conn);

  /* Receive STREAM_DATA_BLOCKED to a local stream which is not opened
     yet. */
  setup_default_client(&conn);

  fr.type = NGTCP2_FRAME_STREAM_DATA_BLOCKED;
  fr.stream_data_blocked.stream_id = 0;
  fr.stream_data_blocked.offset = 65535;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_STREAM_STATE, ==, rv);

  ngtcp2_conn_del(conn);

  /* Receive STREAM_DATA_BLOCKED to a remote bidirectional stream
     which is not opened yet. */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM_DATA_BLOCKED;
  fr.stream_data_blocked.stream_id = 0;
  fr.stream_data_blocked.offset = 65535;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, 0);

  assert_uint64(65535, ==, strm->rx.last_offset);
  assert_uint64(65535, ==, conn->rx.offset);

  ngtcp2_conn_del(conn);

  /* Receive STREAM_DATA_BLOCKED to a remote stream which exceeds
     bidirectional streams limit */
  setup_default_client(&conn);

  fr.type = NGTCP2_FRAME_STREAM_DATA_BLOCKED;
  fr.stream_data_blocked.stream_id = 1;
  fr.stream_data_blocked.offset = 65535;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_STREAM_LIMIT, ==, rv);

  ngtcp2_conn_del(conn);

  /* Receive STREAM_DATA_BLOCKED which violates stream data limit. */
  setup_default_client(&conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  fr.type = NGTCP2_FRAME_STREAM_DATA_BLOCKED;
  fr.stream_data_blocked.stream_id = stream_id;
  fr.stream_data_blocked.offset = 65536;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_FLOW_CONTROL, ==, rv);

  ngtcp2_conn_del(conn);

  /* Receive STREAM_DATA_BLOCKED which violates connection data
     limit. */
  client_default_settings(&settings);
  client_default_transport_params(&params);
  params.initial_max_stream_data_bidi_local = 256 * 1024;
  setup_default_client_settings(&conn, &null_path.path, &settings, &params);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  fr.type = NGTCP2_FRAME_STREAM_DATA_BLOCKED;
  fr.stream_data_blocked.stream_id = stream_id;
  fr.stream_data_blocked.offset = 128 * 1024 + 1;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_FLOW_CONTROL, ==, rv);

  ngtcp2_conn_del(conn);

  /* Receive RESET_STREAM, and then STREAM_DATA_BLOCKED. */
  setup_default_client(&conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = stream_id;
  fr.reset_stream.app_error_code = NGTCP2_NO_ERROR;
  fr.reset_stream.final_size = 11999;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  assert_uint64(11999, ==, strm->rx.last_offset);
  assert_uint64(11999, ==, conn->rx.offset);

  fr.type = NGTCP2_FRAME_STREAM_DATA_BLOCKED;
  fr.stream_data_blocked.stream_id = stream_id;
  fr.stream_data_blocked.offset = 11999;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_uint64(11999, ==, strm->rx.last_offset);
  assert_uint64(11999, ==, conn->rx.offset);

  ngtcp2_conn_del(conn);

  /* Receive RESET_STREAM, and then STREAM_DATA_BLOCKED which exceeds
     final size. */
  setup_default_client(&conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = stream_id;
  fr.reset_stream.app_error_code = NGTCP2_NO_ERROR;
  fr.reset_stream.final_size = 11999;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  assert_uint64(11999, ==, strm->rx.last_offset);
  assert_uint64(11999, ==, conn->rx.offset);

  fr.type = NGTCP2_FRAME_STREAM_DATA_BLOCKED;
  fr.stream_data_blocked.stream_id = stream_id;
  fr.stream_data_blocked.offset = 12000;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_FINAL_SIZE, ==, rv);

  ngtcp2_conn_del(conn);

  /* Send STOP_SENDING, and then receive STREAM_DATA_BLOCKED. */
  setup_default_client(&conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  rv = ngtcp2_conn_shutdown_stream_read(conn, 0, stream_id, NGTCP2_NO_ERROR);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  assert_true(strm->flags & NGTCP2_STRM_FLAG_STOP_SENDING);

  fr.type = NGTCP2_FRAME_STREAM_DATA_BLOCKED;
  fr.stream_data_blocked.stream_id = stream_id;
  fr.stream_data_blocked.offset = 7777;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  assert_uint64(7777, ==, strm->rx.last_offset);
  assert_uint64(7777, ==, conn->rx.offset);
  assert_uint64(128 * 1024 + 7777, ==, conn->rx.unsent_max_offset);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = stream_id;
  fr.stream.fin = 0;
  fr.stream.offset = 7755;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 23;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_uint64(7778, ==, strm->rx.last_offset);
  assert_uint64(7778, ==, conn->rx.offset);
  assert_uint64(128 * 1024 + 7778, ==, conn->rx.unsent_max_offset);

  ngtcp2_conn_del(conn);

  /* Decreasing STREAM_DATA_BLOCKED offset. */
  setup_default_client(&conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  fr.type = NGTCP2_FRAME_STREAM_DATA_BLOCKED;
  fr.stream_data_blocked.stream_id = stream_id;
  fr.stream_data_blocked.offset = 999;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  assert_uint64(999, ==, strm->rx.last_offset);
  assert_uint64(999, ==, conn->rx.offset);
  assert_uint64(128 * 1024, ==, conn->rx.unsent_max_offset);

  fr.type = NGTCP2_FRAME_STREAM_DATA_BLOCKED;
  fr.stream_data_blocked.stream_id = stream_id;
  fr.stream_data_blocked.offset = 998;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_uint64(999, ==, strm->rx.last_offset);
  assert_uint64(999, ==, conn->rx.offset);
  assert_uint64(128 * 1024, ==, conn->rx.unsent_max_offset);

  ngtcp2_conn_del(conn);

  /* Receive STREAM_DATA_BLOCKED to a local unidirectional stream. */
  setup_default_client(&conn);

  ngtcp2_conn_open_uni_stream(conn, &stream_id, NULL);

  fr.type = NGTCP2_FRAME_STREAM_DATA_BLOCKED;
  fr.stream_data_blocked.stream_id = stream_id;
  fr.stream_data_blocked.offset = 1;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_STREAM_STATE, ==, rv);

  ngtcp2_conn_del(conn);

  /* Receive STREAM_DATA_BLOCKED to a remote unidirectional stream. */
  setup_default_client(&conn);

  fr.type = NGTCP2_FRAME_STREAM_DATA_BLOCKED;
  fr.stream_data_blocked.stream_id = 3;
  fr.stream_data_blocked.offset = 719;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, 3);

  assert_uint64(719, ==, strm->rx.last_offset);
  assert_true(strm->flags & NGTCP2_STRM_FLAG_SHUT_WR);
  assert_uint64(719, ==, conn->rx.offset);

  ngtcp2_conn_del(conn);

  /* Receive STREAM_DATA_BLOCKED which violates unidirectional streams
     limit. */
  setup_default_client(&conn);

  fr.type = NGTCP2_FRAME_STREAM_DATA_BLOCKED;
  fr.stream_data_blocked.stream_id = 11;
  fr.stream_data_blocked.offset = 719;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_STREAM_LIMIT, ==, rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_conn_id_omitted(void) {
  ngtcp2_conn *conn;
  int rv;
  uint8_t buf[2048];
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_ksl_it it;
  ngtcp2_scid *scid;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 100;
  fr.stream.data[0].base = null_data;

  /* Receiving packet which has no connection ID while SCID of server
     is not empty. */
  setup_default_server(&conn);

  pktlen = write_pkt(buf, sizeof(buf), /* dcid = */ NULL, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  /* packet is just ignored */
  assert_int(0, ==, rv);
  assert_null(ngtcp2_conn_find_stream(conn, 4));

  ngtcp2_conn_del(conn);

  /* Allow omission of connection ID */
  setup_default_server(&conn);
  ngtcp2_cid_zero(&conn->oscid);

  it = ngtcp2_ksl_begin(&conn->scid.set);
  scid = ngtcp2_ksl_it_get(&it);
  ngtcp2_cid_zero(&scid->cid);

  pktlen = write_pkt(buf, sizeof(buf), /* dcid = */ NULL, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(0, ==, rv);
  assert_not_null(ngtcp2_conn_find_stream(conn, 4));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_short_pkt_type(void) {
  ngtcp2_conn *conn;
  ngtcp2_pkt_hd hd;
  uint8_t buf[2048];
  ngtcp2_ssize spktlen;
  int64_t stream_id;

  /* 1 octet pkt num */
  setup_default_client(&conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 19, 1);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(
      0, <,
      pkt_decode_hd_short_mask(&hd, buf, (size_t)spktlen, conn->oscid.datalen));
  assert_size(1, ==, hd.pkt_numlen);

  ngtcp2_conn_del(conn);

  /* 2 octets pkt num */
  setup_default_client(&conn);
  conn->pktns.rtb.largest_acked_tx_pkt_num = 0x6afa2f;
  conn->pktns.tx.last_pkt_num = 0x6afd78;

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 19, 1);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(
      0, <,
      pkt_decode_hd_short_mask(&hd, buf, (size_t)spktlen, conn->oscid.datalen));
  assert_size(2, ==, hd.pkt_numlen);

  ngtcp2_conn_del(conn);

  /* 4 octets pkt num */
  setup_default_client(&conn);
  conn->pktns.rtb.largest_acked_tx_pkt_num = 0x6afa2f;
  conn->pktns.tx.last_pkt_num = 0x6bc106;

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 19, 1);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(
      0, <,
      pkt_decode_hd_short_mask(&hd, buf, (size_t)spktlen, conn->oscid.datalen));
  assert_size(3, ==, hd.pkt_numlen);

  ngtcp2_conn_del(conn);

  /* 1 octet pkt num (largest)*/
  setup_default_client(&conn);
  conn->pktns.rtb.largest_acked_tx_pkt_num = 1;
  conn->pktns.tx.last_pkt_num = 128;

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 19, 1);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(
      0, <,
      pkt_decode_hd_short_mask(&hd, buf, (size_t)spktlen, conn->oscid.datalen));
  assert_size(1, ==, hd.pkt_numlen);

  ngtcp2_conn_del(conn);

  /* 2 octet pkt num (shortest)*/
  setup_default_client(&conn);
  conn->pktns.rtb.largest_acked_tx_pkt_num = 1;
  conn->pktns.tx.last_pkt_num = 129;

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 19, 1);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(
      0, <,
      pkt_decode_hd_short_mask(&hd, buf, (size_t)spktlen, conn->oscid.datalen));
  assert_size(2, ==, hd.pkt_numlen);

  ngtcp2_conn_del(conn);

  /* 2 octet pkt num (largest)*/
  setup_default_client(&conn);
  conn->pktns.rtb.largest_acked_tx_pkt_num = 1;
  conn->pktns.tx.last_pkt_num = 32768;

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 19, 1);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(
      0, <,
      pkt_decode_hd_short(&hd, buf, (size_t)spktlen, conn->oscid.datalen));
  assert_size(2, ==, hd.pkt_numlen);

  ngtcp2_conn_del(conn);

  /* 3 octet pkt num (shortest) */
  setup_default_client(&conn);
  conn->pktns.rtb.largest_acked_tx_pkt_num = 1;
  conn->pktns.tx.last_pkt_num = 32769;

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 19, 1);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(
      0, <,
      pkt_decode_hd_short(&hd, buf, (size_t)spktlen, conn->oscid.datalen));
  assert_size(3, ==, hd.pkt_numlen);

  ngtcp2_conn_del(conn);

  /* 3 octet pkt num (largest) */
  setup_default_client(&conn);
  conn->pktns.rtb.largest_acked_tx_pkt_num = 1;
  conn->pktns.tx.last_pkt_num = 8388608;

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 19, 1);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(
      0, <,
      pkt_decode_hd_short(&hd, buf, (size_t)spktlen, conn->oscid.datalen));
  assert_size(3, ==, hd.pkt_numlen);

  ngtcp2_conn_del(conn);

  /* 4 octet pkt num (shortest)*/
  setup_default_client(&conn);
  conn->pktns.rtb.largest_acked_tx_pkt_num = 1;
  conn->pktns.tx.last_pkt_num = 8388609;

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 19, 1);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(
      0, <,
      pkt_decode_hd_short(&hd, buf, (size_t)spktlen, conn->oscid.datalen));
  assert_size(4, ==, hd.pkt_numlen);

  ngtcp2_conn_del(conn);

  /* Overflow */
  setup_default_client(&conn);
  conn->pktns.rtb.largest_acked_tx_pkt_num = 1;
  conn->pktns.tx.last_pkt_num = NGTCP2_MAX_PKT_NUM - 1;

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 19, 1);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(
      0, <,
      pkt_decode_hd_short(&hd, buf, (size_t)spktlen, conn->oscid.datalen));
  assert_size(4, ==, hd.pkt_numlen);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_data_blocked(void) {
  ngtcp2_conn *conn;
  int rv;
  uint8_t buf[2048];
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_tstamp t = 0;
  int64_t pkt_num = 0;

  setup_default_client(&conn);

  fr.type = NGTCP2_FRAME_DATA_BLOCKED;
  fr.data_blocked.offset = 128 * 1024;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  ngtcp2_conn_del(conn);

  /* Frame violates flow control limit. */
  setup_default_client(&conn);

  fr.type = NGTCP2_FRAME_DATA_BLOCKED;
  fr.data_blocked.offset = 128 * 1024 + 1;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_FLOW_CONTROL, ==, rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_stateless_reset(void) {
  ngtcp2_conn *conn;
  uint8_t buf[256];
  ngtcp2_ssize spktlen;
  int rv;
  size_t i;
  uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN];

  for (i = 0; i < NGTCP2_STATELESS_RESET_TOKENLEN; ++i) {
    token[i] = (uint8_t)~i;
  }

  /* server */
  setup_default_server(&conn);
  conn->callbacks.decrypt = fail_decrypt;
  conn->pktns.rx.max_pkt_num = 24324325;

  ngtcp2_dcid_set_token(&conn->dcid.current, token);

  spktlen = ngtcp2_pkt_write_stateless_reset(
      buf, sizeof(buf), token, null_data, NGTCP2_MIN_STATELESS_RESET_RANDLEN);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf,
                            (size_t)spktlen, 1);

  assert_int(NGTCP2_ERR_DRAINING, ==, rv);
  assert_int((int)NGTCP2_CS_DRAINING, ==, (int)conn->state);

  ngtcp2_conn_del(conn);

  /* client */
  setup_default_client(&conn);
  conn->callbacks.decrypt = fail_decrypt;
  conn->pktns.rx.max_pkt_num = 3255454;

  ngtcp2_dcid_set_token(&conn->dcid.current, token);

  spktlen =
      ngtcp2_pkt_write_stateless_reset(buf, sizeof(buf), token, null_data, 29);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf,
                            (size_t)spktlen, 1);

  assert_int(NGTCP2_ERR_DRAINING, ==, rv);
  assert_int((int)NGTCP2_CS_DRAINING, ==, (int)conn->state);

  ngtcp2_conn_del(conn);

  /* stateless reset in long packet */
  setup_default_server(&conn);
  conn->callbacks.decrypt = fail_decrypt;
  conn->pktns.rx.max_pkt_num = 754233;

  ngtcp2_dcid_set_token(&conn->dcid.current, token);

  spktlen = ngtcp2_pkt_write_stateless_reset(
      buf, sizeof(buf), token, null_data, NGTCP2_MIN_STATELESS_RESET_RANDLEN);

  assert_ptrdiff(0, <, spktlen);

  /* long packet */
  buf[0] |= NGTCP2_HEADER_FORM_BIT;

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf,
                            (size_t)spktlen, 1);

  assert_int(NGTCP2_ERR_DRAINING, ==, rv);
  assert_int((int)NGTCP2_CS_DRAINING, ==, (int)conn->state);

  ngtcp2_conn_del(conn);

  /* stateless reset in long packet; parsing long header fails */
  setup_default_server(&conn);
  conn->callbacks.decrypt = fail_decrypt;
  conn->pktns.rx.max_pkt_num = 754233;

  ngtcp2_dcid_set_token(&conn->dcid.current, token);

  spktlen = ngtcp2_pkt_write_stateless_reset(
      buf, 41, token, null_data, NGTCP2_MIN_STATELESS_RESET_RANDLEN);

  assert_ptrdiff(0, <, spktlen);

  /* long packet */
  buf[0] |= NGTCP2_HEADER_FORM_BIT;
  buf[0] |= 0x30;
  /* Make version nonzero so that it does not look like Version
     Negotiation packet */
  buf[1] = 0xff;
  /* Make largest CID so that ngtcp2_pkt_decode_hd_long fails */
  buf[5] = 0xff;

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf,
                            (size_t)spktlen, 1);

  assert_int(NGTCP2_ERR_DRAINING, ==, rv);
  assert_int((int)NGTCP2_CS_DRAINING, ==, (int)conn->state);

  ngtcp2_conn_del(conn);

  /* token does not match */
  setup_default_client(&conn);
  conn->callbacks.decrypt = fail_decrypt;
  conn->pktns.rx.max_pkt_num = 24324325;

  spktlen =
      ngtcp2_pkt_write_stateless_reset(buf, sizeof(buf), token, null_data, 29);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf,
                            (size_t)spktlen, 1);

  assert_int(0, ==, rv);
  assert_int((int)NGTCP2_CS_DRAINING, !=, (int)conn->state);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_retry(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  ngtcp2_ssize spktlen;
  uint64_t t = 0;
  ngtcp2_cid dcid;
  const uint8_t token[] = "address-validation-token";
  size_t i;
  int64_t stream_id;
  ngtcp2_ssize datalen;
  int rv;
  ngtcp2_vec datav;
  ngtcp2_strm *strm;
  ngtcp2_crypto_aead aead = {0};
  ngtcp2_crypto_aead_ctx aead_ctx = {0};

  dcid_init(&dcid);
  setup_handshake_client(&conn);
  conn->callbacks.recv_retry = recv_retry;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  spktlen = ngtcp2_pkt_write_retry(
      buf, sizeof(buf), NGTCP2_PROTO_VER_V1, &conn->oscid, &dcid,
      ngtcp2_conn_get_dcid(conn), token, strsize(token), null_encrypt, &aead,
      &aead_ctx);

  assert_ptrdiff(0, <, spktlen);

  for (i = 0; i < 2; ++i) {
    rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf,
                              (size_t)spktlen, ++t);

    assert_int(0, ==, rv);

    spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

    if (i == 1) {
      /* Retry packet was ignored */
      assert_ptrdiff(0, ==, spktlen);
    } else {
      assert_ptrdiff(0, <, spktlen);
      assert_int64(1, ==, conn->in_pktns->tx.last_pkt_num);
      assert_true(ngtcp2_cid_eq(&dcid, ngtcp2_conn_get_dcid(conn)));
      assert_true(conn->flags & NGTCP2_CONN_FLAG_RECV_RETRY);
    }
  }

  ngtcp2_conn_del(conn);

  /* Retry packet with non-matching tag is rejected */
  setup_handshake_client(&conn);
  conn->callbacks.recv_retry = recv_retry;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  spktlen = ngtcp2_pkt_write_retry(
      buf, sizeof(buf), NGTCP2_PROTO_VER_V1, &conn->oscid, &dcid,
      ngtcp2_conn_get_dcid(conn), token, strsize(token), null_encrypt, &aead,
      &aead_ctx);

  assert_ptrdiff(0, <, spktlen);

  /* Change tag */
  buf[spktlen - 1] = 1;

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf,
                            (size_t)spktlen, ++t);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, ==, spktlen);

  ngtcp2_conn_del(conn);

  /* Make sure that 0RTT packets are retransmitted */
  setup_early_client(&conn);
  conn->callbacks.recv_retry = recv_retry;

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen =
      ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, sizeof(buf), &datalen,
                                NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                null_datav(&datav, 219), 1, ++t);

  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, ==, spktlen);
  assert_ptrdiff(219, ==, datalen);

  spktlen =
      ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, sizeof(buf), &datalen,
                                NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                null_datav(&datav, 119), 1, ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(119, ==, datalen);

  spktlen = ngtcp2_pkt_write_retry(
      buf, sizeof(buf), NGTCP2_PROTO_VER_V1, &conn->oscid, &dcid,
      ngtcp2_conn_get_dcid(conn), token, strsize(token), null_encrypt, &aead,
      &aead_ctx);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf,
                            (size_t)spktlen, ++t);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  /* Make sure that resent 0RTT packet is padded */
  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, ==, spktlen);
  assert_int64(2, ==, conn->pktns.tx.last_pkt_num);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  assert_size(0, ==, ngtcp2_ksl_len(strm->tx.streamfrq));

  /* ngtcp2_conn_write_stream sends new 0RTT packet. */
  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf),
                                     &datalen, NGTCP2_WRITE_STREAM_FLAG_NONE,
                                     stream_id, null_data, 120, ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_int64(3, ==, conn->pktns.tx.last_pkt_num);
  assert_ptrdiff(120, ==, datalen);
  assert_null(conn->pktns.tx.frq);
  assert_false(ngtcp2_rtb_empty(&conn->pktns.rtb));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_delayed_handshake_pkt(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_frame fr;
  int rv;

  setup_default_client(&conn);

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 567;
  fr.stream.data[0].base = null_data;

  pktlen = write_handshake_pkt(buf, sizeof(buf), &conn->oscid,
                               ngtcp2_conn_get_dcid(conn), 1,
                               NGTCP2_PROTO_VER_V1, &fr, 1, &null_ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(0, ==, rv);
  assert_size(1, ==, ngtcp2_ksl_len(&conn->hs_pktns->acktr.ents));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_max_streams(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  int rv;
  ngtcp2_frame fr;

  setup_default_client(&conn);

  fr.type = NGTCP2_FRAME_MAX_STREAMS_UNI;
  fr.max_streams.max_streams = 999;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 1);

  assert_int(0, ==, rv);
  assert_uint64(999, ==, conn->local.uni.max_streams);

  fr.type = NGTCP2_FRAME_MAX_STREAMS_BIDI;
  fr.max_streams.max_streams = 997;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 2, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 2);

  assert_int(0, ==, rv);
  assert_uint64(997, ==, conn->local.bidi.max_streams);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_handshake(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_frame fr;
  int64_t pkt_num = 12345689;
  ngtcp2_tstamp t = 0;
  ngtcp2_cid rcid;
  int rv;
  int64_t stream_id;
  ngtcp2_ssize nwrite;
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  ngtcp2_crypto_ctx crypto_ctx;
  ngtcp2_strm *strm;

  rcid_init(&rcid);

  /* Make sure server Initial is padded */
  setup_handshake_server(&conn);
  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1200;
  fr.stream.data[0].base = null_data;

  pktlen = write_initial_pkt(
      buf, sizeof(buf), &rcid, ngtcp2_conn_get_dcid(conn), ++pkt_num,
      conn->client_chosen_version, NULL, 0, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1200, <=, spktlen);

  ngtcp2_conn_del(conn);

  /* Make sure server Handshake is padded when ack-eliciting Initial
     is coalesced. */
  setup_handshake_server(&conn);
  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1200;
  fr.stream.data[0].base = null_data;

  pktlen = write_initial_pkt(
      buf, sizeof(buf), &rcid, ngtcp2_conn_get_dcid(conn), ++pkt_num,
      conn->client_chosen_version, NULL, 0, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,
                                 null_data, 91);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1200, <=, spktlen);
  assert_size(1, ==, ngtcp2_ksl_len(&conn->hs_pktns->rtb.ents));

  ngtcp2_conn_del(conn);

  /* Make sure that client packet is padded if it includes Initial and
     0RTT packets */
  setup_early_client(&conn);

  conn->callbacks.client_initial = client_initial_large_crypto_early_data;

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  /* First packet should only includes Initial.  No space for 0RTT. */
  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, 1280, &nwrite,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 10, ++t);

  assert_ptrdiff(1280, ==, spktlen);
  assert_ptrdiff(-1, ==, nwrite);

  /* Second packet has a room for 0RTT. */
  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, 1280, &nwrite,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 10, ++t);

  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, ==, spktlen);
  assert_ptrdiff(10, ==, nwrite);

  /* We have no data to send. */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, 1280, ++t);

  assert_ptrdiff(0, ==, spktlen);

  ngtcp2_conn_del(conn);

  /* Make sure that client non ack-eliciting Initial triggers
     padding. */
  setup_handshake_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1200, <=, spktlen);

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1200;
  fr.stream.data[0].base = null_data;

  pktlen = write_initial_pkt(
      buf, sizeof(buf), &conn->oscid, ngtcp2_conn_get_dcid(conn), ++pkt_num,
      conn->client_chosen_version, NULL, 0, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  init_crypto_ctx(&crypto_ctx);
  ngtcp2_conn_set_crypto_ctx(conn, &crypto_ctx);
  ngtcp2_conn_install_rx_handshake_key(conn, &aead_ctx, null_iv,
                                       sizeof(null_iv), &hp_ctx);
  ngtcp2_conn_install_tx_handshake_key(conn, &aead_ctx, null_iv,
                                       sizeof(null_iv), &hp_ctx);

  pktlen = write_handshake_pkt(buf, sizeof(buf), &conn->oscid,
                               ngtcp2_conn_get_dcid(conn), ++pkt_num,
                               conn->client_chosen_version, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1200, <=, spktlen);

  ngtcp2_conn_del(conn);

  /* Make sure padding is done in 1-RTT packet */
  setup_handshake_server(&conn);

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1200;
  fr.stream.data[0].base = null_data;

  pktlen = write_initial_pkt(
      buf, sizeof(buf), &conn->oscid, ngtcp2_conn_get_dcid(conn), ++pkt_num,
      conn->client_chosen_version, NULL, 0, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,
                                 null_data, 511);

  ngtcp2_conn_install_rx_key(conn, null_secret, sizeof(null_secret), &aead_ctx,
                             null_iv, sizeof(null_iv), &hp_ctx);
  ngtcp2_conn_install_tx_key(conn, null_secret, sizeof(null_secret), &aead_ctx,
                             null_iv, sizeof(null_iv), &hp_ctx);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1200, <=, spktlen);
  assert_size(1, ==, ngtcp2_ksl_len(&conn->pktns.rtb.ents));

  rv = ngtcp2_conn_on_loss_detection_timer(conn, ++t);

  assert_int(0, ==, rv);
  assert_size(1, ==, conn->in_pktns->rtb.probe_pkt_left);
  assert_size(1, ==, conn->hs_pktns->rtb.probe_pkt_left);

  /* Check retransmission also pads packet in 1-RTT packet */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1200, <=, spktlen);
  assert_size(2, ==, ngtcp2_ksl_len(&conn->pktns.rtb.ents));

  ngtcp2_conn_del(conn);

  /* 0-RTT packet contains PADDING even if stream data is blocked */
  setup_early_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);
  strm->tx.max_offset = 0;

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, 1280, &nwrite,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 10, ++t);

  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, ==, spktlen);
  assert_ptrdiff(-1, ==, nwrite);
  assert_size(1, ==, ngtcp2_ksl_len(&conn->pktns.rtb.ents));

  rv = ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL,
                                      null_data, 23);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, 1280, &nwrite,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 10, ++t);

  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, ==, spktlen);
  assert_ptrdiff(-1, ==, nwrite);
  assert_size(2, ==, ngtcp2_ksl_len(&conn->pktns.rtb.ents));

  ngtcp2_conn_del(conn);

  /* 0-RTT packet contains PADDING enve if stream data is blocked with
     NGTCP2_WRITE_STREAM_FLAG_MORE */
  setup_early_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);
  strm->tx.max_offset = 0;

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, 1280, &nwrite,
                                     NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                     null_data, 10, ++t);

  assert_ptrdiff(NGTCP2_ERR_STREAM_DATA_BLOCKED, ==, spktlen);
  assert_ptrdiff(-1, ==, nwrite);
  assert_size(0, ==, ngtcp2_ksl_len(&conn->pktns.rtb.ents));

  spktlen =
      ngtcp2_conn_write_stream(conn, NULL, NULL, buf, 1280, NULL,
                               NGTCP2_WRITE_STREAM_FLAG_MORE, -1, NULL, 0, ++t);

  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, ==, spktlen);
  assert_size(1, ==, ngtcp2_ksl_len(&conn->pktns.rtb.ents));

  rv = ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL,
                                      null_data, 23);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, 1280, &nwrite,
                                     NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                     null_data, 10, ++t);

  assert_ptrdiff(NGTCP2_ERR_STREAM_DATA_BLOCKED, ==, spktlen);
  assert_ptrdiff(-1, ==, nwrite);
  assert_size(1, ==, ngtcp2_ksl_len(&conn->pktns.rtb.ents));

  spktlen =
      ngtcp2_conn_write_stream(conn, NULL, NULL, buf, 1280, NULL,
                               NGTCP2_WRITE_STREAM_FLAG_MORE, -1, NULL, 0, ++t);

  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, ==, spktlen);
  assert_size(2, ==, ngtcp2_ksl_len(&conn->pktns.rtb.ents));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_handshake_error(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_frame fr;
  int64_t pkt_num = 107;
  ngtcp2_tstamp t = 0;
  ngtcp2_cid rcid;
  int rv;

  rcid_init(&rcid);

  /* client side */
  setup_handshake_client(&conn);
  conn->callbacks.recv_crypto_data = recv_crypto_handshake_error;
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 333;
  fr.stream.data[0].base = null_data;

  pktlen = write_initial_pkt(
      buf, sizeof(buf), &conn->oscid, ngtcp2_conn_get_dcid(conn), ++pkt_num,
      conn->client_chosen_version, NULL, 0, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_CRYPTO, ==, rv);

  ngtcp2_conn_del(conn);

  /* server side */
  setup_handshake_server(&conn);
  conn->callbacks.recv_crypto_data = recv_crypto_handshake_error;

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1200;
  fr.stream.data[0].base = null_data;

  pktlen = write_initial_pkt(
      buf, sizeof(buf), &rcid, ngtcp2_conn_get_dcid(conn), ++pkt_num,
      conn->client_chosen_version, NULL, 0, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_CRYPTO, ==, rv);

  ngtcp2_conn_del(conn);

  /* server side; wrong version */
  setup_handshake_server(&conn);
  conn->callbacks.recv_crypto_data = recv_crypto_handshake_error;

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1201;
  fr.stream.data[0].base = null_data;

  pktlen =
      write_initial_pkt(buf, sizeof(buf), &rcid, ngtcp2_conn_get_dcid(conn),
                        ++pkt_num, 0xffff, NULL, 0, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_DROP_CONN, ==, rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_retransmit_protected(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 0;
  int64_t stream_id, stream_id_a, stream_id_b;
  ngtcp2_ksl_it it;
  ngtcp2_frame fr;
  ngtcp2_frame frs[2];
  size_t pktlen;
  ngtcp2_vec datav;
  int accepted;
  int rv;
  ngtcp2_strm *strm;
  ngtcp2_rtb_entry *ent;
  ngtcp2_frame_chain *frc;

  /* Retransmit a packet completely */
  setup_default_client(&conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 126, ++t);

  assert_ptrdiff(0, <, spktlen);

  /* Kick delayed ACK timer */
  t += NGTCP2_SECONDS;

  conn->pktns.tx.last_pkt_num = 1000000009;
  conn->pktns.rtb.largest_acked_tx_pkt_num = 1000000007;
  it = ngtcp2_rtb_head(&conn->pktns.rtb);
  ngtcp2_conn_detect_lost_pkt(conn, &conn->pktns, &conn->cstat, ++t);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  assert_size(1, ==, strm->tx.loss_count);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_null(conn->pktns.tx.frq);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);

  assert_false(ngtcp2_ksl_it_end(&it));

  ngtcp2_conn_del(conn);

  /* Retransmission takes place per frame basis. */
  setup_default_client(&conn);
  conn->local.bidi.max_streams = 3;

  ngtcp2_conn_open_bidi_stream(conn, &stream_id_a, NULL);
  ngtcp2_conn_open_bidi_stream(conn, &stream_id_b, NULL);

  ngtcp2_conn_shutdown_stream_write(conn, 0, stream_id_a, NGTCP2_APP_ERR01);
  ngtcp2_conn_shutdown_stream_write(conn, 0, stream_id_b, NGTCP2_APP_ERR01);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  /* Kick delayed ACK timer */
  t += NGTCP2_SECONDS;

  conn->pktns.tx.last_pkt_num = 1000000009;
  conn->pktns.rtb.largest_acked_tx_pkt_num = 1000000007;
  it = ngtcp2_rtb_head(&conn->pktns.rtb);
  ngtcp2_conn_detect_lost_pkt(conn, &conn->pktns, &conn->cstat, ++t);
  spktlen =
      ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, (size_t)(spktlen - 1), ++t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);

  assert_false(ngtcp2_ksl_it_end(&it));
  assert_not_null(conn->pktns.tx.frq);

  ngtcp2_conn_del(conn);

  /* DATAGRAM frame must not be retransmitted */
  setup_default_client(&conn);

  conn->callbacks.ack_datagram = ack_datagram;
  conn->remote.transport_params->max_datagram_frame_size = 65535;

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = conn->pktns.tx.last_pkt_num;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 0, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  datav.base = null_data;
  datav.len = 99;

  spktlen = ngtcp2_conn_writev_datagram(
      conn, NULL, NULL, buf, sizeof(buf), &accepted,
      NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 1000000009, &datav, 1, ++t);

  assert_ptrdiff(0, <, spktlen);

  /* Kick delayed ACK timer */
  t += NGTCP2_SECONDS;

  conn->pktns.tx.last_pkt_num = 1000000009;
  conn->pktns.rtb.largest_acked_tx_pkt_num = 1000000007;
  it = ngtcp2_rtb_head(&conn->pktns.rtb);
  ngtcp2_conn_detect_lost_pkt(conn, &conn->pktns, &conn->cstat, ++t);
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, ==, spktlen);
  assert_null(conn->pktns.tx.frq);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);

  assert_false(ngtcp2_ksl_it_end(&it));

  ngtcp2_conn_del(conn);

  /* Retransmit an empty STREAM frame */
  setup_default_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = conn->pktns.tx.last_pkt_num;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 0, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     NULL, 0, ++t);

  assert_ptrdiff(0, <, spktlen);

  /* Kick delayed ACK timer */
  t += NGTCP2_SECONDS;

  conn->pktns.tx.last_pkt_num = 1000000009;
  conn->pktns.rtb.largest_acked_tx_pkt_num = 1000000007;
  it = ngtcp2_rtb_head(&conn->pktns.rtb);
  ngtcp2_conn_detect_lost_pkt(conn, &conn->pktns, &conn->cstat, ++t);
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_null(conn->pktns.tx.frq);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);

  assert_false(ngtcp2_ksl_it_end(&it));

  ent = ngtcp2_ksl_it_get(&it);
  frc = ent->frc;

  assert_uint64(NGTCP2_FRAME_STREAM, ==, frc->fr.type);
  assert_uint64(0, ==, frc->fr.stream.offset);
  assert_size(0, ==, frc->fr.stream.datacnt);

  ngtcp2_conn_del(conn);

  /* Do not retransmit an empty STREAM frame if we have written
     non-zero data on that stream. */
  setup_default_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = conn->pktns.tx.last_pkt_num;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 0, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     NULL, 0, ++t);

  assert_ptrdiff(0, <, spktlen);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 10, ++t);

  assert_ptrdiff(0, <, spktlen);

  /* Kick delayed ACK timer */
  t += NGTCP2_SECONDS;

  conn->pktns.tx.last_pkt_num = 1000000009;
  conn->pktns.rtb.largest_acked_tx_pkt_num = 1000000007;
  it = ngtcp2_rtb_head(&conn->pktns.rtb);
  ngtcp2_conn_detect_lost_pkt(conn, &conn->pktns, &conn->cstat, ++t);
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_null(conn->pktns.tx.frq);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);

  assert_false(ngtcp2_ksl_it_end(&it));

  ent = ngtcp2_ksl_it_get(&it);
  frc = ent->frc;

  assert_uint64(NGTCP2_FRAME_STREAM, ==, frc->fr.type);
  assert_uint64(0, ==, frc->fr.stream.offset);
  assert_size(1, ==, frc->fr.stream.datacnt);
  assert_size(10, ==, frc->fr.stream.data[0].len);

  ngtcp2_conn_del(conn);

  /* Do not retransmit STREAM frame if RESET_STREAM is submitted. */
  setup_default_client(&conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 11, ++t);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_shutdown_stream_write(conn, 0, stream_id, NGTCP2_APP_ERR01);

  assert_int(0, ==, rv);

  spktlen =
      ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                               NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, ++t);

  assert_ptrdiff(0, <, spktlen);

  t += NGTCP2_SECONDS;

  conn->pktns.rtb.largest_acked_tx_pkt_num = 1000;
  ngtcp2_conn_detect_lost_pkt(conn, &conn->pktns, &conn->cstat, ++t);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  assert_size(0, ==, strm->tx.loss_count);
  assert_true(ngtcp2_strm_streamfrq_empty(strm));

  ngtcp2_conn_del(conn);

  /* Do not retransmit RESET_STREAM frame if stream is gone. */
  setup_default_client(&conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_FIN, stream_id,
                                     null_data, 11, ++t);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_shutdown_stream_write(conn, 0, stream_id, NGTCP2_APP_ERR01);

  assert_int(0, ==, rv);

  spktlen =
      ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                               NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, ++t);

  assert_ptrdiff(0, <, spktlen);

  frs[0].type = NGTCP2_FRAME_STREAM;
  frs[0].stream.flags = 0;
  frs[0].stream.fin = 1;
  frs[0].stream.stream_id = stream_id;
  frs[0].stream.offset = 0;
  frs[0].stream.datacnt = 0;
  frs[1].type = NGTCP2_FRAME_ACK;
  frs[1].ack.largest_ack = 0;
  frs[1].ack.ack_delay = 0;
  frs[1].ack.first_ack_range = 0;
  frs[1].ack.rangecnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 0, frs, 2,
                     conn->pktns.crypto.tx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_null(ngtcp2_conn_find_stream(conn, stream_id));

  t += NGTCP2_SECONDS;

  conn->pktns.rtb.largest_acked_tx_pkt_num = 1000;
  ngtcp2_conn_detect_lost_pkt(conn, &conn->pktns, &conn->cstat, ++t);

  spktlen =
      ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                               NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, ++t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);
  ent = ngtcp2_ksl_it_get(&it);

  assert_uint64(NGTCP2_FRAME_RESET_STREAM, ==, ent->frc->fr.type);
  assert_int64(1, ==, ent->hd.pkt_num);
  assert_null(ent->frc->next);

  ngtcp2_ksl_it_next(&it);

  assert_true(ngtcp2_ksl_it_end(&it));

  ngtcp2_conn_del(conn);

  /* Do not retransmit STOP_SENDING frame if stream is gone. */
  setup_default_client(&conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_FIN, stream_id,
                                     null_data, 11, ++t);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_shutdown_stream_read(conn, 0, stream_id, NGTCP2_APP_ERR01);

  assert_int(0, ==, rv);

  spktlen =
      ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                               NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, ++t);

  assert_ptrdiff(0, <, spktlen);

  frs[0].type = NGTCP2_FRAME_STREAM;
  frs[0].stream.flags = 0;
  frs[0].stream.fin = 1;
  frs[0].stream.stream_id = stream_id;
  frs[0].stream.offset = 0;
  frs[0].stream.datacnt = 0;
  frs[1].type = NGTCP2_FRAME_ACK;
  frs[1].ack.largest_ack = 0;
  frs[1].ack.ack_delay = 0;
  frs[1].ack.first_ack_range = 0;
  frs[1].ack.rangecnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 0, frs, 2,
                     conn->pktns.crypto.tx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_null(ngtcp2_conn_find_stream(conn, stream_id));

  t += NGTCP2_SECONDS;

  conn->pktns.rtb.largest_acked_tx_pkt_num = 1000;
  ngtcp2_conn_detect_lost_pkt(conn, &conn->pktns, &conn->cstat, ++t);

  spktlen =
      ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                               NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, ++t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);
  ent = ngtcp2_ksl_it_get(&it);

  assert_uint64(NGTCP2_FRAME_STOP_SENDING, ==, ent->frc->fr.type);
  assert_int64(1, ==, ent->hd.pkt_num);
  assert_null(ent->frc->next);

  ngtcp2_ksl_it_next(&it);

  assert_true(ngtcp2_ksl_it_end(&it));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_send_max_stream_data(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_strm *strm;
  int64_t pkt_num = 890;
  ngtcp2_tstamp t = 0;
  ngtcp2_frame fr;
  int rv;
  const uint32_t datalen = 1024;
  uint64_t max_stream_data;
  ngtcp2_ssize spktlen;

  /* MAX_STREAM_DATA should be sent */
  setup_default_server(&conn);
  conn->local.transport_params.initial_max_stream_data_bidi_remote = datalen;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = datalen;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_extend_max_stream_offset(conn, 4, datalen);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, 4);

  assert_true(ngtcp2_strm_is_tx_queued(strm));

  ngtcp2_conn_del(conn);

  /* MAX_STREAM_DATA should not be sent on incoming fin */
  setup_default_server(&conn);
  conn->local.transport_params.initial_max_stream_data_bidi_remote = datalen;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 1;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = datalen;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_extend_max_stream_offset(conn, 4, datalen);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, 4);

  assert_false(ngtcp2_strm_is_tx_queued(strm));

  ngtcp2_conn_del(conn);

  /* MAX_STREAM_DATA should not be sent if STOP_SENDING frame is being
     sent by local endpoint */
  setup_default_server(&conn);
  conn->local.transport_params.initial_max_stream_data_bidi_remote = datalen;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = datalen;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_shutdown_stream_read(conn, 0, 4, NGTCP2_APP_ERR01);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_extend_max_stream_offset(conn, 4, datalen);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, 4);
  max_stream_data = strm->rx.max_offset;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_uint64(max_stream_data, ==, strm->rx.max_offset);

  ngtcp2_conn_del(conn);

  /* MAX_STREAM_DATA should not be sent if stream is being reset by
     remote endpoint */
  setup_default_server(&conn);
  conn->local.transport_params.initial_max_stream_data_bidi_remote = datalen;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = datalen;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 4;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR01;
  fr.reset_stream.final_size = datalen;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_extend_max_stream_offset(conn, 4, datalen);

  assert_int(0, ==, rv);
  assert_true(ngtcp2_pq_empty(&conn->tx.strmq));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_stream_data(void) {
  uint8_t buf[1024];
  ngtcp2_conn *conn;
  my_user_data ud;
  int64_t pkt_num = 612;
  ngtcp2_tstamp t = 0;
  ngtcp2_frame fr;
  size_t pktlen;
  int rv;
  int64_t stream_id;
  size_t i;

  /* 2 STREAM frames are received in the correct order. */
  setup_default_server(&conn);
  conn->callbacks.recv_stream_data = recv_stream_data;
  conn->user_data = &ud;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 111;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(4, ==, ud.stream_data.stream_id);
  assert_false(ud.stream_data.flags & NGTCP2_STREAM_DATA_FLAG_FIN);
  assert_false(ud.stream_data.flags & NGTCP2_STREAM_DATA_FLAG_0RTT);
  assert_size(111, ==, ud.stream_data.datalen);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 1;
  fr.stream.offset = 111;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 99;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(4, ==, ud.stream_data.stream_id);
  assert_true(ud.stream_data.flags & NGTCP2_STREAM_DATA_FLAG_FIN);
  assert_size(99, ==, ud.stream_data.datalen);

  ngtcp2_conn_del(conn);

  /* 2 STREAM frames are received in the correct order, and 2nd STREAM
     frame has 0 length, and FIN bit set. */
  setup_default_server(&conn);
  conn->callbacks.recv_stream_data = recv_stream_data;
  conn->user_data = &ud;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 111;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(4, ==, ud.stream_data.stream_id);
  assert_false(ud.stream_data.flags & NGTCP2_STREAM_DATA_FLAG_FIN);
  assert_size(111, ==, ud.stream_data.datalen);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 1;
  fr.stream.offset = 111;
  fr.stream.datacnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(4, ==, ud.stream_data.stream_id);
  assert_true(ud.stream_data.flags & NGTCP2_STREAM_DATA_FLAG_FIN);
  assert_size(0, ==, ud.stream_data.datalen);

  ngtcp2_conn_del(conn);

  /* 2 identical STREAM frames with FIN bit set are received.  The
     recv_stream_data callback should not be called for second STREAM
     frame. */
  setup_default_server(&conn);
  conn->callbacks.recv_stream_data = recv_stream_data;
  conn->user_data = &ud;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 1;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 111;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(4, ==, ud.stream_data.stream_id);
  assert_true(ud.stream_data.flags & NGTCP2_STREAM_DATA_FLAG_FIN);
  assert_size(111, ==, ud.stream_data.datalen);

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(0, ==, ud.stream_data.stream_id);
  assert_false(ud.stream_data.flags & NGTCP2_STREAM_DATA_FLAG_FIN);
  assert_size(0, ==, ud.stream_data.datalen);

  ngtcp2_conn_del(conn);

  /* Re-ordered STREAM frame; we first gets 0 length STREAM frame with
     FIN bit set. Then the remaining STREAM frame is received. */
  setup_default_server(&conn);
  conn->callbacks.recv_stream_data = recv_stream_data;
  conn->user_data = &ud;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 1;
  fr.stream.offset = 599;
  fr.stream.datacnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(0, ==, ud.stream_data.stream_id);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 599;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(4, ==, ud.stream_data.stream_id);
  assert_true(ud.stream_data.flags & NGTCP2_STREAM_DATA_FLAG_FIN);
  assert_size(599, ==, ud.stream_data.datalen);

  ngtcp2_conn_del(conn);

  /* Simulate the case where packet is lost.  We first gets 0 length
     STREAM frame with FIN bit set.  Then the lost STREAM frame is
     retransmitted with FIN bit set is received. */
  setup_default_server(&conn);
  conn->callbacks.recv_stream_data = recv_stream_data;
  conn->user_data = &ud;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 1;
  fr.stream.offset = 599;
  fr.stream.datacnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(0, ==, ud.stream_data.stream_id);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 1;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 599;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(4, ==, ud.stream_data.stream_id);
  assert_true(ud.stream_data.flags & NGTCP2_STREAM_DATA_FLAG_FIN);
  assert_size(599, ==, ud.stream_data.datalen);

  ngtcp2_conn_del(conn);

  /* Receive an unidirectional stream data */
  setup_default_client(&conn);
  conn->callbacks.recv_stream_data = recv_stream_data;
  conn->user_data = &ud;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 3;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 911;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(3, ==, ud.stream_data.stream_id);
  assert_false(ud.stream_data.flags & NGTCP2_STREAM_DATA_FLAG_FIN);
  assert_size(911, ==, ud.stream_data.datalen);

  ngtcp2_conn_del(conn);

  /* Receive an unidirectional stream which is beyond the limit. */
  setup_default_server(&conn);
  conn->callbacks.recv_stream_data = recv_stream_data;
  conn->remote.uni.max_streams = 0;
  conn->user_data = &ud;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 2;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 911;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_STREAM_LIMIT, ==, rv);

  ngtcp2_conn_del(conn);

  /* Receiving nonzero payload for an local unidirectional stream is a
     protocol violation. */
  setup_default_client(&conn);

  rv = ngtcp2_conn_open_uni_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = stream_id;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 9;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_STREAM_STATE, ==, rv);

  ngtcp2_conn_del(conn);

  /* DATA on crypto stream, and TLS alert is generated. */
  setup_default_server(&conn);
  conn->callbacks.recv_crypto_data = recv_crypto_fatal_alert_generated;

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 139;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_CRYPTO, ==, rv);

  ngtcp2_conn_del(conn);

  /* 0 length STREAM frame is allowed */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_not_null(ngtcp2_conn_find_stream(conn, 4));

  ngtcp2_conn_del(conn);

  /* After sending STOP_SENDING, receiving 2 STREAM frames with fin
     bit set must not invoke recv_stream_data callback. */
  setup_default_server(&conn);
  conn->callbacks.recv_stream_data = recv_stream_data;
  conn->user_data = &ud;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_not_null(ngtcp2_conn_find_stream(conn, 4));

  rv = ngtcp2_conn_shutdown_stream_read(conn, 0, 4, 99);

  assert_int(0, ==, rv);

  for (i = 0; i < 2; ++i) {
    fr.type = NGTCP2_FRAME_STREAM;
    fr.stream.stream_id = 4;
    fr.stream.fin = 1;
    fr.stream.offset = 0;
    fr.stream.datacnt = 1;
    fr.stream.data[0].base = null_data;
    fr.stream.data[0].len = 19;

    pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                       conn->pktns.crypto.rx.ckm);

    ud.stream_data.stream_id = 0;
    rv =
        ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

    assert_int(0, ==, rv);
    assert_int64(0, ==, ud.stream_data.stream_id);
    assert_uint64(19, ==, conn->rx.offset);
    assert_uint64(19, ==,
                  conn->rx.unsent_max_offset -
                      conn->local.transport_params.initial_max_data);
    assert_uint64(conn->local.transport_params.initial_max_data, ==,
                  conn->rx.max_offset);
  }

  ngtcp2_conn_del(conn);

  /* After receiving RESET_STREAM, recv_stream_data callback must not
     be invoked */
  setup_default_server(&conn);
  conn->callbacks.recv_stream_data = recv_stream_data;
  conn->user_data = &ud;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 0;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_not_null(ngtcp2_conn_find_stream(conn, 0));

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 0;
  fr.reset_stream.app_error_code = 999;
  fr.reset_stream.final_size = 199;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_not_null(ngtcp2_conn_find_stream(conn, 0));
  assert_uint64(199, ==,
                conn->rx.unsent_max_offset -
                    conn->local.transport_params.initial_max_data);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 0;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].base = null_data;
  fr.stream.data[0].len = 198;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  ud.stream_data.stream_id = -1;
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(-1, ==, ud.stream_data.stream_id);
  assert_uint64(199, ==,
                conn->rx.unsent_max_offset -
                    conn->local.transport_params.initial_max_data);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 0;
  fr.stream.fin = 1;
  fr.stream.offset = 198;
  fr.stream.datacnt = 1;
  fr.stream.data[0].base = null_data;
  fr.stream.data[0].len = 1;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  ud.stream_data.stream_id = -1;
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(-1, ==, ud.stream_data.stream_id);
  assert_uint64(199, ==,
                conn->rx.unsent_max_offset -
                    conn->local.transport_params.initial_max_data);

  ngtcp2_conn_del(conn);

  /* ngtcp2_conn_shutdown_stream_read is called in recv_stream_data
     callback.  Further recv_stream_data callback must not be
     called. */
  setup_default_server(&conn);
  conn->callbacks.recv_stream_data = recv_stream_data_shutdown_stream_read;
  conn->user_data = &ud;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 599;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(0, ==, ud.stream_data.stream_id);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 599;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(4, ==, ud.stream_data.stream_id);
  assert_false(ud.stream_data.flags & NGTCP2_STREAM_DATA_FLAG_FIN);
  assert_size(599, ==, ud.stream_data.datalen);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_ping(void) {
  uint8_t buf[1024];
  ngtcp2_conn *conn;
  int64_t pkt_num = 133;
  ngtcp2_tstamp t = 0;
  ngtcp2_frame fr;
  size_t pktlen;
  int rv;

  setup_default_client(&conn);

  fr.type = NGTCP2_FRAME_PING;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_null(conn->pktns.tx.frq);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_max_stream_data(void) {
  uint8_t buf[1024];
  ngtcp2_conn *conn;
  int64_t pkt_num = 1000000007;
  ngtcp2_tstamp t = 0;
  ngtcp2_frame fr;
  size_t pktlen;
  int rv;
  ngtcp2_strm *strm;

  /* Receiving MAX_STREAM_DATA to an uninitiated local bidirectional
     stream ID is an error */
  setup_default_client(&conn);

  fr.type = NGTCP2_FRAME_MAX_STREAM_DATA;
  fr.max_stream_data.stream_id = 4;
  fr.max_stream_data.max_stream_data = 8092;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_STREAM_STATE, ==, rv);

  ngtcp2_conn_del(conn);

  /* Receiving MAX_STREAM_DATA to an uninitiated local unidirectional
     stream ID is an error */
  setup_default_client(&conn);

  fr.type = NGTCP2_FRAME_MAX_STREAM_DATA;
  fr.max_stream_data.stream_id = 2;
  fr.max_stream_data.max_stream_data = 8092;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_STREAM_STATE, ==, rv);

  ngtcp2_conn_del(conn);

  /* Receiving MAX_STREAM_DATA to a remote bidirectional stream which
     exceeds limit */
  setup_default_client(&conn);

  fr.type = NGTCP2_FRAME_MAX_STREAM_DATA;
  fr.max_stream_data.stream_id = 1;
  fr.max_stream_data.max_stream_data = 1000000009;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_STREAM_LIMIT, ==, rv);

  ngtcp2_conn_del(conn);

  /* Receiving MAX_STREAM_DATA to a remote bidirectional stream which
     the local endpoint has not received yet. */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_MAX_STREAM_DATA;
  fr.max_stream_data.stream_id = 4;
  fr.max_stream_data.max_stream_data = 1000000009;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, 4);

  assert_not_null(strm);
  assert_uint64(1000000009, ==, strm->tx.max_offset);

  ngtcp2_conn_del(conn);

  /* Receiving MAX_STREAM_DATA to a idle remote unidirectional stream
     is a protocol violation. */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_MAX_STREAM_DATA;
  fr.max_stream_data.stream_id = 2;
  fr.max_stream_data.max_stream_data = 1000000009;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_STREAM_STATE, ==, rv);

  ngtcp2_conn_del(conn);

  /* Receiving MAX_STREAM_DATA to an existing bidirectional stream */
  setup_default_server(&conn);

  strm = open_stream(conn, 4);

  fr.type = NGTCP2_FRAME_MAX_STREAM_DATA;
  fr.max_stream_data.stream_id = 4;
  fr.max_stream_data.max_stream_data = 1000000009;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_uint64(1000000009, ==, strm->tx.max_offset);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_send_early_data(void) {
  ngtcp2_conn *conn;
  ngtcp2_ssize spktlen;
  ngtcp2_ssize datalen;
  uint8_t buf[1024];
  int64_t stream_id;
  int rv;
  ngtcp2_tstamp t = 0;
  ngtcp2_vec datav;

  setup_early_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf),
                                     &datalen, NGTCP2_WRITE_STREAM_FLAG_FIN,
                                     stream_id, null_data, 1024, ++t);

  assert_ptrdiff((ngtcp2_ssize)sizeof(buf), ==, spktlen);
  assert_ptrdiff(670, ==, datalen);

  ngtcp2_conn_del(conn);

  /* Verify that Handshake packet and 0-RTT packet are coalesced into
     one UDP packet. */
  setup_early_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen =
      ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, sizeof(buf), &datalen,
                                NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                null_datav(&datav, 199), 1, ++t);

  assert_ptrdiff(sizeof(buf), ==, spktlen);
  assert_ptrdiff(199, ==, datalen);

  ngtcp2_conn_del(conn);

  /* 0 length 0-RTT packet with FIN bit set */
  setup_early_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, sizeof(buf),
                                      &datalen, NGTCP2_WRITE_STREAM_FLAG_FIN,
                                      stream_id, NULL, 0, ++t);

  assert_ptrdiff(sizeof(buf), ==, spktlen);
  assert_ptrdiff(0, ==, datalen);

  ngtcp2_conn_del(conn);

  /* Can write 0 length STREAM frame */
  setup_early_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, sizeof(buf),
                                      &datalen, NGTCP2_WRITE_STREAM_FLAG_NONE,
                                      -1, NULL, 0, ++t);

  assert_ptrdiff(0, <, spktlen);

  /* We have written Initial.  Now check that STREAM frame is
     written. */
  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, sizeof(buf),
                                      &datalen, NGTCP2_WRITE_STREAM_FLAG_NONE,
                                      stream_id, NULL, 0, ++t);

  assert_ptrdiff(0, <, spktlen);

  ngtcp2_conn_del(conn);

  /* Could not send 0-RTT data because buffer is too small. */
  setup_early_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_writev_stream(
      conn, NULL, NULL, buf,
      NGTCP2_MIN_LONG_HEADERLEN + 1 + ngtcp2_conn_get_dcid(conn)->datalen +
          conn->oscid.datalen + 300,
      &datalen, NGTCP2_WRITE_STREAM_FLAG_FIN, stream_id, NULL, 0, ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(-1, ==, datalen);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_early_data(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_frame fr;
  int64_t pkt_num = 1;
  ngtcp2_tstamp t = 0;
  ngtcp2_strm *strm;
  ngtcp2_cid rcid;
  int rv;
  my_user_data ud;

  rcid_init(&rcid);

  setup_early_server(&conn);
  conn->callbacks.recv_stream_data = recv_stream_data;
  conn->user_data = &ud;

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1221;
  fr.stream.data[0].base = null_data;

  pktlen = write_initial_pkt(
      buf, sizeof(buf), &rcid, ngtcp2_conn_get_dcid(conn), ++pkt_num,
      conn->client_chosen_version, NULL, 0, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  /* NEW_CONNECTION_ID frame is generated */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, ==, spktlen);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 1;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 911;
  fr.stream.data[0].base = null_data;

  pktlen =
      write_0rtt_pkt(buf, sizeof(buf), &rcid, ngtcp2_conn_get_dcid(conn),
                     ++pkt_num, conn->client_chosen_version, &fr, 1, &null_ckm);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(4, ==, ud.stream_data.stream_id);
  assert_true(ud.stream_data.flags & NGTCP2_STREAM_DATA_FLAG_0RTT);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, ==, spktlen);

  strm = ngtcp2_conn_find_stream(conn, 4);

  assert_not_null(strm);
  assert_uint64(911, ==, strm->rx.last_offset);

  ngtcp2_conn_del(conn);

  /* Re-ordered 0-RTT packet */
  setup_early_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 1;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 119;
  fr.stream.data[0].base = null_data;

  pktlen =
      write_0rtt_pkt(buf, sizeof(buf), &rcid, ngtcp2_conn_get_dcid(conn),
                     ++pkt_num, conn->client_chosen_version, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_DROP_CONN, ==, rv);

  ngtcp2_conn_del(conn);

  /* Compound packet */
  setup_early_server(&conn);

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 111;
  fr.stream.data[0].base = null_data;

  pktlen = write_initial_pkt(
      buf, sizeof(buf), &rcid, ngtcp2_conn_get_dcid(conn), ++pkt_num,
      conn->client_chosen_version, NULL, 0, &fr, 1, &null_ckm);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 1;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 999;
  fr.stream.data[0].base = null_data;

  pktlen += write_0rtt_pkt(buf + pktlen, sizeof(buf) - pktlen, &rcid,
                           ngtcp2_conn_get_dcid(conn), ++pkt_num,
                           conn->client_chosen_version, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  strm = ngtcp2_conn_find_stream(conn, 4);

  assert_not_null(strm);
  assert_uint64(999, ==, strm->rx.last_offset);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_compound_pkt(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_frame fr;
  int64_t pkt_num = 1;
  ngtcp2_tstamp t = 0;
  ngtcp2_acktr_entry *ackent;
  int rv;
  ngtcp2_ksl_it it;

  /* 2 QUIC long packets in one UDP packet */
  setup_handshake_server(&conn);

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 611;
  fr.stream.data[0].base = null_data;

  pktlen = write_initial_pkt(
      buf, sizeof(buf), &conn->oscid, ngtcp2_conn_get_dcid(conn), ++pkt_num,
      conn->client_chosen_version, NULL, 0, &fr, 1, &null_ckm);

  pktlen += write_initial_pkt(buf + pktlen, sizeof(buf) - pktlen, &conn->oscid,
                              ngtcp2_conn_get_dcid(conn), ++pkt_num,
                              conn->client_chosen_version, NULL, 0, &fr, 1,
                              &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_acktr_get(&conn->in_pktns->acktr);
  ackent = ngtcp2_ksl_it_get(&it);

  assert_int64(pkt_num, ==, ackent->pkt_num);
  assert_size(2, ==, ackent->len);

  ngtcp2_ksl_it_next(&it);

  assert_true(ngtcp2_ksl_it_end(&it));

  ngtcp2_conn_del(conn);

  /* 1 long packet and 1 short packet in one UDP packet */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_PADDING;
  fr.padding.len = 1;

  pktlen = write_handshake_pkt(buf, sizeof(buf), &conn->oscid,
                               ngtcp2_conn_get_dcid(conn), ++pkt_num,
                               conn->client_chosen_version, &fr, 1, &null_ckm);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 426;
  fr.stream.data[0].base = null_data;

  pktlen += write_pkt(buf + pktlen, sizeof(buf) - pktlen, &conn->oscid,
                      ++pkt_num, &fr, 1, conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  it = ngtcp2_acktr_get(&conn->pktns.acktr);
  ackent = ngtcp2_ksl_it_get(&it);

  assert_int64(pkt_num, ==, ackent->pkt_num);

  it = ngtcp2_acktr_get(&conn->hs_pktns->acktr);

  assert_false(ngtcp2_ksl_it_end(&it));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_pkt_payloadlen(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_frame fr;
  int64_t pkt_num = 1;
  ngtcp2_tstamp t = 0;
  uint64_t payloadlen;
  int rv;
  const ngtcp2_cid *dcid;

  /* Payload length is invalid */
  setup_handshake_server(&conn);

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1231;
  fr.stream.data[0].base = null_data;

  dcid = ngtcp2_conn_get_dcid(conn);

  pktlen = write_initial_pkt(buf, sizeof(buf), &conn->oscid, dcid, ++pkt_num,
                             conn->client_chosen_version, NULL, 0, &fr, 1,
                             &null_ckm);

  payloadlen = read_pkt_payloadlen(buf, dcid, &conn->oscid);
  write_pkt_payloadlen(buf, dcid, &conn->oscid, payloadlen + 1);

  /* This first packet which does not increase initial packet number
     space CRYPTO offset or it does not get buffered as 0RTT is an
     error.  But it is unsecured Initial, so we just ignore it. */
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_DROP_CONN, ==, rv);
  assert_int((int)NGTCP2_CS_SERVER_INITIAL, ==, (int)conn->state);

  ngtcp2_conn_del(conn);

  /* Client Initial packet included in UDP datagram smaller than 1200
     is discarded. */
  setup_handshake_server(&conn);

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1000;
  fr.stream.data[0].base = null_data;

  pktlen = write_initial_pkt(buf, sizeof(buf), &conn->oscid,
                             ngtcp2_conn_get_dcid(conn), 0, NGTCP2_PROTO_VER_V1,
                             NULL, 0, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_DROP_CONN, ==, rv);
  assert_int((int)NGTCP2_CS_SERVER_INITIAL, ==, (int)conn->state);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_writev_stream(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 0;
  int rv;
  int64_t stream_id;
  ngtcp2_vec datav = {null_data, 10};
  ngtcp2_ssize datalen;
  size_t left;
  ngtcp2_strm *strm;
  ngtcp2_frame fr;
  size_t pktlen;
  int64_t pkt_num = 0;
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};

  /* 0 length STREAM should not be written if we supply nonzero length
     data. */
  setup_default_client(&conn);

  /* This will sends NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  /*
   * Long header (1+18+1)
   * STREAM overhead (+3)
   * AEAD overhead (16)
   */
  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 39, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                      &datav, 1, ++t);

  assert_ptrdiff(0, ==, spktlen);
  assert_ptrdiff(-1, ==, datalen);

  ngtcp2_conn_del(conn);

  /* +1 buffer size */
  setup_default_client(&conn);

  /* This will sends NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 40, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                      &datav, 1, ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(1, ==, datalen);

  ngtcp2_conn_del(conn);

  /* Coalesces multiple STREAM frames */
  setup_default_client(&conn);
  conn->local.bidi.max_streams = 100;

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                      &datav, 1, ++t);

  assert_ptrdiff(NGTCP2_ERR_WRITE_MORE, ==, spktlen);
  assert_ptrdiff(10, ==, datalen);

  left = ngtcp2_ppe_left(&conn->pkt.ppe);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                      &datav, 1, ++t);

  assert_ptrdiff(NGTCP2_ERR_WRITE_MORE, ==, spktlen);
  assert_ptrdiff(10, ==, datalen);
  assert_size(left, >, ngtcp2_ppe_left(&conn->pkt.ppe));

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  ngtcp2_conn_del(conn);

  /* 0RTT: Coalesces multiple STREAM frames */
  setup_early_client(&conn);
  conn->local.bidi.max_streams = 100;

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                      &datav, 1, ++t);

  assert_ptrdiff(NGTCP2_ERR_WRITE_MORE, ==, spktlen);
  assert_ptrdiff(10, ==, datalen);

  left = ngtcp2_ppe_left(&conn->pkt.ppe);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                      &datav, 1, ++t);

  assert_ptrdiff(NGTCP2_ERR_WRITE_MORE, ==, spktlen);
  assert_ptrdiff(10, ==, datalen);
  assert_size(left, >, ngtcp2_ppe_left(&conn->pkt.ppe));

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  /* Make sure that packet is padded */
  assert_ptrdiff(1200, ==, spktlen);

  ngtcp2_conn_del(conn);

  /* 0RTT: Stream data blocked */
  setup_early_client(&conn);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, NULL,
                                      NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL,
                                      0, ++t);

  assert_ptrdiff(1200, <=, spktlen);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);
  strm->tx.max_offset = 0;

  /* This will send STREAM_DATA_BLOCKED */
  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                      &datav, 1, ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(-1, ==, datalen);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                      &datav, 1, ++t);

  assert_ptrdiff(NGTCP2_ERR_STREAM_DATA_BLOCKED, ==, spktlen);
  assert_ptrdiff(-1, ==, datalen);

  ngtcp2_conn_del(conn);

  /* 1RTT: Stream data blocked */
  setup_default_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);
  strm->tx.max_offset = 0;

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, NULL,
                                      NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL,
                                      0, ++t);

  assert_ptrdiff(0, <, spktlen);

  /* This will send STREAM_DATA_BLOCKED */
  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                      &datav, 1, ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(-1, ==, datalen);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                      &datav, 1, ++t);

  assert_ptrdiff(NGTCP2_ERR_STREAM_DATA_BLOCKED, ==, spktlen);
  assert_ptrdiff(-1, ==, datalen);

  ngtcp2_conn_del(conn);

  /* 1RTT: Stream data blocked with NGTCP2_WRITE_STREAM_FLAG_MORE */
  setup_default_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);
  strm->tx.max_offset = 0;

  /* This will send STREAM_DATA_BLOCKED */
  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                      &datav, 1, ++t);

  assert_ptrdiff(NGTCP2_ERR_STREAM_DATA_BLOCKED, ==, spktlen);
  assert_ptrdiff(-1, ==, datalen);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                      &datav, 1, ++t);

  assert_ptrdiff(NGTCP2_ERR_STREAM_DATA_BLOCKED, ==, spktlen);
  assert_ptrdiff(-1, ==, datalen);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, NULL,
                                      NGTCP2_WRITE_STREAM_FLAG_MORE, -1, NULL,
                                      0, ++t);

  assert_ptrdiff(0, <, spktlen);

  ngtcp2_conn_del(conn);

  /* 1RTT: Stream data blocked when attempting coalescing packet */
  setup_handshake_server(&conn);

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1200;
  fr.stream.data[0].base = null_data;

  pktlen = write_initial_pkt(
      buf, sizeof(buf), &conn->oscid, ngtcp2_conn_get_dcid(conn), ++pkt_num,
      conn->client_chosen_version, NULL, 0, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,
                                 null_data, 111);

  ngtcp2_conn_install_rx_key(conn, null_secret, sizeof(null_secret), &aead_ctx,
                             null_iv, sizeof(null_iv), &hp_ctx);
  ngtcp2_conn_install_tx_key(conn, null_secret, sizeof(null_secret), &aead_ctx,
                             null_iv, sizeof(null_iv), &hp_ctx);

  conn->local.uni.max_streams = 1;
  conn->tx.max_offset = 1000;

  rv = ngtcp2_conn_open_uni_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                      &datav, 1, ++t);

  assert_ptrdiff(1200, <=, spktlen);
  assert_ptrdiff(-1, ==, datalen);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  assert_uint64(0, ==, strm->tx.last_blocked_offset);

  rv = ngtcp2_conn_on_loss_detection_timer(conn, ++t);

  assert_int(0, ==, rv);
  assert_size(1, ==, conn->in_pktns->rtb.probe_pkt_left);
  assert_size(1, ==, conn->hs_pktns->rtb.probe_pkt_left);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, NULL,
                                      NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                      &datav, 1, ++t);

  assert_ptrdiff(1200, <=, spktlen);
  assert_ptrdiff(-1, ==, datalen);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, NULL,
                                      NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                      &datav, 1, ++t);

  assert_ptrdiff(NGTCP2_ERR_STREAM_DATA_BLOCKED, ==, spktlen);
  assert_ptrdiff(-1, ==, datalen);

  ngtcp2_conn_del(conn);

  /* 1RTT: Stream data blocked when attempting coalescing packet with
     NGTCP2_WRITE_STREAM_FLAG_MORE */
  setup_handshake_server(&conn);

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1200;
  fr.stream.data[0].base = null_data;

  pktlen = write_initial_pkt(
      buf, sizeof(buf), &conn->oscid, ngtcp2_conn_get_dcid(conn), ++pkt_num,
      conn->client_chosen_version, NULL, 0, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,
                                 null_data, 111);

  ngtcp2_conn_install_rx_key(conn, null_secret, sizeof(null_secret), &aead_ctx,
                             null_iv, sizeof(null_iv), &hp_ctx);
  ngtcp2_conn_install_tx_key(conn, null_secret, sizeof(null_secret), &aead_ctx,
                             null_iv, sizeof(null_iv), &hp_ctx);

  conn->local.uni.max_streams = 1;
  conn->tx.max_offset = 1000;

  rv = ngtcp2_conn_open_uni_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                      &datav, 1, ++t);

  assert_ptrdiff(NGTCP2_ERR_STREAM_DATA_BLOCKED, ==, spktlen);
  assert_ptrdiff(-1, ==, datalen);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, NULL,
                                      NGTCP2_WRITE_STREAM_FLAG_MORE, -1, NULL,
                                      0, ++t);

  assert_ptrdiff(1200, <=, spktlen);
  assert_ptrdiff(-1, ==, datalen);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  assert_uint64(0, ==, strm->tx.last_blocked_offset);

  rv = ngtcp2_conn_on_loss_detection_timer(conn, ++t);

  assert_int(0, ==, rv);
  assert_size(1, ==, conn->in_pktns->rtb.probe_pkt_left);
  assert_size(1, ==, conn->hs_pktns->rtb.probe_pkt_left);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, NULL,
                                      NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                      &datav, 1, ++t);

  assert_ptrdiff(NGTCP2_ERR_STREAM_DATA_BLOCKED, ==, spktlen);
  assert_ptrdiff(-1, ==, datalen);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, NULL,
                                      NGTCP2_WRITE_STREAM_FLAG_MORE, -1, NULL,
                                      0, ++t);

  assert_ptrdiff(1200, <=, spktlen);
  assert_ptrdiff(-1, ==, datalen);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_writev_datagram(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 0;
  ngtcp2_vec datav = {null_data, 10};
  ngtcp2_vec vec;
  int accepted;
  my_user_data ud;
  ngtcp2_frame fr;
  size_t pktlen;
  int rv;

  setup_default_client(&conn);
  conn->callbacks.ack_datagram = ack_datagram;
  conn->remote.transport_params->max_datagram_frame_size = 1 + 1 + 10;
  conn->user_data = &ud;

  spktlen = ngtcp2_conn_writev_datagram(
      conn, NULL, NULL, buf, sizeof(buf), &accepted,
      NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 1000000009, &datav, 1, ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_true(accepted);

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = conn->pktns.tx.last_pkt_num;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 0, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  ud.datagram.dgram_id = 0;
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_uint64(1000000009, ==, ud.datagram.dgram_id);

  ngtcp2_conn_del(conn);

  /* Coalesces multiple DATAGRAM frames into a single QUIC packet */
  setup_default_client(&conn);
  conn->remote.transport_params->max_datagram_frame_size = 65535;

  spktlen = ngtcp2_conn_writev_datagram(
      conn, NULL, NULL, buf, sizeof(buf), &accepted,
      NGTCP2_WRITE_DATAGRAM_FLAG_MORE, 1000000007, &datav, 1, ++t);

  assert_ptrdiff(NGTCP2_ERR_WRITE_MORE, ==, spktlen);
  assert_true(accepted);

  spktlen = ngtcp2_conn_writev_datagram(
      conn, NULL, NULL, buf, sizeof(buf), &accepted,
      NGTCP2_WRITE_DATAGRAM_FLAG_MORE, 1000000007, &datav, 1, ++t);

  assert_ptrdiff(NGTCP2_ERR_WRITE_MORE, ==, spktlen);
  assert_true(accepted);

  spktlen = ngtcp2_conn_writev_datagram(
      conn, NULL, NULL, buf, sizeof(buf), &accepted,
      NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 0, &datav, 1, ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_true(accepted);

  ngtcp2_conn_del(conn);

  /* DATAGRAM cannot fit into QUIC packet because the other frames
     occupy the space */
  setup_default_client(&conn);
  conn->remote.transport_params->max_datagram_frame_size =
      1 + ngtcp2_put_uvarintlen(2000) + 2000;

  vec.base = null_data;
  vec.len = 2000;

  spktlen = ngtcp2_conn_writev_datagram(
      conn, NULL, NULL, buf, sizeof(buf), &accepted,
      NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 987, &vec, 1, ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_false(accepted);

  spktlen = ngtcp2_conn_writev_datagram(
      conn, NULL, NULL, buf, sizeof(buf), &accepted,
      NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 545, &vec, 1, ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_true(accepted);

  ngtcp2_conn_del(conn);

  /* Calling ngtcp2_conn_writev_datagram without receiving positive
     max_datagram_frame_size is an error */
  setup_default_client(&conn);

  spktlen = ngtcp2_conn_writev_datagram(
      conn, NULL, NULL, buf, sizeof(buf), &accepted,
      NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 999, &datav, 1, ++t);

  assert_ptrdiff(NGTCP2_ERR_INVALID_STATE, ==, spktlen);

  ngtcp2_conn_del(conn);

  /* Sending DATAGRAM which is larger than the value of received
     max_datagram_frame_size is an error */
  setup_default_client(&conn);
  conn->remote.transport_params->max_datagram_frame_size = 9;

  spktlen = ngtcp2_conn_writev_datagram(
      conn, NULL, NULL, buf, sizeof(buf), &accepted,
      NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 4433, &datav, 1, ++t);

  assert_ptrdiff(NGTCP2_ERR_INVALID_ARGUMENT, ==, spktlen);

  ngtcp2_conn_del(conn);

  /* Send DATAGRAM frame in a 0RTT packet */
  setup_early_client(&conn);

  conn->remote.transport_params->max_datagram_frame_size = 4311;

  spktlen = ngtcp2_conn_writev_datagram(
      conn, NULL, NULL, buf, sizeof(buf), &accepted,
      NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 22360679, &datav, 1, ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_true(accepted);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_datagram(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  ngtcp2_frame fr;
  size_t pktlen;
  int64_t pkt_num = 0;
  ngtcp2_tstamp t = 0;
  my_user_data ud;
  int rv;
  ngtcp2_cid rcid;

  rcid_init(&rcid);

  setup_default_server(&conn);
  conn->user_data = &ud;
  conn->callbacks.recv_datagram = recv_datagram;
  conn->local.transport_params.max_datagram_frame_size = 1 + 1111;

  fr.type = NGTCP2_FRAME_DATAGRAM;
  fr.datagram.data = fr.datagram.rdata;
  fr.datagram.data->base = null_data;
  fr.datagram.data->len = 1111;
  fr.datagram.datacnt = 1;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(1111, ==, ud.datagram.datalen);
  assert_false(NGTCP2_DATAGRAM_FLAG_0RTT & ud.datagram.flags);

  ngtcp2_conn_del(conn);

  /* Receiving DATAGRAM frame which is strictly larger than the
     declared limit is an error */
  setup_default_server(&conn);
  conn->local.transport_params.max_datagram_frame_size = 1 + 1111 - 1;

  fr.type = NGTCP2_FRAME_DATAGRAM;
  fr.datagram.data = fr.datagram.rdata;
  fr.datagram.data->base = null_data;
  fr.datagram.data->len = 1111;
  fr.datagram.datacnt = 1;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_PROTO, ==, rv);

  ngtcp2_conn_del(conn);

  /* Receiving DATAGRAM frame in a 0RTT packet */
  setup_early_server(&conn);
  conn->user_data = &ud;
  conn->callbacks.recv_datagram = recv_datagram;
  conn->local.transport_params.max_datagram_frame_size = 1 + 1111;

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1199;
  fr.stream.data[0].base = null_data;

  pktlen = write_initial_pkt(
      buf, sizeof(buf), &rcid, ngtcp2_conn_get_dcid(conn), ++pkt_num,
      conn->client_chosen_version, NULL, 0, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  fr.type = NGTCP2_FRAME_DATAGRAM;
  fr.datagram.data = fr.datagram.rdata;
  fr.datagram.data->base = null_data;
  fr.datagram.data->len = 1111;
  fr.datagram.datacnt = 1;

  pktlen =
      write_0rtt_pkt(buf, sizeof(buf), &rcid, ngtcp2_conn_get_dcid(conn),
                     ++pkt_num, conn->client_chosen_version, &fr, 1, &null_ckm);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(1111, ==, ud.datagram.datalen);
  assert_true(NGTCP2_DATAGRAM_FLAG_0RTT & ud.datagram.flags);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_new_connection_id(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 0;
  int64_t pkt_num = 0;
  ngtcp2_frame fr;
  ngtcp2_frame frs[16];
  const uint8_t cid[] = {0xf0, 0xf1, 0xf2, 0xf3};
  const uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN] = {0xff};
  const uint8_t cid2[] = {0xf0, 0xf1, 0xf2, 0xf4};
  const uint8_t token2[NGTCP2_STATELESS_RESET_TOKENLEN] = {0xfe};
  const uint8_t cid3[] = {0xf0, 0xf1, 0xf2, 0xf5};
  const uint8_t token3[NGTCP2_STATELESS_RESET_TOKENLEN] = {0xfd};
  ngtcp2_dcid *dcid;
  int rv;
  ngtcp2_frame_chain *frc;
  size_t i;

  setup_default_client(&conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  fr.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = 1;
  fr.new_connection_id.retire_prior_to = 0;
  ngtcp2_cid_init(&fr.new_connection_id.cid, cid, sizeof(cid));
  memcpy(fr.new_connection_id.stateless_reset_token, token, sizeof(token));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(1, ==, ngtcp2_ringbuf_len(&conn->dcid.unused.rb));

  dcid = ngtcp2_ringbuf_get(&conn->dcid.unused.rb, 0);

  assert_true(ngtcp2_cid_eq(&fr.new_connection_id.cid, &dcid->cid));
  assert_true(dcid->flags & NGTCP2_DCID_FLAG_TOKEN_PRESENT);
  assert_memory_equal(sizeof(fr.new_connection_id.stateless_reset_token),
                      fr.new_connection_id.stateless_reset_token, dcid->token);

  fr.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = 2;
  fr.new_connection_id.retire_prior_to = 2;
  ngtcp2_cid_init(&fr.new_connection_id.cid, cid2, sizeof(cid2));
  memcpy(fr.new_connection_id.stateless_reset_token, token2, sizeof(token2));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, ==, ngtcp2_ringbuf_len(&conn->dcid.bound.rb));
  assert_size(0, ==, ngtcp2_ringbuf_len(&conn->dcid.unused.rb));
  assert_uint64(2, ==, conn->dcid.current.seq);
  assert_not_null(conn->pktns.tx.frq);
  assert_uint64(2, ==, conn->dcid.retire_prior_to);

  frc = conn->pktns.tx.frq;

  assert_uint64(NGTCP2_FRAME_RETIRE_CONNECTION_ID, ==, frc->fr.type);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_RETIRE_CONNECTION_ID, ==, frc->fr.type);
  assert_null(frc->next);

  /* This will send RETIRE_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  ngtcp2_conn_del(conn);

  /* Received connection ID is immediately retired due to packet
     reordering */
  setup_default_client(&conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  fr.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = 2;
  fr.new_connection_id.retire_prior_to = 2;
  ngtcp2_cid_init(&fr.new_connection_id.cid, cid, sizeof(cid));
  memcpy(fr.new_connection_id.stateless_reset_token, token, sizeof(token));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, ==, ngtcp2_ringbuf_len(&conn->dcid.unused.rb));
  assert_uint64(2, ==, conn->dcid.current.seq);
  assert_uint64(2, ==, conn->dcid.retire_prior_to);

  frc = conn->pktns.tx.frq;

  assert_uint64(NGTCP2_FRAME_RETIRE_CONNECTION_ID, ==, frc->fr.type);
  assert_null(frc->next);

  /* This will send RETIRE_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  fr.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = 1;
  fr.new_connection_id.retire_prior_to = 0;
  ngtcp2_cid_init(&fr.new_connection_id.cid, cid2, sizeof(cid2));
  memcpy(fr.new_connection_id.stateless_reset_token, token2, sizeof(token2));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, ==, ngtcp2_ringbuf_len(&conn->dcid.unused.rb));
  assert_uint64(2, ==, conn->dcid.current.seq);
  assert_uint64(2, ==, conn->dcid.retire_prior_to);

  frc = conn->pktns.tx.frq;

  assert_uint64(NGTCP2_FRAME_RETIRE_CONNECTION_ID, ==, frc->fr.type);
  assert_null(frc->next);

  /* Make sure that dup check works */
  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, ==, ngtcp2_ringbuf_len(&conn->dcid.unused.rb));
  assert_uint64(2, ==, conn->dcid.current.seq);
  assert_uint64(2, ==, conn->dcid.retire_prior_to);

  frc = conn->pktns.tx.frq;

  assert_uint64(NGTCP2_FRAME_RETIRE_CONNECTION_ID, ==, frc->fr.type);
  assert_null(frc->next);

  ngtcp2_conn_del(conn);

  /* ngtcp2_pv contains DCIDs that should be retired. */
  setup_default_server(&conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  assert(NULL == conn->pv);

  frs[0].type = NGTCP2_FRAME_PING;
  frs[1].type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  frs[1].new_connection_id.seq = 1;
  frs[1].new_connection_id.retire_prior_to = 0;
  ngtcp2_cid_init(&frs[1].new_connection_id.cid, cid, sizeof(cid));
  memcpy(frs[1].new_connection_id.stateless_reset_token, token, sizeof(token));
  frs[2].type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  frs[2].new_connection_id.seq = 2;
  frs[2].new_connection_id.retire_prior_to = 0;
  ngtcp2_cid_init(&frs[2].new_connection_id.cid, cid2, sizeof(cid2));
  memcpy(frs[2].new_connection_id.stateless_reset_token, token2,
         sizeof(token2));
  frs[3].type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  frs[3].new_connection_id.seq = 3;
  frs[3].new_connection_id.retire_prior_to = 0;
  ngtcp2_cid_init(&frs[3].new_connection_id.cid, cid3, sizeof(cid3));
  memcpy(frs[3].new_connection_id.stateless_reset_token, token3,
         sizeof(token3));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, frs, 4,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  assert(NULL != conn->pv);

  assert_true(conn->pv->flags & NGTCP2_PV_FLAG_FALLBACK_ON_FAILURE);
  assert_uint64(1, ==, conn->pv->dcid.seq);
  assert_uint64(0, ==, conn->pv->fallback_dcid.seq);
  assert_size(2, ==, ngtcp2_ringbuf_len(&conn->dcid.unused.rb));

  fr.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = 3;
  fr.new_connection_id.retire_prior_to = 2;
  ngtcp2_cid_init(&fr.new_connection_id.cid, cid3, sizeof(cid3));
  memcpy(fr.new_connection_id.stateless_reset_token, token3, sizeof(token3));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, ==, ngtcp2_ringbuf_len(&conn->dcid.unused.rb));
  assert_true(conn->pv->flags & NGTCP2_PV_FLAG_FALLBACK_ON_FAILURE);
  assert_uint64(2, ==, conn->pv->dcid.seq);
  assert_uint64(3, ==, conn->pv->fallback_dcid.seq);

  frc = conn->pktns.tx.frq;

  assert_uint64(NGTCP2_FRAME_RETIRE_CONNECTION_ID, ==, frc->fr.type);
  assert_uint64(0, ==, frc->fr.retire_connection_id.seq);
  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_RETIRE_CONNECTION_ID, ==, frc->fr.type);
  assert_uint64(1, ==, frc->fr.retire_connection_id.seq);
  assert_null(frc->next);

  ngtcp2_conn_del(conn);

  /* ngtcp2_pv contains DCID in fallback that should be retired and
     there is not enough connection ID left.  */
  setup_default_server(&conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  assert(NULL == conn->pv);

  frs[0].type = NGTCP2_FRAME_PING;
  frs[1].type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  frs[1].new_connection_id.seq = 1;
  frs[1].new_connection_id.retire_prior_to = 0;
  ngtcp2_cid_init(&frs[1].new_connection_id.cid, cid, sizeof(cid));
  memcpy(frs[1].new_connection_id.stateless_reset_token, token, sizeof(token));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, frs, 2,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  assert(NULL != conn->pv);

  assert_true(conn->pv->flags & NGTCP2_PV_FLAG_FALLBACK_ON_FAILURE);
  assert_uint64(1, ==, conn->pv->dcid.seq);
  assert_uint64(0, ==, conn->pv->fallback_dcid.seq);
  assert_size(0, ==, ngtcp2_ringbuf_len(&conn->dcid.unused.rb));

  fr.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = 2;
  fr.new_connection_id.retire_prior_to = 2;
  ngtcp2_cid_init(&fr.new_connection_id.cid, cid2, sizeof(cid2));
  memcpy(fr.new_connection_id.stateless_reset_token, token2, sizeof(token2));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_uint64(2, ==, conn->dcid.current.seq);
  assert_size(0, ==, ngtcp2_ringbuf_len(&conn->dcid.unused.rb));
  assert_null(conn->pv);

  frc = conn->pktns.tx.frq;

  assert_uint64(NGTCP2_FRAME_RETIRE_CONNECTION_ID, ==, frc->fr.type);
  assert_uint64(0, ==, frc->fr.retire_connection_id.seq);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_RETIRE_CONNECTION_ID, ==, frc->fr.type);
  assert_uint64(1, ==, frc->fr.retire_connection_id.seq);
  assert_null(frc->next);

  ngtcp2_conn_del(conn);

  /* ngtcp2_pv contains DCIDs that should be retired and there is not
     enough connection ID left to continue path validation.  */
  setup_default_server(&conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  assert(NULL == conn->pv);

  frs[0].type = NGTCP2_FRAME_PING;
  frs[1].type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  frs[1].new_connection_id.seq = 1;
  frs[1].new_connection_id.retire_prior_to = 0;
  ngtcp2_cid_init(&frs[1].new_connection_id.cid, cid, sizeof(cid));
  memcpy(frs[1].new_connection_id.stateless_reset_token, token, sizeof(token));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, frs, 2,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  assert(NULL != conn->pv);

  assert_true(conn->pv->flags & NGTCP2_PV_FLAG_FALLBACK_ON_FAILURE);
  assert_uint64(1, ==, conn->pv->dcid.seq);
  assert_uint64(0, ==, conn->pv->fallback_dcid.seq);
  assert_size(0, ==, ngtcp2_ringbuf_len(&conn->dcid.unused.rb));

  /* Overwrite seq in pv->dcid so that pv->dcid cannot be renewed. */
  conn->pv->dcid.seq = 2;
  /* Internally we assume that if primary dcid and pv->dcid differ,
     then no fallback dcid is present. */
  conn->pv->flags &= (uint8_t)~NGTCP2_PV_FLAG_FALLBACK_ON_FAILURE;

  fr.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = 3;
  fr.new_connection_id.retire_prior_to = 3;
  ngtcp2_cid_init(&fr.new_connection_id.cid, cid3, sizeof(cid3));
  memcpy(fr.new_connection_id.stateless_reset_token, token3, sizeof(token3));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_uint64(3, ==, conn->dcid.current.seq);
  assert_size(0, ==, ngtcp2_ringbuf_len(&conn->dcid.unused.rb));
  assert_null(conn->pv);

  frc = conn->pktns.tx.frq;

  assert_uint64(NGTCP2_FRAME_RETIRE_CONNECTION_ID, ==, frc->fr.type);
  assert_uint64(2, ==, frc->fr.retire_connection_id.seq);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_RETIRE_CONNECTION_ID, ==, frc->fr.type);
  assert_uint64(1, ==, frc->fr.retire_connection_id.seq);
  assert_null(frc->next);

  ngtcp2_conn_del(conn);

  /* Receiving more than advertised CID is treated as error */
  setup_default_server(&conn);
  conn->local.transport_params.active_connection_id_limit = 2;

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  assert(NULL == conn->pv);

  frs[0].type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  frs[0].new_connection_id.seq = 1;
  frs[0].new_connection_id.retire_prior_to = 0;
  ngtcp2_cid_init(&frs[0].new_connection_id.cid, cid, sizeof(cid));
  memcpy(frs[0].new_connection_id.stateless_reset_token, token, sizeof(token));
  frs[1].type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  frs[1].new_connection_id.seq = 2;
  frs[1].new_connection_id.retire_prior_to = 0;
  ngtcp2_cid_init(&frs[1].new_connection_id.cid, cid2, sizeof(cid2));
  memcpy(frs[1].new_connection_id.stateless_reset_token, token2,
         sizeof(token2));
  frs[2].type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  frs[2].new_connection_id.seq = 3;
  frs[2].new_connection_id.retire_prior_to = 0;
  ngtcp2_cid_init(&frs[2].new_connection_id.cid, cid3, sizeof(cid3));
  memcpy(frs[2].new_connection_id.stateless_reset_token, token3,
         sizeof(token3));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, frs, 3,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_CONNECTION_ID_LIMIT, ==, rv);

  ngtcp2_conn_del(conn);

  /* Receiving duplicated NEW_CONNECTION_ID frame */
  setup_default_server(&conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  frs[0].type = NGTCP2_FRAME_PING;

  frs[1].type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  frs[1].new_connection_id.seq = 1;
  frs[1].new_connection_id.retire_prior_to = 1;
  ngtcp2_cid_init(&frs[1].new_connection_id.cid, cid, sizeof(cid));
  memcpy(frs[1].new_connection_id.stateless_reset_token, token, sizeof(token));

  frs[2].type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  frs[2].new_connection_id.seq = 2;
  frs[2].new_connection_id.retire_prior_to = 1;
  ngtcp2_cid_init(&frs[2].new_connection_id.cid, cid2, sizeof(cid2));
  memcpy(frs[2].new_connection_id.stateless_reset_token, token2,
         sizeof(token2));

  frs[3].type = NGTCP2_FRAME_PADDING;
  frs[3].padding.len = 1200;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, frs, 4,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, ==, ngtcp2_ringbuf_len(&conn->dcid.unused.rb));
  assert_uint64(2, ==, conn->dcid.current.seq);
  assert_not_null(conn->pv);
  assert_true(ngtcp2_cid_eq(&frs[1].new_connection_id.cid,
                            &conn->pv->fallback_dcid.cid));

  /* This will send PATH_CHALLENGE frame */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1200, <=, spktlen);

  fr.type = NGTCP2_FRAME_PATH_RESPONSE;
  memset(fr.path_response.data, 0, sizeof(fr.path_response.data));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  /* Server starts probing old path */
  assert_not_null(conn->pv);
  assert_true(ngtcp2_path_eq(&null_path.path, &conn->pv->dcid.ps.path));

  /* Receive NEW_CONNECTION_ID seq=1 again, which should be ignored. */
  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, frs, 2,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, ==, ngtcp2_ringbuf_len(&conn->dcid.unused.rb));
  assert_uint64(2, ==, conn->dcid.current.seq);

  ngtcp2_conn_del(conn);

  /* Exceeding the limit for the number of unacknowledged
     RETIRE_CONNECTION_ID leads to NGTCP2_ERR_CONNECTION_ID_LIMIT. */
  setup_default_server(&conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  for (i = 0; i < 7; ++i) {
    frs[i].type = NGTCP2_FRAME_NEW_CONNECTION_ID;
    frs[i].new_connection_id.seq = i + 1;
    frs[i].new_connection_id.retire_prior_to = 0;
    ngtcp2_cid_init(&frs[i].new_connection_id.cid, cid, sizeof(cid));
    frs[i].new_connection_id.cid.data[0] = (uint8_t)i;
    memcpy(frs[i].new_connection_id.stateless_reset_token, token,
           sizeof(token));
  }

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, frs, 7,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  for (i = 0; i < 8; ++i) {
    frs[i].type = NGTCP2_FRAME_NEW_CONNECTION_ID;
    frs[i].new_connection_id.seq = i + 8;
    frs[i].new_connection_id.retire_prior_to = 8;
    ngtcp2_cid_init(&frs[i].new_connection_id.cid, cid, sizeof(cid));
    frs[i].new_connection_id.cid.data[0] = (uint8_t)(i + 8);
    memcpy(frs[i].new_connection_id.stateless_reset_token, token,
           sizeof(token));
  }

  for (i = 0; i < 8; ++i) {
    frs[i + 8].type = NGTCP2_FRAME_NEW_CONNECTION_ID;
    frs[i + 8].new_connection_id.seq = i + 16;
    frs[i + 8].new_connection_id.retire_prior_to = 16;
    ngtcp2_cid_init(&frs[i + 8].new_connection_id.cid, cid, sizeof(cid));
    frs[i + 8].new_connection_id.cid.data[0] = (uint8_t)(i + 16);
    memcpy(frs[i + 8].new_connection_id.stateless_reset_token, token,
           sizeof(token));
  }

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, frs, 16,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  frs[0].type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  frs[0].new_connection_id.seq = 24;
  frs[0].new_connection_id.retire_prior_to = 17;
  ngtcp2_cid_init(&frs[0].new_connection_id.cid, cid, sizeof(cid));
  frs[0].new_connection_id.cid.data[0] = (uint8_t)(i + 24);
  memcpy(frs[0].new_connection_id.stateless_reset_token, token, sizeof(token));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, frs, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_CONNECTION_ID_LIMIT, ==, rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_retire_connection_id(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 1000000009;
  int64_t pkt_num = 0;
  ngtcp2_frame fr;
  int rv;
  ngtcp2_ksl_it it;
  ngtcp2_scid *scid;
  uint64_t seq;

  setup_default_client(&conn);
  conn->remote.transport_params->active_connection_id_limit = 7;

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_ksl_begin(&conn->scid.set);
  scid = ngtcp2_ksl_it_get(&it);
  seq = scid->seq;

  assert_uint8(NGTCP2_SCID_FLAG_NONE, ==, scid->flags);
  assert_uint64(UINT64_MAX, ==, scid->retired_ts);
  assert_size(1, ==, ngtcp2_pq_size(&conn->scid.used));

  fr.type = NGTCP2_FRAME_RETIRE_CONNECTION_ID;
  fr.retire_connection_id.seq = seq;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_uint8(NGTCP2_SCID_FLAG_RETIRED, ==, scid->flags);
  assert_uint64(1000000010, ==, scid->retired_ts);
  assert_size(2, ==, ngtcp2_pq_size(&conn->scid.used));
  assert_size(7, ==, ngtcp2_ksl_len(&conn->scid.set));
  assert_size(1, ==, conn->scid.num_retired);

  /* One NEW_CONNECTION_ID frame is sent as a replacement. */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(8, ==, ngtcp2_ksl_len(&conn->scid.set));
  assert_size(1, ==, conn->scid.num_retired);

  /* No NEW_CONNECTION_ID frames should be sent. */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, ==, spktlen);
  assert_size(8, ==, ngtcp2_ksl_len(&conn->scid.set));
  assert_size(1, ==, conn->scid.num_retired);

  /* Now time passed and retired connection ID is removed */
  t += 7 * NGTCP2_DEFAULT_INITIAL_RTT;

  ngtcp2_conn_handle_expiry(conn, t);

  assert_size(7, ==, ngtcp2_ksl_len(&conn->scid.set));
  assert_size(0, ==, conn->scid.num_retired);

  ngtcp2_conn_del(conn);

  /* Receiving RETIRE_CONNECTION_ID with seq which is greater than the
     sequence number previously sent must be treated as error */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_RETIRE_CONNECTION_ID;
  fr.retire_connection_id.seq = 1;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_PROTO, ==, rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_server_path_validation(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 900;
  int64_t pkt_num = 0;
  ngtcp2_frame fr;
  ngtcp2_frame frs[2];
  int rv;
  const uint8_t raw_cid[] = {0x0f, 0x00, 0x00, 0x00};
  ngtcp2_cid cid, *new_cid, orig_dcid;
  const uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN] = {0xff};
  ngtcp2_path_storage new_path1, new_path2;
  ngtcp2_ksl_it it;

  path_init(&new_path1, 0, 0, 2, 0);
  path_init(&new_path2, 0, 0, 3, 0);

  ngtcp2_cid_init(&cid, raw_cid, sizeof(raw_cid));

  setup_default_server(&conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(1, <, ngtcp2_ksl_len(&conn->scid.set));

  fr.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = 1;
  fr.new_connection_id.retire_prior_to = 0;
  fr.new_connection_id.cid = cid;
  memcpy(fr.new_connection_id.stateless_reset_token, token, sizeof(token));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  fr.type = NGTCP2_FRAME_PING;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &new_path1.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_not_null(conn->pv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(0, <, ngtcp2_ringbuf_len(&conn->pv->ents.rb));

  fr.type = NGTCP2_FRAME_PATH_RESPONSE;
  memset(fr.path_response.data, 0, sizeof(fr.path_response.data));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &new_path1.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_true(ngtcp2_path_eq(&new_path1.path, &conn->dcid.current.ps.path));
  /* DCID does not change because the client does not change its
     DCID. */
  assert_false(ngtcp2_cid_eq(&cid, &conn->dcid.current.cid));

  /* A remote endpoint changes DCID as well */
  fr.type = NGTCP2_FRAME_PING;

  it = ngtcp2_ksl_begin(&conn->scid.set);

  assert(!ngtcp2_ksl_it_end(&it));

  new_cid = &(((ngtcp2_scid *)ngtcp2_ksl_it_get(&it))->cid);

  pktlen = write_pkt(buf, sizeof(buf), new_cid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &new_path2.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_not_null(conn->pv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(0, <, ngtcp2_ringbuf_len(&conn->pv->ents.rb));

  fr.type = NGTCP2_FRAME_PATH_RESPONSE;
  memset(fr.path_response.data, 0, sizeof(fr.path_response.data));

  pktlen = write_pkt(buf, sizeof(buf), new_cid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &new_path2.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_true(ngtcp2_path_eq(&new_path2.path, &conn->dcid.current.ps.path));
  assert_true(ngtcp2_cid_eq(&cid, &conn->dcid.current.cid));

  ngtcp2_conn_del(conn);

  /* Server falls back to the original path if it is unable to verify
     that path is capable of minimum MTU that QUIC requires. */
  setup_default_server(&conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  ngtcp2_cid_init(&orig_dcid, conn->dcid.current.cid.data,
                  conn->dcid.current.cid.datalen);

  assert_ptrdiff(0, <, spktlen);
  assert_size(1, <, ngtcp2_ksl_len(&conn->scid.set));

  fr.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = 1;
  fr.new_connection_id.retire_prior_to = 0;
  fr.new_connection_id.cid = cid;
  memcpy(fr.new_connection_id.stateless_reset_token, token, sizeof(token));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  fr.type = NGTCP2_FRAME_PING;

  it = ngtcp2_ksl_begin(&conn->scid.set);

  assert(!ngtcp2_ksl_it_end(&it));

  new_cid = &(((ngtcp2_scid *)ngtcp2_ksl_it_get(&it))->cid);

  pktlen = write_pkt(buf, sizeof(buf), new_cid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_not_null(conn->pv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(0, <, ngtcp2_ringbuf_len(&conn->pv->ents.rb));

  fr.type = NGTCP2_FRAME_PATH_RESPONSE;
  memset(fr.path_response.data, 0, sizeof(fr.path_response.data));

  pktlen = write_pkt(buf, sizeof(buf), new_cid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_true(ngtcp2_path_eq(&new_path.path, &conn->dcid.current.ps.path));
  assert_true(ngtcp2_cid_eq(&cid, &conn->dcid.current.cid));

  /* Server was unable to expand PATH_CHALLENGE due to amplification
     limit.  Another path validation takes place. */
  assert_not_null(conn->pv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, <=, spktlen);
  assert_size(0, <, ngtcp2_ringbuf_len(&conn->pv->ents.rb));

  /* path validation failed due to timeout.  Path falls back to the
     original. */
  t += conn->pv->timeout;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_null(conn->pv);
  assert_true(ngtcp2_path_eq(&null_path.path, &conn->dcid.current.ps.path));
  assert_true(ngtcp2_cid_eq(&orig_dcid, &conn->dcid.current.cid));

  ngtcp2_conn_del(conn);

  /* Server starts PMTUD after successful path validation. */
  setup_default_server(&conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(1, <, ngtcp2_ksl_len(&conn->scid.set));

  fr.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = 1;
  fr.new_connection_id.retire_prior_to = 0;
  fr.new_connection_id.cid = cid;
  memcpy(fr.new_connection_id.stateless_reset_token, token, sizeof(token));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  frs[0].type = NGTCP2_FRAME_PING;
  frs[1].type = NGTCP2_FRAME_PADDING;
  frs[1].padding.len = 1200;

  it = ngtcp2_ksl_begin(&conn->scid.set);

  assert(!ngtcp2_ksl_it_end(&it));

  new_cid = &(((ngtcp2_scid *)ngtcp2_ksl_it_get(&it))->cid);

  pktlen = write_pkt(buf, sizeof(buf), new_cid, ++pkt_num, frs, 2,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_not_null(conn->pv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(0, <, ngtcp2_ringbuf_len(&conn->pv->ents.rb));
  assert_null(conn->pmtud);

  fr.type = NGTCP2_FRAME_PATH_RESPONSE;
  memset(fr.path_response.data, 0, sizeof(fr.path_response.data));

  pktlen = write_pkt(buf, sizeof(buf), new_cid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_true(ngtcp2_path_eq(&new_path.path, &conn->dcid.current.ps.path));
  assert_true(ngtcp2_cid_eq(&cid, &conn->dcid.current.cid));

  /* Server starts path validation against old path. */
  assert_not_null(conn->pv);
  assert_false(conn->pv->flags & NGTCP2_PV_FLAG_FALLBACK_ON_FAILURE);
  assert_true(conn->pv->flags & NGTCP2_PV_FLAG_DONT_CARE);
  assert_not_null(conn->pmtud);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_client_connection_migration(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_tstamp t = 900;
  int64_t pkt_num = 0;
  ngtcp2_frame fr;
  int rv;
  const uint8_t raw_cid[] = {0x0f, 0x00, 0x00, 0x00};
  ngtcp2_cid cid;
  const uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN] = {0xff};
  my_user_data ud;
  ngtcp2_ssize spktlen;
  ngtcp2_path_storage to_path;

  ngtcp2_cid_init(&cid, raw_cid, sizeof(raw_cid));

  /* immediate migration */
  setup_default_client(&conn);

  fr.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = 1;
  fr.new_connection_id.retire_prior_to = 0;
  fr.new_connection_id.cid = cid;
  memcpy(fr.new_connection_id.stateless_reset_token, token, sizeof(token));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  ngtcp2_path_storage_init2(&to_path, &new_path.path);
  to_path.path.user_data = &ud;

  rv = ngtcp2_conn_initiate_immediate_migration(conn, &to_path.path, ++t);

  assert_int(0, ==, rv);
  assert_not_null(conn->pv);
  assert_true(ngtcp2_path_eq(&to_path.path, &conn->dcid.current.ps.path));
  assert_ptr_equal(&ud, conn->dcid.current.ps.path.user_data);
  assert_true(ngtcp2_cid_eq(&cid, &conn->dcid.current.cid));
  assert_true(ngtcp2_path_eq(&to_path.path, &conn->pv->dcid.ps.path));
  assert_ptr_equal(&ud, conn->pv->dcid.ps.path.user_data);
  assert_true(ngtcp2_cid_eq(&cid, &conn->pv->dcid.cid));

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  fr.type = NGTCP2_FRAME_PATH_RESPONSE;
  memset(fr.path_response.data, 0, sizeof(fr.path_response.data));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_null(conn->pv);
  assert_true(ngtcp2_path_eq(&to_path.path, &conn->dcid.current.ps.path));
  assert_ptr_equal(&ud, conn->dcid.current.ps.path.user_data);
  assert_true(ngtcp2_cid_eq(&cid, &conn->dcid.current.cid));

  ngtcp2_conn_del(conn);

  /* migrate after successful path validation */
  setup_default_client(&conn);

  fr.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = 1;
  fr.new_connection_id.retire_prior_to = 0;
  fr.new_connection_id.cid = cid;
  memcpy(fr.new_connection_id.stateless_reset_token, token, sizeof(token));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  ngtcp2_path_storage_init2(&to_path, &new_path.path);
  to_path.path.user_data = &ud;

  rv = ngtcp2_conn_initiate_migration(conn, &to_path.path, ++t);

  assert_int(0, ==, rv);
  assert_not_null(conn->pv);
  assert_true(ngtcp2_path_eq(&null_path.path, &conn->dcid.current.ps.path));
  assert_null(conn->dcid.current.ps.path.user_data);
  assert_true(ngtcp2_cid_eq(&conn->rcid, &conn->dcid.current.cid));

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  fr.type = NGTCP2_FRAME_PATH_RESPONSE;
  memset(fr.path_response.data, 0, sizeof(fr.path_response.data));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_null(conn->pv);
  assert_true(ngtcp2_path_eq(&to_path.path, &conn->dcid.current.ps.path));
  assert_ptr_equal(&ud, conn->dcid.current.ps.path.user_data);
  assert_true(ngtcp2_cid_eq(&cid, &conn->dcid.current.cid));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_path_challenge(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 11;
  int64_t pkt_num = 0;
  ngtcp2_frame fr;
  ngtcp2_frame frs[2];
  int rv;
  const uint8_t raw_cid[] = {0x0f, 0x00, 0x00, 0x00};
  ngtcp2_cid cid;
  const uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN] = {0xff};
  const uint8_t data[] = {0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8};
  const uint8_t data2[] = {0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf9};
  ngtcp2_path_storage ps;
  ngtcp2_ssize shdlen;
  ngtcp2_pkt_hd hd;
  ngtcp2_dcid *dcid;
  ngtcp2_settings settings;
  ngtcp2_transport_params params;

  ngtcp2_cid_init(&cid, raw_cid, sizeof(raw_cid));

  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = 1;
  fr.new_connection_id.retire_prior_to = 0;
  fr.new_connection_id.cid = cid;
  memcpy(fr.new_connection_id.stateless_reset_token, token, sizeof(token));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  frs[0].type = NGTCP2_FRAME_PATH_CHALLENGE;
  memcpy(frs[0].path_challenge.data, data, sizeof(frs[0].path_challenge.data));
  frs[1].type = NGTCP2_FRAME_PADDING;
  frs[1].padding.len = 1200;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, frs, 2,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, <, ngtcp2_ringbuf_len(&conn->rx.path_challenge.rb));

  ngtcp2_path_storage_zero(&ps);

  spktlen = ngtcp2_conn_write_pkt(conn, &ps.path, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1200, <=, spktlen);
  assert_true(ngtcp2_path_eq(&new_path.path, &ps.path));
  assert_size(0, ==, ngtcp2_ringbuf_len(&conn->rx.path_challenge.rb));
  assert_size(1, ==, ngtcp2_ringbuf_len(&conn->dcid.bound.rb));

  dcid = ngtcp2_ringbuf_get(&conn->dcid.bound.rb, 0);

  assert_uint64((uint64_t)spktlen, ==, dcid->bytes_sent);

  shdlen = ngtcp2_pkt_decode_hd_short(&hd, buf, (size_t)spktlen, cid.datalen);

  assert_ptrdiff(0, <, shdlen);
  assert_true(ngtcp2_cid_eq(&cid, &hd.dcid));

  /* Use same bound DCID for PATH_CHALLENGE from the same path. */
  fr.type = NGTCP2_FRAME_PATH_CHALLENGE;
  memcpy(fr.path_challenge.data, data2, sizeof(fr.path_challenge.data));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, <, ngtcp2_ringbuf_len(&conn->rx.path_challenge.rb));

  ngtcp2_path_storage_zero(&ps);

  spktlen = ngtcp2_conn_write_pkt(conn, &ps.path, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_true(ngtcp2_path_eq(&new_path.path, &ps.path));
  assert_size(0, ==, ngtcp2_ringbuf_len(&conn->rx.path_challenge.rb));
  assert_size(1, ==, ngtcp2_ringbuf_len(&conn->dcid.bound.rb));

  shdlen = ngtcp2_pkt_decode_hd_short(&hd, buf, (size_t)spktlen, cid.datalen);

  assert_ptrdiff(0, <, shdlen);
  assert_true(ngtcp2_cid_eq(&cid, &hd.dcid));

  ngtcp2_conn_del(conn);

  /* PATH_CHALLENGE from the current path */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = 1;
  fr.new_connection_id.retire_prior_to = 0;
  fr.new_connection_id.cid = cid;
  memcpy(fr.new_connection_id.stateless_reset_token, token, sizeof(token));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  frs[0].type = NGTCP2_FRAME_PATH_CHALLENGE;
  memcpy(frs[0].path_challenge.data, data, sizeof(frs[0].path_challenge.data));
  frs[1].type = NGTCP2_FRAME_PADDING;
  frs[1].padding.len = 1200;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, frs, 2,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, <, ngtcp2_ringbuf_len(&conn->rx.path_challenge.rb));

  ngtcp2_path_storage_zero(&ps);

  spktlen = ngtcp2_conn_write_pkt(conn, &ps.path, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1200, <=, spktlen);
  assert_true(ngtcp2_path_eq(&null_path.path, &ps.path));
  assert_size(0, ==, ngtcp2_ringbuf_len(&conn->rx.path_challenge.rb));
  assert_size(0, ==, ngtcp2_ringbuf_len(&conn->dcid.bound.rb));
  assert_uint64((uint64_t)spktlen, ==, conn->dcid.current.bytes_sent);

  ngtcp2_conn_del(conn);

  /* PATH_CHALLENGE should be ignored with server
     disable_active_migration */
  setup_default_server(&conn);

  conn->local.transport_params.disable_active_migration = 1;

  fr.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = 1;
  fr.new_connection_id.retire_prior_to = 0;
  fr.new_connection_id.cid = cid;
  memcpy(fr.new_connection_id.stateless_reset_token, token, sizeof(token));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  frs[0].type = NGTCP2_FRAME_PATH_CHALLENGE;
  memcpy(frs[0].path_challenge.data, data, sizeof(frs[0].path_challenge.data));
  frs[1].type = NGTCP2_FRAME_PADDING;
  frs[1].padding.len = 1200;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, frs, 2,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, ==, ngtcp2_ringbuf_len(&conn->rx.path_challenge.rb));

  ngtcp2_conn_del(conn);

  /* PATH_CHALLENGE on NAT rebinding (passive migration) should be
     accepted with server disable_active_migration */
  setup_default_server(&conn);

  conn->local.transport_params.disable_active_migration = 1;

  fr.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = 1;
  fr.new_connection_id.retire_prior_to = 0;
  fr.new_connection_id.cid = cid;
  memcpy(fr.new_connection_id.stateless_reset_token, token, sizeof(token));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  frs[0].type = NGTCP2_FRAME_PATH_CHALLENGE;
  memcpy(frs[0].path_challenge.data, data, sizeof(frs[0].path_challenge.data));
  frs[1].type = NGTCP2_FRAME_PADDING;
  frs[1].padding.len = 1200;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, frs, 2,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &new_nat_path.path, &null_pi, buf, pktlen,
                            ++t);

  assert_int(0, ==, rv);
  assert_size(0, <, ngtcp2_ringbuf_len(&conn->rx.path_challenge.rb));

  ngtcp2_conn_del(conn);

  /* PATH_CHALLENGE to preferred address should be accepted with
     server disable_active_migration */
  server_default_transport_params(&params);
  params.disable_active_migration = 1;
  params.preferred_addr_present = 1;
  params.preferred_addr.cid = cid;

  /* Set local address of new_path */
  assert(NGTCP2_AF_INET == new_path.path.local.addr->sa_family);

  params.preferred_addr.ipv4_present = 1;
  memcpy(&params.preferred_addr.ipv4, new_path.path.local.addr,
         sizeof(params.preferred_addr.ipv4));

  server_default_settings(&settings);

  setup_default_server_settings(&conn, &null_path.path, &settings, &params);

  fr.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = 1;
  fr.new_connection_id.retire_prior_to = 0;
  fr.new_connection_id.cid = cid;
  memcpy(fr.new_connection_id.stateless_reset_token, token, sizeof(token));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  frs[0].type = NGTCP2_FRAME_PATH_CHALLENGE;
  memcpy(frs[0].path_challenge.data, data, sizeof(frs[0].path_challenge.data));
  frs[1].type = NGTCP2_FRAME_PADDING;
  frs[1].padding.len = 1200;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, frs, 2,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, <, ngtcp2_ringbuf_len(&conn->rx.path_challenge.rb));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_key_update(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 19393;
  int64_t pkt_num = -1;
  ngtcp2_frame fr;
  int rv;
  int64_t stream_id;
  ngtcp2_ssize nwrite;

  setup_default_server(&conn);

  /* The remote endpoint initiates key update */
  fr.type = NGTCP2_FRAME_PING;

  pktlen =
      write_pkt_flags(buf, sizeof(buf), NGTCP2_PKT_FLAG_KEY_PHASE, &conn->oscid,
                      ++pkt_num, &fr, 1, conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_not_null(conn->crypto.key_update.old_rx_ckm);
  assert_null(conn->crypto.key_update.new_tx_ckm);
  assert_null(conn->crypto.key_update.new_rx_ckm);
  assert_uint64(UINT64_MAX, ==, conn->crypto.key_update.confirmed_ts);
  assert_true(conn->flags & NGTCP2_CONN_FLAG_KEY_UPDATE_NOT_CONFIRMED);
  assert_false(conn->flags & NGTCP2_CONN_FLAG_KEY_UPDATE_INITIATOR);

  t += NGTCP2_SECONDS;
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t);

  assert_ptrdiff(0, <, spktlen);
  assert_uint64(t, ==, conn->crypto.key_update.confirmed_ts);
  assert_false(conn->flags & NGTCP2_CONN_FLAG_KEY_UPDATE_NOT_CONFIRMED);
  assert_false(conn->flags & NGTCP2_CONN_FLAG_KEY_UPDATE_INITIATOR);

  t += ngtcp2_conn_get_pto(conn) + 1;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t);

  assert_ptrdiff(0, ==, spktlen);
  assert_null(conn->crypto.key_update.old_rx_ckm);
  assert_not_null(conn->crypto.key_update.new_tx_ckm);
  assert_not_null(conn->crypto.key_update.new_rx_ckm);

  /* The local endpoint initiates key update */
  t += ngtcp2_conn_get_pto(conn) * 2;

  rv = ngtcp2_conn_initiate_key_update(conn, t);

  assert_int(0, ==, rv);
  assert_not_null(conn->crypto.key_update.old_rx_ckm);
  assert_null(conn->crypto.key_update.new_tx_ckm);
  assert_null(conn->crypto.key_update.new_rx_ckm);
  assert_true(conn->flags & NGTCP2_CONN_FLAG_KEY_UPDATE_NOT_CONFIRMED);
  assert_true(conn->flags & NGTCP2_CONN_FLAG_KEY_UPDATE_INITIATOR);

  rv = ngtcp2_conn_open_uni_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf),
                                     &nwrite, NGTCP2_WRITE_STREAM_FLAG_NONE,
                                     stream_id, null_data, 1024, ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_true(conn->flags & NGTCP2_CONN_FLAG_KEY_UPDATE_NOT_CONFIRMED);

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = conn->pktns.tx.last_pkt_num;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;

  pktlen =
      write_pkt_flags(buf, sizeof(buf), NGTCP2_PKT_FLAG_KEY_PHASE, &conn->oscid,
                      ++pkt_num, &fr, 1, conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_uint64(t, ==, conn->crypto.key_update.confirmed_ts);
  assert_false(conn->flags & NGTCP2_CONN_FLAG_KEY_UPDATE_NOT_CONFIRMED);
  assert_false(conn->flags & NGTCP2_CONN_FLAG_KEY_UPDATE_INITIATOR);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_crypto_buffer_exceeded(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_tstamp t = 11111;
  int64_t pkt_num = -1;
  ngtcp2_frame fr;
  int rv;

  setup_default_client(&conn);

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 1000000;
  fr.stream.datacnt = 1;
  fr.stream.data[0].base = null_data;
  fr.stream.data[0].len = 1;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_CRYPTO_BUFFER_EXCEEDED, ==, rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_handshake_probe(void) {
  ngtcp2_conn *conn;
  ngtcp2_tstamp t = 0;
  ngtcp2_ssize spktlen;
  size_t pktlen;
  uint8_t buf[1200];
  ngtcp2_frame fr;
  ngtcp2_rtb_entry *ent;
  ngtcp2_ksl_it it;
  int rv;
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  ngtcp2_crypto_ctx crypto_ctx;

  /* Retransmit first Initial on PTO timer */
  setup_handshake_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(1, ==, conn->in_pktns->rtb.num_ack_eliciting);

  rv = ngtcp2_conn_on_loss_detection_timer(conn, ++t);

  assert_int(0, ==, rv);
  assert_size(1, ==, conn->in_pktns->rtb.probe_pkt_left);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(1, ==, conn->in_pktns->rtb.num_retransmittable);
  assert_size(2, ==, conn->in_pktns->rtb.num_ack_eliciting);
  assert_size(0, ==, conn->in_pktns->rtb.probe_pkt_left);

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = 0;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;

  pktlen = write_initial_pkt(buf, sizeof(buf), &conn->oscid,
                             ngtcp2_conn_get_dcid(conn), 0, NGTCP2_PROTO_VER_V1,
                             NULL, 0, &fr, 1, &null_ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(1, ==, conn->in_pktns->rtb.num_ack_eliciting);

  rv = ngtcp2_conn_on_loss_detection_timer(conn, ++t);

  assert_int(0, ==, rv);
  assert_size(1, ==, conn->in_pktns->rtb.num_retransmittable);
  assert_size(1, ==, conn->in_pktns->rtb.num_ack_eliciting);
  assert_size(1, ==, conn->in_pktns->rtb.probe_pkt_left);

  /* This sends anti-deadlock padded Initial packet even if we have
     nothing to send. */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(0, ==, conn->in_pktns->rtb.num_retransmittable);
  assert_size(2, ==, conn->in_pktns->rtb.num_ack_eliciting);
  assert_size(0, ==, conn->in_pktns->rtb.probe_pkt_left);

  it = ngtcp2_rtb_head(&conn->in_pktns->rtb);
  ent = ngtcp2_ksl_it_get(&it);

  assert_true(ent->flags & NGTCP2_RTB_ENTRY_FLAG_PROBE);
  assert_size(sizeof(buf), ==, ent->pktlen);

  init_crypto_ctx(&crypto_ctx);
  ngtcp2_conn_set_crypto_ctx(conn, &crypto_ctx);
  conn->negotiated_version = conn->client_chosen_version;
  ngtcp2_conn_install_rx_handshake_key(conn, &aead_ctx, null_iv,
                                       sizeof(null_iv), &hp_ctx);
  ngtcp2_conn_install_tx_handshake_key(conn, &aead_ctx, null_iv,
                                       sizeof(null_iv), &hp_ctx);

  rv = ngtcp2_conn_on_loss_detection_timer(conn, ++t);

  assert_int(0, ==, rv);
  assert_size(2, ==, conn->in_pktns->rtb.num_ack_eliciting);
  assert_size(1, ==, conn->hs_pktns->rtb.probe_pkt_left);

  /* This sends anti-deadlock Handshake packet even if we have nothing
     to send. */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(0, ==, conn->hs_pktns->rtb.num_retransmittable);
  assert_size(1, ==, conn->hs_pktns->rtb.num_ack_eliciting);
  assert_size(0, ==, conn->hs_pktns->rtb.probe_pkt_left);

  it = ngtcp2_rtb_head(&conn->hs_pktns->rtb);
  ent = ngtcp2_ksl_it_get(&it);

  assert_true(ent->flags & NGTCP2_RTB_ENTRY_FLAG_PROBE);
  assert_size(sizeof(buf), >, ent->pktlen);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_handshake_loss(void) {
  ngtcp2_conn *conn;
  ngtcp2_tstamp t = 0;
  ngtcp2_ssize spktlen;
  size_t i;
  size_t pktlen;
  uint8_t buf[1252];
  ngtcp2_frame fr;
  ngtcp2_frame frs[2];
  ngtcp2_cid rcid;
  int rv;
  int64_t pkt_num = -1;
  ngtcp2_ksl_it it;
  ngtcp2_rtb_entry *ent;
  int64_t ack_pkt_num;
  int64_t stream_id;
  ngtcp2_ssize nwrite;
  ngtcp2_ssize datalen;

  rcid_init(&rcid);
  setup_handshake_server(&conn);
  conn->callbacks.recv_crypto_data = recv_crypto_data;

  frs[0].type = NGTCP2_FRAME_CRYPTO;
  frs[0].stream.offset = 0;
  frs[0].stream.datacnt = 1;
  frs[0].stream.data[0].len = 123;
  frs[0].stream.data[0].base = null_data;

  frs[1].type = NGTCP2_FRAME_PADDING;
  frs[1].padding.len = 1005;

  pktlen = write_initial_pkt(
      buf, sizeof(buf), &rcid, ngtcp2_conn_get_dcid(conn), ++pkt_num,
      conn->client_chosen_version, NULL, 0, frs, 2, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  /* Increase anti-amplification factor for easier testing */
  conn->dcid.current.bytes_recv += 10000;

  ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL,
                                 null_data, 123);
  ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,
                                 null_data, 163);
  ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,
                                 null_data, 2369);
  ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,
                                 null_data, 79);
  ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,
                                 null_data, 36);

  /* Initial and first Handshake are coalesced into 1 packet. */
  for (i = 0; i < 3; ++i) {
    spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);
    assert_ptrdiff(0, <, spktlen);
  }

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, ==, spktlen);

  t += 30 * NGTCP2_MILLISECONDS;

  ngtcp2_conn_on_loss_detection_timer(conn, t);

  assert_size(1, ==, conn->in_pktns->rtb.probe_pkt_left);
  assert_size(1, ==, conn->hs_pktns->rtb.probe_pkt_left);

  /* Send a PTO probe packet */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, ==, spktlen);

  it = ngtcp2_ksl_begin(&conn->hs_pktns->rtb.ents);
  ent = ngtcp2_ksl_it_get(&it);

  assert_uint64(0, ==, ent->frc->fr.stream.offset);
  assert_uint64(
      987, ==,
      ngtcp2_vec_len(ent->frc->fr.stream.data, ent->frc->fr.stream.datacnt));
  assert_int64(3, ==, ent->hd.pkt_num);

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = 2;
  fr.ack.ack_delay = 0;
  fr.ack.ack_delay_unscaled = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;

  pktlen = write_handshake_pkt(buf, sizeof(buf), &conn->oscid,
                               ngtcp2_conn_get_dcid(conn), ++pkt_num,
                               conn->client_chosen_version, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, t);

  assert_int(0, ==, rv);

  t += 40 * NGTCP2_MILLISECONDS;

  ngtcp2_conn_on_loss_detection_timer(conn, t);

  assert_size(0, ==, conn->hs_pktns->rtb.probe_pkt_left);

  /* Retransmits the contents of lost packet */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_ksl_begin(&conn->hs_pktns->rtb.ents);
  ent = ngtcp2_ksl_it_get(&it);

  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, ent->frc->fr.type);
  assert_uint64(987, ==, ent->frc->fr.stream.offset);
  assert_size(1, ==, ent->frc->fr.stream.datacnt);
  assert_uint64(
      1183, ==,
      ngtcp2_vec_len(ent->frc->fr.stream.data, ent->frc->fr.stream.datacnt));
  assert_int64(4, ==, ent->hd.pkt_num);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, ==, spktlen);

  t += 30 * NGTCP2_MILLISECONDS;

  ngtcp2_conn_on_loss_detection_timer(conn, t);

  assert_size(2, ==, conn->hs_pktns->rtb.probe_pkt_left);

  /* Send 2 PTO probe packets */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_ksl_begin(&conn->hs_pktns->rtb.ents);
  ent = ngtcp2_ksl_it_get(&it);

  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, ent->frc->fr.type);
  assert_uint64(0, ==, ent->frc->fr.stream.offset);
  assert_size(2, ==, ent->frc->fr.stream.datacnt);
  assert_uint64(
      987, ==,
      ngtcp2_vec_len(ent->frc->fr.stream.data, ent->frc->fr.stream.datacnt));
  assert_int64(5, ==, ent->hd.pkt_num);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_ksl_begin(&conn->hs_pktns->rtb.ents);
  ent = ngtcp2_ksl_it_get(&it);

  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, ent->frc->fr.type);
  assert_uint64(987, ==, ent->frc->fr.stream.offset);
  assert_size(1, ==, ent->frc->fr.stream.datacnt);
  assert_uint64(
      1183, ==,
      ngtcp2_vec_len(ent->frc->fr.stream.data, ent->frc->fr.stream.datacnt));

  assert_int64(6, ==, ent->hd.pkt_num);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, ==, spktlen);

  ngtcp2_conn_del(conn);

  /* Retransmission splits CRYPTO frame */
  setup_handshake_server(&conn);
  conn->callbacks.recv_crypto_data = recv_crypto_data;

  frs[0].type = NGTCP2_FRAME_CRYPTO;
  frs[0].stream.offset = 0;
  frs[0].stream.datacnt = 1;
  frs[0].stream.data[0].len = 123;
  frs[0].stream.data[0].base = null_data;

  frs[1].type = NGTCP2_FRAME_PADDING;
  frs[1].padding.len = 1005;

  pktlen = write_initial_pkt(
      buf, sizeof(buf), &rcid, ngtcp2_conn_get_dcid(conn), ++pkt_num,
      conn->client_chosen_version, NULL, 0, frs, 2, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  /* Increase anti-amplification factor for easier testing */
  conn->dcid.current.bytes_recv += 10000;

  ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL,
                                 null_data, 123);
  ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,
                                 null_data, 3000);
  /* Initial and first Handshake are coalesced into 1 packet. */
  for (i = 0; i < 3; ++i) {
    spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);
    assert_ptrdiff(0, <, spktlen);
  }

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, ==, spktlen);

  it = ngtcp2_ksl_begin(&conn->hs_pktns->rtb.ents);
  ent = ngtcp2_ksl_it_get(&it);

  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, ent->frc->fr.type);
  assert_uint64(2170, ==, ent->frc->fr.stream.offset);
  assert_uint64(
      830, ==,
      ngtcp2_vec_len(ent->frc->fr.stream.data, ent->frc->fr.stream.datacnt));
  assert_int64(2, ==, ent->hd.pkt_num);

  t += 30 * NGTCP2_MILLISECONDS;

  ngtcp2_conn_on_loss_detection_timer(conn, t);

  assert_size(1, ==, conn->in_pktns->rtb.probe_pkt_left);
  assert_size(1, ==, conn->hs_pktns->rtb.probe_pkt_left);

  /* 1st PTO */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);
  assert_ptrdiff(0, <, spktlen);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, ==, spktlen);

  it = ngtcp2_ksl_begin(&conn->hs_pktns->rtb.ents);
  ent = ngtcp2_ksl_it_get(&it);

  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, ent->frc->fr.type);
  assert_uint64(0, ==, ent->frc->fr.stream.offset);
  assert_uint64(
      987, ==,
      ngtcp2_vec_len(ent->frc->fr.stream.data, ent->frc->fr.stream.datacnt));
  assert_int64(3, ==, ent->hd.pkt_num);

  t += 30 * NGTCP2_MILLISECONDS;

  ngtcp2_conn_on_loss_detection_timer(conn, t);

  assert_size(1, ==, conn->in_pktns->rtb.probe_pkt_left);
  assert_size(1, ==, conn->hs_pktns->rtb.probe_pkt_left);

  /* 2nd PTO.  Initial and Handshake packets are coalesced.  Handshake
     CRYPTO is split into 2 because of Initial CRYPTO. */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);
  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_ksl_begin(&conn->hs_pktns->rtb.ents);
  ent = ngtcp2_ksl_it_get(&it);

  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, ent->frc->fr.type);
  assert_uint64(987, ==, ent->frc->fr.stream.offset);
  assert_uint64(
      991, ==,
      ngtcp2_vec_len(ent->frc->fr.stream.data, ent->frc->fr.stream.datacnt));
  assert_int64(4, ==, ent->hd.pkt_num);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);
  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_ksl_begin(&conn->hs_pktns->rtb.ents);
  ent = ngtcp2_ksl_it_get(&it);

  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, ent->frc->fr.type);
  assert_uint64(1978, ==, ent->frc->fr.stream.offset);
  assert_uint64(
      192, ==,
      ngtcp2_vec_len(ent->frc->fr.stream.data, ent->frc->fr.stream.datacnt));
  assert_int64(5, ==, ent->hd.pkt_num);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);
  assert_ptrdiff(0, ==, spktlen);

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = 0;
  fr.ack.ack_delay = 0;
  fr.ack.ack_delay_unscaled = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;

  pktlen = write_handshake_pkt(buf, sizeof(buf), &conn->oscid,
                               ngtcp2_conn_get_dcid(conn), ++pkt_num,
                               conn->client_chosen_version, &fr, 1, &null_ckm);

  t += NGTCP2_MILLISECONDS;
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, t);

  assert_int(0, ==, rv);

  t += 40 * NGTCP2_MILLISECONDS;

  ngtcp2_conn_on_loss_detection_timer(conn, t);

  assert_size(2, ==, conn->hs_pktns->rtb.probe_pkt_left);

  /* 3rd PTO */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_ksl_begin(&conn->hs_pktns->rtb.ents);
  ent = ngtcp2_ksl_it_get(&it);

  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, ent->frc->fr.type);
  assert_uint64(2170, ==, ent->frc->fr.stream.offset);
  assert_uint64(
      830, ==,
      ngtcp2_vec_len(ent->frc->fr.stream.data, ent->frc->fr.stream.datacnt));
  assert_int64(6, ==, ent->hd.pkt_num);
  assert_null(ent->frc->next);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_ksl_begin(&conn->hs_pktns->rtb.ents);
  ent = ngtcp2_ksl_it_get(&it);

  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, ent->frc->fr.type);
  assert_uint64(987, ==, ent->frc->fr.stream.offset);
  assert_uint64(
      991, ==,
      ngtcp2_vec_len(ent->frc->fr.stream.data, ent->frc->fr.stream.datacnt));
  assert_int64(7, ==, ent->hd.pkt_num);
  assert_null(ent->frc->next);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, ==, spktlen);

  ngtcp2_conn_del(conn);

  /* Allow resending Handshake CRYPTO even if it exceeds CWND */
  setup_handshake_client(&conn);

  conn->callbacks.recv_crypto_data = recv_crypto_data_client_handshake;

  t = 0;
  pkt_num = -1;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1200, <=, spktlen);

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 117;
  fr.stream.data[0].base = null_data;

  pktlen = write_initial_pkt(
      buf, sizeof(buf), &conn->oscid, ngtcp2_conn_get_dcid(conn), ++pkt_num,
      conn->client_chosen_version, NULL, 0, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  pktlen = write_handshake_pkt(buf, sizeof(buf), &conn->oscid,
                               ngtcp2_conn_get_dcid(conn), ++pkt_num,
                               conn->client_chosen_version, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  /* This will send Handshake ACK and CRYPTO */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1200, <=, spktlen);
  assert_null(conn->in_pktns);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  /* Send 1RTT packets to consume CWND */
  for (i = 0; i < 10; ++i) {
    spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf),
                                       &nwrite, NGTCP2_WRITE_STREAM_FLAG_NONE,
                                       stream_id, null_data, 1024, t);

    assert_ptrdiff(0, <, spktlen);
  }

  ngtcp2_conn_on_loss_detection_timer(conn, t);

  assert_size(2, ==, conn->hs_pktns->rtb.probe_pkt_left);

  /* 1st PTO */
  for (i = 0; i < 2; ++i) {
    spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

    assert_ptrdiff(0, <, spktlen);
  }

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, ==, spktlen);

  /* Send 2 ACKs with PING to declare the latest Handshake CRYPTO to
     be lost */
  for (i = 0; i < 2; ++i) {
    pktlen = write_handshake_pkt(
        buf, sizeof(buf), &conn->oscid, ngtcp2_conn_get_dcid(conn), ++pkt_num,
        conn->client_chosen_version, &fr, 1, &null_ckm);

    rv =
        ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

    assert_int(0, ==, rv);

    t += conn->cstat.smoothed_rtt;
    spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t);

    assert_ptrdiff(0, <, spktlen);
  }

  ack_pkt_num = conn->hs_pktns->tx.last_pkt_num;

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = ack_pkt_num;
  fr.ack.ack_delay = 0;
  fr.ack.ack_delay_unscaled = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;

  pktlen = write_handshake_pkt(buf, sizeof(buf), &conn->oscid,
                               ngtcp2_conn_get_dcid(conn), ++pkt_num,
                               conn->client_chosen_version, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_false(ngtcp2_strm_streamfrq_empty(&conn->hs_pktns->crypto.strm));
  assert_uint64(conn->cstat.bytes_in_flight, >, conn->cstat.cwnd);

  /* Resending Handshake CRYPTO is allowed even if it exceeds CWND in
     this situation. */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_true(ngtcp2_strm_streamfrq_empty(&conn->hs_pktns->crypto.strm));

  /* Check that Handshake ACK only packet can be sent anytime */
  fr.type = NGTCP2_FRAME_PING;

  pktlen = write_handshake_pkt(buf, sizeof(buf), &conn->oscid,
                               ngtcp2_conn_get_dcid(conn), ++pkt_num,
                               conn->client_chosen_version, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  ngtcp2_conn_del(conn);

  /* Client can send PTO Initial packet even if reduced CWND is less
     than in-flight bytes which are mostly occupied by 0-RTT
     packets. */
  setup_early_client(&conn);

  conn->callbacks.client_initial = client_initial_large_crypto_early_data;

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  for (i = 0; i < 14; ++i) {
    spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf),
                                       &datalen, NGTCP2_WRITE_STREAM_FLAG_NONE,
                                       stream_id, null_data, 1024, ++t);

    assert_ptrdiff(0, <, spktlen);
  }

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf),
                                     &datalen, NGTCP2_WRITE_STREAM_FLAG_NONE,
                                     stream_id, null_data, 1024, ++t);

  assert_ptrdiff(0, ==, spktlen);
  assert_uint64(conn->cstat.bytes_in_flight, >=, conn->cstat.cwnd);

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = 1;
  fr.ack.ack_delay = 0;
  fr.ack.ack_delay_unscaled = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;

  pktlen = write_initial_pkt(
      buf, sizeof(buf), &conn->oscid, ngtcp2_conn_get_dcid(conn), ++pkt_num,
      conn->client_chosen_version, NULL, 0, &fr, 1, &null_ckm);

  t += 30 * NGTCP2_MILLISECONDS;

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, t);

  assert_int(0, ==, rv);

  t += 35 * NGTCP2_MILLISECONDS;

  assert_true(ngtcp2_strm_streamfrq_empty(&conn->in_pktns->crypto.strm));

  ngtcp2_conn_on_loss_detection_timer(conn, t);

  /* On loss-based packet loss detection, we need another timeout,
     according to RFC 9002.  No PTO on first
     ngtcp2_conn_on_loss_detection_timer. */
  t = conn->cstat.loss_detection_timer;

  ngtcp2_conn_on_loss_detection_timer(conn, t);

  assert_size(1, ==, conn->in_pktns->rtb.probe_pkt_left);
  assert_uint64(conn->cstat.bytes_in_flight, >, conn->cstat.cwnd);
  assert_false(ngtcp2_strm_streamfrq_empty(&conn->in_pktns->crypto.strm));

  spktlen =
      ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                               NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, ++t);

  assert_ptrdiff(0, <, spktlen);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_probe(void) {
  ngtcp2_conn *conn;
  ngtcp2_tstamp t = 0;
  ngtcp2_ssize spktlen;
  size_t pktlen;
  uint8_t buf[1200];
  ngtcp2_frame fr;
  int rv;
  ngtcp2_vec datav;
  int accepted;
  int64_t stream_id;
  ngtcp2_ksl_it it;
  ngtcp2_rtb_entry *ent;

  /* Probe packet after DATAGRAM */
  setup_default_client(&conn);

  conn->remote.transport_params->max_datagram_frame_size = 65535;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(1, ==, conn->pktns.rtb.num_ack_eliciting);

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = 0;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 0, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, t++);

  assert_int(0, ==, rv);

  datav.base = null_data;
  datav.len = 44;

  spktlen = ngtcp2_conn_writev_datagram(
      conn, NULL, NULL, buf, sizeof(buf), &accepted,
      NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 1, &datav, 1, t++);

  assert_ptrdiff(0, <, spktlen);
  assert_true(accepted);

  t += 30 * NGTCP2_MILLISECONDS;

  ngtcp2_conn_on_loss_detection_timer(conn, t);

  assert_size(2, ==, conn->pktns.rtb.probe_pkt_left);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t++);

  assert_ptrdiff(0, <, spktlen);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t++);

  assert_ptrdiff(0, <, spktlen);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t++);

  assert_ptrdiff(0, ==, spktlen);

  ngtcp2_conn_del(conn);

  /* Do not send STREAM frame as probe packet if RESET_STREAM is
     submitted. */
  setup_default_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(1, ==, conn->pktns.rtb.num_ack_eliciting);

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = 0;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 0, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, t++);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 111, t);

  assert_ptrdiff(0, <, spktlen);

  ngtcp2_conn_shutdown_stream_write(conn, 0, stream_id, NGTCP2_APP_ERR01);

  spktlen =
      ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                               NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, t++);

  assert_ptrdiff(0, <, spktlen);

  t += 30 * NGTCP2_MILLISECONDS;

  ngtcp2_conn_on_loss_detection_timer(conn, t);

  assert_size(2, ==, conn->pktns.rtb.probe_pkt_left);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t++);

  assert_ptrdiff(0, <, spktlen);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t++);

  assert_ptrdiff(0, <, spktlen);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t++);

  assert_ptrdiff(0, ==, spktlen);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);
  ent = ngtcp2_ksl_it_get(&it);

  assert_uint64(NGTCP2_FRAME_RESET_STREAM, ==, ent->frc->fr.type);
  assert_null(ent->frc->next);

  ngtcp2_ksl_it_next(&it);
  ent = ngtcp2_ksl_it_get(&it);

  assert_uint64(NGTCP2_FRAME_RESET_STREAM, ==, ent->frc->fr.type);
  assert_null(ent->frc->next);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_client_initial_retry(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_frame fr;
  int64_t pkt_num = -1;
  ngtcp2_tstamp t = 0;
  ngtcp2_cid rcid;
  int rv;

  rcid_init(&rcid);

  setup_handshake_server(&conn);
  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 1;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1245;
  fr.stream.data[0].base = null_data;

  pktlen = write_initial_pkt(
      buf, sizeof(buf), &rcid, ngtcp2_conn_get_dcid(conn), ++pkt_num,
      conn->client_chosen_version, NULL, 0, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_RETRY, ==, rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_client_initial_token(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_frame fr;
  int64_t pkt_num = -1;
  ngtcp2_tstamp t = 0;
  ngtcp2_cid rcid;
  int rv;
  const uint8_t raw_token[] = {0xff, 0x12, 0x31, 0x04, 0xab};
  uint8_t *token;
  const ngtcp2_mem *mem;

  rcid_init(&rcid);

  setup_handshake_server(&conn);
  mem = conn->mem;

  token = ngtcp2_mem_malloc(mem, sizeof(raw_token));
  memcpy(token, raw_token, sizeof(raw_token));

  conn->local.settings.token = token;
  conn->local.settings.tokenlen = sizeof(raw_token);

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1181;
  fr.stream.data[0].base = null_data;

  pktlen =
      write_initial_pkt(buf, sizeof(buf), &rcid, ngtcp2_conn_get_dcid(conn),
                        ++pkt_num, conn->client_chosen_version, raw_token,
                        sizeof(raw_token), &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_uint64(1181, ==, ngtcp2_strm_rx_offset(&conn->in_pktns->crypto.strm));

  ngtcp2_conn_del(conn);

  /* Specifying invalid token lets server drop the packet */
  setup_handshake_server(&conn);
  mem = conn->mem;

  token = ngtcp2_mem_malloc(mem, sizeof(raw_token));
  memcpy(token, raw_token, sizeof(raw_token));

  conn->local.settings.token = token;
  conn->local.settings.tokenlen = sizeof(raw_token) - 1;

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1179;
  fr.stream.data[0].base = null_data;

  pktlen =
      write_initial_pkt(buf, sizeof(buf), &rcid, ngtcp2_conn_get_dcid(conn),
                        ++pkt_num, conn->client_chosen_version, raw_token,
                        sizeof(raw_token), &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_DROP_CONN, ==, rv);
  assert_uint64(0, ==, ngtcp2_strm_rx_offset(&conn->in_pktns->crypto.strm));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_get_active_dcid(void) {
  ngtcp2_conn *conn;
  ngtcp2_cid_token cid_token[2];
  ngtcp2_cid dcid;
  static uint8_t token[] = {0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1,
                            0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1};

  dcid_init(&dcid);
  setup_default_client(&conn);

  assert_size(1, ==, ngtcp2_conn_get_active_dcid(conn, NULL));
  assert_size(1, ==, ngtcp2_conn_get_active_dcid(conn, cid_token));
  assert_uint64(0, ==, cid_token[0].seq);
  assert_true(ngtcp2_cid_eq(&dcid, &cid_token[0].cid));
  assert_true(ngtcp2_path_eq(&null_path.path, &cid_token[0].ps.path));
  assert_true(cid_token[0].token_present);
  assert_memory_equal(NGTCP2_STATELESS_RESET_TOKENLEN, token,
                      cid_token[0].token);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_version_negotiation(void) {
  ngtcp2_conn *conn;
  const ngtcp2_cid *dcid;
  ngtcp2_ssize spktlen;
  uint8_t buf[1500];
  uint32_t nsv[3];
  int rv;
  ngtcp2_tstamp t = 0;

  setup_handshake_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  dcid = ngtcp2_conn_get_dcid(conn);

  nsv[0] = 0xffffffff;

  spktlen = ngtcp2_pkt_write_version_negotiation(
      buf, sizeof(buf), 0xfe, conn->oscid.data, conn->oscid.datalen, dcid->data,
      dcid->datalen, nsv, 1);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf,
                            (size_t)spktlen, ++t);

  assert_int(NGTCP2_ERR_RECV_VERSION_NEGOTIATION, ==, rv);

  ngtcp2_conn_del(conn);

  /* Ignore Version Negotiation if it contains version selected by
     client */
  setup_handshake_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  dcid = ngtcp2_conn_get_dcid(conn);

  nsv[0] = 0xfffffff0;
  nsv[1] = conn->client_chosen_version;

  spktlen = ngtcp2_pkt_write_version_negotiation(
      buf, sizeof(buf), 0x50, conn->oscid.data, conn->oscid.datalen, dcid->data,
      dcid->datalen, nsv, 2);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf,
                            (size_t)spktlen, ++t);

  assert_int(0, ==, rv);

  ngtcp2_conn_del(conn);

  /* Ignore Version Negotiation if client reacted upon Version
     Negotiation */
  setup_handshake_client(&conn);

  conn->local.settings.original_version = NGTCP2_PROTO_VER_V2;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  dcid = ngtcp2_conn_get_dcid(conn);

  nsv[0] = 0xffffffff;

  spktlen = ngtcp2_pkt_write_version_negotiation(
      buf, sizeof(buf), 0xfe, conn->oscid.data, conn->oscid.datalen, dcid->data,
      dcid->datalen, nsv, 1);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf,
                            (size_t)spktlen, ++t);

  assert_int(0, ==, rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_send_initial_token(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  ngtcp2_callbacks cb;
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  ngtcp2_cid rcid, scid;
  ngtcp2_crypto_aead retry_aead = {0, NGTCP2_FAKE_AEAD_OVERHEAD};
  uint8_t token[] = "this is token";
  ngtcp2_ssize spktlen, shdlen;
  ngtcp2_tstamp t = 0;
  ngtcp2_pkt_hd hd;
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  ngtcp2_crypto_ctx crypto_ctx;

  rcid_init(&rcid);
  scid_init(&scid);

  init_initial_crypto_ctx(&crypto_ctx);

  client_default_callbacks(&cb);
  client_default_settings(&settings);
  client_default_transport_params(&params);

  settings.token = token;
  settings.tokenlen = sizeof(token);

  ngtcp2_conn_client_new(&conn, &rcid, &scid, &null_path.path,
                         NGTCP2_PROTO_VER_V1, &cb, &settings, &params,
                         /* mem = */ NULL, NULL);
  ngtcp2_conn_set_initial_crypto_ctx(conn, &crypto_ctx);
  ngtcp2_conn_install_initial_key(conn, &aead_ctx, null_iv, &hp_ctx, &aead_ctx,
                                  null_iv, &hp_ctx, sizeof(null_iv));
  ngtcp2_conn_set_retry_aead(conn, &retry_aead, &aead_ctx);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  shdlen = ngtcp2_pkt_decode_hd_long(&hd, buf, (size_t)spktlen);

  assert_ptrdiff(0, <, shdlen);
  assert_size(sizeof(token), ==, hd.tokenlen);
  assert_memory_equal(sizeof(token), token, hd.token);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_set_remote_transport_params(void) {
  ngtcp2_conn *conn;
  ngtcp2_transport_params params;
  int rv;
  ngtcp2_cid dcid;
  uint8_t available_versions[2 * sizeof(uint32_t)];

  dcid_init(&dcid);

  /* client: Successful case */
  setup_handshake_client(&conn);

  conn->negotiated_version = conn->client_chosen_version;

  memset(&params, 0, sizeof(params));
  params.active_connection_id_limit = NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT;
  params.max_udp_payload_size = 1450;
  params.initial_scid = conn->dcid.current.cid;
  params.initial_scid_present = 1;
  params.original_dcid = conn->rcid;
  params.original_dcid_present = 1;

  rv = ngtcp2_conn_set_remote_transport_params(conn, &params);

  assert_int(0, ==, rv);

  ngtcp2_conn_del(conn);

  /* client: Wrong original_dcid */
  setup_handshake_client(&conn);

  conn->negotiated_version = conn->client_chosen_version;

  memset(&params, 0, sizeof(params));
  params.active_connection_id_limit = NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT;
  params.max_udp_payload_size = 1450;
  params.initial_scid = conn->dcid.current.cid;
  params.initial_scid_present = 1;
  params.original_dcid_present = 1;

  rv = ngtcp2_conn_set_remote_transport_params(conn, &params);

  assert_int(NGTCP2_ERR_TRANSPORT_PARAM, ==, rv);

  ngtcp2_conn_del(conn);

  /* client: Wrong initial_scid */
  setup_handshake_client(&conn);

  conn->negotiated_version = conn->client_chosen_version;

  memset(&params, 0, sizeof(params));
  params.active_connection_id_limit = NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT;
  params.max_udp_payload_size = 1450;
  params.initial_scid_present = 1;
  params.original_dcid = conn->rcid;
  params.original_dcid_present = 1;

  rv = ngtcp2_conn_set_remote_transport_params(conn, &params);

  assert_int(NGTCP2_ERR_TRANSPORT_PARAM, ==, rv);

  ngtcp2_conn_del(conn);

  /* client: Receiving retry_scid when retry is not attempted */
  setup_handshake_client(&conn);

  conn->negotiated_version = conn->client_chosen_version;

  memset(&params, 0, sizeof(params));
  params.active_connection_id_limit = NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT;
  params.max_udp_payload_size = 1450;
  params.initial_scid = conn->dcid.current.cid;
  params.initial_scid_present = 1;
  params.original_dcid = conn->rcid;
  params.original_dcid_present = 1;
  params.retry_scid_present = 1;

  rv = ngtcp2_conn_set_remote_transport_params(conn, &params);

  assert_int(NGTCP2_ERR_TRANSPORT_PARAM, ==, rv);

  ngtcp2_conn_del(conn);

  /* client: Receiving retry_scid */
  setup_handshake_client(&conn);

  conn->flags |= NGTCP2_CONN_FLAG_RECV_RETRY;
  conn->retry_scid = dcid;
  conn->negotiated_version = conn->client_chosen_version;

  memset(&params, 0, sizeof(params));
  params.active_connection_id_limit = NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT;
  params.max_udp_payload_size = 1450;
  params.initial_scid = conn->dcid.current.cid;
  params.initial_scid_present = 1;
  params.original_dcid = conn->rcid;
  params.original_dcid_present = 1;
  params.retry_scid_present = 1;
  params.retry_scid = dcid;

  rv = ngtcp2_conn_set_remote_transport_params(conn, &params);

  assert_int(0, ==, rv);

  ngtcp2_conn_del(conn);

  /* client: Not receiving retry_scid when retry is attempted */
  setup_handshake_client(&conn);

  conn->flags |= NGTCP2_CONN_FLAG_RECV_RETRY;
  conn->retry_scid = dcid;
  conn->negotiated_version = conn->client_chosen_version;

  memset(&params, 0, sizeof(params));
  params.active_connection_id_limit = NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT;
  params.max_udp_payload_size = 1450;
  params.initial_scid = conn->dcid.current.cid;
  params.initial_scid_present = 1;
  params.original_dcid = conn->rcid;
  params.original_dcid_present = 1;

  rv = ngtcp2_conn_set_remote_transport_params(conn, &params);

  assert_int(NGTCP2_ERR_TRANSPORT_PARAM, ==, rv);

  ngtcp2_conn_del(conn);

  /* client: Special handling for QUIC v1 regarding Version
     Negotiation */
  setup_handshake_client(&conn);

  conn->local.settings.original_version = NGTCP2_PROTO_VER_V2;
  conn->negotiated_version = conn->client_chosen_version;

  memset(&params, 0, sizeof(params));
  params.active_connection_id_limit = NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT;
  params.max_udp_payload_size = 1450;
  params.initial_scid = conn->dcid.current.cid;
  params.initial_scid_present = 1;
  params.original_dcid = conn->rcid;
  params.original_dcid_present = 1;

  rv = ngtcp2_conn_set_remote_transport_params(conn, &params);

  assert_int(0, ==, rv);

  ngtcp2_conn_del(conn);

  /* client: No version_information after Version Negotiation */
  setup_handshake_client_version(&conn, NGTCP2_PROTO_VER_V2);

  conn->local.settings.original_version = NGTCP2_PROTO_VER_V1;
  conn->negotiated_version = conn->client_chosen_version;

  memset(&params, 0, sizeof(params));
  params.active_connection_id_limit = NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT;
  params.max_udp_payload_size = 1450;
  params.initial_scid = conn->dcid.current.cid;
  params.initial_scid_present = 1;
  params.original_dcid = conn->rcid;
  params.original_dcid_present = 1;

  rv = ngtcp2_conn_set_remote_transport_params(conn, &params);

  assert_int(NGTCP2_ERR_VERSION_NEGOTIATION_FAILURE, ==, rv);

  ngtcp2_conn_del(conn);

  /* client: available_versions includes the version that the client
     initially attempted. */
  setup_handshake_client(&conn);

  conn->local.settings.original_version = NGTCP2_PROTO_VER_V2;
  conn->negotiated_version = conn->client_chosen_version;

  ngtcp2_put_uint32be(available_versions, NGTCP2_PROTO_VER_V1);
  ngtcp2_put_uint32be(available_versions + sizeof(uint32_t),
                      NGTCP2_PROTO_VER_V2);

  memset(&params, 0, sizeof(params));
  params.active_connection_id_limit = NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT;
  params.max_udp_payload_size = 1450;
  params.initial_scid = conn->dcid.current.cid;
  params.initial_scid_present = 1;
  params.original_dcid = conn->rcid;
  params.original_dcid_present = 1;
  params.version_info_present = 1;
  params.version_info.chosen_version = conn->negotiated_version;
  params.version_info.available_versions = available_versions;
  params.version_info.available_versionslen = 2 * sizeof(uint32_t);

  rv = ngtcp2_conn_set_remote_transport_params(conn, &params);

  assert_int(NGTCP2_ERR_VERSION_NEGOTIATION_FAILURE, ==, rv);

  ngtcp2_conn_del(conn);

  /* client: client is unable to choose client chosen version from
     server's available_versions and chosen version. */
  setup_handshake_client(&conn);

  conn->local.settings.original_version = NGTCP2_PROTO_VER_V2;
  conn->negotiated_version = 0xff000000u;

  ngtcp2_put_uint32be(conn->vneg.available_versions, NGTCP2_PROTO_VER_V1);
  ngtcp2_put_uint32be(conn->vneg.available_versions + sizeof(uint32_t),
                      0xff000000u);

  ngtcp2_put_uint32be(available_versions, 0xff000000u);

  memset(&params, 0, sizeof(params));
  params.active_connection_id_limit = NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT;
  params.max_udp_payload_size = 1450;
  params.initial_scid = conn->dcid.current.cid;
  params.initial_scid_present = 1;
  params.original_dcid = conn->rcid;
  params.original_dcid_present = 1;
  params.version_info_present = 1;
  params.version_info.chosen_version = conn->negotiated_version;
  params.version_info.available_versions = available_versions;
  params.version_info.available_versionslen = 1;

  rv = ngtcp2_conn_set_remote_transport_params(conn, &params);

  assert_int(NGTCP2_ERR_VERSION_NEGOTIATION_FAILURE, ==, rv);

  ngtcp2_conn_del(conn);

  /* client: client chooses version which differs from client chosen
     version from server's available_versions and chosen version. */
  setup_handshake_client(&conn);

  conn->local.settings.original_version = NGTCP2_PROTO_VER_V2;
  conn->negotiated_version = 0xff000000u;

  conn->vneg.preferred_versions[0] = 0xff000000u;

  ngtcp2_put_uint32be(conn->vneg.available_versions, NGTCP2_PROTO_VER_V1);
  ngtcp2_put_uint32be(conn->vneg.available_versions + sizeof(uint32_t),
                      0xff000000u);

  ngtcp2_put_uint32be(available_versions, 0xff000000u);

  memset(&params, 0, sizeof(params));
  params.active_connection_id_limit = NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT;
  params.max_udp_payload_size = 1450;
  params.initial_scid = conn->dcid.current.cid;
  params.initial_scid_present = 1;
  params.original_dcid = conn->rcid;
  params.original_dcid_present = 1;
  params.version_info_present = 1;
  params.version_info.chosen_version = conn->negotiated_version;
  params.version_info.available_versions = available_versions;
  params.version_info.available_versionslen = 1;

  rv = ngtcp2_conn_set_remote_transport_params(conn, &params);

  assert_int(NGTCP2_ERR_VERSION_NEGOTIATION_FAILURE, ==, rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_write_connection_close(void) {
  ngtcp2_conn *conn;
  uint8_t buf[1200];
  ngtcp2_ssize spktlen, shdlen;
  ngtcp2_pkt_hd hd;
  const uint8_t *p;
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  ngtcp2_crypto_ctx crypto_ctx;
  ngtcp2_ccerr ccerr;

  /* Client only Initial key */
  setup_handshake_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), 0);

  assert_ptrdiff(0, <, spktlen);

  ngtcp2_ccerr_set_transport_error(&ccerr, NGTCP2_NO_ERROR,
                                   (const uint8_t *)"foo", 3);

  spktlen = ngtcp2_conn_write_connection_close(conn, NULL, NULL, buf,
                                               sizeof(buf), &ccerr, 0);

  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, <=, spktlen);

  shdlen = ngtcp2_pkt_decode_hd_long(&hd, buf, (size_t)spktlen);

  assert_ptrdiff(0, <, shdlen);
  assert_uint8(NGTCP2_PKT_INITIAL, ==, hd.type);
  assert_ptrdiff(shdlen + (ngtcp2_ssize)hd.len, ==, spktlen);

  ngtcp2_conn_del(conn);

  /* Client has Initial and Handshake keys */
  setup_handshake_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), 0);

  assert_ptrdiff(0, <, spktlen);

  init_crypto_ctx(&crypto_ctx);

  ngtcp2_conn_set_crypto_ctx(conn, &crypto_ctx);
  conn->negotiated_version = conn->client_chosen_version;
  ngtcp2_conn_install_tx_handshake_key(conn, &aead_ctx, null_iv,
                                       sizeof(null_iv), &hp_ctx);

  ngtcp2_ccerr_set_liberr(&ccerr, 0, NULL, 0);

  spktlen = ngtcp2_conn_write_connection_close(conn, NULL, NULL, buf,
                                               sizeof(buf), &ccerr, 0);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, >, spktlen);

  shdlen = ngtcp2_pkt_decode_hd_long(&hd, buf, (size_t)spktlen);

  assert_ptrdiff(0, <, shdlen);
  assert_uint8(NGTCP2_PKT_HANDSHAKE, ==, hd.type);
  assert_ptrdiff(shdlen + (ngtcp2_ssize)hd.len, ==, spktlen);

  ngtcp2_conn_del(conn);

  /* Client has all keys and has not confirmed handshake */
  setup_handshake_client(&conn);

  init_crypto_ctx(&crypto_ctx);

  ngtcp2_conn_set_crypto_ctx(conn, &crypto_ctx);
  conn->negotiated_version = conn->client_chosen_version;
  ngtcp2_conn_install_tx_handshake_key(conn, &aead_ctx, null_iv,
                                       sizeof(null_iv), &hp_ctx);
  ngtcp2_conn_install_tx_key(conn, null_secret, sizeof(null_secret), &aead_ctx,
                             null_iv, sizeof(null_iv), &hp_ctx);

  conn->state = NGTCP2_CS_POST_HANDSHAKE;

  ngtcp2_ccerr_set_transport_error(&ccerr, NGTCP2_NO_ERROR, NULL, 0);

  spktlen = ngtcp2_conn_write_connection_close(conn, NULL, NULL, buf,
                                               sizeof(buf), &ccerr, 0);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, >, spktlen);

  p = buf;

  shdlen = ngtcp2_pkt_decode_hd_long(&hd, p, (size_t)spktlen);

  assert_ptrdiff(0, <, shdlen);
  assert_uint8(NGTCP2_PKT_HANDSHAKE, ==, hd.type);

  p += shdlen + (ngtcp2_ssize)hd.len;
  spktlen -= shdlen + (ngtcp2_ssize)hd.len;

  shdlen = ngtcp2_pkt_decode_hd_short(&hd, p, (size_t)spktlen,
                                      conn->dcid.current.cid.datalen);
  assert_ptrdiff(0, <, shdlen);
  assert_uint8(NGTCP2_PKT_1RTT, ==, hd.type);

  ngtcp2_conn_del(conn);

  /* Client has confirmed handshake */
  setup_default_client(&conn);

  ngtcp2_ccerr_set_transport_error(&ccerr, NGTCP2_NO_ERROR, NULL, 0);

  spktlen = ngtcp2_conn_write_connection_close(conn, NULL, NULL, buf,
                                               sizeof(buf), &ccerr, 0);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, >, spktlen);

  shdlen = ngtcp2_pkt_decode_hd_short(&hd, buf, (size_t)spktlen,
                                      conn->dcid.current.cid.datalen);

  assert_ptrdiff(0, <, shdlen);
  assert_uint8(NGTCP2_PKT_1RTT, ==, hd.type);

  ngtcp2_conn_del(conn);

  /* Server has Initial and Handshake key */
  setup_handshake_server(&conn);

  conn->dcid.current.bytes_recv = NGTCP2_MAX_UDP_PAYLOAD_SIZE;

  init_initial_crypto_ctx(&crypto_ctx);

  ngtcp2_conn_set_initial_crypto_ctx(conn, &crypto_ctx);
  ngtcp2_conn_install_initial_key(conn, &aead_ctx, null_iv, &hp_ctx, &aead_ctx,
                                  null_iv, &hp_ctx, sizeof(null_iv));

  init_crypto_ctx(&crypto_ctx);

  ngtcp2_conn_set_crypto_ctx(conn, &crypto_ctx);
  conn->negotiated_version = conn->client_chosen_version;
  ngtcp2_conn_install_tx_handshake_key(conn, &aead_ctx, null_iv,
                                       sizeof(null_iv), &hp_ctx);

  ngtcp2_ccerr_set_transport_error(&ccerr, NGTCP2_NO_ERROR, NULL, 0);

  spktlen = ngtcp2_conn_write_connection_close(conn, NULL, NULL, buf,
                                               sizeof(buf), &ccerr, 0);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, >, spktlen);

  p = buf;

  shdlen = ngtcp2_pkt_decode_hd_long(&hd, p, (size_t)spktlen);

  assert_ptrdiff(0, <, shdlen);
  assert_uint8(NGTCP2_PKT_INITIAL, ==, hd.type);

  p += shdlen + (ngtcp2_ssize)hd.len;
  spktlen -= shdlen + (ngtcp2_ssize)hd.len;

  shdlen = ngtcp2_pkt_decode_hd_long(&hd, p, (size_t)spktlen);

  assert_ptrdiff(0, <, shdlen);
  assert_uint8(NGTCP2_PKT_HANDSHAKE, ==, hd.type);
  assert_ptrdiff(shdlen + (ngtcp2_ssize)hd.len, ==, spktlen);

  ngtcp2_conn_del(conn);

  /* Server has all keys and has not confirmed handshake */
  setup_handshake_server(&conn);

  conn->dcid.current.bytes_recv = NGTCP2_MAX_UDP_PAYLOAD_SIZE;

  init_initial_crypto_ctx(&crypto_ctx);

  ngtcp2_conn_set_initial_crypto_ctx(conn, &crypto_ctx);
  ngtcp2_conn_install_initial_key(conn, &aead_ctx, null_iv, &hp_ctx, &aead_ctx,
                                  null_iv, &hp_ctx, sizeof(null_iv));

  init_crypto_ctx(&crypto_ctx);

  ngtcp2_conn_set_crypto_ctx(conn, &crypto_ctx);
  conn->negotiated_version = conn->client_chosen_version;
  ngtcp2_conn_install_tx_handshake_key(conn, &aead_ctx, null_iv,
                                       sizeof(null_iv), &hp_ctx);
  ngtcp2_conn_install_tx_key(conn, null_secret, sizeof(null_secret), &aead_ctx,
                             null_iv, sizeof(null_iv), &hp_ctx);

  conn->state = NGTCP2_CS_POST_HANDSHAKE;

  ngtcp2_ccerr_set_transport_error(&ccerr, NGTCP2_NO_ERROR, NULL, 0);

  spktlen = ngtcp2_conn_write_connection_close(conn, NULL, NULL, buf,
                                               sizeof(buf), &ccerr, 0);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, >, spktlen);

  p = buf;

  shdlen = ngtcp2_pkt_decode_hd_long(&hd, p, (size_t)spktlen);

  assert_ptrdiff(0, <, shdlen);
  assert_uint8(NGTCP2_PKT_INITIAL, ==, hd.type);

  p += shdlen + (ngtcp2_ssize)hd.len;
  spktlen -= shdlen + (ngtcp2_ssize)hd.len;

  shdlen = ngtcp2_pkt_decode_hd_long(&hd, p, (size_t)spktlen);

  assert_ptrdiff(0, <, shdlen);
  assert_uint8(NGTCP2_PKT_HANDSHAKE, ==, hd.type);

  p += shdlen + (ngtcp2_ssize)hd.len;
  spktlen -= shdlen + (ngtcp2_ssize)hd.len;

  shdlen = ngtcp2_pkt_decode_hd_short(&hd, p, (size_t)spktlen,
                                      conn->dcid.current.cid.datalen);

  assert_ptrdiff(0, <, shdlen);
  assert_uint8(NGTCP2_PKT_1RTT, ==, hd.type);

  ngtcp2_conn_del(conn);

  /* Server has confirmed handshake */
  setup_default_server(&conn);

  ngtcp2_ccerr_set_transport_error(&ccerr, NGTCP2_NO_ERROR, NULL, 0);

  spktlen = ngtcp2_conn_write_connection_close(conn, NULL, NULL, buf,
                                               sizeof(buf), &ccerr, 0);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, >, spktlen);

  shdlen = ngtcp2_pkt_decode_hd_short(&hd, buf, (size_t)spktlen,
                                      conn->dcid.current.cid.datalen);

  assert_ptrdiff(0, <, shdlen);
  assert_uint8(NGTCP2_PKT_1RTT, ==, hd.type);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_write_application_close(void) {
  ngtcp2_conn *conn;
  uint8_t buf[1200];
  ngtcp2_ssize spktlen, shdlen;
  ngtcp2_pkt_hd hd;
  const uint8_t *p;
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  uint64_t app_err_code = 0;
  ngtcp2_crypto_ctx crypto_ctx;
  ngtcp2_ccerr ccerr;

  /* Client only Initial key */
  setup_handshake_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), 0);

  assert_ptrdiff(0, <, spktlen);

  ngtcp2_ccerr_set_application_error(&ccerr, app_err_code,
                                     (const uint8_t *)"foo", 3);

  spktlen = ngtcp2_conn_write_connection_close(conn, NULL, NULL, buf,
                                               sizeof(buf), &ccerr, 0);

  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, <=, spktlen);

  shdlen = ngtcp2_pkt_decode_hd_long(&hd, buf, (size_t)spktlen);

  assert_ptrdiff(0, <, shdlen);
  assert_uint8(NGTCP2_PKT_INITIAL, ==, hd.type);
  assert_ptrdiff(shdlen + (ngtcp2_ssize)hd.len, ==, spktlen);

  ngtcp2_conn_del(conn);

  /* Client has Initial and Handshake keys */
  setup_handshake_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), 0);

  assert_ptrdiff(0, <, spktlen);

  init_crypto_ctx(&crypto_ctx);

  ngtcp2_conn_set_crypto_ctx(conn, &crypto_ctx);
  conn->negotiated_version = conn->client_chosen_version;
  ngtcp2_conn_install_tx_handshake_key(conn, &aead_ctx, null_iv,
                                       sizeof(null_iv), &hp_ctx);

  ngtcp2_ccerr_set_application_error(&ccerr, app_err_code, NULL, 0);

  spktlen = ngtcp2_conn_write_connection_close(conn, NULL, NULL, buf,
                                               sizeof(buf), &ccerr, 0);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, >, spktlen);

  shdlen = ngtcp2_pkt_decode_hd_long(&hd, buf, (size_t)spktlen);

  assert_ptrdiff(0, <, shdlen);
  assert_uint8(NGTCP2_PKT_HANDSHAKE, ==, hd.type);
  assert_ptrdiff(shdlen + (ngtcp2_ssize)hd.len, ==, spktlen);

  ngtcp2_conn_del(conn);

  /* Client has all keys and has not confirmed handshake */
  setup_handshake_client(&conn);

  init_crypto_ctx(&crypto_ctx);

  ngtcp2_conn_set_crypto_ctx(conn, &crypto_ctx);
  conn->negotiated_version = conn->client_chosen_version;
  ngtcp2_conn_install_tx_handshake_key(conn, &aead_ctx, null_iv,
                                       sizeof(null_iv), &hp_ctx);
  ngtcp2_conn_install_tx_key(conn, null_secret, sizeof(null_secret), &aead_ctx,
                             null_iv, sizeof(null_iv), &hp_ctx);

  conn->state = NGTCP2_CS_POST_HANDSHAKE;

  ngtcp2_ccerr_set_application_error(&ccerr, app_err_code, NULL, 0);

  spktlen = ngtcp2_conn_write_connection_close(conn, NULL, NULL, buf,
                                               sizeof(buf), &ccerr, 0);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, >, spktlen);

  p = buf;

  shdlen = ngtcp2_pkt_decode_hd_long(&hd, p, (size_t)spktlen);

  assert_ptrdiff(0, <, shdlen);
  assert_uint8(NGTCP2_PKT_HANDSHAKE, ==, hd.type);

  p += shdlen + (ngtcp2_ssize)hd.len;
  spktlen -= shdlen + (ngtcp2_ssize)hd.len;

  shdlen = ngtcp2_pkt_decode_hd_short(&hd, p, (size_t)spktlen,
                                      conn->dcid.current.cid.datalen);
  assert_ptrdiff(0, <, shdlen);
  assert_uint8(NGTCP2_PKT_1RTT, ==, hd.type);

  ngtcp2_conn_del(conn);

  /* Client has confirmed handshake */
  setup_default_client(&conn);

  ngtcp2_ccerr_set_application_error(&ccerr, app_err_code, NULL, 0);

  spktlen = ngtcp2_conn_write_connection_close(conn, NULL, NULL, buf,
                                               sizeof(buf), &ccerr, 0);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, >, spktlen);

  shdlen = ngtcp2_pkt_decode_hd_short(&hd, buf, (size_t)spktlen,
                                      conn->dcid.current.cid.datalen);

  assert_ptrdiff(0, <, shdlen);
  assert_uint8(NGTCP2_PKT_1RTT, ==, hd.type);

  ngtcp2_conn_del(conn);

  /* Server has Initial and Handshake key */
  setup_handshake_server(&conn);

  conn->dcid.current.bytes_recv = NGTCP2_MAX_UDP_PAYLOAD_SIZE;

  init_initial_crypto_ctx(&crypto_ctx);

  ngtcp2_conn_set_initial_crypto_ctx(conn, &crypto_ctx);
  ngtcp2_conn_install_initial_key(conn, &aead_ctx, null_iv, &hp_ctx, &aead_ctx,
                                  null_iv, &hp_ctx, sizeof(null_iv));

  init_crypto_ctx(&crypto_ctx);

  ngtcp2_conn_set_crypto_ctx(conn, &crypto_ctx);
  conn->negotiated_version = conn->client_chosen_version;
  ngtcp2_conn_install_tx_handshake_key(conn, &aead_ctx, null_iv,
                                       sizeof(null_iv), &hp_ctx);

  ngtcp2_ccerr_set_application_error(&ccerr, app_err_code, NULL, 0);

  spktlen = ngtcp2_conn_write_connection_close(conn, NULL, NULL, buf,
                                               sizeof(buf), &ccerr, 0);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, >, spktlen);

  p = buf;

  shdlen = ngtcp2_pkt_decode_hd_long(&hd, p, (size_t)spktlen);

  assert_ptrdiff(0, <, shdlen);
  assert_uint8(NGTCP2_PKT_INITIAL, ==, hd.type);

  p += shdlen + (ngtcp2_ssize)hd.len;
  spktlen -= shdlen + (ngtcp2_ssize)hd.len;

  shdlen = ngtcp2_pkt_decode_hd_long(&hd, p, (size_t)spktlen);

  assert_ptrdiff(0, <, shdlen);
  assert_uint8(NGTCP2_PKT_HANDSHAKE, ==, hd.type);
  assert_ptrdiff(shdlen + (ngtcp2_ssize)hd.len, ==, spktlen);

  ngtcp2_conn_del(conn);

  /* Server has all keys and has not confirmed handshake */
  setup_handshake_server(&conn);

  conn->dcid.current.bytes_recv = NGTCP2_MAX_UDP_PAYLOAD_SIZE;

  init_initial_crypto_ctx(&crypto_ctx);

  ngtcp2_conn_set_initial_crypto_ctx(conn, &crypto_ctx);
  ngtcp2_conn_install_initial_key(conn, &aead_ctx, null_iv, &hp_ctx, &aead_ctx,
                                  null_iv, &hp_ctx, sizeof(null_iv));

  init_crypto_ctx(&crypto_ctx);

  ngtcp2_conn_set_crypto_ctx(conn, &crypto_ctx);
  conn->negotiated_version = conn->client_chosen_version;
  ngtcp2_conn_install_tx_handshake_key(conn, &aead_ctx, null_iv,
                                       sizeof(null_iv), &hp_ctx);
  ngtcp2_conn_install_tx_key(conn, null_secret, sizeof(null_secret), &aead_ctx,
                             null_iv, sizeof(null_iv), &hp_ctx);

  ngtcp2_ccerr_set_application_error(&ccerr, app_err_code, NULL, 0);

  spktlen = ngtcp2_conn_write_connection_close(conn, NULL, NULL, buf,
                                               sizeof(buf), &ccerr, 0);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, >, spktlen);

  p = buf;

  shdlen = ngtcp2_pkt_decode_hd_long(&hd, p, (size_t)spktlen);

  assert_ptrdiff(0, <, shdlen);
  assert_uint8(NGTCP2_PKT_INITIAL, ==, hd.type);

  p += shdlen + (ngtcp2_ssize)hd.len;
  spktlen -= shdlen + (ngtcp2_ssize)hd.len;

  shdlen = ngtcp2_pkt_decode_hd_long(&hd, p, (size_t)spktlen);

  assert_ptrdiff(0, <, shdlen);
  assert_uint8(NGTCP2_PKT_HANDSHAKE, ==, hd.type);

  p += shdlen + (ngtcp2_ssize)hd.len;
  spktlen -= shdlen + (ngtcp2_ssize)hd.len;

  shdlen = ngtcp2_pkt_decode_hd_short(&hd, p, (size_t)spktlen,
                                      conn->dcid.current.cid.datalen);

  assert_ptrdiff(0, <, shdlen);
  assert_uint8(NGTCP2_PKT_1RTT, ==, hd.type);

  ngtcp2_conn_del(conn);

  /* Server has all keys and has confirmed handshake, but not
     transitioned to NGTCP2_CS_POST_HANDSHAKE. */
  setup_handshake_server(&conn);

  conn->dcid.current.bytes_recv = NGTCP2_MAX_UDP_PAYLOAD_SIZE;

  init_initial_crypto_ctx(&crypto_ctx);

  ngtcp2_conn_set_initial_crypto_ctx(conn, &crypto_ctx);
  ngtcp2_conn_install_initial_key(conn, &aead_ctx, null_iv, &hp_ctx, &aead_ctx,
                                  null_iv, &hp_ctx, sizeof(null_iv));

  init_crypto_ctx(&crypto_ctx);

  ngtcp2_conn_set_crypto_ctx(conn, &crypto_ctx);
  conn->negotiated_version = conn->client_chosen_version;
  ngtcp2_conn_install_tx_handshake_key(conn, &aead_ctx, null_iv,
                                       sizeof(null_iv), &hp_ctx);
  ngtcp2_conn_install_tx_key(conn, null_secret, sizeof(null_secret), &aead_ctx,
                             null_iv, sizeof(null_iv), &hp_ctx);

  ngtcp2_conn_tls_handshake_completed(conn);

  ngtcp2_ccerr_set_application_error(&ccerr, app_err_code, NULL, 0);

  spktlen = ngtcp2_conn_write_connection_close(conn, NULL, NULL, buf,
                                               sizeof(buf), &ccerr, 0);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, >, spktlen);

  p = buf;

  shdlen = ngtcp2_pkt_decode_hd_short(&hd, p, (size_t)spktlen,
                                      conn->dcid.current.cid.datalen);

  assert_ptrdiff(0, <, shdlen);
  assert_uint8(NGTCP2_PKT_1RTT, ==, hd.type);

  ngtcp2_conn_del(conn);

  /* Server has confirmed handshake */
  setup_default_server(&conn);

  ngtcp2_ccerr_set_application_error(&ccerr, app_err_code, NULL, 0);

  spktlen = ngtcp2_conn_write_connection_close(conn, NULL, NULL, buf,
                                               sizeof(buf), &ccerr, 0);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, >, spktlen);

  shdlen = ngtcp2_pkt_decode_hd_short(&hd, buf, (size_t)spktlen,
                                      conn->dcid.current.cid.datalen);

  assert_ptrdiff(0, <, shdlen);
  assert_uint8(NGTCP2_PKT_1RTT, ==, hd.type);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_rtb_reclaim_on_pto(void) {
  ngtcp2_conn *conn;
  int rv;
  int64_t stream_id;
  uint8_t buf[2048];
  ngtcp2_ssize nwrite;
  ngtcp2_ssize spktlen;
  size_t i;
  size_t num_reclaim_pkt;
  ngtcp2_rtb_entry *ent;
  ngtcp2_ksl_it it;

  setup_default_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  for (i = 0; i < 5; ++i) {
    spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf),
                                       &nwrite, NGTCP2_WRITE_STREAM_FLAG_NONE,
                                       stream_id, null_data, 1024, 1);

    assert_ptrdiff(0, <, spktlen);
  }

  assert_size(5, ==, ngtcp2_ksl_len(&conn->pktns.rtb.ents));

  rv = ngtcp2_conn_on_loss_detection_timer(conn, 3 * NGTCP2_SECONDS);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf),
                                  3 * NGTCP2_SECONDS);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_ksl_begin(&conn->pktns.rtb.ents);
  num_reclaim_pkt = 0;
  for (; !ngtcp2_ksl_it_end(&it); ngtcp2_ksl_it_next(&it)) {
    ent = ngtcp2_ksl_it_get(&it);
    if (ent->flags & NGTCP2_RTB_ENTRY_FLAG_PTO_RECLAIMED) {
      ++num_reclaim_pkt;
    }
  }

  assert_size(1, ==, num_reclaim_pkt);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_rtb_reclaim_on_pto_datagram(void) {
  ngtcp2_conn *conn;
  int rv;
  int64_t stream_id;
  uint8_t buf[2048];
  ngtcp2_ssize nwrite;
  ngtcp2_ssize spktlen;
  size_t num_reclaim_pkt;
  ngtcp2_rtb_entry *ent;
  ngtcp2_ksl_it it;
  ngtcp2_vec datav;
  int accepted;
  ngtcp2_frame_chain *frc;

  /* DATAGRAM frame must not be reclaimed on PTO */
  setup_default_client(&conn);

  conn->callbacks.ack_datagram = ack_datagram;
  conn->remote.transport_params->max_datagram_frame_size = 65535;

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf),
                                     &nwrite, NGTCP2_WRITE_STREAM_FLAG_NONE,
                                     stream_id, null_data, 1024, 1);

  assert_ptrdiff(0, <, spktlen);

  datav.base = null_data;
  datav.len = 10;

  spktlen = ngtcp2_conn_writev_datagram(
      conn, NULL, NULL, buf, sizeof(buf), &accepted,
      NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 1000000007, &datav, 1, 1);

  assert_true(accepted);
  assert_ptrdiff(0, <, spktlen);
  assert_size(2, ==, ngtcp2_ksl_len(&conn->pktns.rtb.ents));

  rv = ngtcp2_conn_on_loss_detection_timer(conn, 3 * NGTCP2_SECONDS);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf),
                                  3 * NGTCP2_SECONDS);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_ksl_begin(&conn->pktns.rtb.ents);
  num_reclaim_pkt = 0;
  for (; !ngtcp2_ksl_it_end(&it); ngtcp2_ksl_it_next(&it)) {
    ent = ngtcp2_ksl_it_get(&it);
    if (ent->flags & NGTCP2_RTB_ENTRY_FLAG_PTO_RECLAIMED) {
      ++num_reclaim_pkt;
      for (frc = ent->frc; frc; frc = frc->next) {
        assert_uint64(NGTCP2_FRAME_DATAGRAM, !=, frc->fr.type);
      }
    }
  }

  assert_size(1, ==, num_reclaim_pkt);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_validate_ecn(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  ngtcp2_ssize spktlen;
  ngtcp2_pkt_info pi;
  size_t pktlen;
  int rv;
  ngtcp2_frame fr;
  int64_t stream_id;
  ngtcp2_ssize nwrite;
  size_t i;
  ngtcp2_tstamp t = 0;

  setup_default_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, &pi, buf, sizeof(buf), 1);

  assert_ptrdiff(0, <, spktlen);
  assert_uint8(NGTCP2_ECN_ECT_0, ==, pi.ecn);
  assert_int((int)NGTCP2_ECN_STATE_TESTING, ==, (int)conn->tx.ecn.state);
  assert_uint64(1, ==, conn->tx.ecn.validation_start_ts);
  assert_int64(0, ==, conn->pktns.tx.ecn.start_pkt_num);

  fr.type = NGTCP2_FRAME_ACK_ECN;
  fr.ack.largest_ack = 0;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;
  fr.ack.ecn.ect0 = 1;
  fr.ack.ecn.ect1 = 0;
  fr.ack.ecn.ce = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 0, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 2);

  assert_int(0, ==, rv);
  assert_int((int)NGTCP2_ECN_STATE_CAPABLE, ==, (int)conn->tx.ecn.state);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, &pi, buf, sizeof(buf), &nwrite,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 1024, 2);

  assert_ptrdiff(0, <, spktlen);

  /* Receiving ACK frame containing less ECN counts fails
     validation */
  fr.type = NGTCP2_FRAME_ACK_ECN;
  fr.ack.largest_ack = 1;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;
  fr.ack.ecn.ect0 = 0;
  fr.ack.ecn.ect1 = 0;
  fr.ack.ecn.ce = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 3);

  assert_int(0, ==, rv);
  assert_int((int)NGTCP2_ECN_STATE_FAILED, ==, (int)conn->tx.ecn.state);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, &pi, buf, sizeof(buf), &nwrite,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 1024, 3);

  assert_ptrdiff(0, <, spktlen);
  assert_uint8(NGTCP2_ECN_NOT_ECT, ==, pi.ecn);

  ngtcp2_conn_del(conn);

  /* Receiving ACK frame without ECN counts invalidates ECN
     capability */
  setup_default_server(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, &pi, buf, sizeof(buf), 1);

  assert_ptrdiff(0, <, spktlen);
  assert_uint8(NGTCP2_ECN_ECT_0, ==, pi.ecn);
  assert_int((int)NGTCP2_ECN_STATE_TESTING, ==, (int)conn->tx.ecn.state);
  assert_uint64(1, ==, conn->tx.ecn.validation_start_ts);
  assert_int64(0, ==, conn->pktns.tx.ecn.start_pkt_num);

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = 0;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 0, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 2);

  assert_int(0, ==, rv);
  assert_int((int)NGTCP2_ECN_STATE_FAILED, ==, (int)conn->tx.ecn.state);

  ngtcp2_conn_del(conn);

  /* CE counts must be considered */
  setup_default_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  for (i = 0; i < 2; ++i) {
    spktlen = ngtcp2_conn_write_stream(conn, NULL, &pi, buf, sizeof(buf),
                                       &nwrite, NGTCP2_WRITE_STREAM_FLAG_NONE,
                                       stream_id, null_data, 1024, 2);

    assert_ptrdiff(0, <, spktlen);
    assert_uint8(NGTCP2_ECN_ECT_0, ==, pi.ecn);
  }

  assert_int((int)NGTCP2_ECN_STATE_TESTING, ==, (int)conn->tx.ecn.state);
  assert_uint64(2, ==, conn->tx.ecn.validation_start_ts);
  assert_int64(0, ==, conn->pktns.tx.ecn.start_pkt_num);

  fr.type = NGTCP2_FRAME_ACK_ECN;
  fr.ack.largest_ack = 1;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_range = 1;
  fr.ack.rangecnt = 0;
  fr.ack.ecn.ect0 = 1;
  fr.ack.ecn.ect1 = 0;
  fr.ack.ecn.ce = 1;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 0, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 2);

  assert_int(0, ==, rv);
  assert_int((int)NGTCP2_ECN_STATE_CAPABLE, ==, (int)conn->tx.ecn.state);
  assert_size(0, ==, ngtcp2_ksl_len(&conn->pktns.rtb.ents));

  ngtcp2_conn_del(conn);

  /* If increments of ECN counts is less than the number of
     acknowledged ECN entries, ECN validation fails. */
  setup_default_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, &pi, buf, sizeof(buf), 1);

  assert_ptrdiff(0, <, spktlen);
  assert_uint8(NGTCP2_ECN_ECT_0, ==, pi.ecn);
  assert_int((int)NGTCP2_ECN_STATE_TESTING, ==, (int)conn->tx.ecn.state);
  assert_uint64(1, ==, conn->tx.ecn.validation_start_ts);
  assert_int64(0, ==, conn->pktns.tx.ecn.start_pkt_num);

  fr.type = NGTCP2_FRAME_ACK_ECN;
  fr.ack.largest_ack = 0;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;
  fr.ack.ecn.ect0 = 0;
  fr.ack.ecn.ect1 = 1;
  fr.ack.ecn.ce = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 0, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 2);

  assert_int(0, ==, rv);
  assert_int((int)NGTCP2_ECN_STATE_FAILED, ==, (int)conn->tx.ecn.state);

  ngtcp2_conn_del(conn);

  /* If ECT count is larger than the number of ECT marked packet, ECN
     validation fails. */
  setup_default_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, &pi, buf, sizeof(buf), 1);

  assert_ptrdiff(0, <, spktlen);
  assert_uint8(NGTCP2_ECN_ECT_0, ==, pi.ecn);
  assert_int((int)NGTCP2_ECN_STATE_TESTING, ==, (int)conn->tx.ecn.state);
  assert_uint64(1, ==, conn->tx.ecn.validation_start_ts);
  assert_int64(0, ==, conn->pktns.tx.ecn.start_pkt_num);

  fr.type = NGTCP2_FRAME_ACK_ECN;
  fr.ack.largest_ack = 0;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;
  fr.ack.ecn.ect0 = 2;
  fr.ack.ecn.ect1 = 0;
  fr.ack.ecn.ce = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 0, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, 2);

  assert_int(0, ==, rv);
  assert_int((int)NGTCP2_ECN_STATE_FAILED, ==, (int)conn->tx.ecn.state);

  ngtcp2_conn_del(conn);

  /* ECN validation fails if all ECN marked packets are lost */
  setup_default_client(&conn);

  t = 0;

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  for (i = 0; i < NGTCP2_ECN_MAX_NUM_VALIDATION_PKTS; ++i) {
    spktlen = ngtcp2_conn_write_stream(conn, NULL, &pi, buf, sizeof(buf),
                                       &nwrite, NGTCP2_WRITE_STREAM_FLAG_NONE,
                                       stream_id, null_data, 25, t);

    assert_ptrdiff(0, <, spktlen);
    assert_uint8(NGTCP2_ECN_ECT_0, ==, pi.ecn);
  }

  assert_int((int)NGTCP2_ECN_STATE_UNKNOWN, ==, (int)conn->tx.ecn.state);
  assert_size(NGTCP2_ECN_MAX_NUM_VALIDATION_PKTS, ==, conn->tx.ecn.dgram_sent);

  t += NGTCP2_MILLISECONDS;

  spktlen = ngtcp2_conn_write_stream(conn, NULL, &pi, buf, sizeof(buf), &nwrite,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 25, t);

  assert_ptrdiff(0, <, spktlen);
  assert_uint8(NGTCP2_ECN_NOT_ECT, ==, pi.ecn);
  assert_int((int)NGTCP2_ECN_STATE_UNKNOWN, ==, (int)conn->tx.ecn.state);
  assert_uint64(0, ==, conn->tx.ecn.validation_start_ts);
  assert_int64(0, ==, conn->pktns.tx.ecn.start_pkt_num);
  assert_size(NGTCP2_ECN_MAX_NUM_VALIDATION_PKTS, ==, conn->tx.ecn.dgram_sent);
  assert_size(0, ==, conn->pktns.tx.ecn.validation_pkt_lost);

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = NGTCP2_ECN_MAX_NUM_VALIDATION_PKTS;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;

  t += NGTCP2_MILLISECONDS;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 0, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, t);

  assert_int(0, ==, rv);

  assert_int((int)NGTCP2_ECN_STATE_FAILED, ==, (int)conn->tx.ecn.state);
  assert_size(NGTCP2_ECN_MAX_NUM_VALIDATION_PKTS, ==,
              conn->pktns.tx.ecn.validation_pkt_lost);

  ngtcp2_conn_del(conn);

  /* ECN validation fails if all ECN marked packets sent in last 3 *
     RTT are lost */
  setup_default_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  for (i = 0; i < 2; ++i) {
    spktlen = ngtcp2_conn_write_stream(conn, NULL, &pi, buf, sizeof(buf),
                                       &nwrite, NGTCP2_WRITE_STREAM_FLAG_NONE,
                                       stream_id, null_data, 25, 0);

    assert_ptrdiff(0, <, spktlen);
    assert_uint8(NGTCP2_ECN_ECT_0, ==, pi.ecn);
  }

  assert_int((int)NGTCP2_ECN_STATE_TESTING, ==, (int)conn->tx.ecn.state);
  assert_size(2, ==, conn->tx.ecn.dgram_sent);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, &pi, buf, sizeof(buf), &nwrite,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 25, 3 * NGTCP2_SECONDS);

  assert_ptrdiff(0, <, spktlen);
  assert_uint8(NGTCP2_ECN_NOT_ECT, ==, pi.ecn);
  assert_int((int)NGTCP2_ECN_STATE_UNKNOWN, ==, (int)conn->tx.ecn.state);
  assert_uint64(0, ==, conn->tx.ecn.validation_start_ts);
  assert_int64(0, ==, conn->pktns.tx.ecn.start_pkt_num);
  assert_size(2, ==, conn->pktns.tx.ecn.validation_pkt_sent);
  assert_size(0, ==, conn->pktns.tx.ecn.validation_pkt_lost);

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = 2;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 0, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen,
                            4 * NGTCP2_SECONDS);

  assert_int(0, ==, rv);
  assert_int((int)NGTCP2_ECN_STATE_FAILED, ==, (int)conn->tx.ecn.state);
  assert_size(2, ==, conn->pktns.tx.ecn.validation_pkt_lost);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_path_validation(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 0;
  int64_t pkt_num = 0;
  ngtcp2_frame frs[4];
  int rv;
  ngtcp2_path_storage rpath, wpath;
  ngtcp2_pv_entry *ent;

  /* server starts path validation in NAT rebinding scenario. */
  setup_default_server(&conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  frs[0].type = NGTCP2_FRAME_PING;

  /* Just change remote port */
  path_init(&rpath, 0, 0, 0, 1);
  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, frs, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &rpath.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_not_null(conn->pv);
  assert_uint64(0, ==, conn->pv->dcid.seq);
  assert_true(ngtcp2_path_eq(&conn->pv->dcid.ps.path, &rpath.path));

  ngtcp2_path_storage_zero(&wpath);
  spktlen =
      ngtcp2_conn_write_pkt(conn, &wpath.path, NULL, buf, sizeof(buf), ++t);

  /* Server has not received enough bytes to pad probing packet. */
  assert_ptrdiff(1200, >, spktlen);
  assert_true(ngtcp2_path_eq(&rpath.path, &wpath.path));
  assert_size(1, ==, ngtcp2_ringbuf_len(&conn->pv->ents.rb));

  ent = ngtcp2_ringbuf_get(&conn->pv->ents.rb, 0);

  assert_true(ent->flags & NGTCP2_PV_ENTRY_FLAG_UNDERSIZED);
  assert_true(conn->pv->flags & NGTCP2_PV_FLAG_FALLBACK_ON_FAILURE);

  frs[0].type = NGTCP2_FRAME_PATH_RESPONSE;
  memcpy(frs[0].path_response.data, ent->data, sizeof(ent->data));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, frs, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &rpath.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  /* Start another path validation to probe least MTU */
  assert_not_null(conn->pv);
  assert_true(conn->pv->flags & NGTCP2_PV_FLAG_FALLBACK_ON_FAILURE);

  ngtcp2_path_storage_zero(&wpath);
  spktlen =
      ngtcp2_conn_write_pkt(conn, &wpath.path, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1200, <=, spktlen);
  assert_true(ngtcp2_path_eq(&rpath.path, &wpath.path));
  assert_size(1, ==, ngtcp2_ringbuf_len(&conn->pv->ents.rb));

  ent = ngtcp2_ringbuf_get(&conn->pv->ents.rb, 0);
  frs[0].type = NGTCP2_FRAME_PATH_RESPONSE;
  memcpy(frs[0].path_response.data, ent->data, sizeof(ent->data));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, frs, 1,
                     conn->pktns.crypto.rx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &rpath.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  /* Now perform another validation to old path */
  assert_not_null(conn->pv);
  assert_false(conn->pv->flags & NGTCP2_PV_FLAG_FALLBACK_ON_FAILURE);
  assert_true(conn->pv->flags & NGTCP2_PV_FLAG_DONT_CARE);

  ngtcp2_path_storage_zero(&wpath);
  spktlen =
      ngtcp2_conn_write_pkt(conn, &wpath.path, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1200, <=, spktlen);
  assert_true(ngtcp2_path_eq(&null_path.path, &wpath.path));
  assert_size(1, ==, ngtcp2_ringbuf_len(&conn->pv->ents.rb));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_early_data_sync_stream_data_limit(void) {
  ngtcp2_conn *conn;
  uint8_t buf[1024];
  ngtcp2_ssize spktlen;
  ngtcp2_ssize datalen;
  int64_t bidi_stream_id, uni_stream_id;
  int rv;
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_strm *strm;
  ngtcp2_tstamp t = 0;

  setup_early_client(&conn);

  conn->callbacks.recv_crypto_data = recv_crypto_data_client_handshake;

  rv = ngtcp2_conn_open_bidi_stream(conn, &bidi_stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf),
                                     &datalen, NGTCP2_WRITE_STREAM_FLAG_FIN,
                                     bidi_stream_id, null_data, 1024, ++t);

  assert_ptrdiff((ngtcp2_ssize)sizeof(buf), ==, spktlen);
  assert_ptrdiff(670, ==, datalen);

  rv = ngtcp2_conn_open_uni_stream(conn, &uni_stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf),
                                     &datalen, NGTCP2_WRITE_STREAM_FLAG_FIN,
                                     uni_stream_id, null_data, 1024, ++t);

  assert_ptrdiff((ngtcp2_ssize)sizeof(buf), ==, spktlen);
  assert_ptrdiff(956, ==, datalen);

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 198;
  fr.stream.data[0].base = null_data;

  pktlen = write_initial_pkt(buf, sizeof(buf), &conn->oscid,
                             ngtcp2_conn_get_dcid(conn), 0, NGTCP2_PROTO_VER_V1,
                             NULL, 0, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  pktlen = write_handshake_pkt(buf, sizeof(buf), &conn->oscid,
                               ngtcp2_conn_get_dcid(conn), 0,
                               NGTCP2_PROTO_VER_V1, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_true(ngtcp2_conn_get_handshake_completed(conn));

  strm = ngtcp2_conn_find_stream(conn, bidi_stream_id);

  assert_uint64(
      conn->remote.transport_params->initial_max_stream_data_bidi_remote, ==,
      strm->tx.max_offset);

  strm = ngtcp2_conn_find_stream(conn, uni_stream_id);

  assert_uint64(conn->remote.transport_params->initial_max_stream_data_uni, ==,
                strm->tx.max_offset);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_tls_early_data_rejected(void) {
  ngtcp2_conn *conn;
  uint8_t buf[1024];
  ngtcp2_ssize spktlen;
  ngtcp2_ssize datalen;
  int64_t bidi_stream_id, uni_stream_id;
  int rv;
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  ngtcp2_transport_params params;
  ngtcp2_tstamp t = 0;

  setup_early_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &bidi_stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf),
                                     &datalen, NGTCP2_WRITE_STREAM_FLAG_FIN,
                                     bidi_stream_id, null_data, 1024, ++t);

  assert_ptrdiff((ngtcp2_ssize)sizeof(buf), ==, spktlen);
  assert_ptrdiff(670, ==, datalen);

  rv = ngtcp2_conn_open_uni_stream(conn, &uni_stream_id, NULL);

  assert_int(0, ==, rv);

  ngtcp2_conn_extend_max_offset(conn, 1000);
  ngtcp2_conn_extend_max_streams_bidi(conn, 7);
  ngtcp2_conn_extend_max_streams_uni(conn, 5);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf),
                                     &datalen, NGTCP2_WRITE_STREAM_FLAG_FIN,
                                     uni_stream_id, null_data, 300, ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_uint64(0, <, conn->tx.offset);
  assert_uint64(conn->local.transport_params.initial_max_data + 1000, ==,
                conn->rx.unsent_max_offset);
  assert_uint64(conn->local.transport_params.initial_max_streams_bidi + 7, ==,
                conn->remote.bidi.unsent_max_streams);
  assert_uint64(conn->local.transport_params.initial_max_streams_bidi + 7, ==,
                conn->remote.bidi.max_streams);
  assert_uint64(conn->local.transport_params.initial_max_streams_uni + 5, ==,
                conn->remote.uni.unsent_max_streams);
  assert_uint64(conn->local.transport_params.initial_max_streams_uni + 5, ==,
                conn->remote.uni.max_streams);

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 198;
  fr.stream.data[0].base = null_data;

  pktlen = write_initial_pkt(buf, sizeof(buf), &conn->oscid,
                             ngtcp2_conn_get_dcid(conn), 0, NGTCP2_PROTO_VER_V1,
                             NULL, 0, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_install_rx_handshake_key(conn, &aead_ctx, null_iv,
                                            sizeof(null_iv), &hp_ctx);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_install_tx_handshake_key(conn, &aead_ctx, null_iv,
                                            sizeof(null_iv), &hp_ctx);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_install_rx_key(conn, null_secret, sizeof(null_secret),
                                  &aead_ctx, null_iv, sizeof(null_iv), &hp_ctx);

  assert_int(0, ==, rv);

  /* Stream limits in transport parameters can be reduced if early
     data is rejected. */
  memset(&params, 0, sizeof(params));
  ngtcp2_cid_init(&params.initial_scid, conn->dcid.current.cid.data,
                  conn->dcid.current.cid.datalen);
  params.initial_scid_present = 1;
  ngtcp2_cid_init(&params.original_dcid, conn->rcid.data, conn->rcid.datalen);
  params.original_dcid_present = 1;
  params.max_udp_payload_size = 1200;
  params.initial_max_stream_data_bidi_local =
      conn->early.transport_params.initial_max_stream_data_bidi_local;
  params.initial_max_stream_data_bidi_remote =
      conn->early.transport_params.initial_max_stream_data_bidi_remote / 2;
  params.initial_max_stream_data_uni = 0;
  params.initial_max_data = conn->early.transport_params.initial_max_data;
  params.initial_max_streams_bidi =
      conn->early.transport_params.initial_max_streams_bidi;
  params.initial_max_streams_uni =
      conn->early.transport_params.initial_max_streams_uni;
  params.active_connection_id_limit =
      conn->early.transport_params.active_connection_id_limit;

  rv = ngtcp2_conn_set_remote_transport_params(conn, &params);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_install_tx_key(conn, null_secret, sizeof(null_secret),
                                  &aead_ctx, null_iv, sizeof(null_iv), &hp_ctx);

  assert_int(0, ==, rv);

  ngtcp2_conn_tls_handshake_completed(conn);
  ngtcp2_conn_tls_early_data_rejected(conn);
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_null(ngtcp2_conn_find_stream(conn, bidi_stream_id));
  assert_null(ngtcp2_conn_find_stream(conn, uni_stream_id));
  assert_uint64(0, ==, conn->tx.offset);
  assert_uint64(conn->local.transport_params.initial_max_data, ==,
                conn->rx.max_offset);
  assert_uint64(conn->local.transport_params.initial_max_data, ==,
                conn->rx.unsent_max_offset);
  assert_uint64(conn->local.transport_params.initial_max_streams_bidi, ==,
                conn->remote.bidi.max_streams);
  assert_uint64(conn->local.transport_params.initial_max_streams_bidi, ==,
                conn->remote.bidi.unsent_max_streams);
  assert_uint64(conn->local.transport_params.initial_max_streams_uni, ==,
                conn->remote.uni.max_streams);
  assert_uint64(conn->local.transport_params.initial_max_streams_uni, ==,
                conn->remote.uni.unsent_max_streams);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_keep_alive(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  ngtcp2_ssize spktlen;
  ngtcp2_pkt_info pi;
  ngtcp2_tstamp t = 0;
  int rv;
  ngtcp2_frame fr;
  size_t pktlen;
  int64_t pkt_num = 0;
  ngtcp2_cid scid;
  ngtcp2_tstamp last_ts;

  setup_default_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, &pi, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, &pi, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, ==, spktlen);

  ngtcp2_conn_set_keep_alive_timeout(conn, 10 * NGTCP2_SECONDS);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, &pi, buf, sizeof(buf), t);

  assert_ptrdiff(0, ==, spktlen);

  t += 10 * NGTCP2_SECONDS;

  rv = ngtcp2_conn_handle_expiry(conn, t);

  assert_int(0, ==, rv);
  assert_true(conn->flags & NGTCP2_CONN_FLAG_KEEP_ALIVE_CANCELLED);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, &pi, buf, sizeof(buf), t);

  assert_ptrdiff(0, <, spktlen);
  assert_uint64(t, ==, conn->keep_alive.last_ts);

  ngtcp2_conn_del(conn);

  /* Keep alive PING is not sent during handshake */
  ngtcp2_cid_zero(&scid);

  setup_early_client_scid(&conn, &scid);

  ngtcp2_conn_set_keep_alive_timeout(conn, 10 * NGTCP2_MILLISECONDS);

  conn->callbacks.recv_crypto_data = recv_crypto_data_client_handshake;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1200, <=, spktlen);
  assert_size(0, ==, ngtcp2_ksl_len(&conn->pktns.rtb.ents));

  last_ts = conn->keep_alive.last_ts;

  assert_uint64(UINT64_MAX, !=, last_ts);

  t += 10 * NGTCP2_MILLISECONDS;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, ==, spktlen);
  assert_uint64(last_ts, ==, conn->keep_alive.last_ts);
  assert_uint64(10 * NGTCP2_MILLISECONDS, ==, conn->keep_alive.timeout);
  assert_true(ngtcp2_tstamp_elapsed(conn->keep_alive.last_ts,
                                    conn->keep_alive.timeout, t));

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 127;
  fr.stream.data[0].base = null_data;

  pktlen = write_initial_pkt(
      buf, sizeof(buf), &conn->oscid, ngtcp2_conn_get_dcid(conn), ++pkt_num,
      conn->client_chosen_version, NULL, 0, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  pktlen = write_handshake_pkt(buf, sizeof(buf), &conn->oscid,
                               ngtcp2_conn_get_dcid(conn), ++pkt_num,
                               conn->client_chosen_version, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  t += 10 * NGTCP2_MILLISECONDS;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_true(conn->flags & NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED);
  /* 1-RTT packet includes PADDING frame. */
  assert_size(1, ==, ngtcp2_ksl_len(&conn->pktns.rtb.ents));

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, ==, spktlen);

  t += 10 * NGTCP2_MILLISECONDS;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_retire_stale_bound_dcid(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_tstamp t = 0;
  ngtcp2_tstamp expiry;
  int64_t pkt_num = 0;
  ngtcp2_frame fr;
  int rv;
  ngtcp2_cid cid;
  const uint8_t raw_cid[] = {0x0f, 0x00, 0x00, 0x00};
  const uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN] = {0xff};
  const uint8_t data[] = {0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8};

  ngtcp2_cid_init(&cid, raw_cid, sizeof(raw_cid));

  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = 1;
  fr.new_connection_id.retire_prior_to = 0;
  fr.new_connection_id.cid = cid;
  memcpy(fr.new_connection_id.stateless_reset_token, token, sizeof(token));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  fr.type = NGTCP2_FRAME_PATH_CHALLENGE;
  memcpy(fr.path_challenge.data, data, sizeof(fr.path_challenge.data));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, <, ngtcp2_ringbuf_len(&conn->rx.path_challenge.rb));
  assert_size(0, <, ngtcp2_ringbuf_len(&conn->dcid.bound.rb));

  expiry = ngtcp2_conn_get_expiry(conn);

  assert_uint64(UINT64_MAX, !=, expiry);

  t += 3 * ngtcp2_conn_get_pto(conn);

  rv = ngtcp2_conn_handle_expiry(conn, t);

  assert_int(0, ==, rv);
  assert_size(0, ==, ngtcp2_ringbuf_len(&conn->dcid.bound.rb));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_get_scid(void) {
  ngtcp2_conn *conn;
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  ngtcp2_cid dcid, scid;
  ngtcp2_callbacks cb;
  const uint8_t raw_cid[] = {0x0f, 0x00, 0x00, 0x00};
  ngtcp2_cid scids[16];

  dcid_init(&dcid);
  dcid_init(&scid);

  server_default_callbacks(&cb);
  server_default_settings(&settings);

  /* Without preferred address */
  server_default_transport_params(&params);

  ngtcp2_conn_server_new(&conn, &dcid, &scid, &null_path.path,
                         NGTCP2_PROTO_VER_V1, &cb, &settings, &params,
                         /* mem = */ NULL, NULL);

  assert_size(1, ==, ngtcp2_conn_get_scid(conn, NULL));

  ngtcp2_conn_get_scid(conn, scids);

  assert_true(ngtcp2_cid_eq(&scid, &scids[0]));

  ngtcp2_conn_del(conn);

  /* With preferred address */
  server_default_transport_params(&params);
  params.preferred_addr_present = 1;
  ngtcp2_cid_init(&params.preferred_addr.cid, raw_cid, sizeof(raw_cid));

  ngtcp2_conn_server_new(&conn, &dcid, &scid, &null_path.path,
                         NGTCP2_PROTO_VER_V1, &cb, &settings, &params,
                         /* mem = */ NULL, NULL);

  assert_size(2, ==, ngtcp2_conn_get_scid(conn, NULL));

  ngtcp2_conn_get_scid(conn, scids);

  assert_true(ngtcp2_cid_eq(&scid, &scids[0]));
  assert_true(ngtcp2_cid_eq(&params.preferred_addr.cid, &scids[1]));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_stream_close(void) {
  ngtcp2_conn *conn;
  int rv;
  uint8_t buf[2048];
  ngtcp2_frame frs[2];
  size_t pktlen;
  int64_t pkt_num = 0;
  my_user_data ud;
  ngtcp2_strm *strm;
  ngtcp2_tstamp t = 0;
  ngtcp2_ssize spktlen;
  int64_t stream_id;

  /* Receive RESET_STREAM and STOP_SENDING from client */
  setup_default_server(&conn);
  conn->callbacks.stream_close = stream_close;
  conn->user_data = &ud;

  open_stream(conn, 0);

  frs[0].type = NGTCP2_FRAME_RESET_STREAM;
  frs[0].reset_stream.stream_id = 0;
  frs[0].reset_stream.app_error_code = NGTCP2_APP_ERR01;
  frs[0].reset_stream.final_size = 999;

  frs[1].type = NGTCP2_FRAME_STOP_SENDING;
  frs[1].stop_sending.stream_id = 0;
  frs[1].stop_sending.app_error_code = NGTCP2_APP_ERR02;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, frs, 2,
                     conn->pktns.crypto.tx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, 0);

  assert_uint64(NGTCP2_APP_ERR01, ==, strm->app_error_code);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(sizeof(buf), >, (size_t)spktlen);

  frs[0].type = NGTCP2_FRAME_ACK;
  frs[0].ack.largest_ack = 0;
  frs[0].ack.ack_delay = 0;
  frs[0].ack.first_ack_range = 0;
  frs[0].ack.rangecnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, frs, 1,
                     conn->pktns.crypto.tx.ckm);

  ud.stream_close.flags = NGTCP2_STREAM_CLOSE_FLAG_NONE;
  ud.stream_close.stream_id = -1;
  ud.stream_close.app_error_code = 0;

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  assert_true(NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET &
              ud.stream_close.flags);
  assert_int64(0, ==, ud.stream_close.stream_id);
  assert_uint64(NGTCP2_APP_ERR01, ==, ud.stream_close.app_error_code);

  ngtcp2_conn_del(conn);

  /* Client sends STOP_SENDING and then STREAM and fin */
  pkt_num = 0;

  setup_default_server(&conn);
  conn->callbacks.stream_close = stream_close;
  conn->callbacks.recv_stream_data = recv_stream_data;
  conn->user_data = &ud;

  frs[0].type = NGTCP2_FRAME_STOP_SENDING;
  frs[0].stop_sending.stream_id = 0;
  frs[0].stop_sending.app_error_code = NGTCP2_APP_ERR01;

  frs[1].type = NGTCP2_FRAME_STREAM;
  frs[1].stream.flags = 0;
  frs[1].stream.fin = 1;
  frs[1].stream.stream_id = 0;
  frs[1].stream.offset = 0;
  frs[1].stream.datacnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, frs, 2,
                     conn->pktns.crypto.tx.ckm);

  ud.stream_data.stream_id = -1;
  ud.stream_data.flags = NGTCP2_STREAM_DATA_FLAG_NONE;
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(0, ==, ud.stream_data.stream_id);
  assert_true(ud.stream_data.flags & NGTCP2_STREAM_DATA_FLAG_FIN);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(sizeof(buf), >, (size_t)spktlen);

  frs[0].type = NGTCP2_FRAME_ACK;
  frs[0].ack.largest_ack = 0;
  frs[0].ack.ack_delay = 0;
  frs[0].ack.first_ack_range = 0;
  frs[0].ack.rangecnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, frs, 1,
                     conn->pktns.crypto.tx.ckm);

  ud.stream_close.flags = NGTCP2_STREAM_CLOSE_FLAG_NONE;
  ud.stream_close.stream_id = -1;
  ud.stream_close.app_error_code = 0;

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  assert_true(NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET &
              ud.stream_close.flags);
  assert_int64(0, ==, ud.stream_close.stream_id);
  assert_uint64(NGTCP2_APP_ERR01, ==, ud.stream_close.app_error_code);

  ngtcp2_conn_del(conn);

  /* Client calls ngtcp2_conn_shutdown_stream, and before sending
     STOP_SENDING, it receives STREAM with fin bit set. */
  pkt_num = 0;

  setup_default_client(&conn);
  conn->callbacks.stream_close = stream_close;
  conn->user_data = &ud;

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_FIN, stream_id,
                                     null_data, 1, ++t);

  assert_ptrdiff(0, <, spktlen);

  frs[0].type = NGTCP2_FRAME_ACK;
  frs[0].ack.largest_ack = conn->pktns.tx.last_pkt_num;
  frs[0].ack.ack_delay = 0;
  frs[0].ack.first_ack_range = 0;
  frs[0].ack.rangecnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, frs, 1,
                     conn->pktns.crypto.tx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_shutdown_stream(conn, 0, stream_id, NGTCP2_APP_ERR01);

  assert_int(0, ==, rv);

  frs[0].type = NGTCP2_FRAME_STREAM;
  frs[0].stream.flags = 0;
  frs[0].stream.fin = 1;
  frs[0].stream.stream_id = stream_id;
  frs[0].stream.offset = 0;
  frs[0].stream.datacnt = 1;
  frs[0].stream.data[0].len = 97;
  frs[0].stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, frs, 1,
                     conn->pktns.crypto.tx.ckm);

  ud.stream_close.flags = NGTCP2_STREAM_CLOSE_FLAG_NONE;
  ud.stream_close.stream_id = -1;
  ud.stream_close.app_error_code = 0;

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_true(NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET &
              ud.stream_close.flags);
  assert_int64(stream_id, ==, ud.stream_close.stream_id);
  assert_uint64(NGTCP2_APP_ERR01, ==, ud.stream_close.app_error_code);

  ngtcp2_conn_del(conn);

  /* Client sends STREAM fin and then RESET_STREAM.  It receives ACK
     for the STREAM frame, then response fin. No ACK for
     RESET_STREAM. */
  pkt_num = 0;

  setup_default_client(&conn);
  conn->callbacks.stream_close = stream_close;
  conn->user_data = &ud;

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_FIN, stream_id,
                                     null_data, 1, ++t);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_shutdown_stream_write(conn, 0, stream_id, NGTCP2_APP_ERR01);

  assert_int(0, ==, rv);

  frs[0].type = NGTCP2_FRAME_STREAM;
  frs[0].stream.flags = 0;
  frs[0].stream.fin = 1;
  frs[0].stream.stream_id = stream_id;
  frs[0].stream.offset = 0;
  frs[0].stream.datacnt = 0;

  frs[1].type = NGTCP2_FRAME_ACK;
  frs[1].ack.largest_ack = conn->pktns.tx.last_pkt_num;
  frs[1].ack.ack_delay = 0;
  frs[1].ack.first_ack_range = 0;
  frs[1].ack.rangecnt = 0;

  spktlen =
      ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                               NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, ++t);

  assert_ptrdiff(0, <, spktlen);

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, frs, 2,
                     conn->pktns.crypto.tx.ckm);

  ud.stream_close.flags = NGTCP2_STREAM_CLOSE_FLAG_NONE;
  ud.stream_close.stream_id = -1;
  ud.stream_close.app_error_code = 0;

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_true(NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET &
              ud.stream_close.flags);
  assert_int64(stream_id, ==, ud.stream_close.stream_id);
  assert_uint64(NGTCP2_APP_ERR01, ==, ud.stream_close.app_error_code);

  ngtcp2_conn_del(conn);

  /* Check that the closure of remote unidirectional invokes
     stream_close callback */
  pkt_num = 0;

  setup_default_client(&conn);

  conn->callbacks.stream_close = stream_close;
  conn->user_data = &ud;

  frs[0].type = NGTCP2_FRAME_STREAM;
  frs[0].stream.flags = 0;
  frs[0].stream.fin = 1;
  frs[0].stream.stream_id = 3;
  frs[0].stream.offset = 0;
  frs[0].stream.datacnt = 1;
  frs[0].stream.data[0].len = 88;
  frs[0].stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, frs, 1,
                     conn->pktns.crypto.tx.ckm);

  ud.stream_close.flags = NGTCP2_STREAM_CLOSE_FLAG_NONE;
  ud.stream_close.stream_id = -1;
  ud.stream_close.app_error_code = 0;

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_false(NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET &
               ud.stream_close.flags);
  assert_int64(frs[0].stream.stream_id, ==, ud.stream_close.stream_id);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_buffer_pkt(void) {
  ngtcp2_conn *conn;
  int rv;
  uint8_t buf[2048];
  ngtcp2_frame fr;
  ngtcp2_frame frs[2];
  size_t pktlen, in_pktlen;
  int64_t pkt_num = 0;
  ngtcp2_tstamp t = 0;
  ngtcp2_ssize spktlen;
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  ngtcp2_ksl_it it;
  ngtcp2_pkt_chain *pc;

  /* Server should buffer Short packet if it does not complete
     handshake even if it has application tx key. */
  setup_handshake_server(&conn);

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1193;
  fr.stream.data[0].base = null_data;

  pktlen = write_initial_pkt(buf, sizeof(buf), &conn->oscid,
                             ngtcp2_conn_get_dcid(conn), pkt_num++,
                             NGTCP2_PROTO_VER_V1, NULL, 0, &fr, 1, &null_ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_install_tx_key(conn, null_secret, sizeof(null_secret),
                                  &aead_ctx, null_iv, sizeof(null_iv), &hp_ctx);

  assert(0 == rv);

  rv = ngtcp2_conn_install_rx_key(conn, null_secret, sizeof(null_secret),
                                  &aead_ctx, null_iv, sizeof(null_iv), &hp_ctx);

  assert(0 == rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  fr.type = NGTCP2_FRAME_PING;

  in_pktlen = write_initial_pkt(
      buf, sizeof(buf), &conn->oscid, ngtcp2_conn_get_dcid(conn), pkt_num++,
      NGTCP2_PROTO_VER_V1, NULL, 0, &fr, 1, &null_ckm);

  frs[0].type = NGTCP2_FRAME_PING;
  frs[1].type = NGTCP2_FRAME_PADDING;
  frs[1].padding.len = 1200;

  pktlen = write_pkt(buf + in_pktlen, sizeof(buf) - in_pktlen, &conn->oscid,
                     pkt_num++, frs, 2, &null_ckm);

  assert_null(conn->pktns.rx.buffed_pkts);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf,
                            in_pktlen + pktlen, ++t);

  assert_int(0, ==, rv);

  pc = conn->pktns.rx.buffed_pkts;

  assert_size(pktlen, ==, pc->pktlen);
  assert_size(in_pktlen + pktlen, ==, pc->dgramlen);

  it = ngtcp2_acktr_get(&conn->pktns.acktr);

  assert_true(ngtcp2_ksl_it_end(&it));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_handshake_timeout(void) {
  ngtcp2_conn *conn;
  int rv;

  /* handshake has just timed out */
  setup_handshake_server(&conn);

  rv = ngtcp2_conn_handle_expiry(conn,
                                 conn->local.settings.initial_ts +
                                     conn->local.settings.handshake_timeout);

  assert_int(NGTCP2_ERR_HANDSHAKE_TIMEOUT, ==, rv);

  ngtcp2_conn_del(conn);

  /* handshake is still in progress */
  setup_handshake_server(&conn);

  rv = ngtcp2_conn_handle_expiry(
      conn, conn->local.settings.initial_ts +
                conn->local.settings.handshake_timeout - 1);

  assert_int(0, ==, rv);

  ngtcp2_conn_del(conn);

  /* handshake timeout should be ignored after handshake has
     completed. */
  setup_default_server(&conn);

  rv = ngtcp2_conn_handle_expiry(conn,
                                 conn->local.settings.initial_ts +
                                     conn->local.settings.handshake_timeout);

  assert_int(0, ==, rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_get_ccerr(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  ngtcp2_frame frs[2];
  size_t pktlen;
  uint8_t reason[2048];
  ngtcp2_tstamp t = 0;
  int64_t pkt_num = 0;
  int rv;
  const ngtcp2_ccerr *ccerr;

  memset(reason, 'a', sizeof(reason));

  setup_default_server(&conn);

  /* Record the last error. */
  frs[0].type = NGTCP2_FRAME_CONNECTION_CLOSE_APP;
  frs[0].connection_close.error_code = 1;
  frs[0].connection_close.frame_type = 99;
  frs[0].connection_close.reasonlen = 10;
  frs[0].connection_close.reason = reason;

  frs[1].type = NGTCP2_FRAME_CONNECTION_CLOSE;
  frs[1].connection_close.error_code = NGTCP2_PROTOCOL_VIOLATION;
  frs[1].connection_close.frame_type = 1000000007;
  frs[1].connection_close.reasonlen = NGTCP2_CCERR_MAX_REASONLEN + 1;
  frs[1].connection_close.reason = reason;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, frs,
                     ngtcp2_arraylen(frs), conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_DRAINING, ==, rv);

  ccerr = ngtcp2_conn_get_ccerr(conn);

  assert_uint64(NGTCP2_PROTOCOL_VIOLATION, ==, ccerr->error_code);
  assert_int((int)NGTCP2_CCERR_TYPE_TRANSPORT, ==, (int)ccerr->type);
  assert_uint64(1000000007, ==, ccerr->frame_type);
  assert_memory_equal(ccerr->reasonlen, reason, ccerr->reason);
  assert_size(NGTCP2_CCERR_MAX_REASONLEN, ==, ccerr->reasonlen);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_version_negotiation(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  ngtcp2_frame fr;
  ngtcp2_tstamp t = 0;
  ngtcp2_ssize spktlen;
  int64_t pkt_num = 0;
  size_t pktlen;
  int rv;
  ngtcp2_transport_params remote_params;
  uint8_t available_versions[sizeof(uint32_t) * 2];
  uint32_t version;

  ngtcp2_put_uint32be(&available_versions[0], NGTCP2_PROTO_VER_V1);
  ngtcp2_put_uint32be(&available_versions[4], NGTCP2_PROTO_VER_V2);

  /* Client sees the change version in Initial packet which contains
     CRYPTO frame.  It generates new Initial keys and sets negotiated
     version. */
  setup_handshake_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 133;
  fr.stream.data[0].base = null_data;

  pktlen = write_initial_pkt(buf, sizeof(buf), &conn->oscid,
                             ngtcp2_conn_get_dcid(conn), pkt_num++,
                             NGTCP2_PROTO_VER_V2, NULL, 0, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_uint32(NGTCP2_PROTO_VER_V2, ==, conn->negotiated_version);
  assert_uint32(NGTCP2_PROTO_VER_V2, ==, conn->vneg.version);
  assert_not_null(conn->vneg.rx.ckm);
  assert_not_null(conn->vneg.tx.ckm);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  ngtcp2_get_uint32(&version, &buf[1]);

  assert_uint32(NGTCP2_PROTO_VER_V2, ==, version);

  ngtcp2_conn_del(conn);

  /* Client receives Initial packet which does not change version and
     does not contain CRYPTO frame.  It leaves negotiated version
     unchanged. */
  setup_handshake_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  fr.type = NGTCP2_FRAME_PADDING;
  fr.padding.len = 1;

  pktlen = write_initial_pkt(buf, sizeof(buf), &conn->oscid,
                             ngtcp2_conn_get_dcid(conn), pkt_num++,
                             NGTCP2_PROTO_VER_V1, NULL, 0, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_uint32(0, ==, conn->negotiated_version);
  assert_uint32(0, ==, conn->vneg.version);
  assert_null(conn->vneg.rx.ckm);
  assert_null(conn->vneg.tx.ckm);

  ngtcp2_conn_del(conn);

  /* Server sees client supports QUIC v2.  It chooses QUIC v2 as the
     negotiated version, and generates new Initial keys. */
  setup_handshake_server(&conn);

  conn->callbacks.recv_client_initial =
      recv_client_initial_no_remote_transport_params;

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1233;
  fr.stream.data[0].base = null_data;

  pktlen = write_initial_pkt(buf, sizeof(buf), &conn->oscid,
                             ngtcp2_conn_get_dcid(conn), pkt_num++,
                             NGTCP2_PROTO_VER_V1, NULL, 0, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  ngtcp2_transport_params_default(&remote_params);
  ngtcp2_cid_init(&remote_params.initial_scid, conn->dcid.current.cid.data,
                  conn->dcid.current.cid.datalen);
  remote_params.initial_scid_present = 1;
  remote_params.version_info_present = 1;
  remote_params.version_info.chosen_version = NGTCP2_PROTO_VER_V1;
  remote_params.version_info.available_versions = available_versions;
  remote_params.version_info.available_versionslen = sizeof(available_versions);

  rv = ngtcp2_conn_set_remote_transport_params(conn, &remote_params);

  assert_int(0, ==, rv);
  assert_uint32(NGTCP2_PROTO_VER_V2, ==, conn->negotiated_version);
  assert_uint32(NGTCP2_PROTO_VER_V2, ==, conn->vneg.version);
  assert_not_null(conn->vneg.rx.ckm);
  assert_not_null(conn->vneg.tx.ckm);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  ngtcp2_get_uint32(&version, &buf[1]);

  assert_uint32(NGTCP2_PROTO_VER_V2, ==, version);

  ngtcp2_conn_del(conn);

  /* Server receives Version Information transport parameter which
     does not include chosen_version in available_versions. */
  setup_handshake_server(&conn);

  conn->callbacks.recv_client_initial =
      recv_client_initial_no_remote_transport_params;

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1211;
  fr.stream.data[0].base = null_data;

  pktlen = write_initial_pkt(buf, sizeof(buf), &conn->oscid,
                             ngtcp2_conn_get_dcid(conn), pkt_num++,
                             NGTCP2_PROTO_VER_V1, NULL, 0, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  ngtcp2_transport_params_default(&remote_params);
  ngtcp2_cid_init(&remote_params.initial_scid, conn->dcid.current.cid.data,
                  conn->dcid.current.cid.datalen);
  remote_params.initial_scid_present = 1;
  remote_params.version_info_present = 1;
  remote_params.version_info.chosen_version = NGTCP2_PROTO_VER_V1;
  remote_params.version_info.available_versions =
      available_versions + sizeof(uint32_t);
  remote_params.version_info.available_versionslen =
      sizeof(available_versions) - sizeof(uint32_t);

  rv = ngtcp2_conn_set_remote_transport_params(conn, &remote_params);

  assert_int(NGTCP2_ERR_TRANSPORT_PARAM, ==, rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_server_negotiate_version(void) {
  ngtcp2_conn *conn;
  ngtcp2_version_info version_info = {0};
  uint8_t client_available_versions[sizeof(uint32_t) * 2];

  setup_handshake_server(&conn);

  version_info.chosen_version = conn->client_chosen_version;

  /* Empty version_info.available_versions */
  version_info.available_versions = NULL;
  version_info.available_versionslen = 0;

  assert_uint32(conn->client_chosen_version, ==,
                ngtcp2_conn_server_negotiate_version(conn, &version_info));

  /* version_info.available_versions and preferred_versions do not
     share any version. */
  ngtcp2_put_uint32be(&client_available_versions[0], 0xff000001);
  ngtcp2_put_uint32be(&client_available_versions[4], 0xff000002);

  version_info.available_versions = client_available_versions;
  version_info.available_versionslen = sizeof(uint32_t) * 2;

  assert_uint32(conn->client_chosen_version, ==,
                ngtcp2_conn_server_negotiate_version(conn, &version_info));

  /* version_info.available_versions and preferred_versions share the
     version. */
  ngtcp2_put_uint32be(&client_available_versions[0], 0xff000001);
  ngtcp2_put_uint32be(&client_available_versions[4], NGTCP2_PROTO_VER_V2);

  version_info.available_versions = client_available_versions;
  version_info.available_versionslen = sizeof(uint32_t) * 2;

  assert_uint32(NGTCP2_PROTO_VER_V2, ==,
                ngtcp2_conn_server_negotiate_version(conn, &version_info));

  ngtcp2_conn_del(conn);

  /* Without preferred_versions */
  setup_handshake_server(&conn);

  conn->vneg.preferred_versions = NULL;
  conn->vneg.preferred_versionslen = 0;

  ngtcp2_put_uint32be(&client_available_versions[0], 0xff000001);
  ngtcp2_put_uint32be(&client_available_versions[4], NGTCP2_PROTO_VER_V2);

  version_info.available_versions = client_available_versions;
  version_info.available_versionslen = sizeof(uint32_t) * 2;

  assert_uint32(conn->client_chosen_version, ==,
                ngtcp2_conn_server_negotiate_version(conn, &version_info));

  ngtcp2_conn_del(conn);

  /* original version is the most preferred version */
  setup_handshake_server(&conn);

  conn->vneg.preferred_versions[0] = NGTCP2_PROTO_VER_V1;
  conn->vneg.preferred_versions[1] = NGTCP2_PROTO_VER_V2;

  ngtcp2_put_uint32be(&client_available_versions[0], NGTCP2_PROTO_VER_V2);
  ngtcp2_put_uint32be(&client_available_versions[4], NGTCP2_PROTO_VER_V1);

  version_info.available_versions = client_available_versions;
  version_info.available_versionslen = sizeof(uint32_t) * 2;

  assert_uint32(conn->client_chosen_version, ==,
                ngtcp2_conn_server_negotiate_version(conn, &version_info));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_pmtud_loss(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  ngtcp2_ssize spktlen;
  uint64_t t = 0;
  ngtcp2_frame fr;
  int64_t pkt_num = 0;
  size_t pktlen;
  int rv;

  setup_default_client(&conn);

  ngtcp2_conn_start_pmtud(conn);

  /* This sends PMTUD packet. */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1406, ==, spktlen);

  t += NGTCP2_SECONDS;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = conn->pktns.tx.last_pkt_num;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, pkt_num++, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(1, ==, conn->pktns.rtb.num_lost_pkts);
  assert_size(1, ==, conn->pktns.rtb.num_lost_pmtud_pkts);
  assert_uint64(0, ==, conn->pktns.rtb.cc_bytes_in_flight);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_amplification(void) {
  ngtcp2_conn *conn;
  ngtcp2_frame fr;
  size_t pktlen;
  uint8_t buf[2048];
  ngtcp2_cid rcid;
  int64_t pkt_num = 0;
  ngtcp2_tstamp t = 0;
  ngtcp2_ssize spktlen;
  int rv;

  rcid_init(&rcid);

  /* ACK only frame should not be sent due to amplification limit. */
  setup_early_server(&conn);

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1200;
  fr.stream.data[0].base = null_data;

  pktlen = write_initial_pkt(
      buf, sizeof(buf), &rcid, ngtcp2_conn_get_dcid(conn), ++pkt_num,
      conn->client_chosen_version, NULL, 0, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 111;
  fr.stream.data[0].base = null_data;

  pktlen =
      write_0rtt_pkt(buf, sizeof(buf), &rcid, ngtcp2_conn_get_dcid(conn),
                     ++pkt_num, conn->client_chosen_version, &fr, 1, &null_ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  /* Adjust condition so that the execution path goes into sending ACK
     only frame. */
  conn->dcid.current.bytes_sent = conn->dcid.current.bytes_recv * 3 - 1;
  conn->cstat.bytes_in_flight = conn->cstat.cwnd;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, ==, spktlen);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_encode_0rtt_transport_params(void) {
  ngtcp2_conn *conn;
  uint8_t buf[256];
  ngtcp2_ssize slen;
  ngtcp2_transport_params params, early_params;
  ngtcp2_callbacks cb;
  ngtcp2_settings settings;
  ngtcp2_cid rcid, scid;
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  ngtcp2_crypto_ctx crypto_ctx;
  int rv;

  /* client side */
  setup_default_client(&conn);

  slen = ngtcp2_conn_encode_0rtt_transport_params(conn, buf, sizeof(buf));

  assert_ptrdiff(0, <, slen);

  rv = ngtcp2_transport_params_decode(&early_params, buf, (size_t)slen);

  assert_int(0, ==, rv);
  assert_uint64(1, ==, early_params.initial_max_streams_bidi);
  assert_uint64(1, ==, early_params.initial_max_streams_uni);
  assert_uint64(64 * 1024, ==, early_params.initial_max_stream_data_bidi_local);
  assert_uint64(64 * 1024, ==,
                early_params.initial_max_stream_data_bidi_remote);
  assert_uint64(64 * 1024, ==, early_params.initial_max_stream_data_uni);
  assert_uint64(64 * 1024, ==, early_params.initial_max_data);
  assert_uint64(8, ==, early_params.active_connection_id_limit);

  ngtcp2_conn_del(conn);

  rcid_init(&rcid);
  scid_init(&scid);

  init_initial_crypto_ctx(&crypto_ctx);

  client_early_callbacks(&cb);
  client_default_settings(&settings);
  client_default_transport_params(&params);

  ngtcp2_conn_client_new(&conn, &rcid, &scid, &null_path.path,
                         NGTCP2_PROTO_VER_V1, &cb, &settings, &params,
                         /* mem = */ NULL, NULL);
  ngtcp2_conn_set_initial_crypto_ctx(conn, &crypto_ctx);
  ngtcp2_conn_install_initial_key(conn, &aead_ctx, null_iv, &hp_ctx, &aead_ctx,
                                  null_iv, &hp_ctx, sizeof(null_iv));

  rv =
      ngtcp2_conn_decode_and_set_0rtt_transport_params(conn, buf, (size_t)slen);

  assert_int(0, ==, rv);
  assert_uint64(early_params.initial_max_streams_bidi, ==,
                conn->remote.transport_params->initial_max_streams_bidi);
  assert_uint64(early_params.initial_max_streams_uni, ==,
                conn->remote.transport_params->initial_max_streams_uni);
  assert_uint64(
      early_params.initial_max_stream_data_bidi_local, ==,
      conn->remote.transport_params->initial_max_stream_data_bidi_local);
  assert_uint64(
      early_params.initial_max_stream_data_bidi_remote, ==,
      conn->remote.transport_params->initial_max_stream_data_bidi_remote);
  assert_uint64(early_params.initial_max_stream_data_uni, ==,
                conn->remote.transport_params->initial_max_stream_data_uni);
  assert_uint64(early_params.initial_max_data, ==,
                conn->remote.transport_params->initial_max_data);
  assert_uint64(early_params.active_connection_id_limit, ==,
                conn->remote.transport_params->active_connection_id_limit);

  ngtcp2_conn_del(conn);

  /* server side */
  server_default_settings(&settings);
  server_default_transport_params(&params);
  params.disable_active_migration = 1;
  setup_default_server_settings(&conn, &null_path.path, &settings, &params);

  slen = ngtcp2_conn_encode_0rtt_transport_params(conn, buf, sizeof(buf));

  assert_ptrdiff(0, <, slen);

  rv = ngtcp2_transport_params_decode(&early_params, buf, (size_t)slen);

  assert_int(0, ==, rv);
  assert_uint64(params.initial_max_streams_bidi, ==,
                early_params.initial_max_streams_bidi);
  assert_uint64(params.initial_max_streams_uni, ==,
                early_params.initial_max_streams_uni);
  assert_uint64(params.initial_max_stream_data_bidi_local, ==,
                early_params.initial_max_stream_data_bidi_local);
  assert_uint64(params.initial_max_stream_data_bidi_remote, ==,
                early_params.initial_max_stream_data_bidi_remote);
  assert_uint64(params.initial_max_stream_data_uni, ==,
                early_params.initial_max_stream_data_uni);
  assert_uint64(params.initial_max_data, ==, early_params.initial_max_data);
  assert_uint64(params.active_connection_id_limit, ==,
                early_params.active_connection_id_limit);
  assert_uint64(params.max_idle_timeout, ==, early_params.max_idle_timeout);
  assert_uint64(params.max_udp_payload_size, ==,
                early_params.max_udp_payload_size);
  assert_uint8(params.disable_active_migration, ==,
               early_params.disable_active_migration);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_create_ack_frame(void) {
  ngtcp2_conn *conn;
  ngtcp2_frame *ackfr;
  ngtcp2_frame fr;
  uint8_t buf[2048];
  size_t pktlen;
  int rv;
  ngtcp2_ksl_it it;
  size_t i;
  ngtcp2_ack_range ar;

  /* Nothing to acknowledge */
  setup_default_server(&conn);

  ackfr = NULL;
  rv = ngtcp2_conn_create_ack_frame(conn, &ackfr, &conn->pktns, NGTCP2_PKT_1RTT,
                                    0, 0, 0);

  assert_int(0, ==, rv);
  assert_null(ackfr);

  ngtcp2_conn_del(conn);

  /* ACK delay */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_PADDING;
  fr.padding.len = 100;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 0, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

  assert_int(0, ==, rv);

  /* PADDING does not elicit ACK */
  ackfr = NULL;
  rv = ngtcp2_conn_create_ack_frame(conn, &ackfr, &conn->pktns, NGTCP2_PKT_1RTT,
                                    0, 0, 0);

  assert_int(0, ==, rv);
  assert_null(ackfr);

  fr.type = NGTCP2_FRAME_PING;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

  assert_int(0, ==, rv);

  /* PING elicits ACK, but ACK is not generated due to ack delay. */
  ackfr = NULL;
  rv = ngtcp2_conn_create_ack_frame(conn, &ackfr, &conn->pktns, NGTCP2_PKT_1RTT,
                                    0, 25 * NGTCP2_MILLISECONDS, 0);

  assert_int(0, ==, rv);
  assert_null(ackfr);

  /* ACK delay passed. */
  ackfr = NULL;
  rv = ngtcp2_conn_create_ack_frame(
      conn, &ackfr, &conn->pktns, NGTCP2_PKT_1RTT, 25 * NGTCP2_MILLISECONDS,
      25 * NGTCP2_MILLISECONDS, NGTCP2_DEFAULT_ACK_DELAY_EXPONENT);

  assert_int(0, ==, rv);
  assert_int64(1, ==, ackfr->ack.largest_ack);
  assert_uint64(1, ==, ackfr->ack.first_ack_range);
  assert_uint64(25 * NGTCP2_MILLISECONDS, ==, ackfr->ack.ack_delay_unscaled);
  assert_uint64(3125, ==, ackfr->ack.ack_delay);
  assert_size(0, ==, ackfr->ack.rangecnt);

  ngtcp2_conn_del(conn);

  /* reorder (adjacent packets) */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_PING;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

  assert_int(0, ==, rv);

  ackfr = NULL;
  rv = ngtcp2_conn_create_ack_frame(
      conn, &ackfr, &conn->pktns, NGTCP2_PKT_1RTT, 25 * NGTCP2_MILLISECONDS,
      25 * NGTCP2_MILLISECONDS, NGTCP2_DEFAULT_ACK_DELAY_EXPONENT);

  assert_int(0, ==, rv);
  assert_int64(1, ==, ackfr->ack.largest_ack);
  assert_uint64(0, ==, ackfr->ack.first_ack_range);
  assert_uint64(25 * NGTCP2_MILLISECONDS, ==, ackfr->ack.ack_delay_unscaled);
  assert_uint64(3125, ==, ackfr->ack.ack_delay);
  assert_size(0, ==, ackfr->ack.rangecnt);

  ngtcp2_acktr_commit_ack(&conn->pktns.acktr);

  it = ngtcp2_acktr_get(&conn->pktns.acktr);

  assert_false(ngtcp2_ksl_it_end(&it));

  ngtcp2_acktr_forget(&conn->pktns.acktr, ngtcp2_ksl_it_get(&it));

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 0, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

  assert_int(0, ==, rv);

  ackfr = NULL;
  rv = ngtcp2_conn_create_ack_frame(
      conn, &ackfr, &conn->pktns, NGTCP2_PKT_1RTT, 25 * NGTCP2_MILLISECONDS,
      25 * NGTCP2_MILLISECONDS, NGTCP2_DEFAULT_ACK_DELAY_EXPONENT);

  assert_int(0, ==, rv);
  assert_int64(1, ==, ackfr->ack.largest_ack);
  assert_uint64(1, ==, ackfr->ack.first_ack_range);
  assert_uint64(25 * NGTCP2_MILLISECONDS, ==, ackfr->ack.ack_delay_unscaled);
  assert_uint64(3125, ==, ackfr->ack.ack_delay);
  assert_size(0, ==, ackfr->ack.rangecnt);

  ngtcp2_conn_del(conn);

  /* reorder (adjacent packets) with multiple ack ranges. */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_PING;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 10, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

  assert_int(0, ==, rv);

  ackfr = NULL;
  rv = ngtcp2_conn_create_ack_frame(
      conn, &ackfr, &conn->pktns, NGTCP2_PKT_1RTT, 25 * NGTCP2_MILLISECONDS,
      25 * NGTCP2_MILLISECONDS, NGTCP2_DEFAULT_ACK_DELAY_EXPONENT);

  assert_int(0, ==, rv);
  assert_int64(10, ==, ackfr->ack.largest_ack);
  assert_uint64(0, ==, ackfr->ack.first_ack_range);
  assert_uint64(25 * NGTCP2_MILLISECONDS, ==, ackfr->ack.ack_delay_unscaled);
  assert_uint64(3125, ==, ackfr->ack.ack_delay);
  assert_size(0, ==, ackfr->ack.rangecnt);

  ngtcp2_acktr_commit_ack(&conn->pktns.acktr);

  it = ngtcp2_acktr_get(&conn->pktns.acktr);

  assert_false(ngtcp2_ksl_it_end(&it));

  ngtcp2_acktr_forget(&conn->pktns.acktr, ngtcp2_ksl_it_get(&it));

  /* [0..1] */
  for (i = 0; i < 2; ++i) {
    pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, (int64_t)i, &fr, 1,
                       conn->pktns.crypto.rx.ckm);

    rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

    assert_int(0, ==, rv);
  }

  /* [3..6] */
  for (i = 3; i < 7; ++i) {
    pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, (int64_t)i, &fr, 1,
                       conn->pktns.crypto.rx.ckm);

    rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

    assert_int(0, ==, rv);
  }

  /* [9..9] */
  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 9, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

  assert_int(0, ==, rv);

  ackfr = NULL;
  rv = ngtcp2_conn_create_ack_frame(
      conn, &ackfr, &conn->pktns, NGTCP2_PKT_1RTT, 25 * NGTCP2_MILLISECONDS,
      25 * NGTCP2_MILLISECONDS, NGTCP2_DEFAULT_ACK_DELAY_EXPONENT);

  assert_int(0, ==, rv);
  assert_int64(10, ==, ackfr->ack.largest_ack);
  assert_uint64(1, ==, ackfr->ack.first_ack_range);
  assert_uint64(25 * NGTCP2_MILLISECONDS, ==, ackfr->ack.ack_delay_unscaled);
  assert_uint64(3125, ==, ackfr->ack.ack_delay);
  assert_size(2, ==, ackfr->ack.rangecnt);

  ar = ackfr->ack.ranges[0];

  assert_uint64(1, ==, ar.gap);
  assert_uint64(3, ==, ar.len);

  ar = ackfr->ack.ranges[1];

  assert_uint64(0, ==, ar.gap);
  assert_uint64(1, ==, ar.len);

  ngtcp2_conn_del(conn);

  /* reorder (no adjacent packets) with multiple ack ranges. */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_PING;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 10, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

  assert_int(0, ==, rv);

  ackfr = NULL;
  rv = ngtcp2_conn_create_ack_frame(
      conn, &ackfr, &conn->pktns, NGTCP2_PKT_1RTT, 25 * NGTCP2_MILLISECONDS,
      25 * NGTCP2_MILLISECONDS, NGTCP2_DEFAULT_ACK_DELAY_EXPONENT);

  assert_int(0, ==, rv);
  assert_int64(10, ==, ackfr->ack.largest_ack);
  assert_uint64(0, ==, ackfr->ack.first_ack_range);
  assert_uint64(25 * NGTCP2_MILLISECONDS, ==, ackfr->ack.ack_delay_unscaled);
  assert_uint64(3125, ==, ackfr->ack.ack_delay);
  assert_size(0, ==, ackfr->ack.rangecnt);

  ngtcp2_acktr_commit_ack(&conn->pktns.acktr);

  it = ngtcp2_acktr_get(&conn->pktns.acktr);

  assert_false(ngtcp2_ksl_it_end(&it));

  ngtcp2_acktr_forget(&conn->pktns.acktr, ngtcp2_ksl_it_get(&it));

  /* [3..7] */
  for (i = 3; i < 8; ++i) {
    pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, (int64_t)i, &fr, 1,
                       conn->pktns.crypto.rx.ckm);

    rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

    assert_int(0, ==, rv);
  }

  ackfr = NULL;
  rv = ngtcp2_conn_create_ack_frame(
      conn, &ackfr, &conn->pktns, NGTCP2_PKT_1RTT, 25 * NGTCP2_MILLISECONDS,
      25 * NGTCP2_MILLISECONDS, NGTCP2_DEFAULT_ACK_DELAY_EXPONENT);

  assert_int(0, ==, rv);
  assert_int64(10, ==, ackfr->ack.largest_ack);
  assert_uint64(0, ==, ackfr->ack.first_ack_range);
  assert_uint64(25 * NGTCP2_MILLISECONDS, ==, ackfr->ack.ack_delay_unscaled);
  assert_uint64(3125, ==, ackfr->ack.ack_delay);
  assert_size(1, ==, ackfr->ack.rangecnt);

  ar = ackfr->ack.ranges[0];

  assert_uint64(1, ==, ar.gap);
  assert_uint64(4, ==, ar.len);

  ngtcp2_conn_del(conn);

  /* More than NGTCP2_MAX_ACK_RANGES */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_PING;

  for (i = 0; i < NGTCP2_MAX_ACK_RANGES + 2; ++i) {
    pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, (int64_t)(i * 2), &fr, 1,
                       conn->pktns.crypto.rx.ckm);

    rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

    assert_int(0, ==, rv);
  }

  ackfr = NULL;
  rv = ngtcp2_conn_create_ack_frame(
      conn, &ackfr, &conn->pktns, NGTCP2_PKT_1RTT, 25 * NGTCP2_MILLISECONDS,
      25 * NGTCP2_MILLISECONDS, NGTCP2_DEFAULT_ACK_DELAY_EXPONENT);

  assert_int(0, ==, rv);
  assert_int64(66, ==, ackfr->ack.largest_ack);
  assert_uint64(0, ==, ackfr->ack.first_ack_range);
  assert_uint64(25 * NGTCP2_MILLISECONDS, ==, ackfr->ack.ack_delay_unscaled);
  assert_uint64(3125, ==, ackfr->ack.ack_delay);
  assert_size(NGTCP2_MAX_ACK_RANGES, ==, ackfr->ack.rangecnt);

  ngtcp2_conn_del(conn);

  /* Immediate acknowledgement (reorder) */
  setup_default_server(&conn);

  conn->local.settings.ack_thresh = 10;

  fr.type = NGTCP2_FRAME_PING;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

  assert_int(0, ==, rv);

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 0, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

  assert_int(0, ==, rv);

  ackfr = NULL;
  rv = ngtcp2_conn_create_ack_frame(conn, &ackfr, &conn->pktns, NGTCP2_PKT_1RTT,
                                    0, 25 * NGTCP2_MILLISECONDS,
                                    NGTCP2_DEFAULT_ACK_DELAY_EXPONENT);

  assert_int(0, ==, rv);
  assert_int64(1, ==, ackfr->ack.largest_ack);
  assert_uint64(1, ==, ackfr->ack.first_ack_range);
  assert_uint64(0, ==, ackfr->ack.ack_delay_unscaled);
  assert_uint64(0, ==, ackfr->ack.ack_delay);
  assert_size(0, ==, ackfr->ack.rangecnt);

  ngtcp2_conn_del(conn);

  /* Immediate acknowledgement (gap) */
  setup_default_server(&conn);

  conn->local.settings.ack_thresh = 10;

  fr.type = NGTCP2_FRAME_PING;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 0, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

  assert_int(0, ==, rv);

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 2, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

  assert_int(0, ==, rv);

  ackfr = NULL;
  rv = ngtcp2_conn_create_ack_frame(conn, &ackfr, &conn->pktns, NGTCP2_PKT_1RTT,
                                    0, 25 * NGTCP2_MILLISECONDS,
                                    NGTCP2_DEFAULT_ACK_DELAY_EXPONENT);

  assert_int(0, ==, rv);
  assert_int64(2, ==, ackfr->ack.largest_ack);
  assert_uint64(0, ==, ackfr->ack.first_ack_range);
  assert_uint64(0, ==, ackfr->ack.ack_delay_unscaled);
  assert_uint64(0, ==, ackfr->ack.ack_delay);
  assert_size(1, ==, ackfr->ack.rangecnt);

  ar = ackfr->ack.ranges[0];

  assert_uint64(0, ==, ar.gap);
  assert_uint64(0, ==, ar.len);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_grease_quic_bit(void) {
  ngtcp2_conn *conn;
  int rv;
  uint8_t buf[2048];
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_tstamp t = 0;
  int64_t pkt_num = 0;
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  ngtcp2_cid rcid;

  rcid_init(&rcid);

  /* Client disables grease_quic_bit, and receives a 1-RTT packet that
     has fixed bit not set. */
  setup_default_client(&conn);

  fr.type = NGTCP2_FRAME_PING;

  pktlen = write_pkt_flags(buf, sizeof(buf), NGTCP2_PKT_FLAG_FIXED_BIT_CLEAR,
                           &conn->oscid, ++pkt_num, &fr, 1,
                           conn->pktns.crypto.tx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_true(ngtcp2_acktr_empty(&conn->pktns.acktr));

  ngtcp2_conn_del(conn);

  /* Client enables grease_quic_bit, and receives a 1-RTT packet that
     has fixed bit not set. */
  client_default_settings(&settings);
  client_default_transport_params(&params);
  params.grease_quic_bit = 1;
  setup_default_client_settings(&conn, &null_path.path, &settings, &params);

  fr.type = NGTCP2_FRAME_PING;

  pktlen = write_pkt_flags(buf, sizeof(buf), NGTCP2_PKT_FLAG_FIXED_BIT_CLEAR,
                           &conn->oscid, ++pkt_num, &fr, 1,
                           conn->pktns.crypto.tx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_false(ngtcp2_acktr_empty(&conn->pktns.acktr));

  ngtcp2_conn_del(conn);

  /* Server disables grease_quic_bit, and receives a 1-RTT packet that
     has fixed bit not set. */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_PING;

  pktlen = write_pkt_flags(buf, sizeof(buf), NGTCP2_PKT_FLAG_FIXED_BIT_CLEAR,
                           &conn->oscid, ++pkt_num, &fr, 1,
                           conn->pktns.crypto.tx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_true(ngtcp2_acktr_empty(&conn->pktns.acktr));

  ngtcp2_conn_del(conn);

  /* Server enables grease_quic_bit, and receives a 1-RTT packet that
     has fixed bit not set. */
  server_default_settings(&settings);
  server_default_transport_params(&params);
  params.grease_quic_bit = 1;
  setup_default_server_settings(&conn, &null_path.path, &settings, &params);

  fr.type = NGTCP2_FRAME_PING;

  pktlen = write_pkt_flags(buf, sizeof(buf), NGTCP2_PKT_FLAG_FIXED_BIT_CLEAR,
                           &conn->oscid, ++pkt_num, &fr, 1,
                           conn->pktns.crypto.tx.ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_false(ngtcp2_acktr_empty(&conn->pktns.acktr));

  ngtcp2_conn_del(conn);

  /* Server enables grease_quic_bit, and receives an Initial packet
     that has no token. */
  server_default_settings(&settings);
  server_default_transport_params(&params);
  params.grease_quic_bit = 1;
  setup_handshake_server_settings(&conn, &null_path.path, &settings, &params);

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1200;
  fr.stream.data[0].base = null_data;

  pktlen =
      write_initial_pkt_flags(buf, sizeof(buf), NGTCP2_PKT_FLAG_FIXED_BIT_CLEAR,
                              &rcid, ngtcp2_conn_get_dcid(conn), ++pkt_num,
                              NGTCP2_PROTO_VER_V1, NULL, 0, &fr, 1, &null_ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_DROP_CONN, ==, rv);

  ngtcp2_conn_del(conn);

  /* Server enables grease_quic_bit, and receives an Initial packet
     with a token. */
  server_default_settings(&settings);
  settings.token = null_data;
  settings.tokenlen = 117;
  settings.token_type = NGTCP2_TOKEN_TYPE_NEW_TOKEN;
  server_default_transport_params(&params);
  params.grease_quic_bit = 1;
  setup_handshake_server_settings(&conn, &null_path.path, &settings, &params);

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1200;
  fr.stream.data[0].base = null_data;

  pktlen = write_initial_pkt_flags(
      buf, sizeof(buf), NGTCP2_PKT_FLAG_FIXED_BIT_CLEAR, &rcid,
      ngtcp2_conn_get_dcid(conn), ++pkt_num, NGTCP2_PROTO_VER_V1, null_data,
      117, &fr, 1, &null_ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  ngtcp2_conn_del(conn);

  /* Server disables grease_quic_bit, and receives an Initial packet
     with a token. */
  server_default_settings(&settings);
  settings.token = null_data;
  settings.tokenlen = 117;
  settings.token_type = NGTCP2_TOKEN_TYPE_NEW_TOKEN;
  server_default_transport_params(&params);
  setup_handshake_server_settings(&conn, &null_path.path, &settings, &params);

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1200;
  fr.stream.data[0].base = null_data;

  pktlen = write_initial_pkt_flags(
      buf, sizeof(buf), NGTCP2_PKT_FLAG_FIXED_BIT_CLEAR, &rcid,
      ngtcp2_conn_get_dcid(conn), ++pkt_num, NGTCP2_PROTO_VER_V1, null_data,
      117, &fr, 1, &null_ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_DROP_CONN, ==, rv);

  ngtcp2_conn_del(conn);

  /* Server enables grease_quic_bit, and receives an Initial packet
     with a token from Retry packet. */
  server_default_settings(&settings);
  settings.token = null_data;
  settings.tokenlen = 117;
  settings.token_type = NGTCP2_TOKEN_TYPE_RETRY;
  server_default_transport_params(&params);
  params.grease_quic_bit = 1;
  setup_handshake_server_settings(&conn, &null_path.path, &settings, &params);

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1200;
  fr.stream.data[0].base = null_data;

  pktlen = write_initial_pkt_flags(
      buf, sizeof(buf), NGTCP2_PKT_FLAG_FIXED_BIT_CLEAR, &rcid,
      ngtcp2_conn_get_dcid(conn), ++pkt_num, NGTCP2_PROTO_VER_V1, null_data,
      117, &fr, 1, &null_ckm);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_DROP_CONN, ==, rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_send_stream_data_blocked(void) {
  ngtcp2_conn *conn;
  int rv;
  int64_t stream_id, stream_id2;
  ngtcp2_strm *strm;
  uint8_t buf[2048];
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 0;
  ngtcp2_ksl_it it;
  ngtcp2_rtb_entry *ent;
  ngtcp2_frame_chain *frc;

  /* Stream is blocked before writing any data. */
  setup_default_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);
  strm->tx.offset = strm->tx.max_offset;

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                     null_data, 897, ++t);

  assert_ptrdiff(NGTCP2_ERR_STREAM_DATA_BLOCKED, ==, spktlen);
  assert_true(conn->flags & NGTCP2_CONN_FLAG_PPE_PENDING);

  spktlen =
      ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                               NGTCP2_WRITE_STREAM_FLAG_MORE, -1, NULL, 0, t);

  assert_ptrdiff(0, <, spktlen);
  assert_false(conn->flags & NGTCP2_CONN_FLAG_PPE_PENDING);
  assert_true(ngtcp2_pq_empty(&conn->tx.strmq));

  it = ngtcp2_rtb_head(&conn->pktns.rtb);

  assert_false(ngtcp2_ksl_it_end(&it));

  ent = ngtcp2_ksl_it_get(&it);
  frc = ent->frc;

  assert_uint64(NGTCP2_FRAME_STREAM_DATA_BLOCKED, ==, frc->fr.type);
  assert_int64(stream_id, ==, frc->fr.stream_data_blocked.stream_id);
  assert_uint64(strm->tx.max_offset, ==, frc->fr.stream_data_blocked.offset);
  assert_uint64(strm->tx.max_offset, ==, strm->tx.last_blocked_offset);
  assert_null(frc->next);

  ngtcp2_conn_del(conn);

  /* Stream is blocked after writing some data and seeing
     NGTCP2_ERR_STREAM_DATA_BLOCKED. */
  setup_default_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);
  strm->tx.offset = strm->tx.max_offset - 417;

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                     null_data, 418, ++t);

  assert_ptrdiff(NGTCP2_ERR_WRITE_MORE, ==, spktlen);
  assert_true(conn->flags & NGTCP2_CONN_FLAG_PPE_PENDING);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                     null_data, 1, t);

  assert_ptrdiff(NGTCP2_ERR_STREAM_DATA_BLOCKED, ==, spktlen);
  assert_true(conn->flags & NGTCP2_CONN_FLAG_PPE_PENDING);

  spktlen =
      ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                               NGTCP2_WRITE_STREAM_FLAG_MORE, -1, NULL, 0, t);

  assert_ptrdiff(0, <, spktlen);
  assert_false(conn->flags & NGTCP2_CONN_FLAG_PPE_PENDING);
  assert_true(ngtcp2_pq_empty(&conn->tx.strmq));

  it = ngtcp2_rtb_head(&conn->pktns.rtb);

  assert_false(ngtcp2_ksl_it_end(&it));

  ent = ngtcp2_ksl_it_get(&it);
  frc = ent->frc;

  assert_uint64(NGTCP2_FRAME_STREAM, ==, frc->fr.type);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_STREAM_DATA_BLOCKED, ==, frc->fr.type);
  assert_int64(stream_id, ==, frc->fr.stream_data_blocked.stream_id);
  assert_uint64(strm->tx.max_offset, ==, frc->fr.stream_data_blocked.offset);
  assert_uint64(strm->tx.max_offset, ==, strm->tx.last_blocked_offset);
  assert_null(frc->next);

  ngtcp2_conn_del(conn);

  /* Stream is blocked after writing some data. */
  setup_default_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);
  strm->tx.offset = strm->tx.max_offset - 417;

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                     null_data, 418, ++t);

  assert_ptrdiff(NGTCP2_ERR_WRITE_MORE, ==, spktlen);
  assert_true(conn->flags & NGTCP2_CONN_FLAG_PPE_PENDING);

  spktlen =
      ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                               NGTCP2_WRITE_STREAM_FLAG_MORE, -1, NULL, 0, t);

  assert_ptrdiff(0, <, spktlen);
  assert_false(conn->flags & NGTCP2_CONN_FLAG_PPE_PENDING);
  assert_true(ngtcp2_pq_empty(&conn->tx.strmq));

  it = ngtcp2_rtb_head(&conn->pktns.rtb);

  assert_false(ngtcp2_ksl_it_end(&it));

  ent = ngtcp2_ksl_it_get(&it);
  frc = ent->frc;

  assert_uint64(NGTCP2_FRAME_STREAM, ==, frc->fr.type);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_STREAM_DATA_BLOCKED, ==, frc->fr.type);
  assert_int64(stream_id, ==, frc->fr.stream_data_blocked.stream_id);
  assert_uint64(strm->tx.max_offset, ==, frc->fr.stream_data_blocked.offset);
  assert_uint64(strm->tx.max_offset, ==, strm->tx.last_blocked_offset);
  assert_null(frc->next);

  ngtcp2_conn_del(conn);

  /* Stream is blocked after writing another stream data. */
  setup_default_client(&conn);

  conn->local.bidi.max_streams = 2;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id2, NULL);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);
  strm->tx.offset = strm->tx.max_offset;

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id2,
                                     null_data, 317, ++t);

  assert_ptrdiff(NGTCP2_ERR_WRITE_MORE, ==, spktlen);
  assert_true(conn->flags & NGTCP2_CONN_FLAG_PPE_PENDING);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                     null_data, 1, t);

  assert_ptrdiff(NGTCP2_ERR_STREAM_DATA_BLOCKED, ==, spktlen);
  assert_true(conn->flags & NGTCP2_CONN_FLAG_PPE_PENDING);

  spktlen =
      ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                               NGTCP2_WRITE_STREAM_FLAG_MORE, -1, NULL, 0, t);

  assert_ptrdiff(0, <, spktlen);
  assert_false(conn->flags & NGTCP2_CONN_FLAG_PPE_PENDING);
  assert_true(ngtcp2_pq_empty(&conn->tx.strmq));

  it = ngtcp2_rtb_head(&conn->pktns.rtb);

  assert_false(ngtcp2_ksl_it_end(&it));

  ent = ngtcp2_ksl_it_get(&it);
  frc = ent->frc;

  assert_uint64(NGTCP2_FRAME_STREAM, ==, frc->fr.type);
  assert_int64(stream_id2, ==, frc->fr.stream.stream_id);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_STREAM_DATA_BLOCKED, ==, frc->fr.type);
  assert_int64(stream_id, ==, frc->fr.stream_data_blocked.stream_id);
  assert_uint64(strm->tx.max_offset, ==, frc->fr.stream_data_blocked.offset);
  assert_uint64(strm->tx.max_offset, ==, strm->tx.last_blocked_offset);
  assert_null(frc->next);

  ngtcp2_conn_del(conn);

  /* Initial attempt to write STREAM_DATA_BLOCKED fails because no
     space left in packet */
  setup_default_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);
  strm->tx.offset = strm->tx.max_offset - 1156;

  assert_true(ngtcp2_pq_empty(&conn->tx.strmq));

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, 1200, NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                     null_data, 1200, ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_false(conn->flags & NGTCP2_CONN_FLAG_PPE_PENDING);
  assert_size(1, ==, ngtcp2_pq_size(&conn->tx.strmq));

  strm = ngtcp2_struct_of(ngtcp2_pq_top(&conn->tx.strmq), ngtcp2_strm, pe);

  assert_int64(stream_id, ==, strm->stream_id);
  assert_uint64(UINT64_MAX, ==, strm->tx.last_blocked_offset);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                     null_data, 1, t);

  assert_ptrdiff(NGTCP2_ERR_STREAM_DATA_BLOCKED, ==, spktlen);
  assert_true(conn->flags & NGTCP2_CONN_FLAG_PPE_PENDING);
  assert_true(ngtcp2_pq_empty(&conn->tx.strmq));
  assert_uint64(strm->tx.max_offset, ==, strm->tx.last_blocked_offset);

  spktlen =
      ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                               NGTCP2_WRITE_STREAM_FLAG_MORE, -1, NULL, 0, t);

  assert_ptrdiff(0, <, spktlen);
  assert_false(conn->flags & NGTCP2_CONN_FLAG_PPE_PENDING);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);

  assert_false(ngtcp2_ksl_it_end(&it));

  ent = ngtcp2_ksl_it_get(&it);
  frc = ent->frc;

  assert_uint64(NGTCP2_FRAME_STREAM_DATA_BLOCKED, ==, frc->fr.type);
  assert_int64(stream_id, ==, frc->fr.stream_data_blocked.stream_id);
  assert_uint64(strm->tx.max_offset, ==, frc->fr.stream_data_blocked.offset);
  assert_uint64(strm->tx.max_offset, ==, strm->tx.last_blocked_offset);
  assert_null(frc->next);

  ngtcp2_conn_del(conn);

  /* Stream is blocked after writing some data.  Next
     ngtcp2_conn_writev_stream will create empty packet. */
  setup_default_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);
  strm->tx.offset = strm->tx.max_offset - 417;

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                     null_data, 418, ++t);

  assert_ptrdiff(NGTCP2_ERR_WRITE_MORE, ==, spktlen);
  assert_true(conn->flags & NGTCP2_CONN_FLAG_PPE_PENDING);

  spktlen =
      ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                               NGTCP2_WRITE_STREAM_FLAG_MORE, -1, NULL, 0, t);

  assert_ptrdiff(0, <, spktlen);
  assert_false(conn->flags & NGTCP2_CONN_FLAG_PPE_PENDING);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                     null_data, 1, t);

  assert_ptrdiff(NGTCP2_ERR_STREAM_DATA_BLOCKED, ==, spktlen);

  spktlen =
      ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                               NGTCP2_WRITE_STREAM_FLAG_MORE, -1, NULL, 0, t);

  assert_ptrdiff(0, ==, spktlen);
  assert_false(conn->flags & NGTCP2_CONN_FLAG_PPE_PENDING);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_send_data_blocked(void) {
  ngtcp2_conn *conn;
  int rv;
  int64_t stream_id;
  uint8_t buf[2048];
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 0;
  ngtcp2_ksl_it it;
  ngtcp2_rtb_entry *ent;
  ngtcp2_frame_chain *frc;

  /* Stream is blocked before writing any data. */
  setup_default_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  conn->tx.offset = conn->tx.max_offset;

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                     null_data, 111, ++t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);

  assert_false(ngtcp2_ksl_it_end(&it));

  ent = ngtcp2_ksl_it_get(&it);
  frc = ent->frc;

  assert_uint64(NGTCP2_FRAME_DATA_BLOCKED, ==, frc->fr.type);
  assert_uint64(conn->tx.max_offset, ==, frc->fr.data_blocked.offset);
  assert_uint64(conn->tx.max_offset, ==, conn->tx.last_blocked_offset);
  assert_null(frc->next);

  ngtcp2_conn_del(conn);

  /* Stream is blocked after writing some data. */
  setup_default_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  conn->tx.offset = conn->tx.max_offset - 839;

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                     null_data, 840, ++t);

  assert_ptrdiff(NGTCP2_ERR_WRITE_MORE, ==, spktlen);

  spktlen =
      ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                               NGTCP2_WRITE_STREAM_FLAG_MORE, -1, NULL, 0, t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);

  assert_false(ngtcp2_ksl_it_end(&it));

  ent = ngtcp2_ksl_it_get(&it);
  frc = ent->frc;

  assert_uint64(NGTCP2_FRAME_STREAM, ==, frc->fr.type);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_DATA_BLOCKED, ==, frc->fr.type);
  assert_uint64(conn->tx.max_offset, ==, frc->fr.data_blocked.offset);
  assert_uint64(conn->tx.max_offset, ==, conn->tx.last_blocked_offset);
  assert_null(frc->next);

  ngtcp2_conn_del(conn);

  /* Initial attempt to write DATA_BLOCKED fails because no space left
     in packet */
  setup_default_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  conn->tx.offset = conn->tx.max_offset - 1160;

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, 1200, NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                     null_data, 1200, ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_uint64(UINT64_MAX, ==, conn->tx.last_blocked_offset);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                     null_data, 1, t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);

  assert_false(ngtcp2_ksl_it_end(&it));

  ent = ngtcp2_ksl_it_get(&it);
  frc = ent->frc;

  assert_uint64(NGTCP2_FRAME_DATA_BLOCKED, ==, frc->fr.type);
  assert_uint64(conn->tx.max_offset, ==, frc->fr.data_blocked.offset);
  assert_uint64(conn->tx.max_offset, ==, conn->tx.last_blocked_offset);
  assert_null(frc->next);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_send_new_connection_id(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 0;
  ngtcp2_frame fr;
  size_t pktlen;
  int64_t pkt_num = 0;
  int rv;
  uint64_t seq;

  setup_default_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(7, ==, conn->scid.num_in_flight);

  /* Retire 1 Connection ID */
  fr.type = NGTCP2_FRAME_RETIRE_CONNECTION_ID;
  fr.retire_connection_id.seq = conn->scid.last_seq;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(1, ==, conn->scid.num_retired);

  t += ngtcp2_conn_get_pto(conn);

  rv = ngtcp2_conn_handle_expiry(conn, ++t);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(8, ==, conn->scid.num_in_flight);
  assert_size(0, ==, conn->scid.num_retired);

  seq = conn->scid.last_seq;

  /* Retire another Connection ID */
  fr.type = NGTCP2_FRAME_RETIRE_CONNECTION_ID;
  fr.retire_connection_id.seq = conn->scid.last_seq - 2;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(1, ==, conn->scid.num_retired);

  t += ngtcp2_conn_get_pto(conn);

  rv = ngtcp2_conn_handle_expiry(conn, ++t);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  /* We do not send NEW_CONNECTION_ID frame because the number of
     in-flight NEW_CONNECTION_ID frame reached maximum limit. */
  assert_size(8, ==, conn->scid.num_in_flight);
  assert_uint64(seq, ==, conn->scid.last_seq);
  assert_size(0, ==, conn->scid.num_retired);

  /* Acknowledge first packet */
  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = 0;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, ++pkt_num, &fr, 1,
                     conn->pktns.crypto.rx.ckm);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(1, ==, conn->scid.num_in_flight);

  /* Now NEW_CONNECTION_ID can be sent. */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(2, ==, conn->scid.num_in_flight);
  assert_uint64(seq + 1, ==, conn->scid.last_seq);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_persistent_congestion(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 0;
  ngtcp2_frame fr;
  size_t pktlen;
  int rv;
  ngtcp2_ksl_it it;
  int64_t stream_id;
  ngtcp2_strm *strm;

  setup_default_client(&conn);

  spktlen =
      ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                               NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, t);

  assert_ptrdiff(0, <, spktlen);

  spktlen =
      ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                               NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, t);

  assert_ptrdiff(0, ==, spktlen);

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = 0;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 0, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  t += 30 * NGTCP2_MILLISECONDS;
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, t);

  assert_int(0, ==, rv);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);

  assert_true(ngtcp2_ksl_it_end(&it));

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  t += 10 * NGTCP2_MILLISECONDS;
  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 10, t);

  assert_ptrdiff(0, <, spktlen);

  t += (conn->cstat.smoothed_rtt +
        ngtcp2_max(4 * conn->cstat.rttvar, NGTCP2_GRANULARITY) +
        25 * NGTCP2_MILLISECONDS) *
       NGTCP2_PERSISTENT_CONGESTION_THRESHOLD;

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 10, t);

  assert_ptrdiff(0, <, spktlen);

  t += 10 * NGTCP2_MILLISECONDS;
  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 10, t);

  assert_ptrdiff(0, <, spktlen);

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = conn->pktns.tx.last_pkt_num;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_range = 0;
  fr.ack.rangecnt = 0;

  pktlen = write_pkt(buf, sizeof(buf), &conn->oscid, 1, &fr, 1,
                     conn->pktns.crypto.rx.ckm);
  t += 30 * NGTCP2_MILLISECONDS;
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, &null_pi, buf, pktlen, t);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  assert_size(2, ==, strm->tx.loss_count);
  /* Persistent congestion resets min_rtt */
  assert_uint64(UINT64_MAX, ==, conn->cstat.min_rtt);

  ngtcp2_conn_del(conn);
}

typedef struct failmalloc {
  size_t nmalloc;
  size_t fail_start;
} failmalloc;

static void *failmalloc_malloc(size_t size, void *user_data) {
  failmalloc *mc = user_data;

  if (mc->fail_start <= ++mc->nmalloc) {
    return NULL;
  }

  return malloc(size);
}

static void failmalloc_free(void *ptr, void *user_data) {
  (void)user_data;

  free(ptr);
}

static void *failmalloc_calloc(size_t nmemb, size_t size, void *user_data) {
  failmalloc *mc = user_data;

  if (mc->fail_start <= ++mc->nmalloc) {
    return NULL;
  }

  return calloc(nmemb, size);
}

static void *failmalloc_realloc(void *ptr, size_t size, void *user_data) {
  failmalloc *mc = user_data;

  if (mc->fail_start <= ++mc->nmalloc) {
    return NULL;
  }

  return realloc(ptr, size);
}

void test_ngtcp2_conn_new_failmalloc(void) {
  ngtcp2_conn *conn;
  ngtcp2_callbacks cb;
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  failmalloc mc;
  ngtcp2_mem mem = {
      &mc,
      failmalloc_malloc,
      failmalloc_free,
      failmalloc_calloc,
      failmalloc_realloc,
  };
  uint8_t token[] = "token";
  size_t tokenlen = strsize(token);
  uint32_t preferred_versions[] = {
      NGTCP2_PROTO_VER_V1,
      NGTCP2_PROTO_VER_V2,
  };
  uint32_t available_versions[] = {
      NGTCP2_PROTO_VER_V2,
      NGTCP2_PROTO_VER_V1,
      0x5a9aeaca,
  };
  ngtcp2_cid dcid, scid;
  int rv;
  size_t i;
  size_t nmalloc;

  dcid_init(&dcid);
  scid_init(&scid);

  ngtcp2_settings_default(&settings);
  ngtcp2_transport_params_default(&params);

  settings.qlog_write = qlog_write;
  settings.token = token;
  settings.tokenlen = tokenlen;
  settings.preferred_versions = preferred_versions;
  settings.preferred_versionslen = ngtcp2_arraylen(preferred_versions);
  settings.available_versions = available_versions;
  settings.available_versionslen = ngtcp2_arraylen(available_versions);

  params.original_dcid = dcid;
  params.original_dcid_present = 1;

  /* server */
  server_default_callbacks(&cb);

  mc.nmalloc = 0;
  mc.fail_start = SIZE_MAX;

  rv = ngtcp2_conn_server_new(&conn, &dcid, &scid, &null_path.path,
                              NGTCP2_PROTO_VER_V1, &cb, &settings, &params,
                              &mem, NULL);

  assert_int(0, ==, rv);

  ngtcp2_conn_del(conn);

  nmalloc = mc.nmalloc;

  for (i = 0; i <= nmalloc; ++i) {
    mc.nmalloc = 0;
    mc.fail_start = i;

    rv = ngtcp2_conn_server_new(&conn, &dcid, &scid, &null_path.path,
                                NGTCP2_PROTO_VER_V1, &cb, &settings, &params,
                                &mem, NULL);

    assert_int(NGTCP2_ERR_NOMEM, ==, rv);
  }

  mc.nmalloc = 0;
  mc.fail_start = nmalloc + 1;

  rv = ngtcp2_conn_server_new(&conn, &dcid, &scid, &null_path.path,
                              NGTCP2_PROTO_VER_V1, &cb, &settings, &params,
                              &mem, NULL);

  assert_int(0, ==, rv);

  ngtcp2_conn_del(conn);

  /* client */
  ngtcp2_transport_params_default(&params);

  client_default_callbacks(&cb);

  mc.nmalloc = 0;
  mc.fail_start = SIZE_MAX;

  rv = ngtcp2_conn_client_new(&conn, &dcid, &scid, &null_path.path,
                              NGTCP2_PROTO_VER_V1, &cb, &settings, &params,
                              &mem, NULL);

  assert_int(0, ==, rv);

  ngtcp2_conn_del(conn);

  nmalloc = mc.nmalloc;

  for (i = 0; i <= nmalloc; ++i) {
    mc.nmalloc = 0;
    mc.fail_start = i;

    rv = ngtcp2_conn_client_new(&conn, &dcid, &scid, &null_path.path,
                                NGTCP2_PROTO_VER_V1, &cb, &settings, &params,
                                &mem, NULL);

    assert_int(NGTCP2_ERR_NOMEM, ==, rv);
  }

  mc.nmalloc = 0;
  mc.fail_start = nmalloc + 1;

  rv = ngtcp2_conn_client_new(&conn, &dcid, &scid, &null_path.path,
                              NGTCP2_PROTO_VER_V1, &cb, &settings, &params,
                              &mem, NULL);

  assert_int(0, ==, rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_accept(void) {
  size_t pktlen;
  uint8_t buf[2048];
  ngtcp2_cid dcid, scid;
  ngtcp2_frame fr;
  int rv;
  ngtcp2_pkt_hd hd;

  dcid_init(&dcid);
  scid_init(&scid);

  /* Initial packet */
  memset(&hd, 0, sizeof(hd));

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1200;
  fr.stream.data[0].base = null_data;

  pktlen = write_initial_pkt(buf, sizeof(buf), &dcid, &scid, 0,
                             NGTCP2_PROTO_VER_V1, NULL, 0, &fr, 1, &null_ckm);

  assert_size(1200, <=, pktlen);

  rv = ngtcp2_accept(&hd, buf, pktlen);

  assert_int(0, ==, rv);
  assert_true(ngtcp2_cid_eq(&dcid, &hd.dcid));
  assert_true(ngtcp2_cid_eq(&scid, &hd.scid));
  assert_size(0, ==, hd.tokenlen);
  assert_size(0, <, hd.len);
  assert_uint32(NGTCP2_PROTO_VER_V1, ==, hd.version);
  assert_uint8(NGTCP2_PKT_INITIAL, ==, hd.type);
  assert_true(hd.flags & NGTCP2_PKT_FLAG_LONG_FORM);

  /* 0RTT packet */
  memset(&hd, 0, sizeof(hd));

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 0;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1200;
  fr.stream.data[0].base = null_data;

  pktlen = write_0rtt_pkt(buf, sizeof(buf), &dcid, &scid, 1,
                          NGTCP2_PROTO_VER_V1, &fr, 1, &null_ckm);

  assert_size(1200, <=, pktlen);

  rv = ngtcp2_accept(&hd, buf, pktlen);

  assert_int(NGTCP2_ERR_INVALID_ARGUMENT, ==, rv);

  /* Unknown version */
  memset(&hd, 0, sizeof(hd));

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1200;
  fr.stream.data[0].base = null_data;

  pktlen = write_initial_pkt(buf, sizeof(buf), &dcid, &scid, 0, 0x2, NULL, 0,
                             &fr, 1, &null_ckm);

  assert_size(1200, <=, pktlen);

  rv = ngtcp2_accept(&hd, buf, pktlen);

  /* Unknown version should be filtered out by earlier call of
     ngtcp2_pkt_decode_version_cid, that is, only supported versioned
     packet should be passed to ngtcp2_accept. */
  assert_int(NGTCP2_ERR_INVALID_ARGUMENT, ==, rv);

  /* Unknown version and the UDP payload size is less than
     NGTCP2_MAX_UDP_PAYLOAD_SIZE. */
  memset(&hd, 0, sizeof(hd));

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1127;
  fr.stream.data[0].base = null_data;

  pktlen = write_initial_pkt(buf, sizeof(buf), &dcid, &scid, 0, 0x2, NULL, 0,
                             &fr, 1, &null_ckm);

  assert_size(1199, ==, pktlen);

  rv = ngtcp2_accept(&hd, buf, pktlen);

  assert_int(NGTCP2_ERR_INVALID_ARGUMENT, ==, rv);

  /* Short packet */
  memset(&hd, 0, sizeof(hd));

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1200;
  fr.stream.data[0].base = null_data;

  pktlen = write_pkt(buf, sizeof(buf), &dcid, 0, &fr, 1, &null_ckm);

  assert_size(1200, <=, pktlen);

  rv = ngtcp2_accept(&hd, buf, pktlen);

  assert_int(NGTCP2_ERR_INVALID_ARGUMENT, ==, rv);

  /* Unable to decode packet header */
  memset(&hd, 0, sizeof(hd));

  memset(buf, 0, 4);
  buf[0] = NGTCP2_HEADER_FORM_BIT;

  rv = ngtcp2_accept(&hd, buf, 4);

  assert_int(NGTCP2_ERR_INVALID_ARGUMENT, ==, rv);
}

void test_ngtcp2_select_version(void) {
  assert_uint32(0, ==, ngtcp2_select_version(NULL, 0, NULL, 0));

  {
    uint32_t preferred_versions[] = {NGTCP2_PROTO_VER_V1, NGTCP2_PROTO_VER_V2};
    uint32_t offered_versions[] = {0x00000004, 0x00000003, NGTCP2_PROTO_VER_V2};

    assert_uint32(NGTCP2_PROTO_VER_V2, ==,
                  ngtcp2_select_version(
                      preferred_versions, ngtcp2_arraylen(preferred_versions),
                      offered_versions, ngtcp2_arraylen(offered_versions)));
  }

  {
    uint32_t preferred_versions[] = {NGTCP2_PROTO_VER_V1, NGTCP2_PROTO_VER_V2};
    uint32_t offered_versions[] = {0x00000004, 0x00000003};

    assert_uint32(0, ==,
                  ngtcp2_select_version(
                      preferred_versions, ngtcp2_arraylen(preferred_versions),
                      offered_versions, ngtcp2_arraylen(offered_versions)));
  }
}

void test_ngtcp2_pkt_write_connection_close(void) {
  ngtcp2_ssize spktlen;
  uint8_t buf[1200];
  ngtcp2_cid dcid, scid;
  ngtcp2_crypto_aead aead = {0, NGTCP2_INITIAL_AEAD_OVERHEAD};
  ngtcp2_crypto_cipher hp_mask = {0};
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};

  dcid_init(&dcid);
  scid_init(&scid);

  spktlen = ngtcp2_pkt_write_connection_close(
      buf, sizeof(buf), NGTCP2_PROTO_VER_V1, &dcid, &scid, NGTCP2_INVALID_TOKEN,
      (const uint8_t *)"foo", 3, null_encrypt, &aead, &aead_ctx, null_iv,
      null_hp_mask, &hp_mask, &hp_ctx);

  assert_ptrdiff(0, <, spktlen);

  spktlen = ngtcp2_pkt_write_connection_close(
      buf, 16, NGTCP2_PROTO_VER_V1, &dcid, &scid, NGTCP2_INVALID_TOKEN, NULL, 0,
      null_encrypt, &aead, &aead_ctx, null_iv, null_hp_mask, &hp_mask, &hp_ctx);

  assert_ptrdiff(NGTCP2_ERR_NOBUF, ==, spktlen);
}

void test_ngtcp2_ccerr_set_liberr(void) {
  ngtcp2_ccerr ccerr;

  ngtcp2_ccerr_set_liberr(&ccerr, NGTCP2_ERR_RECV_VERSION_NEGOTIATION, NULL, 0);

  assert_enum(ngtcp2_ccerr_type, NGTCP2_CCERR_TYPE_VERSION_NEGOTIATION, ==,
              ccerr.type);

  ngtcp2_ccerr_set_liberr(&ccerr, NGTCP2_ERR_IDLE_CLOSE, NULL, 0);

  assert_enum(ngtcp2_ccerr_type, NGTCP2_CCERR_TYPE_IDLE_CLOSE, ==, ccerr.type);

  ngtcp2_ccerr_set_liberr(&ccerr, NGTCP2_ERR_DROP_CONN, NULL, 0);

  assert_enum(ngtcp2_ccerr_type, NGTCP2_CCERR_TYPE_DROP_CONN, ==, ccerr.type);

  ngtcp2_ccerr_set_liberr(&ccerr, NGTCP2_ERR_RETRY, NULL, 0);

  assert_enum(ngtcp2_ccerr_type, NGTCP2_CCERR_TYPE_RETRY, ==, ccerr.type);
}
