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
#include "ngtcp2_settings.h"

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
  munit_void_test(test_ngtcp2_conn_recv_streams_blocked),
  munit_void_test(test_ngtcp2_conn_recv_new_token),
  munit_void_test(test_ngtcp2_conn_recv_conn_id_omitted),
  munit_void_test(test_ngtcp2_conn_short_pkt_type),
  munit_void_test(test_ngtcp2_conn_recv_stateless_reset),
  munit_void_test(test_ngtcp2_conn_recv_retry),
  munit_void_test(test_ngtcp2_conn_recv_delayed_handshake_pkt),
  munit_void_test(test_ngtcp2_conn_recv_max_streams),
  munit_void_test(test_ngtcp2_conn_handshake),
  munit_void_test(test_ngtcp2_conn_handshake_error),
  munit_void_test(test_ngtcp2_conn_retransmit_protected),
  munit_void_test(test_ngtcp2_conn_cancel_retransmission),
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
  munit_void_test(test_ngtcp2_conn_disable_active_migration),
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
  munit_void_test(test_ngtcp2_conn_submit_crypto_data),
  munit_void_test(test_ngtcp2_conn_submit_new_token),
  munit_void_test(test_ngtcp2_conn_persistent_congestion),
  munit_void_test(test_ngtcp2_conn_ack_padding),
  munit_void_test(test_ngtcp2_conn_super_small_rtt),
  munit_void_test(test_ngtcp2_conn_recv_ack),
  munit_void_test(test_ngtcp2_conn_write_aggregate_pkt),
  munit_void_test(test_ngtcp2_conn_crumble_initial_pkt),
  munit_void_test(test_ngtcp2_conn_skip_pkt_num),
  munit_void_test(test_ngtcp2_conn_get_timestamp),
  munit_void_test(test_ngtcp2_conn_get_stream_user_data),
  munit_void_test(test_ngtcp2_conn_new_failmalloc),
  munit_void_test(test_ngtcp2_conn_post_handshake_failmalloc),
  munit_void_test(test_ngtcp2_accept),
  munit_void_test(test_ngtcp2_select_version),
  munit_void_test(test_ngtcp2_pkt_write_connection_close),
  munit_void_test(test_ngtcp2_ccerr_set_liberr),
  munit_test_end(),
};

const MunitSuite conn_suite = {
  .prefix = "/conn",
  .tests = tests,
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
  memcpy(dest, NGTCP2_FAKE_HP_MASK, ngtcp2_strlen_lit(NGTCP2_FAKE_HP_MASK));
  return 0;
}

static int get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                 ngtcp2_stateless_reset_token *token,
                                 size_t cidlen, void *user_data) {
  (void)user_data;

  *cid = (ngtcp2_cid){
    .datalen = cidlen,
    .data = {(uint8_t)(conn->scid.last_seq + 1)},
  };
  *token = (ngtcp2_stateless_reset_token){0};

  return 0;
}

static uint8_t null_secret[32];
static uint8_t null_iv[16];
static uint8_t null_data[4096];

static ngtcp2_crypto_km null_ckm = {
  .iv =
    {
      .base = null_iv,
      .len = sizeof(null_iv),
    },
  .pkt_num = -1,
};

static ngtcp2_path_storage null_path;
static ngtcp2_path_storage new_path;
static ngtcp2_path_storage new_nat_path;

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
  *ctx = (ngtcp2_crypto_ctx){
    .aead.max_overhead = NGTCP2_FAKE_AEAD_OVERHEAD,
    .max_encryption = 9999,
    .max_decryption_failure = 8888,
  };
}

static void init_initial_crypto_ctx(ngtcp2_crypto_ctx *ctx) {
  *ctx = (ngtcp2_crypto_ctx){
    .aead.max_overhead = NGTCP2_INITIAL_AEAD_OVERHEAD,
    .max_encryption = 9999,
    .max_decryption_failure = 8888,
  };
}

typedef struct {
  uint64_t pkt_num;
  /* stream_data is intended to store the arguments passed in
     recv_stream_data callback. */
  struct {
    int64_t stream_id;
    uint32_t flags;
    uint64_t offset;
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
  struct {
    uint32_t flags;
    ngtcp2_path_storage path;
    ngtcp2_path_storage fallback_path;
  } begin_path_validation;
  struct {
    int64_t stream_id;
    size_t num_write_left;
  } write_pkt;
  struct {
    uint8_t token[256];
    size_t tokenlen;
  } new_token;
} my_user_data;

static int client_initial(ngtcp2_conn *conn, void *user_data) {
  (void)user_data;

  ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL,
                                 null_data, 217);

  return 0;
}

static int client_initial_null(ngtcp2_conn *conn, void *user_data) {
  (void)conn;
  (void)user_data;

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

static int client_initial_null_early_data(ngtcp2_conn *conn, void *user_data) {
  (void)conn;
  (void)user_data;

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
  ngtcp2_conn *conn, ngtcp2_encryption_level encryption_level, uint64_t offset,
  const uint8_t *data, size_t datalen, void *user_data) {
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
  ngtcp2_conn *conn, ngtcp2_encryption_level encryption_level, uint64_t offset,
  const uint8_t *data, size_t datalen, void *user_data) {
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

    params = (ngtcp2_transport_params){
      .initial_scid = conn->dcid.current.cid,
      .initial_scid_present = 1,
      .original_dcid = conn->rcid,
      .original_dcid_present = 1,
      .max_udp_payload_size = 1200,
      .initial_max_stream_data_bidi_local =
        early_params->initial_max_stream_data_bidi_local,
      .initial_max_stream_data_bidi_remote = ngtcp2_max_uint64(
        100 * 1024, early_params->initial_max_stream_data_bidi_remote),
      .initial_max_stream_data_uni = early_params->initial_max_stream_data_uni,
      .initial_max_streams_bidi =
        ngtcp2_max_uint64(1, early_params->initial_max_streams_bidi),
      .initial_max_streams_uni =
        ngtcp2_max_uint64(1, early_params->initial_max_streams_uni),
      .initial_max_data =
        ngtcp2_max_uint64(100 * 1024, early_params->initial_max_data),
      .active_connection_id_limit =
        ngtcp2_max_uint64(2, early_params->active_connection_id_limit),
      .max_datagram_frame_size = early_params->max_datagram_frame_size,
    };

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

  memset(rx_secret, 0xFF, sizeof(null_secret));
  memset(tx_secret, 0xFF, sizeof(null_secret));
  rx_aead_ctx->native_handle = NULL;
  memset(rx_iv, 0xFF, sizeof(null_iv));
  tx_aead_ctx->native_handle = NULL;
  memset(tx_iv, 0xFF, sizeof(null_iv));

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
  ngtcp2_conn *conn, ngtcp2_encryption_level encryption_level, uint64_t offset,
  const uint8_t *data, size_t datalen, void *user_data) {
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
  (void)data;
  (void)stream_user_data;

  if (ud) {
    ud->stream_data.stream_id = stream_id;
    ud->stream_data.flags = flags;
    ud->stream_data.offset = offset;
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

static int recv_stream_data_deferred_shutdown_stream_read(
  ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t offset,
  const uint8_t *data, size_t datalen, void *user_data,
  void *stream_user_data) {
  recv_stream_data(conn, flags, stream_id, offset, data, datalen, user_data,
                   stream_user_data);

  conn->callbacks.recv_stream_data = recv_stream_data_shutdown_stream_read;

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

static int lost_datagram(ngtcp2_conn *conn, uint64_t dgram_id,
                         void *user_data) {
  (void)conn;
  (void)dgram_id;
  (void)user_data;

  return 0;
}

static int begin_path_validation(ngtcp2_conn *conn, uint32_t flags,
                                 const ngtcp2_path *path,
                                 const ngtcp2_path *fallback_path,
                                 void *user_data) {
  my_user_data *ud = user_data;
  (void)conn;

  if (!ud) {
    return 0;
  }

  ud->begin_path_validation.flags = flags;
  ngtcp2_path_storage_init2(&ud->begin_path_validation.path, path);

  if (fallback_path) {
    ngtcp2_path_storage_init2(&ud->begin_path_validation.fallback_path,
                              fallback_path);
  } else {
    ngtcp2_path_storage_zero(&ud->begin_path_validation.fallback_path);
  }

  return 0;
}

static int recv_new_token(ngtcp2_conn *conn, const uint8_t *token,
                          size_t tokenlen, void *user_data) {
  my_user_data *ud = user_data;
  (void)conn;

  assert_size(sizeof(ud->new_token.token), >=, tokenlen);

  memcpy(ud->new_token.token, token, tokenlen);
  ud->new_token.tokenlen = tokenlen;

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

static void
server_default_remote_transport_params(ngtcp2_transport_params *params) {
  *params = (ngtcp2_transport_params){
    .initial_max_stream_data_bidi_local = 64 * 1024,
    .initial_max_stream_data_bidi_remote = 64 * 1024,
    .initial_max_stream_data_uni = 64 * 1024,
    .initial_max_streams_uni = 1,
    .initial_max_data = 64 * 1024,
    .active_connection_id_limit = 8,
    .max_udp_payload_size = NGTCP2_DEFAULT_MAX_RECV_UDP_PAYLOAD_SIZE,
    .initial_scid_present = 1,
  };
  dcid_init(&params->initial_scid);
}

static void server_default_callbacks(ngtcp2_callbacks *cb) {
  *cb = (ngtcp2_callbacks){
    .recv_client_initial = recv_client_initial,
    .recv_crypto_data = recv_crypto_data_server,
    .decrypt = null_decrypt,
    .encrypt = null_encrypt,
    .hp_mask = null_hp_mask,
    .rand = genrand,
    .update_key = update_key,
    .delete_crypto_aead_ctx = delete_crypto_aead_ctx,
    .delete_crypto_cipher_ctx = delete_crypto_cipher_ctx,
    .get_path_challenge_data = get_path_challenge_data,
    .version_negotiation = version_negotiation,
    .get_new_connection_id2 = get_new_connection_id,
  };
}

static void server_handshake_settings(ngtcp2_settings *settings) {
  static const uint32_t preferred_versions[] = {
    NGTCP2_PROTO_VER_V2,
    NGTCP2_PROTO_VER_V1,
  };

  server_default_settings(settings);
  settings->preferred_versions = preferred_versions;
  settings->preferred_versionslen = ngtcp2_arraylen(preferred_versions);
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

static void
client_default_remote_transport_params(ngtcp2_transport_params *params) {
  *params = (ngtcp2_transport_params){
    .initial_max_stream_data_bidi_local = 64 * 1024,
    .initial_max_stream_data_bidi_remote = 64 * 1024,
    .initial_max_stream_data_uni = 64 * 1024,
    .initial_max_streams_bidi = 1,
    .initial_max_streams_uni = 1,
    .initial_max_data = 64 * 1024,
    .active_connection_id_limit = 8,
    .max_udp_payload_size = NGTCP2_DEFAULT_MAX_RECV_UDP_PAYLOAD_SIZE,
    .initial_scid_present = 1,
    .original_dcid_present = 1,
  };
  dcid_init(&params->initial_scid);
  dcid_init(&params->original_dcid);
}

static void client_default_callbacks(ngtcp2_callbacks *cb) {
  *cb = (ngtcp2_callbacks){
    .client_initial = client_initial,
    .recv_crypto_data = recv_crypto_data,
    .decrypt = null_decrypt,
    .encrypt = null_encrypt,
    .hp_mask = null_hp_mask,
    .recv_retry = recv_retry,
    .rand = genrand,
    .update_key = update_key,
    .delete_crypto_aead_ctx = delete_crypto_aead_ctx,
    .delete_crypto_cipher_ctx = delete_crypto_cipher_ctx,
    .get_path_challenge_data = get_path_challenge_data,
    .version_negotiation = version_negotiation,
    .get_new_connection_id2 = get_new_connection_id,
  };
}

static void client_handshake_settings(ngtcp2_settings *settings) {
  static const uint32_t preferred_versions[] = {
    NGTCP2_PROTO_VER_V2,
    NGTCP2_PROTO_VER_V1,
  };

  static const uint32_t available_versions[] = {
    NGTCP2_PROTO_VER_V1,
    NGTCP2_PROTO_VER_V2,
  };

  client_default_settings(settings);

  settings->preferred_versions = preferred_versions;
  settings->preferred_versionslen = ngtcp2_arraylen(preferred_versions);

  settings->available_versions = available_versions;
  settings->available_versionslen = ngtcp2_arraylen(available_versions);
}

static void
client_early_remote_transport_params(ngtcp2_transport_params *params) {
  *params = (ngtcp2_transport_params){
    .initial_max_stream_data_bidi_local = 64 * 1024,
    .initial_max_stream_data_bidi_remote = 64 * 1024,
    .initial_max_stream_data_uni = 64 * 1024,
    .initial_max_streams_bidi = 1,
    .initial_max_streams_uni = 1,
    .initial_max_data = 64 * 1024,
    .active_connection_id_limit = 8,
  };
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

typedef struct conn_options {
  const ngtcp2_cid *dcid;
  const ngtcp2_cid *scid;
  const ngtcp2_path *path;
  const ngtcp2_settings *settings;
  const ngtcp2_transport_params *params;
  const ngtcp2_transport_params *remote_params;
  const ngtcp2_callbacks *callbacks;
  const ngtcp2_mem *mem;
  uint32_t client_chosen_version;
  void *user_data;
  int skip_pkt_num;
} conn_options;

static void conn_server_new(ngtcp2_conn **pconn, conn_options opts) {
  ngtcp2_cid dcid, scid;
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  ngtcp2_callbacks cb;

  if (!opts.dcid) {
    dcid_init(&dcid);
    opts.dcid = &dcid;
  }

  if (!opts.scid) {
    scid_init(&scid);
    opts.scid = &scid;
  }

  if (!opts.path) {
    opts.path = &null_path.path;
  }

  if (!opts.settings) {
    server_default_settings(&settings);
    opts.settings = &settings;
  }

  if (!opts.params) {
    server_default_transport_params(&params);
    opts.params = &params;
  }

  if (!opts.callbacks) {
    server_default_callbacks(&cb);
    opts.callbacks = &cb;
  }

  if (!opts.client_chosen_version) {
    opts.client_chosen_version = NGTCP2_PROTO_VER_V1;
  }

  ngtcp2_conn_server_new(pconn, opts.dcid, opts.scid, opts.path,
                         opts.client_chosen_version, opts.callbacks,
                         opts.settings, opts.params, opts.mem, opts.user_data);

  if (!opts.skip_pkt_num) {
    (*pconn)->pktns.tx.skip_pkt.next_pkt_num = INT64_MAX;
  }
}

static void setup_default_server_with_options(ngtcp2_conn **pconn,
                                              conn_options opts) {
  ngtcp2_transport_params remote_params;
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  ngtcp2_crypto_ctx crypto_ctx;
  int rv;

  conn_server_new(pconn, opts);

  init_crypto_ctx(&crypto_ctx);

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

  if (!opts.remote_params) {
    server_default_remote_transport_params(&remote_params);
    opts.remote_params = &remote_params;
  }

  rv = ngtcp2_conn_set_remote_transport_params(*pconn, opts.remote_params);

  assert_int(0, ==, rv);

  (*pconn)->handshake_confirmed_ts = 0;
}

static void setup_default_server(ngtcp2_conn **pconn) {
  conn_options opts = {0};

  setup_default_server_with_options(pconn, opts);
}

static void conn_client_new(ngtcp2_conn **pconn, conn_options opts) {
  ngtcp2_cid dcid, scid;
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  ngtcp2_callbacks cb;

  if (!opts.dcid) {
    dcid_init(&dcid);
    opts.dcid = &dcid;
  }

  if (!opts.scid) {
    scid_init(&scid);
    opts.scid = &scid;
  }

  if (!opts.path) {
    opts.path = &null_path.path;
  }

  if (!opts.settings) {
    client_default_settings(&settings);
    opts.settings = &settings;
  }

  if (!opts.params) {
    client_default_transport_params(&params);
    opts.params = &params;
  }

  if (!opts.callbacks) {
    client_default_callbacks(&cb);
    opts.callbacks = &cb;
  }

  if (!opts.client_chosen_version) {
    opts.client_chosen_version = NGTCP2_PROTO_VER_V1;
  }

  ngtcp2_conn_client_new(pconn, opts.dcid, opts.scid, opts.path,
                         opts.client_chosen_version, opts.callbacks,
                         opts.settings, opts.params, opts.mem, opts.user_data);

  if (!opts.skip_pkt_num) {
    (*pconn)->pktns.tx.skip_pkt.next_pkt_num = INT64_MAX;
  }

  (*pconn)->flags &= ~NGTCP2_CONN_FLAG_CRUMBLE_INITIAL_CRYPTO;
}

static void setup_default_client_with_options(ngtcp2_conn **pconn,
                                              conn_options opts) {
  ngtcp2_transport_params remote_params;
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  ngtcp2_crypto_ctx crypto_ctx;
  int rv;

  conn_client_new(pconn, opts);

  init_crypto_ctx(&crypto_ctx);

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

  (*pconn)->negotiated_version = (*pconn)->client_chosen_version;

  if (!opts.remote_params) {
    client_default_remote_transport_params(&remote_params);
    opts.remote_params = &remote_params;
  }

  rv = ngtcp2_conn_set_remote_transport_params(*pconn, opts.remote_params);

  assert_int(0, ==, rv);

  (*pconn)->dcid.current.flags |= NGTCP2_DCID_FLAG_TOKEN_PRESENT;
  (*pconn)->dcid.current.token =
    (ngtcp2_stateless_reset_token)make_client_stateless_reset_token();
  (*pconn)->handshake_confirmed_ts = 0;
}

static void setup_default_client(ngtcp2_conn **pconn) {
  conn_options opts = {0};

  setup_default_client_with_options(pconn, opts);
}

static void setup_handshake_server_with_options(ngtcp2_conn **pconn,
                                                conn_options opts) {
  ngtcp2_settings settings;

  if (!opts.settings) {
    server_handshake_settings(&settings);

    opts.settings = &settings;
  }

  conn_server_new(pconn, opts);
}

static void setup_handshake_server(ngtcp2_conn **pconn) {
  conn_options opts = {0};

  setup_handshake_server_with_options(pconn, opts);
}

static void setup_handshake_client_with_options(ngtcp2_conn **pconn,
                                                conn_options opts) {
  ngtcp2_cid rcid;
  ngtcp2_settings settings;
  ngtcp2_crypto_aead retry_aead = {
    .max_overhead = NGTCP2_FAKE_AEAD_OVERHEAD,
  };
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  ngtcp2_crypto_ctx crypto_ctx;
  const uint32_t preferred_versions[] = {
    NGTCP2_PROTO_VER_V2,
    NGTCP2_PROTO_VER_V1,
  };
  const uint32_t available_versions[] = {
    NGTCP2_PROTO_VER_V1,
    NGTCP2_PROTO_VER_V2,
  };

  if (!opts.dcid) {
    rcid_init(&rcid);
    opts.dcid = &rcid;
  }

  if (!opts.settings) {
    client_default_settings(&settings);

    settings.preferred_versions = preferred_versions;
    settings.preferred_versionslen = ngtcp2_arraylen(preferred_versions);

    settings.available_versions = available_versions;
    settings.available_versionslen = ngtcp2_arraylen(available_versions);

    opts.settings = &settings;
  }

  conn_client_new(pconn, opts);

  init_initial_crypto_ctx(&crypto_ctx);

  ngtcp2_conn_set_initial_crypto_ctx(*pconn, &crypto_ctx);
  ngtcp2_conn_install_initial_key(*pconn, &aead_ctx, null_iv, &hp_ctx,
                                  &aead_ctx, null_iv, &hp_ctx, sizeof(null_iv));
  ngtcp2_conn_set_retry_aead(*pconn, &retry_aead, &aead_ctx);
}

static void setup_handshake_client(ngtcp2_conn **pconn) {
  conn_options opts = {0};

  setup_handshake_client_with_options(pconn, opts);
}

static void setup_early_server_with_options(ngtcp2_conn **pconn,
                                            conn_options opts) {
  ngtcp2_callbacks cb;

  if (!opts.callbacks) {
    server_early_callbacks(&cb);
    opts.callbacks = &cb;
  }

  conn_server_new(pconn, opts);
}

static void setup_early_server(ngtcp2_conn **pconn) {
  conn_options opts = {0};

  setup_early_server_with_options(pconn, opts);
}

static void setup_early_client_with_options(ngtcp2_conn **pconn,
                                            conn_options opts) {
  ngtcp2_cid rcid;
  ngtcp2_callbacks cb;
  ngtcp2_transport_params remote_params;
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  ngtcp2_crypto_ctx crypto_ctx;

  if (!opts.dcid) {
    rcid_init(&rcid);
    opts.dcid = &rcid;
  }

  if (!opts.callbacks) {
    client_early_callbacks(&cb);
    opts.callbacks = &cb;
  }

  conn_client_new(pconn, opts);

  init_initial_crypto_ctx(&crypto_ctx);

  ngtcp2_conn_set_initial_crypto_ctx(*pconn, &crypto_ctx);
  ngtcp2_conn_install_initial_key(*pconn, &aead_ctx, null_iv, &hp_ctx,
                                  &aead_ctx, null_iv, &hp_ctx, sizeof(null_iv));

  if (!opts.remote_params) {
    client_early_remote_transport_params(&remote_params);
    opts.remote_params = &remote_params;
  }

  ngtcp2_conn_set_0rtt_remote_transport_params(*pconn, opts.remote_params);
}

static void setup_early_client(ngtcp2_conn **pconn) {
  conn_options opts = {0};

  setup_early_client_with_options(pconn, opts);
}

void test_ngtcp2_conn_stream_open_close(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  int rv;
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  ngtcp2_strm *strm;
  int64_t stream_id;
  ngtcp2_tpe tpe;

  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.app.last_pkt_num = 0;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 17,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, 4);

  assert_uint32(NGTCP2_STRM_FLAG_NONE, ==, strm->flags);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .fin = 1,
    .stream_id = 4,
    .offset = 17,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

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
  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 2,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 19,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 3);

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
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  ngtcp2_strm *strm;
  size_t i;
  int64_t stream_id;
  ngtcp2_tpe tpe;
  ngtcp2_transport_params params;
  conn_options opts;

  server_default_transport_params(&params);
  params.initial_max_stream_data_bidi_remote = 2047;

  opts = (conn_options){
    .params = &params,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  for (i = 0; i < 3; ++i) {
    stream_id = (int64_t)(i * 4);
    fr.stream = (ngtcp2_stream){
      .type = NGTCP2_FRAME_STREAM,
      .stream_id = stream_id,
      .datacnt = 1,
      .data = &datav,
    };
    datav = (ngtcp2_vec){
      .len = 1024,
      .base = null_data,
    };

    pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
    rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

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
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  ngtcp2_tpe tpe;
  ngtcp2_transport_params params;
  conn_options opts;

  server_default_transport_params(&params);
  params.initial_max_stream_data_bidi_remote = 1023;

  opts = (conn_options){
    .params = &params,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1024,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

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
  ngtcp2_tpe tpe;
  ngtcp2_transport_params remote_params;
  conn_options opts;

  client_default_remote_transport_params(&remote_params);
  remote_params.initial_max_stream_data_bidi_remote = 2047;

  opts = (conn_options){
    .remote_params = &remote_params,
  };

  setup_default_client_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

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

  /* We cannot write 0 length STREAM frame after committing some
     data. */
  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf),
                                     &nwrite, NGTCP2_WRITE_STREAM_FLAG_NONE,
                                     stream_id, null_data, 0, 3);

  assert_ptrdiff(0, ==, spktlen);
  assert_ptrdiff(-1, ==, nwrite);
  assert_uint64(2047, ==, strm->tx.offset);

  fr.max_stream_data = (ngtcp2_max_stream_data){
    .type = NGTCP2_FRAME_MAX_STREAM_DATA,
    .stream_id = stream_id,
    .max_stream_data = 2048,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 4);

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
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  ngtcp2_tpe tpe;
  ngtcp2_transport_params params;
  conn_options opts;

  server_default_transport_params(&params);
  params.initial_max_data = 1024;

  opts = (conn_options){
    .params = &params,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1023,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

  assert_int(0, ==, rv);

  ngtcp2_conn_extend_max_offset(conn, 1023);

  assert_uint64(1024 + 1023, ==, conn->rx.unsent_max_offset);
  assert_uint64(1024, ==, conn->rx.max_offset);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .offset = 1023,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 2);

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
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  ngtcp2_tpe tpe;
  ngtcp2_transport_params params;
  conn_options opts;

  server_default_transport_params(&params);
  params.initial_max_data = 1024;

  opts = (conn_options){
    .params = &params,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1025,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

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
  ngtcp2_tpe tpe;
  ngtcp2_transport_params remote_params;
  conn_options opts;

  client_default_remote_transport_params(&remote_params);
  remote_params.initial_max_data = 2048;

  opts = (conn_options){
    .remote_params = &remote_params,
  };

  setup_default_client_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

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

  fr.max_data = (ngtcp2_max_data){
    .type = NGTCP2_FRAME_MAX_DATA,
    .max_data = 3072,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 5);

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
  ngtcp2_tpe tpe;

  /* Stream not found */
  setup_default_server(&conn);

  rv = ngtcp2_conn_shutdown_stream_write(conn, 0, 4, NGTCP2_APP_ERR01);

  assert_int(0, ==, rv);

  ngtcp2_conn_del(conn);

  /* Check final_size */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

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

  fr.reset_stream = (ngtcp2_reset_stream){
    .type = NGTCP2_FRAME_RESET_STREAM,
    .stream_id = stream_id,
    .app_error_code = NGTCP2_APP_ERR02,
    .final_size = 100,
  };

  tpe.app.last_pkt_num = 889;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 2);

  assert_int(0, ==, rv);
  assert_not_null(ngtcp2_conn_find_stream(conn, stream_id));

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
  };

  tpe.app.last_pkt_num = 898;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 2);

  assert_int(0, ==, rv);
  assert_null(ngtcp2_conn_find_stream(conn, stream_id));

  ngtcp2_conn_del(conn);

  /* Check that stream is closed when RESET_STREAM is acknowledged */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = stream_id,
  };

  tpe.app.last_pkt_num = 118;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

  assert_int(0, ==, rv);
  assert_not_null(ngtcp2_conn_find_stream(conn, stream_id));

  rv = ngtcp2_conn_shutdown_stream_write(conn, 0, stream_id, NGTCP2_APP_ERR01);

  assert_int(0, ==, rv);
  assert_not_null(ngtcp2_conn_find_stream(conn, stream_id));

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), 2);

  assert_ptrdiff(0, <, spktlen);

  /* Incoming FIN does not close stream */
  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .fin = 1,
  };

  tpe.app.last_pkt_num = 120;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 2);

  assert_int(0, ==, rv);
  assert_not_null(ngtcp2_conn_find_stream(conn, stream_id));

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
  };

  tpe.app.last_pkt_num = 331;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 3);

  assert_int(0, ==, rv);
  assert_null(ngtcp2_conn_find_stream(conn, stream_id));

  ngtcp2_conn_del(conn);

  /* RESET_STREAM is not sent if all tx data are acknowledged */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_FIN, stream_id,
                                     null_data, 0, 3);

  assert_ptrdiff(0, <, spktlen);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
  };

  tpe.app.last_pkt_num = 998;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 7);

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
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  ngtcp2_tstamp t = 0;
  size_t pktlen;
  ngtcp2_tpe tpe;

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
  ngtcp2_tpe_init_conn(&tpe, conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  fr.reset_stream = (ngtcp2_reset_stream){
    .type = NGTCP2_FRAME_RESET_STREAM,
    .stream_id = stream_id,
    .app_error_code = NGTCP2_APP_ERR01,
    .final_size = 1,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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
  ngtcp2_tpe_init_conn(&tpe, conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = stream_id,
    .fin = 1,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 77,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_strm *strm;
  int64_t stream_id;
  ngtcp2_tpe tpe;
  ngtcp2_transport_params params, remote_params;
  conn_options opts;

  /* Receive RESET_STREAM */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 955,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

  assert_int(0, ==, rv);

  ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                           NGTCP2_WRITE_STREAM_FLAG_NONE, 4, null_data, 354, 2);

  fr.reset_stream = (ngtcp2_reset_stream){
    .type = NGTCP2_FRAME_RESET_STREAM,
    .stream_id = 4,
    .app_error_code = NGTCP2_APP_ERR02,
    .final_size = 955,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 3);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, 4);

  assert_true(strm->flags & NGTCP2_STRM_FLAG_SHUT_RD);
  assert_true(strm->flags & NGTCP2_STRM_FLAG_RESET_STREAM_RECVED);

  ngtcp2_conn_del(conn);

  /* Receive RESET_STREAM after sending STOP_SENDING */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 955,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

  assert_int(0, ==, rv);

  ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                           NGTCP2_WRITE_STREAM_FLAG_NONE, 4, null_data, 354, 2);
  ngtcp2_conn_shutdown_stream_read(conn, 0, 4, NGTCP2_APP_ERR01);
  ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), 3);

  fr.reset_stream = (ngtcp2_reset_stream){
    .type = NGTCP2_FRAME_RESET_STREAM,
    .stream_id = 4,
    .app_error_code = NGTCP2_APP_ERR02,
    .final_size = 955,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 4);

  assert_int(0, ==, rv);
  assert_not_null(ngtcp2_conn_find_stream(conn, 4));

  ngtcp2_conn_del(conn);

  /* Receive RESET_STREAM after sending RESET_STREAM */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 955,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

  assert_int(0, ==, rv);

  ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                           NGTCP2_WRITE_STREAM_FLAG_NONE, 4, null_data, 354, 2);
  ngtcp2_conn_shutdown_stream_write(conn, 0, 4, NGTCP2_APP_ERR01);
  ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), 3);

  fr.reset_stream = (ngtcp2_reset_stream){
    .type = NGTCP2_FRAME_RESET_STREAM,
    .stream_id = 4,
    .app_error_code = NGTCP2_APP_ERR02,
    .final_size = 955,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 4);

  assert_int(0, ==, rv);
  assert_not_null(ngtcp2_conn_find_stream(conn, 4));

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 5);

  assert_int(0, ==, rv);
  assert_null(ngtcp2_conn_find_stream(conn, 4));

  ngtcp2_conn_del(conn);

  /* Receive RESET_STREAM after receiving STOP_SENDING */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 955,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

  assert_int(0, ==, rv);

  ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                           NGTCP2_WRITE_STREAM_FLAG_NONE, 4, null_data, 354, 2);

  fr.stop_sending = (ngtcp2_stop_sending){
    .type = NGTCP2_FRAME_STOP_SENDING,
    .stream_id = 4,
    .app_error_code = NGTCP2_APP_ERR01,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 3);

  assert_int(0, ==, rv);
  assert_not_null(ngtcp2_conn_find_stream(conn, 4));

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), 4);

  assert_ptrdiff(0, <, spktlen);

  fr.reset_stream = (ngtcp2_reset_stream){
    .type = NGTCP2_FRAME_RESET_STREAM,
    .stream_id = 4,
    .app_error_code = NGTCP2_APP_ERR02,
    .final_size = 955,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 4);

  assert_int(0, ==, rv);
  assert_not_null(ngtcp2_conn_find_stream(conn, 4));

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 5);

  assert_int(0, ==, rv);
  assert_null(ngtcp2_conn_find_stream(conn, 4));

  ngtcp2_conn_del(conn);

  /* final_size in RESET_STREAM exceeds the already received offset */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 955,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

  assert_int(0, ==, rv);

  fr.reset_stream = (ngtcp2_reset_stream){
    .type = NGTCP2_FRAME_RESET_STREAM,
    .stream_id = 4,
    .app_error_code = NGTCP2_APP_ERR02,
    .final_size = 954,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 2);

  assert_int(NGTCP2_ERR_FINAL_SIZE, ==, rv);

  ngtcp2_conn_del(conn);

  /* final_size in RESET_STREAM differs from the final offset which
     STREAM frame with fin indicated. */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .fin = 1,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 955,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

  assert_int(0, ==, rv);

  fr.reset_stream = (ngtcp2_reset_stream){
    .type = NGTCP2_FRAME_RESET_STREAM,
    .stream_id = 4,
    .app_error_code = NGTCP2_APP_ERR02,
    .final_size = 956,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 2);

  assert_int(NGTCP2_ERR_FINAL_SIZE, ==, rv);

  ngtcp2_conn_del(conn);

  /* RESET_STREAM against local stream which has not been initiated. */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.reset_stream = (ngtcp2_reset_stream){
    .type = NGTCP2_FRAME_RESET_STREAM,
    .stream_id = 1,
    .app_error_code = NGTCP2_APP_ERR01,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

  assert_int(NGTCP2_ERR_STREAM_STATE, ==, rv);

  ngtcp2_conn_del(conn);

  /* RESET_STREAM against remote stream which has not been initiated */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.reset_stream = (ngtcp2_reset_stream){
    .type = NGTCP2_FRAME_RESET_STREAM,
    .app_error_code = NGTCP2_APP_ERR01,
    .final_size = 1999,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, 0);

  assert_uint64(1999, ==, strm->rx.last_offset);
  assert_true(strm->flags & NGTCP2_STRM_FLAG_RESET_STREAM_RECVED);
  assert_uint64(3, ==, conn->remote.bidi.unsent_max_streams);

  ngtcp2_conn_del(conn);

  /* RESET_STREAM against remote stream which is larger than allowed
     maximum */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.reset_stream = (ngtcp2_reset_stream){
    .type = NGTCP2_FRAME_RESET_STREAM,
    .stream_id = 16,
    .app_error_code = NGTCP2_APP_ERR01,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

  assert_int(NGTCP2_ERR_STREAM_LIMIT, ==, rv);

  ngtcp2_conn_del(conn);

  /* RESET_STREAM against remote stream which is allowed, and no
     ngtcp2_strm object has been created */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.reset_stream = (ngtcp2_reset_stream){
    .type = NGTCP2_FRAME_RESET_STREAM,
    .stream_id = 4,
    .app_error_code = NGTCP2_APP_ERR01,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

  assert_int(0, ==, rv);
  assert_true(
    ngtcp2_idtr_is_open(&conn->remote.bidi.idtr, fr.reset_stream.stream_id));

  ngtcp2_conn_del(conn);

  /* RESET_STREAM against remote stream which is allowed, and no
     ngtcp2_strm object has been created, and final_size violates
     connection-level flow control. */
  server_default_remote_transport_params(&remote_params);
  remote_params.initial_max_stream_data_bidi_remote = 1 << 21;

  opts = (conn_options){
    .remote_params = &remote_params,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.reset_stream = (ngtcp2_reset_stream){
    .type = NGTCP2_FRAME_RESET_STREAM,
    .stream_id = 4,
    .app_error_code = NGTCP2_APP_ERR01,
    .final_size = 1 << 20,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

  assert_int(NGTCP2_ERR_FLOW_CONTROL, ==, rv);

  ngtcp2_conn_del(conn);

  /* RESET_STREAM against remote stream which is allowed, and no
      ngtcp2_strm object has been created, and final_size violates
      stream-level flow control. */
  server_default_transport_params(&params);
  params.initial_max_data = 1 << 21;

  opts = (conn_options){
    .params = &params,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.reset_stream = (ngtcp2_reset_stream){
    .type = NGTCP2_FRAME_RESET_STREAM,
    .stream_id = 4,
    .app_error_code = NGTCP2_APP_ERR01,
    .final_size = 1 << 20,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

  assert_int(NGTCP2_ERR_FLOW_CONTROL, ==, rv);

  ngtcp2_conn_del(conn);

  /* final_size in RESET_STREAM violates connection-level flow
     control */
  server_default_remote_transport_params(&remote_params);
  remote_params.initial_max_stream_data_bidi_remote = 1 << 21;

  opts = (conn_options){
    .remote_params = &remote_params,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 955,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

  assert_int(0, ==, rv);

  fr.reset_stream = (ngtcp2_reset_stream){
    .type = NGTCP2_FRAME_RESET_STREAM,
    .stream_id = 4,
    .app_error_code = NGTCP2_APP_ERR02,
    .final_size = 1024 * 1024,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 2);

  assert_int(NGTCP2_ERR_FLOW_CONTROL, ==, rv);

  ngtcp2_conn_del(conn);

  /* final_size in RESET_STREAM violates stream-level flow control */
  server_default_transport_params(&params);
  params.initial_max_data = 1 << 21;

  opts = (conn_options){
    .params = &params,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 955,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

  assert_int(0, ==, rv);

  fr.reset_stream = (ngtcp2_reset_stream){
    .type = NGTCP2_FRAME_RESET_STREAM,
    .stream_id = 4,
    .app_error_code = NGTCP2_APP_ERR02,
    .final_size = 1024 * 1024,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 2);

  assert_int(NGTCP2_ERR_FLOW_CONTROL, ==, rv);

  ngtcp2_conn_del(conn);

  /* Receiving RESET_STREAM for a local unidirectional stream is a
     protocol violation. */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  rv = ngtcp2_conn_open_uni_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  fr.reset_stream = (ngtcp2_reset_stream){
    .type = NGTCP2_FRAME_RESET_STREAM,
    .stream_id = stream_id,
    .app_error_code = NGTCP2_APP_ERR02,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

  assert_int(NGTCP2_ERR_PROTO, ==, rv);

  ngtcp2_conn_del(conn);

  /* RESET_STREAM extends connection window including buffered data */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .offset = 1,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 955,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

  assert_int(0, ==, rv);

  fr.reset_stream = (ngtcp2_reset_stream){
    .type = NGTCP2_FRAME_RESET_STREAM,
    .stream_id = 4,
    .app_error_code = NGTCP2_APP_ERR02,
    .final_size = 1024,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 2);

  assert_int(0, ==, rv);
  assert_uint64(1024, ==, conn->rx.offset);
  assert_uint64(128 * 1024 + 1024, ==, conn->rx.unsent_max_offset);

  /* Receiving same RESET_STREAM does not increase rx offsets. */
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 3);

  assert_int(0, ==, rv);
  assert_uint64(1024, ==, conn->rx.offset);
  assert_uint64(128 * 1024 + 1024, ==, conn->rx.unsent_max_offset);

  ngtcp2_conn_del(conn);

  /* Verify that connection window is properly updated when
     RESET_STREAM is received after sending STOP_SENDING */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .offset = 1,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 955,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

  assert_int(0, ==, rv);

  ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                           NGTCP2_WRITE_STREAM_FLAG_NONE, 4, null_data, 354, 2);
  ngtcp2_conn_shutdown_stream_read(conn, 0, 4, NGTCP2_APP_ERR01);
  ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), 3);

  assert_uint64(128 * 1024 + 956, ==, conn->rx.unsent_max_offset);

  fr.reset_stream = (ngtcp2_reset_stream){
    .type = NGTCP2_FRAME_RESET_STREAM,
    .stream_id = 4,
    .app_error_code = NGTCP2_APP_ERR02,
    .final_size = 957,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 4);

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
  ngtcp2_frame_chain *frc;
  int64_t stream_id;
  ngtcp2_ksl_it it;
  ngtcp2_rtb_entry *ent;
  ngtcp2_tpe tpe;

  /* Receive STOP_SENDING */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                           NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id, null_data,
                           333, ++t);

  fr.stop_sending = (ngtcp2_stop_sending){
    .type = NGTCP2_FRAME_STOP_SENDING,
    .stream_id = stream_id,
    .app_error_code = NGTCP2_APP_ERR01,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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

  assert_uint64(NGTCP2_FRAME_RESET_STREAM, ==, frc->fr.hd.type);
  assert_uint64(NGTCP2_APP_ERR01, ==, frc->fr.reset_stream.app_error_code);
  assert_uint64(333, ==, frc->fr.reset_stream.final_size);

  /* Make sure that receiving duplicated STOP_SENDING does not trigger
     another RESET_STREAM. */
  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  assert_true(strm->flags & NGTCP2_STRM_FLAG_SHUT_WR);
  assert_true(strm->flags & NGTCP2_STRM_FLAG_RESET_STREAM);
  assert_false(strm->flags & NGTCP2_STRM_FLAG_SEND_RESET_STREAM);

  ngtcp2_conn_del(conn);

  /* Receive STOP_SENDING after receiving RESET_STREAM */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  t = 0;

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                           NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id, null_data,
                           333, ++t);

  fr.reset_stream = (ngtcp2_reset_stream){
    .type = NGTCP2_FRAME_RESET_STREAM,
    .stream_id = stream_id,
    .app_error_code = NGTCP2_APP_ERR01,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  fr.stop_sending = (ngtcp2_stop_sending){
    .type = NGTCP2_FRAME_STOP_SENDING,
    .stream_id = stream_id,
    .app_error_code = NGTCP2_APP_ERR01,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_not_null(ngtcp2_conn_find_stream(conn, stream_id));

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);

  assert_false(ngtcp2_ksl_it_end(&it));

  ent = ngtcp2_ksl_it_get(&it);
  frc = ent->frc;

  assert_uint64(NGTCP2_FRAME_RESET_STREAM, ==, frc->fr.hd.type);
  assert_uint64(NGTCP2_APP_ERR01, ==, frc->fr.reset_stream.app_error_code);
  assert_uint64(333, ==, frc->fr.reset_stream.final_size);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_null(ngtcp2_conn_find_stream(conn, stream_id));

  ngtcp2_conn_del(conn);

  /* STOP_SENDING against remote bidirectional stream which has not
     been initiated. */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.stop_sending = (ngtcp2_stop_sending){
    .type = NGTCP2_FRAME_STOP_SENDING,
    .app_error_code = NGTCP2_APP_ERR01,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, 0);

  assert_not_null(strm);
  assert_true(strm->flags & NGTCP2_STRM_FLAG_SHUT_WR);

  ngtcp2_conn_del(conn);

  /* STOP_SENDING against local bidirectional stream which has not
     been initiated. */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.stop_sending = (ngtcp2_stop_sending){
    .type = NGTCP2_FRAME_STOP_SENDING,
    .stream_id = 1,
    .app_error_code = NGTCP2_APP_ERR01,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

  assert_int(NGTCP2_ERR_STREAM_STATE, ==, rv);

  ngtcp2_conn_del(conn);

  /* Receiving STOP_SENDING for a local unidirectional stream */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  rv = ngtcp2_conn_open_uni_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  fr.stop_sending = (ngtcp2_stop_sending){
    .type = NGTCP2_FRAME_STOP_SENDING,
    .stream_id = stream_id,
    .app_error_code = NGTCP2_APP_ERR01,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  assert_true(strm->flags & NGTCP2_STRM_FLAG_SEND_RESET_STREAM);

  ngtcp2_conn_del(conn);

  /* STOP_SENDING against local unidirectional stream which has not
     been initiated. */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.stop_sending = (ngtcp2_stop_sending){
    .type = NGTCP2_FRAME_STOP_SENDING,
    .stream_id = 3,
    .app_error_code = NGTCP2_APP_ERR01,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

  assert_int(NGTCP2_ERR_STREAM_STATE, ==, rv);

  ngtcp2_conn_del(conn);

  /* STOP_SENDING against local bidirectional stream in Data Sent
     state.  Because all data have been acknowledged, and FIN is sent,
     RESET_STREAM is not necessary. */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_FIN, stream_id,
                                     null_data, 1, 1);

  assert_ptrdiff(0, <, spktlen);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

  assert_int(0, ==, rv);

  fr.stop_sending = (ngtcp2_stop_sending){
    .type = NGTCP2_FRAME_STOP_SENDING,
    .stream_id = stream_id,
    .app_error_code = NGTCP2_APP_ERR01,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

  assert_int(0, ==, rv);
  assert_null(conn->pktns.tx.frq);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_stream_data_blocked(void) {
  ngtcp2_conn *conn;
  int rv;
  uint8_t buf[2048];
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_strm *strm;
  ngtcp2_tstamp t = 0;
  int64_t stream_id;
  ngtcp2_transport_params params;
  ngtcp2_tpe tpe;
  conn_options opts;

  /* Receive STREAM_DATA_BLOCKED to locally initiated stream. */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  fr.stream_data_blocked = (ngtcp2_stream_data_blocked){
    .type = NGTCP2_FRAME_STREAM_DATA_BLOCKED,
    .stream_id = stream_id,
    .offset = 65535,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  assert_uint64(65535, ==, strm->rx.last_offset);
  assert_uint64(65535, ==, conn->rx.offset);

  ngtcp2_conn_del(conn);

  /* Receive STREAM_DATA_BLOCKED to a local stream which is not opened
     yet. */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.stream_data_blocked = (ngtcp2_stream_data_blocked){
    .type = NGTCP2_FRAME_STREAM_DATA_BLOCKED,
    .offset = 65535,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_STREAM_STATE, ==, rv);

  ngtcp2_conn_del(conn);

  /* Receive STREAM_DATA_BLOCKED to a remote bidirectional stream
     which is not opened yet. */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.stream_data_blocked = (ngtcp2_stream_data_blocked){
    .type = NGTCP2_FRAME_STREAM_DATA_BLOCKED,
    .offset = 65535,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, 0);

  assert_uint64(65535, ==, strm->rx.last_offset);
  assert_uint64(65535, ==, conn->rx.offset);

  ngtcp2_conn_del(conn);

  /* Receive STREAM_DATA_BLOCKED to a remote stream which exceeds
     bidirectional streams limit */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.stream_data_blocked = (ngtcp2_stream_data_blocked){
    .type = NGTCP2_FRAME_STREAM_DATA_BLOCKED,
    .stream_id = 1,
    .offset = 65535,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_STREAM_LIMIT, ==, rv);

  ngtcp2_conn_del(conn);

  /* Receive STREAM_DATA_BLOCKED which violates stream data limit. */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  fr.stream_data_blocked = (ngtcp2_stream_data_blocked){
    .type = NGTCP2_FRAME_STREAM_DATA_BLOCKED,
    .stream_id = stream_id,
    .offset = 65536,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_FLOW_CONTROL, ==, rv);

  ngtcp2_conn_del(conn);

  /* Receive STREAM_DATA_BLOCKED which violates connection data
     limit. */
  client_default_transport_params(&params);
  params.initial_max_stream_data_bidi_local = 256 * 1024;

  opts = (conn_options){
    .params = &params,
  };

  setup_default_client_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  fr.stream_data_blocked = (ngtcp2_stream_data_blocked){
    .type = NGTCP2_FRAME_STREAM_DATA_BLOCKED,
    .stream_id = stream_id,
    .offset = 128 * 1024 + 1,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_FLOW_CONTROL, ==, rv);

  ngtcp2_conn_del(conn);

  /* Receive RESET_STREAM, and then STREAM_DATA_BLOCKED. */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  fr.reset_stream = (ngtcp2_reset_stream){
    .type = NGTCP2_FRAME_RESET_STREAM,
    .stream_id = stream_id,
    .app_error_code = NGTCP2_NO_ERROR,
    .final_size = 11999,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  assert_uint64(11999, ==, strm->rx.last_offset);
  assert_uint64(11999, ==, conn->rx.offset);

  fr.stream_data_blocked = (ngtcp2_stream_data_blocked){
    .type = NGTCP2_FRAME_STREAM_DATA_BLOCKED,
    .stream_id = stream_id,
    .offset = 11999,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_uint64(11999, ==, strm->rx.last_offset);
  assert_uint64(11999, ==, conn->rx.offset);

  ngtcp2_conn_del(conn);

  /* Receive RESET_STREAM, and then STREAM_DATA_BLOCKED which exceeds
     final size. */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  fr.reset_stream = (ngtcp2_reset_stream){
    .type = NGTCP2_FRAME_RESET_STREAM,
    .stream_id = stream_id,
    .app_error_code = NGTCP2_NO_ERROR,
    .final_size = 11999,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  assert_uint64(11999, ==, strm->rx.last_offset);
  assert_uint64(11999, ==, conn->rx.offset);

  fr.stream_data_blocked = (ngtcp2_stream_data_blocked){
    .type = NGTCP2_FRAME_STREAM_DATA_BLOCKED,
    .stream_id = stream_id,
    .offset = 12000,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_FINAL_SIZE, ==, rv);

  ngtcp2_conn_del(conn);

  /* Send STOP_SENDING, and then receive STREAM_DATA_BLOCKED. */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  rv = ngtcp2_conn_shutdown_stream_read(conn, 0, stream_id, NGTCP2_NO_ERROR);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  assert_true(strm->flags & NGTCP2_STRM_FLAG_STOP_SENDING);

  fr.stream_data_blocked = (ngtcp2_stream_data_blocked){
    .type = NGTCP2_FRAME_STREAM_DATA_BLOCKED,
    .stream_id = stream_id,
    .offset = 7777,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  assert_uint64(7777, ==, strm->rx.last_offset);
  assert_uint64(7777, ==, conn->rx.offset);
  assert_uint64(128 * 1024 + 7777, ==, conn->rx.unsent_max_offset);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = stream_id,
    .offset = 7755,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 23,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_uint64(7778, ==, strm->rx.last_offset);
  assert_uint64(7778, ==, conn->rx.offset);
  assert_uint64(128 * 1024 + 7778, ==, conn->rx.unsent_max_offset);

  ngtcp2_conn_del(conn);

  /* Decreasing STREAM_DATA_BLOCKED offset. */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  fr.stream_data_blocked = (ngtcp2_stream_data_blocked){
    .type = NGTCP2_FRAME_STREAM_DATA_BLOCKED,
    .stream_id = stream_id,
    .offset = 999,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  assert_uint64(999, ==, strm->rx.last_offset);
  assert_uint64(999, ==, conn->rx.offset);
  assert_uint64(128 * 1024, ==, conn->rx.unsent_max_offset);

  fr.stream_data_blocked = (ngtcp2_stream_data_blocked){
    .type = NGTCP2_FRAME_STREAM_DATA_BLOCKED,
    .stream_id = stream_id,
    .offset = 998,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_uint64(999, ==, strm->rx.last_offset);
  assert_uint64(999, ==, conn->rx.offset);
  assert_uint64(128 * 1024, ==, conn->rx.unsent_max_offset);

  ngtcp2_conn_del(conn);

  /* Receive STREAM_DATA_BLOCKED to a local unidirectional stream. */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  ngtcp2_conn_open_uni_stream(conn, &stream_id, NULL);

  fr.stream_data_blocked = (ngtcp2_stream_data_blocked){
    .type = NGTCP2_FRAME_STREAM_DATA_BLOCKED,
    .stream_id = stream_id,
    .offset = 1,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_STREAM_STATE, ==, rv);

  ngtcp2_conn_del(conn);

  /* Receive STREAM_DATA_BLOCKED to a remote unidirectional stream. */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.stream_data_blocked = (ngtcp2_stream_data_blocked){
    .type = NGTCP2_FRAME_STREAM_DATA_BLOCKED,
    .stream_id = 3,
    .offset = 719,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, 3);

  assert_uint64(719, ==, strm->rx.last_offset);
  assert_true(strm->flags & NGTCP2_STRM_FLAG_SHUT_WR);
  assert_uint64(719, ==, conn->rx.offset);

  ngtcp2_conn_del(conn);

  /* Receive STREAM_DATA_BLOCKED which violates unidirectional streams
     limit. */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.stream_data_blocked = (ngtcp2_stream_data_blocked){
    .type = NGTCP2_FRAME_STREAM_DATA_BLOCKED,
    .stream_id = 11,
    .offset = 719,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_STREAM_LIMIT, ==, rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_conn_id_omitted(void) {
  ngtcp2_conn *conn;
  int rv;
  uint8_t buf[2048];
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_tpe tpe;
  ngtcp2_cid scid;
  conn_options opts;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 100,
    .base = null_data,
  };

  /* Receiving packet which has no connection ID while SCID of server
     is not empty. */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);
  ngtcp2_cid_zero(&tpe.dcid);

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

  /* packet is just ignored */
  assert_int(0, ==, rv);
  assert_null(ngtcp2_conn_find_stream(conn, 4));

  ngtcp2_conn_del(conn);

  /* Allow omission of connection ID */
  ngtcp2_cid_zero(&scid);

  opts = (conn_options){
    .scid = &scid,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

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
  conn->pktns.rtb.largest_acked_tx_pkt_num = 0x6AFA2F;
  conn->pktns.tx.last_pkt_num = 0x6AFD78;

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
  conn->pktns.rtb.largest_acked_tx_pkt_num = 0x6AFA2F;
  conn->pktns.tx.last_pkt_num = 0x6BC106;

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
    0, <, pkt_decode_hd_short(&hd, buf, (size_t)spktlen, conn->oscid.datalen));
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
    0, <, pkt_decode_hd_short(&hd, buf, (size_t)spktlen, conn->oscid.datalen));
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
    0, <, pkt_decode_hd_short(&hd, buf, (size_t)spktlen, conn->oscid.datalen));
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
    0, <, pkt_decode_hd_short(&hd, buf, (size_t)spktlen, conn->oscid.datalen));
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
    0, <, pkt_decode_hd_short(&hd, buf, (size_t)spktlen, conn->oscid.datalen));
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
  ngtcp2_tpe tpe;

  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.data_blocked = (ngtcp2_data_blocked){
    .type = NGTCP2_FRAME_DATA_BLOCKED,
    .offset = 128 * 1024,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  ngtcp2_conn_del(conn);

  /* Frame violates flow control limit. */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.data_blocked = (ngtcp2_data_blocked){
    .type = NGTCP2_FRAME_DATA_BLOCKED,
    .offset = 128 * 1024 + 1,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_FLOW_CONTROL, ==, rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_streams_blocked(void) {
  ngtcp2_conn *conn;
  int rv;
  uint8_t buf[1200];
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_tstamp t = 0;
  ngtcp2_tpe tpe;

  /* STREAMS_BLOCKED (bidi) */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.streams_blocked = (ngtcp2_streams_blocked){
    .type = NGTCP2_FRAME_STREAMS_BLOCKED_BIDI,
    .max_streams = conn->remote.bidi.max_streams,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  ngtcp2_conn_del(conn);

  /* STREAMS_BLOCKED (bidi) with invalid max_streams */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.streams_blocked = (ngtcp2_streams_blocked){
    .type = NGTCP2_FRAME_STREAMS_BLOCKED_BIDI,
    .max_streams = conn->remote.bidi.max_streams + 1,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_FRAME_ENCODING, ==, rv);

  ngtcp2_conn_del(conn);

  /* STREAMS_BLOCKED (uni) */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.streams_blocked = (ngtcp2_streams_blocked){
    .type = NGTCP2_FRAME_STREAMS_BLOCKED_UNI,
    .max_streams = conn->remote.uni.max_streams,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  ngtcp2_conn_del(conn);

  /* STREAMS_BLOCKED (uni) with invalid max_streams */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.streams_blocked = (ngtcp2_streams_blocked){
    .type = NGTCP2_FRAME_STREAMS_BLOCKED_UNI,
    .max_streams = conn->remote.uni.max_streams + 1,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_FRAME_ENCODING, ==, rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_new_token(void) {
  ngtcp2_conn *conn;
  int rv;
  uint8_t buf[1200];
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 0;
  ngtcp2_crypto_cc cc;
  ngtcp2_ppe ppe;
  ngtcp2_pkt_hd hd;
  ngtcp2_tpe tpe;
  const uint8_t token[] = "I am token";
  ngtcp2_callbacks callbacks;
  my_user_data ud;
  conn_options opts;

  /* Receive NEW_TOKEN */
  client_default_callbacks(&callbacks);
  callbacks.recv_new_token = recv_new_token;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_client_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.new_token = (ngtcp2_new_token){
    .type = NGTCP2_FRAME_NEW_TOKEN,
    .token = (uint8_t *)token,
    .tokenlen = ngtcp2_strlen_lit(token),
  };

  ud = (my_user_data){0};
  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(ngtcp2_strlen_lit(token), ==, ud.new_token.tokenlen);
  assert_memory_equal(ngtcp2_strlen_lit(token), token, ud.new_token.token);

  ngtcp2_conn_del(conn);

  /* Receiving NEW_TOKEN by server is treated as an error */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.new_token = (ngtcp2_new_token){
    .type = NGTCP2_FRAME_NEW_TOKEN,
    .token = (uint8_t *)token,
    .tokenlen = ngtcp2_strlen_lit(token),
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_PROTO, ==, rv);

  ngtcp2_conn_del(conn);

  /* Empty token is treated as an error */
  setup_default_client(&conn);

  cc = (ngtcp2_crypto_cc){
    .encrypt = null_encrypt,
    .hp_mask = null_hp_mask,
    .ckm = conn->pktns.crypto.rx.ckm,
    .aead.max_overhead = NGTCP2_FAKE_AEAD_OVERHEAD,
  };

  ngtcp2_pkt_hd_init(&hd, 0, NGTCP2_PKT_1RTT, &conn->oscid, NULL, 0, 4,
                     NGTCP2_PROTO_VER_V1);
  ngtcp2_ppe_init(&ppe, buf, sizeof(buf), 0, &cc);
  rv = ngtcp2_ppe_encode_hd(&ppe, &hd);

  assert_int(0, ==, rv);

  *ppe.buf.last++ = NGTCP2_FRAME_NEW_TOKEN;
  *ppe.buf.last++ = 0;

  spktlen = ngtcp2_ppe_final(&ppe, NULL);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, (size_t)spktlen,
                            ++t);

  assert_int(NGTCP2_ERR_FRAME_ENCODING, ==, rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_stateless_reset(void) {
  ngtcp2_conn *conn;
  uint8_t buf[256];
  ngtcp2_ssize spktlen;
  int rv;
  static const ngtcp2_stateless_reset_token token =
    make_stateless_reset_token();
  ngtcp2_callbacks callbacks;
  conn_options opts;

  /* server */
  server_default_callbacks(&callbacks);
  callbacks.decrypt = fail_decrypt;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_default_server_with_options(&conn, opts);
  conn->pktns.acktr.max_pkt_num = 24324325;

  ngtcp2_dcid_set_token(&conn->dcid.current, &token);

  spktlen = ngtcp2_pkt_write_stateless_reset2(
    buf, sizeof(buf), &token, null_data, NGTCP2_MIN_STATELESS_RESET_RANDLEN);

  assert_ptrdiff(0, <, spktlen);

  rv =
    ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, (size_t)spktlen, 1);

  assert_int(NGTCP2_ERR_DRAINING, ==, rv);
  assert_int((int)NGTCP2_CS_DRAINING, ==, (int)conn->state);

  ngtcp2_conn_del(conn);

  /* client */
  client_default_callbacks(&callbacks);
  callbacks.decrypt = fail_decrypt;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_default_client_with_options(&conn, opts);
  conn->pktns.acktr.max_pkt_num = 3255454;

  ngtcp2_dcid_set_token(&conn->dcid.current, &token);

  spktlen =
    ngtcp2_pkt_write_stateless_reset2(buf, sizeof(buf), &token, null_data, 29);

  assert_ptrdiff(0, <, spktlen);

  rv =
    ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, (size_t)spktlen, 1);

  assert_int(NGTCP2_ERR_DRAINING, ==, rv);
  assert_int((int)NGTCP2_CS_DRAINING, ==, (int)conn->state);

  ngtcp2_conn_del(conn);

  /* stateless reset in long packet */
  server_default_callbacks(&callbacks);
  callbacks.decrypt = fail_decrypt;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_default_server_with_options(&conn, opts);
  conn->pktns.acktr.max_pkt_num = 754233;

  ngtcp2_dcid_set_token(&conn->dcid.current, &token);

  spktlen = ngtcp2_pkt_write_stateless_reset2(
    buf, sizeof(buf), &token, null_data, NGTCP2_MIN_STATELESS_RESET_RANDLEN);

  assert_ptrdiff(0, <, spktlen);

  /* long packet */
  buf[0] |= NGTCP2_HEADER_FORM_BIT;

  rv =
    ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, (size_t)spktlen, 1);

  assert_int(NGTCP2_ERR_DRAINING, ==, rv);
  assert_int((int)NGTCP2_CS_DRAINING, ==, (int)conn->state);

  ngtcp2_conn_del(conn);

  /* stateless reset in long packet; parsing long header fails */
  server_default_callbacks(&callbacks);
  callbacks.decrypt = fail_decrypt;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_default_server_with_options(&conn, opts);
  conn->pktns.acktr.max_pkt_num = 754233;

  ngtcp2_dcid_set_token(&conn->dcid.current, &token);

  spktlen = ngtcp2_pkt_write_stateless_reset2(
    buf, 41, &token, null_data, NGTCP2_MIN_STATELESS_RESET_RANDLEN + 1);

  assert_ptrdiff(0, <, spktlen);

  /* long packet */
  buf[0] |= NGTCP2_HEADER_FORM_BIT;
  buf[0] |= 0x30;
  /* Make version nonzero so that it does not look like Version
     Negotiation packet */
  buf[1] = 0xFF;
  /* Make largest CID so that ngtcp2_pkt_decode_hd_long fails */
  buf[5] = 0xFF;

  rv =
    ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, (size_t)spktlen, 1);

  assert_int(NGTCP2_ERR_DRAINING, ==, rv);
  assert_int((int)NGTCP2_CS_DRAINING, ==, (int)conn->state);

  ngtcp2_conn_del(conn);

  /* token does not match */
  client_default_callbacks(&callbacks);
  callbacks.decrypt = fail_decrypt;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_default_client_with_options(&conn, opts);
  conn->pktns.acktr.max_pkt_num = 24324325;

  spktlen =
    ngtcp2_pkt_write_stateless_reset2(buf, sizeof(buf), &token, null_data, 29);

  assert_ptrdiff(0, <, spktlen);

  rv =
    ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, (size_t)spktlen, 1);

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
  int accepted;
  ngtcp2_vec datav;
  ngtcp2_strm *strm;
  ngtcp2_frame_chain *frc;
  ngtcp2_crypto_aead aead = {0};
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_ksl_it it;
  ngtcp2_rtb_entry *ent;
  ngtcp2_transport_params remote_params;
  ngtcp2_callbacks callbacks;
  conn_options opts;

  dcid_init(&dcid);

  client_default_callbacks(&callbacks);
  callbacks.recv_retry = recv_retry;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_handshake_client_with_options(&conn, opts);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  spktlen = ngtcp2_pkt_write_retry(
    buf, sizeof(buf), NGTCP2_PROTO_VER_V1, &conn->oscid, &dcid,
    ngtcp2_conn_get_dcid(conn), token, ngtcp2_strlen_lit(token), null_encrypt,
    &aead, &aead_ctx);

  assert_ptrdiff(0, <, spktlen);

  for (i = 0; i < 2; ++i) {
    rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, (size_t)spktlen,
                              ++t);

    assert_int(0, ==, rv);

    spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

    if (i == 1) {
      /* Retry packet was ignored */
      assert_ptrdiff(0, ==, spktlen);
      assert_uint64(1, ==, conn->cstat.pkt_discarded);
    } else {
      assert_ptrdiff(0, <, spktlen);
      assert_int64(1, ==, conn->in_pktns->tx.last_pkt_num);
      assert_true(ngtcp2_cid_eq(&dcid, ngtcp2_conn_get_dcid(conn)));
      assert_true(conn->flags & NGTCP2_CONN_FLAG_RECV_RETRY);
    }
  }

  ngtcp2_conn_del(conn);

  /* Retry packet with non-matching tag is rejected */
  client_default_callbacks(&callbacks);
  callbacks.recv_retry = recv_retry;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_handshake_client_with_options(&conn, opts);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  spktlen = ngtcp2_pkt_write_retry(
    buf, sizeof(buf), NGTCP2_PROTO_VER_V1, &conn->oscid, &dcid,
    ngtcp2_conn_get_dcid(conn), token, ngtcp2_strlen_lit(token), null_encrypt,
    &aead, &aead_ctx);

  assert_ptrdiff(0, <, spktlen);

  /* Change tag */
  buf[spktlen - 1] = 1;

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, (size_t)spktlen,
                            ++t);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, ==, spktlen);

  ngtcp2_conn_del(conn);

  /* Make sure that 0RTT packets are retransmitted and padded */
  client_early_callbacks(&callbacks);
  callbacks.recv_retry = recv_retry;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_early_client_with_options(&conn, opts);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_writev_stream(
    conn, NULL, NULL, buf, NGTCP2_MAX_UDP_PAYLOAD_SIZE, &datalen,
    NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id, null_datav(&datav, 219), 1, ++t);

  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, ==, spktlen);
  assert_ptrdiff(219, ==, datalen);

  spktlen = ngtcp2_conn_writev_stream(
    conn, NULL, NULL, buf, NGTCP2_MAX_UDP_PAYLOAD_SIZE, &datalen,
    NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id, null_datav(&datav, 119), 1, ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(119, ==, datalen);

  spktlen = ngtcp2_pkt_write_retry(
    buf, sizeof(buf), NGTCP2_PROTO_VER_V1, &conn->oscid, &dcid,
    ngtcp2_conn_get_dcid(conn), token, ngtcp2_strlen_lit(token), null_encrypt,
    &aead, &aead_ctx);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, (size_t)spktlen,
                            ++t);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf,
                                  NGTCP2_MAX_UDP_PAYLOAD_SIZE, ++t);

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

  /* Make sure that multiple 0RTT packets are retransmitted */
  client_early_callbacks(&callbacks);
  callbacks.recv_retry = recv_retry;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_early_client_with_options(&conn, opts);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_writev_stream(
    conn, NULL, NULL, buf, NGTCP2_MAX_UDP_PAYLOAD_SIZE, &datalen,
    NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id, null_datav(&datav, 1200), 1, ++t);

  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, ==, spktlen);
  assert_ptrdiff(846, ==, datalen);

  spktlen = ngtcp2_conn_writev_stream(
    conn, NULL, NULL, buf, NGTCP2_MAX_UDP_PAYLOAD_SIZE, &datalen,
    NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id, null_datav(&datav, 1200), 1, ++t);

  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, ==, spktlen);
  assert_ptrdiff(1130, ==, datalen);

  spktlen = ngtcp2_pkt_write_retry(
    buf, sizeof(buf), NGTCP2_PROTO_VER_V1, &conn->oscid, &dcid,
    ngtcp2_conn_get_dcid(conn), token, ngtcp2_strlen_lit(token), null_encrypt,
    &aead, &aead_ctx);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, (size_t)spktlen,
                            ++t);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf,
                                  NGTCP2_MAX_UDP_PAYLOAD_SIZE, ++t);

  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, ==, spktlen);
  assert_int64(2, ==, conn->pktns.tx.last_pkt_num);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf,
                                  NGTCP2_MAX_UDP_PAYLOAD_SIZE, ++t);

  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, ==, spktlen);
  assert_int64(3, ==, conn->pktns.tx.last_pkt_num);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf,
                                  NGTCP2_MAX_UDP_PAYLOAD_SIZE, ++t);

  assert_ptrdiff(93, ==, spktlen);
  assert_int64(4, ==, conn->pktns.tx.last_pkt_num);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  assert_size(0, ==, ngtcp2_ksl_len(strm->tx.streamfrq));

  ngtcp2_conn_del(conn);

  /* Make sure that empty stream data in 0RTT packets is
     retransmitted */
  client_early_callbacks(&callbacks);
  callbacks.recv_retry = recv_retry;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_early_client_with_options(&conn, opts);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_writev_stream(
    conn, NULL, NULL, buf, NGTCP2_MAX_UDP_PAYLOAD_SIZE, &datalen,
    NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id, NULL, 0, ++t);

  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, ==, spktlen);
  assert_ptrdiff(0, ==, datalen);

  spktlen = ngtcp2_pkt_write_retry(
    buf, sizeof(buf), NGTCP2_PROTO_VER_V1, &conn->oscid, &dcid,
    ngtcp2_conn_get_dcid(conn), token, ngtcp2_strlen_lit(token), null_encrypt,
    &aead, &aead_ctx);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, (size_t)spktlen,
                            ++t);

  assert_int(0, ==, rv);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);

  assert_true(ngtcp2_ksl_it_end(&it));

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf,
                                  NGTCP2_MAX_UDP_PAYLOAD_SIZE, ++t);

  /* Make sure that resent 0RTT packet is padded */
  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, ==, spktlen);
  assert_int64(1, ==, conn->pktns.tx.last_pkt_num);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  assert_size(0, ==, ngtcp2_ksl_len(strm->tx.streamfrq));

  it = ngtcp2_rtb_head(&conn->pktns.rtb);

  assert_false(ngtcp2_ksl_it_end(&it));

  ent = ngtcp2_ksl_it_get(&it);

  assert_uint64(NGTCP2_FRAME_STREAM, ==, ent->frc->fr.hd.type);
  assert_uint64(0, ==, ent->frc->fr.stream.offset);
  assert_uint64(
    0, ==,
    ngtcp2_vec_len(ent->frc->fr.stream.data, ent->frc->fr.stream.datacnt));
  assert_int64(stream_id, ==, ent->frc->fr.stream.stream_id);
  assert_false(ent->frc->fr.stream.fin);

  ngtcp2_conn_del(conn);

  /* Receive Retry packet after resending some packets */
  client_early_remote_transport_params(&remote_params);
  remote_params.max_datagram_frame_size = 65536;

  client_early_callbacks(&callbacks);
  callbacks.recv_retry = recv_retry;
  callbacks.lost_datagram = lost_datagram;

  opts = (conn_options){
    .remote_params = &remote_params,
    .callbacks = &callbacks,
  };

  setup_early_client_with_options(&conn, opts);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf),
                                     &datalen, NGTCP2_WRITE_STREAM_FLAG_NONE,
                                     stream_id, null_data, 100, ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(100, ==, datalen);

  t = ngtcp2_conn_get_expiry(conn);

  rv = ngtcp2_conn_handle_expiry(conn, t);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  /* DATAGRAM frame never be retransmitted. */
  spktlen = ngtcp2_conn_write_datagram(
    conn, NULL, NULL, buf, sizeof(buf), &accepted,
    NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 0, null_data, 56, ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_true(accepted);

  spktlen = ngtcp2_pkt_write_retry(
    buf, sizeof(buf), NGTCP2_PROTO_VER_V1, &conn->oscid, &dcid,
    ngtcp2_conn_get_dcid(conn), token, ngtcp2_strlen_lit(token), null_encrypt,
    &aead, &aead_ctx);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, (size_t)spktlen,
                            ++t);

  assert_int(0, ==, rv);
  assert_null(conn->pktns.tx.frq);
  assert_false(ngtcp2_pq_empty(&conn->tx.strmq));
  assert_false(ngtcp2_strm_streamfrq_empty(&conn->in_pktns->crypto.strm));

  strm = ngtcp2_conn_tx_strmq_top(conn);
  frc = ngtcp2_strm_streamfrq_top(strm);

  assert_uint64(NGTCP2_FRAME_STREAM, ==, frc->fr.hd.type);
  assert_uint64(0, ==, frc->fr.stream.offset);
  assert_uint64(100, ==,
                ngtcp2_vec_len(frc->fr.stream.data, frc->fr.stream.datacnt));
  assert_null(frc->next);

  frc = ngtcp2_strm_streamfrq_top(&conn->in_pktns->crypto.strm);

  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, frc->fr.hd.type);
  assert_uint64(217, ==,
                ngtcp2_vec_len(frc->fr.stream.data, frc->fr.stream.datacnt));
  assert_null(frc->next);

  ngtcp2_conn_del(conn);

  /* client_initial does not produce any CRYPTO data */
  client_early_callbacks(&callbacks);
  callbacks.recv_retry = recv_retry;
  callbacks.client_initial = client_initial_null_early_data;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_early_client_with_options(&conn, opts);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, ==, spktlen);

  t = ngtcp2_conn_get_expiry(conn);

  /* This is idle timeout */
  assert_uint64(60 * NGTCP2_SECONDS, ==, t);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, ==, spktlen);

  ngtcp2_conn_del(conn);

  /* Make sure that 0RTT packets are retransmitted and padded when
     client Initial spans across multiple packets.  */
  client_early_callbacks(&callbacks);
  callbacks.client_initial = client_initial_large_crypto_early_data;
  callbacks.recv_retry = recv_retry;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_early_client_with_options(&conn, opts);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_writev_stream(
    conn, NULL, NULL, buf, NGTCP2_MAX_UDP_PAYLOAD_SIZE, &datalen,
    NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id, null_datav(&datav, 219), 1, ++t);

  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, ==, spktlen);
  assert_ptrdiff(-1, ==, datalen);

  spktlen = ngtcp2_conn_writev_stream(
    conn, NULL, NULL, buf, NGTCP2_MAX_UDP_PAYLOAD_SIZE, &datalen,
    NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id, null_datav(&datav, 219), 1, ++t);

  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, ==, spktlen);
  assert_ptrdiff(219, ==, datalen);

  spktlen = ngtcp2_pkt_write_retry(
    buf, sizeof(buf), NGTCP2_PROTO_VER_V1, &conn->oscid, &dcid,
    ngtcp2_conn_get_dcid(conn), token, ngtcp2_strlen_lit(token), null_encrypt,
    &aead, &aead_ctx);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, (size_t)spktlen,
                            ++t);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf,
                                  NGTCP2_MAX_UDP_PAYLOAD_SIZE, ++t);

  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, ==, spktlen);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf,
                                  NGTCP2_MAX_UDP_PAYLOAD_SIZE, ++t);

  assert_ptrdiff(NGTCP2_MAX_UDP_PAYLOAD_SIZE, ==, spktlen);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf,
                                  NGTCP2_MAX_UDP_PAYLOAD_SIZE, ++t);

  assert_ptrdiff(0, ==, spktlen);
  assert_true(ngtcp2_strm_streamfrq_empty(&conn->in_pktns->crypto.strm));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_delayed_handshake_pkt(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  int rv;
  ngtcp2_tpe tpe;

  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 567,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_handshake(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

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
  ngtcp2_tpe tpe;

  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.max_streams = (ngtcp2_max_streams){
    .type = NGTCP2_FRAME_MAX_STREAMS_UNI,
    .max_streams = 999,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 1);

  assert_int(0, ==, rv);
  assert_uint64(999, ==, conn->local.uni.max_streams);

  fr.max_streams = (ngtcp2_max_streams){
    .type = NGTCP2_FRAME_MAX_STREAMS_BIDI,
    .max_streams = 997,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 2);

  assert_int(0, ==, rv);
  assert_uint64(997, ==, conn->local.bidi.max_streams);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_handshake(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  int64_t pkt_num = 12345689;
  ngtcp2_tstamp t = 0;
  int rv;
  int64_t stream_id;
  ngtcp2_ssize nwrite;
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  ngtcp2_crypto_ctx crypto_ctx;
  ngtcp2_strm *strm;
  ngtcp2_tpe tpe;
  ngtcp2_callbacks callbacks;
  conn_options opts;
  size_t i;

  /* Make sure server Initial is padded */
  setup_handshake_server(&conn);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);
  tpe.initial.last_pkt_num = pkt_num;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1200,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1200, <=, spktlen);

  ngtcp2_conn_del(conn);

  /* Make sure server Handshake is padded when ack-eliciting Initial
     is coalesced. */
  setup_handshake_server(&conn);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);
  tpe.initial.last_pkt_num = pkt_num;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1200,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,
                                 null_data, 91);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1200, <=, spktlen);
  assert_size(1, ==, ngtcp2_ksl_len(&conn->hs_pktns->rtb.ents));

  ngtcp2_conn_del(conn);

  /* Make sure that client packet is padded if it includes Initial and
     0RTT packets */
  client_early_callbacks(&callbacks);
  callbacks.client_initial = client_initial_large_crypto_early_data;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_early_client_with_options(&conn, opts);

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

  assert_ptrdiff(1280, ==, spktlen);
  assert_ptrdiff(10, ==, nwrite);

  /* We have no data to send. */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, 1280, ++t);

  assert_ptrdiff(0, ==, spktlen);

  ngtcp2_conn_del(conn);

  /* Make sure that client non ack-eliciting Initial triggers
     padding. */
  setup_handshake_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.initial.last_pkt_num = pkt_num;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1200, <=, spktlen);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1200,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  init_crypto_ctx(&crypto_ctx);
  ngtcp2_conn_set_crypto_ctx(conn, &crypto_ctx);
  ngtcp2_conn_install_rx_handshake_key(conn, &aead_ctx, null_iv,
                                       sizeof(null_iv), &hp_ctx);
  ngtcp2_conn_install_tx_handshake_key(conn, &aead_ctx, null_iv,
                                       sizeof(null_iv), &hp_ctx);

  tpe.handshake.last_pkt_num = pkt_num;
  tpe.handshake.ckm = conn->hs_pktns->crypto.rx.ckm;

  pktlen = ngtcp2_tpe_write_handshake(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1200, <=, spktlen);

  ngtcp2_conn_del(conn);

  /* Make sure that client Initial is be padded when we do workaround
     for deadlock in CWND limited situation. */
  client_default_callbacks(&callbacks);
  callbacks.recv_crypto_data = recv_crypto_data_client_handshake;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_handshake_client_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.initial.last_pkt_num = pkt_num;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1200, <=, spktlen);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1200,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  tpe.handshake.last_pkt_num = pkt_num;
  tpe.handshake.ckm = conn->hs_pktns->crypto.rx.ckm;

  pktlen = ngtcp2_tpe_write_handshake(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  /* Artificially inflate in-flight.  Make it way higher because we
     will discard initial packet number space which decreases
     bytes_in_flight. */
  conn->cstat.bytes_in_flight = 50000;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1200, ==, spktlen);

  ngtcp2_conn_del(conn);

  /* Make sure that client Initial is be padded when we do workaround
     for deadlock in CWND limited situation.  In this time, we have
     probe packet left in application packet number space. */
  client_default_callbacks(&callbacks);
  callbacks.recv_crypto_data = recv_crypto_data_client_handshake;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_handshake_client_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.initial.last_pkt_num = pkt_num;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1200, <=, spktlen);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1200,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  tpe.handshake.last_pkt_num = pkt_num;
  tpe.handshake.ckm = conn->hs_pktns->crypto.rx.ckm;

  pktlen = ngtcp2_tpe_write_handshake(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  /* Artificially inflate in-flight.  Make it way higher because we
     will discard initial packet number space which decreases
     bytes_in_flight. */
  conn->cstat.bytes_in_flight = 50000;

  conn->pktns.rtb.probe_pkt_left = 1;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1200, ==, spktlen);

  ngtcp2_conn_del(conn);

  /* Make sure padding is done in 1-RTT packet */
  setup_handshake_server(&conn);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);
  tpe.initial.last_pkt_num = pkt_num;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1200,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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

  assert_ptrdiff(1280, ==, spktlen);
  assert_ptrdiff(-1, ==, nwrite);
  assert_size(1, ==, ngtcp2_ksl_len(&conn->pktns.rtb.ents));

  rv = ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL,
                                      null_data, 23);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, 1280, &nwrite,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 10, ++t);

  assert_ptrdiff(1280, ==, spktlen);
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

  assert_ptrdiff(1280, ==, spktlen);
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

  assert_ptrdiff(1280, ==, spktlen);
  assert_size(2, ==, ngtcp2_ksl_len(&conn->pktns.rtb.ents));

  ngtcp2_conn_del(conn);

  /* Received too many 0 length CRYPTO in Handshake packet */
  setup_handshake_server(&conn);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1200,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
  };

  for (i = 0; i < NGTCP2_DEFAULT_GLITCH_RATELIM_BURST; ++i) {
    pktlen = ngtcp2_tpe_write_handshake(&tpe, buf, sizeof(buf), &fr, 1);

    rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

    assert_int(0, ==, rv);
  }

  pktlen = ngtcp2_tpe_write_handshake(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_INTERNAL, ==, rv);

  ngtcp2_conn_del(conn);

  /* Received too many overlapping out-of-order CRYPTO in Handshake
     packet */
  setup_handshake_server(&conn);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1200,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .offset = 100,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .base = null_data,
    .len = 397,
  };

  /* The first CRYPTO does not consume glitch tokens. */
  for (i = 0; i < NGTCP2_DEFAULT_GLITCH_RATELIM_BURST + 1; ++i) {
    pktlen = ngtcp2_tpe_write_handshake(&tpe, buf, sizeof(buf), &fr, 1);

    rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

    assert_int(0, ==, rv);
  }

  pktlen = ngtcp2_tpe_write_handshake(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_INTERNAL, ==, rv);

  ngtcp2_conn_del(conn);

  /* Received too many overlapping in-order CRYPTO in Handshake
     packet */
  setup_handshake_server(&conn);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1200,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .base = null_data,
    .len = 651,
  };

  /* The first CRYPTO does not consume glitch tokens. */
  for (i = 0; i < NGTCP2_DEFAULT_GLITCH_RATELIM_BURST + 1; ++i) {
    pktlen = ngtcp2_tpe_write_handshake(&tpe, buf, sizeof(buf), &fr, 1);

    rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

    assert_int(0, ==, rv);
  }

  pktlen = ngtcp2_tpe_write_handshake(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_INTERNAL, ==, rv);

  ngtcp2_conn_del(conn);

  /* Receive HANDSHAKE_DONE */
  client_default_callbacks(&callbacks);
  callbacks.recv_crypto_data = recv_crypto_data_client_handshake;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_handshake_client_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1200, <=, spktlen);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1200,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  tpe.handshake.ckm = conn->hs_pktns->crypto.rx.ckm;

  pktlen = ngtcp2_tpe_write_handshake(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  ngtcp2_conn_tls_handshake_completed(conn);
  tpe.app.ckm = conn->pktns.crypto.rx.ckm;

  fr.handshake_done = (ngtcp2_handshake_done){
    .type = NGTCP2_FRAME_HANDSHAKE_DONE,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_true(conn->flags & NGTCP2_CONN_FLAG_HANDSHAKE_CONFIRMED);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_handshake_error(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  int64_t pkt_num = 107;
  ngtcp2_tstamp t = 0;
  int rv;
  ngtcp2_tpe tpe;
  ngtcp2_callbacks callbacks;
  conn_options opts;

  /* client side */
  client_default_callbacks(&callbacks);
  callbacks.recv_crypto_data = recv_crypto_handshake_error;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_handshake_client_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.initial.last_pkt_num = pkt_num;
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 333,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_CRYPTO, ==, rv);

  ngtcp2_conn_del(conn);

  /* server side */
  server_default_callbacks(&callbacks);
  callbacks.recv_crypto_data = recv_crypto_handshake_error;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_handshake_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);
  tpe.initial.last_pkt_num = pkt_num;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1200,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_CRYPTO, ==, rv);

  ngtcp2_conn_del(conn);

  /* server side; wrong version */
  server_default_callbacks(&callbacks);
  callbacks.recv_crypto_data = recv_crypto_handshake_error;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_handshake_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);
  tpe.version = 0xFFFF;
  tpe.initial.last_pkt_num = pkt_num;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1201,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_DROP_CONN, ==, rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_retransmit_protected(void) {
  ngtcp2_conn *conn;
  uint8_t buf[1200];
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 0;
  int64_t stream_id, stream_id_a, stream_id_b;
  ngtcp2_ksl_it it;
  ngtcp2_ack_range ack_ranges[NGTCP2_MAX_ACK_RANGES];
  ngtcp2_frame fr;
  ngtcp2_frame frs[2];
  size_t pktlen;
  ngtcp2_vec datav;
  int accepted;
  int rv;
  ngtcp2_strm *strm;
  ngtcp2_rtb_entry *ent;
  ngtcp2_frame_chain *frc;
  ngtcp2_tpe tpe;
  ngtcp2_transport_params remote_params;
  ngtcp2_callbacks callbacks;
  conn_options opts;
  size_t i;
  ngtcp2_ssize datalen;

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
  client_default_remote_transport_params(&remote_params);
  remote_params.initial_max_streams_bidi = 3;

  opts = (conn_options){
    .remote_params = &remote_params,
  };

  setup_default_client_with_options(&conn, opts);

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
  client_default_remote_transport_params(&remote_params);
  remote_params.max_datagram_frame_size = 65535;

  client_default_callbacks(&callbacks);
  callbacks.ack_datagram = ack_datagram;

  opts = (conn_options){
    .remote_params = &remote_params,
  };

  setup_default_client_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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
  ngtcp2_tpe_init_conn(&tpe, conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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

  assert_uint64(NGTCP2_FRAME_STREAM, ==, frc->fr.hd.type);
  assert_uint64(0, ==, frc->fr.stream.offset);
  assert_size(0, ==, frc->fr.stream.datacnt);

  ngtcp2_conn_del(conn);

  /* Do not retransmit an empty STREAM frame if we have written
     non-zero data on that stream. */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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

  assert_uint64(NGTCP2_FRAME_STREAM, ==, frc->fr.hd.type);
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
  ngtcp2_tpe_init_conn(&tpe, conn);

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

  frs[0].stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .fin = 1,
    .stream_id = stream_id,
  };
  frs[1].ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 2);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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

  assert_uint64(NGTCP2_FRAME_RESET_STREAM, ==, ent->frc->fr.hd.type);
  assert_int64(1, ==, ent->hd.pkt_num);
  assert_null(ent->frc->next);

  ngtcp2_ksl_it_next(&it);

  assert_true(ngtcp2_ksl_it_end(&it));

  ngtcp2_conn_del(conn);

  /* Do not retransmit STOP_SENDING frame if stream is gone. */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

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

  frs[0].stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .fin = 1,
    .stream_id = stream_id,
  };
  frs[1].ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 2);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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

  assert_uint64(NGTCP2_FRAME_STOP_SENDING, ==, ent->frc->fr.hd.type);
  assert_int64(1, ==, ent->hd.pkt_num);
  assert_null(ent->frc->next);

  ngtcp2_ksl_it_next(&it);

  assert_true(ngtcp2_ksl_it_end(&it));

  ngtcp2_conn_del(conn);

  /* Retransmit 0 length STREAM frames; one without fin and one with
     it */
  client_default_remote_transport_params(&remote_params);
  remote_params.initial_max_streams_bidi = 2;

  opts = (conn_options){
    .remote_params = &remote_params,
  };

  setup_default_client_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id_a, NULL);

  spktlen =
    ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                             NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, ++t);
  assert_ptrdiff(0, <, spktlen);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  t += 30 * NGTCP2_MILLISECONDS;
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id_a,
                                     NULL, 0, ++t);

  assert_ptrdiff(0, <, spktlen);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_FIN, stream_id_a,
                                     NULL, 0, ++t);

  assert_ptrdiff(0, <, spktlen);

  t += 30 * NGTCP2_MILLISECONDS;
  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id_b, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id_b,
                                     NULL, 0, t);

  assert_ptrdiff(0, <, spktlen);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  t += 30 * NGTCP2_MILLISECONDS;
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id_a);

  assert_true(!ngtcp2_strm_streamfrq_empty(strm));

  ngtcp2_conn_del(conn);

  /* New STREAM frame cannot be sent if there are STREAM frames that
     need retransmission to avoid overlapping 0 length frame edge
     case. */
  client_default_remote_transport_params(&remote_params);
  remote_params.initial_max_streams_bidi = 16384;

  opts = (conn_options){
    .remote_params = &remote_params,
  };

  setup_default_client_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  for (i = 0; i < (1 << 14); ++i) {
    rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

    assert_int(0, ==, rv);
  }

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, 0,
                                     null_data, 1157, t);

  assert_ptrdiff(0, <, spktlen);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 44, t);

  assert_ptrdiff(0, <, spktlen);

  spktlen =
    ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                             NGTCP2_WRITE_STREAM_FLAG_NONE, 4, NULL, 0, t);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_1RTT,
                                      null_data, 9);

  assert_int(0, ==, rv);

  t += 4 * NGTCP2_MILLISECONDS;
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t);

  assert_ptrdiff(0, <, spktlen);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
    .rangecnt = 1,
    .ranges = ack_ranges,
  };
  ack_ranges[0] = (ngtcp2_ack_range){
    .gap = 2,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  t += 30 * NGTCP2_MILLISECONDS;
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_tx_strmq_top(conn);

  assert_int64(0, ==, strm->stream_id);

  strm = ngtcp2_conn_find_stream(conn, 4);

  ngtcp2_pq_remove(&conn->tx.strmq, &strm->pe);
  ++strm->cycle;
  ngtcp2_conn_tx_strmq_push(conn, strm);

  spktlen =
    ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), &datalen,
                             NGTCP2_WRITE_STREAM_FLAG_FIN, 4, NULL, 0, t);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(-1, ==, datalen);

  strm = ngtcp2_conn_tx_strmq_top(conn);

  assert_int64(stream_id, ==, strm->stream_id);

  ngtcp2_conn_del(conn);

  /* Handling skipped packet lost */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  conn->pktns.tx.skip_pkt.next_pkt_num = 0;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_int64(1, ==, conn->pktns.tx.last_pkt_num);

  t += 30 * NGTCP2_MILLISECONDS;

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  assert_int(0, ==, rv);

  t = ngtcp2_conn_get_expiry(conn);
  rv = ngtcp2_conn_handle_expiry(conn, t);

  assert_int(0, ==, rv);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);
  ent = ngtcp2_ksl_it_get(&it);

  assert_int64(0, ==, ent->hd.pkt_num);
  assert_true(ent->flags & NGTCP2_RTB_ENTRY_FLAG_SKIP);
  assert_true(ent->flags & NGTCP2_RTB_ENTRY_FLAG_LOST_RETRANSMITTED);
  assert_size(1, ==, conn->pktns.rtb.num_lost_pkts);
  assert_size(1, ==, conn->pktns.rtb.num_lost_ignore_pkts);

  t = ngtcp2_conn_get_expiry(conn);
  rv = ngtcp2_conn_handle_expiry(conn, t);

  assert_int(0, ==, rv);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);

  assert_true(ngtcp2_ksl_it_end(&it));
  assert_size(0, ==, conn->pktns.rtb.num_lost_pkts);
  assert_size(0, ==, conn->pktns.rtb.num_lost_ignore_pkts);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_cancel_retransmission(void) {
  ngtcp2_conn *conn;
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 0;
  ngtcp2_tpe tpe;
  ngtcp2_vec datav;
  ngtcp2_ack_range ack_ranges[NGTCP2_MAX_ACK_RANGES];
  ngtcp2_frame fr[2];
  ngtcp2_frame_chain *frc;
  ngtcp2_frame_chain_binder *binder;
  ngtcp2_transport_params params;
  ngtcp2_rtb_entry *ent;
  ngtcp2_ksl_it it;
  ngtcp2_strm *strm;
  ngtcp2_transport_params remote_params;
  conn_options opts;
  uint8_t buf[2048];
  int64_t stream_id;
  size_t pktlen;
  int rv;

  /* Stop retransmission because the original packet is acknowledged
     via ngtcp2_frame_chain_bider. */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  t += 4 * NGTCP2_MILLISECONDS;
  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     NULL, 0, t);
  assert_ptrdiff(0, <, spktlen);

  fr[0].ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), fr, 1);

  t += 30 * NGTCP2_MILLISECONDS;
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  assert_int(0, ==, rv);
  assert_not_null(conn->pktns.tx.frq);

  binder = conn->pktns.tx.frq->binder;

  assert_not_null(binder);
  assert_size(2, ==, binder->refcount);
  assert_uint32(NGTCP2_FRAME_CHAIN_BINDER_FLAG_NONE, ==, binder->flags);

  fr[0].ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
    .first_ack_range = 1,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  assert_int(0, ==, rv);
  assert_not_null(conn->pktns.tx.frq);

  binder = conn->pktns.tx.frq->binder;

  assert_not_null(binder);
  assert_size(1, ==, binder->refcount);
  assert_uint32(NGTCP2_FRAME_CHAIN_BINDER_FLAG_ACK, ==, binder->flags);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t);

  assert_ptrdiff(0, ==, spktlen);

  ngtcp2_conn_del(conn);

  /* Cancel retransmission of frames because they are now stale */
  client_default_transport_params(&params);
  params.initial_max_stream_data_bidi_local = 100;
  params.initial_max_data = 100;

  client_default_remote_transport_params(&remote_params);
  remote_params.initial_max_streams_bidi = 2;

  opts = (conn_options){
    .params = &params,
    .remote_params = &remote_params,
  };

  setup_default_client_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);
  t = 0;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_shutdown_stream_read(conn, 0, stream_id, NGTCP2_APP_ERR01);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_shutdown_stream_write(conn, 0, stream_id, NGTCP2_APP_ERR01);

  assert_int(0, ==, rv);

  ngtcp2_conn_extend_max_streams_bidi(conn, 100);
  ngtcp2_conn_extend_max_streams_uni(conn, 111);

  fr[0].stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = stream_id,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .base = null_data,
    .len = 100,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_extend_max_stream_offset(conn, stream_id, 100);

  assert_int(0, ==, rv);

  ngtcp2_conn_extend_max_offset(conn, 100);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);
  ent = ngtcp2_ksl_it_get(&it);
  frc = ent->frc;

  assert_uint64(NGTCP2_FRAME_MAX_DATA, ==, frc->fr.hd.type);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_STOP_SENDING, ==, frc->fr.hd.type);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_RESET_STREAM, ==, frc->fr.hd.type);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_MAX_STREAM_DATA, ==, frc->fr.hd.type);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_MAX_STREAMS_BIDI, ==, frc->fr.hd.type);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_MAX_STREAMS_UNI, ==, frc->fr.hd.type);
  assert_null(frc->next);

  t += 4 * NGTCP2_MILLISECONDS;
  spktlen =
    ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                             NGTCP2_WRITE_STREAM_FLAG_NONE, 0, NULL, 0, t);

  assert_ptrdiff(0, <, spktlen);
  assert_null(conn->pktns.tx.frq);

  fr[0].ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
    .rangecnt = 1,
    .ranges = ack_ranges,
  };
  ack_ranges[0] = (ngtcp2_ack_range){0};

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), fr, 1);

  t += 30 * NGTCP2_MILLISECONDS;
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  assert_int(0, ==, rv);
  assert_not_null(conn->pktns.tx.frq);

  frc = conn->pktns.tx.frq;

  assert_uint64(NGTCP2_FRAME_MAX_DATA, ==, frc->fr.hd.type);
  assert_uint64(200, ==, frc->fr.max_data.max_data);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_STOP_SENDING, ==, frc->fr.hd.type);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_RESET_STREAM, ==, frc->fr.hd.type);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_MAX_STREAM_DATA, ==, frc->fr.hd.type);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_MAX_STREAMS_BIDI, ==, frc->fr.hd.type);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_MAX_STREAMS_UNI, ==, frc->fr.hd.type);
  assert_null(frc->next);

  /* Retransmit frames once */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t);

  assert_ptrdiff(0, <, spktlen);
  assert_null(conn->pktns.tx.frq);

  t += 4 * NGTCP2_MILLISECONDS;
  spktlen =
    ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                             NGTCP2_WRITE_STREAM_FLAG_NONE, 0, null_data, 1, t);
  assert_ptrdiff(0, <, spktlen);
  assert_null(conn->pktns.tx.frq);

  fr[0].ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), fr, 1);

  t += 30 * NGTCP2_MILLISECONDS;
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  assert_int(0, ==, rv);
  assert_not_null(conn->pktns.tx.frq);

  frc = conn->pktns.tx.frq;

  assert_uint64(NGTCP2_FRAME_MAX_DATA, ==, frc->fr.hd.type);
  assert_uint64(200, ==, frc->fr.max_data.max_data);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_STOP_SENDING, ==, frc->fr.hd.type);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_RESET_STREAM, ==, frc->fr.hd.type);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_MAX_STREAM_DATA, ==, frc->fr.hd.type);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_MAX_STREAMS_BIDI, ==, frc->fr.hd.type);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_MAX_STREAMS_UNI, ==, frc->fr.hd.type);
  assert_null(frc->next);

  /* Adjust variables so that frames are not retransmitted */
  strm = ngtcp2_conn_find_stream(conn, 0);
  strm->flags |= NGTCP2_STRM_FLAG_SHUT_RD;

  strm = ngtcp2_conn_find_stream(conn, stream_id);
  strm->flags |= NGTCP2_STRM_FLAG_FIN_ACKED | NGTCP2_STRM_FLAG_SHUT_RD;

  conn->remote.bidi.max_streams += 100;
  conn->remote.uni.max_streams += 100;

  ngtcp2_conn_extend_max_offset(conn, 100);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);
  ent = ngtcp2_ksl_it_get(&it);
  frc = ent->frc;

  assert_uint64(NGTCP2_FRAME_MAX_DATA, ==, frc->fr.hd.type);
  assert_uint64(300, ==, frc->fr.max_data.max_data);

  frc = frc->next;

  assert_null(frc);

  ngtcp2_conn_del(conn);

  /* Cancel retransmission for STREAM_DATA_BLOCKED and DATA_BLOCKED
     frames */
  client_default_remote_transport_params(&remote_params);
  remote_params.initial_max_stream_data_bidi_remote = 100;
  remote_params.initial_max_data = 100;

  opts = (conn_options){
    .remote_params = &remote_params,
  };

  setup_default_client_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);
  t = 0;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 100, t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);
  ent = ngtcp2_ksl_it_get(&it);
  frc = ent->frc;

  assert_uint64(NGTCP2_FRAME_STREAM, ==, frc->fr.hd.type);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_DATA_BLOCKED, ==, frc->fr.hd.type);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_STREAM_DATA_BLOCKED, ==, frc->fr.hd.type);
  assert_null(frc->next);

  rv = ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_1RTT,
                                      (const uint8_t *)"foo", 3);

  assert_int(0, ==, rv);

  t += 4 * NGTCP2_MILLISECONDS;
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t);

  assert_ptrdiff(0, <, spktlen);
  assert_null(conn->pktns.tx.frq);

  fr[0].ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
    .rangecnt = 1,
    .ranges = ack_ranges,
  };
  ack_ranges[0] = (ngtcp2_ack_range){0};

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), fr, 1);

  t += 30 * NGTCP2_MILLISECONDS;
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  assert_int(0, ==, rv);
  assert_not_null(conn->pktns.tx.frq);

  frc = conn->pktns.tx.frq;

  assert_uint64(NGTCP2_FRAME_DATA_BLOCKED, ==, frc->fr.hd.type);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_STREAM_DATA_BLOCKED, ==, frc->fr.hd.type);
  assert_null(frc->next);

  /* Retransmit frames once */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t);

  assert_ptrdiff(0, <, spktlen);
  assert_null(conn->pktns.tx.frq);

  rv = ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_1RTT,
                                      (const uint8_t *)"bar", 3);

  assert_int(0, ==, rv);

  t += 4 * NGTCP2_MILLISECONDS;
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t);

  assert_ptrdiff(0, <, spktlen);
  assert_null(conn->pktns.tx.frq);

  fr[0].ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), fr, 1);

  t += 30 * NGTCP2_MILLISECONDS;
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  assert_int(0, ==, rv);
  assert_not_null(conn->pktns.tx.frq);

  frc = conn->pktns.tx.frq;

  assert_uint64(NGTCP2_FRAME_DATA_BLOCKED, ==, frc->fr.hd.type);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_STREAM_DATA_BLOCKED, ==, frc->fr.hd.type);
  assert_null(frc->next);

  fr[0].max_stream_data = (ngtcp2_max_stream_data){
    .type = NGTCP2_FRAME_MAX_STREAM_DATA,
    .stream_id = stream_id,
    .max_stream_data = 200,
  };
  fr[1].max_data = (ngtcp2_max_data){
    .type = NGTCP2_FRAME_MAX_DATA,
    .max_data = 200,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), fr, 2);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  assert_int(0, ==, rv);
  assert_not_null(conn->pktns.tx.frq);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t);

  assert_ptrdiff(0, <, spktlen);
  assert_null(conn->pktns.tx.frq);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);
  ent = ngtcp2_ksl_it_get(&it);
  frc = ent->frc;

  assert_uint64(NGTCP2_FRAME_STREAM, ==, frc->fr.hd.type);
  assert_null(frc->next);

  ngtcp2_conn_del(conn);

  /* Retransmission of CRYPTO frame is cancelled because the original
     packet is acknowledged. */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_1RTT,
                                      null_data, 171);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);
  ent = ngtcp2_ksl_it_get(&it);
  frc = ent->frc;

  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, frc->fr.hd.type);
  assert_null(frc->next);

  rv = ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_1RTT,
                                      null_data, 7);

  assert_int(0, ==, rv);

  t += 4 * NGTCP2_MILLISECONDS;
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t);

  assert_ptrdiff(0, <, spktlen);
  assert_true(ngtcp2_strm_streamfrq_empty(&conn->pktns.crypto.strm));

  fr[0].ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
    .rangecnt = 1,
    .ranges = ack_ranges,
  };
  ack_ranges[0] = (ngtcp2_ack_range){0};

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), fr, 1);

  t += 30 * NGTCP2_MILLISECONDS;
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  assert_int(0, ==, rv);
  assert_false(ngtcp2_strm_streamfrq_empty(&conn->pktns.crypto.strm));

  /* Retransmit frames once */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t);

  assert_ptrdiff(0, <, spktlen);
  assert_true(ngtcp2_strm_streamfrq_empty(&conn->pktns.crypto.strm));

  rv = ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_1RTT,
                                      null_data, 9);

  assert_int(0, ==, rv);

  t += 4 * NGTCP2_MILLISECONDS;
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t);

  assert_ptrdiff(0, <, spktlen);
  assert_true(ngtcp2_strm_streamfrq_empty(&conn->pktns.crypto.strm));

  fr[0].ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), fr, 1);

  t += 30 * NGTCP2_MILLISECONDS;
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  assert_int(0, ==, rv);
  assert_false(ngtcp2_strm_streamfrq_empty(&conn->pktns.crypto.strm));

  fr[0].ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
    .rangecnt = 1,
    .ranges = ack_ranges,
  };
  ack_ranges[0] = (ngtcp2_ack_range){
    .gap = 1,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t);

  assert_ptrdiff(0, ==, spktlen);
  assert_true(ngtcp2_strm_streamfrq_empty(&conn->pktns.crypto.strm));

  ngtcp2_conn_del(conn);

  /* During handshake, retransmission of CRYPTO frame is cancelled
     because the original packet is acknowledged. */
  setup_handshake_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  rv = ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL,
                                      null_data, 171);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_rtb_head(&conn->in_pktns->rtb);
  ent = ngtcp2_ksl_it_get(&it);
  frc = ent->frc;

  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, frc->fr.hd.type);
  assert_null(frc->next);

  rv = ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL,
                                      null_data, 7);

  assert_int(0, ==, rv);

  t += 4 * NGTCP2_MILLISECONDS;
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t);

  assert_ptrdiff(0, <, spktlen);
  assert_true(ngtcp2_strm_streamfrq_empty(&conn->in_pktns->crypto.strm));

  fr[0].ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->in_pktns->tx.last_pkt_num,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), fr, 1);

  t += 30 * NGTCP2_MILLISECONDS;
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  assert_int(0, ==, rv);
  assert_false(ngtcp2_strm_streamfrq_empty(&conn->in_pktns->crypto.strm));

  /* Retransmit frames once */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t);

  assert_ptrdiff(0, <, spktlen);
  assert_true(ngtcp2_strm_streamfrq_empty(&conn->in_pktns->crypto.strm));

  rv = ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL,
                                      null_data, 9);

  assert_int(0, ==, rv);

  t += 4 * NGTCP2_MILLISECONDS;
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t);

  assert_ptrdiff(0, <, spktlen);
  assert_true(ngtcp2_strm_streamfrq_empty(&conn->in_pktns->crypto.strm));

  fr[0].ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->in_pktns->tx.last_pkt_num,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), fr, 1);

  t += 30 * NGTCP2_MILLISECONDS;
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  assert_int(0, ==, rv);
  assert_false(ngtcp2_strm_streamfrq_empty(&conn->in_pktns->crypto.strm));

  fr[0].ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->in_pktns->tx.last_pkt_num,
    .rangecnt = 1,
    .ranges = ack_ranges,
  };
  ack_ranges[0] = (ngtcp2_ack_range){
    .gap = 1,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t);

  assert_ptrdiff(0, ==, spktlen);
  assert_true(ngtcp2_strm_streamfrq_empty(&conn->in_pktns->crypto.strm));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_send_max_stream_data(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_strm *strm;
  int64_t pkt_num = 890;
  ngtcp2_tstamp t = 0;
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  int rv;
  const uint32_t datalen = 1024;
  uint64_t max_stream_data;
  ngtcp2_ssize spktlen;
  ngtcp2_tpe tpe;
  ngtcp2_transport_params params;
  conn_options opts;

  /* MAX_STREAM_DATA should be sent */
  server_default_transport_params(&params);
  params.initial_max_stream_data_bidi_remote = datalen;

  opts = (conn_options){
    .params = &params,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.app.last_pkt_num = pkt_num;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = datalen,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_extend_max_stream_offset(conn, 4, datalen);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, 4);

  assert_true(ngtcp2_strm_is_tx_queued(strm));

  ngtcp2_conn_del(conn);

  /* MAX_STREAM_DATA should not be sent on incoming fin */
  server_default_transport_params(&params);
  params.initial_max_stream_data_bidi_remote = datalen;

  opts = (conn_options){
    .params = &params,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.app.last_pkt_num = pkt_num;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .fin = 1,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = datalen,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_extend_max_stream_offset(conn, 4, datalen);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, 4);

  assert_false(ngtcp2_strm_is_tx_queued(strm));

  ngtcp2_conn_del(conn);

  /* MAX_STREAM_DATA should not be sent if STOP_SENDING frame is being
     sent by local endpoint */
  server_default_transport_params(&params);
  params.initial_max_stream_data_bidi_remote = datalen;

  opts = (conn_options){
    .params = &params,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.app.last_pkt_num = pkt_num;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = datalen,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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
  server_default_transport_params(&params);
  params.initial_max_stream_data_bidi_remote = datalen;

  opts = (conn_options){
    .params = &params,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.app.last_pkt_num = pkt_num;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = datalen,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  fr.reset_stream = (ngtcp2_reset_stream){
    .type = NGTCP2_FRAME_RESET_STREAM,
    .stream_id = 4,
    .app_error_code = NGTCP2_APP_ERR01,
    .final_size = datalen,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  ngtcp2_frame frs[2];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  int rv;
  int64_t stream_id;
  size_t i;
  ngtcp2_tpe tpe;
  ngtcp2_transport_params params, remote_params;
  ngtcp2_callbacks callbacks;
  conn_options opts;

  /* 2 STREAM frames are received in the correct order. */
  server_default_callbacks(&callbacks);
  callbacks.recv_stream_data = recv_stream_data;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.app.last_pkt_num = pkt_num;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 111,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(4, ==, ud.stream_data.stream_id);
  assert_false(ud.stream_data.flags & NGTCP2_STREAM_DATA_FLAG_FIN);
  assert_false(ud.stream_data.flags & NGTCP2_STREAM_DATA_FLAG_0RTT);
  assert_size(111, ==, ud.stream_data.datalen);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .fin = 1,
    .offset = 111,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 99,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(4, ==, ud.stream_data.stream_id);
  assert_true(ud.stream_data.flags & NGTCP2_STREAM_DATA_FLAG_FIN);
  assert_size(99, ==, ud.stream_data.datalen);

  ngtcp2_conn_del(conn);

  /* 2 STREAM frames are received in the correct order, and 2nd STREAM
     frame has 0 length, and FIN bit set. */
  server_default_callbacks(&callbacks);
  callbacks.recv_stream_data = recv_stream_data;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.app.last_pkt_num = pkt_num;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 111,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(4, ==, ud.stream_data.stream_id);
  assert_false(ud.stream_data.flags & NGTCP2_STREAM_DATA_FLAG_FIN);
  assert_size(111, ==, ud.stream_data.datalen);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .fin = 1,
    .offset = 111,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(4, ==, ud.stream_data.stream_id);
  assert_true(ud.stream_data.flags & NGTCP2_STREAM_DATA_FLAG_FIN);
  assert_size(0, ==, ud.stream_data.datalen);

  ngtcp2_conn_del(conn);

  /* 2 identical STREAM frames with FIN bit set are received.  The
     recv_stream_data callback should not be called for second STREAM
     frame. */
  server_default_callbacks(&callbacks);
  callbacks.recv_stream_data = recv_stream_data;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.app.last_pkt_num = pkt_num;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .fin = 1,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 111,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(4, ==, ud.stream_data.stream_id);
  assert_true(ud.stream_data.flags & NGTCP2_STREAM_DATA_FLAG_FIN);
  assert_size(111, ==, ud.stream_data.datalen);

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(0, ==, ud.stream_data.stream_id);
  assert_false(ud.stream_data.flags & NGTCP2_STREAM_DATA_FLAG_FIN);
  assert_size(0, ==, ud.stream_data.datalen);

  ngtcp2_conn_del(conn);

  /* Re-ordered STREAM frame; we first gets 0 length STREAM frame with
     FIN bit set. Then the remaining STREAM frame is received. */
  server_default_callbacks(&callbacks);
  callbacks.recv_stream_data = recv_stream_data;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.app.last_pkt_num = pkt_num;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .fin = 1,
    .offset = 599,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(0, ==, ud.stream_data.stream_id);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 599,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(4, ==, ud.stream_data.stream_id);
  assert_true(ud.stream_data.flags & NGTCP2_STREAM_DATA_FLAG_FIN);
  assert_size(599, ==, ud.stream_data.datalen);

  ngtcp2_conn_del(conn);

  /* Simulate the case where packet is lost.  We first gets 0 length
     STREAM frame with FIN bit set.  Then the lost STREAM frame is
     retransmitted with FIN bit set is received. */
  server_default_callbacks(&callbacks);
  callbacks.recv_stream_data = recv_stream_data;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.app.last_pkt_num = pkt_num;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .fin = 1,
    .offset = 599,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(0, ==, ud.stream_data.stream_id);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .fin = 1,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 599,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(4, ==, ud.stream_data.stream_id);
  assert_true(ud.stream_data.flags & NGTCP2_STREAM_DATA_FLAG_FIN);
  assert_size(599, ==, ud.stream_data.datalen);

  ngtcp2_conn_del(conn);

  /* Receive an unidirectional stream data */
  client_default_callbacks(&callbacks);
  callbacks.recv_stream_data = recv_stream_data;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_client_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.app.last_pkt_num = pkt_num;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 3,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 911,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(3, ==, ud.stream_data.stream_id);
  assert_false(ud.stream_data.flags & NGTCP2_STREAM_DATA_FLAG_FIN);
  assert_size(911, ==, ud.stream_data.datalen);

  ngtcp2_conn_del(conn);

  /* Receive an unidirectional stream which is beyond the limit. */
  server_default_transport_params(&params);
  params.initial_max_streams_uni = 0;

  server_default_callbacks(&callbacks);
  callbacks.recv_stream_data = recv_stream_data;

  opts = (conn_options){
    .params = &params,
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.app.last_pkt_num = pkt_num;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 2,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 911,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_STREAM_LIMIT, ==, rv);

  ngtcp2_conn_del(conn);

  /* Receiving nonzero payload for an local unidirectional stream is a
     protocol violation. */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.app.last_pkt_num = pkt_num;

  rv = ngtcp2_conn_open_uni_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = stream_id,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 9,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_STREAM_STATE, ==, rv);

  ngtcp2_conn_del(conn);

  /* DATA on crypto stream, and TLS alert is generated. */
  server_default_callbacks(&callbacks);
  callbacks.recv_crypto_data = recv_crypto_fatal_alert_generated;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.app.last_pkt_num = pkt_num;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 139,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_CRYPTO, ==, rv);

  ngtcp2_conn_del(conn);

  /* 0 length STREAM frame is allowed */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.app.last_pkt_num = pkt_num;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_not_null(ngtcp2_conn_find_stream(conn, 4));

  ngtcp2_conn_del(conn);

  /* After sending STOP_SENDING, receiving 2 STREAM frames with fin
     bit set must not invoke recv_stream_data callback. */
  server_default_callbacks(&callbacks);
  callbacks.recv_stream_data = recv_stream_data;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.app.last_pkt_num = pkt_num;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_not_null(ngtcp2_conn_find_stream(conn, 4));

  rv = ngtcp2_conn_shutdown_stream_read(conn, 0, 4, 99);

  assert_int(0, ==, rv);

  for (i = 0; i < 2; ++i) {
    fr.stream = (ngtcp2_stream){
      .type = NGTCP2_FRAME_STREAM,
      .stream_id = 4,
      .fin = 1,
      .datacnt = 1,
      .data = &datav,
    };
    datav = (ngtcp2_vec){
      .base = null_data,
      .len = 19,
    };

    pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

    ud.stream_data.stream_id = 0;
    rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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
  server_default_callbacks(&callbacks);
  callbacks.recv_stream_data = recv_stream_data;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.app.last_pkt_num = pkt_num;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_not_null(ngtcp2_conn_find_stream(conn, 0));

  fr.reset_stream = (ngtcp2_reset_stream){
    .type = NGTCP2_FRAME_RESET_STREAM,
    .app_error_code = 999,
    .final_size = 199,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_not_null(ngtcp2_conn_find_stream(conn, 0));
  assert_uint64(199, ==,
                conn->rx.unsent_max_offset -
                  conn->local.transport_params.initial_max_data);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .base = null_data,
    .len = 198,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  ud.stream_data.stream_id = -1;
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(-1, ==, ud.stream_data.stream_id);
  assert_uint64(199, ==,
                conn->rx.unsent_max_offset -
                  conn->local.transport_params.initial_max_data);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .fin = 1,
    .offset = 198,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .base = null_data,
    .len = 1,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  ud.stream_data.stream_id = -1;
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(-1, ==, ud.stream_data.stream_id);
  assert_uint64(199, ==,
                conn->rx.unsent_max_offset -
                  conn->local.transport_params.initial_max_data);

  ngtcp2_conn_del(conn);

  /* ngtcp2_conn_shutdown_stream_read is called in recv_stream_data
     callback.  Further recv_stream_data callback must not be
     called. */
  server_default_callbacks(&callbacks);
  callbacks.recv_stream_data = recv_stream_data_shutdown_stream_read;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.app.last_pkt_num = pkt_num;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .offset = 599,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(0, ==, ud.stream_data.stream_id);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 599,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(4, ==, ud.stream_data.stream_id);
  assert_false(ud.stream_data.flags & NGTCP2_STREAM_DATA_FLAG_FIN);
  assert_size(599, ==, ud.stream_data.datalen);

  ngtcp2_conn_del(conn);

  /* ngtcp2_conn_shutdown_stream_read is called in 2nd
     recv_stream_data callback. */
  server_default_callbacks(&callbacks);
  callbacks.recv_stream_data = recv_stream_data_deferred_shutdown_stream_read;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.app.last_pkt_num = pkt_num;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .offset = 599,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(0, ==, ud.stream_data.stream_id);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 599,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(4, ==, ud.stream_data.stream_id);
  assert_false(ud.stream_data.flags & NGTCP2_STREAM_DATA_FLAG_FIN);
  assert_uint64(599, ==, ud.stream_data.offset);
  assert_size(1, ==, ud.stream_data.datalen);

  ngtcp2_conn_del(conn);

  /* Received too many STREAM frames on closed remote stream. */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_shutdown_stream(conn, 0, 0, NGTCP2_APP_ERR01);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  frs[0].ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
  };
  frs[1].reset_stream = (ngtcp2_reset_stream){
    .type = NGTCP2_FRAME_RESET_STREAM,
    .app_error_code = NGTCP2_APP_ERR01,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 2);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
  };

  for (i = 0; i < NGTCP2_DEFAULT_GLITCH_RATELIM_BURST; ++i) {
    pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

    rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

    assert_int(0, ==, rv);
  }

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_INTERNAL, ==, rv);

  ngtcp2_conn_del(conn);

  /* Received too many STREAMS frames on closed local streams. */
  server_default_remote_transport_params(&remote_params);
  remote_params.initial_max_streams_bidi = 1;

  opts = (conn_options){
    .remote_params = &remote_params,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_shutdown_stream(conn, 0, stream_id, NGTCP2_APP_ERR01);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  frs[0].ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
  };
  frs[1].reset_stream = (ngtcp2_reset_stream){
    .type = NGTCP2_FRAME_RESET_STREAM,
    .stream_id = stream_id,
    .app_error_code = NGTCP2_APP_ERR01,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 2);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = stream_id,
  };

  for (i = 0; i < NGTCP2_DEFAULT_GLITCH_RATELIM_BURST; ++i) {
    pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

    rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

    assert_int(0, ==, rv);
  }

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_INTERNAL, ==, rv);

  ngtcp2_conn_del(conn);

  /* Received too many overlapping STREAM frames (0 length). */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  for (i = 0; i < NGTCP2_DEFAULT_GLITCH_RATELIM_BURST; ++i) {
    pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

    rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

    assert_int(0, ==, rv);
  }

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_INTERNAL, ==, rv);

  ngtcp2_conn_del(conn);

  /* Received too many overlapping STREAM frames (nonzero length). */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .offset = 10,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .base = null_data,
    .len = 10,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  for (i = 0; i < NGTCP2_DEFAULT_GLITCH_RATELIM_BURST; ++i) {
    pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

    rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

    assert_int(0, ==, rv);
  }

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_INTERNAL, ==, rv);

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
  ngtcp2_tpe tpe;

  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.app.last_pkt_num = pkt_num;

  fr.ping.type = NGTCP2_FRAME_PING;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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
  ngtcp2_tpe tpe;

  /* Receiving MAX_STREAM_DATA to an uninitiated local bidirectional
     stream ID is an error */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.app.last_pkt_num = pkt_num;

  fr.max_stream_data = (ngtcp2_max_stream_data){
    .type = NGTCP2_FRAME_MAX_STREAM_DATA,
    .stream_id = 4,
    .max_stream_data = 8092,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_STREAM_STATE, ==, rv);

  ngtcp2_conn_del(conn);

  /* Receiving MAX_STREAM_DATA to an uninitiated local unidirectional
     stream ID is an error */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.app.last_pkt_num = pkt_num;

  fr.max_stream_data = (ngtcp2_max_stream_data){
    .type = NGTCP2_FRAME_MAX_STREAM_DATA,
    .stream_id = 2,
    .max_stream_data = 8092,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_STREAM_STATE, ==, rv);

  ngtcp2_conn_del(conn);

  /* Receiving MAX_STREAM_DATA to a remote bidirectional stream which
     exceeds limit */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.app.last_pkt_num = pkt_num;

  fr.max_stream_data = (ngtcp2_max_stream_data){
    .type = NGTCP2_FRAME_MAX_STREAM_DATA,
    .stream_id = 1,
    .max_stream_data = 1000000009,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_STREAM_LIMIT, ==, rv);

  ngtcp2_conn_del(conn);

  /* Receiving MAX_STREAM_DATA to a remote bidirectional stream which
     the local endpoint has not received yet. */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.app.last_pkt_num = pkt_num;

  fr.max_stream_data = (ngtcp2_max_stream_data){
    .type = NGTCP2_FRAME_MAX_STREAM_DATA,
    .stream_id = 4,
    .max_stream_data = 1000000009,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, 4);

  assert_not_null(strm);
  assert_uint64(1000000009, ==, strm->tx.max_offset);

  ngtcp2_conn_del(conn);

  /* Receiving MAX_STREAM_DATA to a idle remote unidirectional stream
     is a protocol violation. */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.app.last_pkt_num = pkt_num;

  fr.max_stream_data = (ngtcp2_max_stream_data){
    .type = NGTCP2_FRAME_MAX_STREAM_DATA,
    .stream_id = 2,
    .max_stream_data = 1000000009,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_STREAM_STATE, ==, rv);

  ngtcp2_conn_del(conn);

  /* Receiving MAX_STREAM_DATA to an existing bidirectional stream */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.app.last_pkt_num = pkt_num;

  strm = open_stream(conn, 4);

  fr.max_stream_data = (ngtcp2_max_stream_data){
    .type = NGTCP2_FRAME_MAX_STREAM_DATA,
    .stream_id = 4,
    .max_stream_data = 1000000009,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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

  spktlen = ngtcp2_conn_writev_stream(
    conn, NULL, NULL, buf, sizeof(buf), &datalen, NGTCP2_WRITE_STREAM_FLAG_NONE,
    stream_id, null_datav(&datav, 199), 1, ++t);

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

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, sizeof(buf),
                                      &datalen, NGTCP2_WRITE_STREAM_FLAG_FIN,
                                      stream_id, NULL, 0, ++t);

  assert_ptrdiff(NGTCP2_ERR_STREAM_SHUT_WR, ==, spktlen);
  assert_ptrdiff(-1, ==, datalen);

  ngtcp2_conn_del(conn);

  /* Can write 0 length STREAM frame without FIN bit set */
  setup_early_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen =
    ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, sizeof(buf), &datalen,
                              NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, ++t);

  assert_ptrdiff(0, <, spktlen);

  /* We have written Initial.  Now check that STREAM frame is
     written. */
  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, sizeof(buf),
                                      &datalen, NGTCP2_WRITE_STREAM_FLAG_NONE,
                                      stream_id, NULL, 0, ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(0, ==, datalen);

  /* 0 length data cannot be written more than once. */
  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, sizeof(buf),
                                      &datalen, NGTCP2_WRITE_STREAM_FLAG_NONE,
                                      stream_id, NULL, 0, ++t);

  assert_ptrdiff(0, ==, spktlen);
  assert_ptrdiff(-1, ==, datalen);

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
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  int64_t pkt_num = 1;
  ngtcp2_tstamp t = 0;
  ngtcp2_strm *strm;
  int rv;
  my_user_data ud;
  ngtcp2_tpe tpe;
  ngtcp2_callbacks callbacks;
  conn_options opts;

  server_early_callbacks(&callbacks);
  callbacks.recv_stream_data = recv_stream_data;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_early_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);
  tpe.initial.last_pkt_num = pkt_num;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1221,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  /* NEW_CONNECTION_ID frame is generated */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff((ngtcp2_ssize)sizeof(buf), ==, spktlen);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .fin = 1,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 911,
    .base = null_data,
  };

  tpe.app.last_pkt_num = pkt_num;
  tpe.early.ckm = &null_ckm;

  pktlen = ngtcp2_tpe_write_0rtt(&tpe, buf, sizeof(buf), &fr, 1);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .fin = 1,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 119,
    .base = null_data,
  };

  tpe.app.last_pkt_num = pkt_num;
  tpe.early.ckm = &null_ckm;

  pktlen = ngtcp2_tpe_write_0rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_DROP_CONN, ==, rv);

  ngtcp2_conn_del(conn);

  /* Compound packet */
  setup_early_server(&conn);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);
  tpe.initial.last_pkt_num = pkt_num;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 111,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .fin = 1,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 999,
    .base = null_data,
  };

  tpe.app.last_pkt_num = pkt_num;
  tpe.early.ckm = &null_ckm;

  pktlen +=
    ngtcp2_tpe_write_0rtt(&tpe, buf + pktlen, sizeof(buf) - pktlen, &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  int64_t pkt_num = 1;
  ngtcp2_tstamp t = 0;
  ngtcp2_acktr_entry *ackent;
  int rv;
  ngtcp2_ksl_it it;
  ngtcp2_tpe tpe;

  /* 2 QUIC long packets in one UDP packet */
  setup_handshake_server(&conn);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);
  tpe.initial.last_pkt_num = pkt_num;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 611,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  pktlen +=
    ngtcp2_tpe_write_initial(&tpe, buf + pktlen, sizeof(buf) - pktlen, &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_acktr_get(&conn->in_pktns->acktr);
  ackent = ngtcp2_ksl_it_get(&it);

  assert_int64(tpe.initial.last_pkt_num, ==, ackent->pkt_num);
  assert_size(2, ==, ackent->len);

  ngtcp2_ksl_it_next(&it);

  assert_true(ngtcp2_ksl_it_end(&it));

  ngtcp2_conn_del(conn);

  /* 1 long packet and 1 short packet in one UDP packet */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.handshake.last_pkt_num = pkt_num;
  tpe.app.last_pkt_num = pkt_num;

  fr.padding = (ngtcp2_padding){
    .type = NGTCP2_FRAME_PADDING,
    .len = 1,
  };

  pktlen = ngtcp2_tpe_write_handshake(&tpe, buf, sizeof(buf), &fr, 1);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 426,
    .base = null_data,
  };

  pktlen +=
    ngtcp2_tpe_write_1rtt(&tpe, buf + pktlen, sizeof(buf) - pktlen, &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  it = ngtcp2_acktr_get(&conn->pktns.acktr);
  ackent = ngtcp2_ksl_it_get(&it);

  assert_int64(tpe.app.last_pkt_num, ==, ackent->pkt_num);

  it = ngtcp2_acktr_get(&conn->hs_pktns->acktr);

  assert_false(ngtcp2_ksl_it_end(&it));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_pkt_payloadlen(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  ngtcp2_tstamp t = 0;
  uint64_t payloadlen;
  int rv;
  const ngtcp2_cid *dcid;
  ngtcp2_tpe tpe;

  /* Payload length is invalid */
  setup_handshake_server(&conn);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1231,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  dcid = ngtcp2_conn_get_dcid(conn);
  payloadlen = read_pkt_payloadlen(buf, dcid, &conn->oscid);
  write_pkt_payloadlen(buf, dcid, &conn->oscid, payloadlen + 1);

  /* This first packet which does not increase initial packet number
     space CRYPTO offset or it does not get buffered as 0RTT is an
     error.  But it is unsecured Initial, so we just ignore it. */
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_DROP_CONN, ==, rv);
  assert_int((int)NGTCP2_CS_SERVER_INITIAL, ==, (int)conn->state);

  ngtcp2_conn_del(conn);

  /* Client Initial packet included in UDP datagram smaller than 1200
     is discarded. */
  setup_handshake_server(&conn);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1000,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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
  ngtcp2_vec datav = {
    .base = null_data,
    .len = 10,
  };
  ngtcp2_vec large_datav = {
    .base = null_data,
    .len = 800,
  };
  ngtcp2_vec vec;
  ngtcp2_ssize datalen;
  size_t left;
  ngtcp2_strm *strm;
  ngtcp2_vec frdatav;
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  ngtcp2_tpe tpe;
  ngtcp2_transport_params remote_params;
  conn_options opts;
  ngtcp2_ksl_it it;
  ngtcp2_rtb_entry *ent;
  ngtcp2_cid dcid;
  ngtcp2_crypto_aead aead = {0};
  const uint8_t token[] = "token";

  dcid_init(&dcid);

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

  /* +10 buffer size */
  setup_default_client(&conn);

  /* This will sends NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 39 + 10, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                      &datav, 1, ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(10, ==, datalen);

  ngtcp2_conn_del(conn);

  /* Coalesces multiple STREAM frames */
  client_default_remote_transport_params(&remote_params);
  remote_params.initial_max_streams_bidi = 100;

  opts = (conn_options){
    .remote_params = &remote_params,
  };

  setup_default_client_with_options(&conn, opts);

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

  /* Do not write too small STREAM frame */
  client_default_remote_transport_params(&remote_params);

  opts = (conn_options){
    .remote_params = &remote_params,
  };

  setup_default_client_with_options(&conn, opts);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                      &large_datav, 1, ++t);

  assert_ptrdiff(NGTCP2_ERR_WRITE_MORE, ==, spktlen);
  assert_ptrdiff((ngtcp2_ssize)ngtcp2_vec_len(&large_datav, 1), ==, datalen);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                      &large_datav, 1, ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(-1, ==, datalen);

  ngtcp2_conn_del(conn);

  /* 0RTT: Coalesces multiple STREAM frames */
  client_early_remote_transport_params(&remote_params);
  remote_params.initial_max_streams_bidi = 100;

  opts = (conn_options){
    .remote_params = &remote_params,
  };

  setup_early_client_with_options(&conn, opts);

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

  spktlen =
    ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, NULL,
                              NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, ++t);

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

  spktlen =
    ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, NULL,
                              NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, ++t);

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

  spktlen =
    ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, NULL,
                              NGTCP2_WRITE_STREAM_FLAG_MORE, -1, NULL, 0, ++t);

  assert_ptrdiff(0, <, spktlen);

  ngtcp2_conn_del(conn);

  /* 1RTT: Stream data blocked when attempting coalescing packet */
  setup_handshake_server(&conn);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &frdatav,
  };
  frdatav = (ngtcp2_vec){
    .len = 1200,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &frdatav,
  };
  frdatav = (ngtcp2_vec){
    .len = 1200,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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

  spktlen =
    ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, NULL,
                              NGTCP2_WRITE_STREAM_FLAG_MORE, -1, NULL, 0, ++t);

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

  spktlen =
    ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, NULL,
                              NGTCP2_WRITE_STREAM_FLAG_MORE, -1, NULL, 0, ++t);

  assert_ptrdiff(1200, <=, spktlen);
  assert_ptrdiff(-1, ==, datalen);

  ngtcp2_conn_del(conn);

  /* Writing 0 length data with 0 length vector */
  setup_default_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, 1200, ++t);

  assert_ptrdiff(0, <, spktlen);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, NULL,
                                      NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                      NULL, 0, ++t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);
  ent = ngtcp2_ksl_it_get(&it);

  assert_uint64(NGTCP2_FRAME_STREAM, ==, ent->frc->fr.hd.type);
  assert_uint64(0, ==, ent->frc->fr.stream.offset);
  assert_uint64(0, ==, ent->frc->fr.stream.datacnt);

  ngtcp2_conn_del(conn);

  /* Writing 0 length data with 1 length vector */
  setup_default_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, 1200, ++t);

  assert_ptrdiff(0, <, spktlen);

  vec.base = NULL;
  vec.len = 0;

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, NULL,
                                      NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                      &vec, 1, ++t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);
  ent = ngtcp2_ksl_it_get(&it);

  assert_uint64(NGTCP2_FRAME_STREAM, ==, ent->frc->fr.hd.type);
  assert_uint64(0, ==, ent->frc->fr.stream.offset);
  assert_uint64(0, ==, ent->frc->fr.stream.datacnt);

  ngtcp2_conn_del(conn);

  /* Writing 0 length data with ngtcp2_conn_write_stream */
  setup_default_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, 1200, ++t);

  assert_ptrdiff(0, <, spktlen);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, 1200, NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     NULL, 0, ++t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);
  ent = ngtcp2_ksl_it_get(&it);

  assert_uint64(NGTCP2_FRAME_STREAM, ==, ent->frc->fr.hd.type);
  assert_uint64(0, ==, ent->frc->fr.stream.offset);
  assert_uint64(0, ==, ent->frc->fr.stream.datacnt);

  ngtcp2_conn_del(conn);

  /* Attempt to write stream after fin */
  setup_default_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_FIN, stream_id,
                                      &datav, 1, ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff((ptrdiff_t)ngtcp2_vec_len(&datav, 1), ==, datalen);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_FIN, stream_id,
                                      NULL, 0, ++t);

  assert_ptrdiff(NGTCP2_ERR_STREAM_SHUT_WR, ==, spktlen);

  ngtcp2_conn_del(conn);

  /* NGTCP2_WRITE_STREAM_FLAG_PADDING */
  setup_default_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_MORE |
                                        NGTCP2_WRITE_STREAM_FLAG_PADDING,
                                      stream_id, &datav, 1, ++t);

  assert_ptrdiff(NGTCP2_ERR_WRITE_MORE, ==, spktlen);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_MORE |
                                        NGTCP2_WRITE_STREAM_FLAG_PADDING,
                                      -1, NULL, 0, ++t);

  assert_ptrdiff(1200, ==, spktlen);

  ngtcp2_conn_del(conn);

  /* Do not specify NGTCP2_WRITE_STREAM_FLAG_PADDING in the final call
     to ngtcp2_conn_writev_stream. */
  setup_default_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_MORE |
                                        NGTCP2_WRITE_STREAM_FLAG_PADDING,
                                      stream_id, &datav, 1, ++t);

  assert_ptrdiff(NGTCP2_ERR_WRITE_MORE, ==, spktlen);

  spktlen =
    ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, &datalen,
                              NGTCP2_WRITE_STREAM_FLAG_MORE, -1, NULL, 0, ++t);

  assert_ptrdiff(1200, >, spktlen);

  ngtcp2_conn_del(conn);

  /* Set NGTCP2_WRITE_STREAM_FLAG_PADDING only in the final call to
     ngtcp2_conn_writev_stream. */
  setup_default_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                      &datav, 1, ++t);

  assert_ptrdiff(NGTCP2_ERR_WRITE_MORE, ==, spktlen);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_MORE |
                                        NGTCP2_WRITE_STREAM_FLAG_PADDING,
                                      -1, NULL, 0, ++t);

  assert_ptrdiff(1200, ==, spktlen);

  ngtcp2_conn_del(conn);

  /* 0 RTT packet is also padded with
     NGTCP2_WRITE_STREAM_FLAG_PADDING. */
  setup_early_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen =
    ngtcp2_conn_write_stream(conn, NULL, NULL, buf, 1200, &datalen,
                             NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, ++t);

  assert_ptrdiff(0, <, spktlen);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                      &datav, 1, ++t);

  assert_ptrdiff(NGTCP2_ERR_WRITE_MORE, ==, spktlen);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_MORE |
                                        NGTCP2_WRITE_STREAM_FLAG_PADDING,
                                      -1, NULL, 0, ++t);

  assert_ptrdiff(1200, ==, spktlen);

  ngtcp2_conn_del(conn);

  /* 0 RTT packet after Retry is also padded with
     NGTCP2_WRITE_STREAM_FLAG_PADDING. */
  setup_early_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen =
    ngtcp2_conn_write_stream(conn, NULL, NULL, buf, 1200, &datalen,
                             NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, ++t);

  assert_ptrdiff(0, <, spktlen);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, 1200, &datalen,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 1200, ++t);

  spktlen = ngtcp2_pkt_write_retry(
    buf, sizeof(buf), NGTCP2_PROTO_VER_V1, &conn->oscid, &dcid,
    ngtcp2_conn_get_dcid(conn), token, ngtcp2_strlen_lit(token), null_encrypt,
    &aead, &aead_ctx);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, (size_t)spktlen,
                            ++t);

  assert_int(0, ==, rv);

  /* UDP datagram containing Initial packet is always padded. */
  spktlen =
    ngtcp2_conn_write_stream(conn, NULL, NULL, buf, 1200, &datalen,
                             NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, ++t);

  assert_ptrdiff(1200, ==, spktlen);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, 1200, &datalen,
                                     NGTCP2_WRITE_STREAM_FLAG_PADDING, -1, NULL,
                                     0, ++t);

  assert_ptrdiff(1200, ==, spktlen);

  spktlen =
    ngtcp2_conn_write_stream(conn, NULL, NULL, buf, 1200, &datalen,
                             NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, ++t);

  assert_ptrdiff(0, ==, spktlen);

  ngtcp2_conn_del(conn);

  /* Padding is subject to anti-amplification limit when server has
     not validated the path. */
  setup_default_server(&conn);

  conn->dcid.current.flags &= (uint8_t)~NGTCP2_DCID_FLAG_PATH_VALIDATED;
  conn->dcid.current.bytes_recv = 300;

  open_stream(conn, 0);

  spktlen =
    ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, &datalen,
                              NGTCP2_WRITE_STREAM_FLAG_MORE, 0, &datav, 1, ++t);

  assert_ptrdiff(NGTCP2_ERR_WRITE_MORE, ==, spktlen);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, 1200, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_MORE |
                                        NGTCP2_WRITE_STREAM_FLAG_PADDING,
                                      -1, NULL, 0, ++t);

  assert_ptrdiff(900, ==, spktlen);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_writev_datagram(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 0;
  ngtcp2_vec datav = {
    .base = null_data,
    .len = 10,
  };
  ngtcp2_vec vec;
  int accepted;
  my_user_data ud;
  ngtcp2_frame fr;
  size_t pktlen;
  int rv;
  ngtcp2_tpe tpe;
  ngtcp2_transport_params remote_params;
  ngtcp2_callbacks callbacks;
  conn_options opts;

  client_default_remote_transport_params(&remote_params);
  remote_params.max_datagram_frame_size = 1 + 1 + 10;

  client_default_callbacks(&callbacks);
  callbacks.ack_datagram = ack_datagram;

  opts = (conn_options){
    .remote_params = &remote_params,
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_client_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  spktlen = ngtcp2_conn_writev_datagram(
    conn, NULL, NULL, buf, sizeof(buf), &accepted,
    NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 1000000009, &datav, 1, ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_true(accepted);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  ud.datagram.dgram_id = 0;
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_uint64(1000000009, ==, ud.datagram.dgram_id);

  ngtcp2_conn_del(conn);

  /* Coalesces multiple DATAGRAM frames into a single QUIC packet */
  client_default_remote_transport_params(&remote_params);
  remote_params.max_datagram_frame_size = 65535;

  opts = (conn_options){
    .remote_params = &remote_params,
  };

  setup_default_client_with_options(&conn, opts);

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
  client_default_remote_transport_params(&remote_params);
  remote_params.max_datagram_frame_size =
    1 + ngtcp2_put_uvarintlen(2000) + 2000;

  opts = (conn_options){
    .remote_params = &remote_params,
  };

  setup_default_client_with_options(&conn, opts);

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
  client_default_remote_transport_params(&remote_params);
  remote_params.max_datagram_frame_size = 9;

  opts = (conn_options){
    .remote_params = &remote_params,
  };

  setup_default_client_with_options(&conn, opts);

  spktlen = ngtcp2_conn_writev_datagram(
    conn, NULL, NULL, buf, sizeof(buf), &accepted,
    NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 4433, &datav, 1, ++t);

  assert_ptrdiff(NGTCP2_ERR_INVALID_ARGUMENT, ==, spktlen);

  ngtcp2_conn_del(conn);

  /* Send DATAGRAM frame in a 0RTT packet */
  client_early_remote_transport_params(&remote_params);
  remote_params.max_datagram_frame_size = 4311;

  opts = (conn_options){
    .remote_params = &remote_params,
  };

  setup_early_client_with_options(&conn, opts);

  spktlen = ngtcp2_conn_writev_datagram(
    conn, NULL, NULL, buf, sizeof(buf), &accepted,
    NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 22360679, &datav, 1, ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_true(accepted);

  ngtcp2_conn_del(conn);

  /* Writing 0 length data with 0 length vector */
  client_default_remote_transport_params(&remote_params);
  remote_params.max_datagram_frame_size = 1200;

  opts = (conn_options){
    .remote_params = &remote_params,
  };

  setup_default_client_with_options(&conn, opts);

  spktlen = ngtcp2_conn_writev_datagram(
    conn, NULL, NULL, buf, sizeof(buf), &accepted,
    NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 1000000007, NULL, 0, ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_true(accepted);

  ngtcp2_conn_del(conn);

  /* Writing 0 length data with 1 length vector */
  client_default_remote_transport_params(&remote_params);
  remote_params.max_datagram_frame_size = 1200;

  opts = (conn_options){
    .remote_params = &remote_params,
  };

  setup_default_client_with_options(&conn, opts);

  vec.base = NULL;
  vec.len = 0;

  spktlen = ngtcp2_conn_writev_datagram(
    conn, NULL, NULL, buf, sizeof(buf), &accepted,
    NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 1000000009, &vec, 1, ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_true(accepted);

  ngtcp2_conn_del(conn);

  /* Writing 0 length data with ngtcp2_conn_write_datagram */
  client_default_remote_transport_params(&remote_params);
  remote_params.max_datagram_frame_size = 1200;

  opts = (conn_options){
    .remote_params = &remote_params,
  };

  setup_default_client_with_options(&conn, opts);

  spktlen = ngtcp2_conn_write_datagram(
    conn, NULL, NULL, buf, sizeof(buf), &accepted,
    NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 1000000007, NULL, 0, ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_true(accepted);

  ngtcp2_conn_del(conn);

  /* NGTCP2_WRITE_DATAGRAM_FLAG_PADDING */
  client_default_remote_transport_params(&remote_params);
  remote_params.max_datagram_frame_size = 1500;

  opts = (conn_options){
    .remote_params = &remote_params,
  };

  setup_default_client_with_options(&conn, opts);

  spktlen = ngtcp2_conn_writev_datagram(conn, NULL, NULL, buf, 1200, &accepted,
                                        NGTCP2_WRITE_DATAGRAM_FLAG_MORE, 999,
                                        &datav, 1, ++t);

  assert_ptrdiff(NGTCP2_ERR_WRITE_MORE, ==, spktlen);
  assert_true(accepted);

  spktlen = ngtcp2_conn_write_datagram(conn, NULL, NULL, buf, 1200, &accepted,
                                       NGTCP2_WRITE_DATAGRAM_FLAG_PADDING, 3,
                                       null_data, 1200, ++t);

  assert_ptrdiff(1200, ==, spktlen);
  assert_false(accepted);

  ngtcp2_conn_del(conn);

  /* Add padding with NGTCP2_WRITE_STREAM_FLAG_PADDING to the final
     call to ngtcp2_conn_writev_stream. */
  client_default_remote_transport_params(&remote_params);
  remote_params.max_datagram_frame_size = 1200;

  opts = (conn_options){
    .remote_params = &remote_params,
  };

  setup_default_client_with_options(&conn, opts);

  spktlen = ngtcp2_conn_writev_datagram(
    conn, NULL, NULL, buf, sizeof(buf), &accepted,
    NGTCP2_WRITE_DATAGRAM_FLAG_MORE, 999, &datav, 1, ++t);

  assert_ptrdiff(NGTCP2_ERR_WRITE_MORE, ==, spktlen);
  assert_true(accepted);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                      NGTCP2_WRITE_STREAM_FLAG_PADDING, -1,
                                      NULL, 0, ++t);

  assert_ptrdiff(sizeof(buf), ==, spktlen);

  ngtcp2_conn_del(conn);

  /* 0 RTT packet is also padded with
     NGTCP2_WRITE_STREAM_FLAG_PADDING. */
  client_early_remote_transport_params(&remote_params);
  remote_params.max_datagram_frame_size = 1500;

  opts = (conn_options){
    .remote_params = &remote_params,
  };

  setup_early_client_with_options(&conn, opts);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, 1200, ++t);

  assert_ptrdiff(0, <, spktlen);

  spktlen = ngtcp2_conn_writev_datagram(conn, NULL, NULL, buf, 1200, &accepted,
                                        NGTCP2_WRITE_DATAGRAM_FLAG_MORE, 999,
                                        &datav, 1, ++t);

  assert_ptrdiff(NGTCP2_ERR_WRITE_MORE, ==, spktlen);
  assert_true(accepted);

  spktlen = ngtcp2_conn_write_datagram(conn, NULL, NULL, buf, 1200, &accepted,
                                       NGTCP2_WRITE_DATAGRAM_FLAG_PADDING, 3,
                                       null_data, 1200, ++t);

  assert_ptrdiff(1200, ==, spktlen);
  assert_false(accepted);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_datagram(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_tstamp t = 0;
  my_user_data ud;
  int rv;
  ngtcp2_tpe tpe;
  ngtcp2_transport_params params;
  ngtcp2_callbacks callbacks;
  conn_options opts;

  server_default_transport_params(&params);
  params.max_datagram_frame_size = 1 + 1111;

  server_default_callbacks(&callbacks);
  callbacks.recv_datagram = recv_datagram;

  opts = (conn_options){
    .params = &params,
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.datagram = (ngtcp2_datagram){
    .type = NGTCP2_FRAME_DATAGRAM,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .base = null_data,
    .len = 1111,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(1111, ==, ud.datagram.datalen);
  assert_false(NGTCP2_DATAGRAM_FLAG_0RTT & ud.datagram.flags);

  ngtcp2_conn_del(conn);

  /* Receiving DATAGRAM frame which is strictly larger than the
     declared limit is an error */
  server_default_transport_params(&params);
  params.max_datagram_frame_size = 1 + 1111 - 1;

  opts = (conn_options){
    .params = &params,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.datagram = (ngtcp2_datagram){
    .type = NGTCP2_FRAME_DATAGRAM,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .base = null_data,
    .len = 1111,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_PROTO, ==, rv);

  ngtcp2_conn_del(conn);

  /* Receiving DATAGRAM frame in a 0RTT packet */
  server_default_transport_params(&params);
  params.max_datagram_frame_size = 1 + 1111;

  server_early_callbacks(&callbacks);
  callbacks.recv_datagram = recv_datagram;

  opts = (conn_options){
    .params = &params,
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_early_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1199,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  fr.datagram = (ngtcp2_datagram){
    .type = NGTCP2_FRAME_DATAGRAM,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .base = null_data,
    .len = 1111,
  };

  tpe.early.ckm = conn->early.ckm;

  pktlen = ngtcp2_tpe_write_0rtt(&tpe, buf, sizeof(buf), &fr, 1);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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
  ngtcp2_frame fr;
  ngtcp2_frame frs[16];
  static const ngtcp2_cid cid = {
    .datalen = 4,
    .data = {0xF0, 0xF1, 0xF2, 0xF3},
  };
  static const ngtcp2_stateless_reset_token token = {
    .data = {0xFF},
  };
  static const ngtcp2_cid cid2 = {
    .datalen = 4,
    .data = {0xF0, 0xF1, 0xF2, 0xF4},
  };
  static const ngtcp2_stateless_reset_token token2 = {
    .data = {0xFE},
  };
  static const ngtcp2_cid cid3 = {
    .datalen = 4,
    .data = {0xF0, 0xF1, 0xF2, 0xF5},
  };
  static const ngtcp2_stateless_reset_token token3 = {
    .data = {0xFD},
  };
  ngtcp2_dcid *dcid;
  int rv;
  ngtcp2_frame_chain *frc;
  size_t i;
  ngtcp2_tpe tpe;
  ngtcp2_transport_params params;
  conn_options opts;

  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  fr.new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 1,
    .cid = cid,
    .token = token,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(1, ==, ngtcp2_dcidtr_unused_len(&conn->dcid.dtr));

  dcid = ngtcp2_ringbuf_get(&conn->dcid.dtr.unused.rb, 0);
  assert_true(ngtcp2_cid_eq(&fr.new_connection_id.cid, &dcid->cid));
  assert_true(dcid->flags & NGTCP2_DCID_FLAG_TOKEN_PRESENT);
  assert_true(
    ngtcp2_stateless_reset_token_eq(&fr.new_connection_id.token, &dcid->token));

  fr.new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 2,
    .retire_prior_to = 2,
    .cid = cid2,
    .token = token2,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, ==, ngtcp2_dcidtr_bound_len(&conn->dcid.dtr));
  assert_size(0, ==, ngtcp2_dcidtr_unused_len(&conn->dcid.dtr));
  assert_uint64(2, ==, conn->dcid.current.seq);
  assert_not_null(conn->pktns.tx.frq);
  assert_uint64(2, ==, conn->dcid.retire_prior_to);

  frc = conn->pktns.tx.frq;

  assert_uint64(NGTCP2_FRAME_RETIRE_CONNECTION_ID, ==, frc->fr.hd.type);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_RETIRE_CONNECTION_ID, ==, frc->fr.hd.type);
  assert_null(frc->next);

  /* This will send RETIRE_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  ngtcp2_conn_del(conn);

  /* Received connection ID is immediately retired due to packet
     reordering */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  fr.new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 2,
    .retire_prior_to = 2,
    .cid = cid,
    .token = token,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, ==, ngtcp2_dcidtr_unused_len(&conn->dcid.dtr));
  assert_uint64(2, ==, conn->dcid.current.seq);
  assert_uint64(2, ==, conn->dcid.retire_prior_to);

  frc = conn->pktns.tx.frq;

  assert_uint64(NGTCP2_FRAME_RETIRE_CONNECTION_ID, ==, frc->fr.hd.type);
  assert_null(frc->next);

  /* This will send RETIRE_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  fr.new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 1,
    .cid = cid2,
    .token = token2,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, ==, ngtcp2_dcidtr_unused_len(&conn->dcid.dtr));
  assert_uint64(2, ==, conn->dcid.current.seq);
  assert_uint64(2, ==, conn->dcid.retire_prior_to);

  frc = conn->pktns.tx.frq;

  assert_uint64(NGTCP2_FRAME_RETIRE_CONNECTION_ID, ==, frc->fr.hd.type);
  assert_null(frc->next);

  /* Make sure that dup check works */
  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, ==, ngtcp2_dcidtr_unused_len(&conn->dcid.dtr));
  assert_uint64(2, ==, conn->dcid.current.seq);
  assert_uint64(2, ==, conn->dcid.retire_prior_to);

  frc = conn->pktns.tx.frq;

  assert_uint64(NGTCP2_FRAME_RETIRE_CONNECTION_ID, ==, frc->fr.hd.type);
  assert_null(frc->next);

  ngtcp2_conn_del(conn);

  /* ngtcp2_pv contains DCIDs that should be retired. */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  assert(NULL == conn->pv);

  frs[0].ping.type = NGTCP2_FRAME_PING;
  frs[1].new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 1,
    .cid = cid,
    .token = token,
  };
  frs[2].new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 2,
    .cid = cid2,
    .token = token2,
  };
  frs[3].new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 3,
    .cid = cid3,
    .token = token3,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 4);
  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  assert(NULL != conn->pv);

  assert_true(conn->pv->flags & NGTCP2_PV_FLAG_FALLBACK_PRESENT);
  assert_uint64(1, ==, conn->pv->dcid.seq);
  assert_uint64(0, ==, conn->pv->fallback_dcid.seq);
  assert_size(2, ==, ngtcp2_dcidtr_unused_len(&conn->dcid.dtr));
  assert_uint64(1, ==, conn->cstat.ping_recv);

  fr.new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 3,
    .retire_prior_to = 2,
    .cid = cid3,
    .token = token3,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, ==, ngtcp2_dcidtr_unused_len(&conn->dcid.dtr));
  assert_true(conn->pv->flags & NGTCP2_PV_FLAG_FALLBACK_PRESENT);
  assert_uint64(2, ==, conn->pv->dcid.seq);
  assert_uint64(3, ==, conn->pv->fallback_dcid.seq);

  frc = conn->pktns.tx.frq;

  assert_uint64(NGTCP2_FRAME_RETIRE_CONNECTION_ID, ==, frc->fr.hd.type);
  assert_uint64(0, ==, frc->fr.retire_connection_id.seq);
  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_RETIRE_CONNECTION_ID, ==, frc->fr.hd.type);
  assert_uint64(1, ==, frc->fr.retire_connection_id.seq);
  assert_null(frc->next);

  ngtcp2_conn_del(conn);

  /* ngtcp2_pv contains DCID in fallback that should be retired and
     there is not enough connection ID left.  */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  assert(NULL == conn->pv);

  frs[0].ping.type = NGTCP2_FRAME_PING;
  frs[1].new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 1,
    .cid = cid,
    .token = token,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 2);
  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  assert(NULL != conn->pv);

  assert_true(conn->pv->flags & NGTCP2_PV_FLAG_FALLBACK_PRESENT);
  assert_uint64(1, ==, conn->pv->dcid.seq);
  assert_uint64(0, ==, conn->pv->fallback_dcid.seq);
  assert_size(0, ==, ngtcp2_dcidtr_unused_len(&conn->dcid.dtr));

  fr.new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 2,
    .retire_prior_to = 2,
    .cid = cid2,
    .token = token2,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_uint64(2, ==, conn->dcid.current.seq);
  assert_size(0, ==, ngtcp2_dcidtr_unused_len(&conn->dcid.dtr));
  assert_null(conn->pv);

  frc = conn->pktns.tx.frq;

  assert_uint64(NGTCP2_FRAME_RETIRE_CONNECTION_ID, ==, frc->fr.hd.type);
  assert_uint64(0, ==, frc->fr.retire_connection_id.seq);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_RETIRE_CONNECTION_ID, ==, frc->fr.hd.type);
  assert_uint64(1, ==, frc->fr.retire_connection_id.seq);
  assert_null(frc->next);

  ngtcp2_conn_del(conn);

  /* ngtcp2_pv contains DCIDs that should be retired and there is not
     enough connection ID left to continue path validation.  */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  assert(NULL == conn->pv);

  frs[0].ping.type = NGTCP2_FRAME_PING;
  frs[1].new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 1,
    .cid = cid,
    .token = token,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 2);
  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  assert(NULL != conn->pv);

  assert_true(conn->pv->flags & NGTCP2_PV_FLAG_FALLBACK_PRESENT);
  assert_uint64(1, ==, conn->pv->dcid.seq);
  assert_uint64(0, ==, conn->pv->fallback_dcid.seq);
  assert_size(0, ==, ngtcp2_dcidtr_unused_len(&conn->dcid.dtr));

  /* Overwrite seq in pv->dcid so that pv->dcid cannot be renewed. */
  conn->pv->dcid.seq = 2;
  /* Internally we assume that if primary dcid and pv->dcid differ,
     then no fallback dcid is present. */
  conn->pv->flags &= (uint8_t)~NGTCP2_PV_FLAG_FALLBACK_PRESENT;

  fr.new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 3,
    .retire_prior_to = 3,
    .cid = cid3,
    .token = token3,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_uint64(3, ==, conn->dcid.current.seq);
  assert_size(0, ==, ngtcp2_dcidtr_unused_len(&conn->dcid.dtr));
  assert_null(conn->pv);

  frc = conn->pktns.tx.frq;

  assert_uint64(NGTCP2_FRAME_RETIRE_CONNECTION_ID, ==, frc->fr.hd.type);
  assert_uint64(2, ==, frc->fr.retire_connection_id.seq);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_RETIRE_CONNECTION_ID, ==, frc->fr.hd.type);
  assert_uint64(1, ==, frc->fr.retire_connection_id.seq);
  assert_null(frc->next);

  ngtcp2_conn_del(conn);

  /* Receiving more than advertised CID is treated as error */
  server_default_transport_params(&params);
  params.active_connection_id_limit = 2;

  opts = (conn_options){
    .params = &params,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  assert(NULL == conn->pv);

  frs[0].new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 1,
    .cid = cid,
    .token = token,
  };
  frs[1].new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 2,
    .cid = cid2,
    .token = token2,
  };
  frs[2].new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 3,
    .cid = cid3,
    .token = token3,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 3);
  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_CONNECTION_ID_LIMIT, ==, rv);

  ngtcp2_conn_del(conn);

  /* Receiving duplicated NEW_CONNECTION_ID frame */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  frs[0].ping.type = NGTCP2_FRAME_PING;

  frs[1].new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 1,
    .retire_prior_to = 1,
    .cid = cid,
    .token = token,
  };

  frs[2].new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 2,
    .retire_prior_to = 1,
    .cid = cid2,
    .token = token2,
  };

  frs[3].padding = (ngtcp2_padding){
    .type = NGTCP2_FRAME_PADDING,
    .len = 1200,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 4);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, ==, ngtcp2_dcidtr_unused_len(&conn->dcid.dtr));
  assert_uint64(2, ==, conn->dcid.current.seq);
  assert_not_null(conn->pv);
  assert_true(
    ngtcp2_cid_eq(&frs[1].new_connection_id.cid, &conn->pv->fallback_dcid.cid));

  /* This will send PATH_CHALLENGE frame */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1200, <=, spktlen);

  fr.path_response.type = NGTCP2_FRAME_PATH_RESPONSE;
  memset(fr.path_response.data, 0, sizeof(fr.path_response.data));

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  /* Server starts probing old path */
  assert_not_null(conn->pv);
  assert_true(ngtcp2_path_eq(&null_path.path, &conn->pv->dcid.ps.path));

  /* Receive NEW_CONNECTION_ID seq=1 again, which should be ignored. */
  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 2);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, ==, ngtcp2_dcidtr_unused_len(&conn->dcid.dtr));
  assert_uint64(2, ==, conn->dcid.current.seq);

  ngtcp2_conn_del(conn);

  /* Exceeding the limit for the number of unacknowledged
     RETIRE_CONNECTION_ID leads to NGTCP2_ERR_CONNECTION_ID_LIMIT. */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  for (i = 0; i < 7; ++i) {
    frs[i].new_connection_id = (ngtcp2_new_connection_id){
      .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
      .seq = i + 1,
      .cid =
        {
          .datalen = 4,
          .data = {(uint8_t)i, 0xF1, 0xF2, 0xF3},
        },
      .token = token,
    };
  }

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 7);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  for (i = 0; i < 8; ++i) {
    frs[i].new_connection_id = (ngtcp2_new_connection_id){
      .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
      .seq = i + 8,
      .retire_prior_to = 8,
      .cid =
        {
          .datalen = 4,
          .data = {(uint8_t)(i + 8), 0xF1, 0xF2, 0xF3},
        },
      .token = token,
    };
  }

  for (i = 0; i < 8; ++i) {
    frs[i + 8].new_connection_id = (ngtcp2_new_connection_id){
      .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
      .seq = i + 16,
      .retire_prior_to = 16,
      .cid =
        {
          .datalen = 4,
          .data = {(uint8_t)(i + 16), 0xF1, 0xF2, 0xF3},
        },
      .token = token,
    };
  }

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 16);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  frs[0].new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 24,
    .retire_prior_to = 17,
    .cid =
      {
        .datalen = 4,
        .data = {(uint8_t)(i + 24), 0xF1, 0xF2, 0xF3},
      },
    .token = token,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_CONNECTION_ID_LIMIT, ==, rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_retire_connection_id(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 1000000009;
  ngtcp2_frame fr;
  int rv;
  ngtcp2_ksl_it it;
  ngtcp2_scid *scid;
  uint64_t seq;
  ngtcp2_tpe tpe;
  ngtcp2_transport_params remote_params;
  conn_options opts;

  client_default_remote_transport_params(&remote_params);
  remote_params.active_connection_id_limit = 7;

  opts = (conn_options){
    .remote_params = &remote_params,
  };

  setup_default_client_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_ksl_begin(&conn->scid.set);
  scid = ngtcp2_ksl_it_get(&it);
  seq = scid->seq;

  assert_uint8(NGTCP2_SCID_FLAG_NONE, ==, scid->flags);
  assert_uint64(UINT64_MAX, ==, scid->retired_ts);
  assert_size(1, ==, ngtcp2_pq_size(&conn->scid.used));

  fr.retire_connection_id = (ngtcp2_retire_connection_id){
    .type = NGTCP2_FRAME_RETIRE_CONNECTION_ID,
    .seq = seq,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.retire_connection_id = (ngtcp2_retire_connection_id){
    .type = NGTCP2_FRAME_RETIRE_CONNECTION_ID,
    .seq = 1,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_PROTO, ==, rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_server_path_validation(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 900;
  ngtcp2_frame fr;
  ngtcp2_frame frs[2];
  int rv;
  static const ngtcp2_cid cid = {
    .datalen = 4,
    .data = {0x0F, 0x00, 0x00, 0x00},
  };
  ngtcp2_cid *new_cid, orig_dcid, zerolen_cid;
  static const ngtcp2_stateless_reset_token token = {
    .data = {0xFF},
  };
  ngtcp2_path_storage new_path1, new_path2, new_path3;
  ngtcp2_ksl_it it;
  ngtcp2_path_history_entry *ph_ent;
  ngtcp2_tpe tpe;
  ngtcp2_transport_params params, remote_params;
  conn_options opts;

  path_init(&new_path1, 0, 0, 2, 0);
  path_init(&new_path2, 0, 0, 3, 0);
  path_init(&new_path3, 1, 0, 0, 0);

  ngtcp2_cid_zero(&zerolen_cid);

  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(1, <, ngtcp2_ksl_len(&conn->scid.set));

  frs[0].new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 1,
    .cid = cid,
    .token = token,
  };
  frs[1].new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 2,
    .cid =
      {
        .datalen = 4,
        .data = {0x1F, 0x00, 0x00, 0x00},
      },
    .token = token,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 2);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  fr.ping.type = NGTCP2_FRAME_PING;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &new_path1.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_not_null(conn->pv);
  assert_size(1, ==, ngtcp2_ringbuf_len(&conn->path_history.rb));

  ph_ent = ngtcp2_ringbuf_get(&conn->path_history.rb, 0);

  assert_true(ngtcp2_path_eq(&null_path.path, &ph_ent->ps.path));
  assert_size(NGTCP2_MAX_UDP_PAYLOAD_SIZE, ==, ph_ent->max_udp_payload_size);
  assert_uint64(t, ==, ph_ent->ts);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(0, <, ngtcp2_ringbuf_len(&conn->pv->ents.rb));

  fr.path_response.type = NGTCP2_FRAME_PATH_RESPONSE;
  memset(fr.path_response.data, 0, sizeof(fr.path_response.data));

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &new_path1.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_true(ngtcp2_path_eq(&new_path1.path, &conn->dcid.current.ps.path));
  /* DCID does not change because the client does not change its
     DCID. */
  assert_false(ngtcp2_cid_eq(&cid, &conn->dcid.current.cid));

  /* A remote endpoint changes DCID as well */
  fr.ping.type = NGTCP2_FRAME_PING;

  it = ngtcp2_ksl_begin(&conn->scid.set);

  assert(!ngtcp2_ksl_it_end(&it));

  new_cid = &(((ngtcp2_scid *)ngtcp2_ksl_it_get(&it))->cid);
  tpe.dcid = *new_cid;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &new_path2.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_not_null(conn->pv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(0, <, ngtcp2_ringbuf_len(&conn->pv->ents.rb));

  fr.path_response.type = NGTCP2_FRAME_PATH_RESPONSE;
  memset(fr.path_response.data, 0, sizeof(fr.path_response.data));

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &new_path2.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_true(ngtcp2_path_eq(&new_path2.path, &conn->dcid.current.ps.path));
  assert_true(ngtcp2_cid_eq(&cid, &conn->dcid.current.cid));

  /* A remote endpoint migrates back to the new_path1.  Path
     validation is skipped because new_path1 has been validated. */
  fr.ping.type = NGTCP2_FRAME_PING;

  ngtcp2_ksl_it_next(&it);

  assert(!ngtcp2_ksl_it_end(&it));

  new_cid = &(((ngtcp2_scid *)ngtcp2_ksl_it_get(&it))->cid);
  tpe.dcid = *new_cid;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &new_path1.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_null(conn->pv);
  assert_true(ngtcp2_path_eq(&new_path1.path, &conn->dcid.current.ps.path));
  assert_true(conn->dcid.current.flags & NGTCP2_DCID_FLAG_PATH_VALIDATED);

  ngtcp2_conn_del(conn);

  /* Server falls back to the original path if it is unable to verify
     that path is capable of minimum MTU that QUIC requires. */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  ngtcp2_cid_init(&orig_dcid, conn->dcid.current.cid.data,
                  conn->dcid.current.cid.datalen);

  assert_ptrdiff(0, <, spktlen);
  assert_size(1, <, ngtcp2_ksl_len(&conn->scid.set));

  fr.new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 1,
    .cid = cid,
    .token = token,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  fr.ping.type = NGTCP2_FRAME_PING;

  it = ngtcp2_ksl_begin(&conn->scid.set);

  assert(!ngtcp2_ksl_it_end(&it));

  new_cid = &(((ngtcp2_scid *)ngtcp2_ksl_it_get(&it))->cid);
  tpe.dcid = *new_cid;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_not_null(conn->pv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(0, <, ngtcp2_ringbuf_len(&conn->pv->ents.rb));

  fr.path_response.type = NGTCP2_FRAME_PATH_RESPONSE;
  memset(fr.path_response.data, 0, sizeof(fr.path_response.data));

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, NULL, buf, pktlen, ++t);

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
  ngtcp2_tpe_init_conn(&tpe, conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(1, <, ngtcp2_ksl_len(&conn->scid.set));

  fr.new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 1,
    .cid = cid,
    .token = token,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  frs[0].ping.type = NGTCP2_FRAME_PING;
  frs[1].padding = (ngtcp2_padding){
    .type = NGTCP2_FRAME_PADDING,
    .len = 1200,
  };

  it = ngtcp2_ksl_begin(&conn->scid.set);

  assert(!ngtcp2_ksl_it_end(&it));

  new_cid = &(((ngtcp2_scid *)ngtcp2_ksl_it_get(&it))->cid);
  tpe.dcid = *new_cid;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 2);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_not_null(conn->pv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(0, <, ngtcp2_ringbuf_len(&conn->pv->ents.rb));
  assert_null(conn->pmtud);

  fr.path_response.type = NGTCP2_FRAME_PATH_RESPONSE;
  memset(fr.path_response.data, 0, sizeof(fr.path_response.data));

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_true(ngtcp2_path_eq(&new_path.path, &conn->dcid.current.ps.path));
  assert_true(ngtcp2_cid_eq(&cid, &conn->dcid.current.cid));

  /* Server starts path validation against old path. */
  assert_not_null(conn->pv);
  assert_false(conn->pv->flags & NGTCP2_PV_FLAG_FALLBACK_PRESENT);
  assert_true(conn->pv->flags & NGTCP2_PV_FLAG_DONT_CARE);
  assert_not_null(conn->pmtud);

  ngtcp2_conn_del(conn);

  /* Server changes its local address to the preferred address chosen
     by client after successful path validation.  */
  server_default_transport_params(&params);
  params.preferred_addr_present = 1;
  params.preferred_addr.cid = cid;
  params.preferred_addr.ipv4_present = 1;

  assert_size(sizeof(params.preferred_addr.ipv4), ==,
              (size_t)new_path3.path.local.addrlen);

  memcpy(&params.preferred_addr.ipv4, new_path3.path.local.addr,
         sizeof(params.preferred_addr.ipv4));

  opts = (conn_options){
    .params = &params,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  fr.new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 1,
    .cid = cid,
    .token = token,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  frs[0].path_challenge.type = NGTCP2_FRAME_PATH_CHALLENGE;
  memset(frs[0].path_challenge.data, 0xFE, sizeof(frs[0].path_challenge.data));
  frs[1].padding = (ngtcp2_padding){
    .type = NGTCP2_FRAME_PADDING,
    .len = 1200,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 2);

  rv = ngtcp2_conn_read_pkt(conn, &new_path3.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_null(conn->pv);
  assert_true(ngtcp2_path_eq(&null_path.path, &conn->dcid.current.ps.path));

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  fr.ping.type = NGTCP2_FRAME_PING;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &new_path3.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_not_null(conn->pv);
  assert_true(ngtcp2_path_eq(&null_path.path, &conn->dcid.current.ps.path));
  assert_true(ngtcp2_path_eq(&new_path3.path, &conn->pv->dcid.ps.path));
  assert_false(conn->pv->flags & NGTCP2_PV_FLAG_FALLBACK_PRESENT);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  fr.path_response.type = NGTCP2_FRAME_PATH_RESPONSE;
  memcpy(fr.path_response.data,
         ((ngtcp2_pv_entry *)ngtcp2_ringbuf_get(&conn->pv->ents.rb, 0))->data,
         sizeof(fr.path_response.data));

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &new_path3.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_null(conn->pv);
  assert_true(ngtcp2_path_eq(&new_path3.path, &conn->dcid.current.ps.path));
  assert_uint64(1, ==, conn->dcid.current.seq);
  assert_int64(tpe.app.last_pkt_num, ==, conn->pktns.acktr.max_pkt_num);
  assert_int64(tpe.app.last_pkt_num, ==, conn->rx.preferred_addr.pkt_num);

  /* A packet from old path is discarded. */
  fr.ping.type = NGTCP2_FRAME_PING;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(tpe.app.last_pkt_num - 1, ==, conn->pktns.acktr.max_pkt_num);

  ngtcp2_conn_del(conn);

  /* client uses zero-length CID as its Source Connection ID. */
  server_default_remote_transport_params(&remote_params);
  remote_params.initial_scid = zerolen_cid;

  opts = (conn_options){
    .dcid = &zerolen_cid,
    .remote_params = &remote_params,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(1, <, ngtcp2_ksl_len(&conn->scid.set));

  frs[0].ping.type = NGTCP2_FRAME_PING;
  frs[1].padding = (ngtcp2_padding){
    .type = NGTCP2_FRAME_PADDING,
    .len = 1200,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 2);

  rv = ngtcp2_conn_read_pkt(conn, &new_path1.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_not_null(conn->pv);
  assert_true(ngtcp2_path_eq(&new_path1.path, &conn->pv->dcid.ps.path));
  assert_true(ngtcp2_path_eq(&new_path1.path, &conn->dcid.current.ps.path));
  assert_true(ngtcp2_cid_eq(&zerolen_cid, &conn->dcid.current.cid));

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  fr.path_response.type = NGTCP2_FRAME_PATH_RESPONSE;
  memcpy(fr.path_response.data,
         ((ngtcp2_pv_entry *)ngtcp2_ringbuf_get(&conn->pv->ents.rb, 0))->data,
         sizeof(fr.path_response.data));

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &new_path1.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_not_null(conn->pv);
  assert_true(ngtcp2_path_eq(&null_path.path, &conn->pv->dcid.ps.path));
  assert_true(ngtcp2_path_eq(&new_path1.path, &conn->dcid.current.ps.path));
  assert_true(ngtcp2_cid_eq(&zerolen_cid, &conn->dcid.current.cid));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_client_connection_migration(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_tstamp t = 900;
  ngtcp2_frame fr[2];
  int rv;
  static const ngtcp2_cid cid = {
    .datalen = 4,
    .data = {0x0F, 0x00, 0x00, 0x00},
  };
  static const ngtcp2_stateless_reset_token token = {
    .data = {0xFF},
  };
  my_user_data ud;
  ngtcp2_ssize spktlen;
  ngtcp2_path_storage to_path;
  ngtcp2_tpe tpe;
  ngtcp2_path_history_entry *ph_ent;

  /* immediate migration */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr[0].new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 1,
    .cid = cid,
    .token = token,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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

  fr[0].path_response.type = NGTCP2_FRAME_PATH_RESPONSE;
  memset(fr[0].path_response.data, 0, sizeof(fr[0].path_response.data));

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_null(conn->pv);
  assert_true(ngtcp2_path_eq(&to_path.path, &conn->dcid.current.ps.path));
  assert_ptr_equal(&ud, conn->dcid.current.ps.path.user_data);
  assert_true(ngtcp2_cid_eq(&cid, &conn->dcid.current.cid));

  ngtcp2_conn_del(conn);

  /* migrate after successful path validation */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr[0].new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 1,
    .cid = cid,
    .token = token,
  };
  fr[1].new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 2,
    .cid =
      {
        .datalen = 4,
        .data = {0x0E, 0x00, 0x00, 0x00},
      },
    .token = token,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), fr, 2);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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

  fr[0].path_response.type = NGTCP2_FRAME_PATH_RESPONSE;
  memset(fr[0].path_response.data, 0, sizeof(fr[0].path_response.data));

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_null(conn->pv);
  assert_true(ngtcp2_path_eq(&to_path.path, &conn->dcid.current.ps.path));
  assert_ptr_equal(&ud, conn->dcid.current.ps.path.user_data);
  assert_true(ngtcp2_cid_eq(&cid, &conn->dcid.current.cid));
  assert_size(1, ==, ngtcp2_ringbuf_len(&conn->path_history.rb));

  ph_ent = ngtcp2_ringbuf_get(&conn->path_history.rb, 0);

  assert_true(ngtcp2_path_eq(&null_path.path, &ph_ent->ps.path));
  assert_size(NGTCP2_MAX_UDP_PAYLOAD_SIZE, ==, ph_ent->max_udp_payload_size);

  /* Migrate back to the original path.  Path validation is skipped
     because the path has been validated. */
  rv = ngtcp2_conn_initiate_migration(conn, &null_path.path, ++t);

  assert_int(0, ==, rv);
  assert_null(conn->pv);
  assert_true(ngtcp2_path_eq(&null_path.path, &conn->dcid.current.ps.path));
  assert_true(conn->dcid.current.flags & NGTCP2_DCID_FLAG_PATH_VALIDATED);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_path_challenge(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 11;
  ngtcp2_frame fr;
  ngtcp2_frame frs[2];
  int rv;
  static const ngtcp2_cid cid = {
    .datalen = 4,
    .data = {0x0F, 0x00, 0x00, 0x00},
  };
  static const ngtcp2_stateless_reset_token token = {
    .data = {0xFF},
  };
  const uint8_t data[] = {0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8};
  const uint8_t data2[] = {0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF9};
  ngtcp2_path_storage ps;
  ngtcp2_ssize shdlen;
  ngtcp2_pkt_hd hd;
  ngtcp2_dcid *dcid;
  int64_t stream_id;
  ngtcp2_transport_params params;
  ngtcp2_tpe tpe;
  conn_options opts;

  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 1,
    .cid = cid,
    .token = token,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  frs[0].path_challenge.type = NGTCP2_FRAME_PATH_CHALLENGE;
  memcpy(frs[0].path_challenge.data, data, sizeof(frs[0].path_challenge.data));
  frs[1].padding = (ngtcp2_padding){
    .type = NGTCP2_FRAME_PADDING,
    .len = 1200,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 2);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, <, ngtcp2_ringbuf_len(&conn->rx.path_challenge.rb));

  ngtcp2_path_storage_zero(&ps);

  spktlen = ngtcp2_conn_write_pkt(conn, &ps.path, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1200, <=, spktlen);
  assert_true(ngtcp2_path_eq(&new_path.path, &ps.path));
  assert_size(0, ==, ngtcp2_ringbuf_len(&conn->rx.path_challenge.rb));
  assert_size(1, ==, ngtcp2_dcidtr_bound_len(&conn->dcid.dtr));

  dcid = ngtcp2_ringbuf_get(&conn->dcid.dtr.bound.rb, 0);

  assert_uint64((uint64_t)spktlen, ==, dcid->bytes_sent);

  shdlen = ngtcp2_pkt_decode_hd_short(&hd, buf, (size_t)spktlen, cid.datalen);

  assert_ptrdiff(0, <, shdlen);
  assert_true(ngtcp2_cid_eq(&cid, &hd.dcid));

  /* Use same bound DCID for PATH_CHALLENGE from the same path. */
  fr.path_challenge.type = NGTCP2_FRAME_PATH_CHALLENGE;
  memcpy(fr.path_challenge.data, data2, sizeof(fr.path_challenge.data));

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, <, ngtcp2_ringbuf_len(&conn->rx.path_challenge.rb));

  ngtcp2_path_storage_zero(&ps);

  spktlen = ngtcp2_conn_write_pkt(conn, &ps.path, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_true(ngtcp2_path_eq(&new_path.path, &ps.path));
  assert_size(0, ==, ngtcp2_ringbuf_len(&conn->rx.path_challenge.rb));
  assert_size(1, ==, ngtcp2_dcidtr_bound_len(&conn->dcid.dtr));

  shdlen = ngtcp2_pkt_decode_hd_short(&hd, buf, (size_t)spktlen, cid.datalen);

  assert_ptrdiff(0, <, shdlen);
  assert_true(ngtcp2_cid_eq(&cid, &hd.dcid));

  ngtcp2_conn_del(conn);

  /* PATH_CHALLENGE from the current path */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 1,
    .cid = cid,
    .token = token,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  frs[0].path_challenge.type = NGTCP2_FRAME_PATH_CHALLENGE;
  memcpy(frs[0].path_challenge.data, data, sizeof(frs[0].path_challenge.data));
  frs[1].padding = (ngtcp2_padding){
    .type = NGTCP2_FRAME_PADDING,
    .len = 1200,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 2);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, <, ngtcp2_ringbuf_len(&conn->rx.path_challenge.rb));

  ngtcp2_path_storage_zero(&ps);

  spktlen = ngtcp2_conn_write_pkt(conn, &ps.path, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1200, <=, spktlen);
  assert_true(ngtcp2_path_eq(&null_path.path, &ps.path));
  assert_size(0, ==, ngtcp2_ringbuf_len(&conn->rx.path_challenge.rb));
  assert_size(0, ==, ngtcp2_dcidtr_bound_len(&conn->dcid.dtr));
  assert_uint64((uint64_t)spktlen, ==, conn->dcid.current.bytes_sent);

  ngtcp2_conn_del(conn);

  /* PATH_CHALLENGE from the current path is padded at least 1200 with
     NGTCP2_WRITE_STREAM_FLAG_MORE. */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 1,
    .cid = cid,
    .token = token,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  frs[0].path_challenge.type = NGTCP2_FRAME_PATH_CHALLENGE;
  memcpy(frs[0].path_challenge.data, data, sizeof(frs[0].path_challenge.data));
  frs[1].padding = (ngtcp2_padding){
    .type = NGTCP2_FRAME_PADDING,
    .len = 1200,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 2);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, <, ngtcp2_ringbuf_len(&conn->rx.path_challenge.rb));

  rv = ngtcp2_conn_open_uni_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  ngtcp2_path_storage_zero(&ps);

  spktlen = ngtcp2_conn_write_stream(conn, &ps.path, NULL, buf, sizeof(buf),
                                     NULL, NGTCP2_WRITE_STREAM_FLAG_MORE,
                                     stream_id, null_data, 10, ++t);

  assert_ptrdiff(NGTCP2_ERR_WRITE_MORE, ==, spktlen);

  spktlen = ngtcp2_conn_write_pkt(conn, &ps.path, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1200, <=, spktlen);
  assert_true(ngtcp2_path_eq(&null_path.path, &ps.path));
  assert_size(0, ==, ngtcp2_ringbuf_len(&conn->rx.path_challenge.rb));
  assert_size(0, ==, ngtcp2_dcidtr_bound_len(&conn->dcid.dtr));
  assert_uint64((uint64_t)spktlen, ==, conn->dcid.current.bytes_sent);

  ngtcp2_conn_del(conn);

  /* PATH_CHALLENGE to new local address should be ignored with server
     disable_active_migration */
  server_default_transport_params(&params);
  params.disable_active_migration = 1;

  opts = (conn_options){
    .params = &params,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 1,
    .cid = cid,
    .token = token,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  frs[0].path_challenge.type = NGTCP2_FRAME_PATH_CHALLENGE;
  memcpy(frs[0].path_challenge.data, data, sizeof(frs[0].path_challenge.data));
  frs[1].padding = (ngtcp2_padding){
    .type = NGTCP2_FRAME_PADDING,
    .len = 1200,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 2);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, ==, ngtcp2_ringbuf_len(&conn->rx.path_challenge.rb));
  assert_int64(0, ==, conn->pktns.acktr.max_pkt_num);

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

  opts = (conn_options){
    .params = &params,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 1,
    .cid = cid,
    .token = token,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  frs[0].path_challenge.type = NGTCP2_FRAME_PATH_CHALLENGE;
  memcpy(frs[0].path_challenge.data, data, sizeof(frs[0].path_challenge.data));
  frs[1].padding = (ngtcp2_padding){
    .type = NGTCP2_FRAME_PADDING,
    .len = 1200,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 2);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, <, ngtcp2_ringbuf_len(&conn->rx.path_challenge.rb));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_disable_active_migration(void) {
  ngtcp2_conn *conn;
  ngtcp2_transport_params params, remote_params;
  conn_options opts;
  ngtcp2_path_storage path1, path2;
  ngtcp2_frame fr;
  ngtcp2_tpe tpe;
  uint8_t buf[1200];
  size_t pktlen;
  int rv;

  path_init(&path1, 1, 0, 0, 0);
  path_init(&path2, 2, 0, 0, 0);

  /* If a remote endpoint disables active migration, and a packet is
     received on preferred address, the packet is accepted. */
  server_default_transport_params(&params);
  params.preferred_addr_present = 1;
  params.preferred_addr.ipv4_present = 1;
  memcpy(&params.preferred_addr.ipv4, path1.path.local.addr,
         sizeof(params.preferred_addr.ipv4));

  server_default_remote_transport_params(&remote_params);
  remote_params.disable_active_migration = 1;

  opts = (conn_options){
    .params = &params,
    .remote_params = &remote_params,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.ping.type = NGTCP2_FRAME_PING;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &path1.path, NULL, buf, pktlen, 0);

  assert_int(0, ==, rv);
  assert_int64(0, ==, conn->pktns.acktr.max_pkt_num);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_key_update(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 19393;
  ngtcp2_frame fr;
  int rv;
  int64_t stream_id;
  ngtcp2_ssize nwrite;
  ngtcp2_tpe tpe;

  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.flags = NGTCP2_PKT_FLAG_KEY_PHASE;

  /* The remote endpoint initiates key update */
  fr.ping.type = NGTCP2_FRAME_PING;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
  };

  tpe.app.ckm = conn->pktns.crypto.rx.ckm;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  int rv;
  ngtcp2_tpe tpe;

  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .offset = 1000000,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .base = null_data,
    .len = 1,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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
  ngtcp2_tpe tpe;

  /* Retransmit first Initial on PTO timer */
  setup_handshake_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

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

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  ngtcp2_frame frs[2];
  int rv;
  ngtcp2_ksl_it it;
  ngtcp2_rtb_entry *ent;
  int64_t ack_pkt_num;
  int64_t stream_id;
  ngtcp2_ssize nwrite;
  ngtcp2_ssize datalen;
  ngtcp2_tpe tpe;
  ngtcp2_callbacks callbacks;
  conn_options opts;

  server_default_callbacks(&callbacks);
  callbacks.recv_crypto_data = recv_crypto_data;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_handshake_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);

  frs[0].stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 123,
    .base = null_data,
  };

  frs[1].padding = (ngtcp2_padding){
    .type = NGTCP2_FRAME_PADDING,
    .len = 1005,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), frs, 2);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = 2,
  };

  tpe.dcid = conn->oscid;
  tpe.handshake.ckm = conn->hs_pktns->crypto.rx.ckm;

  pktlen = ngtcp2_tpe_write_handshake(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  assert_int(0, ==, rv);

  t += 40 * NGTCP2_MILLISECONDS;

  ngtcp2_conn_on_loss_detection_timer(conn, t);

  assert_size(0, ==, conn->hs_pktns->rtb.probe_pkt_left);

  /* Retransmits the contents of lost packet */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_ksl_begin(&conn->hs_pktns->rtb.ents);
  ent = ngtcp2_ksl_it_get(&it);

  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, ent->frc->fr.hd.type);
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

  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, ent->frc->fr.hd.type);
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

  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, ent->frc->fr.hd.type);
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
  server_default_callbacks(&callbacks);
  callbacks.recv_crypto_data = recv_crypto_data;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_handshake_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);

  frs[0].stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 123,
    .base = null_data,
  };

  frs[1].padding = (ngtcp2_padding){
    .type = NGTCP2_FRAME_PADDING,
    .len = 1005,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), frs, 2);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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

  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, ent->frc->fr.hd.type);
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

  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, ent->frc->fr.hd.type);
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

  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, ent->frc->fr.hd.type);
  assert_uint64(987, ==, ent->frc->fr.stream.offset);
  assert_uint64(
    991, ==,
    ngtcp2_vec_len(ent->frc->fr.stream.data, ent->frc->fr.stream.datacnt));
  assert_int64(4, ==, ent->hd.pkt_num);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);
  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_ksl_begin(&conn->hs_pktns->rtb.ents);
  ent = ngtcp2_ksl_it_get(&it);

  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, ent->frc->fr.hd.type);
  assert_uint64(1978, ==, ent->frc->fr.stream.offset);
  assert_uint64(
    192, ==,
    ngtcp2_vec_len(ent->frc->fr.stream.data, ent->frc->fr.stream.datacnt));
  assert_int64(5, ==, ent->hd.pkt_num);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);
  assert_ptrdiff(0, ==, spktlen);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
  };

  tpe.dcid = conn->oscid;
  tpe.handshake.ckm = conn->hs_pktns->crypto.rx.ckm;

  pktlen = ngtcp2_tpe_write_handshake(&tpe, buf, sizeof(buf), &fr, 1);

  t += NGTCP2_MILLISECONDS;
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  assert_int(0, ==, rv);

  t += 40 * NGTCP2_MILLISECONDS;

  ngtcp2_conn_on_loss_detection_timer(conn, t);

  assert_size(2, ==, conn->hs_pktns->rtb.probe_pkt_left);

  /* 3rd PTO */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_ksl_begin(&conn->hs_pktns->rtb.ents);
  ent = ngtcp2_ksl_it_get(&it);

  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, ent->frc->fr.hd.type);
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

  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, ent->frc->fr.hd.type);
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
  client_default_callbacks(&callbacks);
  callbacks.recv_crypto_data = recv_crypto_data_client_handshake;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_handshake_client_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  t = 0;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1200, <=, spktlen);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 117,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  tpe.handshake.ckm = conn->hs_pktns->crypto.rx.ckm;

  pktlen = ngtcp2_tpe_write_handshake(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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
    pktlen = ngtcp2_tpe_write_handshake(&tpe, buf, sizeof(buf), &fr, 1);

    rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

    assert_int(0, ==, rv);

    t += conn->cstat.smoothed_rtt;
    spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t);

    assert_ptrdiff(0, <, spktlen);
  }

  ack_pkt_num = conn->hs_pktns->tx.last_pkt_num;

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = ack_pkt_num,
  };

  pktlen = ngtcp2_tpe_write_handshake(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_false(ngtcp2_strm_streamfrq_empty(&conn->hs_pktns->crypto.strm));
  assert_uint64(conn->cstat.bytes_in_flight, >, conn->cstat.cwnd);

  /* Resending Handshake CRYPTO is allowed even if it exceeds CWND in
     this situation. */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_true(ngtcp2_strm_streamfrq_empty(&conn->hs_pktns->crypto.strm));

  /* Check that Handshake ACK only packet can be sent anytime */
  fr.ping.type = NGTCP2_FRAME_PING;

  pktlen = ngtcp2_tpe_write_handshake(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  ngtcp2_conn_del(conn);

  /* Client can send PTO Initial packet even if reduced CWND is less
     than in-flight bytes which are mostly occupied by 0-RTT
     packets. */
  client_early_callbacks(&callbacks);
  callbacks.client_initial = client_initial_large_crypto_early_data;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_early_client_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

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

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = 1,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  t += 30 * NGTCP2_MILLISECONDS;

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

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
  ngtcp2_tpe tpe;
  conn_options opts;
  ngtcp2_transport_params remote_params;

  /* Probe packet after DATAGRAM */
  client_default_remote_transport_params(&remote_params);
  remote_params.max_datagram_frame_size = 65535;

  opts = (conn_options){
    .remote_params = &remote_params,
  };

  setup_default_client_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(1, ==, conn->pktns.rtb.num_ack_eliciting);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t++);

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
  ngtcp2_tpe_init_conn(&tpe, conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(1, ==, conn->pktns.rtb.num_ack_eliciting);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t++);

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

  assert_uint64(NGTCP2_FRAME_RESET_STREAM, ==, ent->frc->fr.hd.type);
  assert_null(ent->frc->next);

  ngtcp2_ksl_it_next(&it);
  ent = ngtcp2_ksl_it_get(&it);

  assert_uint64(NGTCP2_FRAME_RESET_STREAM, ==, ent->frc->fr.hd.type);
  assert_null(ent->frc->next);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_client_initial_retry(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  ngtcp2_tstamp t = 0;
  int rv;
  ngtcp2_tpe tpe;

  setup_handshake_server(&conn);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .offset = 1,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1245,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_RETRY, ==, rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_client_initial_token(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  ngtcp2_tstamp t = 0;
  int rv;
  const uint8_t raw_token[] = {0xFF, 0x12, 0x31, 0x04, 0xAB};
  ngtcp2_tpe tpe;
  ngtcp2_settings settings;
  conn_options opts;

  server_handshake_settings(&settings);
  settings.token = raw_token;
  settings.tokenlen = sizeof(raw_token);

  opts = (conn_options){
    .settings = &settings,
  };

  setup_handshake_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1181,
    .base = null_data,
  };

  tpe.token = raw_token;
  tpe.tokenlen = sizeof(raw_token);

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_uint64(1181, ==, ngtcp2_strm_rx_offset(&conn->in_pktns->crypto.strm));

  ngtcp2_conn_del(conn);

  /* Specifying invalid token lets server drop the packet */
  server_handshake_settings(&settings);
  settings.token = raw_token;
  settings.tokenlen = sizeof(raw_token) - 1;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_handshake_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1179,
    .base = null_data,
  };

  tpe.token = raw_token;
  tpe.tokenlen = sizeof(raw_token);

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_DROP_CONN, ==, rv);
  assert_uint64(0, ==, ngtcp2_strm_rx_offset(&conn->in_pktns->crypto.strm));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_get_active_dcid(void) {
  ngtcp2_conn *conn;
  ngtcp2_cid_token2 cid_token[2];
  ngtcp2_cid dcid;
  const ngtcp2_cid new_dcid = {
    .datalen = 4,
    .data = {0xDE, 0xAD, 0xBE, 0xEF},
  };
  static const ngtcp2_stateless_reset_token token =
    make_client_stateless_reset_token();
  ngtcp2_tpe tpe;
  ngtcp2_frame fr, frs[3];
  size_t pktlen;
  uint8_t buf[1200];
  int rv;
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 0;
  ngtcp2_transport_params remote_params;
  conn_options opts;

  dcid_init(&dcid);

  {
    /* Compatibility test */
    ngtcp2_cid_token regacy_cid_token[1];

    setup_default_client(&conn);

    assert_size(1, ==, ngtcp2_conn_get_active_dcid(conn, NULL));
    assert_size(1, ==, ngtcp2_conn_get_active_dcid(conn, regacy_cid_token));
    assert_uint64(0, ==, regacy_cid_token[0].seq);
    assert_true(ngtcp2_cid_eq(&dcid, &regacy_cid_token[0].cid));
    assert_true(ngtcp2_path_eq(&null_path.path, &regacy_cid_token[0].ps.path));
    assert_true(regacy_cid_token[0].token_present);
    assert_memory_equal(NGTCP2_STATELESS_RESET_TOKENLEN, token.data,
                        regacy_cid_token[0].token);

    ngtcp2_conn_del(conn);
  }

  setup_default_client(&conn);

  assert_size(1, ==, ngtcp2_conn_get_active_dcid2(conn, NULL));
  assert_size(1, ==, ngtcp2_conn_get_active_dcid2(conn, cid_token));
  assert_uint64(0, ==, cid_token[0].seq);
  assert_true(ngtcp2_cid_eq(&dcid, &cid_token[0].cid));
  assert_true(ngtcp2_path_eq(&null_path.path, &cid_token[0].ps.path));
  assert_true(cid_token[0].token_present);
  assert_true(ngtcp2_stateless_reset_token_eq(&token, &cid_token[0].token));

  ngtcp2_conn_del(conn);

  /* zero-length Destination Connection ID */
  ngtcp2_cid_zero(&dcid);

  server_default_remote_transport_params(&remote_params);
  remote_params.initial_scid = dcid;

  opts = (conn_options){
    .dcid = &dcid,
    .remote_params = &remote_params,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  assert_size(1, ==, ngtcp2_conn_get_active_dcid2(conn, NULL));

  fr.path_challenge.type = NGTCP2_FRAME_PATH_CHALLENGE;
  memset(fr.path_challenge.data, 0, sizeof(fr.path_challenge.data));

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, NULL, buf, pktlen, 1);

  assert_int(0, ==, rv);

  fr.ping.type = NGTCP2_FRAME_PING;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, NULL, buf, pktlen, 1);

  assert_int(0, ==, rv);
  assert_not_null(conn->pv);
  assert_size(1, ==, ngtcp2_conn_get_active_dcid2(conn, NULL));
  assert_size(1, ==, ngtcp2_conn_get_active_dcid2(conn, cid_token));
  assert_uint64(0, ==, cid_token[0].seq);
  assert_true(ngtcp2_cid_eq(&dcid, &cid_token[0].cid));

  ngtcp2_conn_del(conn);

  /* With path validation and retired Connection ID */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(1, <, ngtcp2_ksl_len(&conn->scid.set));

  fr.new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 1,
    .cid = new_dcid,
    .token = token,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(1, ==, ngtcp2_conn_get_active_dcid2(conn, NULL));

  frs[0].ping.type = NGTCP2_FRAME_PING;
  frs[1].padding = (ngtcp2_padding){
    .len = 1000,
  };
  frs[2].ack = (ngtcp2_ack){
    .largest_ack = conn->pktns.tx.last_pkt_num,
    .first_ack_range = 1,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 3);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_not_null(conn->pv);
  assert_size(2, ==, ngtcp2_conn_get_active_dcid2(conn, NULL));
  assert_size(2, ==, ngtcp2_conn_get_active_dcid2(conn, cid_token));
  assert_uint64(1, ==, cid_token[0].seq);
  assert_true(ngtcp2_cid_eq(&new_dcid, &cid_token[0].cid));
  assert_true(ngtcp2_path_eq(&new_path.path, &cid_token[0].ps.path));
  assert_true(ngtcp2_stateless_reset_token_eq(&token, &cid_token[0].token));

  dcid_init(&dcid);

  assert_uint64(0, ==, cid_token[1].seq);
  assert_true(ngtcp2_cid_eq(&dcid, &cid_token[1].cid));
  assert_true(ngtcp2_path_eq(&null_path.path, &cid_token[1].ps.path));
  assert_false(cid_token[1].token_present);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(sizeof(buf), ==, spktlen);

  frs[0].path_response = (ngtcp2_path_response){
    .type = NGTCP2_FRAME_PATH_RESPONSE,
  };
  frs[1].ack = (ngtcp2_ack){
    .largest_ack = conn->pktns.tx.last_pkt_num,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 2);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  /* On successful path validation, the next path validation against
     old path begins. */
  assert_not_null(conn->pv);
  assert_false(conn->pv->flags & NGTCP2_PV_FLAG_FALLBACK_PRESENT);
  assert_size(2, ==, ngtcp2_conn_get_active_dcid2(conn, NULL));
  assert_size(2, ==, ngtcp2_conn_get_active_dcid2(conn, cid_token));
  assert_uint64(1, ==, cid_token[0].seq);
  assert_true(ngtcp2_cid_eq(&new_dcid, &cid_token[0].cid));
  assert_true(ngtcp2_path_eq(&new_path.path, &cid_token[0].ps.path));
  assert_true(ngtcp2_stateless_reset_token_eq(&token, &cid_token[0].token));

  dcid_init(&dcid);

  assert_uint64(0, ==, cid_token[1].seq);
  assert_true(ngtcp2_cid_eq(&dcid, &cid_token[1].cid));
  assert_true(ngtcp2_path_eq(&null_path.path, &cid_token[1].ps.path));
  assert_false(cid_token[1].token_present);
  assert_size(0, ==, ngtcp2_ringbuf_len(&conn->dcid.dtr.retired.rb));

  /* Wait for the path validation to stop */
  for (;;) {
    t = ngtcp2_conn_get_expiry(conn);

    assert_uint64(UINT64_MAX, !=, t);

    rv = ngtcp2_conn_handle_expiry(conn, t);

    assert_int(0, ==, rv);

    spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t);

    assert_ptrdiff(0, <=, spktlen);

    if (ngtcp2_ringbuf_len(&conn->dcid.dtr.retired.rb)) {
      break;
    }
  }

  assert_null(conn->pv);
  assert_size(2, ==, ngtcp2_conn_get_active_dcid2(conn, NULL));
  assert_size(2, ==, ngtcp2_conn_get_active_dcid2(conn, cid_token));
  assert_uint64(1, ==, cid_token[0].seq);
  assert_true(ngtcp2_cid_eq(&new_dcid, &cid_token[0].cid));
  assert_true(ngtcp2_path_eq(&new_path.path, &cid_token[0].ps.path));
  assert_true(ngtcp2_stateless_reset_token_eq(&token, &cid_token[0].token));

  dcid_init(&dcid);

  assert_uint64(0, ==, cid_token[1].seq);
  assert_true(ngtcp2_cid_eq(&dcid, &cid_token[1].cid));
  assert_true(ngtcp2_path_eq(&null_path.path, &cid_token[1].ps.path));
  assert_false(cid_token[1].token_present);

  /* Wait for old Connection ID to retire */
  for (;;) {
    t = ngtcp2_conn_get_expiry(conn);

    assert_uint64(UINT64_MAX, !=, t);

    rv = ngtcp2_conn_handle_expiry(conn, t);

    assert_int(0, ==, rv);

    spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), t);

    assert_ptrdiff(0, <=, spktlen);

    if (ngtcp2_ringbuf_len(&conn->dcid.dtr.retired.rb) == 0) {
      break;
    }
  }

  assert_size(1, ==, ngtcp2_conn_get_active_dcid2(conn, NULL));
  assert_size(1, ==, ngtcp2_conn_get_active_dcid2(conn, cid_token));
  assert_uint64(1, ==, cid_token[0].seq);
  assert_true(ngtcp2_cid_eq(&new_dcid, &cid_token[0].cid));
  assert_true(ngtcp2_path_eq(&new_path.path, &cid_token[0].ps.path));
  assert_true(ngtcp2_stateless_reset_token_eq(&token, &cid_token[0].token));

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
  ngtcp2_settings settings;
  conn_options opts;

  setup_handshake_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  dcid = ngtcp2_conn_get_dcid(conn);

  nsv[0] = 0xFFFFFFFF;

  spktlen = ngtcp2_pkt_write_version_negotiation(
    buf, sizeof(buf), 0xFE, conn->oscid.data, conn->oscid.datalen, dcid->data,
    dcid->datalen, nsv, 1);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, (size_t)spktlen,
                            ++t);

  assert_int(NGTCP2_ERR_RECV_VERSION_NEGOTIATION, ==, rv);

  ngtcp2_conn_del(conn);

  /* Ignore Version Negotiation if it contains version selected by
     client */
  setup_handshake_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  dcid = ngtcp2_conn_get_dcid(conn);

  nsv[0] = 0xFFFFFFF0;
  nsv[1] = conn->client_chosen_version;

  spktlen = ngtcp2_pkt_write_version_negotiation(
    buf, sizeof(buf), 0x50, conn->oscid.data, conn->oscid.datalen, dcid->data,
    dcid->datalen, nsv, 2);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, (size_t)spktlen,
                            ++t);

  assert_int(0, ==, rv);

  ngtcp2_conn_del(conn);

  /* Ignore Version Negotiation if client reacted upon Version
     Negotiation */
  client_handshake_settings(&settings);
  settings.original_version = NGTCP2_PROTO_VER_V2;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_handshake_client_with_options(&conn, opts);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  dcid = ngtcp2_conn_get_dcid(conn);

  nsv[0] = 0xFFFFFFFF;

  spktlen = ngtcp2_pkt_write_version_negotiation(
    buf, sizeof(buf), 0xFE, conn->oscid.data, conn->oscid.datalen, dcid->data,
    dcid->datalen, nsv, 1);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, (size_t)spktlen,
                            ++t);

  assert_int(0, ==, rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_send_initial_token(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  ngtcp2_settings settings;
  uint8_t token[] = "this is token";
  ngtcp2_ssize spktlen, shdlen;
  ngtcp2_tstamp t = 0;
  ngtcp2_pkt_hd hd;
  conn_options opts = {
    .settings = &settings,
  };

  client_default_settings(&settings);

  settings.token = token;
  settings.tokenlen = sizeof(token);

  setup_handshake_client_with_options(&conn, opts);

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
  ngtcp2_settings settings;
  conn_options opts;

  dcid_init(&dcid);

  /* client: Successful case */
  setup_handshake_client(&conn);

  conn->negotiated_version = conn->client_chosen_version;

  params = (ngtcp2_transport_params){
    .active_connection_id_limit = NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT,
    .max_udp_payload_size = 1450,
    .initial_scid = conn->dcid.current.cid,
    .initial_scid_present = 1,
    .original_dcid = conn->rcid,
    .original_dcid_present = 1,
  };

  rv = ngtcp2_conn_set_remote_transport_params(conn, &params);

  assert_int(0, ==, rv);

  ngtcp2_conn_del(conn);

  /* client: Wrong original_dcid */
  setup_handshake_client(&conn);

  conn->negotiated_version = conn->client_chosen_version;

  params = (ngtcp2_transport_params){
    .active_connection_id_limit = NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT,
    .max_udp_payload_size = 1450,
    .initial_scid = conn->dcid.current.cid,
    .initial_scid_present = 1,
    .original_dcid_present = 1,
  };

  rv = ngtcp2_conn_set_remote_transport_params(conn, &params);

  assert_int(NGTCP2_ERR_TRANSPORT_PARAM, ==, rv);

  ngtcp2_conn_del(conn);

  /* client: Wrong initial_scid */
  setup_handshake_client(&conn);

  conn->negotiated_version = conn->client_chosen_version;

  params = (ngtcp2_transport_params){
    .active_connection_id_limit = NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT,
    .max_udp_payload_size = 1450,
    .initial_scid_present = 1,
    .original_dcid = conn->rcid,
    .original_dcid_present = 1,
  };

  rv = ngtcp2_conn_set_remote_transport_params(conn, &params);

  assert_int(NGTCP2_ERR_TRANSPORT_PARAM, ==, rv);

  ngtcp2_conn_del(conn);

  /* client: Receiving retry_scid when retry is not attempted */
  setup_handshake_client(&conn);

  conn->negotiated_version = conn->client_chosen_version;

  params = (ngtcp2_transport_params){
    .active_connection_id_limit = NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT,
    .max_udp_payload_size = 1450,
    .initial_scid = conn->dcid.current.cid,
    .initial_scid_present = 1,
    .original_dcid = conn->rcid,
    .original_dcid_present = 1,
    .retry_scid_present = 1,
  };

  rv = ngtcp2_conn_set_remote_transport_params(conn, &params);

  assert_int(NGTCP2_ERR_TRANSPORT_PARAM, ==, rv);

  ngtcp2_conn_del(conn);

  /* client: Receiving retry_scid */
  setup_handshake_client(&conn);

  conn->flags |= NGTCP2_CONN_FLAG_RECV_RETRY;
  conn->retry_scid = dcid;
  conn->negotiated_version = conn->client_chosen_version;

  params = (ngtcp2_transport_params){
    .active_connection_id_limit = NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT,
    .max_udp_payload_size = 1450,
    .initial_scid = conn->dcid.current.cid,
    .initial_scid_present = 1,
    .original_dcid = conn->rcid,
    .original_dcid_present = 1,
    .retry_scid_present = 1,
    .retry_scid = dcid,
  };

  rv = ngtcp2_conn_set_remote_transport_params(conn, &params);

  assert_int(0, ==, rv);

  ngtcp2_conn_del(conn);

  /* client: Not receiving retry_scid when retry is attempted */
  setup_handshake_client(&conn);

  conn->flags |= NGTCP2_CONN_FLAG_RECV_RETRY;
  conn->retry_scid = dcid;
  conn->negotiated_version = conn->client_chosen_version;

  params = (ngtcp2_transport_params){
    .active_connection_id_limit = NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT,
    .max_udp_payload_size = 1450,
    .initial_scid = conn->dcid.current.cid,
    .initial_scid_present = 1,
    .original_dcid = conn->rcid,
    .original_dcid_present = 1,
  };

  rv = ngtcp2_conn_set_remote_transport_params(conn, &params);

  assert_int(NGTCP2_ERR_TRANSPORT_PARAM, ==, rv);

  ngtcp2_conn_del(conn);

  /* client: Special handling for QUIC v1 regarding Version
     Negotiation */
  client_handshake_settings(&settings);
  settings.original_version = NGTCP2_PROTO_VER_V2;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_handshake_client_with_options(&conn, opts);

  conn->negotiated_version = conn->client_chosen_version;

  params = (ngtcp2_transport_params){
    .active_connection_id_limit = NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT,
    .max_udp_payload_size = 1450,
    .initial_scid = conn->dcid.current.cid,
    .initial_scid_present = 1,
    .original_dcid = conn->rcid,
    .original_dcid_present = 1,
  };

  rv = ngtcp2_conn_set_remote_transport_params(conn, &params);

  assert_int(0, ==, rv);

  ngtcp2_conn_del(conn);

  /* client: No version_information after Version Negotiation */
  client_handshake_settings(&settings);
  settings.original_version = NGTCP2_PROTO_VER_V1;

  opts = (conn_options){
    .settings = &settings,
    .client_chosen_version = NGTCP2_PROTO_VER_V2,
  };

  setup_handshake_client_with_options(&conn, opts);

  conn->negotiated_version = conn->client_chosen_version;

  params = (ngtcp2_transport_params){
    .active_connection_id_limit = NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT,
    .max_udp_payload_size = 1450,
    .initial_scid = conn->dcid.current.cid,
    .initial_scid_present = 1,
    .original_dcid = conn->rcid,
    .original_dcid_present = 1,
  };

  rv = ngtcp2_conn_set_remote_transport_params(conn, &params);

  assert_int(NGTCP2_ERR_VERSION_NEGOTIATION_FAILURE, ==, rv);

  ngtcp2_conn_del(conn);

  /* client: available_versions includes the version that the client
     initially attempted. */
  client_handshake_settings(&settings);
  settings.original_version = NGTCP2_PROTO_VER_V2;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_handshake_client_with_options(&conn, opts);

  conn->negotiated_version = conn->client_chosen_version;

  ngtcp2_put_uint32be(available_versions, NGTCP2_PROTO_VER_V1);
  ngtcp2_put_uint32be(available_versions + sizeof(uint32_t),
                      NGTCP2_PROTO_VER_V2);

  params = (ngtcp2_transport_params){
    .active_connection_id_limit = NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT,
    .max_udp_payload_size = 1450,
    .initial_scid = conn->dcid.current.cid,
    .initial_scid_present = 1,
    .original_dcid = conn->rcid,
    .original_dcid_present = 1,
    .version_info_present = 1,
    .version_info =
      {
        .chosen_version = conn->negotiated_version,
        .available_versions = available_versions,
        .available_versionslen = 2 * sizeof(uint32_t),
      },
  };

  rv = ngtcp2_conn_set_remote_transport_params(conn, &params);

  assert_int(NGTCP2_ERR_VERSION_NEGOTIATION_FAILURE, ==, rv);

  ngtcp2_conn_del(conn);

  /* client: client is unable to choose client chosen version from
     server's available_versions and chosen version. */
  client_handshake_settings(&settings);
  settings.original_version = NGTCP2_PROTO_VER_V2;
  settings.preferred_versions = NULL;
  settings.preferred_versionslen = 0;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_handshake_client_with_options(&conn, opts);

  conn->negotiated_version = NGTCP2_PROTO_VER_V1;

  ngtcp2_put_uint32be(available_versions, NGTCP2_PROTO_VER_V2);

  params = (ngtcp2_transport_params){
    .active_connection_id_limit = NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT,
    .max_udp_payload_size = 1450,
    .initial_scid = conn->dcid.current.cid,
    .initial_scid_present = 1,
    .original_dcid = conn->rcid,
    .original_dcid_present = 1,
    .version_info_present = 1,
    .version_info =
      {
        .chosen_version = conn->negotiated_version,
        .available_versions = available_versions,
        .available_versionslen = sizeof(uint32_t),
      },
  };

  rv = ngtcp2_conn_set_remote_transport_params(conn, &params);

  assert_int(NGTCP2_ERR_VERSION_NEGOTIATION_FAILURE, ==, rv);

  ngtcp2_conn_del(conn);

  /* client: client chooses version which differs from client chosen
     version from server's available_versions and chosen version. */
  client_handshake_settings(&settings);
  settings.original_version = NGTCP2_RESERVED_VERSION_MASK;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_handshake_client_with_options(&conn, opts);

  conn->negotiated_version = NGTCP2_PROTO_VER_V1;

  ngtcp2_put_uint32be(available_versions, NGTCP2_PROTO_VER_V1);
  ngtcp2_put_uint32be(available_versions + sizeof(uint32_t),
                      NGTCP2_PROTO_VER_V2);

  params = (ngtcp2_transport_params){
    .active_connection_id_limit = NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT,
    .max_udp_payload_size = 1450,
    .initial_scid = conn->dcid.current.cid,
    .initial_scid_present = 1,
    .original_dcid = conn->rcid,
    .original_dcid_present = 1,
    .version_info_present = 1,
    .version_info =
      {
        .chosen_version = conn->negotiated_version,
        .available_versions = available_versions,
        .available_versionslen = sizeof(available_versions),
      },
  };

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
  ngtcp2_cid dcid, scid;
  ngtcp2_transport_params remote_params;
  conn_options opts;

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

  /* A packet containing CONNECTION_CLOSE must not be stored in
     ngtcp2_rtb. */
  ngtcp2_cid_init(&dcid, (const uint8_t *)"01234567", 8);
  ngtcp2_cid_init(&scid, (const uint8_t *)"012345678", 9);

  client_default_remote_transport_params(&remote_params);
  remote_params.initial_scid = dcid;
  remote_params.original_dcid = dcid;

  opts = (conn_options){
    .dcid = &dcid,
    .scid = &scid,
    .remote_params = &remote_params,
  };

  setup_default_client_with_options(&conn, opts);

  ngtcp2_ccerr_set_transport_error(&ccerr, NGTCP2_NO_ERROR, NULL, 0);

  spktlen = ngtcp2_conn_write_connection_close(conn, NULL, NULL, buf,
                                               sizeof(buf), &ccerr, 0);

  assert_ptrdiff(0, <, spktlen);
  assert_true(ngtcp2_rtb_empty(&conn->pktns.rtb));

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
  ngtcp2_cid dcid, scid;
  ngtcp2_transport_params remote_params;
  conn_options opts;

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

  /* A packet containing CONNECTION_CLOSE must not be stored in
     ngtcp2_rtb. */
  ngtcp2_cid_init(&dcid, (const uint8_t *)"01234567", 8);
  ngtcp2_cid_init(&scid, (const uint8_t *)"01234567", 8);

  client_default_remote_transport_params(&remote_params);
  remote_params.initial_scid = dcid;
  remote_params.original_dcid = dcid;

  opts = (conn_options){
    .dcid = &dcid,
    .scid = &scid,
    .remote_params = &remote_params,
  };

  setup_default_client_with_options(&conn, opts);

  ngtcp2_ccerr_set_application_error(&ccerr, app_err_code, NULL, 0);

  spktlen = ngtcp2_conn_write_connection_close(conn, NULL, NULL, buf,
                                               sizeof(buf), &ccerr, 0);

  assert_ptrdiff(0, <, spktlen);
  assert_true(ngtcp2_rtb_empty(&conn->pktns.rtb));

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
  ngtcp2_tstamp t = 0;
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_tpe tpe;
  ngtcp2_callbacks callbacks;
  conn_options opts;
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  ngtcp2_crypto_ctx crypto_ctx;

  init_crypto_ctx(&crypto_ctx);

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

  /* Skip frame which is acknowledged by late ACK */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  t = ngtcp2_conn_get_expiry(conn);
  rv = ngtcp2_conn_handle_expiry(conn, t);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);
  ent = ngtcp2_ksl_it_get(&it);

  assert_not_null(ent->frc->binder);
  assert_uint64(NGTCP2_FRAME_NEW_CONNECTION_ID, ==, ent->frc->fr.hd.type);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  t = ngtcp2_conn_get_expiry(conn);

  assert_uint64(UINT64_MAX, !=, t);

  rv = ngtcp2_conn_handle_expiry(conn, t);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, ==, spktlen);

  ngtcp2_conn_del(conn);

  /* Handshaking server: skip frame which is acknowledged by late
     ACK */
  server_default_callbacks(&callbacks);
  callbacks.recv_crypto_data = recv_crypto_data;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_handshake_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 33,
    .base = null_data,
  };

  memset(buf, 0, NGTCP2_MAX_UDP_PAYLOAD_SIZE);
  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf,
                            NGTCP2_MAX_UDP_PAYLOAD_SIZE, ++t);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL,
                                      null_data, 123);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  t = ngtcp2_conn_get_expiry(conn);
  rv = ngtcp2_conn_handle_expiry(conn, t);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_rtb_head(&conn->in_pktns->rtb);
  ent = ngtcp2_ksl_it_get(&it);

  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, ent->frc->fr.hd.type);

  ngtcp2_ksl_it_next(&it);

  assert_false(ngtcp2_ksl_it_end(&it));

  ent = ngtcp2_ksl_it_get(&it);

  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, ent->frc->fr.hd.type);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
  };

  memset(buf, 0, NGTCP2_MAX_UDP_PAYLOAD_SIZE);
  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf,
                            NGTCP2_MAX_UDP_PAYLOAD_SIZE, ++t);

  assert_int(0, ==, rv);

  t = ngtcp2_conn_get_expiry(conn);

  assert_uint64(UINT64_MAX, !=, t);

  rv = ngtcp2_conn_handle_expiry(conn, t);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, ==, spktlen);

  ngtcp2_conn_del(conn);

  /* Handshaking client: skip frame which is acknowledged by late
     ACK, and server address verified client address */
  setup_handshake_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.handshake.ckm = &null_ckm;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 33,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  ngtcp2_conn_set_crypto_ctx(conn, &crypto_ctx);

  rv = ngtcp2_conn_install_rx_handshake_key(conn, &aead_ctx, null_iv,
                                            sizeof(null_iv), &hp_ctx);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_install_tx_handshake_key(conn, &aead_ctx, null_iv,
                                            sizeof(null_iv), &hp_ctx);

  rv = ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,
                                      null_data, 10);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  t += 30 * NGTCP2_MILLISECONDS;

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
  };

  pktlen = ngtcp2_tpe_write_handshake(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,
                                      null_data, 117);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  t = ngtcp2_conn_get_expiry(conn);
  rv = ngtcp2_conn_handle_expiry(conn, t);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_rtb_head(&conn->hs_pktns->rtb);
  ent = ngtcp2_ksl_it_get(&it);

  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, ent->frc->fr.hd.type);

  ngtcp2_ksl_it_next(&it);

  assert_false(ngtcp2_ksl_it_end(&it));

  ent = ngtcp2_ksl_it_get(&it);

  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, ent->frc->fr.hd.type);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = 1,
  };

  pktlen = ngtcp2_tpe_write_handshake(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  t = ngtcp2_conn_get_expiry(conn);

  assert_uint64(UINT64_MAX, !=, t);

  rv = ngtcp2_conn_handle_expiry(conn, t);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, ==, spktlen);

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
  conn_options opts;
  ngtcp2_transport_params remote_params;
  ngtcp2_callbacks callbacks;

  /* DATAGRAM frame must not be reclaimed on PTO */
  client_default_remote_transport_params(&remote_params);
  remote_params.max_datagram_frame_size = 65535;

  client_default_callbacks(&callbacks);
  callbacks.ack_datagram = ack_datagram;

  opts = (conn_options){
    .remote_params = &remote_params,
    .callbacks = &callbacks,
  };

  setup_default_client_with_options(&conn, opts);

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
        assert_uint64(NGTCP2_FRAME_DATAGRAM, !=, frc->fr.hd.type);
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
  ngtcp2_tpe tpe;

  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, &pi, buf, sizeof(buf), 1);

  assert_ptrdiff(0, <, spktlen);
  assert_uint8(NGTCP2_ECN_ECT_0, ==, pi.ecn);
  assert_int((int)NGTCP2_ECN_STATE_TESTING, ==, (int)conn->tx.ecn.state);
  assert_uint64(1, ==, conn->tx.ecn.validation_start_ts);
  assert_int64(0, ==, conn->pktns.tx.ecn.start_pkt_num);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK_ECN,
    .ecn.ect0 = 1,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 2);

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
  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK_ECN,
    .largest_ack = 1,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 3);

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
  ngtcp2_tpe_init_conn(&tpe, conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, &pi, buf, sizeof(buf), 1);

  assert_ptrdiff(0, <, spktlen);
  assert_uint8(NGTCP2_ECN_ECT_0, ==, pi.ecn);
  assert_int((int)NGTCP2_ECN_STATE_TESTING, ==, (int)conn->tx.ecn.state);
  assert_uint64(1, ==, conn->tx.ecn.validation_start_ts);
  assert_int64(0, ==, conn->pktns.tx.ecn.start_pkt_num);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 2);

  assert_int(0, ==, rv);
  assert_int((int)NGTCP2_ECN_STATE_FAILED, ==, (int)conn->tx.ecn.state);

  ngtcp2_conn_del(conn);

  /* CE counts must be considered */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

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

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK_ECN,
    .largest_ack = 1,
    .first_ack_range = 1,
    .ecn =
      {
        .ect0 = 1,
        .ce = 1,
      },
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 2);

  assert_int(0, ==, rv);
  assert_int((int)NGTCP2_ECN_STATE_CAPABLE, ==, (int)conn->tx.ecn.state);
  assert_size(0, ==, ngtcp2_ksl_len(&conn->pktns.rtb.ents));

  ngtcp2_conn_del(conn);

  /* If increments of ECN counts is less than the number of
     acknowledged ECN entries, ECN validation fails. */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, &pi, buf, sizeof(buf), 1);

  assert_ptrdiff(0, <, spktlen);
  assert_uint8(NGTCP2_ECN_ECT_0, ==, pi.ecn);
  assert_int((int)NGTCP2_ECN_STATE_TESTING, ==, (int)conn->tx.ecn.state);
  assert_uint64(1, ==, conn->tx.ecn.validation_start_ts);
  assert_int64(0, ==, conn->pktns.tx.ecn.start_pkt_num);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK_ECN,
    .ecn.ect1 = 1,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 2);

  assert_int(0, ==, rv);
  assert_int((int)NGTCP2_ECN_STATE_FAILED, ==, (int)conn->tx.ecn.state);

  ngtcp2_conn_del(conn);

  /* If ECT count is larger than the number of ECT marked packet, ECN
     validation fails. */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, &pi, buf, sizeof(buf), 1);

  assert_ptrdiff(0, <, spktlen);
  assert_uint8(NGTCP2_ECN_ECT_0, ==, pi.ecn);
  assert_int((int)NGTCP2_ECN_STATE_TESTING, ==, (int)conn->tx.ecn.state);
  assert_uint64(1, ==, conn->tx.ecn.validation_start_ts);
  assert_int64(0, ==, conn->pktns.tx.ecn.start_pkt_num);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK_ECN,
    .ecn.ect0 = 2,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 2);

  assert_int(0, ==, rv);
  assert_int((int)NGTCP2_ECN_STATE_FAILED, ==, (int)conn->tx.ecn.state);

  ngtcp2_conn_del(conn);

  /* ECN validation fails if all ECN marked packets are lost */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

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

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = NGTCP2_ECN_MAX_NUM_VALIDATION_PKTS,
  };

  t += NGTCP2_MILLISECONDS;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  assert_int(0, ==, rv);

  assert_int((int)NGTCP2_ECN_STATE_FAILED, ==, (int)conn->tx.ecn.state);
  assert_size(NGTCP2_ECN_MAX_NUM_VALIDATION_PKTS, ==,
              conn->pktns.tx.ecn.validation_pkt_lost);

  ngtcp2_conn_del(conn);

  /* ECN validation fails if all ECN marked packets sent in last 3 *
     RTT are lost */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

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

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = 2,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen,
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
  ngtcp2_frame frs[4];
  int rv;
  ngtcp2_path_storage rpath, wpath;
  ngtcp2_pv_entry *ent;
  ngtcp2_tpe tpe;
  my_user_data ud;
  ngtcp2_callbacks callbacks;
  conn_options opts;

  /* server starts path validation in NAT rebinding scenario. */
  server_default_callbacks(&callbacks);
  callbacks.begin_path_validation = begin_path_validation;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  frs[0].ping.type = NGTCP2_FRAME_PING;

  /* Just change remote port */
  path_init(&rpath, 0, 0, 0, 1);
  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 1);

  ud.begin_path_validation.flags = 0;
  ngtcp2_path_storage_zero(&ud.begin_path_validation.path);
  ngtcp2_path_storage_zero(&ud.begin_path_validation.fallback_path);

  rv = ngtcp2_conn_read_pkt(conn, &rpath.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_not_null(conn->pv);
  assert_uint64(0, ==, conn->pv->dcid.seq);
  assert_true(ngtcp2_path_eq(&conn->pv->dcid.ps.path, &rpath.path));
  assert_uint32(0, ==, ud.begin_path_validation.flags);
  assert_true(ngtcp2_path_eq(&rpath.path, &ud.begin_path_validation.path.path));
  assert_true(ngtcp2_path_eq(&null_path.path,
                             &ud.begin_path_validation.fallback_path.path));

  ngtcp2_path_storage_zero(&wpath);
  spktlen =
    ngtcp2_conn_write_pkt(conn, &wpath.path, NULL, buf, sizeof(buf), ++t);

  /* Server has not received enough bytes to pad probing packet. */
  assert_ptrdiff(1200, >, spktlen);
  assert_true(ngtcp2_path_eq(&rpath.path, &wpath.path));
  assert_size(1, ==, ngtcp2_ringbuf_len(&conn->pv->ents.rb));

  ent = ngtcp2_ringbuf_get(&conn->pv->ents.rb, 0);

  assert_true(ent->flags & NGTCP2_PV_ENTRY_FLAG_UNDERSIZED);
  assert_true(conn->pv->flags & NGTCP2_PV_FLAG_FALLBACK_PRESENT);

  frs[0].path_response.type = NGTCP2_FRAME_PATH_RESPONSE;
  memcpy(frs[0].path_response.data, ent->data, sizeof(ent->data));

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 1);
  rv = ngtcp2_conn_read_pkt(conn, &rpath.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  /* Start another path validation to probe least MTU */
  assert_not_null(conn->pv);
  assert_true(conn->pv->flags & NGTCP2_PV_FLAG_FALLBACK_PRESENT);

  ngtcp2_path_storage_zero(&wpath);
  spktlen =
    ngtcp2_conn_write_pkt(conn, &wpath.path, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1200, <=, spktlen);
  assert_true(ngtcp2_path_eq(&rpath.path, &wpath.path));
  assert_size(1, ==, ngtcp2_ringbuf_len(&conn->pv->ents.rb));

  ent = ngtcp2_ringbuf_get(&conn->pv->ents.rb, 0);
  frs[0].path_response.type = NGTCP2_FRAME_PATH_RESPONSE;
  memcpy(frs[0].path_response.data, ent->data, sizeof(ent->data));

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 1);
  rv = ngtcp2_conn_read_pkt(conn, &rpath.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  /* Now perform another validation to old path */
  assert_not_null(conn->pv);
  assert_false(conn->pv->flags & NGTCP2_PV_FLAG_FALLBACK_PRESENT);
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
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_strm *strm;
  ngtcp2_tstamp t = 0;
  ngtcp2_tpe tpe;
  ngtcp2_callbacks callbacks;
  conn_options opts;

  client_early_callbacks(&callbacks);
  callbacks.recv_crypto_data = recv_crypto_data_client_handshake;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_early_client_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

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

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 198,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  tpe.handshake.ckm = conn->hs_pktns->crypto.rx.ckm;

  pktlen = ngtcp2_tpe_write_handshake(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  ngtcp2_transport_params params;
  ngtcp2_tstamp t = 0;
  ngtcp2_tpe tpe;
  ngtcp2_crypto_ctx crypto_ctx;

  init_crypto_ctx(&crypto_ctx);

  setup_early_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

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

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 198,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  ngtcp2_conn_set_crypto_ctx(conn, &crypto_ctx);

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
  params = (ngtcp2_transport_params){
    .initial_scid = conn->dcid.current.cid,
    .initial_scid_present = 1,
    .original_dcid = conn->rcid,
    .original_dcid_present = 1,
    .max_udp_payload_size = 1200,
    .initial_max_stream_data_bidi_local =
      conn->early.transport_params.initial_max_stream_data_bidi_local,
    .initial_max_stream_data_bidi_remote =
      conn->early.transport_params.initial_max_stream_data_bidi_remote / 2,
    .initial_max_data = conn->early.transport_params.initial_max_data,
    .initial_max_streams_bidi =
      conn->early.transport_params.initial_max_streams_bidi,
    .initial_max_streams_uni =
      conn->early.transport_params.initial_max_streams_uni,
    .active_connection_id_limit =
      conn->early.transport_params.active_connection_id_limit,
  };

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
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_cid scid;
  ngtcp2_tstamp last_ts;
  ngtcp2_tpe tpe;
  ngtcp2_callbacks callbacks;
  conn_options opts;

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

  client_early_callbacks(&callbacks);
  callbacks.recv_crypto_data = recv_crypto_data_client_handshake;

  opts = (conn_options){
    .scid = &scid,
    .callbacks = &callbacks,
  };

  setup_early_client_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  ngtcp2_conn_set_keep_alive_timeout(conn, 10 * NGTCP2_MILLISECONDS);

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

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 127,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  tpe.handshake.ckm = conn->hs_pktns->crypto.rx.ckm;

  pktlen = ngtcp2_tpe_write_handshake(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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

  /* Keep-alive elicits PTO */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, &pi, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, &pi, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, ==, spktlen);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, ==, ngtcp2_ksl_len(&conn->pktns.rtb.ents));

  ngtcp2_conn_set_keep_alive_timeout(conn, 10 * NGTCP2_SECONDS);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, &pi, buf, sizeof(buf), t);

  assert_ptrdiff(0, ==, spktlen);
  assert_uint64(UINT64_MAX, ==, ngtcp2_conn_loss_detection_expiry(conn));

  t += 10 * NGTCP2_SECONDS;

  rv = ngtcp2_conn_handle_expiry(conn, t);

  assert_int(0, ==, rv);
  assert_true(conn->flags & NGTCP2_CONN_FLAG_KEEP_ALIVE_CANCELLED);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, &pi, buf, sizeof(buf), t);

  assert_ptrdiff(0, <, spktlen);
  assert_uint64(t, ==, conn->keep_alive.last_ts);
  assert_uint64(UINT64_MAX, !=, ngtcp2_conn_loss_detection_expiry(conn));

  t = ngtcp2_conn_loss_detection_expiry(conn);

  rv = ngtcp2_conn_handle_expiry(conn, t);

  assert_int(0, ==, rv);
  assert_size(2, ==, conn->pktns.rtb.probe_pkt_left);

  /* Send 2 PTO probes */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, &pi, buf, sizeof(buf), t);

  assert_ptrdiff(0, <, spktlen);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, &pi, buf, sizeof(buf), t);

  assert_ptrdiff(0, <, spktlen);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, &pi, buf, sizeof(buf), t);

  assert_ptrdiff(0, ==, spktlen);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
    .first_ack_range = 1,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, ==, conn->pktns.rtb.probe_pkt_left);
  assert_uint64(UINT64_MAX, ==, ngtcp2_conn_loss_detection_expiry(conn));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_retire_stale_bound_dcid(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_tstamp t = 0;
  ngtcp2_tstamp expiry;
  ngtcp2_frame fr;
  int rv;
  static const ngtcp2_cid cid = {
    .datalen = 4,
    .data = {0x0F, 0x00, 0x00, 0x00},
  };
  static const ngtcp2_stateless_reset_token token = {
    .data = {0xFF},
  };
  const uint8_t data[] = {0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8};
  ngtcp2_tpe tpe;

  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 1,
    .cid = cid,
    .token = token,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  fr.path_challenge.type = NGTCP2_FRAME_PATH_CHALLENGE;
  memcpy(fr.path_challenge.data, data, sizeof(fr.path_challenge.data));

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, <, ngtcp2_ringbuf_len(&conn->rx.path_challenge.rb));
  assert_size(0, <, ngtcp2_dcidtr_bound_len(&conn->dcid.dtr));

  expiry = ngtcp2_conn_get_expiry(conn);

  assert_uint64(UINT64_MAX, !=, expiry);

  t += 3 * ngtcp2_conn_get_pto(conn);

  rv = ngtcp2_conn_handle_expiry(conn, t);

  assert_int(0, ==, rv);
  assert_size(0, ==, ngtcp2_dcidtr_bound_len(&conn->dcid.dtr));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_get_scid(void) {
  ngtcp2_conn *conn;
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  ngtcp2_cid dcid, scid;
  ngtcp2_callbacks cb;
  const uint8_t raw_cid[] = {0x0F, 0x00, 0x00, 0x00};
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
  ngtcp2_vec datav;
  ngtcp2_frame frs[2];
  size_t pktlen;
  my_user_data ud;
  ngtcp2_strm *strm;
  ngtcp2_tstamp t = 0;
  ngtcp2_ssize spktlen;
  int64_t stream_id;
  ngtcp2_tpe tpe;
  ngtcp2_callbacks callbacks;
  conn_options opts;

  /* Receive RESET_STREAM and STOP_SENDING from client */
  server_default_callbacks(&callbacks);
  callbacks.stream_close = stream_close;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  open_stream(conn, 0);

  frs[0].reset_stream = (ngtcp2_reset_stream){
    .type = NGTCP2_FRAME_RESET_STREAM,
    .app_error_code = NGTCP2_APP_ERR01,
    .final_size = 999,
  };

  frs[1].stop_sending = (ngtcp2_stop_sending){
    .type = NGTCP2_FRAME_STOP_SENDING,
    .app_error_code = NGTCP2_APP_ERR02,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 2);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, 0);

  assert_uint64(NGTCP2_APP_ERR01, ==, strm->app_error_code);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(sizeof(buf), >, (size_t)spktlen);

  frs[0].ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 1);

  ud.stream_close.flags = NGTCP2_STREAM_CLOSE_FLAG_NONE;
  ud.stream_close.stream_id = -1;
  ud.stream_close.app_error_code = 0;

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  assert_true(NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET &
              ud.stream_close.flags);
  assert_int64(0, ==, ud.stream_close.stream_id);
  assert_uint64(NGTCP2_APP_ERR01, ==, ud.stream_close.app_error_code);

  ngtcp2_conn_del(conn);

  /* Client sends STOP_SENDING and then STREAM and fin */
  server_default_callbacks(&callbacks);
  callbacks.stream_close = stream_close;
  callbacks.recv_stream_data = recv_stream_data;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  frs[0].stop_sending = (ngtcp2_stop_sending){
    .type = NGTCP2_FRAME_STOP_SENDING,
    .app_error_code = NGTCP2_APP_ERR01,
  };

  frs[1].stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .fin = 1,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 2);

  ud.stream_data.stream_id = -1;
  ud.stream_data.flags = NGTCP2_STREAM_DATA_FLAG_NONE;
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_int64(0, ==, ud.stream_data.stream_id);
  assert_true(ud.stream_data.flags & NGTCP2_STREAM_DATA_FLAG_FIN);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(sizeof(buf), >, (size_t)spktlen);

  frs[0].ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 1);

  ud.stream_close.flags = NGTCP2_STREAM_CLOSE_FLAG_NONE;
  ud.stream_close.stream_id = -1;
  ud.stream_close.app_error_code = 0;

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  assert_true(NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET &
              ud.stream_close.flags);
  assert_int64(0, ==, ud.stream_close.stream_id);
  assert_uint64(NGTCP2_APP_ERR01, ==, ud.stream_close.app_error_code);

  ngtcp2_conn_del(conn);

  /* Client calls ngtcp2_conn_shutdown_stream, and before sending
     STOP_SENDING, it receives STREAM with fin bit set. */
  client_default_callbacks(&callbacks);
  callbacks.stream_close = stream_close;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_client_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_FIN, stream_id,
                                     null_data, 1, ++t);

  assert_ptrdiff(0, <, spktlen);

  frs[0].ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_shutdown_stream(conn, 0, stream_id, NGTCP2_APP_ERR01);

  assert_int(0, ==, rv);

  frs[0].stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .fin = 1,
    .stream_id = stream_id,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 97,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 1);

  ud.stream_close.flags = NGTCP2_STREAM_CLOSE_FLAG_NONE;
  ud.stream_close.stream_id = -1;
  ud.stream_close.app_error_code = 0;

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_true(NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET &
              ud.stream_close.flags);
  assert_int64(stream_id, ==, ud.stream_close.stream_id);
  assert_uint64(NGTCP2_APP_ERR01, ==, ud.stream_close.app_error_code);

  ngtcp2_conn_del(conn);

  /* Client sends STREAM fin and then RESET_STREAM.  It receives ACK
     for the STREAM frame, then response fin. No ACK for
     RESET_STREAM. */
  client_default_callbacks(&callbacks);
  callbacks.stream_close = stream_close;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_client_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_FIN, stream_id,
                                     null_data, 1, ++t);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_shutdown_stream_write(conn, 0, stream_id, NGTCP2_APP_ERR01);

  assert_int(0, ==, rv);

  frs[0].stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .fin = 1,
    .stream_id = stream_id,
  };

  frs[1].ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
  };

  spktlen =
    ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                             NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, ++t);

  assert_ptrdiff(0, <, spktlen);

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 2);

  ud.stream_close.flags = NGTCP2_STREAM_CLOSE_FLAG_NONE;
  ud.stream_close.stream_id = -1;
  ud.stream_close.app_error_code = 0;

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_true(NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET &
              ud.stream_close.flags);
  assert_int64(stream_id, ==, ud.stream_close.stream_id);
  assert_uint64(NGTCP2_APP_ERR01, ==, ud.stream_close.app_error_code);

  ngtcp2_conn_del(conn);

  /* Check that the closure of remote unidirectional invokes
     stream_close callback */
  client_default_callbacks(&callbacks);
  callbacks.stream_close = stream_close;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_client_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  frs[0].stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .fin = 1,
    .stream_id = 3,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 88,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 1);

  ud.stream_close.flags = NGTCP2_STREAM_CLOSE_FLAG_NONE;
  ud.stream_close.stream_id = -1;
  ud.stream_close.app_error_code = 0;

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  ngtcp2_frame frs[2];
  size_t pktlen, in_pktlen;
  ngtcp2_tstamp t = 0;
  ngtcp2_ssize spktlen;
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  ngtcp2_ksl_it it;
  ngtcp2_pkt_chain *pc;
  ngtcp2_tpe tpe;

  /* Server should buffer Short packet if it does not complete
     handshake even if it has application tx key. */
  setup_handshake_server(&conn);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1193,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_install_tx_key(conn, null_secret, sizeof(null_secret),
                                  &aead_ctx, null_iv, sizeof(null_iv), &hp_ctx);

  assert(0 == rv);

  rv = ngtcp2_conn_install_rx_key(conn, null_secret, sizeof(null_secret),
                                  &aead_ctx, null_iv, sizeof(null_iv), &hp_ctx);

  assert(0 == rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_null(conn->pktns.rx.buffed_pkts);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, null_data,
                            NGTCP2_MIN_QUIC_PKTLEN - 1, ++t);

  assert_int(0, ==, rv);
  assert_null(conn->pktns.rx.buffed_pkts);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, null_data,
                            NGTCP2_MIN_QUIC_PKTLEN, ++t);

  assert_int(0, ==, rv);
  assert_null(conn->pktns.rx.buffed_pkts);

  memset(buf, 1, NGTCP2_MIN_QUIC_PKTLEN);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf,
                            NGTCP2_MIN_QUIC_PKTLEN, ++t);

  assert_int(0, ==, rv);

  pc = conn->pktns.rx.buffed_pkts;

  assert_not_null(pc);
  assert_size(NGTCP2_MIN_QUIC_PKTLEN, ==, pc->pktlen);
  assert_size(NGTCP2_MIN_QUIC_PKTLEN, ==, pc->dgramlen);

  fr.ping.type = NGTCP2_FRAME_PING;

  in_pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  frs[0].ping.type = NGTCP2_FRAME_PING;
  frs[1].padding = (ngtcp2_padding){
    .type = NGTCP2_FRAME_PADDING,
    .len = 1200,
  };

  tpe.app.ckm = conn->pktns.crypto.rx.ckm;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf + in_pktlen, sizeof(buf) - in_pktlen,
                                 frs, 2);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf,
                            in_pktlen + pktlen, ++t);

  assert_int(0, ==, rv);

  pc = conn->pktns.rx.buffed_pkts->next;

  assert_not_null(pc);
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

  rv =
    ngtcp2_conn_handle_expiry(conn, conn->local.settings.initial_ts +
                                      conn->local.settings.handshake_timeout);

  assert_int(NGTCP2_ERR_HANDSHAKE_TIMEOUT, ==, rv);

  ngtcp2_conn_del(conn);

  /* handshake is still in progress */
  setup_handshake_server(&conn);

  rv = ngtcp2_conn_handle_expiry(conn,
                                 conn->local.settings.initial_ts +
                                   conn->local.settings.handshake_timeout - 1);

  assert_int(0, ==, rv);

  ngtcp2_conn_del(conn);

  /* handshake timeout should be ignored after handshake has
     completed. */
  setup_default_server(&conn);

  rv =
    ngtcp2_conn_handle_expiry(conn, conn->local.settings.initial_ts +
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
  int rv;
  const ngtcp2_ccerr *ccerr;
  ngtcp2_tpe tpe;

  memset(reason, 'a', sizeof(reason));

  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  /* Record the last error. */
  frs[0].connection_close = (ngtcp2_connection_close){
    .type = NGTCP2_FRAME_CONNECTION_CLOSE_APP,
    .error_code = 1,
    .frame_type = 99,
    .reasonlen = 10,
    .reason = reason,
  };

  frs[1].connection_close = (ngtcp2_connection_close){
    .type = NGTCP2_FRAME_CONNECTION_CLOSE,
    .error_code = NGTCP2_PROTOCOL_VIOLATION,
    .frame_type = 1000000007,
    .reasonlen = NGTCP2_CCERR_MAX_REASONLEN + 1,
    .reason = reason,
  };

  pktlen =
    ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, ngtcp2_arraylen(frs));

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  ngtcp2_tstamp t = 0;
  ngtcp2_ssize spktlen;
  size_t pktlen;
  int rv;
  ngtcp2_transport_params remote_params;
  uint8_t available_versions[sizeof(uint32_t) * 2];
  uint32_t version;
  ngtcp2_tpe tpe;
  ngtcp2_callbacks callbacks;
  conn_options opts;

  ngtcp2_put_uint32be(&available_versions[0], NGTCP2_PROTO_VER_V1);
  ngtcp2_put_uint32be(&available_versions[4], NGTCP2_PROTO_VER_V2);

  /* Client sees the change version in Initial packet which contains
     CRYPTO frame.  It generates new Initial keys and sets negotiated
     version. */
  setup_handshake_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.version = NGTCP2_PROTO_VER_V2;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 133,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_uint32(NGTCP2_PROTO_VER_V2, ==, conn->negotiated_version);
  assert_uint32(NGTCP2_PROTO_VER_V2, ==, conn->vneg.version);
  assert_not_null(conn->vneg.rx.ckm);
  assert_not_null(conn->vneg.tx.ckm);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  ngtcp2_get_uint32be(&version, &buf[1]);

  assert_uint32(NGTCP2_PROTO_VER_V2, ==, version);

  ngtcp2_conn_del(conn);

  /* Client observes that server chose reserved version. */
  setup_handshake_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.version = NGTCP2_RESERVED_VERSION_MASK;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 133,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_uint32(0, ==, conn->negotiated_version);
  assert_uint32(0, ==, conn->vneg.version);

  ngtcp2_conn_del(conn);

  /* Client receives Initial packet which does not change version and
     does not contain CRYPTO frame.  It leaves negotiated version
     unchanged. */
  setup_handshake_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  fr.padding = (ngtcp2_padding){
    .type = NGTCP2_FRAME_PADDING,
    .len = 1,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_uint32(0, ==, conn->negotiated_version);
  assert_uint32(0, ==, conn->vneg.version);
  assert_null(conn->vneg.rx.ckm);
  assert_null(conn->vneg.tx.ckm);

  ngtcp2_conn_del(conn);

  /* Server sees client supports QUIC v2.  It chooses QUIC v2 as the
     negotiated version, and generates new Initial keys. */
  server_default_callbacks(&callbacks);
  callbacks.recv_client_initial =
    recv_client_initial_no_remote_transport_params;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_handshake_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1233,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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

  ngtcp2_get_uint32be(&version, &buf[1]);

  assert_uint32(NGTCP2_PROTO_VER_V2, ==, version);

  ngtcp2_conn_del(conn);

  /* Server receives Version Information transport parameter which
     does not include chosen_version in available_versions. */
  server_default_callbacks(&callbacks);
  callbacks.recv_client_initial =
    recv_client_initial_no_remote_transport_params;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_handshake_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1211,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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
  ngtcp2_version_info version_info;
  uint8_t client_available_versions[sizeof(uint32_t) * 2];
  const uint32_t v1_preferred_versions[] = {
    NGTCP2_PROTO_VER_V1,
    NGTCP2_PROTO_VER_V2,
  };
  ngtcp2_settings settings;
  conn_options opts;

  setup_handshake_server(&conn);

  version_info = (ngtcp2_version_info){
    .chosen_version = conn->client_chosen_version,
  };

  /* Empty version_info.available_versions */
  version_info.available_versions = NULL;
  version_info.available_versionslen = 0;

  assert_uint32(conn->client_chosen_version, ==,
                ngtcp2_conn_server_negotiate_version(conn, &version_info));

  /* version_info.available_versions and preferred_versions do not
     share any version. */
  ngtcp2_put_uint32be(&client_available_versions[0], 0xFF000001);
  ngtcp2_put_uint32be(&client_available_versions[4], 0xFF000002);

  version_info.available_versions = client_available_versions;
  version_info.available_versionslen = sizeof(uint32_t) * 2;

  assert_uint32(conn->client_chosen_version, ==,
                ngtcp2_conn_server_negotiate_version(conn, &version_info));

  /* version_info.available_versions and preferred_versions share the
     version. */
  ngtcp2_put_uint32be(&client_available_versions[0], 0xFF000001);
  ngtcp2_put_uint32be(&client_available_versions[4], NGTCP2_PROTO_VER_V2);

  version_info.available_versions = client_available_versions;
  version_info.available_versionslen = sizeof(uint32_t) * 2;

  assert_uint32(NGTCP2_PROTO_VER_V2, ==,
                ngtcp2_conn_server_negotiate_version(conn, &version_info));

  ngtcp2_conn_del(conn);

  /* Without preferred_versions */
  server_handshake_settings(&settings);
  settings.preferred_versions = NULL;
  settings.preferred_versionslen = 0;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_handshake_server_with_options(&conn, opts);

  ngtcp2_put_uint32be(&client_available_versions[0], 0xFF000001);
  ngtcp2_put_uint32be(&client_available_versions[4], NGTCP2_PROTO_VER_V2);

  version_info.available_versions = client_available_versions;
  version_info.available_versionslen = sizeof(uint32_t) * 2;

  assert_uint32(conn->client_chosen_version, ==,
                ngtcp2_conn_server_negotiate_version(conn, &version_info));

  ngtcp2_conn_del(conn);

  /* original version is the most preferred version */
  server_handshake_settings(&settings);
  settings.preferred_versions = v1_preferred_versions;
  settings.preferred_versionslen = 2;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_handshake_server_with_options(&conn, opts);

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
  size_t pktlen;
  int rv;
  ngtcp2_tpe tpe;

  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  ngtcp2_conn_start_pmtud(conn);

  /* This sends PMTUD packet. */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(1406, ==, spktlen);

  t += NGTCP2_SECONDS;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(1, ==, conn->pktns.rtb.num_lost_pkts);
  assert_size(1, ==, conn->pktns.rtb.num_lost_ignore_pkts);
  assert_uint64(0, ==, conn->pktns.rtb.cc_bytes_in_flight);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
    .first_ack_range = 1,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  /* Handle spuriously lost PMTUD packet */
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(0, ==, conn->pktns.rtb.num_lost_pkts);
  assert_size(0, ==, conn->pktns.rtb.num_lost_ignore_pkts);
  assert_uint64(0, ==, conn->pktns.rtb.cc_bytes_in_flight);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_amplification(void) {
  ngtcp2_conn *conn;
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  size_t pktlen;
  uint8_t buf[2048];
  ngtcp2_tstamp t = 0;
  ngtcp2_ssize spktlen;
  int rv;
  ngtcp2_tpe tpe;

  /* ACK only frame should not be sent due to amplification limit. */
  setup_early_server(&conn);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1200,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 111,
    .base = null_data,
  };

  tpe.early.ckm = conn->early.ckm;

  pktlen = ngtcp2_tpe_write_0rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  /* Adjust condition so that the execution path goes into sending ACK
     only frame. */
  conn->dcid.current.bytes_sent = conn->dcid.current.bytes_recv * 3 - 1;
  conn->cstat.bytes_in_flight = conn->cstat.cwnd;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, ==, spktlen);

  ngtcp2_conn_del(conn);

  /* Disarm loss detection due to amplification limit */
  setup_handshake_server(&conn);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .base = null_data,
    .len = 1200,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL,
                                      null_data, sizeof(null_data));

  assert_int(0, ==, rv);

  for (;;) {
    spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

    if (spktlen == 0) {
      break;
    }

    assert_ptrdiff(0, <=, spktlen);
    assert_uint64(UINT64_MAX, !=, ngtcp2_conn_loss_detection_expiry(conn));
  }

  assert_uint64(UINT64_MAX, ==, ngtcp2_conn_loss_detection_expiry(conn));

  /* Re-arm loss detection timer when receiving more packets */
  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .offset = 1200,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .base = null_data,
    .len = 1200,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);
  /* If we wait long enough, ngtcp2_conn_on_loss_detection_timer will
     be called and probe packets are armed. */
  t += NGTCP2_SECONDS;
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  assert_int(0, ==, rv);
  assert_uint64(UINT64_MAX, !=, ngtcp2_conn_loss_detection_expiry(conn));
  assert_size(1, ==, conn->in_pktns->rtb.probe_pkt_left);

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
  conn_options opts;

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
  server_default_transport_params(&params);
  params.disable_active_migration = 1;

  opts = (conn_options){
    .params = &params,
  };

  setup_default_server_with_options(&conn, opts);

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
  ngtcp2_ack_range ack_ranges[NGTCP2_MAX_ACK_RANGES];
  ngtcp2_frame fr;
  uint8_t buf[2048];
  size_t pktlen;
  int rv;
  ngtcp2_ksl_it it;
  size_t i;
  ngtcp2_ack_range ar;
  ngtcp2_tpe tpe;
  ngtcp2_settings settings;
  conn_options opts;

  /* Nothing to acknowledge */
  setup_default_server(&conn);

  fr.ack.ranges = ack_ranges;
  rv = ngtcp2_acktr_create_ack_frame(&conn->pktns.acktr, &fr.ack,
                                     NGTCP2_PKT_1RTT, 0, 0, 0);

  assert_int(-1, ==, rv);

  ngtcp2_conn_del(conn);

  /* ACK delay */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.padding = (ngtcp2_padding){
    .type = NGTCP2_FRAME_PADDING,
    .len = 100,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

  assert_int(0, ==, rv);

  /* PADDING does not elicit ACK */
  fr.ack.ranges = ack_ranges;
  rv = ngtcp2_acktr_create_ack_frame(&conn->pktns.acktr, &fr.ack,
                                     NGTCP2_PKT_1RTT, 0, 0, 0);

  assert_int(-1, ==, rv);

  fr.ping.type = NGTCP2_FRAME_PING;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

  assert_int(0, ==, rv);

  /* PING elicits ACK, but ACK is not generated due to ack delay. */
  fr.ack.ranges = ack_ranges;
  rv =
    ngtcp2_acktr_create_ack_frame(&conn->pktns.acktr, &fr.ack, NGTCP2_PKT_1RTT,
                                  0, 25 * NGTCP2_MILLISECONDS, 0);

  assert_int(-1, ==, rv);

  /* ACK delay passed. */
  fr.ack.ranges = ack_ranges;
  rv = ngtcp2_acktr_create_ack_frame(
    &conn->pktns.acktr, &fr.ack, NGTCP2_PKT_1RTT, 25 * NGTCP2_MILLISECONDS,
    25 * NGTCP2_MILLISECONDS, NGTCP2_DEFAULT_ACK_DELAY_EXPONENT);

  assert_int(0, ==, rv);
  assert_int64(1, ==, fr.ack.largest_ack);
  assert_uint64(1, ==, fr.ack.first_ack_range);
  assert_uint64(25 * NGTCP2_MILLISECONDS, ==, fr.ack.ack_delay_unscaled);
  assert_uint64(3125, ==, fr.ack.ack_delay);
  assert_size(0, ==, fr.ack.rangecnt);

  ngtcp2_conn_del(conn);

  /* reorder (adjacent packets) */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.ping.type = NGTCP2_FRAME_PING;

  tpe.app.last_pkt_num = 0;

  fr.ping.type = NGTCP2_FRAME_PING;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

  assert_int(0, ==, rv);

  fr.ack.ranges = ack_ranges;
  rv = ngtcp2_acktr_create_ack_frame(
    &conn->pktns.acktr, &fr.ack, NGTCP2_PKT_1RTT, 25 * NGTCP2_MILLISECONDS,
    25 * NGTCP2_MILLISECONDS, NGTCP2_DEFAULT_ACK_DELAY_EXPONENT);

  assert_int(0, ==, rv);
  assert_int64(1, ==, fr.ack.largest_ack);
  assert_uint64(0, ==, fr.ack.first_ack_range);
  assert_uint64(25 * NGTCP2_MILLISECONDS, ==, fr.ack.ack_delay_unscaled);
  assert_uint64(3125, ==, fr.ack.ack_delay);
  assert_size(0, ==, fr.ack.rangecnt);

  ngtcp2_acktr_commit_ack(&conn->pktns.acktr);

  it = ngtcp2_acktr_get(&conn->pktns.acktr);

  assert_false(ngtcp2_ksl_it_end(&it));

  ngtcp2_acktr_forget(&conn->pktns.acktr, ngtcp2_ksl_it_get(&it));

  tpe.app.last_pkt_num = -1;

  fr.ping.type = NGTCP2_FRAME_PING;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

  assert_int(0, ==, rv);

  fr.ack.ranges = ack_ranges;
  rv = ngtcp2_acktr_create_ack_frame(
    &conn->pktns.acktr, &fr.ack, NGTCP2_PKT_1RTT, 25 * NGTCP2_MILLISECONDS,
    25 * NGTCP2_MILLISECONDS, NGTCP2_DEFAULT_ACK_DELAY_EXPONENT);

  assert_int(0, ==, rv);
  assert_int64(1, ==, fr.ack.largest_ack);
  assert_uint64(1, ==, fr.ack.first_ack_range);
  assert_uint64(25 * NGTCP2_MILLISECONDS, ==, fr.ack.ack_delay_unscaled);
  assert_uint64(3125, ==, fr.ack.ack_delay);
  assert_size(0, ==, fr.ack.rangecnt);

  ngtcp2_conn_del(conn);

  /* reorder (adjacent packets) with multiple ack ranges. */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.ping.type = NGTCP2_FRAME_PING;

  tpe.app.last_pkt_num = 9;

  fr.ping.type = NGTCP2_FRAME_PING;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

  assert_int(0, ==, rv);

  fr.ack.ranges = ack_ranges;
  rv = ngtcp2_acktr_create_ack_frame(
    &conn->pktns.acktr, &fr.ack, NGTCP2_PKT_1RTT, 25 * NGTCP2_MILLISECONDS,
    25 * NGTCP2_MILLISECONDS, NGTCP2_DEFAULT_ACK_DELAY_EXPONENT);

  assert_int(0, ==, rv);
  assert_int64(10, ==, fr.ack.largest_ack);
  assert_uint64(0, ==, fr.ack.first_ack_range);
  assert_uint64(25 * NGTCP2_MILLISECONDS, ==, fr.ack.ack_delay_unscaled);
  assert_uint64(3125, ==, fr.ack.ack_delay);
  assert_size(0, ==, fr.ack.rangecnt);

  ngtcp2_acktr_commit_ack(&conn->pktns.acktr);

  it = ngtcp2_acktr_get(&conn->pktns.acktr);

  assert_false(ngtcp2_ksl_it_end(&it));

  ngtcp2_acktr_forget(&conn->pktns.acktr, ngtcp2_ksl_it_get(&it));

  fr.ping.type = NGTCP2_FRAME_PING;

  /* [0..1] */
  for (i = 0; i < 2; ++i) {
    tpe.app.last_pkt_num = (int64_t)i - 1;

    pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

    rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

    assert_int(0, ==, rv);
  }

  /* [3..6] */
  for (i = 3; i < 7; ++i) {
    tpe.app.last_pkt_num = (int64_t)i - 1;

    pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

    rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

    assert_int(0, ==, rv);
  }

  /* [9..9] */
  tpe.app.last_pkt_num = 8;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

  assert_int(0, ==, rv);

  fr.ack.ranges = ack_ranges;
  rv = ngtcp2_acktr_create_ack_frame(
    &conn->pktns.acktr, &fr.ack, NGTCP2_PKT_1RTT, 25 * NGTCP2_MILLISECONDS,
    25 * NGTCP2_MILLISECONDS, NGTCP2_DEFAULT_ACK_DELAY_EXPONENT);

  assert_int(0, ==, rv);
  assert_int64(10, ==, fr.ack.largest_ack);
  assert_uint64(1, ==, fr.ack.first_ack_range);
  assert_uint64(25 * NGTCP2_MILLISECONDS, ==, fr.ack.ack_delay_unscaled);
  assert_uint64(3125, ==, fr.ack.ack_delay);
  assert_size(2, ==, fr.ack.rangecnt);

  ar = fr.ack.ranges[0];

  assert_uint64(1, ==, ar.gap);
  assert_uint64(3, ==, ar.len);

  ar = fr.ack.ranges[1];

  assert_uint64(0, ==, ar.gap);
  assert_uint64(1, ==, ar.len);

  ngtcp2_conn_del(conn);

  /* reorder (no adjacent packets) with multiple ack ranges. */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.ping.type = NGTCP2_FRAME_PING;

  tpe.app.last_pkt_num = 9;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

  assert_int(0, ==, rv);

  fr.ack.ranges = ack_ranges;
  rv = ngtcp2_acktr_create_ack_frame(
    &conn->pktns.acktr, &fr.ack, NGTCP2_PKT_1RTT, 25 * NGTCP2_MILLISECONDS,
    25 * NGTCP2_MILLISECONDS, NGTCP2_DEFAULT_ACK_DELAY_EXPONENT);

  assert_int(0, ==, rv);
  assert_int64(10, ==, fr.ack.largest_ack);
  assert_uint64(0, ==, fr.ack.first_ack_range);
  assert_uint64(25 * NGTCP2_MILLISECONDS, ==, fr.ack.ack_delay_unscaled);
  assert_uint64(3125, ==, fr.ack.ack_delay);
  assert_size(0, ==, fr.ack.rangecnt);

  ngtcp2_acktr_commit_ack(&conn->pktns.acktr);

  it = ngtcp2_acktr_get(&conn->pktns.acktr);

  assert_false(ngtcp2_ksl_it_end(&it));

  ngtcp2_acktr_forget(&conn->pktns.acktr, ngtcp2_ksl_it_get(&it));

  fr.ping.type = NGTCP2_FRAME_PING;

  /* [3..7] */
  for (i = 3; i < 8; ++i) {
    tpe.app.last_pkt_num = (int64_t)i - 1;

    pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

    rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

    assert_int(0, ==, rv);
  }

  fr.ack.ranges = ack_ranges;
  rv = ngtcp2_acktr_create_ack_frame(
    &conn->pktns.acktr, &fr.ack, NGTCP2_PKT_1RTT, 25 * NGTCP2_MILLISECONDS,
    25 * NGTCP2_MILLISECONDS, NGTCP2_DEFAULT_ACK_DELAY_EXPONENT);

  assert_int(0, ==, rv);
  assert_int64(10, ==, fr.ack.largest_ack);
  assert_uint64(0, ==, fr.ack.first_ack_range);
  assert_uint64(25 * NGTCP2_MILLISECONDS, ==, fr.ack.ack_delay_unscaled);
  assert_uint64(3125, ==, fr.ack.ack_delay);
  assert_size(1, ==, fr.ack.rangecnt);

  ar = fr.ack.ranges[0];

  assert_uint64(1, ==, ar.gap);
  assert_uint64(4, ==, ar.len);

  ngtcp2_conn_del(conn);

  /* More than NGTCP2_MAX_ACK_RANGES */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.ping.type = NGTCP2_FRAME_PING;

  for (i = 0; i < NGTCP2_MAX_ACK_RANGES + 2; ++i) {
    tpe.app.last_pkt_num = (int64_t)(i * 2) - 1;

    pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

    rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

    assert_int(0, ==, rv);
  }

  fr.ack.ranges = ack_ranges;
  rv = ngtcp2_acktr_create_ack_frame(
    &conn->pktns.acktr, &fr.ack, NGTCP2_PKT_1RTT, 25 * NGTCP2_MILLISECONDS,
    25 * NGTCP2_MILLISECONDS, NGTCP2_DEFAULT_ACK_DELAY_EXPONENT);

  assert_int(0, ==, rv);
  assert_int64(66, ==, fr.ack.largest_ack);
  assert_uint64(0, ==, fr.ack.first_ack_range);
  assert_uint64(25 * NGTCP2_MILLISECONDS, ==, fr.ack.ack_delay_unscaled);
  assert_uint64(3125, ==, fr.ack.ack_delay);
  assert_size(NGTCP2_MAX_ACK_RANGES, ==, fr.ack.rangecnt);

  ngtcp2_conn_del(conn);

  /* Immediate acknowledgement (reorder) */
  server_default_settings(&settings);
  settings.ack_thresh = 10;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.ping.type = NGTCP2_FRAME_PING;

  tpe.app.last_pkt_num = 0;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

  assert_int(0, ==, rv);

  tpe.app.last_pkt_num = -1;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

  assert_int(0, ==, rv);

  fr.ack.ranges = ack_ranges;
  rv = ngtcp2_acktr_create_ack_frame(
    &conn->pktns.acktr, &fr.ack, NGTCP2_PKT_1RTT, 0, 25 * NGTCP2_MILLISECONDS,
    NGTCP2_DEFAULT_ACK_DELAY_EXPONENT);

  assert_int(0, ==, rv);
  assert_int64(1, ==, fr.ack.largest_ack);
  assert_uint64(1, ==, fr.ack.first_ack_range);
  assert_uint64(0, ==, fr.ack.ack_delay_unscaled);
  assert_uint64(0, ==, fr.ack.ack_delay);
  assert_size(0, ==, fr.ack.rangecnt);

  ngtcp2_conn_del(conn);

  /* Immediate acknowledgement (gap) */
  server_default_settings(&settings);
  settings.ack_thresh = 10;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  fr.ping.type = NGTCP2_FRAME_PING;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

  assert_int(0, ==, rv);

  tpe.app.last_pkt_num = 1;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, 0);

  assert_int(0, ==, rv);

  fr.ack.ranges = ack_ranges;
  rv = ngtcp2_acktr_create_ack_frame(
    &conn->pktns.acktr, &fr.ack, NGTCP2_PKT_1RTT, 0, 25 * NGTCP2_MILLISECONDS,
    NGTCP2_DEFAULT_ACK_DELAY_EXPONENT);

  assert_int(0, ==, rv);
  assert_int64(2, ==, fr.ack.largest_ack);
  assert_uint64(0, ==, fr.ack.first_ack_range);
  assert_uint64(0, ==, fr.ack.ack_delay_unscaled);
  assert_uint64(0, ==, fr.ack.ack_delay);
  assert_size(1, ==, fr.ack.rangecnt);

  ar = fr.ack.ranges[0];

  assert_uint64(0, ==, ar.gap);
  assert_uint64(0, ==, ar.len);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_grease_quic_bit(void) {
  ngtcp2_conn *conn;
  int rv;
  uint8_t buf[2048];
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_tstamp t = 0;
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  ngtcp2_tpe tpe;
  conn_options opts;

  /* Client disables grease_quic_bit, and receives a 1-RTT packet that
     has fixed bit not set. */
  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.flags = NGTCP2_PKT_FLAG_FIXED_BIT_CLEAR;

  fr.ping.type = NGTCP2_FRAME_PING;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_true(ngtcp2_acktr_empty(&conn->pktns.acktr));

  ngtcp2_conn_del(conn);

  /* Client enables grease_quic_bit, and receives a 1-RTT packet that
     has fixed bit not set. */
  client_default_transport_params(&params);
  params.grease_quic_bit = 1;

  opts = (conn_options){
    .params = &params,
  };

  setup_default_client_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.flags = NGTCP2_PKT_FLAG_FIXED_BIT_CLEAR;

  fr.ping.type = NGTCP2_FRAME_PING;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_false(ngtcp2_acktr_empty(&conn->pktns.acktr));

  ngtcp2_conn_del(conn);

  /* Server disables grease_quic_bit, and receives a 1-RTT packet that
     has fixed bit not set. */
  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.flags = NGTCP2_PKT_FLAG_FIXED_BIT_CLEAR;

  fr.ping.type = NGTCP2_FRAME_PING;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_true(ngtcp2_acktr_empty(&conn->pktns.acktr));

  ngtcp2_conn_del(conn);

  /* Server enables grease_quic_bit, and receives a 1-RTT packet that
     has fixed bit not set. */
  server_default_transport_params(&params);
  params.grease_quic_bit = 1;

  opts = (conn_options){
    .params = &params,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.flags = NGTCP2_PKT_FLAG_FIXED_BIT_CLEAR;

  fr.ping.type = NGTCP2_FRAME_PING;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_false(ngtcp2_acktr_empty(&conn->pktns.acktr));

  ngtcp2_conn_del(conn);

  /* Server enables grease_quic_bit, and receives an Initial packet
     that has no token. */
  server_default_transport_params(&params);
  params.grease_quic_bit = 1;

  opts = (conn_options){
    .params = &params,
  };

  setup_handshake_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);
  tpe.flags = NGTCP2_PKT_FLAG_FIXED_BIT_CLEAR;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1200,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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

  opts = (conn_options){
    .settings = &settings,
    .params = &params,
  };

  setup_handshake_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);
  tpe.flags = NGTCP2_PKT_FLAG_FIXED_BIT_CLEAR;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1200,
    .base = null_data,
  };

  tpe.token = null_data;
  tpe.tokenlen = 117;

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);

  ngtcp2_conn_del(conn);

  /* Server disables grease_quic_bit, and receives an Initial packet
     with a token. */
  server_default_settings(&settings);
  settings.token = null_data;
  settings.tokenlen = 117;
  settings.token_type = NGTCP2_TOKEN_TYPE_NEW_TOKEN;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_handshake_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);
  tpe.flags = NGTCP2_PKT_FLAG_FIXED_BIT_CLEAR;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1200,
    .base = null_data,
  };

  tpe.token = null_data;
  tpe.tokenlen = 117;

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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

  opts = (conn_options){
    .settings = &settings,
    .params = &params,
  };

  setup_handshake_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn_handshake_server(&tpe, conn, &null_ckm);
  tpe.flags = NGTCP2_PKT_FLAG_FIXED_BIT_CLEAR;

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1200,
    .base = null_data,
  };

  tpe.token = null_data;
  tpe.tokenlen = 117;

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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
  ngtcp2_transport_params remote_params;
  conn_options opts;

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

  assert_uint64(NGTCP2_FRAME_STREAM_DATA_BLOCKED, ==, frc->fr.hd.type);
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

  assert_uint64(NGTCP2_FRAME_STREAM, ==, frc->fr.hd.type);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_STREAM_DATA_BLOCKED, ==, frc->fr.hd.type);
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

  assert_uint64(NGTCP2_FRAME_STREAM, ==, frc->fr.hd.type);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_STREAM_DATA_BLOCKED, ==, frc->fr.hd.type);
  assert_int64(stream_id, ==, frc->fr.stream_data_blocked.stream_id);
  assert_uint64(strm->tx.max_offset, ==, frc->fr.stream_data_blocked.offset);
  assert_uint64(strm->tx.max_offset, ==, strm->tx.last_blocked_offset);
  assert_null(frc->next);

  ngtcp2_conn_del(conn);

  /* Stream is blocked after writing another stream data. */
  client_default_remote_transport_params(&remote_params);
  remote_params.initial_max_streams_bidi = 2;

  opts = (conn_options){
    .remote_params = &remote_params,
  };

  setup_default_client_with_options(&conn, opts);

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

  assert_uint64(NGTCP2_FRAME_STREAM, ==, frc->fr.hd.type);
  assert_int64(stream_id2, ==, frc->fr.stream.stream_id);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_STREAM_DATA_BLOCKED, ==, frc->fr.hd.type);
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

  assert_uint64(NGTCP2_FRAME_STREAM_DATA_BLOCKED, ==, frc->fr.hd.type);
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

  assert_uint64(NGTCP2_FRAME_DATA_BLOCKED, ==, frc->fr.hd.type);
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

  assert_uint64(NGTCP2_FRAME_STREAM, ==, frc->fr.hd.type);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_DATA_BLOCKED, ==, frc->fr.hd.type);
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

  assert_uint64(NGTCP2_FRAME_DATA_BLOCKED, ==, frc->fr.hd.type);
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
  int rv;
  uint64_t seq;
  ngtcp2_tpe tpe;

  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(7, ==, conn->scid.num_in_flight);

  /* Retire 1 Connection ID */
  fr.retire_connection_id = (ngtcp2_retire_connection_id){
    .type = NGTCP2_FRAME_RETIRE_CONNECTION_ID,
    .seq = conn->scid.last_seq,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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
  fr.retire_connection_id = (ngtcp2_retire_connection_id){
    .type = NGTCP2_FRAME_RETIRE_CONNECTION_ID,
    .seq = conn->scid.last_seq - 2,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

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
  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(0, ==, rv);
  assert_size(1, ==, conn->scid.num_in_flight);

  /* Now NEW_CONNECTION_ID can be sent. */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_size(2, ==, conn->scid.num_in_flight);
  assert_uint64(seq + 1, ==, conn->scid.last_seq);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_submit_crypto_data(void) {
  ngtcp2_conn *conn;
  uint8_t buf[1200];
  ngtcp2_ssize spktlen;
  ngtcp2_ksl_it it;
  ngtcp2_rtb_entry *ent;
  ngtcp2_frame_chain *frc;
  int rv;

  /* Send CRYPTO in 1RTT packet */
  setup_default_server(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), 0);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_1RTT,
                                      null_data, 999);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), 0);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);

  assert_false(ngtcp2_ksl_it_end(&it));

  ent = ngtcp2_ksl_it_get(&it);
  frc = ent->frc;

  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, frc->fr.hd.type);
  assert_uint64(0, ==, frc->fr.stream.offset);
  assert_uint64(999, ==,
                ngtcp2_vec_len(frc->fr.stream.data, frc->fr.stream.datacnt));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_submit_new_token(void) {
  ngtcp2_conn *conn;
  ngtcp2_rtb_entry *ent;
  ngtcp2_ksl_it it;
  ngtcp2_frame_chain *frc;
  ngtcp2_ssize spktlen;
  ngtcp2_frame fr;
  ngtcp2_tpe tpe;
  const uint8_t large_token[NGTCP2_FRAME_CHAIN_NEW_TOKEN_THRES + 1] = {0xEF};
  const uint8_t small_token[NGTCP2_FRAME_CHAIN_NEW_TOKEN_THRES] = {0xFE};
  uint8_t buf[1200];
  size_t pktlen;
  int rv;

  setup_default_server(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), 0);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_submit_new_token(conn, large_token, sizeof(large_token));

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_submit_new_token(conn, small_token, sizeof(small_token));

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), 0);

  assert_ptrdiff(0, <, spktlen);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);
  ent = ngtcp2_ksl_it_get(&it);
  frc = ent->frc;

  assert_uint64(NGTCP2_FRAME_NEW_TOKEN, ==, frc->fr.hd.type);
  assert_memn_equal(small_token, sizeof(small_token), frc->fr.new_token.token,
                    frc->fr.new_token.tokenlen);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_NEW_TOKEN, ==, frc->fr.hd.type);
  assert_memn_equal(large_token, sizeof(large_token), frc->fr.new_token.token,
                    frc->fr.new_token.tokenlen);
  assert_null(frc->next);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
    .first_ack_range = 1,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen,
                            30 * NGTCP2_MILLISECONDS);

  assert_int(0, ==, rv);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);

  assert_true(ngtcp2_ksl_it_end(&it));
  assert_null(conn->pktns.tx.frq);

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
  ngtcp2_tpe tpe;

  setup_default_client(&conn);
  ngtcp2_tpe_init_conn(&tpe, conn);

  spktlen =
    ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                             NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, t);

  assert_ptrdiff(0, <, spktlen);

  spktlen =
    ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                             NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, t);

  assert_ptrdiff(0, ==, spktlen);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  t += 30 * NGTCP2_MILLISECONDS;
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

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
        ngtcp2_max_uint64(4 * conn->cstat.rttvar, NGTCP2_GRANULARITY) +
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

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  t += 30 * NGTCP2_MILLISECONDS;
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  assert_int(0, ==, rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  assert_size(2, ==, strm->tx.loss_count);
  /* Persistent congestion resets min_rtt */
  assert_uint64(UINT64_MAX, ==, conn->cstat.min_rtt);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_ack_padding(void) {
  ngtcp2_conn *conn;
  uint8_t buf[1200];
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 0;
  ngtcp2_frame fr[2];
  ngtcp2_tpe tpe;
  size_t pktlen;
  int rv;
  ngtcp2_cid dcid;
  ngtcp2_transport_params remote_params;
  conn_options opts;

  dcid.datalen = 0;

  server_default_remote_transport_params(&remote_params);
  remote_params.initial_scid = dcid;

  opts = (conn_options){
    .dcid = &dcid,
    .remote_params = &remote_params,
  };

  /* ACK only packet which is padded to make packet at minimum size is
     not counted toward CWND. */
  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  spktlen =
    ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                             NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, t);

  assert_ptrdiff(0, <, spktlen);

  spktlen =
    ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                             NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, t);

  assert_ptrdiff(0, ==, spktlen);

  fr[0].ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
  };

  fr[1].ping.type = NGTCP2_FRAME_PING;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), fr, 2);
  t += 30 * NGTCP2_MILLISECONDS;
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  assert_int(0, ==, rv);

  t += 30 * NGTCP2_MILLISECONDS;

  spktlen =
    ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                             NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, t);

  assert_ptrdiff(0, <, spktlen);
  assert_true(ngtcp2_rtb_empty(&conn->pktns.rtb));
  assert_uint64(0, ==, conn->cstat.bytes_in_flight);

  fr[0].ping.type = NGTCP2_FRAME_PING;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  assert_int(0, ==, rv);

  t += 30 * NGTCP2_MILLISECONDS;

  /* PING frame is included along side ACK this time. */
  spktlen =
    ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                             NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, t);

  assert_ptrdiff(0, <, spktlen);
  assert_false(ngtcp2_rtb_empty(&conn->pktns.rtb));

  fr[0].ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = 2,
    .first_ack_range = 1,
  };

  fr[1].ping.type = NGTCP2_FRAME_PING;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), fr, 2);
  t += 30 * NGTCP2_MILLISECONDS;
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  assert_int(0, ==, rv);
  assert_true(ngtcp2_rtb_empty(&conn->pktns.rtb));
  assert_uint64(0, ==, conn->cstat.bytes_in_flight);

  /* Make CWND limited */
  conn->cstat.bytes_in_flight = conn->cstat.cwnd;

  t += 30 * NGTCP2_MILLISECONDS;

  spktlen =
    ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                             NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, t);

  assert_ptrdiff(0, <, spktlen);
  assert_true(ngtcp2_rtb_empty(&conn->pktns.rtb));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_super_small_rtt(void) {
  ngtcp2_settings settings;
  ngtcp2_conn *conn;
  uint8_t buf[1200];
  ngtcp2_ssize spktlen;
  int rv;
  int64_t stream_id;
  ngtcp2_tstamp expiry;
  ngtcp2_tpe tpe;
  ngtcp2_tstamp t = 0;
  ngtcp2_frame fr;
  size_t pktlen;
  conn_options opts;

  client_default_settings(&settings);
  settings.initial_rtt = NGTCP2_NANOSECONDS;

  opts = (conn_options){
    .settings = &settings,
  };

  setup_default_client_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  spktlen =
    ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                             NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, t);

  assert_ptrdiff(0, <, spktlen);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 211, t);

  assert_ptrdiff(0, <, spktlen);

  expiry = ngtcp2_conn_loss_detection_expiry(conn);

  assert_uint64(1000001, ==, expiry);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  assert_int(0, ==, rv);
  assert_uint64(NGTCP2_NANOSECONDS, ==, conn->cstat.latest_rtt);
  assert_uint64(NGTCP2_NANOSECONDS, ==, conn->cstat.min_rtt);
  assert_uint64(NGTCP2_NANOSECONDS, ==, conn->cstat.smoothed_rtt);
  assert_uint64(0, ==, conn->cstat.rttvar);

  spktlen =
    ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                             NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, t);

  assert_ptrdiff(0, ==, spktlen);

  t = 1000001;

  rv = ngtcp2_conn_handle_expiry(conn, t);

  assert_int(0, ==, rv);

  spktlen =
    ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                             NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, t);

  assert_ptrdiff(0, <, spktlen);

  expiry = ngtcp2_conn_loss_detection_expiry(conn);

  assert_uint64(3000003, ==, expiry);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_ack(void) {
  ngtcp2_conn *conn;
  uint8_t buf[1200];
  ngtcp2_ack_range ack_ranges[NGTCP2_MAX_ACK_RANGES];
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_tpe tpe;
  ngtcp2_tstamp t = 0;
  int rv;
  int64_t stream_id;

  /* Acknowledging skipped packet number. */
  setup_default_server(&conn);
  conn->pktns.tx.skip_pkt.next_pkt_num = 0;
  ngtcp2_tpe_init_conn(&tpe, conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_int64(1, ==, conn->pktns.tx.last_pkt_num);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_PROTO, ==, rv);

  ngtcp2_conn_del(conn);

  /* Acknowledging skipped packet number along with the following
     packet. */
  setup_default_server(&conn);
  conn->pktns.tx.skip_pkt.next_pkt_num = 0;
  ngtcp2_tpe_init_conn(&tpe, conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_int64(1, ==, conn->pktns.tx.last_pkt_num);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
    .first_ack_range = 1,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_PROTO, ==, rv);

  ngtcp2_conn_del(conn);

  /* Acknowledging skipped packet number in the second ACK block. */
  setup_default_client(&conn);
  conn->pktns.tx.skip_pkt.next_pkt_num = 0;
  ngtcp2_tpe_init_conn(&tpe, conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_int64(1, ==, conn->pktns.tx.last_pkt_num);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     null_data, 999, ++t);

  assert_ptrdiff(0, <, spktlen);
  assert_int64(2, ==, conn->pktns.tx.last_pkt_num);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = conn->pktns.tx.last_pkt_num,
    .rangecnt = 1,
    .ranges = ack_ranges,
  };
  ack_ranges[0] = (ngtcp2_ack_range){0};

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);
  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, ++t);

  assert_int(NGTCP2_ERR_PROTO, ==, rv);

  ngtcp2_conn_del(conn);
}

static ngtcp2_ssize write_pkt(ngtcp2_conn *conn, ngtcp2_path *path,
                              ngtcp2_pkt_info *pi, uint8_t *buf, size_t buflen,
                              ngtcp2_tstamp ts, void *user_data) {
  my_user_data *ud = user_data;
  ngtcp2_ssize nwrite;
  ngtcp2_ssize datalen;

  if (ud->write_pkt.num_write_left == 0) {
    return 0;
  }

  nwrite = ngtcp2_conn_write_stream(
    conn, path, pi, buf, buflen, &datalen, NGTCP2_WRITE_STREAM_FLAG_PADDING,
    ud->write_pkt.stream_id, null_data, buflen, ts);

  if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
    return 0;
  }

  if (nwrite) {
    --ud->write_pkt.num_write_left;
  }

  return nwrite;
}

void test_ngtcp2_conn_write_aggregate_pkt(void) {
  ngtcp2_conn *conn;
  uint8_t buf[65536];
  ngtcp2_ssize spktlen;
  ngtcp2_path_storage ps;
  ngtcp2_pkt_info pi;
  ngtcp2_tstamp t = 0;
  int64_t stream_id;
  my_user_data ud;
  conn_options opt;
  size_t gsolen;
  ngtcp2_frame frs[2];
  int rv;
  size_t pktlen;
  ngtcp2_tpe tpe;

  opt = (conn_options){
    .user_data = &ud,
  };

  setup_default_client_with_options(&conn, opt);
  ngtcp2_path_storage_zero(&ps);
  memset(&pi, 0, sizeof(pi));

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  ud.write_pkt.stream_id = stream_id;
  ud.write_pkt.num_write_left = 10;

  spktlen = ngtcp2_conn_write_aggregate_pkt(conn, &ps.path, &pi, buf,
                                            sizeof(buf), &gsolen, write_pkt, t);

  /* Due to CWND, only 8 packets are written. */
  assert_ptrdiff(
    (ngtcp2_ssize)ngtcp2_conn_get_path_max_tx_udp_payload_size(conn) * 8, ==,
    spktlen);
  assert_ptrdiff(sizeof(buf), >=, spktlen);
  assert_size(ngtcp2_conn_get_path_max_tx_udp_payload_size(conn), ==, gsolen);
  assert_true(ngtcp2_path_eq(&null_path.path, &ps.path));
  assert_uint8(NGTCP2_ECN_ECT_0, ==, pi.ecn);
  assert_size(2, ==, ud.write_pkt.num_write_left);

  ngtcp2_conn_del(conn);

  /* num_pkts = 1 */
  opt = (conn_options){
    .user_data = &ud,
  };

  setup_default_client_with_options(&conn, opt);
  ngtcp2_path_storage_zero(&ps);
  memset(&pi, 0, sizeof(pi));

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  ud.write_pkt.stream_id = stream_id;
  ud.write_pkt.num_write_left = 10;

  spktlen = ngtcp2_conn_write_aggregate_pkt2(
    conn, &ps.path, &pi, buf, sizeof(buf), &gsolen, write_pkt, 1, t);

  assert_ptrdiff(
    (ngtcp2_ssize)ngtcp2_conn_get_path_max_tx_udp_payload_size(conn), ==,
    spktlen);
  assert_ptrdiff(sizeof(buf), >=, spktlen);
  assert_size(ngtcp2_conn_get_path_max_tx_udp_payload_size(conn), ==, gsolen);
  assert_true(ngtcp2_path_eq(&null_path.path, &ps.path));
  assert_uint8(NGTCP2_ECN_ECT_0, ==, pi.ecn);
  assert_size(9, ==, ud.write_pkt.num_write_left);

  ngtcp2_conn_del(conn);

  /* num_pkts = 3 */
  opt = (conn_options){
    .user_data = &ud,
  };

  setup_default_client_with_options(&conn, opt);
  ngtcp2_path_storage_zero(&ps);
  memset(&pi, 0, sizeof(pi));

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  ud.write_pkt.stream_id = stream_id;
  ud.write_pkt.num_write_left = 10;

  spktlen = ngtcp2_conn_write_aggregate_pkt2(
    conn, &ps.path, &pi, buf, sizeof(buf), &gsolen, write_pkt, 3, t);

  assert_ptrdiff(
    (ngtcp2_ssize)ngtcp2_conn_get_path_max_tx_udp_payload_size(conn) * 3, ==,
    spktlen);
  assert_ptrdiff(sizeof(buf), >=, spktlen);
  assert_size(ngtcp2_conn_get_path_max_tx_udp_payload_size(conn), ==, gsolen);
  assert_true(ngtcp2_path_eq(&null_path.path, &ps.path));
  assert_uint8(NGTCP2_ECN_ECT_0, ==, pi.ecn);
  assert_size(7, ==, ud.write_pkt.num_write_left);

  ngtcp2_conn_del(conn);

  /* PATH_RESPONSE stops aggregation. */
  opt = (conn_options){
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opt);
  ngtcp2_tpe_init_conn(&tpe, conn);
  ngtcp2_path_storage_zero(&ps);
  memset(&pi, 0, sizeof(pi));

  frs[0].path_challenge = (ngtcp2_path_challenge){
    .type = NGTCP2_FRAME_PATH_CHALLENGE,
    .data = {0x11},
  };
  frs[1].new_connection_id = (ngtcp2_new_connection_id){
    .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
    .seq = 1,
    .cid =
      {
        .data = {0xFE},
        .datalen = 11,
      },
    .token =
      {
        .data = {0xAB},
      },
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), frs, 2);

  rv = ngtcp2_conn_read_pkt(conn, &new_path.path, NULL, buf, pktlen, t);

  assert_int(0, ==, rv);
  assert_size(1, ==, ngtcp2_ringbuf_len(&conn->rx.path_challenge.rb));

  open_stream(conn, 0);

  ud.write_pkt.stream_id = 0;
  ud.write_pkt.num_write_left = 2;

  spktlen = ngtcp2_conn_write_aggregate_pkt(
    conn, &ps.path, &pi, buf, sizeof(buf), &gsolen, write_pkt, ++t);

  /* We have not validated new path, and server is subject to
     anti-amplification limit. */
  assert_ptrdiff(0, <, spktlen);
  assert_ptrdiff(
    (ngtcp2_ssize)ngtcp2_conn_get_path_max_tx_udp_payload_size(conn), >,
    spktlen);
  assert_size((size_t)spktlen, ==, gsolen);
  assert_true(ngtcp2_path_eq(&new_path.path, &ps.path));
  assert_uint8(NGTCP2_ECN_NOT_ECT, ==, pi.ecn);
  assert_size(0, ==, ngtcp2_ringbuf_len(&conn->rx.path_challenge.rb));
  assert_size(1, ==, ud.write_pkt.num_write_left);

  t += ngtcp2_conn_get_expiry(conn);

  ud.write_pkt.stream_id = 0;
  ud.write_pkt.num_write_left = 2;

  spktlen = ngtcp2_conn_write_aggregate_pkt(conn, &ps.path, &pi, buf,
                                            sizeof(buf), &gsolen, write_pkt, t);

  assert_ptrdiff(
    (ngtcp2_ssize)ngtcp2_conn_get_path_max_tx_udp_payload_size(conn) * 2, ==,
    spktlen);
  assert_size(ngtcp2_conn_get_path_max_tx_udp_payload_size(conn), ==, gsolen);
  assert_true(ngtcp2_path_eq(&null_path.path, &ps.path));
  assert_uint8(NGTCP2_ECN_ECT_0, ==, pi.ecn);
  assert_size(0, ==, ud.write_pkt.num_write_left);

  ngtcp2_conn_del(conn);

  /* Pass the buffer of the minimum size */
  opt = (conn_options){
    .user_data = &ud,
  };

  setup_default_client_with_options(&conn, opt);
  ngtcp2_path_storage_zero(&ps);
  memset(&pi, 0, sizeof(pi));

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  ud.write_pkt.stream_id = stream_id;
  ud.write_pkt.num_write_left = 10;

  spktlen = ngtcp2_conn_write_aggregate_pkt(
    conn, &ps.path, &pi, buf,
    ngtcp2_conn_get_path_max_tx_udp_payload_size(conn), &gsolen, write_pkt, t);

  assert_ptrdiff(
    (ngtcp2_ssize)ngtcp2_conn_get_path_max_tx_udp_payload_size(conn), ==,
    spktlen);
  assert_size(ngtcp2_conn_get_path_max_tx_udp_payload_size(conn), ==, gsolen);
  assert_true(ngtcp2_path_eq(&null_path.path, &ps.path));
  assert_uint8(NGTCP2_ECN_ECT_0, ==, pi.ecn);
  assert_size(9, ==, ud.write_pkt.num_write_left);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_crumble_initial_pkt(void) {
  ngtcp2_conn *conn;
  uint8_t tls_rawbuf[4096] = {0};
  ngtcp2_buf tls_buf;
  int rv;
  ngtcp2_tstamp t = 0;
  uint8_t buf[1200];
  ngtcp2_ssize spktlen;
  ngtcp2_ssize slen;
  ngtcp2_pkt_hd hd;
  ngtcp2_frame_decoder frd;
  ngtcp2_frame fr;
  uint64_t offset;
  uint8_t *p;
  size_t len;
  ngtcp2_frame_chain *frc;
  ngtcp2_ksl_it it;
  ngtcp2_rtb_entry *ent;
  ngtcp2_callbacks callbacks;
  conn_options opts;
  uint8_t *end_data;

  ngtcp2_buf_init(&tls_buf, tls_rawbuf, sizeof(tls_rawbuf));

  /* msg_type */
  *tls_buf.last++ = 1;
  /* length */
  tls_buf.last = ngtcp2_put_uint24be(tls_buf.last, 1000);
  /* legacy_version */
  tls_buf.last = ngtcp2_put_uint16be(tls_buf.last, 0x0303);
  /* random */
  tls_buf.last += 32;
  /* legacy_session_id */
  *tls_buf.last++ = 23;
  tls_buf.last += 23;
  /* cipher_suites */
  tls_buf.last = ngtcp2_put_uint16be(tls_buf.last, 125);
  tls_buf.last += 125;
  /* legacy_compression_methods */
  *tls_buf.last++ = 7;
  tls_buf.last += 7;
  /* extensions */
  tls_buf.last = ngtcp2_put_uint16be(tls_buf.last, 400);
  /* extension 1 */
  tls_buf.last = ngtcp2_put_uint16be(tls_buf.last, 999);
  tls_buf.last = ngtcp2_put_uint16be(tls_buf.last, 120);
  tls_buf.last += 120;
  /* extension 2 */
  tls_buf.last = ngtcp2_put_uint16be(tls_buf.last, 65530);
  tls_buf.last = ngtcp2_put_uint16be(tls_buf.last, 0);
  /* server_name extension */
  tls_buf.last = ngtcp2_put_uint16be(tls_buf.last, 0);
  tls_buf.last = ngtcp2_put_uint16be(tls_buf.last, 15);
  /* server_name_list */
  tls_buf.last = ngtcp2_put_uint16be(tls_buf.last, 13);
  /* name_type */
  *tls_buf.last++ = 0;
  /* name */
  tls_buf.last = ngtcp2_put_uint16be(tls_buf.last, 10);
  tls_buf.last += 10;

  /* Crumble client Initial CRYPTO frame */
  client_default_callbacks(&callbacks);
  callbacks.client_initial = client_initial_null;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_handshake_client_with_options(&conn, opts);
  conn->flags |= NGTCP2_CONN_FLAG_CRUMBLE_INITIAL_CRYPTO;

  rv = ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL,
                                      tls_buf.pos, ngtcp2_buf_len(&tls_buf));

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ssize(0, <, spktlen);

  slen = ngtcp2_pkt_decode_hd_long(&hd, buf, (size_t)spktlen);

  assert_ptrdiff(0, <, slen);
  assert_uint8(NGTCP2_PKT_INITIAL, ==, hd.type);

  slen = ngtcp2_frame_decoder_decode(&frd, &fr, buf + slen,
                                     (size_t)(spktlen - slen));

  assert_ptrdiff(0, <, slen);
  /* If PADDING is seen at the top, it means CRYPTO was crumbled. */
  assert_uint64(NGTCP2_FRAME_PADDING, ==, fr.hd.type);
  assert_uint64(1, ==, fr.padding.len);

  ngtcp2_conn_del(conn);

  /* We have CRYPTO data worth of more than 1 packet.  The part of SNI
     should be in the second packet. */
  client_default_callbacks(&callbacks);
  callbacks.client_initial = client_initial_null;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_handshake_client_with_options(&conn, opts);
  conn->flags |= NGTCP2_CONN_FLAG_CRUMBLE_INITIAL_CRYPTO;

  rv = ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL,
                                      tls_buf.pos, ngtcp2_buf_len(&tls_buf));

  assert_int(0, ==, rv);

  rv = ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL,
                                      null_data, sizeof(null_data));

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ssize(0, <, spktlen);
  assert_size(2, ==, ngtcp2_ksl_len(conn->in_pktns->crypto.strm.tx.streamfrq));

  it = ngtcp2_rtb_head(&conn->in_pktns->rtb);

  ent = ngtcp2_ksl_it_get(&it);
  frc = ent->frc;

  /* This is the data before the removed data. */
  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, frc->fr.hd.type);
  assert_uint64(0, ==, frc->fr.stream.offset);
  assert_size(1, ==, frc->fr.stream.datacnt);
  assert_size(341, ==, frc->fr.stream.data[0].len);
  assert_not_null(frc->next);

  end_data = ngtcp2_vec_end(&frc->fr.stream.data[0]);

  frc = frc->next;

  /* This is the data after the removed data. */
  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, frc->fr.hd.type);
  assert_uint64(ngtcp2_buf_len(&tls_buf) - 1, ==, frc->fr.stream.offset);
  assert_size(2, ==, frc->fr.stream.datacnt);
  assert_size(1, ==, frc->fr.stream.data[0].len);
  assert_ptr_equal(end_data + 4, frc->fr.stream.data[0].base);
  assert_size(735, ==, frc->fr.stream.data[1].len);
  assert_null(frc->next);

  slen = ngtcp2_pkt_decode_hd_long(&hd, buf, (size_t)spktlen);

  assert_ptrdiff(0, <, slen);
  assert_uint8(NGTCP2_PKT_INITIAL, ==, hd.type);

  offset = 0;
  p = buf + slen;
  len = hd.len - NGTCP2_FAKE_AEAD_OVERHEAD;

  for (;;) {
    slen = ngtcp2_frame_decoder_decode(&frd, &fr, p, len);

    assert_ptrdiff(0, <, slen);

    if (fr.hd.type == NGTCP2_FRAME_CRYPTO) {
      offset = ngtcp2_max_uint64(offset, fr.stream.offset);
    }

    p += slen;
    len -= (size_t)slen;

    if (len == 0) {
      break;
    }
  }

  assert_uint64(0, <, offset);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ssize(0, <, spktlen);

  it = ngtcp2_rtb_head(&conn->in_pktns->rtb);

  ent = ngtcp2_ksl_it_get(&it);
  frc = ent->frc;

  /* This is the portion of removed data. */
  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, frc->fr.hd.type);
  assert_uint64(341, ==, frc->fr.stream.offset);
  assert_size(1, ==, frc->fr.stream.datacnt);
  assert_size(4, ==, frc->fr.stream.data[0].len);
  assert_ptr_equal(end_data, frc->fr.stream.data[0].base);
  assert_not_null(frc->next);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, frc->fr.hd.type);
  assert_uint64(ngtcp2_buf_len(&tls_buf) + 735, ==, frc->fr.stream.offset);
  assert_size(1, ==, frc->fr.stream.datacnt);
  assert_size(1022, ==, frc->fr.stream.data[0].len);
  assert_null(frc->next);

  slen = ngtcp2_pkt_decode_hd_long(&hd, buf, (size_t)spktlen);

  assert_ptrdiff(0, <, slen);
  assert_uint8(NGTCP2_PKT_INITIAL, ==, hd.type);

  p = buf + slen;
  len = hd.len - NGTCP2_FAKE_AEAD_OVERHEAD;

  /* The 2nd packet should have CRYPTO whose offset is less than
     offset. */
  for (;;) {
    slen = ngtcp2_frame_decoder_decode(&frd, &fr, p, len);

    assert_ptrdiff(0, <, slen);

    if (fr.hd.type == NGTCP2_FRAME_CRYPTO) {
      if (fr.stream.offset < offset) {
        offset = 0;
        break;
      }
    }

    p += slen;
    len -= (size_t)slen;

    if (len == 0) {
      break;
    }
  }

  assert_uint64(0, ==, offset);

  ngtcp2_conn_del(conn);

  /* Check the case that datacnt does not change. */
  client_default_callbacks(&callbacks);
  callbacks.client_initial = client_initial_null;

  opts = (conn_options){
    .callbacks = &callbacks,
  };

  setup_handshake_client_with_options(&conn, opts);
  conn->flags |= NGTCP2_CONN_FLAG_CRUMBLE_INITIAL_CRYPTO;

  rv = ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL,
                                      tls_buf.pos, ngtcp2_buf_len(&tls_buf));

  assert_int(0, ==, rv);

  rv = ngtcp2_frame_chain_stream_datacnt_objalloc_new(
    &frc, 1, &conn->frc_objalloc, conn->mem);

  assert_int(0, ==, rv);

  frc->fr.stream.type = NGTCP2_FRAME_CRYPTO;
  frc->fr.stream.flags = 0;
  frc->fr.stream.fin = 0;
  frc->fr.stream.stream_id = 0;
  frc->fr.stream.offset = 1200;
  frc->fr.stream.datacnt = 1;
  frc->fr.stream.data[0] = (ngtcp2_vec){
    .base = null_data,
    .len = 100,
  };

  rv = ngtcp2_strm_streamfrq_push(&conn->in_pktns->crypto.strm, frc);

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), ++t);

  assert_ssize(0, <, spktlen);
  assert_size(0, ==, ngtcp2_ksl_len(conn->in_pktns->crypto.strm.tx.streamfrq));

  it = ngtcp2_rtb_head(&conn->in_pktns->rtb);

  ent = ngtcp2_ksl_it_get(&it);
  frc = ent->frc;

  /* This is the data before the removed data. */
  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, frc->fr.hd.type);
  assert_uint64(0, ==, frc->fr.stream.offset);
  assert_size(1, ==, frc->fr.stream.datacnt);
  assert_size(341, ==, frc->fr.stream.data[0].len);
  assert_not_null(frc->next);

  end_data = ngtcp2_vec_end(&frc->fr.stream.data[0]);

  frc = frc->next;

  /* This is the data after the removed data. */
  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, frc->fr.hd.type);
  assert_uint64(ngtcp2_buf_len(&tls_buf) - 1, ==, frc->fr.stream.offset);
  assert_size(1, ==, frc->fr.stream.datacnt);
  assert_size(1, ==, frc->fr.stream.data[0].len);
  assert_ptr_equal(end_data + 4, frc->fr.stream.data[0].base);
  assert_not_null(frc->next);

  frc = frc->next;

  /* This is the portion of removed data. */
  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, frc->fr.hd.type);
  assert_uint64(341, ==, frc->fr.stream.offset);
  assert_size(1, ==, frc->fr.stream.datacnt);
  assert_size(4, ==, frc->fr.stream.data[0].len);
  assert_ptr_equal(end_data, frc->fr.stream.data[0].base);
  assert_not_null(frc->next);

  frc = frc->next;

  assert_uint64(NGTCP2_FRAME_CRYPTO, ==, frc->fr.hd.type);
  assert_uint64(1200, ==, frc->fr.stream.offset);
  assert_size(1, ==, frc->fr.stream.datacnt);
  assert_size(100, ==, frc->fr.stream.data[0].len);
  assert_null(frc->next);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_skip_pkt_num(void) {
  ngtcp2_conn *conn;
  uint8_t buf[1200];
  ngtcp2_ssize spktlen;
  int64_t stream_id;
  int rv;
  size_t i;
  ngtcp2_tstamp t = 0;
  conn_options opts;
  ngtcp2_rtb_entry *ent;
  ngtcp2_ksl_it it;

  /* Skip packet number */
  opts = (conn_options){
    .skip_pkt_num = 1,
  };

  setup_default_client_with_options(&conn, opts);

  assert_int64(3, ==, conn->pktns.tx.skip_pkt.next_pkt_num);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  for (i = 0; i < 4; ++i) {
    spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                       NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                       null_data, 1, ++t);

    assert_ptrdiff(0, <, spktlen);
  }

  assert_int64(4, ==, conn->pktns.tx.last_pkt_num);
  assert_int64(8, ==, conn->pktns.tx.skip_pkt.next_pkt_num);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);
  ngtcp2_ksl_it_next(&it);
  ent = ngtcp2_ksl_it_get(&it);

  assert_int64(3, ==, ent->hd.pkt_num);
  assert_true(ent->flags & NGTCP2_RTB_ENTRY_FLAG_SKIP);

  for (i = 0; i < 4; ++i) {
    spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                       NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                       null_data, 1, ++t);

    assert_ptrdiff(0, <, spktlen);
  }

  assert_int64(9, ==, conn->pktns.tx.last_pkt_num);
  assert_int64(15, ==, conn->pktns.tx.skip_pkt.next_pkt_num);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);
  ngtcp2_ksl_it_next(&it);
  ent = ngtcp2_ksl_it_get(&it);

  assert_int64(8, ==, ent->hd.pkt_num);
  assert_true(ent->flags & NGTCP2_RTB_ENTRY_FLAG_SKIP);

  ngtcp2_conn_del(conn);

  /* gap overflow */
  opts = (conn_options){
    .skip_pkt_num = 1,
  };

  setup_default_client_with_options(&conn, opts);

  conn->pktns.tx.skip_pkt.exponent = 62;

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  for (i = 0; i < 4; ++i) {
    spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                       NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                       null_data, 1, ++t);

    assert_ptrdiff(0, <, spktlen);
  }

  assert_int64(4, ==, conn->pktns.tx.last_pkt_num);
  assert_int64(INT64_MAX, ==, conn->pktns.tx.skip_pkt.next_pkt_num);

  ngtcp2_conn_del(conn);

  /* adding packet number and gap causes overflow */
  opts = (conn_options){
    .skip_pkt_num = 1,
  };

  setup_default_client_with_options(&conn, opts);

  conn->pktns.tx.skip_pkt.next_pkt_num = NGTCP2_MAX_PKT_NUM - 4;
  conn->pktns.tx.last_pkt_num = NGTCP2_MAX_PKT_NUM - 8;

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);

  for (i = 0; i < 4; ++i) {
    spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                       NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                       null_data, 1, ++t);

    assert_ptrdiff(0, <, spktlen);
  }

  assert_int64(NGTCP2_MAX_PKT_NUM - 3, ==, conn->pktns.tx.last_pkt_num);
  assert_int64(INT64_MAX, ==, conn->pktns.tx.skip_pkt.next_pkt_num);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_get_timestamp(void) {
  ngtcp2_conn *conn;
  uint8_t buf[1200];
  ngtcp2_ssize spktlen;

  setup_default_client(&conn);

  assert_uint64(0, ==, ngtcp2_conn_get_timestamp(conn));

  spktlen =
    ngtcp2_conn_write_pkt(conn, NULL, NULL, buf, sizeof(buf), 1000000007);

  assert_ssize(0, <, spktlen);
  assert_uint64(1000000007, ==, ngtcp2_conn_get_timestamp(conn));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_get_stream_user_data(void) {
  ngtcp2_conn *conn;
  int rv;
  int64_t stream_id;

  /* Getting NULL stream_user_data */
  setup_default_client(&conn);

  assert_null(ngtcp2_conn_get_stream_user_data(conn, 0));

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);
  assert_null(ngtcp2_conn_get_stream_user_data(conn, stream_id));

  ngtcp2_conn_del(conn);

  /* Getting the associated stream_user_data */
  setup_default_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, &rv);

  assert_int(0, ==, rv);
  assert_ptr_equal(&rv, ngtcp2_conn_get_stream_user_data(conn, stream_id));

  rv = ngtcp2_conn_open_uni_stream(conn, &stream_id, &stream_id);

  assert_int(0, ==, rv);
  assert_ptr_equal(&stream_id,
                   ngtcp2_conn_get_stream_user_data(conn, stream_id));

  rv = ngtcp2_conn_set_stream_user_data(conn, stream_id, conn);

  assert_int(0, ==, rv);
  assert_ptr_equal(conn, ngtcp2_conn_get_stream_user_data(conn, stream_id));

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

static void setup_failmalloc_mem(ngtcp2_mem *mem, failmalloc *mc) {
  mem->user_data = mc;
  mem->malloc = failmalloc_malloc;
  mem->free = failmalloc_free;
  mem->calloc = failmalloc_calloc;
  mem->realloc = failmalloc_realloc;
}

void test_ngtcp2_conn_new_failmalloc(void) {
  ngtcp2_conn *conn;
  ngtcp2_callbacks cb;
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  failmalloc mc;
  ngtcp2_mem mem;
  uint8_t token[] = "token";
  size_t tokenlen = ngtcp2_strlen_lit(token);
  uint32_t preferred_versions[] = {
    NGTCP2_PROTO_VER_V1,
    NGTCP2_PROTO_VER_V2,
  };
  uint32_t available_versions[] = {
    NGTCP2_PROTO_VER_V2,
    NGTCP2_PROTO_VER_V1,
    0x5A9AEACA,
  };
  ngtcp2_cid dcid, scid;
  int rv;
  size_t i;
  size_t nmalloc;

  setup_failmalloc_mem(&mem, &mc);

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

static size_t server_perform_post_handshake(size_t nmalloc_fail_start) {
  ngtcp2_conn *conn;
  failmalloc mc;
  ngtcp2_mem mem;
  int rv;
  uint8_t buf[1200];
  ngtcp2_tstamp t = 0;
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_tpe tpe;
  ngtcp2_ssize spktlen;
  conn_options opts;

  setup_failmalloc_mem(&mem, &mc);

  mc.nmalloc = 0;
  mc.fail_start = SIZE_MAX;

  opts = (conn_options){
    .mem = &mem,
  };

  setup_default_server_with_options(&conn, opts);
  ngtcp2_tpe_init_conn(&tpe, conn);

  mc.nmalloc = 0;
  mc.fail_start = nmalloc_fail_start;

  spktlen =
    ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                             NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, t);

  if (mc.nmalloc >= mc.fail_start) {
    rv = (int)spktlen;
    goto fail;
  }

  assert_ptrdiff(0, <, spktlen);

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  t += 22 * NGTCP2_MILLISECONDS;

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  if (mc.nmalloc >= mc.fail_start) {
    goto fail;
  }

  assert_int(0, ==, rv);

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .stream_id = 4,
    .offset = 1,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1008,
    .base = null_data,
  };

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

  t += 5 * NGTCP2_MILLISECONDS;

  rv = ngtcp2_conn_read_pkt(conn, &null_path.path, NULL, buf, pktlen, t);

  if (mc.nmalloc >= mc.fail_start) {
    goto fail;
  }

  assert_int(0, ==, rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, 4,
                                     null_data, 1111, t);

  if (mc.nmalloc >= mc.fail_start) {
    rv = (int)spktlen;
    goto fail;
  }

  assert_ptrdiff(0, <, spktlen);

  t = ngtcp2_conn_get_expiry(conn);

  rv = ngtcp2_conn_handle_expiry(conn, t);

  if (mc.nmalloc >= mc.fail_start) {
    goto fail;
  }

  assert_int(0, ==, rv);

  spktlen =
    ngtcp2_conn_write_stream(conn, NULL, NULL, buf, sizeof(buf), NULL,
                             NGTCP2_WRITE_STREAM_FLAG_NONE, 4, NULL, 0, t);

  if (mc.nmalloc >= mc.fail_start) {
    rv = (int)spktlen;
    goto fail;
  }

  assert_ptrdiff(0, <, spktlen);

fail:
  if (rv < 0) {
    assert_int(NGTCP2_ERR_NOMEM, ==, rv);
  }

  ngtcp2_conn_del(conn);

  return mc.nmalloc;
}

void test_ngtcp2_conn_post_handshake_failmalloc(void) {
  size_t nmalloc, n;
  size_t i;

  nmalloc = server_perform_post_handshake(SIZE_MAX);

  for (i = 0; i < nmalloc; ++i) {
    n = server_perform_post_handshake(i + 1);

    assert_size(i + 1, ==, n);
  }

  n = server_perform_post_handshake(i + 1);

  assert_size(nmalloc, ==, n);
}

void test_ngtcp2_accept(void) {
  size_t pktlen;
  uint8_t buf[2048];
  ngtcp2_cid dcid, scid;
  ngtcp2_vec datav;
  ngtcp2_frame fr;
  int rv;
  ngtcp2_pkt_hd hd;
  ngtcp2_tpe tpe;

  dcid_init(&dcid);
  scid_init(&scid);

  /* Initial packet */
  memset(&hd, 0, sizeof(hd));

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1200,
    .base = null_data,
  };

  ngtcp2_tpe_init(&tpe, &dcid, &scid, NGTCP2_PROTO_VER_V1);
  tpe.initial.ckm = &null_ckm;

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

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

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1200,
    .base = null_data,
  };

  ngtcp2_tpe_init(&tpe, &dcid, &scid, NGTCP2_PROTO_VER_V1);
  tpe.early.ckm = &null_ckm;

  pktlen = ngtcp2_tpe_write_0rtt(&tpe, buf, sizeof(buf), &fr, 1);

  assert_size(1200, <=, pktlen);

  rv = ngtcp2_accept(&hd, buf, pktlen);

  assert_int(NGTCP2_ERR_INVALID_ARGUMENT, ==, rv);

  /* Unknown version */
  memset(&hd, 0, sizeof(hd));

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1200,
    .base = null_data,
  };

  ngtcp2_tpe_init(&tpe, &dcid, &scid, 0x2);
  tpe.initial.ckm = &null_ckm;

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  assert_size(1200, <=, pktlen);

  rv = ngtcp2_accept(&hd, buf, pktlen);

  /* Unknown version should be filtered out by earlier call of
     ngtcp2_pkt_decode_version_cid, that is, only supported versioned
     packet should be passed to ngtcp2_accept. */
  assert_int(NGTCP2_ERR_INVALID_ARGUMENT, ==, rv);

  /* Unknown version and the UDP payload size is less than
     NGTCP2_MAX_UDP_PAYLOAD_SIZE. */
  memset(&hd, 0, sizeof(hd));

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1127,
    .base = null_data,
  };

  ngtcp2_tpe_init(&tpe, &dcid, &scid, 0x2);
  tpe.initial.ckm = &null_ckm;

  pktlen = ngtcp2_tpe_write_initial(&tpe, buf, sizeof(buf), &fr, 1);

  assert_size(1199, ==, pktlen);

  rv = ngtcp2_accept(&hd, buf, pktlen);

  assert_int(NGTCP2_ERR_INVALID_ARGUMENT, ==, rv);

  /* Short packet */
  memset(&hd, 0, sizeof(hd));

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_CRYPTO,
    .datacnt = 1,
    .data = &datav,
  };
  datav = (ngtcp2_vec){
    .len = 1200,
    .base = null_data,
  };

  ngtcp2_tpe_init(&tpe, &dcid, NULL, NGTCP2_PROTO_VER_V1);
  tpe.app.ckm = &null_ckm;

  pktlen = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), &fr, 1);

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
  ngtcp2_crypto_aead aead = {
    .max_overhead = NGTCP2_INITIAL_AEAD_OVERHEAD,
  };
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
