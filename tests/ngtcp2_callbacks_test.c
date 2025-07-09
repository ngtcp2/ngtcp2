/*
 * ngtcp2
 *
 * Copyright (c) 2025 ngtcp2 contributors
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
#include "ngtcp2_callbacks_test.h"

#include <stdio.h>

#include "ngtcp2_callbacks.h"
#include "ngtcp2_test_helper.h"

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_callbacks_convert_to_latest),
  munit_void_test(test_ngtcp2_callbacks_convert_to_old),
  munit_test_end(),
};

const MunitSuite callbacks_suite = {
  .prefix = "/callbacks",
  .tests = tests,
};

static int client_initial(ngtcp2_conn *conn, void *user_data) {
  (void)conn;
  (void)user_data;

  return 0;
}

static int recv_client_initial(ngtcp2_conn *conn, const ngtcp2_cid *dcid,
                               void *user_data) {
  (void)conn;
  (void)dcid;
  (void)user_data;

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

static int handshake_completed(ngtcp2_conn *conn, void *user_data) {
  (void)conn;
  (void)user_data;

  return 0;
}

static int recv_version_negotiation(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                                    const uint32_t *sv, size_t nsv,
                                    void *user_data) {
  (void)conn;
  (void)hd;
  (void)sv;
  (void)nsv;
  (void)user_data;

  return 0;
}

static int encrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                   const ngtcp2_crypto_aead_ctx *aead_ctx,
                   const uint8_t *plaintext, size_t plaintextlen,
                   const uint8_t *nonce, size_t noncelen, const uint8_t *aad,
                   size_t aadlen) {
  (void)dest;
  (void)aead;
  (void)aead_ctx;
  (void)plaintext;
  (void)plaintextlen;
  (void)nonce;
  (void)noncelen;
  (void)aad;
  (void)aadlen;

  return 0;
}

static int decrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                   const ngtcp2_crypto_aead_ctx *aead_ctx,
                   const uint8_t *ciphertext, size_t ciphertextlen,
                   const uint8_t *nonce, size_t noncelen, const uint8_t *aad,
                   size_t aadlen) {
  (void)dest;
  (void)aead;
  (void)aead_ctx;
  (void)ciphertext;
  (void)ciphertextlen;
  (void)nonce;
  (void)noncelen;
  (void)aad;
  (void)aadlen;

  return 0;
}

static int hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                   const ngtcp2_crypto_cipher_ctx *hp_ctx,
                   const uint8_t *sample) {
  (void)dest;
  (void)hp;
  (void)hp_ctx;
  (void)sample;

  return 0;
}

static int recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                            int64_t stream_id, uint64_t offset,
                            const uint8_t *data, size_t datalen,
                            void *user_data, void *stream_user_data) {
  (void)conn;
  (void)flags;
  (void)stream_id;
  (void)offset;
  (void)data;
  (void)datalen;
  (void)user_data;
  (void)stream_user_data;

  return 0;
}

static int acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id,
                                    uint64_t offset, uint64_t datalen,
                                    void *user_data, void *stream_user_data) {
  (void)conn;
  (void)stream_id;
  (void)offset;
  (void)datalen;
  (void)user_data;
  (void)stream_user_data;

  return 0;
}

static int stream_open(ngtcp2_conn *conn, int64_t stream_id, void *user_data) {
  (void)conn;
  (void)stream_id;
  (void)user_data;

  return 0;
}

static int stream_close(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                        uint64_t app_error_code, void *user_data,
                        void *stream_user_data) {
  (void)conn;
  (void)flags;
  (void)stream_id;
  (void)app_error_code;
  (void)user_data;
  (void)stream_user_data;

  return 0;
}

static int recv_stateless_reset(ngtcp2_conn *conn,
                                const ngtcp2_pkt_stateless_reset *sr,
                                void *user_data) {
  (void)conn;
  (void)sr;
  (void)user_data;

  return 0;
}

static int recv_retry(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                      void *user_data) {
  (void)conn;
  (void)hd;
  (void)user_data;

  return 0;
}

static int extend_max_local_streams_bidi(ngtcp2_conn *conn,
                                         uint64_t max_streams,
                                         void *user_data) {
  (void)conn;
  (void)max_streams;
  (void)user_data;

  return 0;
}

static int extend_max_local_streams_uni(ngtcp2_conn *conn, uint64_t max_streams,
                                        void *user_data) {
  (void)conn;
  (void)max_streams;
  (void)user_data;

  return 0;
}

static void rand_cb(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx) {
  (void)dest;
  (void)destlen;
  (void)rand_ctx;
}

static int get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                 uint8_t *token, size_t cidlen,
                                 void *user_data) {
  (void)conn;
  (void)cid;
  (void)token;
  (void)cidlen;
  (void)user_data;

  return 0;
}

static int remove_connection_id(ngtcp2_conn *conn, const ngtcp2_cid *cid,
                                void *user_data) {
  (void)conn;
  (void)cid;
  (void)user_data;

  return 0;
}

static int update_key(ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
                      ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
                      ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
                      const uint8_t *current_rx_secret,
                      const uint8_t *current_tx_secret, size_t secretlen,
                      void *user_data) {
  (void)conn;
  (void)rx_secret;
  (void)tx_secret;
  (void)rx_aead_ctx;
  (void)rx_iv;
  (void)tx_aead_ctx;
  (void)tx_iv;
  (void)current_rx_secret;
  (void)current_tx_secret;
  (void)secretlen;
  (void)user_data;

  return 0;
}

static int path_validation(ngtcp2_conn *conn, uint32_t flags,
                           const ngtcp2_path *path, const ngtcp2_path *old_path,
                           ngtcp2_path_validation_result res, void *user_data) {
  (void)conn;
  (void)flags;
  (void)path;
  (void)old_path;
  (void)res;
  (void)user_data;

  return 0;
}

static int select_preferred_addr(ngtcp2_conn *conn, ngtcp2_path *dest,
                                 const ngtcp2_preferred_addr *paddr,
                                 void *user_data) {
  (void)conn;
  (void)dest;
  (void)paddr;
  (void)user_data;

  return 0;
}

static int stream_reset(ngtcp2_conn *conn, int64_t stream_id,
                        uint64_t final_size, uint64_t app_error_code,
                        void *user_data, void *stream_user_data) {
  (void)conn;
  (void)stream_id;
  (void)final_size;
  (void)app_error_code;
  (void)user_data;
  (void)stream_user_data;

  return 0;
}

static int extend_max_remote_streams_bidi(ngtcp2_conn *conn,
                                          uint64_t max_streams,
                                          void *user_data) {
  (void)conn;
  (void)max_streams;
  (void)user_data;

  return 0;
}

static int extend_max_remote_streams_uni(ngtcp2_conn *conn,
                                         uint64_t max_streams,
                                         void *user_data) {
  (void)conn;
  (void)max_streams;
  (void)user_data;

  return 0;
}

static int extend_max_stream_data(ngtcp2_conn *conn, int64_t stream_id,
                                  uint64_t max_data, void *user_data,
                                  void *stream_user_data) {
  (void)conn;
  (void)stream_id;
  (void)max_data;
  (void)user_data;
  (void)stream_user_data;

  return 0;
}

static int dcid_status(ngtcp2_conn *conn, ngtcp2_connection_id_status_type type,
                       uint64_t seq, const ngtcp2_cid *cid,
                       const uint8_t *token, void *user_data) {
  (void)conn;
  (void)type;
  (void)seq;
  (void)cid;
  (void)token;
  (void)user_data;

  return 0;
}

static int handshake_confirmed(ngtcp2_conn *conn, void *user_data) {
  (void)conn;
  (void)user_data;

  return 0;
}

static int recv_new_token(ngtcp2_conn *conn, const uint8_t *token,
                          size_t tokenlen, void *user_data) {
  (void)conn;
  (void)token;
  (void)tokenlen;
  (void)user_data;

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

static int recv_datagram(ngtcp2_conn *conn, uint32_t flags, const uint8_t *data,
                         size_t datalen, void *user_data) {
  (void)conn;
  (void)flags;
  (void)data;
  (void)datalen;
  (void)user_data;

  return 0;
}

static int ack_datagram(ngtcp2_conn *conn, uint64_t dgram_id, void *user_data) {
  (void)conn;
  (void)dgram_id;
  (void)user_data;

  return 0;
}

static int lost_datagram(ngtcp2_conn *conn, uint64_t dgram_id,
                         void *user_data) {
  (void)conn;
  (void)dgram_id;
  (void)user_data;

  return 0;
}

static int get_path_challenge_data(ngtcp2_conn *conn, uint8_t *data,
                                   void *user_data) {
  (void)conn;
  (void)data;
  (void)user_data;

  return 0;
}

static int stream_stop_sending(ngtcp2_conn *conn, int64_t stream_id,
                               uint64_t app_error_code, void *user_data,
                               void *stream_user_data) {
  (void)conn;
  (void)stream_id;
  (void)app_error_code;
  (void)user_data;
  (void)stream_user_data;

  return 0;
}

static int version_negotiation(ngtcp2_conn *conn, uint32_t version,
                               const ngtcp2_cid *client_dcid, void *user_data) {
  (void)conn;
  (void)version;
  (void)client_dcid;
  (void)user_data;

  return 0;
}

static int recv_rx_key(ngtcp2_conn *conn, ngtcp2_encryption_level level,
                       void *user_data) {
  (void)conn;
  (void)level;
  (void)user_data;

  return 0;
}

static int recv_tx_key(ngtcp2_conn *conn, ngtcp2_encryption_level level,
                       void *user_data) {
  (void)conn;
  (void)level;
  (void)user_data;

  return 0;
}

static int tls_early_data_rejected(ngtcp2_conn *conn, void *user_data) {
  (void)conn;
  (void)user_data;

  return 0;
}

static int begin_path_validation(ngtcp2_conn *conn, uint32_t flags,
                                 const ngtcp2_path *path,
                                 const ngtcp2_path *fallback_path,
                                 void *user_data) {
  (void)conn;
  (void)flags;
  (void)path;
  (void)fallback_path;
  (void)user_data;

  return 0;
}

void test_ngtcp2_callbacks_convert_to_latest(void) {
  ngtcp2_callbacks srcbuf = {
    .client_initial = client_initial,
    .recv_client_initial = recv_client_initial,
    .recv_crypto_data = recv_crypto_data,
    .handshake_completed = handshake_completed,
    .recv_version_negotiation = recv_version_negotiation,
    .encrypt = encrypt,
    .decrypt = decrypt,
    .hp_mask = hp_mask,
    .recv_stream_data = recv_stream_data,
    .acked_stream_data_offset = acked_stream_data_offset,
    .stream_open = stream_open,
    .stream_close = stream_close,
    .recv_stateless_reset = recv_stateless_reset,
    .recv_retry = recv_retry,
    .extend_max_local_streams_bidi = extend_max_local_streams_bidi,
    .extend_max_local_streams_uni = extend_max_local_streams_uni,
    .rand = rand_cb,
    .get_new_connection_id = get_new_connection_id,
    .remove_connection_id = remove_connection_id,
    .update_key = update_key,
    .path_validation = path_validation,
    .select_preferred_addr = select_preferred_addr,
    .stream_reset = stream_reset,
    .extend_max_remote_streams_bidi = extend_max_remote_streams_bidi,
    .extend_max_remote_streams_uni = extend_max_remote_streams_uni,
    .extend_max_stream_data = extend_max_stream_data,
    .dcid_status = dcid_status,
    .handshake_confirmed = handshake_confirmed,
    .recv_new_token = recv_new_token,
    .delete_crypto_aead_ctx = delete_crypto_aead_ctx,
    .delete_crypto_cipher_ctx = delete_crypto_cipher_ctx,
    .recv_datagram = recv_datagram,
    .ack_datagram = ack_datagram,
    .lost_datagram = lost_datagram,
    .get_path_challenge_data = get_path_challenge_data,
    .stream_stop_sending = stream_stop_sending,
    .version_negotiation = version_negotiation,
    .recv_rx_key = recv_rx_key,
    .recv_tx_key = recv_tx_key,
    .tls_early_data_rejected = tls_early_data_rejected,
  };
  ngtcp2_callbacks *src, callbacksbuf;
  const ngtcp2_callbacks *dest;
  size_t v1len;

  v1len = ngtcp2_callbackslen_version(NGTCP2_CALLBACKS_V1);

  src = malloc(v1len);

  memcpy(src, &srcbuf, v1len);

  dest =
    ngtcp2_callbacks_convert_to_latest(&callbacksbuf, NGTCP2_CALLBACKS_V1, src);

  free(src);

  assert_ptr_equal(&callbacksbuf, dest);
  assert_ptr_equal(srcbuf.client_initial, dest->client_initial);
  assert_ptr_equal(srcbuf.recv_client_initial, dest->recv_client_initial);
  assert_ptr_equal(srcbuf.recv_crypto_data, dest->recv_crypto_data);
  assert_ptr_equal(srcbuf.handshake_completed, dest->handshake_completed);
  assert_ptr_equal(srcbuf.recv_version_negotiation,
                   dest->recv_version_negotiation);
  assert_ptr_equal(srcbuf.encrypt, dest->encrypt);
  assert_ptr_equal(srcbuf.decrypt, dest->decrypt);
  assert_ptr_equal(srcbuf.hp_mask, dest->hp_mask);
  assert_ptr_equal(srcbuf.recv_stream_data, dest->recv_stream_data);
  assert_ptr_equal(srcbuf.acked_stream_data_offset,
                   dest->acked_stream_data_offset);
  assert_ptr_equal(srcbuf.stream_open, dest->stream_open);
  assert_ptr_equal(srcbuf.stream_close, dest->stream_close);
  assert_ptr_equal(srcbuf.recv_stateless_reset, dest->recv_stateless_reset);
  assert_ptr_equal(srcbuf.recv_retry, dest->recv_retry);
  assert_ptr_equal(srcbuf.extend_max_local_streams_bidi,
                   dest->extend_max_local_streams_bidi);
  assert_ptr_equal(srcbuf.extend_max_local_streams_uni,
                   dest->extend_max_local_streams_uni);
  assert_ptr_equal(srcbuf.rand, dest->rand);
  assert_ptr_equal(srcbuf.get_new_connection_id, dest->get_new_connection_id);
  assert_ptr_equal(srcbuf.remove_connection_id, dest->remove_connection_id);
  assert_ptr_equal(srcbuf.update_key, dest->update_key);
  assert_ptr_equal(srcbuf.path_validation, dest->path_validation);
  assert_ptr_equal(srcbuf.select_preferred_addr, dest->select_preferred_addr);
  assert_ptr_equal(srcbuf.stream_reset, dest->stream_reset);
  assert_ptr_equal(srcbuf.extend_max_remote_streams_bidi,
                   dest->extend_max_remote_streams_bidi);
  assert_ptr_equal(srcbuf.extend_max_remote_streams_uni,
                   dest->extend_max_remote_streams_uni);
  assert_ptr_equal(srcbuf.extend_max_stream_data, dest->extend_max_stream_data);
  assert_ptr_equal(srcbuf.dcid_status, dest->dcid_status);
  assert_ptr_equal(srcbuf.handshake_confirmed, dest->handshake_confirmed);
  assert_ptr_equal(srcbuf.recv_new_token, dest->recv_new_token);
  assert_ptr_equal(srcbuf.delete_crypto_aead_ctx, dest->delete_crypto_aead_ctx);
  assert_ptr_equal(srcbuf.delete_crypto_cipher_ctx,
                   dest->delete_crypto_cipher_ctx);
  assert_ptr_equal(srcbuf.recv_datagram, dest->recv_datagram);
  assert_ptr_equal(srcbuf.ack_datagram, dest->ack_datagram);
  assert_ptr_equal(srcbuf.lost_datagram, dest->lost_datagram);
  assert_ptr_equal(srcbuf.get_path_challenge_data,
                   dest->get_path_challenge_data);
  assert_ptr_equal(srcbuf.stream_stop_sending, dest->stream_stop_sending);
  assert_ptr_equal(srcbuf.version_negotiation, dest->version_negotiation);
  assert_ptr_equal(srcbuf.recv_rx_key, dest->recv_rx_key);
  assert_ptr_equal(srcbuf.recv_tx_key, dest->recv_tx_key);
  assert_ptr_equal(srcbuf.tls_early_data_rejected,
                   dest->tls_early_data_rejected);
  assert_null(dest->begin_path_validation);
}

void test_ngtcp2_callbacks_convert_to_old(void) {
  ngtcp2_callbacks src = {
    .client_initial = client_initial,
    .recv_client_initial = recv_client_initial,
    .recv_crypto_data = recv_crypto_data,
    .handshake_completed = handshake_completed,
    .recv_version_negotiation = recv_version_negotiation,
    .encrypt = encrypt,
    .decrypt = decrypt,
    .hp_mask = hp_mask,
    .recv_stream_data = recv_stream_data,
    .acked_stream_data_offset = acked_stream_data_offset,
    .stream_open = stream_open,
    .stream_close = stream_close,
    .recv_stateless_reset = recv_stateless_reset,
    .recv_retry = recv_retry,
    .extend_max_local_streams_bidi = extend_max_local_streams_bidi,
    .extend_max_local_streams_uni = extend_max_local_streams_uni,
    .rand = rand_cb,
    .get_new_connection_id = get_new_connection_id,
    .remove_connection_id = remove_connection_id,
    .update_key = update_key,
    .path_validation = path_validation,
    .select_preferred_addr = select_preferred_addr,
    .stream_reset = stream_reset,
    .extend_max_remote_streams_bidi = extend_max_remote_streams_bidi,
    .extend_max_remote_streams_uni = extend_max_remote_streams_uni,
    .extend_max_stream_data = extend_max_stream_data,
    .dcid_status = dcid_status,
    .handshake_confirmed = handshake_confirmed,
    .recv_new_token = recv_new_token,
    .delete_crypto_aead_ctx = delete_crypto_aead_ctx,
    .delete_crypto_cipher_ctx = delete_crypto_cipher_ctx,
    .recv_datagram = recv_datagram,
    .ack_datagram = ack_datagram,
    .lost_datagram = lost_datagram,
    .get_path_challenge_data = get_path_challenge_data,
    .stream_stop_sending = stream_stop_sending,
    .version_negotiation = version_negotiation,
    .recv_rx_key = recv_rx_key,
    .recv_tx_key = recv_tx_key,
    .tls_early_data_rejected = tls_early_data_rejected,
    .begin_path_validation = begin_path_validation,
  };
  ngtcp2_callbacks *dest, destbuf;
  size_t v1len;

  v1len = ngtcp2_callbackslen_version(NGTCP2_CALLBACKS_V1);

  dest = malloc(v1len);

  ngtcp2_callbacks_convert_to_old(NGTCP2_CALLBACKS_V1, dest, &src);

  memset(&destbuf, 0, sizeof(destbuf));
  memcpy(&destbuf, dest, v1len);

  free(dest);

  assert_ptr_equal(src.client_initial, destbuf.client_initial);
  assert_ptr_equal(src.recv_client_initial, destbuf.recv_client_initial);
  assert_ptr_equal(src.recv_crypto_data, destbuf.recv_crypto_data);
  assert_ptr_equal(src.handshake_completed, destbuf.handshake_completed);
  assert_ptr_equal(src.recv_version_negotiation,
                   destbuf.recv_version_negotiation);
  assert_ptr_equal(src.encrypt, destbuf.encrypt);
  assert_ptr_equal(src.decrypt, destbuf.decrypt);
  assert_ptr_equal(src.hp_mask, destbuf.hp_mask);
  assert_ptr_equal(src.recv_stream_data, destbuf.recv_stream_data);
  assert_ptr_equal(src.acked_stream_data_offset,
                   destbuf.acked_stream_data_offset);
  assert_ptr_equal(src.stream_open, destbuf.stream_open);
  assert_ptr_equal(src.stream_close, destbuf.stream_close);
  assert_ptr_equal(src.recv_stateless_reset, destbuf.recv_stateless_reset);
  assert_ptr_equal(src.recv_retry, destbuf.recv_retry);
  assert_ptr_equal(src.extend_max_local_streams_bidi,
                   destbuf.extend_max_local_streams_bidi);
  assert_ptr_equal(src.extend_max_local_streams_uni,
                   destbuf.extend_max_local_streams_uni);
  assert_ptr_equal(src.rand, destbuf.rand);
  assert_ptr_equal(src.get_new_connection_id, destbuf.get_new_connection_id);
  assert_ptr_equal(src.remove_connection_id, destbuf.remove_connection_id);
  assert_ptr_equal(src.update_key, destbuf.update_key);
  assert_ptr_equal(src.path_validation, destbuf.path_validation);
  assert_ptr_equal(src.select_preferred_addr, destbuf.select_preferred_addr);
  assert_ptr_equal(src.stream_reset, destbuf.stream_reset);
  assert_ptr_equal(src.extend_max_remote_streams_bidi,
                   destbuf.extend_max_remote_streams_bidi);
  assert_ptr_equal(src.extend_max_remote_streams_uni,
                   destbuf.extend_max_remote_streams_uni);
  assert_ptr_equal(src.extend_max_stream_data, destbuf.extend_max_stream_data);
  assert_ptr_equal(src.dcid_status, destbuf.dcid_status);
  assert_ptr_equal(src.handshake_confirmed, destbuf.handshake_confirmed);
  assert_ptr_equal(src.recv_new_token, destbuf.recv_new_token);
  assert_ptr_equal(src.delete_crypto_aead_ctx, destbuf.delete_crypto_aead_ctx);
  assert_ptr_equal(src.delete_crypto_cipher_ctx,
                   destbuf.delete_crypto_cipher_ctx);
  assert_ptr_equal(src.recv_datagram, destbuf.recv_datagram);
  assert_ptr_equal(src.ack_datagram, destbuf.ack_datagram);
  assert_ptr_equal(src.lost_datagram, destbuf.lost_datagram);
  assert_ptr_equal(src.get_path_challenge_data,
                   destbuf.get_path_challenge_data);
  assert_ptr_equal(src.stream_stop_sending, destbuf.stream_stop_sending);
  assert_ptr_equal(src.version_negotiation, destbuf.version_negotiation);
  assert_ptr_equal(src.recv_rx_key, destbuf.recv_rx_key);
  assert_ptr_equal(src.recv_tx_key, destbuf.recv_tx_key);
  assert_ptr_equal(src.tls_early_data_rejected,
                   destbuf.tls_early_data_rejected);
  assert_null(destbuf.begin_path_validation);
}
