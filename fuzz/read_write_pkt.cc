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
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <cassert>
#include <cstring>
#include <array>

#include <fuzzer/FuzzedDataProvider.h>

#ifdef __cplusplus
extern "C" {
#endif // defined(__cplusplus)

#include "ngtcp2_conn.h"
#include "ngtcp2_transport_params.h"

#ifdef __cplusplus
}
#endif // defined(__cplusplus)

namespace {
constexpr size_t NGTCP2_FAKE_AEAD_OVERHEAD = NGTCP2_INITIAL_AEAD_OVERHEAD;

const uint8_t null_secret[32]{};
const uint8_t null_iv[16]{};
} // namespace

namespace {
int client_initial(ngtcp2_conn *conn, void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
int recv_client_initial(ngtcp2_conn *conn, const ngtcp2_cid *dcid,
                        void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
int recv_crypto_data(ngtcp2_conn *conn,
                     ngtcp2_encryption_level encryption_level, uint64_t offset,
                     const uint8_t *data, size_t datalen, void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
int handshake_completed(ngtcp2_conn *conn, void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
int recv_version_negotiation(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                             const uint32_t *sv, size_t nsv, void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
int null_encrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                 const ngtcp2_crypto_aead_ctx *aead_ctx,
                 const uint8_t *plaintext, size_t plaintextlen,
                 const uint8_t *nonce, size_t noncelen, const uint8_t *aad,
                 size_t aadlen) {
  if (plaintextlen && plaintext != dest) {
    memcpy(dest, plaintext, plaintextlen);
  }

  memset(dest + plaintextlen, 0, NGTCP2_FAKE_AEAD_OVERHEAD);

  return 0;
}
} // namespace

namespace {
int null_decrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                 const ngtcp2_crypto_aead_ctx *aead_ctx,
                 const uint8_t *ciphertext, size_t ciphertextlen,
                 const uint8_t *nonce, size_t noncelen, const uint8_t *aad,
                 size_t aadlen) {
  assert(ciphertextlen >= NGTCP2_FAKE_AEAD_OVERHEAD);

  memcpy(dest, ciphertext, ciphertextlen - NGTCP2_FAKE_AEAD_OVERHEAD);

  return 0;
}
} // namespace

namespace {
int null_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                 const ngtcp2_crypto_cipher_ctx *hp_ctx,
                 const uint8_t *sample) {
  constexpr static const uint8_t NGTCP2_FAKE_HP_MASK[] = "\x00\x00\x00\x00\x00";

  memcpy(dest, NGTCP2_FAKE_HP_MASK, sizeof(NGTCP2_FAKE_HP_MASK) - 1);

  return 0;
}
} // namespace

namespace {
int recv_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data, void *stream_user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
int acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id,
                             uint64_t offset, uint64_t datalen, void *user_data,
                             void *stream_user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
int stream_open(ngtcp2_conn *conn, int64_t stream_id, void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
int stream_close(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                 uint64_t app_error_code, void *user_data,
                 void *stream_user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
int recv_stateless_reset(ngtcp2_conn *conn,
                         const ngtcp2_pkt_stateless_reset *sr,
                         void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
int recv_retry(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd, void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
int extend_max_local_streams_bidi(ngtcp2_conn *conn, uint64_t max_streams,
                                  void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
int extend_max_local_streams_uni(ngtcp2_conn *conn, uint64_t max_streams,
                                 void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
void genrand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx) {
  memset(dest, 0, destlen);
}
} // namespace

namespace {
int get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
                          size_t cidlen, void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  if (fuzzed_data_provider->ConsumeBool()) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  memset(cid->data, 0, cidlen);

  cid->data[0] = static_cast<uint8_t>(conn->scid.last_seq + 1);
  cid->datalen = cidlen;

  memset(token, 0, NGTCP2_STATELESS_RESET_TOKENLEN);

  return 0;
}
} // namespace

namespace {
int remove_connection_id(ngtcp2_conn *conn, const ngtcp2_cid *cid,
                         void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
int update_key(ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
               ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
               ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
               const uint8_t *current_rx_secret,
               const uint8_t *current_tx_secret, size_t secretlen,
               void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  if (fuzzed_data_provider->ConsumeBool()) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  assert(sizeof(null_secret) == secretlen);

  memset(rx_secret, 0xff, sizeof(null_secret));
  memset(tx_secret, 0xff, sizeof(null_secret));

  rx_aead_ctx->native_handle = nullptr;

  memset(rx_iv, 0xff, sizeof(null_iv));

  tx_aead_ctx->native_handle = nullptr;

  memset(tx_iv, 0xff, sizeof(null_iv));

  return 0;
}
} // namespace

namespace {
int path_validation(ngtcp2_conn *conn, uint32_t flags, const ngtcp2_path *path,
                    const ngtcp2_path *old_path,
                    ngtcp2_path_validation_result res, void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
int select_preferred_addr(ngtcp2_conn *conn, ngtcp2_path *dest,
                          const ngtcp2_preferred_addr *paddr, void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
int stream_reset(ngtcp2_conn *conn, int64_t stream_id, uint64_t final_size,
                 uint64_t app_error_code, void *user_data,
                 void *stream_user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
int extend_max_remote_streams_bidi(ngtcp2_conn *conn, uint64_t max_streams,
                                   void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
int extend_max_remote_streams_uni(ngtcp2_conn *conn, uint64_t max_streams,
                                  void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
int extend_max_stream_data(ngtcp2_conn *conn, int64_t stream_id,
                           uint64_t max_data, void *user_data,
                           void *stream_user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
int dcid_status(ngtcp2_conn *conn, ngtcp2_connection_id_status_type type,
                uint64_t seq, const ngtcp2_cid *cid, const uint8_t *token,
                void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
int handshake_confirmed(ngtcp2_conn *conn, void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
int recv_new_token(ngtcp2_conn *conn, const uint8_t *token, size_t tokenlen,
                   void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
void delete_crypto_aead_ctx(ngtcp2_conn *conn, ngtcp2_crypto_aead_ctx *aead_ctx,
                            void *user_data) {}
} // namespace

namespace {
void delete_crypto_cipher_ctx(ngtcp2_conn *conn,
                              ngtcp2_crypto_cipher_ctx *cipher_ctx,
                              void *user_data) {}
} // namespace

namespace {
int recv_datagram(ngtcp2_conn *conn, uint32_t flags, const uint8_t *data,
                  size_t datalen, void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
int ack_datagram(ngtcp2_conn *conn, uint64_t dgram_id, void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
int lost_datagram(ngtcp2_conn *conn, uint64_t dgram_id, void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
int get_path_challenge_data(ngtcp2_conn *conn, uint8_t *data, void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  if (fuzzed_data_provider->ConsumeBool()) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  memset(data, 0, NGTCP2_PATH_CHALLENGE_DATALEN);

  return 0;
}
} // namespace

namespace {
int stream_stop_sending(ngtcp2_conn *conn, int64_t stream_id,
                        uint64_t app_error_code, void *user_data,
                        void *stream_user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
int version_negotiation(ngtcp2_conn *conn, uint32_t version,
                        const ngtcp2_cid *client_dcid, void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  if (fuzzed_data_provider->ConsumeBool()) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  ngtcp2_crypto_aead_ctx aead_ctx{};
  ngtcp2_crypto_cipher_ctx hp_ctx{};

  ngtcp2_conn_install_vneg_initial_key(conn, version, &aead_ctx, null_iv,
                                       &hp_ctx, &aead_ctx, null_iv, &hp_ctx,
                                       sizeof(null_iv));

  return 0;
}
} // namespace

namespace {
int recv_rx_key(ngtcp2_conn *conn, ngtcp2_encryption_level level,
                void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
int recv_tx_key(ngtcp2_conn *conn, ngtcp2_encryption_level level,
                void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
int tls_early_data_rejected(ngtcp2_conn *conn, void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
int begin_path_validation(ngtcp2_conn *conn, uint32_t flags,
                          const ngtcp2_path *path,
                          const ngtcp2_path *fallback_path, void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
} // namespace

namespace {
void init_path(ngtcp2_path_storage *ps) {
  addrinfo *local, *remote,
    hints{
      .ai_flags = AI_NUMERICHOST | AI_NUMERICSERV,
      .ai_family = AF_UNSPEC,
      .ai_socktype = SOCK_DGRAM,
    };

  auto rv = getaddrinfo("127.0.0.1", "4433", &hints, &local);

  assert(0 == rv);

  rv = getaddrinfo("127.0.0.1", "12345", &hints, &remote);

  assert(0 == rv);

  ngtcp2_path_storage_init(ps, local->ai_addr, local->ai_addrlen,
                           remote->ai_addr, remote->ai_addrlen, nullptr);

  freeaddrinfo(remote);
  freeaddrinfo(local);
}
} // namespace

namespace {
void qlog_write(void *user_data, uint32_t flags, const void *data,
                size_t datalen) {}
} // namespace

namespace {
void *fuzzed_malloc(size_t size, void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? nullptr : malloc(size);
}
} // namespace

namespace {
void *fuzzed_calloc(size_t nmemb, size_t size, void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? nullptr : calloc(nmemb, size);
}
} // namespace

namespace {
void *fuzzed_realloc(void *ptr, size_t size, void *user_data) {
  auto fuzzed_data_provider = static_cast<FuzzedDataProvider *>(user_data);

  return fuzzed_data_provider->ConsumeBool() ? nullptr : realloc(ptr, size);
}
} // namespace

namespace {
ngtcp2_conn *setup_conn(FuzzedDataProvider &fuzzed_data_provider,
                        const ngtcp2_mem &mem) {
  ngtcp2_callbacks cb{
    .client_initial = client_initial,
    .recv_client_initial = recv_client_initial,
    .recv_crypto_data = recv_crypto_data,
    .handshake_completed = handshake_completed,
    .recv_version_negotiation = recv_version_negotiation,
    .encrypt = null_encrypt,
    .decrypt = null_decrypt,
    .hp_mask = null_hp_mask,
    .recv_stream_data = recv_stream_data,
    .acked_stream_data_offset = acked_stream_data_offset,
    .stream_open = stream_open,
    .stream_close = stream_close,
    .recv_stateless_reset = recv_stateless_reset,
    .recv_retry = recv_retry,
    .extend_max_local_streams_bidi = extend_max_local_streams_bidi,
    .extend_max_local_streams_uni = extend_max_local_streams_uni,
    .rand = genrand,
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
  ngtcp2_cid dcid, scid, odcid;

  ngtcp2_cid_init(
    &dcid,
    reinterpret_cast<const uint8_t *>("\x10\xe7\x43\x2a\xaf\x7a\x19\xb0\x3c"
                                      "\x34\xb3\x3f\xc1\x8d\xe7\x90\x36"),
    17);
  ngtcp2_cid_init(
    &scid,
    reinterpret_cast<const uint8_t *>("\x8d\x8f\x16\x90\x4e\x41\x90\xb1\x70"
                                      "\x1e\x5c\x5d\x00\x09\x92\x1d\xdf\xab"),
    18);
  ngtcp2_cid_init(
    &odcid,
    reinterpret_cast<const uint8_t *>("\xaa\x0a\x9d\x0e\xa4\xc7\xb1\x54\x50"
                                      "\xf5\x51\x94\x5e\xd6\x16\x9d\xe3\x57"),
    18);

  ngtcp2_path_storage ps;

  init_path(&ps);

  ngtcp2_settings settings;

  ngtcp2_settings_default(&settings);

  settings.qlog_write = qlog_write;
  settings.cc_algo = fuzzed_data_provider.PickValueInArray(
    {NGTCP2_CC_ALGO_RENO, NGTCP2_CC_ALGO_CUBIC, NGTCP2_CC_ALGO_BBR});

  ngtcp2_transport_params params;

  ngtcp2_transport_params_default(&params);

  params.original_dcid = odcid;
  params.initial_max_stream_data_bidi_local = 65535;
  params.initial_max_stream_data_bidi_remote = 65535;
  params.initial_max_stream_data_uni = 65535;
  params.initial_max_data = 128 * 1024;
  params.initial_max_streams_bidi = 3;
  params.initial_max_streams_uni = 2;
  params.max_idle_timeout = 60 * NGTCP2_SECONDS;
  params.active_connection_id_limit = 8;
  for (size_t i = 0; i < NGTCP2_STATELESS_RESET_TOKENLEN; ++i) {
    params.stateless_reset_token[i] = static_cast<uint8_t>(i);
  }

  ngtcp2_conn *conn;

  if (fuzzed_data_provider.ConsumeBool()) {
    params.original_dcid_present = 1;
    params.stateless_reset_token_present = 1;

    auto rv = ngtcp2_conn_server_new(&conn, &dcid, &scid, &ps.path,
                                     NGTCP2_PROTO_VER_V1, &cb, &settings,
                                     &params, &mem, &fuzzed_data_provider);
    if (rv != 0) {
      return nullptr;
    }
  } else {
    auto rv = ngtcp2_conn_client_new(&conn, &dcid, &scid, &ps.path,
                                     NGTCP2_PROTO_VER_V1, &cb, &settings,
                                     &params, &mem, &fuzzed_data_provider);
    if (rv != 0) {
      return nullptr;
    }
  }

  ngtcp2_crypto_ctx crypto_ctx{
    .aead =
      {
        .max_overhead = NGTCP2_FAKE_AEAD_OVERHEAD,
      },
    .max_encryption = 9999,
    .max_decryption_failure = 8888,
  };

  ngtcp2_conn_set_initial_crypto_ctx(conn, &crypto_ctx);

  ngtcp2_crypto_aead_ctx aead_ctx{};
  ngtcp2_crypto_cipher_ctx hp_ctx{};

  auto rv = ngtcp2_conn_install_initial_key(conn, &aead_ctx, null_iv, &hp_ctx,
                                            &aead_ctx, null_iv, &hp_ctx,
                                            sizeof(null_iv));
  if (rv != 0) {
    ngtcp2_conn_del(conn);
    return nullptr;
  }

  ngtcp2_conn_set_crypto_ctx(conn, &crypto_ctx);

  rv = ngtcp2_conn_install_rx_handshake_key(conn, &aead_ctx, null_iv,
                                            sizeof(null_iv), &hp_ctx);
  if (rv != 0) {
    ngtcp2_conn_del(conn);
    return nullptr;
  }

  rv = ngtcp2_conn_install_tx_handshake_key(conn, &aead_ctx, null_iv,
                                            sizeof(null_iv), &hp_ctx);
  if (rv != 0) {
    ngtcp2_conn_del(conn);
    return nullptr;
  }

  rv = ngtcp2_conn_install_rx_key(conn, null_secret, sizeof(null_secret),
                                  &aead_ctx, null_iv, sizeof(null_iv), &hp_ctx);
  if (rv != 0) {
    ngtcp2_conn_del(conn);
    return nullptr;
  }

  rv = ngtcp2_conn_install_tx_key(conn, null_secret, sizeof(null_secret),
                                  &aead_ctx, null_iv, sizeof(null_iv), &hp_ctx);
  if (rv != 0) {
    ngtcp2_conn_del(conn);
    return nullptr;
  }

  ngtcp2_conn_discard_initial_state(conn, 0);
  ngtcp2_conn_discard_handshake_state(conn, 0);

  conn->state = NGTCP2_CS_POST_HANDSHAKE;
  conn->flags |= NGTCP2_CONN_FLAG_INITIAL_PKT_PROCESSED |
                 NGTCP2_CONN_FLAG_TLS_HANDSHAKE_COMPLETED |
                 NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED |
                 NGTCP2_CONN_FLAG_HANDSHAKE_CONFIRMED;
  conn->dcid.current.flags |= NGTCP2_DCID_FLAG_PATH_VALIDATED;

  {
    auto it = ngtcp2_ksl_begin(&conn->scid.set);
    auto scid = static_cast<ngtcp2_scid *>(ngtcp2_ksl_it_get(&it));

    scid->flags |= NGTCP2_SCID_FLAG_USED;

    rv = ngtcp2_pq_push(&conn->scid.used, &scid->pe);
    if (rv != 0) {
      ngtcp2_conn_del(conn);
      return nullptr;
    }
  }

  conn->negotiated_version = conn->client_chosen_version;
  conn->handshake_confirmed_ts = 0;

  auto chunk_len = fuzzed_data_provider.ConsumeIntegral<size_t>();
  auto chunk = fuzzed_data_provider.ConsumeBytes<uint8_t>(chunk_len);

  rv = ngtcp2_conn_decode_and_set_remote_transport_params(conn, chunk.data(),
                                                          chunk.size());
  if (rv != 0) {
    ngtcp2_conn_del(conn);
    return nullptr;
  }

  return conn;
}
} // namespace

namespace {
int read_write(ngtcp2_conn *conn, FuzzedDataProvider &fuzzed_data_provider,
               const ngtcp2_path *path, ngtcp2_tstamp &ts) {
  auto pi = ngtcp2_pkt_info{
    .ecn = NGTCP2_ECN_ECT_1,
  };

  std::array<uint8_t, 1500> pkt;
  std::vector<std::vector<uint8_t>> chunks;

  while (fuzzed_data_provider.remaining_bytes() > 0) {
    ts = fuzzed_data_provider.ConsumeIntegralInRange<ngtcp2_tstamp>(
      ts, std::numeric_limits<ngtcp2_tstamp>::max() - 1);

    if (fuzzed_data_provider.ConsumeBool()) {
      auto rv = ngtcp2_conn_handle_expiry(conn, ts);
      if (rv != 0) {
        return -1;
      }
    }

    if (!ngtcp2_conn_is_server(conn) && fuzzed_data_provider.ConsumeBool()) {
      auto rv = ngtcp2_conn_initiate_migration(conn, path, ts);
      if (rv != 0) {
        return -1;
      }
    }

    auto recv_pkt_len = fuzzed_data_provider.ConsumeIntegral<size_t>();

    auto recv_pkt = fuzzed_data_provider.ConsumeBytes<uint8_t>(recv_pkt_len);

    auto rv = ngtcp2_conn_read_pkt(conn, path, &pi, recv_pkt.data(),
                                   recv_pkt.size(), ts);
    if (rv != 0) {
      return -1;
    }

    if (fuzzed_data_provider.ConsumeBool()) {
      auto stream_id = fuzzed_data_provider.ConsumeIntegral<uint64_t>();
      auto datalen = fuzzed_data_provider.ConsumeIntegral<uint64_t>();

      rv = ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
      if (rv != 0) {
        return -1;
      }
    }

    if (fuzzed_data_provider.ConsumeBool()) {
      auto datalen = fuzzed_data_provider.ConsumeIntegral<uint64_t>();

      ngtcp2_conn_extend_max_offset(conn, datalen);
    }

    ngtcp2_path_storage ps;

    ngtcp2_path_storage_zero(&ps);

    ngtcp2_pkt_info pi{};

    auto chunk_len = fuzzed_data_provider.ConsumeIntegral<size_t>();
    auto chunk = fuzzed_data_provider.ConsumeBytes<uint8_t>(chunk_len);

    for (;;) {
      if (fuzzed_data_provider.remaining_bytes() == 0) {
        return 0;
      }

      auto flags = fuzzed_data_provider.ConsumeIntegral<uint32_t>();

      if (fuzzed_data_provider.ConsumeBool()) {
        int64_t stream_id;

        switch (fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 2)) {
        case 0:
          stream_id = fuzzed_data_provider.ConsumeIntegral<int64_t>();
          break;
        case 1:
          rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, nullptr);
          if (rv != 0) {
            return -1;
          }

          break;
        case 2:
          rv = ngtcp2_conn_open_uni_stream(conn, &stream_id, nullptr);
          if (rv != 0) {
            return -1;
          }

          break;
        }

        ngtcp2_ssize ndatalen;

        auto spktlen = ngtcp2_conn_write_stream(
          conn, &ps.path, &pi, pkt.data(), pkt.size(), &ndatalen, flags,
          stream_id, chunk.data(), chunk.size(), ts);
        if (spktlen < 0) {
          switch (spktlen) {
          case NGTCP2_ERR_WRITE_MORE:
            if (ndatalen > 0) {
              chunks.push_back(std::move(chunk));
            }

            if (ndatalen >= 0) {
              chunk_len = fuzzed_data_provider.ConsumeIntegral<size_t>();
              chunk = fuzzed_data_provider.ConsumeBytes<uint8_t>(chunk_len);
            }

            continue;
          case NGTCP2_ERR_STREAM_DATA_BLOCKED:
          case NGTCP2_ERR_STREAM_NOT_FOUND:
          case NGTCP2_ERR_STREAM_SHUT_WR:
            continue;
          }

          return -1;
        }

        if (ndatalen > 0) {
          chunks.push_back(std::move(chunk));
        }
      } else {
        int accepted;

        auto spktlen = ngtcp2_conn_write_datagram(
          conn, &ps.path, &pi, pkt.data(), pkt.size(), &accepted, flags,
          fuzzed_data_provider.ConsumeIntegral<uint64_t>(), chunk.data(),
          chunk.size(), ts);
        if (spktlen < 0) {
          if (spktlen == NGTCP2_ERR_WRITE_MORE) {
            if (accepted) {
              chunk_len = fuzzed_data_provider.ConsumeIntegral<size_t>();
              chunk = fuzzed_data_provider.ConsumeBytes<uint8_t>(chunk_len);
            }

            continue;
          }

          return -1;
        }
      }

      break;
    }
  }

  return 0;
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data_provider(data, size);
  ngtcp2_path_storage ps;
  std::array<uint8_t, 1500> pkt;

  init_path(&ps);

  ngtcp2_mem mem = *ngtcp2_mem_default();
  mem.user_data = &fuzzed_data_provider;
  mem.malloc = fuzzed_malloc;
  mem.calloc = fuzzed_calloc;
  mem.realloc = fuzzed_realloc;

  auto conn = setup_conn(fuzzed_data_provider, mem);
  if (conn == nullptr) {
    return 0;
  }

  ngtcp2_tstamp ts{};

  read_write(conn, fuzzed_data_provider, &ps.path, ts);

  auto ccerr = ngtcp2_conn_get_ccerr(conn);

  ngtcp2_pkt_info pi{};

  ngtcp2_conn_write_connection_close(conn, &ps.path, &pi, pkt.data(),
                                     pkt.size(), ccerr, ts);

  ngtcp2_conn_del(conn);

  return 0;
}
