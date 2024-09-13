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
const uint8_t null_data[2048]{};
} // namespace

struct TLSState {
  bool keys_installed;
  bool handshake_completed;
};

namespace {
int recv_client_initial(ngtcp2_conn *conn, const ngtcp2_cid *dcid,
                        void *user_data) {
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

  ngtcp2_conn_install_initial_key(conn, &aead_ctx, null_iv, &hp_ctx, &aead_ctx,
                                  null_iv, &hp_ctx, sizeof(null_iv));

  return 0;
}
} // namespace

namespace {
ngtcp2_cid dcid, scid, odcid;
} // namespace

namespace {
int recv_crypto_data(ngtcp2_conn *conn,
                     ngtcp2_encryption_level encryption_level, uint64_t offset,
                     const uint8_t *data, size_t datalen, void *user_data) {
  auto state = static_cast<TLSState *>(user_data);

  ngtcp2_crypto_ctx crypto_ctx{
    .aead =
      {
        .max_overhead = NGTCP2_FAKE_AEAD_OVERHEAD,
      },
    .max_encryption = 9999,
    .max_decryption_failure = 8888,
  };

  ngtcp2_conn_set_crypto_ctx(conn, &crypto_ctx);

  ngtcp2_crypto_aead_ctx aead_ctx{};
  ngtcp2_crypto_cipher_ctx hp_ctx{};

  switch (encryption_level) {
  case NGTCP2_ENCRYPTION_LEVEL_INITIAL:
    if (!state->keys_installed) {
      state->keys_installed = true;

      ngtcp2_conn_install_rx_handshake_key(conn, &aead_ctx, null_iv,
                                           sizeof(null_iv), &hp_ctx);
      ngtcp2_conn_install_tx_handshake_key(conn, &aead_ctx, null_iv,
                                           sizeof(null_iv), &hp_ctx);

      ngtcp2_conn_install_rx_key(conn, null_secret, sizeof(null_secret),
                                 &aead_ctx, null_iv, sizeof(null_iv), &hp_ctx);
      ngtcp2_conn_install_tx_key(conn, null_secret, sizeof(null_secret),
                                 &aead_ctx, null_iv, sizeof(null_iv), &hp_ctx);

      ngtcp2_transport_params remote_params{};

      remote_params.initial_max_stream_data_bidi_local = 64 * 1024;
      remote_params.initial_max_stream_data_bidi_remote = 64 * 1024;
      remote_params.initial_max_stream_data_uni = 64 * 1024;
      remote_params.initial_max_streams_bidi = 0;
      remote_params.initial_max_streams_uni = 1;
      remote_params.initial_max_data = 64 * 1024;
      remote_params.active_connection_id_limit = 8;
      remote_params.max_udp_payload_size =
        NGTCP2_DEFAULT_MAX_RECV_UDP_PAYLOAD_SIZE;
      remote_params.initial_scid_present = 1;
      remote_params.initial_scid = dcid;

      ngtcp2_conn_set_remote_transport_params(conn, &remote_params);

      ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL,
                                     null_data, 123);
      ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,
                                     null_data, 1999);
    }

    break;
  case NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE:
    if (!state->handshake_completed) {
      state->handshake_completed = true;

      ngtcp2_conn_tls_handshake_completed(conn);
    }

    break;
  default:
    break;
  }

  return 0;
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
void genrand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx) {
  memset(dest, 0, destlen);
}
} // namespace

namespace {
int get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
                          size_t cidlen, void *user_data) {
  memset(cid->data, 0, cidlen);

  cid->data[0] = static_cast<uint8_t>(conn->scid.last_seq + 1);
  cid->datalen = cidlen;

  memset(token, 0, NGTCP2_STATELESS_RESET_TOKENLEN);

  return 0;
}
} // namespace

namespace {
int update_key(ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
               ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
               ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
               const uint8_t *current_rx_secret,
               const uint8_t *current_tx_secret, size_t secretlen,
               void *user_data) {
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
void delete_crypto_aead_ctx(ngtcp2_conn *conn, ngtcp2_crypto_aead_ctx *aead_ctx,
                            void *user_data) {}
} // namespace

namespace {
void delete_crypto_cipher_ctx(ngtcp2_conn *conn,
                              ngtcp2_crypto_cipher_ctx *cipher_ctx,
                              void *user_data) {}
} // namespace

namespace {
int get_path_challenge_data(ngtcp2_conn *conn, uint8_t *data, void *user_data) {
  memset(data, 0, NGTCP2_PATH_CHALLENGE_DATALEN);

  return 0;
}
} // namespace

namespace {
int version_negotiation(ngtcp2_conn *conn, uint32_t version,
                        const ngtcp2_cid *client_dcid, void *user_data) {
  ngtcp2_crypto_aead_ctx aead_ctx{};
  ngtcp2_crypto_cipher_ctx hp_ctx{};

  ngtcp2_conn_install_vneg_initial_key(conn, version, &aead_ctx, null_iv,
                                       &hp_ctx, &aead_ctx, null_iv, &hp_ctx,
                                       sizeof(null_iv));

  return 0;
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
ngtcp2_conn *setup_conn(TLSState *state) {
  ngtcp2_callbacks cb{
    .recv_client_initial = recv_client_initial,
    .recv_crypto_data = recv_crypto_data,
    .encrypt = null_encrypt,
    .decrypt = null_decrypt,
    .hp_mask = null_hp_mask,
    .rand = genrand,
    .get_new_connection_id = get_new_connection_id,
    .update_key = update_key,
    .delete_crypto_aead_ctx = delete_crypto_aead_ctx,
    .delete_crypto_cipher_ctx = delete_crypto_cipher_ctx,
    .get_path_challenge_data = get_path_challenge_data,
    .version_negotiation = version_negotiation,
  };

  ngtcp2_path_storage ps;

  init_path(&ps);

  ngtcp2_settings settings;

  ngtcp2_settings_default(&settings);

  ngtcp2_transport_params params;

  ngtcp2_transport_params_default(&params);

  params.original_dcid_present = 1;
  params.original_dcid = odcid;
  params.initial_max_stream_data_bidi_local = 65535;
  params.initial_max_stream_data_bidi_remote = 65535;
  params.initial_max_stream_data_uni = 65535;
  params.initial_max_data = 128 * 1024;
  params.initial_max_streams_bidi = 3;
  params.initial_max_streams_uni = 2;
  params.max_idle_timeout = 60 * NGTCP2_SECONDS;
  params.stateless_reset_token_present = 1;
  params.active_connection_id_limit = 8;
  for (size_t i = 0; i < NGTCP2_STATELESS_RESET_TOKENLEN; ++i) {
    params.stateless_reset_token[i] = static_cast<uint8_t>(i);
  }

  ngtcp2_conn *conn;

  ngtcp2_conn_server_new(&conn, &dcid, &scid, &ps.path, NGTCP2_PROTO_VER_V1,
                         &cb, &settings, &params,
                         /* mem = */ nullptr, state);

  return conn;
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::array<uint8_t, 1500> pkt;

  ngtcp2_path_storage ps;

  init_path(&ps);

  auto pi = ngtcp2_pkt_info{
    .ecn = NGTCP2_ECN_ECT_1,
  };

  TLSState state{};

  ngtcp2_cid_init(
    &dcid,
    reinterpret_cast<const uint8_t *>("\xc1\xd8\x21\x9c\xe9\xbf\x6a\x01\x63"
                                      "\x4e\xfd\xca\x46\x5f\xb5\xb6\x06"),
    17);
  ngtcp2_cid_init(
    &scid,
    reinterpret_cast<const uint8_t *>("\xac\xc8\xa6\x3d\xa8\x28\x14\xbd\x0b"
                                      "\xaf\x5f\xfe\x40\x79\xb9\x03\x11\x83"),
    18);
  ngtcp2_cid_init(
    &odcid,
    reinterpret_cast<const uint8_t *>("\xc3\xd7\x24\x52\x16\xc9\x7b\xa6\xf5"
                                      "\x16\xc8\x53\x4d\x10\x6e\x54\x9a\xb2"),
    18);

  auto conn = setup_conn(&state);

  ngtcp2_tstamp ts{};

  for (size_t i = 0; i < 10; ++i) {
    ts = i * NGTCP2_MILLISECONDS;

    auto rv = ngtcp2_conn_read_pkt(conn, &ps.path, &pi, data, size, ts);
    if (rv != 0) {
      break;
    }

    ngtcp2_path_storage ps;

    ngtcp2_path_storage_zero(&ps);

    ngtcp2_pkt_info pi{};

    auto spktlen = ngtcp2_conn_writev_stream(
      conn, &ps.path, &pi, pkt.data(), pkt.size(), nullptr,
      NGTCP2_WRITE_STREAM_FLAG_NONE, -1, nullptr, 0, ts);
    if (spktlen < 0) {
      break;
    }
  }

  auto ccerr = ngtcp2_conn_get_ccerr(conn);

  ngtcp2_conn_write_connection_close(conn, &ps.path, &pi, pkt.data(),
                                     pkt.size(), ccerr, ts);

  ngtcp2_conn_del(conn);

  return 0;
}
