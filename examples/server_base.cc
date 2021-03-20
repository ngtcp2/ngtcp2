/*
 * ngtcp2
 *
 * Copyright (c) 2020 ngtcp2 contributors
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
#include "server_base.h"

#include <cassert>
#include <array>
#include <iostream>

#include <ngtcp2/ngtcp2_crypto.h>

#include "debug.h"

using namespace ngtcp2;

extern Config config;

Buffer::Buffer(const uint8_t *data, size_t datalen)
    : buf{data, data + datalen}, begin(buf.data()), tail(begin + datalen) {}
Buffer::Buffer(size_t datalen) : buf(datalen), begin(buf.data()), tail(begin) {}

HandlerBase::HandlerBase()
    : crypto_{}, conn_(nullptr), last_error_{QUICErrorType::Transport, 0} {}

HandlerBase::~HandlerBase() {
  if (conn_) {
    ngtcp2_conn_del(conn_);
  }
}

int HandlerBase::on_rx_key(ngtcp2_crypto_level level, const uint8_t *secret,
                           size_t secretlen) {
  std::array<uint8_t, 64> key, iv, hp_key;

  if (ngtcp2_crypto_derive_and_install_rx_key(conn_, key.data(), iv.data(),
                                              hp_key.data(), level, secret,
                                              secretlen) != 0) {
    return -1;
  }

  auto crypto_ctx = level == NGTCP2_CRYPTO_LEVEL_EARLY
                        ? ngtcp2_conn_get_early_crypto_ctx(conn_)
                        : ngtcp2_conn_get_crypto_ctx(conn_);
  auto aead = &crypto_ctx->aead;
  auto keylen = ngtcp2_crypto_aead_keylen(aead);
  auto ivlen = ngtcp2_crypto_packet_protection_ivlen(aead);
  auto title = debug::secret_title(level);

  if (!config.quiet && config.show_secret) {
    std::cerr << title << " rx secret" << std::endl;
    debug::print_secrets(secret, secretlen, key.data(), keylen, iv.data(),
                         ivlen, hp_key.data(), keylen);
  }

  return 0;
}

int HandlerBase::on_tx_key(ngtcp2_crypto_level level, const uint8_t *secret,
                           size_t secretlen) {
  std::array<uint8_t, 64> key, iv, hp_key;

  if (ngtcp2_crypto_derive_and_install_tx_key(conn_, key.data(), iv.data(),
                                              hp_key.data(), level, secret,
                                              secretlen) != 0) {
    return -1;
  }

  auto crypto_ctx = level == NGTCP2_CRYPTO_LEVEL_EARLY
                        ? ngtcp2_conn_get_early_crypto_ctx(conn_)
                        : ngtcp2_conn_get_crypto_ctx(conn_);
  auto aead = &crypto_ctx->aead;
  auto keylen = ngtcp2_crypto_aead_keylen(aead);
  auto ivlen = ngtcp2_crypto_packet_protection_ivlen(aead);

  const char *title = nullptr;
  switch (level) {
  case NGTCP2_CRYPTO_LEVEL_EARLY:
    assert(0);
  case NGTCP2_CRYPTO_LEVEL_HANDSHAKE:
    title = "handshake_traffic";
    break;
  case NGTCP2_CRYPTO_LEVEL_APPLICATION:
    title = "application_traffic";
    break;
  default:
    assert(0);
  }

  if (!config.quiet && config.show_secret) {
    std::cerr << title << " tx secret" << std::endl;
    debug::print_secrets(secret, secretlen, key.data(), keylen, iv.data(),
                         ivlen, hp_key.data(), keylen);
  }

  return 0;
}

void HandlerBase::write_server_handshake(ngtcp2_crypto_level level,
                                         const uint8_t *data, size_t datalen) {
  auto &crypto = crypto_[level];
  crypto.data.emplace_back(data, datalen);

  auto &buf = crypto.data.back();

  ngtcp2_conn_submit_crypto_data(conn_, level, buf.rpos(), buf.size());
}

namespace {
void remove_tx_data(std::deque<Buffer> &d, uint64_t &tx_offset,
                    uint64_t offset) {
  for (; !d.empty() && tx_offset + d.front().size() <= offset;) {
    auto &v = d.front();
    tx_offset += v.size();
    d.pop_front();
  }
}
} // namespace

void HandlerBase::remove_tx_crypto_data(ngtcp2_crypto_level crypto_level,
                                        uint64_t offset, uint64_t datalen) {
  auto &crypto = crypto_[crypto_level];
  remove_tx_data(crypto.data, crypto.acked_offset, offset + datalen);
}

void HandlerBase::set_tls_alert(uint8_t alert) {
  last_error_ = quic_err_tls(alert);
}

ngtcp2_conn *HandlerBase::conn() const { return conn_; }

int HandlerBase::call_application_tx_key_cb() const {
  if (!application_tx_key_cb_) {
    return 0;
  }
  return application_tx_key_cb_();
}
