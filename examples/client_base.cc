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
#include "client_base.h"

#include <cassert>
#include <array>
#include <iostream>
#include <fstream>

#include <ngtcp2/ngtcp2_crypto.h>

#include "debug.h"
#include "template.h"
#include "util.h"

using namespace ngtcp2;

extern Config config;

Buffer::Buffer(const uint8_t *data, size_t datalen)
    : buf{data, data + datalen}, tail(buf.data() + datalen) {}
Buffer::Buffer(size_t datalen) : buf(datalen), tail(buf.data()) {}

ClientBase::ClientBase()
    : qlog_(nullptr),
      crypto_{},
      conn_(nullptr),
      last_error_{QUICErrorType::Transport, 0} {}

ClientBase::~ClientBase() {
  if (conn_) {
    ngtcp2_conn_del(conn_);
  }

  if (qlog_) {
    fclose(qlog_);
  }
}

int ClientBase::write_transport_params(const char *path,
                                       const ngtcp2_transport_params *params) {
  auto f = std::ofstream(path);
  if (!f) {
    return -1;
  }

  f << "initial_max_streams_bidi=" << params->initial_max_streams_bidi << '\n'
    << "initial_max_streams_uni=" << params->initial_max_streams_uni << '\n'
    << "initial_max_stream_data_bidi_local="
    << params->initial_max_stream_data_bidi_local << '\n'
    << "initial_max_stream_data_bidi_remote="
    << params->initial_max_stream_data_bidi_remote << '\n'
    << "initial_max_stream_data_uni=" << params->initial_max_stream_data_uni
    << '\n'
    << "initial_max_data=" << params->initial_max_data << '\n'
    << "active_connection_id_limit=" << params->active_connection_id_limit
    << '\n'
    << "max_datagram_frame_size=" << params->max_datagram_frame_size << '\n';

  f.close();
  if (!f) {
    return -1;
  }

  return 0;
}

int ClientBase::read_transport_params(const char *path,
                                      ngtcp2_transport_params *params) {
  auto f = std::ifstream(path);
  if (!f) {
    return -1;
  }

  for (std::string line; std::getline(f, line);) {
    if (util::istarts_with_l(line, "initial_max_streams_bidi=")) {
      if (auto n = util::parse_uint(line.c_str() +
                                    str_size("initial_max_streams_bidi="));
          !n) {
        return -1;
      } else {
        params->initial_max_streams_bidi = *n;
      }
      continue;
    }

    if (util::istarts_with_l(line, "initial_max_streams_uni=")) {
      if (auto n = util::parse_uint(line.c_str() +
                                    str_size("initial_max_streams_uni="));
          !n) {
        return -1;
      } else {
        params->initial_max_streams_uni = *n;
      }
      continue;
    }

    if (util::istarts_with_l(line, "initial_max_stream_data_bidi_local=")) {
      if (auto n = util::parse_uint(
              line.c_str() + str_size("initial_max_stream_data_bidi_local="));
          !n) {
        return -1;
      } else {
        params->initial_max_stream_data_bidi_local = *n;
      }
      continue;
    }

    if (util::istarts_with_l(line, "initial_max_stream_data_bidi_remote=")) {
      if (auto n = util::parse_uint(
              line.c_str() + str_size("initial_max_stream_data_bidi_remote="));
          !n) {
        return -1;
      } else {
        params->initial_max_stream_data_bidi_remote = *n;
      }
      continue;
    }

    if (util::istarts_with_l(line, "initial_max_stream_data_uni=")) {
      if (auto n = util::parse_uint(line.c_str() +
                                    str_size("initial_max_stream_data_uni="));
          !n) {
        return -1;
      } else {
        params->initial_max_stream_data_uni = *n;
      }
      continue;
    }

    if (util::istarts_with_l(line, "initial_max_data=")) {
      if (auto n =
              util::parse_uint(line.c_str() + str_size("initial_max_data="));
          !n) {
        return -1;
      } else {
        params->initial_max_data = *n;
      }
      continue;
    }

    if (util::istarts_with_l(line, "active_connection_id_limit=")) {
      if (auto n = util::parse_uint(line.c_str() +
                                    str_size("active_connection_id_limit="));
          !n) {
        return -1;
      } else {
        params->active_connection_id_limit = *n;
      }
      continue;
    }

    if (util::istarts_with_l(line, "max_datagram_frame_size=")) {
      if (auto n = util::parse_uint(line.c_str() +
                                    str_size("max_datagram_frame_size="));
          !n) {
        return -1;
      } else {
        params->max_datagram_frame_size = *n;
      }
      continue;
    }
  }

  return 0;
}

int ClientBase::on_rx_key(ngtcp2_crypto_level level, const uint8_t *secret,
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
    std::cerr << title << " rx secret" << std::endl;
    debug::print_secrets(secret, secretlen, key.data(), keylen, iv.data(),
                         ivlen, hp_key.data(), keylen);
  }

  if (level == NGTCP2_CRYPTO_LEVEL_APPLICATION) {
    if (config.tp_file) {
      ngtcp2_transport_params params;

      ngtcp2_conn_get_remote_transport_params(conn_, &params);

      if (write_transport_params(config.tp_file, &params) != 0) {
        std::cerr << "Could not write transport parameters in "
                  << config.tp_file << std::endl;
      }
    }
  }

  return 0;
}

int ClientBase::on_tx_key(ngtcp2_crypto_level level, const uint8_t *secret,
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
  auto title = debug::secret_title(level);

  if (!config.quiet && config.show_secret) {
    std::cerr << title << " tx secret" << std::endl;
    debug::print_secrets(secret, secretlen, key.data(), keylen, iv.data(),
                         ivlen, hp_key.data(), keylen);
  }

  return 0;
}

void ClientBase::write_client_handshake(ngtcp2_crypto_level level,
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
    tx_offset += d.front().size();
    d.pop_front();
  }
}
} // namespace

void ClientBase::remove_tx_crypto_data(ngtcp2_crypto_level crypto_level,
                                       uint64_t offset, uint64_t datalen) {
  auto &crypto = crypto_[crypto_level];
  remove_tx_data(crypto.data, crypto.acked_offset, offset + datalen);
}

void ClientBase::set_tls_alert(uint8_t alert) {
  last_error_ = quic_err_tls(alert);
}

ngtcp2_conn *ClientBase::conn() const { return conn_; }

void qlog_write_cb(void *user_data, uint32_t flags, const void *data,
                   size_t datalen) {
  auto c = static_cast<ClientBase *>(user_data);
  c->write_qlog(data, datalen);
}

void ClientBase::write_qlog(const void *data, size_t datalen) {
  assert(qlog_);
  fwrite(data, 1, datalen, qlog_);
}

int ClientBase::call_application_rx_key_cb() const {
  if (!application_rx_key_cb_) {
    return 0;
  }
  return application_rx_key_cb_();
}
