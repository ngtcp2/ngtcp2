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
#include "tls_server_session_gnutls.h"

#include <cassert>
#include <iostream>
#include <fstream>
#include <array>

#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include "tls_server_context_gnutls.h"
#include "server_base.h"
#include "util.h"

// Based on https://github.com/ueno/ngtcp2-gnutls-examples

using namespace ngtcp2;

extern Config config;

TLSServerSession::TLSServerSession() {}

TLSServerSession::~TLSServerSession() {}

namespace {
int secret_func(gnutls_session_t session,
                gnutls_record_encryption_level_t gtls_level,
                const void *secret_read, const void *secret_write,
                size_t secret_size) {
  auto h = static_cast<HandlerBase *>(gnutls_session_get_ptr(session));
  auto level =
      ngtcp2_crypto_gnutls_from_gnutls_record_encryption_level(gtls_level);
  if (secret_read &&
      h->on_rx_key(level, reinterpret_cast<const uint8_t *>(secret_read),
                   secret_size) != 0) {
    return -1;
  }

  if (secret_write) {
    if (h->on_tx_key(level, reinterpret_cast<const uint8_t *>(secret_write),
                     secret_size) != 0) {
      return -1;
    }

    if (level == NGTCP2_CRYPTO_LEVEL_APPLICATION &&
        h->call_application_tx_key_cb() != 0) {
      return -1;
    }
  }

  return 0;
}
} // namespace

namespace {
int read_func(gnutls_session_t session, gnutls_record_encryption_level_t level,
              gnutls_handshake_description_t htype, const void *data,
              size_t data_size) {
  if (htype == GNUTLS_HANDSHAKE_CHANGE_CIPHER_SPEC) {
    return 0;
  }

  auto h = static_cast<HandlerBase *>(gnutls_session_get_ptr(session));
  h->write_server_handshake(
      ngtcp2_crypto_gnutls_from_gnutls_record_encryption_level(level),
      reinterpret_cast<const uint8_t *>(data), data_size);
  return 1;
}
} // namespace

namespace {
int alert_read_func(gnutls_session_t session,
                    gnutls_record_encryption_level_t level,
                    gnutls_alert_level_t alert_level,
                    gnutls_alert_description_t alert_desc) {
  auto h = static_cast<HandlerBase *>(gnutls_session_get_ptr(session));
  h->set_tls_alert(alert_desc);
  return 0;
}
} // namespace

namespace {
int client_hello_cb(gnutls_session_t session, unsigned int htype, unsigned when,
                    unsigned int incoming, const gnutls_datum_t *msg) {
  assert(htype == GNUTLS_HANDSHAKE_CLIENT_HELLO);
  assert(when == GNUTLS_HOOK_POST);
  assert(incoming == 1);

  // check if ALPN extension is present and properly selected h3
  gnutls_datum_t alpn;
  if (auto rv = gnutls_alpn_get_selected_protocol(session, &alpn); rv != 0) {
    return rv;
  }

  // TODO Fix this to properly select ALPN based on app_proto.

  // strip the first byte from H3_ALPN_V1
  auto h3 = reinterpret_cast<const char *>(&H3_ALPN_V1[1]);
  if (static_cast<size_t>(H3_ALPN_V1[0]) != alpn.size ||
      !std::equal(alpn.data, alpn.data + alpn.size, h3)) {
    return -1;
  }

  return 0;
}
} // namespace

namespace {
int set_remote_transport_params(const HandlerBase *handler, const uint8_t *data,
                                size_t datalen) {
  auto conn = handler->conn();

  ngtcp2_transport_params params;

  if (auto rv = ngtcp2_decode_transport_params(
          &params, NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, data, datalen);
      rv != 0) {
    std::cerr << "ngtcp2_decode_transport_params: " << ngtcp2_strerror(rv)
              << std::endl;
    return -1;
  }

  if (auto rv = ngtcp2_conn_set_remote_transport_params(conn, &params);
      rv != 0) {
    std::cerr << "ngtcp2_conn_set_remote_transport_params: "
              << ngtcp2_strerror(rv) << std::endl;
    return -1;
  }

  return 0;
}
} // namespace

namespace {
int tp_recv_func(gnutls_session_t session, const uint8_t *data,
                 size_t data_size) {
  auto h = static_cast<HandlerBase *>(gnutls_session_get_ptr(session));
  if (set_remote_transport_params(h, data, data_size) != 0) {
    return -1;
  }
  return 0;
}
} // namespace

namespace {
int append_local_transport_params(const HandlerBase *handler,
                                  gnutls_buffer_st *extdata) {
  auto conn = handler->conn();

  ngtcp2_transport_params params;
  ngtcp2_conn_get_local_transport_params(conn, &params);

  std::array<uint8_t, 256> buf;

  auto nwrite = ngtcp2_encode_transport_params(
      buf.data(), buf.size(), NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS,
      &params);
  if (nwrite < 0) {
    std::cerr << "ngtcp2_encode_transport_params: " << ngtcp2_strerror(nwrite)
              << std::endl;
    return -1;
  }

  if (auto rv = gnutls_buffer_append_data(extdata, buf.data(), nwrite);
      rv != 0) {
    std::cerr << "gnutls_buffer_append_data failed: " << gnutls_strerror(rv)
              << std::endl;
    return -1;
  }

  return nwrite;
}
} // namespace

namespace {
int tp_send_func(gnutls_session_t session, gnutls_buffer_st *extdata) {
  auto h = static_cast<HandlerBase *>(gnutls_session_get_ptr(session));
  auto nwrite = append_local_transport_params(h, extdata);
  if (nwrite < 0) {
    return -1;
  }
  return nwrite;
}
} // namespace

int TLSServerSession::init(const TLSServerContext &tls_ctx,
                           HandlerBase *handler) {
  if (auto rv =
          gnutls_init(&session_, GNUTLS_SERVER | GNUTLS_ENABLE_EARLY_DATA |
                                     GNUTLS_NO_AUTO_SEND_TICKET |
                                     GNUTLS_NO_END_OF_EARLY_DATA);
      rv != 0) {
    std::cerr << "gnutls_init failed: " << gnutls_strerror(rv) << std::endl;
    return -1;
  }

  std::string priority = "%DISABLE_TLS13_COMPAT_MODE:";
  priority += config.ciphers;
  priority += ':';
  priority += config.groups;

  if (auto rv = gnutls_priority_set_direct(session_, priority.c_str(), nullptr);
      rv != 0) {
    std::cerr << "gnutls_priority_set_direct failed: " << gnutls_strerror(rv)
              << std::endl;
    return -1;
  }

  auto rv = gnutls_session_ticket_enable_server(
      session_, tls_ctx.get_session_ticket_key());
  if (rv != 0) {
    std::cerr << "gnutls_session_ticket_enable_server failed: "
              << gnutls_strerror(rv) << std::endl;
    return -1;
  }

  gnutls_handshake_set_secret_function(session_, secret_func);
  gnutls_handshake_set_read_function(session_, read_func);
  gnutls_alert_set_read_function(session_, alert_read_func);
  gnutls_handshake_set_hook_function(session_, GNUTLS_HANDSHAKE_CLIENT_HELLO,
                                     GNUTLS_HOOK_POST, client_hello_cb);
  if (auto rv = gnutls_session_ext_register(
          session_, "QUIC Transport Parameters",
          NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS_V1, GNUTLS_EXT_TLS,
          tp_recv_func, tp_send_func, nullptr, nullptr, nullptr,
          GNUTLS_EXT_FLAG_TLS | GNUTLS_EXT_FLAG_CLIENT_HELLO |
              GNUTLS_EXT_FLAG_EE);
      rv != 0) {
    std::cerr << "gnutls_session_ext_register failed: " << gnutls_strerror(rv)
              << std::endl;
    return -1;
  }

  gnutls_anti_replay_enable(session_, tls_ctx.get_anti_replay());

  gnutls_record_set_max_early_data_size(session_, 0xffffffffu);

  gnutls_session_set_ptr(session_, handler);

  if (auto rv = gnutls_credentials_set(session_, GNUTLS_CRD_CERTIFICATE,
                                       tls_ctx.get_certificate_credentials());
      rv != 0) {
    std::cerr << "gnutls_credentials_set failed: " << gnutls_strerror(rv)
              << std::endl;
    return -1;
  }

  // TODO Set all available ALPN based on app_proto.

  // strip the first byte from H3_ALPN_V1
  gnutls_datum_t alpn = {nullptr, 0};
  alpn.data = const_cast<uint8_t *>(&H3_ALPN_V1[1]);
  alpn.size = H3_ALPN_V1[0];
  gnutls_alpn_set_protocols(session_, &alpn, 1, 0);

  return 0;
}

int TLSServerSession::send_session_ticket() {
  if (auto rv = gnutls_session_ticket_send(session_, 1, 0); rv != 0) {
    std::cerr << "gnutls_session_ticket_send failed: " << gnutls_strerror(rv)
              << std::endl;
    return -1;
  }

  return 0;
}
