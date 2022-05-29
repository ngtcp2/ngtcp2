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

  gnutls_handshake_set_hook_function(session_, GNUTLS_HANDSHAKE_CLIENT_HELLO,
                                     GNUTLS_HOOK_POST, client_hello_cb);

  if (ngtcp2_crypto_gnutls_configure_server_session(session_) != 0) {
    std::cerr << "ngtcp2_crypto_gnutls_configure_server_session failed"
              << std::endl;
    return -1;
  }

  gnutls_anti_replay_enable(session_, tls_ctx.get_anti_replay());

  gnutls_record_set_max_early_data_size(session_, 0xffffffffu);

  gnutls_session_set_ptr(session_, handler->conn_ref());

  if (auto rv = gnutls_credentials_set(session_, GNUTLS_CRD_CERTIFICATE,
                                       tls_ctx.get_certificate_credentials());
      rv != 0) {
    std::cerr << "gnutls_credentials_set failed: " << gnutls_strerror(rv)
              << std::endl;
    return -1;
  }

  // TODO Set all available ALPN based on app_proto.

  // strip the first byte from H3_ALPN_V1
  gnutls_datum_t alpn{
      .data = const_cast<uint8_t *>(&H3_ALPN_V1[1]),
      .size = H3_ALPN_V1[0],
  };
  gnutls_alpn_set_protocols(session_, &alpn, 1,
                            GNUTLS_ALPN_MANDATORY |
                                GNUTLS_ALPN_SERVER_PRECEDENCE);

  if (config.verify_client) {
    gnutls_certificate_server_set_request(session_, GNUTLS_CERT_REQUIRE);
    gnutls_certificate_send_x509_rdn_sequence(session_, 1);
  }

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
