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
#include "tls_client_session_gnutls.h"

#include <cstring>
#include <iostream>
#include <fstream>
#include <array>

#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include <gnutls/crypto.h>

#include "tls_client_context_gnutls.h"
#include "client_base.h"
#include "template.h"
#include "util.h"

// Based on https://github.com/ueno/ngtcp2-gnutls-examples

extern Config config;

TLSClientSession::TLSClientSession() {}

TLSClientSession::~TLSClientSession() {}

namespace {
int hook_func(gnutls_session_t session, unsigned int htype, unsigned when,
              unsigned int incoming, const gnutls_datum_t *msg) {
  if (config.session_file && htype == GNUTLS_HANDSHAKE_NEW_SESSION_TICKET) {
    auto conn_ref =
        static_cast<ngtcp2_crypto_conn_ref *>(gnutls_session_get_ptr(session));
    auto c = static_cast<ClientBase *>(conn_ref->user_data);

    c->ticket_received();

    gnutls_datum_t data;
    if (auto rv = gnutls_session_get_data2(session, &data); rv != 0) {
      std::cerr << "gnutls_session_get_data2 failed: " << gnutls_strerror(rv)
                << std::endl;
      return rv;
    }
    auto f = std::ofstream(config.session_file);
    if (!f) {
      return -1;
    }

    gnutls_datum_t d;
    if (auto rv =
            gnutls_pem_base64_encode2("GNUTLS SESSION PARAMETERS", &data, &d);
        rv < 0) {
      std::cerr << "Could not encode session in " << config.session_file
                << std::endl;
      return -1;
    }

    f.write(reinterpret_cast<const char *>(d.data), d.size);
    if (!f) {
      std::cerr << "Unable to write TLS session to file" << std::endl;
    }
    gnutls_free(d.data);
    gnutls_free(data.data);
  }

  return 0;
}
} // namespace

int TLSClientSession::init(bool &early_data_enabled,
                           const TLSClientContext &tls_ctx,
                           const char *remote_addr, ClientBase *client,
                           uint32_t quic_version, AppProtocol app_proto) {
  early_data_enabled = false;

  if (auto rv =
          gnutls_init(&session_, GNUTLS_CLIENT | GNUTLS_ENABLE_EARLY_DATA |
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

  gnutls_handshake_set_hook_function(session_, GNUTLS_HANDSHAKE_ANY,
                                     GNUTLS_HOOK_POST, hook_func);

  if (ngtcp2_crypto_gnutls_configure_client_session(session_) != 0) {
    std::cerr << "ngtcp2_crypto_gnutls_configure_client_session failed"
              << std::endl;
    return -1;
  }

  if (config.session_file) {
    auto f = std::ifstream(config.session_file);
    if (f) {
      f.seekg(0, std::ios::end);
      auto pos = f.tellg();
      std::vector<char> content(pos);
      f.seekg(0, std::ios::beg);
      f.read(content.data(), pos);

      gnutls_datum_t s{
          .data = reinterpret_cast<unsigned char *>(content.data()),
          .size = static_cast<unsigned int>(content.size()),
      };

      gnutls_datum_t d;
      if (auto rv =
              gnutls_pem_base64_decode2("GNUTLS SESSION PARAMETERS", &s, &d);
          rv < 0) {
        std::cerr << "Could not read session in " << config.session_file
                  << std::endl;
        return -1;
      }

      auto d_d = defer(gnutls_free, d.data);

      if (auto rv = gnutls_session_set_data(session_, d.data, d.size);
          rv != 0) {
        std::cerr << "gnutls_session_set_data failed: " << gnutls_strerror(rv)
                  << std::endl;
        return -1;
      }

      if (!config.disable_early_data) {
        early_data_enabled = true;
      }
    }
  }

  gnutls_session_set_ptr(session_, client->conn_ref());

  if (auto rv = gnutls_credentials_set(session_, GNUTLS_CRD_CERTIFICATE,
                                       tls_ctx.get_native_handle());
      rv != 0) {
    std::cerr << "gnutls_credentials_set failed: " << gnutls_strerror(rv)
              << std::endl;
    return -1;
  }

  // strip the first byte from H3_ALPN_V1
  gnutls_datum_t alpn{
      .data = const_cast<uint8_t *>(&H3_ALPN_V1[1]),
      .size = H3_ALPN_V1[0],
  };

  gnutls_alpn_set_protocols(session_, &alpn, 1, GNUTLS_ALPN_MANDATORY);

  if (util::numeric_host(remote_addr)) {
    // If remote host is numeric address, just send "localhost" as SNI
    // for now.
    gnutls_server_name_set(session_, GNUTLS_NAME_DNS, "localhost",
                           strlen("localhost"));
  } else {
    gnutls_server_name_set(session_, GNUTLS_NAME_DNS, remote_addr,
                           strlen(remote_addr));
  }

  return 0;
}

bool TLSClientSession::get_early_data_accepted() const {
  return gnutls_session_get_flags(session_) & GNUTLS_SFLAGS_EARLY_DATA;
}
