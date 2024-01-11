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
#include "tls_client_session_wolfssl.h"

#include <cassert>
#include <cstring>
#include <iostream>

#include "tls_client_context_wolfssl.h"
#include "client_base.h"
#include "template.h"
#include "util.h"
#include "debug.h"

using namespace std::literals;

TLSClientSession::TLSClientSession() {}

TLSClientSession::~TLSClientSession() {}

extern Config config;

int TLSClientSession::init(bool &early_data_enabled,
                           const TLSClientContext &tls_ctx,
                           const char *remote_addr, ClientBase *client,
                           uint32_t quic_version, AppProtocol app_proto) {
  early_data_enabled = false;

  auto ssl_ctx = tls_ctx.get_native_handle();

  ssl_ = wolfSSL_new(ssl_ctx);
  if (!ssl_) {
    debug::print("wolfSSL_new: {}\n",
                 ERR_error_string(ERR_get_error(), nullptr));
    return -1;
  }

  wolfSSL_set_app_data(ssl_, client->conn_ref());
  wolfSSL_set_connect_state(ssl_);

  switch (app_proto) {
  case AppProtocol::H3:
    wolfSSL_set_alpn_protos(ssl_, H3_ALPN, str_size(H3_ALPN));
    break;
  case AppProtocol::HQ:
    wolfSSL_set_alpn_protos(ssl_, HQ_ALPN, str_size(HQ_ALPN));
    break;
  }

  if (!config.sni.empty()) {
    wolfSSL_UseSNI(ssl_, WOLFSSL_SNI_HOST_NAME, config.sni.data(),
                   config.sni.length());
  } else if (util::numeric_host(remote_addr)) {
    // If remote host is numeric address, just send "localhost" as SNI
    // for now.
    wolfSSL_UseSNI(ssl_, WOLFSSL_SNI_HOST_NAME, "localhost",
                   sizeof("localhost") - 1);
  } else {
    wolfSSL_UseSNI(ssl_, WOLFSSL_SNI_HOST_NAME, remote_addr,
                   strlen(remote_addr));
  }

  if (config.session_file) {
#ifdef HAVE_SESSION_TICKET
    auto f = wolfSSL_BIO_new_file(config.session_file, "r");
    if (f == nullptr) {
      debug::print("Could not open TLS session file {}\n", config.session_file);
    } else {
      char *name, *header;
      unsigned char *data;
      const unsigned char *pdata;
      long datalen;
      unsigned int ret;
      WOLFSSL_SESSION *session;

      if (wolfSSL_PEM_read_bio(f, &name, &header, &data, &datalen) != 1) {
        debug::print("Could not read TLS session file {}\n",
                     config.session_file);
      } else {
        if ("WOLFSSL SESSION PARAMETERS"sv != name) {
          debug::print("TLS session file contains unexpected name: {}\n", name);
        } else {
          pdata = data;
          session = wolfSSL_d2i_SSL_SESSION(nullptr, &pdata, datalen);
          if (session == nullptr) {
            debug::print("Could not parse TLS session from file {}\n",
                         config.session_file);
          } else {
            ret = wolfSSL_set_session(ssl_, session);
            if (ret != WOLFSSL_SUCCESS) {
              debug::print("Could not install TLS session from file {}\n",
                           config.session_file);
            } else {
              if (!config.disable_early_data &&
                  wolfSSL_SESSION_get_max_early_data(session)) {
                early_data_enabled = true;
                wolfSSL_set_quic_early_data_enabled(ssl_, 1);
              }
            }
            wolfSSL_SESSION_free(session);
          }
        }

        wolfSSL_OPENSSL_free(name);
        wolfSSL_OPENSSL_free(header);
        wolfSSL_OPENSSL_free(data);
      }
      wolfSSL_BIO_free(f);
    }
    wolfSSL_UseSessionTicket(ssl_);
#else
    debug::print("TLS session im-/export not enabled in wolfSSL\n");
#endif
  }

  return 0;
}

bool TLSClientSession::get_early_data_accepted() const {
  // wolfSSL_get_early_data_status works after handshake completes.
#ifdef WOLFSSL_EARLY_DATA
  return wolfSSL_get_early_data_status(ssl_) == SSL_EARLY_DATA_ACCEPTED;
#else
  return 0;
#endif
}
