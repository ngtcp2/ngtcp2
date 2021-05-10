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
    gnutls_free(d.data);
    gnutls_free(data.data);
  }

  return 0;
}
} // namespace

namespace {
int secret_func(gnutls_session_t session,
                gnutls_record_encryption_level_t gtls_level,
                const void *secret_read, const void *secret_write,
                size_t secret_size) {
  auto c = static_cast<ClientBase *>(gnutls_session_get_ptr(session));
  auto level =
      ngtcp2_crypto_gnutls_from_gnutls_record_encryption_level(gtls_level);
  if (secret_read) {
    if (c->on_rx_key(level, reinterpret_cast<const uint8_t *>(secret_read),
                     secret_size) != 0) {
      return -1;
    }

    if (level == NGTCP2_CRYPTO_LEVEL_APPLICATION &&
        c->call_application_rx_key_cb() != 0) {
      return -1;
    }
  }
  if (secret_write &&
      c->on_tx_key(level, reinterpret_cast<const uint8_t *>(secret_write),
                   secret_size) != 0) {
    return -1;
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

  auto c = static_cast<ClientBase *>(gnutls_session_get_ptr(session));
  c->write_client_handshake(
      ngtcp2_crypto_gnutls_from_gnutls_record_encryption_level(level),
      reinterpret_cast<const uint8_t *>(data), data_size);
  return 0;
}
} // namespace

namespace {
int alert_read_func(gnutls_session_t session,
                    gnutls_record_encryption_level_t level,
                    gnutls_alert_level_t alert_level,
                    gnutls_alert_description_t alert_desc) {
  auto c = static_cast<ClientBase *>(gnutls_session_get_ptr(session));
  c->set_tls_alert(alert_desc);
  return 0;
}
} // namespace

namespace {
int set_remote_transport_params(const ClientBase *client, const uint8_t *data,
                                size_t datalen) {
  auto conn = client->conn();

  ngtcp2_transport_params params;

  if (auto rv = ngtcp2_decode_transport_params(
          &params, NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, data,
          datalen);
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
  auto c = static_cast<ClientBase *>(gnutls_session_get_ptr(session));
  if (set_remote_transport_params(c, data, data_size) != 0) {
    return -1;
  }
  return 0;
}
} // namespace

namespace {
int append_local_transport_params(const ClientBase *client,
                                  gnutls_buffer_st *extdata) {
  auto conn = client->conn();

  ngtcp2_transport_params params;
  ngtcp2_conn_get_local_transport_params(conn, &params);

  std::array<uint8_t, 64> buf;

  auto nwrite = ngtcp2_encode_transport_params(
      buf.data(), buf.size(), NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO,
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
  auto c = static_cast<ClientBase *>(gnutls_session_get_ptr(session));
  auto nwrite = append_local_transport_params(c, extdata);
  if (nwrite < 0) {
    return -1;
  }
  return nwrite;
}
} // namespace

int TLSClientSession::init(bool &early_data_enabled,
                           const TLSClientContext &tls_ctx,
                           const char *remote_addr, ClientBase *client,
                           AppProtocol app_proto) {
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
  gnutls_handshake_set_secret_function(session_, secret_func);
  gnutls_handshake_set_read_function(session_, read_func);
  gnutls_alert_set_read_function(session_, alert_read_func);

  if (auto rv = gnutls_session_ext_register(
          session_, "QUIC Transport Parameters",
          NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS_DRAFT, GNUTLS_EXT_TLS,
          tp_recv_func, tp_send_func, nullptr, nullptr, nullptr,
          GNUTLS_EXT_FLAG_TLS | GNUTLS_EXT_FLAG_CLIENT_HELLO |
              GNUTLS_EXT_FLAG_EE);
      rv != 0) {
    std::cerr << "gnutls_session_ext_register failed: " << gnutls_strerror(rv)
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

      gnutls_datum_t s{};
      s.data = reinterpret_cast<unsigned char *>(content.data());
      s.size = content.size();

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

      early_data_enabled = true;
    }
  }

  gnutls_session_set_ptr(session_, client);

  if (auto rv = gnutls_credentials_set(session_, GNUTLS_CRD_CERTIFICATE,
                                       tls_ctx.get_native_handle());
      rv != 0) {
    std::cerr << "gnutls_credentials_set failed: " << gnutls_strerror(rv)
              << std::endl;
    return -1;
  }

  gnutls_datum_t alpn = {NULL, 0};

  // strip the first byte from H3_ALPN_DRAFT29
  alpn.data = const_cast<uint8_t *>(&H3_ALPN_DRAFT29[1]);
  alpn.size = H3_ALPN_DRAFT29[0];
  gnutls_alpn_set_protocols(session_, &alpn, 1, 0);

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
