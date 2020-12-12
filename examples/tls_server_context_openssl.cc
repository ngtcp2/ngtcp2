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
#include "tls_server_context_openssl.h"

#include <iostream>
#include <fstream>

#include <ngtcp2/ngtcp2_crypto_openssl.h>

#include <openssl/err.h>

#include "server_base.h"
#include "template.h"

extern Config config;

TLSServerContext::TLSServerContext() : ssl_ctx_{nullptr} {}

TLSServerContext::~TLSServerContext() {
  if (ssl_ctx_) {
    SSL_CTX_free(ssl_ctx_);
  }
}

SSL_CTX *TLSServerContext::get_native_handle() const { return ssl_ctx_; }

namespace {
int alpn_select_proto_h3_cb(SSL *ssl, const unsigned char **out,
                            unsigned char *outlen, const unsigned char *in,
                            unsigned int inlen, void *arg) {
  auto h = static_cast<HandlerBase *>(SSL_get_app_data(ssl));
  const uint8_t *alpn;
  size_t alpnlen;
  auto version = ngtcp2_conn_get_negotiated_version(h->conn());

  switch (version) {
  case QUIC_VER_DRAFT29:
    alpn = reinterpret_cast<const uint8_t *>(H3_ALPN_DRAFT29);
    alpnlen = str_size(H3_ALPN_DRAFT29);
    break;
  case QUIC_VER_DRAFT30:
    alpn = reinterpret_cast<const uint8_t *>(H3_ALPN_DRAFT30);
    alpnlen = str_size(H3_ALPN_DRAFT30);
    break;
  case QUIC_VER_DRAFT31:
    alpn = reinterpret_cast<const uint8_t *>(H3_ALPN_DRAFT31);
    alpnlen = str_size(H3_ALPN_DRAFT31);
    break;
  case QUIC_VER_DRAFT32:
    alpn = reinterpret_cast<const uint8_t *>(H3_ALPN_DRAFT32);
    alpnlen = str_size(H3_ALPN_DRAFT32);
    break;
  case QUIC_VER_V1:
    alpn = reinterpret_cast<const uint8_t *>(H3_ALPN_V1);
    alpnlen = str_size(H3_ALPN_V1);
    break;
  default:
    if (!config.quiet) {
      std::cerr << "Unexpected quic protocol version: " << std::hex << "0x"
                << version << std::dec << std::endl;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }

  for (auto p = in, end = in + inlen; p + alpnlen <= end; p += *p + 1) {
    if (std::equal(alpn, alpn + alpnlen, p)) {
      *out = p + 1;
      *outlen = *p;
      return SSL_TLSEXT_ERR_OK;
    }
  }

  if (!config.quiet) {
    std::cerr << "Client did not present ALPN " << &alpn[1] << std::endl;
  }

  return SSL_TLSEXT_ERR_ALERT_FATAL;
}
} // namespace

namespace {
int alpn_select_proto_hq_cb(SSL *ssl, const unsigned char **out,
                            unsigned char *outlen, const unsigned char *in,
                            unsigned int inlen, void *arg) {
  auto h = static_cast<HandlerBase *>(SSL_get_app_data(ssl));
  const uint8_t *alpn;
  size_t alpnlen;
  auto version = ngtcp2_conn_get_negotiated_version(h->conn());

  switch (version) {
  case QUIC_VER_DRAFT29:
    alpn = reinterpret_cast<const uint8_t *>(HQ_ALPN_DRAFT29);
    alpnlen = str_size(HQ_ALPN_DRAFT29);
    break;
  case QUIC_VER_DRAFT30:
    alpn = reinterpret_cast<const uint8_t *>(HQ_ALPN_DRAFT30);
    alpnlen = str_size(HQ_ALPN_DRAFT30);
    break;
  case QUIC_VER_DRAFT31:
    alpn = reinterpret_cast<const uint8_t *>(HQ_ALPN_DRAFT31);
    alpnlen = str_size(HQ_ALPN_DRAFT31);
    break;
  case QUIC_VER_DRAFT32:
    alpn = reinterpret_cast<const uint8_t *>(HQ_ALPN_DRAFT32);
    alpnlen = str_size(HQ_ALPN_DRAFT32);
    break;
  case QUIC_VER_V1:
    alpn = reinterpret_cast<const uint8_t *>(HQ_ALPN_V1);
    alpnlen = str_size(HQ_ALPN_V1);
    break;
  default:
    if (!config.quiet) {
      std::cerr << "Unexpected quic protocol version: " << std::hex << "0x"
                << version << std::dec << std::endl;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }

  for (auto p = in, end = in + inlen; p + alpnlen <= end; p += *p + 1) {
    if (std::equal(alpn, alpn + alpnlen, p)) {
      *out = p + 1;
      *outlen = *p;
      return SSL_TLSEXT_ERR_OK;
    }
  }

  if (!config.quiet) {
    std::cerr << "Client did not present ALPN " << &alpn[1] << std::endl;
  }

  return SSL_TLSEXT_ERR_ALERT_FATAL;
}
} // namespace

namespace {
int set_encryption_secrets(SSL *ssl, OSSL_ENCRYPTION_LEVEL ossl_level,
                           const uint8_t *read_secret,
                           const uint8_t *write_secret, size_t secret_len) {
  auto h = static_cast<HandlerBase *>(SSL_get_app_data(ssl));
  auto level = ngtcp2_crypto_openssl_from_ossl_encryption_level(ossl_level);

  if (auto rv = h->on_rx_key(level, read_secret, secret_len); rv != 0) {
    return 0;
  }
  if (write_secret) {
    if (auto rv = h->on_tx_key(level, write_secret, secret_len); rv != 0) {
      return 0;
    }

    if (level == NGTCP2_CRYPTO_LEVEL_APPLICATION &&
        h->call_application_tx_key_cb() != 0) {
      return 0;
    }
  }

  return 1;
}
} // namespace

namespace {
int add_handshake_data(SSL *ssl, OSSL_ENCRYPTION_LEVEL ossl_level,
                       const uint8_t *data, size_t len) {
  auto h = static_cast<HandlerBase *>(SSL_get_app_data(ssl));
  auto level = ngtcp2_crypto_openssl_from_ossl_encryption_level(ossl_level);
  h->write_server_handshake(level, data, len);
  return 1;
}
} // namespace

namespace {
int flush_flight(SSL *ssl) { return 1; }
} // namespace

namespace {
int send_alert(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert) {
  auto h = static_cast<HandlerBase *>(SSL_get_app_data(ssl));
  h->set_tls_alert(alert);
  return 1;
}
} // namespace

namespace {
auto quic_method = SSL_QUIC_METHOD{
    set_encryption_secrets,
    add_handshake_data,
    flush_flight,
    send_alert,
};
} // namespace

namespace {
int verify_cb(int preverify_ok, X509_STORE_CTX *ctx) {
  // We don't verify the client certificate.  Just request it for the
  // testing purpose.
  return 1;
}
} // namespace

int TLSServerContext::init(const char *private_key_file, const char *cert_file,
                           AppProtocol app_proto) {
  constexpr static unsigned char sid_ctx[] = "ngtcp2 server";

  ssl_ctx_ = SSL_CTX_new(TLS_server_method());

  constexpr auto ssl_opts = (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) |
                            SSL_OP_SINGLE_ECDH_USE |
                            SSL_OP_CIPHER_SERVER_PREFERENCE |
                            SSL_OP_NO_ANTI_REPLAY;

  SSL_CTX_set_options(ssl_ctx_, ssl_opts);

  if (SSL_CTX_set_ciphersuites(ssl_ctx_, config.ciphers) != 1) {
    std::cerr << "SSL_CTX_set_ciphersuites: "
              << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
    return -1;
  }

  if (SSL_CTX_set1_groups_list(ssl_ctx_, config.groups) != 1) {
    std::cerr << "SSL_CTX_set1_groups_list failed" << std::endl;
    return -1;
  }

  SSL_CTX_set_mode(ssl_ctx_, SSL_MODE_RELEASE_BUFFERS);

  SSL_CTX_set_min_proto_version(ssl_ctx_, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ssl_ctx_, TLS1_3_VERSION);

  switch (app_proto) {
  case AppProtocol::H3:
    SSL_CTX_set_alpn_select_cb(ssl_ctx_, alpn_select_proto_h3_cb, nullptr);
    break;
  case AppProtocol::HQ:
    SSL_CTX_set_alpn_select_cb(ssl_ctx_, alpn_select_proto_hq_cb, nullptr);
    break;
  }

  SSL_CTX_set_default_verify_paths(ssl_ctx_);

  if (SSL_CTX_use_PrivateKey_file(ssl_ctx_, private_key_file,
                                  SSL_FILETYPE_PEM) != 1) {
    std::cerr << "SSL_CTX_use_PrivateKey_file: "
              << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
    return -1;
  }

  if (SSL_CTX_use_certificate_chain_file(ssl_ctx_, cert_file) != 1) {
    std::cerr << "SSL_CTX_use_certificate_file: "
              << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
    return -1;
  }

  if (SSL_CTX_check_private_key(ssl_ctx_) != 1) {
    std::cerr << "SSL_CTX_check_private_key: "
              << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
    return -1;
  }

  SSL_CTX_set_session_id_context(ssl_ctx_, sid_ctx, sizeof(sid_ctx) - 1);

  if (config.verify_client) {
    SSL_CTX_set_verify(ssl_ctx_,
                       SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE |
                           SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       verify_cb);
  }

  SSL_CTX_set_max_early_data(ssl_ctx_, std::numeric_limits<uint32_t>::max());
  SSL_CTX_set_quic_method(ssl_ctx_, &quic_method);

  return 0;
}

extern std::ofstream keylog_file;

namespace {
void keylog_callback(const SSL *ssl, const char *line) {
  keylog_file.write(line, strlen(line));
  keylog_file.put('\n');
  keylog_file.flush();
}
} // namespace

void TLSServerContext::enable_keylog() {
  SSL_CTX_set_keylog_callback(ssl_ctx_, keylog_callback);
}
