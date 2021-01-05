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
#include "tls_client_context_openssl.h"

#include <iostream>
#include <fstream>

#include <ngtcp2/ngtcp2_crypto_openssl.h>

#include <openssl/err.h>

#include "client_base.h"
#include "template.h"

extern Config config;

TLSClientContext::TLSClientContext() : ssl_ctx_{nullptr} {}

TLSClientContext::~TLSClientContext() {
  if (ssl_ctx_) {
    SSL_CTX_free(ssl_ctx_);
  }
}

SSL_CTX *TLSClientContext::get_native_handle() const { return ssl_ctx_; }

namespace {
int new_session_cb(SSL *ssl, SSL_SESSION *session) {
  if (SSL_SESSION_get_max_early_data(session) !=
      std::numeric_limits<uint32_t>::max()) {
    std::cerr << "max_early_data_size is not 0xffffffff" << std::endl;
  }
  auto f = BIO_new_file(config.session_file, "w");
  if (f == nullptr) {
    std::cerr << "Could not write TLS session in " << config.session_file
              << std::endl;
    return 0;
  }

  PEM_write_bio_SSL_SESSION(f, session);
  BIO_free(f);

  return 0;
}
} // namespace

namespace {
int set_encryption_secrets(SSL *ssl, OSSL_ENCRYPTION_LEVEL ossl_level,
                           const uint8_t *read_secret,
                           const uint8_t *write_secret, size_t secret_len) {
  auto c = static_cast<ClientBase *>(SSL_get_app_data(ssl));
  auto level = ngtcp2_crypto_openssl_from_ossl_encryption_level(ossl_level);

  if (read_secret) {
    if (c->on_rx_key(level, read_secret, secret_len) != 0) {
      return 0;
    }

    if (level == NGTCP2_CRYPTO_LEVEL_APPLICATION &&
        c->call_application_rx_key_cb() != 0) {
      return 0;
    }
  }

  if (c->on_tx_key(level, write_secret, secret_len) != 0) {
    return 0;
  }

  return 1;
}
} // namespace

namespace {
int add_handshake_data(SSL *ssl, OSSL_ENCRYPTION_LEVEL ossl_level,
                       const uint8_t *data, size_t len) {
  auto c = static_cast<ClientBase *>(SSL_get_app_data(ssl));
  auto level = ngtcp2_crypto_openssl_from_ossl_encryption_level(ossl_level);
  c->write_client_handshake(level, data, len);
  return 1;
}
} // namespace

namespace {
int flush_flight(SSL *ssl) { return 1; }
} // namespace

namespace {
int send_alert(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert) {
  auto c = static_cast<ClientBase *>(SSL_get_app_data(ssl));
  c->set_tls_alert(alert);
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

int TLSClientContext::init(const char *private_key_file,
                           const char *cert_file) {
  ssl_ctx_ = SSL_CTX_new(TLS_client_method());

  SSL_CTX_set_min_proto_version(ssl_ctx_, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ssl_ctx_, TLS1_3_VERSION);

  SSL_CTX_set_default_verify_paths(ssl_ctx_);

  if (SSL_CTX_set_ciphersuites(ssl_ctx_, config.ciphers) != 1) {
    std::cerr << "SSL_CTX_set_ciphersuites: "
              << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
    return -1;
  }

  if (SSL_CTX_set1_groups_list(ssl_ctx_, config.groups) != 1) {
    std::cerr << "SSL_CTX_set1_groups_list failed" << std::endl;
    return -1;
  }

  if (private_key_file && cert_file) {
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
  }

  SSL_CTX_set_quic_method(ssl_ctx_, &quic_method);

  if (config.session_file) {
    SSL_CTX_set_session_cache_mode(
        ssl_ctx_, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
    SSL_CTX_sess_set_new_cb(ssl_ctx_, new_session_cb);
  }

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

void TLSClientContext::enable_keylog() {
  SSL_CTX_set_keylog_callback(ssl_ctx_, keylog_callback);
}
