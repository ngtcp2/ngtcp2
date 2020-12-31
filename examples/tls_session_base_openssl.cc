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
#include "tls_session_base_openssl.h"

#include <array>

#include "util.h"

using namespace ngtcp2;

TLSSessionBase::TLSSessionBase() : ssl_{nullptr} {}

TLSSessionBase::~TLSSessionBase() {
  if (ssl_) {
    SSL_free(ssl_);
  }
}

SSL *TLSSessionBase::get_native_handle() const { return ssl_; }

void TLSSessionBase::log_secret(const char *name, const uint8_t *secret,
                                size_t secretlen) {
  auto keylog_cb = SSL_CTX_get_keylog_callback(SSL_get_SSL_CTX(ssl_));
  if (!keylog_cb) {
    return;
  }

  std::array<unsigned char, 32> crandom;
  if (SSL_get_client_random(ssl_, crandom.data(), crandom.size()) !=
      crandom.size()) {
    return;
  }
  std::string line = name;
  line += ' ';
  line += util::format_hex(crandom.data(), crandom.size());
  line += ' ';
  line += util::format_hex(secret, secretlen);
  keylog_cb(ssl_, line.c_str());
}

std::string TLSSessionBase::get_cipher_name() const {
  return SSL_get_cipher_name(ssl_);
}

std::string TLSSessionBase::get_selected_alpn() const {
  const unsigned char *alpn = nullptr;
  unsigned int alpnlen;

  SSL_get0_alpn_selected(ssl_, &alpn, &alpnlen);

  return std::string{alpn, alpn + alpnlen};
}
