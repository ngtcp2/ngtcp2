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
#include "tls_client_context_gnutls.h"

#include <iostream>

#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include "client_base.h"
#include "template.h"

// Based on https://github.com/ueno/ngtcp2-gnutls-examples

extern Config config;

TLSClientContext::TLSClientContext() : cred_{nullptr} {}

TLSClientContext::~TLSClientContext() {
  gnutls_certificate_free_credentials(cred_);
}

gnutls_certificate_credentials_t TLSClientContext::get_native_handle() const {
  return cred_;
}

int TLSClientContext::init(const char *private_key_file,
                           const char *cert_file) {
  if (auto rv = gnutls_certificate_allocate_credentials(&cred_); rv != 0) {
    std::cerr << "gnutls_certificate_allocate_credentials failed: "
              << gnutls_strerror(rv) << std::endl;
    return -1;
  }

  if (auto rv = gnutls_certificate_set_x509_system_trust(cred_); rv < 0) {
    std::cerr << "gnutls_certificate_set_x509_system_trust failed: "
              << gnutls_strerror(rv) << std::endl;
    return -1;
  }

  if (private_key_file != nullptr && cert_file != nullptr) {
    if (auto rv = gnutls_certificate_set_x509_key_file(
          cred_, cert_file, private_key_file, GNUTLS_X509_FMT_PEM);
        rv != 0) {
      std::cerr << "gnutls_certificate_set_x509_key_file failed: "
                << gnutls_strerror(rv) << std::endl;
      return -1;
    }
  }

  return 0;
}
