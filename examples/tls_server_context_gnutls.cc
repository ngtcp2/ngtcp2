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
#include "tls_server_context_gnutls.h"

#include <iostream>

#include "server_base.h"
#include "template.h"

// Based on https://github.com/ueno/ngtcp2-gnutls-examples

extern Config config;

namespace {
int anti_replay_db_add_func(void *dbf, time_t exp_time,
                            const gnutls_datum_t *key,
                            const gnutls_datum_t *data) {
  return 0;
}
} // namespace

TLSServerContext::TLSServerContext() : cred_{nullptr}, session_ticket_key_{} {
  gnutls_anti_replay_init(&anti_replay_);
  gnutls_anti_replay_set_add_function(anti_replay_, anti_replay_db_add_func);
  gnutls_anti_replay_set_ptr(anti_replay_, nullptr);
}

TLSServerContext::~TLSServerContext() {
  gnutls_anti_replay_deinit(anti_replay_);
  gnutls_free(session_ticket_key_.data);
  gnutls_certificate_free_credentials(cred_);
}

gnutls_certificate_credentials_t
TLSServerContext::get_certificate_credentials() const {
  return cred_;
}

const gnutls_datum_t *TLSServerContext::get_session_ticket_key() const {
  return &session_ticket_key_;
}

gnutls_anti_replay_t TLSServerContext::get_anti_replay() const {
  return anti_replay_;
}

int TLSServerContext::init(const char *private_key_file, const char *cert_file,
                           AppProtocol app_proto) {
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

  if (auto rv = gnutls_certificate_set_x509_key_file(
        cred_, cert_file, private_key_file, GNUTLS_X509_FMT_PEM);
      rv != 0) {
    std::cerr << "gnutls_certificate_set_x509_key_file failed: "
              << gnutls_strerror(rv) << std::endl;
    return -1;
  }

  if (auto rv = gnutls_session_ticket_key_generate(&session_ticket_key_);
      rv != 0) {
    std::cerr << "gnutls_session_ticket_key_generate failed: "
              << gnutls_strerror(rv) << std::endl;
    return -1;
  }

  return 0;
}
