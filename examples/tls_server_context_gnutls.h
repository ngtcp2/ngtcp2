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
#ifndef TLS_SERVER_CONTEXT_GNUTLS_H
#define TLS_SERVER_CONTEXT_GNUTLS_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif // defined(HAVE_CONFIG_H)

#include <gnutls/gnutls.h>

#include "shared.h"

using namespace ngtcp2;

class TLSServerContext {
public:
  TLSServerContext();
  ~TLSServerContext();

  int init(const char *private_key_file, const char *cert_file,
           AppProtocol app_proto);

  gnutls_certificate_credentials_t get_certificate_credentials() const;
  const gnutls_datum_t *get_session_ticket_key() const;
  gnutls_anti_replay_t get_anti_replay() const;

  // Keylog is enabled per session.
  void enable_keylog() {}

private:
  gnutls_certificate_credentials_t cred_;
  gnutls_datum_t session_ticket_key_;
  gnutls_anti_replay_t anti_replay_;
};

#endif // !defined(TLS_SERVER_CONTEXT_GNUTLS_H)
