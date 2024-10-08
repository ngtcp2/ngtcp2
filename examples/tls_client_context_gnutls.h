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
#ifndef TLS_CLIENT_CONTEXT_GNUTLS_H
#define TLS_CLIENT_CONTEXT_GNUTLS_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif // defined(HAVE_CONFIG_H)

#include <gnutls/gnutls.h>

class TLSClientContext {
public:
  TLSClientContext();
  ~TLSClientContext();

  int init(const char *private_key_file, const char *cert_file);

  gnutls_certificate_credentials_t get_native_handle() const;

  // Keylog is enabled per session.
  void enable_keylog() {}

private:
  gnutls_certificate_credentials_t cred_;
};

#endif // !defined(TLS_CLIENT_CONTEXT_GNUTLS_H)
