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
#include "tls_session_base_gnutls.h"

#include <cstring>
#include <fstream>

#include "util.h"

// Based on https://github.com/ueno/ngtcp2-gnutls-examples

using namespace ngtcp2;

TLSSessionBase::TLSSessionBase() : session_{nullptr} {}

TLSSessionBase::~TLSSessionBase() { gnutls_deinit(session_); }

gnutls_session_t TLSSessionBase::get_native_handle() const { return session_; }

std::string TLSSessionBase::get_cipher_name() const {
  return gnutls_cipher_get_name(gnutls_cipher_get(session_));
}

std::string_view TLSSessionBase::get_negotiated_group() const {
  return gnutls_group_get_name(gnutls_group_get(session_));
}

std::string TLSSessionBase::get_selected_alpn() const {
  gnutls_datum_t alpn;

  if (auto rv = gnutls_alpn_get_selected_protocol(session_, &alpn); rv == 0) {
    return std::string{alpn.data, alpn.data + alpn.size};
  }

  return {};
}

extern std::ofstream keylog_file;

namespace {
int keylog_callback(gnutls_session_t session, const char *label,
                    const gnutls_datum_t *secret) {
  keylog_file.write(label, strlen(label));
  keylog_file.put(' ');

  gnutls_datum_t crandom;
  gnutls_datum_t srandom;

  gnutls_session_get_random(session, &crandom, &srandom);
  if (crandom.size != 32) {
    return -1;
  }

  auto crandom_hex = util::format_hex({crandom.data, 32});
  keylog_file << crandom_hex << " ";

  auto secret_hex = util::format_hex({secret->data, secret->size});
  keylog_file << secret_hex << " ";

  keylog_file.put('\n');
  keylog_file.flush();
  return 0;
}
} // namespace

void TLSSessionBase::enable_keylog() {
  gnutls_session_set_keylog_function(session_, keylog_callback);
}
