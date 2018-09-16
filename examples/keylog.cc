/*
 * ngtcp2
 *
 * Copyright (c) 2018 ngtcp2 contributors
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
#include <string>

#include "keylog.h"
#include "util.h"

namespace ngtcp2 {

namespace keylog {

void log_secret(SSL *ssl, int name, const unsigned char *secret,
                size_t secretlen) {
  if (auto keylog_cb = SSL_CTX_get_keylog_callback(SSL_get_SSL_CTX(ssl))) {
    unsigned char crandom[32];
    if (SSL_get_client_random(ssl, crandom, 32) != 32) {
      return;
    }
    std::string line;
    switch (name) {
    case SSL_KEY_CLIENT_EARLY_TRAFFIC:
      line = "QUIC_CLIENT_EARLY_TRAFFIC_SECRET";
      break;
    case SSL_KEY_CLIENT_HANDSHAKE_TRAFFIC:
      line = "QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET";
      break;
    case SSL_KEY_CLIENT_APPLICATION_TRAFFIC:
      line = "QUIC_CLIENT_TRAFFIC_SECRET_0";
      break;
    case SSL_KEY_SERVER_HANDSHAKE_TRAFFIC:
      line = "QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET";
      break;
    case SSL_KEY_SERVER_APPLICATION_TRAFFIC:
      line = "QUIC_SERVER_TRAFFIC_SECRET_0";
      break;
    default:
      return;
    }
    line += " " + util::format_hex(crandom, 32);
    line += " " + util::format_hex(secret, secretlen);
    keylog_cb(ssl, line.c_str());
  }
}

} // namespace keylog

} // namespace ngtcp2
