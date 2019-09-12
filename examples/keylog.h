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
#ifndef KEYLOG_H
#define KEYLOG_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif // HAVE_CONFIG_H

#include <ngtcp2/ngtcp2.h>

#include <openssl/ssl.h>

namespace ngtcp2 {

namespace keylog {

constexpr char QUIC_CLIENT_EARLY_TRAFFIC_SECRET[] =
    "QUIC_CLIENT_EARLY_TRAFFIC_SECRET";
constexpr char QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET[] =
    "QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET";
constexpr char QUIC_CLIENT_TRAFFIC_SECRET_0[] = "QUIC_CLIENT_TRAFFIC_SECRET_0";
constexpr char QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET[] =
    "QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET";
constexpr char QUIC_SERVER_TRAFFIC_SECRET_0[] = "QUIC_SERVER_TRAFFIC_SECRET_0";

void log_secret(SSL *ssl, const char *name, const unsigned char *secret,
                size_t secretlen);

} // namespace keylog

} // namespace ngtcp2

#endif // KEYLOG_H
