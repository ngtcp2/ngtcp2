/*
 * ngtcp2
 *
 * Copyright (c) 2017 ngtcp2 contributors
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
#ifndef DEBUG_H
#define DEBUG_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif // HAVE_CONFIG_H

#ifndef __STDC_FORMAT_MACROS
// For travis and PRIu64
#  define __STDC_FORMAT_MACROS
#endif // __STDC_FORMAT_MACROS

#include <cinttypes>
#include <string_view>

#include <ngtcp2/ngtcp2.h>
#include <nghttp3/nghttp3.h>

namespace ngtcp2 {

namespace debug {

int handshake_completed(ngtcp2_conn *conn, void *user_data);

int handshake_confirmed(ngtcp2_conn *conn, void *user_data);

bool packet_lost(double prob);

void print_crypto_data(ngtcp2_encryption_level encryption_level,
                       const uint8_t *data, size_t datalen);

void print_stream_data(int64_t stream_id, const uint8_t *data, size_t datalen);

void print_initial_secret(const uint8_t *data, size_t len);

void print_client_in_secret(const uint8_t *data, size_t len);
void print_server_in_secret(const uint8_t *data, size_t len);

void print_handshake_secret(const uint8_t *data, size_t len);

void print_client_hs_secret(const uint8_t *data, size_t len);
void print_server_hs_secret(const uint8_t *data, size_t len);

void print_client_0rtt_secret(const uint8_t *data, size_t len);

void print_client_1rtt_secret(const uint8_t *data, size_t len);
void print_server_1rtt_secret(const uint8_t *data, size_t len);

void print_client_pp_key(const uint8_t *data, size_t len);
void print_server_pp_key(const uint8_t *data, size_t len);

void print_client_pp_iv(const uint8_t *data, size_t len);
void print_server_pp_iv(const uint8_t *data, size_t len);

void print_client_pp_hp(const uint8_t *data, size_t len);
void print_server_pp_hp(const uint8_t *data, size_t len);

void print_secrets(const uint8_t *secret, size_t secretlen, const uint8_t *key,
                   size_t keylen, const uint8_t *iv, size_t ivlen,
                   const uint8_t *hp, size_t hplen);

void print_secrets(const uint8_t *secret, size_t secretlen, const uint8_t *key,
                   size_t keylen, const uint8_t *iv, size_t ivlen);

void print_hp_mask(const uint8_t *mask, size_t masklen, const uint8_t *sample,
                   size_t samplelen);

void log_printf(void *user_data, const char *fmt, ...);

void path_validation(const ngtcp2_path *path,
                     ngtcp2_path_validation_result res);

void print_http_begin_request_headers(int64_t stream_id);

void print_http_begin_response_headers(int64_t stream_id);

void print_http_header(int64_t stream_id, const nghttp3_rcbuf *name,
                       const nghttp3_rcbuf *value, uint8_t flags);

void print_http_end_headers(int64_t stream_id);

void print_http_data(int64_t stream_id, const uint8_t *data, size_t datalen);

void print_http_begin_trailers(int64_t stream_id);

void print_http_end_trailers(int64_t stream_id);

void print_http_request_headers(int64_t stream_id, const nghttp3_nv *nva,
                                size_t nvlen);

void print_http_response_headers(int64_t stream_id, const nghttp3_nv *nva,
                                 size_t nvlen);

std::string_view secret_title(ngtcp2_encryption_level level);

} // namespace debug

} // namespace ngtcp2

#endif // DEBUG_H
