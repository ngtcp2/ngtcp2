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
#include "debug.h"

#include <cassert>
#include <random>
#include <iostream>

#include "util.h"

namespace ngtcp2 {

namespace debug {

namespace {
auto randgen = util::make_mt19937();
} // namespace

namespace {
auto color_output = false;
} // namespace

void set_color_output(bool f) { color_output = f; }

namespace {
auto *outfile = stderr;
} // namespace

int handshake_completed(ngtcp2_conn *conn, void *user_data) {
  fprintf(outfile, "QUIC handshake has completed\n");
  return 0;
}

bool packet_lost(double prob) {
  auto p = std::uniform_real_distribution<>(0, 1)(randgen);
  return p < prob;
}

void print_crypto_data(ngtcp2_crypto_level crypto_level, const uint8_t *data,
                       size_t datalen) {
  const char *crypto_level_str;
  switch (crypto_level) {
  case NGTCP2_CRYPTO_LEVEL_INITIAL:
    crypto_level_str = "Initial";
    break;
  case NGTCP2_CRYPTO_LEVEL_HANDSHAKE:
    crypto_level_str = "Handshake";
    break;
  case NGTCP2_CRYPTO_LEVEL_APP:
    crypto_level_str = "Application";
    break;
  default:
    assert(0);
  }
  fprintf(outfile, "Ordered CRYPTO data in %s crypto level\n",
          crypto_level_str);
  util::hexdump(outfile, data, datalen);
}

void print_stream_data(int64_t stream_id, const uint8_t *data, size_t datalen) {
  fprintf(outfile, "Ordered STREAM data stream_id=0x%" PRIx64 "\n", stream_id);
  util::hexdump(outfile, data, datalen);
}

void print_initial_secret(const uint8_t *data, size_t len) {
  fprintf(outfile, "initial_secret=%s\n", util::format_hex(data, len).c_str());
}

void print_client_in_secret(const uint8_t *data, size_t len) {
  fprintf(outfile, "client_in_secret=%s\n",
          util::format_hex(data, len).c_str());
}

void print_server_in_secret(const uint8_t *data, size_t len) {
  fprintf(outfile, "server_in_secret=%s\n",
          util::format_hex(data, len).c_str());
}

void print_handshake_secret(const uint8_t *data, size_t len) {
  fprintf(outfile, "handshake_secret=%s\n",
          util::format_hex(data, len).c_str());
}

void print_client_hs_secret(const uint8_t *data, size_t len) {
  fprintf(outfile, "client_hs_secret=%s\n",
          util::format_hex(data, len).c_str());
}

void print_server_hs_secret(const uint8_t *data, size_t len) {
  fprintf(outfile, "server_hs_secret=%s\n",
          util::format_hex(data, len).c_str());
}

void print_client_0rtt_secret(const uint8_t *data, size_t len) {
  fprintf(outfile, "client_0rtt_secret=%s\n",
          util::format_hex(data, len).c_str());
}

void print_client_1rtt_secret(const uint8_t *data, size_t len) {
  fprintf(outfile, "client_1rtt_secret=%s\n",
          util::format_hex(data, len).c_str());
}

void print_server_1rtt_secret(const uint8_t *data, size_t len) {
  fprintf(outfile, "server_1rtt_secret=%s\n",
          util::format_hex(data, len).c_str());
}

void print_client_pp_key(const uint8_t *data, size_t len) {
  fprintf(outfile, "+ client_pp_key=%s\n", util::format_hex(data, len).c_str());
}

void print_server_pp_key(const uint8_t *data, size_t len) {
  fprintf(outfile, "+ server_pp_key=%s\n", util::format_hex(data, len).c_str());
}

void print_client_pp_iv(const uint8_t *data, size_t len) {
  fprintf(outfile, "+ client_pp_iv=%s\n", util::format_hex(data, len).c_str());
}

void print_server_pp_iv(const uint8_t *data, size_t len) {
  fprintf(outfile, "+ server_pp_iv=%s\n", util::format_hex(data, len).c_str());
}

void print_client_pp_hp(const uint8_t *data, size_t len) {
  fprintf(outfile, "+ client_pp_hp=%s\n", util::format_hex(data, len).c_str());
}

void print_server_pp_hp(const uint8_t *data, size_t len) {
  fprintf(outfile, "+ server_pp_hp=%s\n", util::format_hex(data, len).c_str());
}

void print_secrets(const uint8_t *secret, size_t secretlen, const uint8_t *key,
                   size_t keylen, const uint8_t *iv, size_t ivlen,
                   const uint8_t *hp, size_t hplen) {
  std::cerr << "+ secret=" << util::format_hex(secret, secretlen) << "\n"
            << "+ key=" << util::format_hex(key, keylen) << "\n"
            << "+ iv=" << util::format_hex(iv, ivlen) << "\n"
            << "+ hp=" << util::format_hex(hp, hplen) << std::endl;
}

void print_secrets(const uint8_t *secret, size_t secretlen, const uint8_t *key,
                   size_t keylen, const uint8_t *iv, size_t ivlen) {
  std::cerr << "+ secret=" << util::format_hex(secret, secretlen) << "\n"
            << "+ key=" << util::format_hex(key, keylen) << "\n"
            << "+ iv=" << util::format_hex(iv, ivlen) << std::endl;
}

void print_hp_mask(const uint8_t *mask, size_t masklen, const uint8_t *sample,
                   size_t samplelen) {
  fprintf(outfile, "mask=%s sample=%s\n",
          util::format_hex(mask, masklen).c_str(),
          util::format_hex(sample, samplelen).c_str());
}

void log_printf(void *user_data, const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);

  fprintf(stderr, "\n");
}

void path_validation(const ngtcp2_path *path,
                     ngtcp2_path_validation_result res) {
  auto local_addr = util::straddr(
      reinterpret_cast<sockaddr *>(path->local.addr), path->local.addrlen);
  auto remote_addr = util::straddr(
      reinterpret_cast<sockaddr *>(path->remote.addr), path->remote.addrlen);

  std::cerr << "Path validation against path {local:" << local_addr
            << ", remote:" << remote_addr << "} "
            << (res == NGTCP2_PATH_VALIDATION_RESULT_SUCCESS ? "succeeded"
                                                             : "failed")
            << std::endl;
}

void print_http_begin_request_headers(int64_t stream_id) {
  fprintf(outfile, "http: stream 0x%" PRIx64 " request headers started\n",
          stream_id);
}

void print_http_begin_response_headers(int64_t stream_id) {
  fprintf(outfile, "http: stream 0x%" PRIx64 " response headers started\n",
          stream_id);
}

namespace {
void print_header(const uint8_t *name, const uint8_t *value, uint8_t flags) {
  fprintf(outfile, "[%s: %s]%s\n", name, value,
          (flags & NGHTTP3_NV_FLAG_NEVER_INDEX) ? "(sensitive)" : "");
}
} // namespace

namespace {
void print_header(const nghttp3_rcbuf *name, const nghttp3_rcbuf *value,
                  uint8_t flags) {
  print_header(nghttp3_rcbuf_get_buf(name).base,
               nghttp3_rcbuf_get_buf(value).base, flags);
}
} // namespace

namespace {
void print_header(const nghttp3_nv &nv) {
  print_header(nv.name, nv.value, nv.flags);
}
} // namespace

void print_http_header(int64_t stream_id, const nghttp3_rcbuf *name,
                       const nghttp3_rcbuf *value, uint8_t flags) {
  fprintf(outfile, "http: stream 0x%" PRIx64 " ", stream_id);
  print_header(name, value, flags);
}

void print_http_end_headers(int64_t stream_id) {
  fprintf(outfile, "http: stream 0x%" PRIx64 " headers ended\n", stream_id);
}

void print_http_data(int64_t stream_id, const uint8_t *data, size_t datalen) {
  fprintf(outfile, "http: stream 0x%" PRIx64 " body %zu bytes\n", stream_id,
          datalen);
  util::hexdump(outfile, data, datalen);
}

void print_http_begin_trailers(int64_t stream_id) {
  fprintf(outfile, "http: stream 0x%" PRIx64 " trailers started\n", stream_id);
}

void print_http_end_trailers(int64_t stream_id) {
  fprintf(outfile, "http: stream 0x%" PRIx64 " trailers ended\n", stream_id);
}

void print_http_begin_push_promise(int64_t stream_id, int64_t push_id) {
  fprintf(outfile, "http: stream 0x%" PRIx64 " push 0x%" PRIx64 " started\n",
          stream_id, push_id);
}

void print_http_push_promise(int64_t stream_id, int64_t push_id,
                             const nghttp3_rcbuf *name,
                             const nghttp3_rcbuf *value, uint8_t flags) {
  fprintf(outfile, "http: stream 0x%" PRIx64 " push 0x%" PRIx64 " ", stream_id,
          push_id);
  print_header(name, value, flags);
}

void print_http_end_push_promise(int64_t stream_id, int64_t push_id) {
  fprintf(outfile, "http: stream 0x%" PRIx64 " push 0x%" PRIx64 " ended\n",
          stream_id, push_id);
}

void cancel_push(int64_t push_id, int64_t stream_id) {
  fprintf(outfile,
          "http: push 0x%" PRIx64 " (stream 0x%" PRIx64
          ") has been cancelled by remote endpoint\n",
          push_id, stream_id);
}

void push_stream(int64_t push_id, int64_t stream_id) {
  fprintf(outfile,
          "http: push 0x%" PRIx64 " promise fulfilled stream 0x%" PRIx64 "\n",
          push_id, stream_id);
}

void print_http_request_headers(int64_t stream_id, const nghttp3_nv *nva,
                                size_t nvlen) {
  fprintf(outfile, "http: stream 0x%" PRIx64 " submit request headers\n",
          stream_id);
  for (size_t i = 0; i < nvlen; ++i) {
    auto &nv = nva[i];
    print_header(nv);
  }
}

void print_http_response_headers(int64_t stream_id, const nghttp3_nv *nva,
                                 size_t nvlen) {
  fprintf(outfile, "http: stream 0x%" PRIx64 " submit response headers\n",
          stream_id);
  for (size_t i = 0; i < nvlen; ++i) {
    auto &nv = nva[i];
    print_header(nv);
  }
}

void print_http_push_promise(int64_t stream_id, int64_t push_id,
                             const nghttp3_nv *nva, size_t nvlen) {
  fprintf(outfile, "http: stream 0x%" PRIx64 " submit push 0x%" PRIx64 "\n",
          stream_id, push_id);
  for (size_t i = 0; i < nvlen; ++i) {
    auto &nv = nva[i];
    print_header(nv);
  }
}

} // namespace debug

} // namespace ngtcp2
