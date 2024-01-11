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

#include <unistd.h>

#include <cassert>
#include <random>
#include <array>

#include "util.h"

using namespace std::literals;

namespace ngtcp2 {

namespace debug {

namespace {
auto randgen = util::make_mt19937();
} // namespace

namespace {
auto *outfile = stderr;
} // namespace

int handshake_completed(ngtcp2_conn *conn, void *user_data) {
  print("QUIC handshake has completed\n");
  return 0;
}

int handshake_confirmed(ngtcp2_conn *conn, void *user_data) {
  print("QUIC handshake has been confirmed\n");
  return 0;
}

bool packet_lost(double prob) {
  auto p = std::uniform_real_distribution<>(0, 1)(randgen);
  return p < prob;
}

void print_crypto_data(ngtcp2_encryption_level encryption_level,
                       const uint8_t *data, size_t datalen) {
  const char *encryption_level_str;
  switch (encryption_level) {
  case NGTCP2_ENCRYPTION_LEVEL_INITIAL:
    encryption_level_str = "Initial";
    break;
  case NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE:
    encryption_level_str = "Handshake";
    break;
  case NGTCP2_ENCRYPTION_LEVEL_1RTT:
    encryption_level_str = "1-RTT";
    break;
  default:
    assert(0);
    abort();
  }
  print("Ordered CRYPTO data in {} crypto level\n", encryption_level_str);
  util::hexdump(outfile, data, datalen);
}

void print_stream_data(int64_t stream_id, const uint8_t *data, size_t datalen) {
  print("Ordered STREAM data stream_id={:#x}\n", stream_id);
  util::hexdump(outfile, data, datalen);
}

void print_secrets(const uint8_t *secret, size_t secretlen, const uint8_t *key,
                   size_t keylen, const uint8_t *iv, size_t ivlen) {
  print("+ secret={}\n"
        "+ key={}\n"
        "+ iv={}\n",
        util::format_hex(secret, secretlen), util::format_hex(key, keylen),
        util::format_hex(iv, ivlen));
}

void print_hp_mask(const uint8_t *mask, size_t masklen, const uint8_t *sample,
                   size_t samplelen) {
  print("mask={} sample={}\n", util::format_hex(mask, masklen),
        util::format_hex(sample, samplelen));
}

void log_printf(void *user_data, const char *fmt, ...) {
  va_list ap;
  std::array<char, 4096> buf;

  va_start(ap, fmt);
  auto n = vsnprintf(buf.data(), buf.size(), fmt, ap);
  va_end(ap);

  if (static_cast<size_t>(n) >= buf.size()) {
    n = buf.size() - 1;
  }

  buf[n++] = '\n';

  while (write(fileno(stderr), buf.data(), n) == -1 && errno == EINTR)
    ;
}

void path_validation(const ngtcp2_path *path,
                     ngtcp2_path_validation_result res) {
  auto local_addr = util::straddr(
      reinterpret_cast<sockaddr *>(path->local.addr), path->local.addrlen);
  auto remote_addr = util::straddr(
      reinterpret_cast<sockaddr *>(path->remote.addr), path->remote.addrlen);

  print("Path validation against path {{local:{}, remote:{}}} {}\n", local_addr,
        remote_addr,
        res == NGTCP2_PATH_VALIDATION_RESULT_SUCCESS ? "succeeded" : "failed");
}

void print_http_begin_request_headers(int64_t stream_id) {
  print("http: stream {:#x} request headers started\n", stream_id);
}

void print_http_begin_response_headers(int64_t stream_id) {
  print("http: stream {:#x} response headers started\n", stream_id);
}

namespace {
void print_http_header(int64_t stream_id, const uint8_t *name, size_t namelen,
                       const uint8_t *value, size_t valuelen, uint8_t flags) {
  print("http: stream {:#x} [{}: {}]{}\n", stream_id,
        std::string_view{reinterpret_cast<const char *>(name), namelen},
        std::string_view{reinterpret_cast<const char *>(value), valuelen},
        (flags & NGHTTP3_NV_FLAG_NEVER_INDEX) ? "(sensitive)" : "");
}
} // namespace

namespace {
void print_http_header(int64_t stream_id, const nghttp3_nv &nv) {
  print_http_header(stream_id, nv.name, nv.namelen, nv.value, nv.valuelen,
                    nv.flags);
}
} // namespace

void print_http_header(int64_t stream_id, const nghttp3_rcbuf *name,
                       const nghttp3_rcbuf *value, uint8_t flags) {
  auto namebuf = nghttp3_rcbuf_get_buf(name);
  auto valuebuf = nghttp3_rcbuf_get_buf(value);
  print_http_header(stream_id, namebuf.base, namebuf.len, valuebuf.base,
                    valuebuf.len, flags);
}

void print_http_end_headers(int64_t stream_id) {
  print("http: stream {:#x} headers ended\n", stream_id);
}

void print_http_data(int64_t stream_id, const uint8_t *data, size_t datalen) {
  print("http: stream {:#x} body {} bytes\n", stream_id, datalen);
  util::hexdump(outfile, data, datalen);
}

void print_http_begin_trailers(int64_t stream_id) {
  print("http: stream {:#x} trailers started\n", stream_id);
}

void print_http_end_trailers(int64_t stream_id) {
  print("http: stream {:#x} trailers ended\n", stream_id);
}

void print_http_request_headers(int64_t stream_id, const nghttp3_nv *nva,
                                size_t nvlen) {
  print("http: stream {:#x} submit request headers\n", stream_id);
  for (size_t i = 0; i < nvlen; ++i) {
    auto &nv = nva[i];
    print_http_header(stream_id, nv);
  }
}

void print_http_response_headers(int64_t stream_id, const nghttp3_nv *nva,
                                 size_t nvlen) {
  print("http: stream {:#x} submit response headers\n", stream_id);
  for (size_t i = 0; i < nvlen; ++i) {
    auto &nv = nva[i];
    print_http_header(stream_id, nv);
  }
}

void print_http_settings(const nghttp3_settings *settings) {
  print("http: remote settings\n"
        "http: SETTINGS_MAX_FIELD_SECTION_SIZE={}\n"
        "http: SETTINGS_QPACK_MAX_TABLE_CAPACITY={}\n"
        "http: SETTINGS_QPACK_BLOCKED_STREAMS={}\n"
        "http: SETTINGS_ENABLE_CONNECT_PROTOCOL={}\n"
        "http: SETTINGS_H3_DATAGRAM={}\n",
        settings->max_field_section_size, settings->qpack_max_dtable_capacity,
        settings->qpack_blocked_streams, settings->enable_connect_protocol,
        settings->h3_datagram);
}

std::string_view secret_title(ngtcp2_encryption_level level) {
  switch (level) {
  case NGTCP2_ENCRYPTION_LEVEL_0RTT:
    return "early_traffic"sv;
  case NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE:
    return "handshake_traffic"sv;
  case NGTCP2_ENCRYPTION_LEVEL_1RTT:
    return "application_traffic"sv;
  default:
    assert(0);
    abort();
  }
}

} // namespace debug

} // namespace ngtcp2
