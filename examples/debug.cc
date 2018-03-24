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

#include <random>

#include "util.h"

namespace ngtcp2 {

namespace debug {

namespace {
auto randgen = util::make_mt19937();
} // namespace

namespace {
std::chrono::steady_clock::time_point ts_base;
} // namespace

void reset_timestamp() { ts_base = std::chrono::steady_clock::now(); }

std::chrono::nanoseconds timestamp() {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::steady_clock::now() - ts_base);
}

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

void print_stream_data(uint64_t stream_id, const uint8_t *data,
                       size_t datalen) {
  fprintf(outfile, "Ordered STREAM data stream_id=0x%" PRIx64 "\n", stream_id);
  util::hexdump(outfile, data, datalen);
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

} // namespace debug

} // namespace ngtcp2
