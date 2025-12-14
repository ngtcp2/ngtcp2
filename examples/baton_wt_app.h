/*
 * ngtcp2
 *
 * Copyright (c) 2026 ngtcp2 contributors
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
#ifndef BATON_WT_APP_H
#define BATON_WT_APP_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif // defined(HAVE_CONFIG_H)

#include <deque>
#include <unordered_map>
#include <memory>

#include "wt_app.h"
#include "baton.h"
#include "shared.h"

namespace ngtcp2 {
namespace webtransport {
namespace baton {

struct Config {
  bool quiet{};
};

extern Config config;

struct Stream {
  Stream(int64_t stream_id) : stream_id{stream_id} {}

  int64_t stream_id;
  Baton baton;
};

class App : public AppBase {
public:
  App(ngtcp2_conn *conn, nghttp3_conn *httpconn, int64_t session_id, Side side);

  std::expected<void, Error>
  submit_session_request(std::string_view scheme, std::string_view authority,
                         std::string_view path) override;

  std::expected<void, Error>
  accept_session_request(std::string_view path,
                         std::span<const std::string> avail_protos) override;

  std::expected<void, Error> on_data(int64_t stream_id,
                                     std::span<const uint8_t> data) override;

  std::expected<void, Error> on_end_stream(int64_t stream_id) override {
    return {};
  }

  std::expected<void, Error>
  on_datagram(std::span<const uint8_t> data) override {
    return {};
  }

  std::vector<Datagram> pull_datagram() override;

  bool has_pending_bidi_stream() const override { return false; }

  bool has_pending_uni_stream() const override { return false; }

  void on_stream_close(int64_t stream_id, uint64_t app_error_code) override;

  std::expected<void, Error> handle_pending_bidi_stream() override {
    return {};
  }

  std::expected<void, Error> handle_pending_uni_stream() override { return {}; }

  bool finished() const override { return false; }

  void on_proto_negotiated(std::string_view proto) override {}

  std::expected<void, Error> on_session_started() override { return {}; }

private:
  std::expected<void, Error> start_baton_session(uint8_t baton);

  std::expected<void, Error> open_baton_bidi(uint8_t baton);

  std::expected<void, Error> open_baton_uni(uint8_t baton);

  std::expected<void, Error> send_baton(Stream *stream, uint8_t baton);

  ngtcp2_conn *conn_;
  nghttp3_conn *httpconn_;
  int64_t session_id_;
  Side side_;
  std::unordered_map<int64_t, std::unique_ptr<Stream>> streams_;
  std::deque<Datagram> batons_;
  size_t count_{};
};

} // namespace baton
} // namespace webtransport
} // namespace ngtcp2

#endif // BATON_WT_APP_H
