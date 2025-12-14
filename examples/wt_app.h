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
#ifndef WT_APP_H
#define WT_APP_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif // defined(HAVE_CONFIG_H)

#include <ngtcp2/ngtcp2.h>

#include <string_view>
#include <expected>
#include <vector>
#include <span>

#include "shared.h"

namespace ngtcp2 {
namespace webtransport {

enum class Side {
  CLIENT,
  SERVER,
};

struct Datagram {
  int64_t session_id;
  std::vector<uint8_t> data;
};

class AppBase {
public:
  virtual ~AppBase() {}

  virtual std::expected<void, Error>
  submit_session_request(std::string_view scheme, std::string_view authority,
                         std::string_view path) = 0;

  virtual std::expected<void, Error>
  accept_session_request(std::string_view path,
                         std::span<const std::string> avail_protos) = 0;

  virtual std::expected<void, Error> on_data(int64_t stream_id,
                                             std::span<const uint8_t> data) = 0;

  virtual std::expected<void, Error> on_end_stream(int64_t stream_id) = 0;

  virtual std::expected<void, Error>
  on_datagram(std::span<const uint8_t> data) = 0;

  virtual void on_stream_close(int64_t stream_id, uint64_t app_error_code) = 0;

  virtual std::vector<Datagram> pull_datagram() = 0;

  virtual bool has_pending_bidi_stream() const = 0;

  virtual bool has_pending_uni_stream() const = 0;

  virtual std::expected<void, Error> handle_pending_bidi_stream() = 0;

  virtual std::expected<void, Error> handle_pending_uni_stream() = 0;

  virtual bool finished() const = 0;

  virtual void on_proto_negotiated(std::string_view proto) = 0;

  virtual std::expected<void, Error> on_session_started() = 0;
};

} // namespace webtransport
} // namespace ngtcp2

#endif // WT_APP_H
