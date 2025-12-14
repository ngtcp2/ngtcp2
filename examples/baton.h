/*
 * ngtcp2
 *
 * Copyright (c) 2025 ngtcp2 contributors
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
#ifndef BATON_H
#define BATON_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif // defined(HAVE_CONFIG_H)

#include <cassert>
#include <span>
#include <string_view>
#include <tuple>
#include <optional>

#include <nghttp3/nghttp3.h>

namespace ngtcp2 {

inline constexpr size_t max_baton_count = 10;

struct BatonMsg {
  int64_t session_id{};
  int64_t padlen{};
  uint8_t baton{};
};

enum {
  BATON_READ_PADDING_LENGTH_VARINTLEN,
  BATON_READ_PADDING_LENGTH,
  BATON_SKIP_PADDING,
  BATON_READ_BATON,
};

struct Baton {
  struct {
    uint32_t padding_be{};
    uint8_t value{};
  } tx;
  struct {
    int state{BATON_READ_PADDING_LENGTH_VARINTLEN};
    int64_t padlen{};
    int64_t rleft{};
  } rx;
  int64_t session_id{};
  size_t count{};
  uint8_t baton{};

  void set_baton_msg(uint32_t padlen, uint8_t value) {
    nghttp3_put_varint(reinterpret_cast<uint8_t *>(&tx.padding_be),
                       static_cast<int64_t>(padlen));
    tx.value = value;
  }

  std::tuple<int, std::span<const uint8_t>>
  recv_data(std::span<const uint8_t> data) {
    for (; !data.empty();) {
      switch (rx.state) {
      case BATON_READ_PADDING_LENGTH_VARINTLEN: {
        rx.rleft = static_cast<int64_t>(nghttp3_get_varintlen(data.data()));
        if (data.size() >= static_cast<size_t>(rx.rleft)) {
          nghttp3_get_varint(&rx.padlen, data.data());
          data = data.subspan(static_cast<size_t>(rx.rleft));
          rx.state = BATON_SKIP_PADDING;
          rx.rleft = rx.padlen;

          break;
        }

        rx.padlen = *data.data() & ~0xc0;
        --rx.rleft;
        data = data.subspan(1);
        rx.state = BATON_READ_PADDING_LENGTH;

        if (data.empty()) {
          break;
        }

        // Fall through
      }
      case BATON_READ_PADDING_LENGTH: {
        auto len = static_cast<size_t>(
          std::min(rx.rleft, static_cast<int64_t>(data.size())));

        auto p = data.data();

        for (size_t i = 0; i < len; ++i) {
          rx.padlen <<= 8;
          rx.padlen += *p++;
        }

        data = data.subspan(len);
        rx.rleft -= len;

        if (rx.rleft) {
          break;
        }

        rx.state = BATON_SKIP_PADDING;
        rx.rleft = rx.padlen;

        break;
      }
      case BATON_SKIP_PADDING: {
        auto len = static_cast<size_t>(
          std::min(rx.rleft, static_cast<int64_t>(data.size())));

        data = data.subspan(len);
        rx.rleft -= len;

        if (rx.rleft) {
          break;
        }

        rx.state = BATON_READ_BATON;

        break;
      }
      case BATON_READ_BATON: {
        return {*data.data(), data.subspan(1)};
      }
      }
    }

    return {-1, data};
  }
};

struct BatonParams {
  size_t count{};
  uint8_t baton{};
};

std::optional<BatonParams> parse_baton_parameters(const std::string_view &q);

} // namespace ngtcp2

#endif // !defined(BATON_H)
