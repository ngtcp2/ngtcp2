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
#include "baton.h"
#include "util.h"

using namespace std::literals;

namespace ngtcp2 {

std::optional<BatonParams> parse_baton_parameters(const std::string_view &q) {
  static constexpr auto version_prefix = "version="sv;
  static constexpr auto baton_prefix = "baton="sv;
  static constexpr auto count_prefix = "count="sv;

  BatonParams bp{
    .count = 1,
    .baton = 1,
  };

  for (auto p = std::ranges::begin(q); p != std::ranges::end(q);) {
    if (util::istarts_with(std::string_view{p, std::ranges::end(q)},
                           version_prefix)) {
      auto start = p + version_prefix.size();
      auto end = std::ranges::find(start, std::ranges::end(q), '&');

      auto r = util::parse_uint({start, end});
      if (!r || *r != 0) {
        return {};
      }

      if (end == std::ranges::end(q)) {
        break;
      }

      p = end + 1;

      continue;
    }

    if (util::istarts_with(std::string_view{p, std::ranges::end(q)},
                           baton_prefix)) {
      auto start = p + baton_prefix.size();
      auto end = std::ranges::find(start, std::ranges::end(q), '&');

      auto r = util::parse_uint({start, end});
      if (!r || !*r || *r > 255) {
        return {};
      }

      bp.baton = static_cast<uint8_t>(*r);

      if (end == std::ranges::end(q)) {
        break;
      }

      p = end + 1;

      continue;
    }

    if (util::istarts_with(std::string_view{p, std::ranges::end(q)},
                           count_prefix)) {
      auto start = p + count_prefix.size();
      auto end = std::ranges::find(start, std::ranges::end(q), '&');

      auto r = util::parse_uint({start, end});
      if (!r || !*r || *r > max_baton_count) {
        return {};
      }

      bp.count = *r;

      if (end == std::ranges::end(q)) {
        break;
      }

      p = end + 1;

      continue;
    }

    p = std::ranges::find(p, std::ranges::end(q), '&');

    if (p == std::ranges::end(q)) {
      break;
    }

    ++p;
  }

  return bp;
}

} // namespace ngtcp2
