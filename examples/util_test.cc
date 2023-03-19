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
#include "util_test.h"

#include <limits>

#include <CUnit/CUnit.h>

#include "util.h"

namespace ngtcp2 {

namespace util {
std::optional<std::string> read_pem(const std::string_view &filename,
                                    const std::string_view &name,
                                    const std::string_view &type) {
  return {};
}
} // namespace util

namespace util {
int write_pem(const std::string_view &filename, const std::string_view &name,
              const std::string_view &type, const uint8_t *data,
              size_t datalen) {
  return -1;
}
} // namespace util

void test_util_format_durationf() {
  CU_ASSERT("0ns" == util::format_durationf(0));
  CU_ASSERT("999ns" == util::format_durationf(999));
  CU_ASSERT("1.00us" == util::format_durationf(1000));
  CU_ASSERT("1.00us" == util::format_durationf(1004));
  CU_ASSERT("1.00us" == util::format_durationf(1005));
  CU_ASSERT("1.02us" == util::format_durationf(1015));
  CU_ASSERT("2.00us" == util::format_durationf(1999));
  CU_ASSERT("1.00ms" == util::format_durationf(999999));
  CU_ASSERT("3.50ms" == util::format_durationf(3500111));
  CU_ASSERT("9999.99s" == util::format_durationf(9999990000000llu));
}

void test_util_format_uint() {
  CU_ASSERT("0" == util::format_uint(0));
  CU_ASSERT("18446744073709551615" ==
            util::format_uint(18446744073709551615ull));
}

void test_util_format_uint_iec() {
  CU_ASSERT("0" == util::format_uint_iec(0));
  CU_ASSERT("1023" == util::format_uint_iec((1 << 10) - 1));
  CU_ASSERT("1K" == util::format_uint_iec(1 << 10));
  CU_ASSERT("1M" == util::format_uint_iec(1 << 20));
  CU_ASSERT("1G" == util::format_uint_iec(1 << 30));
  CU_ASSERT("18446744073709551615" ==
            util::format_uint_iec(std::numeric_limits<uint64_t>::max()));
  CU_ASSERT("1025K" == util::format_uint_iec((1 << 20) + (1 << 10)));
}

void test_util_format_duration() {
  CU_ASSERT("0ns" == util::format_duration(0));
  CU_ASSERT("999ns" == util::format_duration(999));
  CU_ASSERT("1us" == util::format_duration(1000));
  CU_ASSERT("1ms" == util::format_duration(1000000));
  CU_ASSERT("1s" == util::format_duration(1000000000));
  CU_ASSERT("1m" == util::format_duration(60000000000ull));
  CU_ASSERT("1h" == util::format_duration(3600000000000ull));
  CU_ASSERT("18446744073709551615ns" ==
            util::format_duration(std::numeric_limits<uint64_t>::max()));
  CU_ASSERT("61s" == util::format_duration(61000000000ull));
}

void test_util_parse_uint() {
  {
    auto res = util::parse_uint("0");
    CU_ASSERT(res.has_value());
    CU_ASSERT(0 == *res);
  }
  {
    auto res = util::parse_uint("1");
    CU_ASSERT(res.has_value());
    CU_ASSERT(1 == *res);
  }
  {
    auto res = util::parse_uint("18446744073709551615");
    CU_ASSERT(res.has_value());
    CU_ASSERT(18446744073709551615ull == *res);
  }
  {
    auto res = util::parse_uint("18446744073709551616");
    CU_ASSERT(!res.has_value());
  }
  {
    auto res = util::parse_uint("a");
    CU_ASSERT(!res.has_value());
  }
  {
    auto res = util::parse_uint("1a");
    CU_ASSERT(!res.has_value());
  }
}

void test_util_parse_uint_iec() {
  {
    auto res = util::parse_uint_iec("0");
    CU_ASSERT(res.has_value());
    CU_ASSERT(0 == *res);
  }
  {
    auto res = util::parse_uint_iec("1023");
    CU_ASSERT(res.has_value());
    CU_ASSERT(1023 == *res);
  }
  {
    auto res = util::parse_uint_iec("1K");
    CU_ASSERT(res.has_value());
    CU_ASSERT(1 << 10 == *res);
  }
  {
    auto res = util::parse_uint_iec("1M");
    CU_ASSERT(res.has_value());
    CU_ASSERT(1 << 20 == *res);
  }
  {
    auto res = util::parse_uint_iec("1G");
    CU_ASSERT(res.has_value());
    CU_ASSERT(1 << 30 == *res);
  }
  {
    auto res = util::parse_uint_iec("11G");
    CU_ASSERT(res.has_value());
    CU_ASSERT((1ull << 30) * 11 == *res);
  }
  {
    auto res = util::parse_uint_iec("18446744073709551616");
    CU_ASSERT(!res.has_value());
  }
  {
    auto res = util::parse_uint_iec("1x");
    CU_ASSERT(!res.has_value());
  }
  {
    auto res = util::parse_uint_iec("1Gx");
    CU_ASSERT(!res.has_value());
  }
}

void test_util_parse_duration() {
  {
    auto res = util::parse_duration("0");
    CU_ASSERT(res.has_value());
    CU_ASSERT(0 == *res);
  }
  {
    auto res = util::parse_duration("1");
    CU_ASSERT(res.has_value());
    CU_ASSERT(NGTCP2_SECONDS == *res);
  }
  {
    auto res = util::parse_duration("0ns");
    CU_ASSERT(res.has_value());
    CU_ASSERT(0 == *res);
  }
  {
    auto res = util::parse_duration("1ns");
    CU_ASSERT(res.has_value());
    CU_ASSERT(1 == *res);
  }
  {
    auto res = util::parse_duration("1us");
    CU_ASSERT(res.has_value());
    CU_ASSERT(NGTCP2_MICROSECONDS == *res);
  }
  {
    auto res = util::parse_duration("1ms");
    CU_ASSERT(res.has_value());
    CU_ASSERT(NGTCP2_MILLISECONDS == *res);
  }
  {
    auto res = util::parse_duration("1s");
    CU_ASSERT(res.has_value());
    CU_ASSERT(NGTCP2_SECONDS == *res);
  }
  {
    auto res = util::parse_duration("1m");
    CU_ASSERT(res.has_value());
    CU_ASSERT(60 * NGTCP2_SECONDS == *res);
  }
  {
    auto res = util::parse_duration("1h");
    CU_ASSERT(res.has_value());
    CU_ASSERT(3600 * NGTCP2_SECONDS == *res);
  }
  {
    auto res = util::parse_duration("2h");
    CU_ASSERT(res.has_value());
    CU_ASSERT(2 * 3600 * NGTCP2_SECONDS == *res);
  }
  {
    auto res = util::parse_duration("18446744073709551616");
    CU_ASSERT(!res.has_value());
  }
  {
    auto res = util::parse_duration("1x");
    CU_ASSERT(!res.has_value());
  }
  {
    auto res = util::parse_duration("1mx");
    CU_ASSERT(!res.has_value());
  }
  {
    auto res = util::parse_duration("1mxy");
    CU_ASSERT(!res.has_value());
  }
}

void test_util_normalize_path() {
  CU_ASSERT("/" == util::normalize_path("/"));
  CU_ASSERT("/" == util::normalize_path("//"));
  CU_ASSERT("/foo" == util::normalize_path("/foo"));
  CU_ASSERT("/foo/bar/" == util::normalize_path("/foo/bar/"));
  CU_ASSERT("/foo/bar/" == util::normalize_path("/foo/abc/../bar/"));
  CU_ASSERT("/foo/bar/" == util::normalize_path("/../foo/abc/../bar/"));
  CU_ASSERT("/foo/bar/" ==
            util::normalize_path("/./foo/././abc///.././bar/./"));
  CU_ASSERT("/foo/" == util::normalize_path("/foo/."));
  CU_ASSERT("/foo/bar" == util::normalize_path("/foo/./bar"));
  CU_ASSERT("/bar" == util::normalize_path("/foo/./../bar"));
  CU_ASSERT("/bar" == util::normalize_path("/../../bar"));
}

} // namespace ngtcp2
