/*
 * ngtcp2
 *
 * Copyright (c) 2017 ngtcp2 contributors
 * Copyright (c) 2012 nghttp2 contributors
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
#ifndef UTIL_H
#define UTIL_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif // defined(HAVE_CONFIG_H)

#include <sys/socket.h>

#include <cassert>
#include <optional>
#include <string>
#include <random>
#include <unordered_map>
#include <string_view>
#include <span>

#include <ngtcp2/ngtcp2.h>
#include <nghttp3/nghttp3.h>

#include "network.h"
#include "siphash.h"
#include "template.h"

namespace ngtcp2 {

namespace util {

inline nghttp3_nv make_nv(const std::string_view &name,
                          const std::string_view &value, uint8_t flags) {
  return nghttp3_nv{
    reinterpret_cast<uint8_t *>(const_cast<char *>(std::ranges::data(name))),
    reinterpret_cast<uint8_t *>(const_cast<char *>(std::ranges::data(value))),
    name.size(),
    value.size(),
    flags,
  };
}

inline nghttp3_nv make_nv_cc(const std::string_view &name,
                             const std::string_view &value) {
  return make_nv(name, value, NGHTTP3_NV_FLAG_NONE);
}

inline nghttp3_nv make_nv_nc(const std::string_view &name,
                             const std::string_view &value) {
  return make_nv(name, value, NGHTTP3_NV_FLAG_NO_COPY_NAME);
}

inline nghttp3_nv make_nv_nn(const std::string_view &name,
                             const std::string_view &value) {
  return make_nv(name, value,
                 NGHTTP3_NV_FLAG_NO_COPY_NAME | NGHTTP3_NV_FLAG_NO_COPY_VALUE);
}

std::string format_hex(uint8_t c);

std::string format_hex(std::span<const uint8_t> s);

std::string format_hex(const std::string_view &s);

std::string decode_hex(const std::string_view &s);

// format_durationf formats |ns| in human readable manner.  |ns| must
// be nanoseconds resolution.  This function uses the largest unit so
// that the integral part is strictly more than zero, and the
// precision is at most 2 digits.  For example, 1234 is formatted as
// "1.23us".  The largest unit is seconds.
std::string format_durationf(uint64_t ns);

std::mt19937 make_mt19937();

ngtcp2_tstamp timestamp();

bool numeric_host(const char *hostname);

bool numeric_host(const char *hostname, int family);

// hexdump dumps |data| of length |datalen| in the format similar to
// hexdump(1) with -C option.  This function returns 0 if it succeeds,
// or -1.
int hexdump(FILE *out, const void *data, size_t datalen);

static constexpr uint8_t lowcase_tbl[] = {
  0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,
  15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,
  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,
  45,  46,  47,  48,  49,  50,  51,  52,  53,  54,  55,  56,  57,  58,  59,
  60,  61,  62,  63,  64,  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
  'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
  'z', 91,  92,  93,  94,  95,  96,  97,  98,  99,  100, 101, 102, 103, 104,
  105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
  120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134,
  135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149,
  150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164,
  165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179,
  180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194,
  195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209,
  210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224,
  225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
  240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254,
  255,
};

constexpr char lowcase(char c) noexcept {
  return lowcase_tbl[static_cast<uint8_t>(c)];
}

struct CaseCmp {
  constexpr bool operator()(char lhs, char rhs) const noexcept {
    return lowcase(lhs) == lowcase(rhs);
  }
};

// istarts_with returns true if |s| starts with |prefix|.  Comparison
// is performed in case-insensitive manner.
constexpr bool istarts_with(const std::string_view &s,
                            const std::string_view &prefix) {
  return s.size() >= prefix.size() &&
         std::ranges::equal(s.substr(0, prefix.size()), prefix, CaseCmp());
}

// make_cid_key returns the key for |cid|.
std::string_view make_cid_key(const ngtcp2_cid *cid);
ngtcp2_cid make_cid_key(std::span<const uint8_t> cid);

// straddr stringifies |sa| of length |salen| in a format "[IP]:PORT".
std::string straddr(const sockaddr *sa, socklen_t salen);

// port returns port from |su|.
uint16_t port(const sockaddr_union *su);

// prohibited_port returns true if |port| is prohibited as a client
// port.
bool prohibited_port(uint16_t port);

// strccalgo stringifies |cc_algo|.
std::string_view strccalgo(ngtcp2_cc_algo cc_algo);

// read_mime_types reads "MIME media types and the extensions" file
// denoted by |filename| and returns the mapping of extension to MIME
// media type.
std::optional<std::unordered_map<std::string, std::string>>
read_mime_types(const std::string_view &filename);

// format_uint converts |n| into string.
template <typename T> std::string format_uint(T n) {
  if (n == 0) {
    return "0";
  }
  size_t nlen = 0;
  for (auto t = n; t; t /= 10, ++nlen)
    ;
  std::string res(nlen, '\0');
  for (; n; n /= 10) {
    res[--nlen] = (n % 10) + '0';
  }
  return res;
}

// format_uint_iec converts |n| into string with the IEC unit (either
// "G", "M", or "K").  It chooses the largest unit which does not drop
// precision.
template <typename T> std::string format_uint_iec(T n) {
  if (n >= (1 << 30) && (n & ((1 << 30) - 1)) == 0) {
    return format_uint(n / (1 << 30)) + 'G';
  }
  if (n >= (1 << 20) && (n & ((1 << 20) - 1)) == 0) {
    return format_uint(n / (1 << 20)) + 'M';
  }
  if (n >= (1 << 10) && (n & ((1 << 10) - 1)) == 0) {
    return format_uint(n / (1 << 10)) + 'K';
  }
  return format_uint(n);
}

// format_duration converts |n| into string with the unit in either
// "h" (hours), "m" (minutes), "s" (seconds), "ms" (milliseconds),
// "us" (microseconds) or "ns" (nanoseconds).  It chooses the largest
// unit which does not drop precision.  |n| is in nanosecond
// resolution.
std::string format_duration(ngtcp2_duration n);

// parse_uint parses |s| as 64-bit unsigned integer.  If it cannot
// parse |s|, the return value does not contain a value.
std::optional<uint64_t> parse_uint(const std::string_view &s);

// parse_uint_iec parses |s| as 64-bit unsigned integer.  It accepts
// IEC unit letter (either "G", "M", or "K") in |s|.  If it cannot
// parse |s|, the return value does not contain a value.
std::optional<uint64_t> parse_uint_iec(const std::string_view &s);

// parse_duration parses |s| as 64-bit unsigned integer.  It accepts a
// unit (either "h", "m", "s", "ms", "us", or "ns") in |s|.  If no
// unit is present, the unit "s" is assumed.  If it cannot parse |s|,
// the return value does not contain a value.
std::optional<uint64_t> parse_duration(const std::string_view &s);

// generate_secure_random generates a cryptographically secure pseudo
// random data of |data|.
int generate_secure_random(std::span<uint8_t> data);

// generate_secret generates secret and writes it to |secret|.
// Currently, |secret| must be 32 bytes long.
int generate_secret(std::span<uint8_t> secret);

// normalize_path removes ".." by consuming a previous path component.
// It also removes ".".  It assumes that |path| starts with "/".  If
// it cannot consume a previous path component, it just removes "..".
std::string normalize_path(const std::string_view &path);

constexpr bool is_digit(const char c) { return '0' <= c && c <= '9'; }

constexpr bool is_hex_digit(const char c) {
  return is_digit(c) || ('A' <= c && c <= 'F') || ('a' <= c && c <= 'f');
}

// Returns integer corresponding to hex notation |c|.  If
// is_hex_digit(c) is false, it returns 256.
constexpr uint32_t hex_to_uint(char c) {
  if (c <= '9') {
    return c - '0';
  }
  if (c <= 'Z') {
    return c - 'A' + 10;
  }
  if (c <= 'z') {
    return c - 'a' + 10;
  }
  return 256;
}

std::string percent_decode(const std::string_view &s);

int make_socket_nonblocking(int fd);

int create_nonblock_socket(int domain, int type, int protocol);

std::optional<std::string> read_token(const std::string_view &filename);
int write_token(const std::string_view &filename,
                std::span<const uint8_t> token);

std::optional<std::string>
read_transport_params(const std::string_view &filename);
int write_transport_params(const std::string_view &filename,
                           std::span<const uint8_t> data);

const char *crypto_default_ciphers();

const char *crypto_default_groups();

// split_str parses delimited strings in |s| and returns substrings
// delimited by |delim|.  The any white spaces around substring are
// treated as a part of substring.
std::vector<std::string_view> split_str(const std::string_view &s,
                                        char delim = ',');

// parse_version parses |s| to get 4 byte QUIC version.  |s| must be a
// hex string and must start with "0x" (.e.g, 0x00000001).
std::optional<uint32_t> parse_version(const std::string_view &s);

} // namespace util

std::ostream &operator<<(std::ostream &os, const ngtcp2_cid &cid);

} // namespace ngtcp2

namespace std {
template <> struct hash<ngtcp2_cid> {
  hash() {
    assert(0 == ngtcp2::util::generate_secure_random(
                  as_writable_uint8_span(std::span{key})));
  }

  std::size_t operator()(const ngtcp2_cid &cid) const noexcept {
    return static_cast<size_t>(siphash24(key, {cid.data, cid.datalen}));
  }

  std::array<uint64_t, 2> key;
};
} // namespace std

inline bool operator==(const ngtcp2_cid &lhs, const ngtcp2_cid &rhs) {
  return ngtcp2_cid_eq(&lhs, &rhs);
}

#endif // !defined(UTIL_H)
