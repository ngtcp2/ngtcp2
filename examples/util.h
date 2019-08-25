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
#endif // HAVE_CONFIG_H

#include <sys/socket.h>

#include <string>
#include <random>
#include <map>

#include <ngtcp2/ngtcp2.h>
#include <nghttp3/nghttp3.h>

#include <openssl/ssl.h>

#include <ev.h>

namespace ngtcp2 {

namespace util {

template <typename T, size_t N1, size_t N2>
constexpr nghttp3_nv make_nv(const T (&name)[N1], const T (&value)[N2]) {
  return nghttp3_nv{(uint8_t *)name, (uint8_t *)value, N1 - 1, N2 - 1,
                    NGHTTP3_NV_FLAG_NONE};
}

template <typename T, size_t N, typename S>
constexpr nghttp3_nv make_nv(const T (&name)[N], const S &value) {
  return nghttp3_nv{(uint8_t *)name, (uint8_t *)value.data(), N - 1,
                    value.size(), NGHTTP3_NV_FLAG_NONE};
}

template <typename S1, typename S2>
constexpr nghttp3_nv make_nv(const S1 &name, const S2 &value) {
  return nghttp3_nv{(uint8_t *)name.data(), (uint8_t *)value.data(),
                    name.size(), value.size(), NGHTTP3_NV_FLAG_NONE};
}

std::string format_hex(uint8_t c);

std::string format_hex(const uint8_t *s, size_t len);

std::string format_hex(const std::string &s);

template <size_t N> std::string format_hex(const uint8_t (&s)[N]) {
  return format_hex(s, N);
}

std::string decode_hex(const std::string &s);

// format_duration formats |ns| in human readable manner.  |ns| must
// be nanoseconds resolution.  This function uses the largest unit so
// that the integral part is strictly more than zero, and the
// precision is at most 2 digits.  For example, 1234 is formatted as
// "1.23us".  The largest unit is seconds.
std::string format_duration(uint64_t ns);

std::mt19937 make_mt19937();

ngtcp2_tstamp timestamp(struct ev_loop *loop);

bool numeric_host(const char *hostname);

bool numeric_host(const char *hostname, int family);

// Dumps |src| of length |len| in the format similar to `hexdump -C`.
void hexdump(FILE *out, const uint8_t *src, size_t len);

inline char lowcase(char c) {
  constexpr static unsigned char tbl[] = {
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
  return tbl[static_cast<unsigned char>(c)];
}

struct CaseCmp {
  bool operator()(char lhs, char rhs) const {
    return lowcase(lhs) == lowcase(rhs);
  }
};

template <typename InputIterator1, typename InputIterator2>
bool istarts_with(InputIterator1 first1, InputIterator1 last1,
                  InputIterator2 first2, InputIterator2 last2) {
  if (last1 - first1 < last2 - first2) {
    return false;
  }
  return std::equal(first2, last2, first1, CaseCmp());
}

template <typename S, typename T> bool istarts_with(const S &a, const T &b) {
  return istarts_with(a.begin(), a.end(), b.begin(), b.end());
}

template <typename T, typename CharT, size_t N>
bool istarts_with_l(const T &a, const CharT (&b)[N]) {
  return istarts_with(a.begin(), a.end(), b, b + N - 1);
}

// make_cid_key returns the key for |cid|.
std::string make_cid_key(const ngtcp2_cid *cid);
std::string make_cid_key(const uint8_t *cid, size_t cidlen);

// straddr stringifies |sa| of length |salen| in a format "[IP]:PORT".
std::string straddr(const sockaddr *sa, socklen_t salen);

template <typename T, size_t N>
bool streq_l(const T (&a)[N], const nghttp3_vec &b) {
  return N - 1 == b.len && memcmp(a, b.base, N - 1) == 0;
}

namespace {
constexpr char B64_CHARS[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
};
} // namespace

template <typename InputIt> std::string b64encode(InputIt first, InputIt last) {
  std::string res;
  size_t len = last - first;
  if (len == 0) {
    return res;
  }
  size_t r = len % 3;
  res.resize((len + 2) / 3 * 4);
  auto j = last - r;
  auto p = std::begin(res);
  while (first != j) {
    uint32_t n = static_cast<uint8_t>(*first++) << 16;
    n += static_cast<uint8_t>(*first++) << 8;
    n += static_cast<uint8_t>(*first++);
    *p++ = B64_CHARS[n >> 18];
    *p++ = B64_CHARS[(n >> 12) & 0x3fu];
    *p++ = B64_CHARS[(n >> 6) & 0x3fu];
    *p++ = B64_CHARS[n & 0x3fu];
  }

  if (r == 2) {
    uint32_t n = static_cast<uint8_t>(*first++) << 16;
    n += static_cast<uint8_t>(*first++) << 8;
    *p++ = B64_CHARS[n >> 18];
    *p++ = B64_CHARS[(n >> 12) & 0x3fu];
    *p++ = B64_CHARS[(n >> 6) & 0x3fu];
    *p++ = '=';
  } else if (r == 1) {
    uint32_t n = static_cast<uint8_t>(*first++) << 16;
    *p++ = B64_CHARS[n >> 18];
    *p++ = B64_CHARS[(n >> 12) & 0x3fu];
    *p++ = '=';
    *p++ = '=';
  }
  return res;
}

// read_mime_types reads "MIME media types and the extensions" file
// denoted by |filename| and stores the mapping of extension to MIME
// media type in |dest|.  It returns 0 if it succeeds, or -1.
int read_mime_types(std::map<std::string, std::string> &dest,
                    const char *filename);

// from_ossl_level translates |ossl_level| to ngtcp2_crypto_level.
ngtcp2_crypto_level from_ossl_level(OSSL_ENCRYPTION_LEVEL ossl_level);

// from_ngtcp2_level translates |crypto_level| to
// OSSL_ENCRYPTION_LEVEL.
OSSL_ENCRYPTION_LEVEL from_ngtcp2_level(ngtcp2_crypto_level crypto_level);

} // namespace util

} // namespace ngtcp2

#endif // UTIL_H
