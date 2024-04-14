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
#include "util.h"

#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif // HAVE_ARPA_INET_H
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>

#include <cassert>
#include <cstring>
#include <chrono>
#include <array>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <limits>
#include <charconv>

#include "template.h"

using namespace std::literals;

namespace ngtcp2 {

namespace util {

std::optional<std::string> read_pem(const std::string_view &filename,
                                    const std::string_view &name,
                                    const std::string_view &type);

int write_pem(const std::string_view &filename, const std::string_view &name,
              const std::string_view &type, std::span<const uint8_t> data);

namespace {
constexpr char LOWER_XDIGITS[] = "0123456789abcdef";
} // namespace

std::string format_hex(uint8_t c) {
  std::string s;
  s.resize(2);

  s[0] = LOWER_XDIGITS[c >> 4];
  s[1] = LOWER_XDIGITS[c & 0xf];

  return s;
}

std::string format_hex(std::span<const uint8_t> s) {
  std::string res;
  res.resize(s.size() * 2);

  auto p = std::begin(res);

  for (auto c : s) {
    *p++ = LOWER_XDIGITS[c >> 4];
    *p++ = LOWER_XDIGITS[c & 0x0f];
  }
  return res;
}

std::string format_hex(const std::string_view &s) {
  return format_hex({reinterpret_cast<const uint8_t *>(s.data()), s.size()});
}

std::string decode_hex(const std::string_view &s) {
  assert(s.size() % 2 == 0);
  std::string res(s.size() / 2, '0');
  auto p = std::begin(res);
  for (auto it = std::begin(s); it != std::end(s); it += 2) {
    *p++ = (hex_to_uint(*it) << 4) | hex_to_uint(*(it + 1));
  }
  return res;
}

namespace {
// format_fraction2 formats |n| as fraction part of integer.  |n| is
// considered as fraction, and its precision is 3 digits.  The last
// digit is ignored.  The precision of the resulting fraction is 2
// digits.
std::string format_fraction2(uint32_t n) {
  n /= 10;

  if (n < 10) {
    return {'.', '0', static_cast<char>('0' + n)};
  }
  return {'.', static_cast<char>('0' + n / 10),
          static_cast<char>('0' + (n % 10))};
}
} // namespace

namespace {
// round2even rounds the last digit of |n| so that the n / 10 becomes
// even.
uint64_t round2even(uint64_t n) {
  if (n % 10 == 5) {
    if ((n / 10) & 1) {
      n += 10;
    }
  } else {
    n += 5;
  }
  return n;
}
} // namespace

std::string format_durationf(uint64_t ns) {
  static constexpr const std::string_view units[] = {"us"sv, "ms"sv, "s"sv};
  if (ns < 1000) {
    return format_uint(ns) + "ns";
  }
  auto unit = 0;
  if (ns < 1000000) {
    // do nothing
  } else if (ns < 1000000000) {
    ns /= 1000;
    unit = 1;
  } else {
    ns /= 1000000;
    unit = 2;
  }

  ns = round2even(ns);

  if (ns / 1000 >= 1000 && unit < 2) {
    ns /= 1000;
    ++unit;
  }

  auto res = format_uint(ns / 1000);
  res += format_fraction2(ns % 1000);
  res += units[unit];

  return res;
}

std::mt19937 make_mt19937() {
  std::random_device rd;
  return std::mt19937(rd());
}

ngtcp2_tstamp timestamp() {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

bool numeric_host(const char *hostname) {
  return numeric_host(hostname, AF_INET) || numeric_host(hostname, AF_INET6);
}

bool numeric_host(const char *hostname, int family) {
  int rv;
  std::array<uint8_t, sizeof(struct in6_addr)> dst;

  rv = inet_pton(family, hostname, dst.data());

  return rv == 1;
}

namespace {
uint8_t *hexdump_addr(uint8_t *dest, size_t addr) {
  // Lower 32 bits are displayed.
  for (size_t i = 0; i < 4; ++i) {
    auto a = (addr >> (3 - i) * 8) & 0xff;

    *dest++ = LOWER_XDIGITS[a >> 4];
    *dest++ = LOWER_XDIGITS[a & 0xf];
  }

  return dest;
}
} // namespace

namespace {
uint8_t *hexdump_ascii(uint8_t *dest, std::span<const uint8_t> data) {
  *dest++ = '|';

  for (auto c : data) {
    if (0x20 <= c && c <= 0x7e) {
      *dest++ = c;
    } else {
      *dest++ = '.';
    }
  }

  *dest++ = '|';

  return dest;
}
} // namespace

namespace {
uint8_t *hexdump8(uint8_t *dest, std::span<const uint8_t> data) {
  for (auto c : data) {
    *dest++ = LOWER_XDIGITS[c >> 4];
    *dest++ = LOWER_XDIGITS[c & 0xf];
    *dest++ = ' ';
  }

  for (auto i = data.size(); i < 8; ++i) {
    *dest++ = ' ';
    *dest++ = ' ';
    *dest++ = ' ';
  }

  return dest;
}
} // namespace

namespace {
uint8_t *hexdump16(uint8_t *dest, std::span<const uint8_t> data) {
  if (data.size() > 8) {
    dest = hexdump8(dest, {data.data(), 8});
    *dest++ = ' ';
    dest = hexdump8(dest, data.subspan(8));
    *dest++ = ' ';
  } else {
    dest = hexdump8(dest, data);
    *dest++ = ' ';
    dest = hexdump8(dest, {});
    *dest++ = ' ';
  }

  return dest;
}
} // namespace

namespace {
uint8_t *hexdump_line(uint8_t *dest, std::span<const uint8_t> data,
                      size_t addr) {
  dest = hexdump_addr(dest, addr);
  *dest++ = ' ';
  *dest++ = ' ';

  dest = hexdump16(dest, data);

  return hexdump_ascii(dest, data);
}
} // namespace

namespace {
int hexdump_write(int fd, std::span<const uint8_t> data) {
  ssize_t nwrite;

  for (;
       (nwrite = write(fd, data.data(), data.size())) == -1 && errno == EINTR;)
    ;
  if (nwrite == -1) {
    return -1;
  }

  return 0;
}
} // namespace

int hexdump(FILE *out, const void *data, size_t datalen) {
  if (datalen == 0) {
    return 0;
  }

  // min_space is the additional minimum space that the buffer must
  // accept, which is the size of a single full line output + one
  // repeat line marker ("*\n").  If the remaining buffer size is less
  // than that, flush the buffer and reset.
  constexpr size_t min_space = 79 + 2;

  auto fd = fileno(out);
  std::array<uint8_t, 4096> buf;
  auto last = buf.data();
  auto in = reinterpret_cast<const uint8_t *>(data);
  auto repeated = false;

  for (size_t offset = 0; offset < datalen; offset += 16) {
    auto n = datalen - offset;
    auto s = in + offset;

    if (n >= 16) {
      n = 16;

      if (offset > 0) {
        if (std::equal(s - 16, s, s)) {
          if (repeated) {
            continue;
          }

          repeated = true;

          *last++ = '*';
          *last++ = '\n';

          continue;
        }

        repeated = false;
      }
    }

    last = hexdump_line(last, {s, n}, offset);
    *last++ = '\n';

    auto len = static_cast<size_t>(last - buf.data());
    if (len + min_space > buf.size()) {
      if (hexdump_write(fd, {buf.data(), len}) != 0) {
        return -1;
      }

      last = buf.data();
    }
  }

  last = hexdump_addr(last, datalen);
  *last++ = '\n';

  auto len = static_cast<size_t>(last - buf.data());
  if (len) {
    return hexdump_write(fd, {buf.data(), len});
  }

  return 0;
}

std::string_view make_cid_key(const ngtcp2_cid *cid) {
  return make_cid_key({cid->data, cid->datalen});
}

std::string_view make_cid_key(std::span<const uint8_t> cid) {
  return std::string_view{reinterpret_cast<const char *>(cid.data()),
                          cid.size()};
}

std::string straddr(const sockaddr *sa, socklen_t salen) {
  std::array<char, NI_MAXHOST> host;
  std::array<char, NI_MAXSERV> port;

  auto rv = getnameinfo(sa, salen, host.data(), host.size(), port.data(),
                        port.size(), NI_NUMERICHOST | NI_NUMERICSERV);
  if (rv != 0) {
    std::cerr << "getnameinfo: " << gai_strerror(rv) << std::endl;
    return "";
  }
  std::string res = "[";
  res.append(host.data(), strlen(host.data()));
  res += "]:";
  res.append(port.data(), strlen(port.data()));
  return res;
}

uint16_t port(const sockaddr_union *su) {
  switch (su->sa.sa_family) {
  case AF_INET:
    return ntohs(su->in.sin_port);
  case AF_INET6:
    return ntohs(su->in6.sin6_port);
  default:
    return 0;
  }
}

bool prohibited_port(uint16_t port) {
  switch (port) {
  case 1900:
  case 5353:
  case 11211:
  case 20800:
  case 27015:
    return true;
  default:
    return port < 1024;
  }
}

std::string_view strccalgo(ngtcp2_cc_algo cc_algo) {
  switch (cc_algo) {
  case NGTCP2_CC_ALGO_RENO:
    return "reno"sv;
  case NGTCP2_CC_ALGO_CUBIC:
    return "cubic"sv;
  case NGTCP2_CC_ALGO_BBR:
    return "bbr"sv;
  default:
    assert(0);
    abort();
  }
}

namespace {
constexpr bool rws(char c) { return c == '\t' || c == ' '; }
} // namespace

std::optional<std::unordered_map<std::string, std::string>>
read_mime_types(const std::string_view &filename) {
  std::ifstream f(filename.data());
  if (!f) {
    return {};
  }

  std::unordered_map<std::string, std::string> dest;

  std::string line;
  while (std::getline(f, line)) {
    if (line.empty() || line[0] == '#') {
      continue;
    }

    auto p = std::find_if(std::begin(line), std::end(line), rws);
    if (p == std::begin(line) || p == std::end(line)) {
      continue;
    }

    auto media_type = std::string{std::begin(line), p};
    for (;;) {
      auto ext = std::find_if_not(p, std::end(line), rws);
      if (ext == std::end(line)) {
        break;
      }

      p = std::find_if(ext, std::end(line), rws);
      dest.emplace(std::string{ext, p}, media_type);
    }
  }

  return dest;
}

std::string format_duration(ngtcp2_duration n) {
  if (n >= 3600 * NGTCP2_SECONDS && (n % (3600 * NGTCP2_SECONDS)) == 0) {
    return format_uint(n / (3600 * NGTCP2_SECONDS)) + 'h';
  }
  if (n >= 60 * NGTCP2_SECONDS && (n % (60 * NGTCP2_SECONDS)) == 0) {
    return format_uint(n / (60 * NGTCP2_SECONDS)) + 'm';
  }
  if (n >= NGTCP2_SECONDS && (n % NGTCP2_SECONDS) == 0) {
    return format_uint(n / NGTCP2_SECONDS) + 's';
  }
  if (n >= NGTCP2_MILLISECONDS && (n % NGTCP2_MILLISECONDS) == 0) {
    return format_uint(n / NGTCP2_MILLISECONDS) + "ms";
  }
  if (n >= NGTCP2_MICROSECONDS && (n % NGTCP2_MICROSECONDS) == 0) {
    return format_uint(n / NGTCP2_MICROSECONDS) + "us";
  }
  return format_uint(n) + "ns";
}

namespace {
std::optional<std::pair<uint64_t, size_t>>
parse_uint_internal(const std::string_view &s) {
  uint64_t res = 0;

  if (s.empty()) {
    return {};
  }

  for (size_t i = 0; i < s.size(); ++i) {
    auto c = s[i];
    if (c < '0' || '9' < c) {
      return {{res, i}};
    }

    auto d = c - '0';
    if (res > (std::numeric_limits<uint64_t>::max() - d) / 10) {
      return {};
    }

    res *= 10;
    res += d;
  }

  return {{res, s.size()}};
}
} // namespace

std::optional<uint64_t> parse_uint(const std::string_view &s) {
  auto o = parse_uint_internal(s);
  if (!o) {
    return {};
  }
  auto [res, idx] = *o;
  if (idx != s.size()) {
    return {};
  }
  return res;
}

std::optional<uint64_t> parse_uint_iec(const std::string_view &s) {
  auto o = parse_uint_internal(s);
  if (!o) {
    return {};
  }
  auto [res, idx] = *o;
  if (idx == s.size()) {
    return res;
  }
  if (idx + 1 != s.size()) {
    return {};
  }

  uint64_t m;
  switch (s[idx]) {
  case 'G':
  case 'g':
    m = 1 << 30;
    break;
  case 'M':
  case 'm':
    m = 1 << 20;
    break;
  case 'K':
  case 'k':
    m = 1 << 10;
    break;
  default:
    return {};
  }

  if (res > std::numeric_limits<uint64_t>::max() / m) {
    return {};
  }

  return res * m;
}

std::optional<uint64_t> parse_duration(const std::string_view &s) {
  auto o = parse_uint_internal(s);
  if (!o) {
    return {};
  }
  auto [res, idx] = *o;
  if (idx == s.size()) {
    return res * NGTCP2_SECONDS;
  }

  uint64_t m;
  if (idx + 1 == s.size()) {
    switch (s[idx]) {
    case 'H':
    case 'h':
      m = 3600 * NGTCP2_SECONDS;
      break;
    case 'M':
    case 'm':
      m = 60 * NGTCP2_SECONDS;
      break;
    case 'S':
    case 's':
      m = NGTCP2_SECONDS;
      break;
    default:
      return {};
    }
  } else if (idx + 2 == s.size() && (s[idx + 1] == 's' || s[idx + 1] == 'S')) {
    switch (s[idx]) {
    case 'M':
    case 'm':
      m = NGTCP2_MILLISECONDS;
      break;
    case 'U':
    case 'u':
      m = NGTCP2_MICROSECONDS;
      break;
    case 'N':
    case 'n':
      return res;
    default:
      return {};
    }
  } else {
    return {};
  }

  if (res > std::numeric_limits<uint64_t>::max() / m) {
    return {};
  }

  return res * m;
}

namespace {
template <typename InputIt> InputIt eat_file(InputIt first, InputIt last) {
  if (first == last) {
    *first++ = '/';
    return first;
  }

  if (*(last - 1) == '/') {
    return last;
  }

  auto p = last;
  for (; p != first && *(p - 1) != '/'; --p)
    ;
  if (p == first) {
    // this should not happened in normal case, where we expect path
    // starts with '/'
    *first++ = '/';
    return first;
  }

  return p;
}
} // namespace

namespace {
template <typename InputIt> InputIt eat_dir(InputIt first, InputIt last) {
  auto p = eat_file(first, last);

  --p;

  assert(*p == '/');

  return eat_file(first, p);
}
} // namespace

std::string normalize_path(const std::string_view &path) {
  assert(path.size() <= 1024);
  assert(path.size() > 0);
  assert(path[0] == '/');

  std::array<char, 1024> res;
  auto p = res.data();

  auto first = std::begin(path);
  auto last = std::end(path);

  *p++ = '/';
  ++first;
  for (; first != last && *first == '/'; ++first)
    ;

  for (; first != last;) {
    if (*first == '.') {
      if (first + 1 == last) {
        break;
      }
      if (*(first + 1) == '/') {
        first += 2;
        continue;
      }
      if (*(first + 1) == '.') {
        if (first + 2 == last) {
          p = eat_dir(res.data(), p);
          break;
        }
        if (*(first + 2) == '/') {
          p = eat_dir(res.data(), p);
          first += 3;
          continue;
        }
      }
    }
    if (*(p - 1) != '/') {
      p = eat_file(res.data(), p);
    }
    auto slash = std::find(first, last, '/');
    if (slash == last) {
      p = std::copy(first, last, p);
      break;
    }
    p = std::copy(first, slash + 1, p);
    first = slash + 1;
    for (; first != last && *first == '/'; ++first)
      ;
  }
  return std::string{res.data(), p};
}

int make_socket_nonblocking(int fd) {
  int rv;
  int flags;

  while ((flags = fcntl(fd, F_GETFL, 0)) == -1 && errno == EINTR)
    ;
  if (flags == -1) {
    return -1;
  }

  while ((rv = fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1 && errno == EINTR)
    ;

  return rv;
}

int create_nonblock_socket(int domain, int type, int protocol) {
#ifdef SOCK_NONBLOCK
  auto fd = socket(domain, type | SOCK_NONBLOCK, protocol);
  if (fd == -1) {
    return -1;
  }
#else  // !SOCK_NONBLOCK
  auto fd = socket(domain, type, protocol);
  if (fd == -1) {
    return -1;
  }

  make_socket_nonblocking(fd);
#endif // !SOCK_NONBLOCK

  return fd;
}

std::vector<std::string_view> split_str(const std::string_view &s, char delim) {
  size_t len = 1;
  auto last = std::end(s);
  std::string_view::const_iterator d;
  for (auto first = std::begin(s); (d = std::find(first, last, delim)) != last;
       ++len, first = d + 1)
    ;

  auto list = std::vector<std::string_view>(len);

  len = 0;
  for (auto first = std::begin(s);; ++len) {
    auto stop = std::find(first, last, delim);
    // xcode clang does not understand std::string_view{first, stop}.
    list[len] = std::string_view{first, static_cast<size_t>(stop - first)};
    if (stop == last) {
      break;
    }
    first = stop + 1;
  }
  return list;
}

std::optional<uint32_t> parse_version(const std::string_view &s) {
  auto k = s;
  if (!util::istarts_with(k, "0x"sv)) {
    return {};
  }
  k = k.substr(2);
  uint32_t v;
  auto rv = std::from_chars(k.data(), k.data() + k.size(), v, 16);
  if (rv.ptr != k.data() + k.size() || rv.ec != std::errc{}) {
    return {};
  }

  return v;
}

std::optional<std::string> read_token(const std::string_view &filename) {
  return read_pem(filename, "token", "QUIC TOKEN");
}

int write_token(const std::string_view &filename,
                std::span<const uint8_t> token) {
  return write_pem(filename, "token", "QUIC TOKEN", token);
}

std::optional<std::string>
read_transport_params(const std::string_view &filename) {
  return read_pem(filename, "transport parameters",
                  "QUIC TRANSPORT PARAMETERS");
}

int write_transport_params(const std::string_view &filename,
                           std::span<const uint8_t> data) {
  return write_pem(filename, "transport parameters",
                   "QUIC TRANSPORT PARAMETERS", data);
}

} // namespace util

std::ostream &operator<<(std::ostream &os, const ngtcp2_cid &cid) {
  return os << "0x" << util::format_hex({cid.data, cid.datalen});
}

} // namespace ngtcp2
