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
#include "ngtcp2_conv.h"

#include <string.h>

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif /* HAVE_ARPA_INET_H */

#include "ngtcp2_str.h"

#ifdef WORDS_BIGENDIAN
#define bwap64(N) (N)
#else /* !WORDS_BIGENDIAN */
#define bswap64(N)                                                             \
  (((uint64_t)(ntohl(((uint32_t)(N)) & 0xffffffffu))) << 32 | ntohl((N) >> 32))
#endif /* !WORDS_BIGENDIAN */

uint64_t ngtcp2_get_uint64(const uint8_t *p) {
  uint64_t n;
  memcpy(&n, p, 8);
  return bswap64(n);
}

uint64_t ngtcp2_get_uint48(const uint8_t *p) {
  uint64_t n = 0;
  memcpy(((uint8_t *)&n) + 2, p, 6);
  return bswap64(n);
}

uint32_t ngtcp2_get_uint32(const uint8_t *p) {
  uint32_t n;
  memcpy(&n, p, 4);
  return ntohl(n);
}

uint32_t ngtcp2_get_uint24(const uint8_t *p) {
  uint32_t n = 0;
  memcpy(((uint8_t *)&n) + 1, p, 3);
  return ntohl(n);
}

uint16_t ngtcp2_get_uint16(const uint8_t *p) {
  uint16_t n;
  memcpy(&n, p, 2);
  return ntohs(n);
}

uint8_t *ngtcp2_put_uint64be(uint8_t *p, uint64_t n) {
  n = bswap64(n);
  return ngtcp2_cpymem(p, (const uint8_t *)&n, sizeof(n));
}

uint8_t *ngtcp2_put_uint48be(uint8_t *p, uint64_t n) {
  n = bswap64(n);
  return ngtcp2_cpymem(p, ((const uint8_t *)&n) + 2, 6);
}

uint8_t *ngtcp2_put_uint32be(uint8_t *p, uint32_t n) {
  n = htonl(n);
  return ngtcp2_cpymem(p, (const uint8_t *)&n, sizeof(n));
}

uint8_t *ngtcp2_put_uint24be(uint8_t *p, uint32_t n) {
  n = htonl(n);
  return ngtcp2_cpymem(p, ((const uint8_t *)&n) + 1, 3);
}

uint8_t *ngtcp2_put_uint16be(uint8_t *p, uint16_t n) {
  n = htons(n);
  return ngtcp2_cpymem(p, (const uint8_t *)&n, sizeof(n));
}
