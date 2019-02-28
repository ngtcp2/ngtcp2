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
#include "crypto.h"

#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif /* HAVE_ARPA_INET_H */

#include <algorithm>

#include "template.h"

namespace ngtcp2 {

namespace crypto {

#ifndef bswap64
#ifdef WORDS_BIGENDIAN
#  define bswap64(N) (N)
#else /* !WORDS_BIGENDIAN */
#  define bswap64(N)                                                           \
    ((uint64_t)(ntohl((uint32_t)(N))) << 32 | ntohl((uint32_t)((N) >> 32)))
#endif /* !WORDS_BIGENDIAN */
#endif

int derive_initial_secret(uint8_t *dest, size_t destlen,
                          const ngtcp2_cid *secret, const uint8_t *salt,
                          size_t saltlen) {
  Context ctx;
  prf_sha256(ctx);
  return hkdf_extract(dest, destlen, secret->data, secret->datalen, salt,
                      saltlen, ctx);
}

int derive_client_initial_secret(uint8_t *dest, size_t destlen,
                                 const uint8_t *secret, size_t secretlen) {
  static constexpr uint8_t LABEL[] = "client in";
  Context ctx;
  prf_sha256(ctx);
  return crypto::hkdf_expand_label(dest, destlen, secret, secretlen, LABEL,
                                   str_size(LABEL), ctx);
}

int derive_server_initial_secret(uint8_t *dest, size_t destlen,
                                 const uint8_t *secret, size_t secretlen) {
  static constexpr uint8_t LABEL[] = "server in";
  Context ctx;
  prf_sha256(ctx);
  return crypto::hkdf_expand_label(dest, destlen, secret, secretlen, LABEL,
                                   str_size(LABEL), ctx);
}

ssize_t update_traffic_secret(uint8_t *dest, size_t destlen,
                              const uint8_t *secret, size_t secretlen,
                              const Context &ctx) {
  int rv;
  static constexpr uint8_t LABEL[] = "traffic upd";

  if (destlen < secretlen) {
    return -1;
  }

  rv = crypto::hkdf_expand_label(dest, secretlen, secret, secretlen, LABEL,
                                 str_size(LABEL), ctx);
  if (rv != 0) {
    return -1;
  }

  return secretlen;
}

ssize_t derive_packet_protection_key(uint8_t *dest, size_t destlen,
                                     const uint8_t *secret, size_t secretlen,
                                     const Context &ctx) {
  int rv;
  static constexpr uint8_t LABEL[] = "quic key";

  auto keylen = aead_key_length(ctx);
  if (keylen > destlen) {
    return -1;
  }

  rv = crypto::hkdf_expand_label(dest, keylen, secret, secretlen, LABEL,
                                 str_size(LABEL), ctx);
  if (rv != 0) {
    return -1;
  }

  return keylen;
}

ssize_t derive_packet_protection_iv(uint8_t *dest, size_t destlen,
                                    const uint8_t *secret, size_t secretlen,
                                    const Context &ctx) {
  int rv;
  static constexpr uint8_t LABEL[] = "quic iv";

  auto ivlen = std::max(static_cast<size_t>(8), aead_nonce_length(ctx));
  if (ivlen > destlen) {
    return -1;
  }

  rv = crypto::hkdf_expand_label(dest, ivlen, secret, secretlen, LABEL,
                                 str_size(LABEL), ctx);
  if (rv != 0) {
    return -1;
  }

  return ivlen;
}

ssize_t derive_header_protection_key(uint8_t *dest, size_t destlen,
                                     const uint8_t *secret, size_t secretlen,
                                     const Context &ctx) {
  int rv;
  static constexpr uint8_t LABEL[] = "quic hp";

  auto keylen = aead_key_length(ctx);
  if (keylen > destlen) {
    return -1;
  }

  rv = crypto::hkdf_expand_label(dest, keylen, secret, secretlen, LABEL,
                                 str_size(LABEL), ctx);

  if (rv != 0) {
    return -1;
  }

  return keylen;
}

int hkdf_expand_label(uint8_t *dest, size_t destlen, const uint8_t *secret,
                      size_t secretlen, const uint8_t *label, size_t labellen,
                      const Context &ctx) {
  std::array<uint8_t, 256> info;
  static constexpr const uint8_t LABEL[] = "tls13 ";

  auto p = std::begin(info);
  *p++ = destlen / 256;
  *p++ = destlen % 256;
  *p++ = str_size(LABEL) + labellen;
  p = std::copy_n(LABEL, str_size(LABEL), p);
  p = std::copy_n(label, labellen, p);
  *p++ = 0;

  return hkdf_expand(dest, destlen, secret, secretlen, info.data(),
                     p - std::begin(info), ctx);
}

} // namespace crypto

} // namespace ngtcp2
