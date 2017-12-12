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
#include <arpa/inet.h>
#endif /* HAVE_ARPA_INET_H */

#include <algorithm>

#include "template.h"

namespace ngtcp2 {

namespace crypto {

int export_secret(uint8_t *dest, size_t destlen, SSL *ssl, const uint8_t *label,
                  size_t labellen) {
  int rv;

  rv = SSL_export_keying_material(
      ssl, dest, destlen, reinterpret_cast<const char *>(label), labellen,
      reinterpret_cast<const uint8_t *>(""), 0, 1);
  if (rv != 1) {
    return -1;
  }

  return 0;
}

int export_client_secret(uint8_t *dest, size_t destlen, SSL *ssl) {
  static constexpr uint8_t label[] = "EXPORTER-QUIC client 1-RTT Secret";
  return export_secret(dest, destlen, ssl, label, str_size(label));
}

int export_server_secret(uint8_t *dest, size_t destlen, SSL *ssl) {
  static constexpr uint8_t label[] = "EXPORTER-QUIC server 1-RTT Secret";
  return export_secret(dest, destlen, ssl, label, str_size(label));
}

int export_early_secret(uint8_t *dest, size_t destlen, SSL *ssl) {
  int rv;
  static constexpr char label[] = "EXPORTER-QUIC 0-RTT Secret";

  rv = SSL_export_keying_material_early(
      ssl, dest, destlen, label, str_size(label),
      reinterpret_cast<const uint8_t *>(""), 0, 1);
  if (rv != 1) {
    return -1;
  }

  return 0;
}

#ifdef WORDS_BIGENDIAN
#define bswap64(N) (N)
#else /* !WORDS_BIGENDIAN */
#define bswap64(N)                                                             \
  ((uint64_t)(ntohl((uint32_t)(N))) << 32 | ntohl((uint32_t)((N) >> 32)))
#endif /* !WORDS_BIGENDIAN */

int derive_handshake_secret(uint8_t *dest, size_t destlen, uint64_t secret,
                            const uint8_t *salt, size_t saltlen) {
  Context ctx;
  prf_sha256(ctx);
  secret = bswap64(secret);
  return hkdf_extract(dest, destlen, reinterpret_cast<uint8_t *>(&secret),
                      sizeof(secret), salt, saltlen, ctx);
}

int derive_client_handshake_secret(uint8_t *dest, size_t destlen,
                                   const uint8_t *secret, size_t secretlen) {
  static constexpr uint8_t LABEL[] = "QUIC client handshake secret";
  Context ctx;
  prf_sha256(ctx);
  return crypto::hkdf_expand_label(dest, destlen, secret, secretlen, LABEL,
                                   str_size(LABEL), ctx);
}

int derive_server_handshake_secret(uint8_t *dest, size_t destlen,
                                   const uint8_t *secret, size_t secretlen) {
  static constexpr uint8_t LABEL[] = "QUIC server handshake secret";
  Context ctx;
  prf_sha256(ctx);
  return crypto::hkdf_expand_label(dest, destlen, secret, secretlen, LABEL,
                                   str_size(LABEL), ctx);
}

ssize_t derive_packet_protection_key(uint8_t *dest, size_t destlen,
                                     const uint8_t *secret, size_t secretlen,
                                     const Context &ctx) {
  int rv;
  static constexpr uint8_t LABEL_KEY[] = "key";

  auto keylen = aead_key_length(ctx);
  if (keylen > destlen) {
    return -1;
  }

  rv = crypto::hkdf_expand_label(dest, keylen, secret, secretlen, LABEL_KEY,
                                 str_size(LABEL_KEY), ctx);
  if (rv != 0) {
    return -1;
  }

  return keylen;
}

ssize_t derive_packet_protection_iv(uint8_t *dest, size_t destlen,
                                    const uint8_t *secret, size_t secretlen,
                                    const Context &ctx) {
  int rv;
  static constexpr uint8_t LABEL_IV[] = "iv";

  auto ivlen = std::max(static_cast<size_t>(8), aead_nonce_length(ctx));
  if (ivlen > destlen) {
    return -1;
  }

  rv = crypto::hkdf_expand_label(dest, ivlen, secret, secretlen, LABEL_IV,
                                 str_size(LABEL_IV), ctx);
  if (rv != 0) {
    return -1;
  }

  return ivlen;
}

int hkdf_expand_label(uint8_t *dest, size_t destlen, const uint8_t *secret,
                      size_t secretlen, const uint8_t *qlabel, size_t qlabellen,
                      const Context &ctx) {
  std::array<uint8_t, 256> info;
  static constexpr const uint8_t LABEL[] = "tls13 ";

  auto p = std::begin(info);
  *p++ = destlen / 256;
  *p++ = destlen % 256;
  *p++ = str_size(LABEL) + qlabellen;
  p = std::copy_n(LABEL, str_size(LABEL), p);
  p = std::copy_n(qlabel, qlabellen, p);
  *p++ = 0;

  return hkdf_expand(dest, destlen, secret, secretlen, info.data(),
                     p - std::begin(info), ctx);
}

} // namespace crypto

} // namespace ngtcp2
