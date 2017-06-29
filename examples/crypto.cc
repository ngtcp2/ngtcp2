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

#include <cassert>
#include <algorithm>

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif /* HAVE_ARPA_INET_H */

#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/aead.h>

#include "template.h"

#ifdef WORDS_BIGENDIAN
#define bwap64(N) (N)
#else /* !WORDS_BIGENDIAN */
#define bswap64(N)                                                             \
  (((uint64_t)(ntohl(((uint32_t)(N)) & 0xffffffffu))) << 32 | ntohl((N) >> 32))
#endif /* !WORDS_BIGENDIAN */

namespace ngtcp2 {

namespace crypto {

const EVP_MD *get_negotiated_prf(SSL *ssl) {
  switch (SSL_CIPHER_get_id(SSL_get_current_cipher(ssl))) {
  case 0x03001301u: // TLS_AES_128_GCM_SHA256
  case 0x03001303u: // TLS_CHACHA20_POLY1305_SHA256
    return EVP_sha256();
  case 0x03001302u: // TLS_AES_256_GCM_SHA384
    return EVP_sha384();
  default:
    return NULL;
  }
}

const EVP_AEAD *get_negotiated_aead(SSL *ssl) {
  switch (SSL_CIPHER_get_id(SSL_get_current_cipher(ssl))) {
  case 0x03001301u: // TLS_AES_128_GCM_SHA256
    return EVP_aead_aes_128_gcm();
  case 0x03001302u: // TLS_AES_256_GCM_SHA384
    return EVP_aead_aes_256_gcm();
  case 0x03001303u: // TLS_CHACHA20_POLY1305_SHA256
    return EVP_aead_chacha20_poly1305();
  default:
    return NULL;
  }
}

int export_secret(uint8_t *dest, size_t destlen, SSL *ssl, const uint8_t *label,
                  size_t labellen) {
  int rv;

  rv = SSL_export_keying_material(ssl, dest, destlen,
                                  reinterpret_cast<const char *>(label),
                                  labellen, nullptr, 0, 1);
  if (rv != 1) {
    return -1;
  }

  return 0;
}

int export_client_secret(uint8_t *dest, size_t destlen, SSL *ssl) {
  constexpr uint8_t label[] = "EXPORTER-QUIC client 1-RTT Secret";
  return export_secret(dest, destlen, ssl, label, str_size(label));
}

int export_server_secret(uint8_t *dest, size_t destlen, SSL *ssl) {
  constexpr uint8_t label[] = "EXPORTER-QUIC server 1-RTT Secret";
  return export_secret(dest, destlen, ssl, label, str_size(label));
}

int hkdf_expand_label(uint8_t *dest, size_t destlen, const uint8_t *secret,
                      size_t secretlen, const uint8_t *qlabel, size_t qlabellen,
                      const Context &ctx) {
  std::array<uint8_t, 256> info;
  int rv;
  constexpr const uint8_t LABEL[] = "TLS 1.3, ";

  auto p = std::begin(info);
  *p++ = destlen / 256;
  *p++ = destlen % 256;
  *p++ = str_size(LABEL) + qlabellen;
  p = std::copy_n(LABEL, str_size(LABEL), p);
  p = std::copy_n(qlabel, qlabellen, p);
  *p++ = 0;

  rv = HKDF(dest, destlen, ctx.prf, secret, secretlen, nullptr, 0, info.data(),
            p - std::begin(info));

  if (rv != 1) {
    return -1;
  }

  return 0;
}

ssize_t derive_packet_protection_key(uint8_t *dest, size_t destlen,
                                     const uint8_t *secret, size_t secretlen,
                                     const Context &ctx) {
  int rv;
  constexpr uint8_t LABEL_KEY[] = "key";

  auto keylen = EVP_AEAD_key_length(ctx.aead);
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
  constexpr uint8_t LABEL_IV[] = "iv";

  auto ivlen =
      std::max(static_cast<size_t>(8), EVP_AEAD_nonce_length(ctx.aead));
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

ssize_t encrypt(uint8_t *dest, size_t destlen, const uint8_t *plaintext,
                size_t plaintextlen, const Context &ctx, const uint8_t *key,
                size_t keylen, const uint8_t *nonce, size_t noncelen,
                const uint8_t *ad, size_t adlen) {
  int rv;

  auto actx = EVP_AEAD_CTX_new(ctx.aead, key, keylen, 0);

  assert(actx);

  auto actx_d = defer(EVP_AEAD_CTX_free, actx);

  size_t outlen;

  rv = EVP_AEAD_CTX_seal(actx, dest, &outlen, destlen, nonce, noncelen,
                         plaintext, plaintextlen, ad, adlen);
  if (rv != 1) {
    return -1;
  }

  return outlen;
}

ssize_t decrypt(uint8_t *dest, size_t destlen, const uint8_t *ciphertext,
                size_t ciphertextlen, const Context &ctx, const uint8_t *key,
                size_t keylen, const uint8_t *nonce, size_t noncelen,
                const uint8_t *ad, size_t adlen) {
  int rv;

  auto actx = EVP_AEAD_CTX_new(ctx.aead, key, keylen, 0);

  assert(actx);

  auto actx_d = defer(EVP_AEAD_CTX_free, actx);

  size_t outlen;

  rv = EVP_AEAD_CTX_open(actx, dest, &outlen, destlen, nonce, noncelen,
                         ciphertext, ciphertextlen, ad, adlen);
  if (rv != 1) {
    return -1;
  }

  return outlen;
}

size_t aead_max_overhead(const Context &ctx) {
  return EVP_AEAD_max_overhead(ctx.aead);
}

} // namespace crypto

} // namespace ngtcp2
