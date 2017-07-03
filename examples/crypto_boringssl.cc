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

#if defined(OPENSSL_IS_BORINGSSL)

#include <cassert>

#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/aead.h>

#include "template.h"

namespace ngtcp2 {

namespace crypto {

int negotiated_prf(Context &ctx, SSL *ssl) {
  switch (SSL_CIPHER_get_id(SSL_get_current_cipher(ssl))) {
  case 0x03001301u: // TLS_AES_128_GCM_SHA256
  case 0x03001303u: // TLS_CHACHA20_POLY1305_SHA256
    ctx.prf = EVP_sha256();
    return 0;
  case 0x03001302u: // TLS_AES_256_GCM_SHA384
    ctx.prf = EVP_sha384();
    return 0;
  default:
    return -1;
  }
}

int negotiated_aead(Context &ctx, SSL *ssl) {
  switch (SSL_CIPHER_get_id(SSL_get_current_cipher(ssl))) {
  case 0x03001301u: // TLS_AES_128_GCM_SHA256
    ctx.aead = EVP_aead_aes_128_gcm();
    return 0;
  case 0x03001302u: // TLS_AES_256_GCM_SHA384
    ctx.aead = EVP_aead_aes_256_gcm();
    return 0;
  case 0x03001303u: // TLS_CHACHA20_POLY1305_SHA256
    ctx.aead = EVP_aead_chacha20_poly1305();
    return 0;
  default:
    return -1;
  }
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

size_t aead_key_length(const Context &ctx) {
  return EVP_AEAD_key_length(ctx.aead);
}

size_t aead_nonce_length(const Context &ctx) {
  return EVP_AEAD_nonce_length(ctx.aead);
}

int hkdf(uint8_t *dest, size_t destlen, const uint8_t *secret, size_t secretlen,
         const uint8_t *info, size_t infolen, const Context &ctx) {
  if (HKDF(dest, destlen, ctx.prf, secret, secretlen, nullptr, 0, info,
           infolen) != 1) {
    return -1;
  }
  return 0;
}

} // namespace crypto

} // namespace ngtcp2

#endif // defined(OPENSSL_IS_BORINGSSL)
