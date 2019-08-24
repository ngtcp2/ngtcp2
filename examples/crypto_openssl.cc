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

#include <iostream>

#if !defined(OPENSSL_IS_BORINGSSL)

#  include <cassert>

#  include <openssl/evp.h>
#  include <openssl/kdf.h>

#  include "template.h"

namespace ngtcp2 {

namespace crypto {

int negotiated_prf(Context &ctx, SSL *ssl) {
  switch (SSL_CIPHER_get_id(SSL_get_current_cipher(ssl))) {
  case 0x03001301u: // TLS_AES_128_GCM_SHA256
  case 0x03001303u: // TLS_CHACHA20_POLY1305_SHA256
  case 0x03001304u: // TLS_AES_128_CCM_SHA256
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
    ctx.aead = EVP_aes_128_gcm();
    ctx.hp = EVP_aes_128_ctr();
    return 0;
  case 0x03001302u: // TLS_AES_256_GCM_SHA384
    ctx.aead = EVP_aes_256_gcm();
    ctx.hp = EVP_aes_256_ctr();
    return 0;
  case 0x03001303u: // TLS_CHACHA20_POLY1305_SHA256
    ctx.aead = EVP_chacha20_poly1305();
    ctx.hp = EVP_chacha20();
    return 0;
  case 0x03001304u: // TLS_AES_128_CCM_SHA256
    ctx.aead = EVP_aes_128_ccm();
    ctx.hp = EVP_aes_128_ctr();
    return 0;
  default:
    return -1;
  }
}

static size_t aead_tag_length(const Context &ctx) {
  if (ctx.aead == EVP_aes_128_gcm() || ctx.aead == EVP_aes_256_gcm()) {
    return EVP_GCM_TLS_TAG_LEN;
  }
  if (ctx.aead == EVP_chacha20_poly1305()) {
    return EVP_CHACHAPOLY_TLS_TAG_LEN;
  }
  if (ctx.aead == EVP_aes_128_ccm()) {
    return EVP_CCM_TLS_TAG_LEN;
  }
  assert(0);
}

ssize_t encrypt(uint8_t *dest, size_t destlen, const uint8_t *plaintext,
                size_t plaintextlen, const Context &ctx, const uint8_t *key,
                size_t keylen, const uint8_t *nonce, size_t noncelen,
                const uint8_t *ad, size_t adlen) {
  auto taglen = aead_tag_length(ctx);

  if (destlen < plaintextlen + taglen) {
    return -1;
  }

  auto actx = EVP_CIPHER_CTX_new();
  if (actx == nullptr) {
    return -1;
  }

  auto actx_d = defer(EVP_CIPHER_CTX_free, actx);

  if (EVP_EncryptInit_ex(actx, ctx.aead, nullptr, nullptr, nullptr) != 1) {
    return -1;
  }

  if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_IVLEN, noncelen, nullptr) !=
      1) {
    return -1;
  }

  if (ctx.aead == EVP_aes_128_ccm() &&
      EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_TAG, taglen, nullptr) != 1) {
    return -1;
  }

  if (EVP_EncryptInit_ex(actx, nullptr, nullptr, key, nonce) != 1) {
    return -1;
  }

  size_t outlen = 0;
  int len;

  if (ctx.aead == EVP_aes_128_ccm() &&
      EVP_EncryptUpdate(actx, nullptr, &len, nullptr, plaintextlen) != 1) {
    return -1;
  }

  if (EVP_EncryptUpdate(actx, nullptr, &len, ad, adlen) != 1) {
    return -1;
  }

  if (EVP_EncryptUpdate(actx, dest, &len, plaintext, plaintextlen) != 1) {
    return -1;
  }

  outlen = len;

  if (EVP_EncryptFinal_ex(actx, dest + outlen, &len) != 1) {
    return -1;
  }

  outlen += len;

  assert(outlen + taglen <= destlen);

  if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_GET_TAG, taglen, dest + outlen) !=
      1) {
    return -1;
  }

  outlen += taglen;

  return outlen;
}

ssize_t decrypt(uint8_t *dest, size_t destlen, const uint8_t *ciphertext,
                size_t ciphertextlen, const Context &ctx, const uint8_t *key,
                size_t keylen, const uint8_t *nonce, size_t noncelen,
                const uint8_t *ad, size_t adlen) {
  auto taglen = aead_tag_length(ctx);

  if (taglen > ciphertextlen || destlen + taglen < ciphertextlen) {
    return -1;
  }

  ciphertextlen -= taglen;
  auto tag = ciphertext + ciphertextlen;

  auto actx = EVP_CIPHER_CTX_new();
  if (actx == nullptr) {
    return -1;
  }

  auto actx_d = defer(EVP_CIPHER_CTX_free, actx);

  if (EVP_DecryptInit_ex(actx, ctx.aead, nullptr, nullptr, nullptr) != 1) {
    return -1;
  }

  if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_IVLEN, noncelen, nullptr) !=
      1) {
    return -1;
  }

  if (ctx.aead == EVP_aes_128_ccm() &&
      EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_TAG, taglen,
                          const_cast<uint8_t *>(tag)) != 1) {
    return -1;
  }

  if (EVP_DecryptInit_ex(actx, nullptr, nullptr, key, nonce) != 1) {
    return -1;
  }

  size_t outlen;
  int len;

  if (ctx.aead == EVP_aes_128_ccm() &&
      EVP_DecryptUpdate(actx, nullptr, &len, nullptr, ciphertextlen) != 1) {
    return -1;
  }

  if (EVP_DecryptUpdate(actx, nullptr, &len, ad, adlen) != 1) {
    return -1;
  }

  if (EVP_DecryptUpdate(actx, dest, &len, ciphertext, ciphertextlen) != 1) {
    return -1;
  }

  outlen = len;

  if (ctx.aead == EVP_aes_128_ccm()) {
    return outlen;
  }

  if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_TAG, taglen,
                          const_cast<uint8_t *>(tag)) != 1) {
    return -1;
  }

  if (EVP_DecryptFinal_ex(actx, dest + outlen, &len) != 1) {
    return -1;
  }

  outlen += len;

  return outlen;
}

size_t aead_max_overhead(const Context &ctx) { return aead_tag_length(ctx); }

size_t aead_key_length(const Context &ctx) {
  return EVP_CIPHER_key_length(ctx.aead);
}

size_t aead_nonce_length(const Context &ctx) {
  return EVP_CIPHER_iv_length(ctx.aead);
}

ssize_t hp_mask(uint8_t *dest, size_t destlen, const Context &ctx,
                const uint8_t *key, size_t keylen, const uint8_t *sample,
                size_t samplelen) {
  static constexpr uint8_t PLAINTEXT[] = "\x00\x00\x00\x00\x00";

  auto actx = EVP_CIPHER_CTX_new();
  if (actx == nullptr) {
    return -1;
  }

  auto actx_d = defer(EVP_CIPHER_CTX_free, actx);

  if (EVP_EncryptInit_ex(actx, ctx.hp, nullptr, key, sample) != 1) {
    return -1;
  }

  size_t outlen = 0;
  int len;

  if (EVP_EncryptUpdate(actx, dest, &len, PLAINTEXT, str_size(PLAINTEXT)) !=
      1) {
    return -1;
  }

  assert(len == 5);

  outlen = len;

  if (EVP_EncryptFinal_ex(actx, dest + outlen, &len) != 1) {
    return -1;
  }

  assert(len == 0);

  return outlen;
}

int hkdf_expand(uint8_t *dest, size_t destlen, const uint8_t *secret,
                size_t secretlen, const uint8_t *info, size_t infolen,
                const Context &ctx) {
  auto pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (pctx == nullptr) {
    return -1;
  }

  auto pctx_d = defer(EVP_PKEY_CTX_free, pctx);

  if (EVP_PKEY_derive_init(pctx) != 1) {
    return -1;
  }

  if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) != 1) {
    return -1;
  }

  if (EVP_PKEY_CTX_set_hkdf_md(pctx, ctx.prf) != 1) {
    return -1;
  }

  if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, "", 0) != 1) {
    return -1;
  }

  if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secretlen) != 1) {
    return -1;
  }

  if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, infolen) != 1) {
    return -1;
  }

  if (EVP_PKEY_derive(pctx, dest, &destlen) != 1) {
    return -1;
  }

  return 0;
}

int hkdf_extract(uint8_t *dest, size_t destlen, const uint8_t *secret,
                 size_t secretlen, const uint8_t *salt, size_t saltlen,
                 const Context &ctx) {
  auto pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (pctx == nullptr) {
    return -1;
  }

  auto pctx_d = defer(EVP_PKEY_CTX_free, pctx);

  if (EVP_PKEY_derive_init(pctx) != 1) {
    return -1;
  }

  if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) != 1) {
    return -1;
  }

  if (EVP_PKEY_CTX_set_hkdf_md(pctx, ctx.prf) != 1) {
    return -1;
  }

  if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, saltlen) != 1) {
    return -1;
  }

  if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secretlen) != 1) {
    return -1;
  }

  if (EVP_PKEY_derive(pctx, dest, &destlen) != 1) {
    return -1;
  }

  return 0;
}

void prf_sha256(Context &ctx) { ctx.prf = EVP_sha256(); }

void aead_aes_128_gcm(Context &ctx) {
  ctx.aead = EVP_aes_128_gcm();
  ctx.hp = EVP_aes_128_ctr();
}

int message_digest(uint8_t *res, const EVP_MD *meth, const uint8_t *data,
                   size_t len) {
  int rv;

  auto ctx = EVP_MD_CTX_new();
  if (ctx == nullptr) {
    return -1;
  }

  auto ctx_deleter = defer(EVP_MD_CTX_free, ctx);

  rv = EVP_DigestInit_ex(ctx, meth, nullptr);
  if (rv != 1) {
    return -1;
  }

  rv = EVP_DigestUpdate(ctx, data, len);
  if (rv != 1) {
    return -1;
  }

  unsigned int mdlen = EVP_MD_size(meth);

  rv = EVP_DigestFinal_ex(ctx, res, &mdlen);
  if (rv != 1) {
    return -1;
  }

  return 0;
}

} // namespace crypto

} // namespace ngtcp2

#endif // !defined(OPENSSL_IS_BORINGSSL)
