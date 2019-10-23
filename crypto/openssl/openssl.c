/*
 * ngtcp2
 *
 * Copyright (c) 2019 ngtcp2 contributors
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
#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <assert.h>

#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_openssl.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_initial(ngtcp2_crypto_ctx *ctx) {
  ctx->aead.native_handle = (void *)EVP_aes_128_gcm();
  ctx->md.native_handle = (void *)EVP_sha256();
  ctx->hp.native_handle = (void *)EVP_aes_128_ctr();
  return ctx;
}

static const EVP_CIPHER *crypto_ssl_get_aead(SSL *ssl) {
  switch (SSL_CIPHER_get_id(SSL_get_current_cipher(ssl))) {
  case TLS1_3_CK_AES_128_GCM_SHA256:
    return EVP_aes_128_gcm();
  case TLS1_3_CK_AES_256_GCM_SHA384:
    return EVP_aes_256_gcm();
  case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
    return EVP_chacha20_poly1305();
  case TLS1_3_CK_AES_128_CCM_SHA256:
    return EVP_aes_128_ccm();
  default:
    return NULL;
  }
}

static const EVP_CIPHER *crypto_ssl_get_hp(SSL *ssl) {
  switch (SSL_CIPHER_get_id(SSL_get_current_cipher(ssl))) {
  case TLS1_3_CK_AES_128_GCM_SHA256:
  case TLS1_3_CK_AES_128_CCM_SHA256:
    return EVP_aes_128_ctr();
  case TLS1_3_CK_AES_256_GCM_SHA384:
    return EVP_aes_256_ctr();
  case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
    return EVP_chacha20();
  default:
    return NULL;
  }
}

static const EVP_MD *crypto_ssl_get_md(SSL *ssl) {
  switch (SSL_CIPHER_get_id(SSL_get_current_cipher(ssl))) {
  case TLS1_3_CK_AES_128_GCM_SHA256:
  case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
  case TLS1_3_CK_AES_128_CCM_SHA256:
    return EVP_sha256();
  case TLS1_3_CK_AES_256_GCM_SHA384:
    return EVP_sha384();
  default:
    return NULL;
  }
}

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_tls(ngtcp2_crypto_ctx *ctx,
                                         void *tls_native_handle) {
  SSL *ssl = tls_native_handle;
  ctx->aead.native_handle = (void *)crypto_ssl_get_aead(ssl);
  ctx->md.native_handle = (void *)crypto_ssl_get_md(ssl);
  ctx->hp.native_handle = (void *)crypto_ssl_get_hp(ssl);
  return ctx;
}

static size_t crypto_aead_keylen(const EVP_CIPHER *aead) {
  return (size_t)EVP_CIPHER_key_length(aead);
}

size_t ngtcp2_crypto_aead_keylen(const ngtcp2_crypto_aead *aead) {
  return crypto_aead_keylen(aead->native_handle);
}

static size_t crypto_aead_noncelen(const EVP_CIPHER *aead) {
  return (size_t)EVP_CIPHER_iv_length(aead);
}

size_t ngtcp2_crypto_aead_noncelen(const ngtcp2_crypto_aead *aead) {
  return crypto_aead_noncelen(aead->native_handle);
}

static size_t crypto_aead_taglen(const EVP_CIPHER *aead) {
  if (aead == EVP_aes_128_gcm() || aead == EVP_aes_256_gcm()) {
    return EVP_GCM_TLS_TAG_LEN;
  }
  if (aead == EVP_chacha20_poly1305()) {
    return EVP_CHACHAPOLY_TLS_TAG_LEN;
  }
  if (aead == EVP_aes_128_ccm()) {
    return EVP_CCM_TLS_TAG_LEN;
  }
  return 0;
}

size_t ngtcp2_crypto_aead_taglen(const ngtcp2_crypto_aead *aead) {
  return crypto_aead_taglen(aead->native_handle);
}

int ngtcp2_crypto_hkdf_extract(uint8_t *dest, size_t destlen,
                               const ngtcp2_crypto_md *md,
                               const uint8_t *secret, size_t secretlen,
                               const uint8_t *salt, size_t saltlen) {
  const EVP_MD *prf = md->native_handle;
  int rv = 0;
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
  if (pctx == NULL) {
    return -1;
  }

  if (EVP_PKEY_derive_init(pctx) != 1 ||
      EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) != 1 ||
      EVP_PKEY_CTX_set_hkdf_md(pctx, prf) != 1 ||
      EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, (int)saltlen) != 1 ||
      EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, (int)secretlen) != 1 ||
      EVP_PKEY_derive(pctx, dest, &destlen) != 1) {
    rv = -1;
  }

  EVP_PKEY_CTX_free(pctx);

  return rv;
}

int ngtcp2_crypto_hkdf_expand(uint8_t *dest, size_t destlen,
                              const ngtcp2_crypto_md *md, const uint8_t *secret,
                              size_t secretlen, const uint8_t *info,
                              size_t infolen) {
  const EVP_MD *prf = md->native_handle;
  int rv = 0;
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
  if (pctx == NULL) {
    return -1;
  }

  if (EVP_PKEY_derive_init(pctx) != 1 ||
      EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) != 1 ||
      EVP_PKEY_CTX_set_hkdf_md(pctx, prf) != 1 ||
      EVP_PKEY_CTX_set1_hkdf_salt(pctx, "", 0) != 1 ||
      EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, (int)secretlen) != 1 ||
      EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int)infolen) != 1 ||
      EVP_PKEY_derive(pctx, dest, &destlen) != 1) {
    rv = -1;
  }

  EVP_PKEY_CTX_free(pctx);

  return rv;
}

int ngtcp2_crypto_encrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                          const uint8_t *plaintext, size_t plaintextlen,
                          const uint8_t *key, const uint8_t *nonce,
                          size_t noncelen, const uint8_t *ad, size_t adlen) {
  const EVP_CIPHER *cipher = aead->native_handle;
  size_t taglen = crypto_aead_taglen(cipher);
  EVP_CIPHER_CTX *actx;
  int rv = 0;
  int len;

  actx = EVP_CIPHER_CTX_new();
  if (actx == NULL) {
    return -1;
  }

  if (!EVP_EncryptInit_ex(actx, cipher, NULL, NULL, NULL) ||
      !EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_IVLEN, (int)noncelen,
                           NULL) ||
      (cipher == EVP_aes_128_ccm() &&
       !EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_TAG, (int)taglen, NULL)) ||
      !EVP_EncryptInit_ex(actx, NULL, NULL, key, nonce) ||
      (cipher == EVP_aes_128_ccm() &&
       !EVP_EncryptUpdate(actx, NULL, &len, NULL, (int)plaintextlen)) ||
      !EVP_EncryptUpdate(actx, NULL, &len, ad, (int)adlen) ||
      !EVP_EncryptUpdate(actx, dest, &len, plaintext, (int)plaintextlen) ||
      !EVP_EncryptFinal_ex(actx, dest + len, &len) ||
      !EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_GET_TAG, (int)taglen,
                           dest + plaintextlen)) {
    rv = -1;
  }

  EVP_CIPHER_CTX_free(actx);

  return rv;
}

int ngtcp2_crypto_decrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                          const uint8_t *ciphertext, size_t ciphertextlen,
                          const uint8_t *key, const uint8_t *nonce,
                          size_t noncelen, const uint8_t *ad, size_t adlen) {
  const EVP_CIPHER *cipher = aead->native_handle;
  size_t taglen = crypto_aead_taglen(cipher);
  EVP_CIPHER_CTX *actx;
  int rv = 0;
  int len;
  const uint8_t *tag;

  if (taglen > ciphertextlen) {
    return -1;
  }

  ciphertextlen -= taglen;
  tag = ciphertext + ciphertextlen;

  actx = EVP_CIPHER_CTX_new();
  if (actx == NULL) {
    return -1;
  }

  if (!EVP_DecryptInit_ex(actx, cipher, NULL, NULL, NULL) ||
      !EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_IVLEN, (int)noncelen,
                           NULL) ||
      (cipher == EVP_aes_128_ccm() &&
       !EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_TAG, (int)taglen,
                            (uint8_t *)tag)) ||
      !EVP_DecryptInit_ex(actx, NULL, NULL, key, nonce) ||
      (cipher == EVP_aes_128_ccm() &&
       !EVP_DecryptUpdate(actx, NULL, &len, NULL, (int)ciphertextlen)) ||
      !EVP_DecryptUpdate(actx, NULL, &len, ad, (int)adlen) ||
      !EVP_DecryptUpdate(actx, dest, &len, ciphertext, (int)ciphertextlen) ||
      (cipher != EVP_aes_128_ccm() &&
       (!EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_TAG, (int)taglen,
                             (uint8_t *)tag) ||
        !EVP_DecryptFinal_ex(actx, dest + ciphertextlen, &len)))) {
    rv = -1;
  }

  EVP_CIPHER_CTX_free(actx);

  return rv;
}

int ngtcp2_crypto_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                          const uint8_t *hp_key, const uint8_t *sample) {
  static const uint8_t PLAINTEXT[] = "\x00\x00\x00\x00\x00";
  const EVP_CIPHER *cipher = hp->native_handle;
  EVP_CIPHER_CTX *actx;
  int rv = 0;
  int len;

  actx = EVP_CIPHER_CTX_new();
  if (actx == NULL) {
    return -1;
  }

  if (!EVP_EncryptInit_ex(actx, cipher, NULL, hp_key, sample) ||
      !EVP_EncryptUpdate(actx, dest, &len, PLAINTEXT, sizeof(PLAINTEXT) - 1) ||
      !EVP_EncryptFinal_ex(actx, dest + sizeof(PLAINTEXT) - 1, &len)) {
    rv = -1;
  }

  EVP_CIPHER_CTX_free(actx);

  return rv;
}

static OSSL_ENCRYPTION_LEVEL
from_ngtcp2_level(ngtcp2_crypto_level crypto_level) {
  switch (crypto_level) {
  case NGTCP2_CRYPTO_LEVEL_INITIAL:
    return ssl_encryption_initial;
  case NGTCP2_CRYPTO_LEVEL_HANDSHAKE:
    return ssl_encryption_handshake;
  case NGTCP2_CRYPTO_LEVEL_APP:
    return ssl_encryption_application;
  case NGTCP2_CRYPTO_LEVEL_EARLY:
    return ssl_encryption_early_data;
  default:
    assert(0);
  }
}

int ngtcp2_crypto_read_write_crypto_data(ngtcp2_conn *conn, void *tls,
                                         ngtcp2_crypto_level crypto_level,
                                         const uint8_t *data, size_t datalen) {
  SSL *ssl = tls;
  int rv;
  int err;

  if (SSL_provide_quic_data(ssl, from_ngtcp2_level(crypto_level), data,
                            datalen) != 1) {
    return -1;
  }

  if (!ngtcp2_conn_get_handshake_completed(conn)) {
    rv = SSL_do_handshake(ssl);
    if (rv <= 0) {
      err = SSL_get_error(ssl, rv);
      switch (err) {
      case SSL_ERROR_WANT_READ:
      case SSL_ERROR_WANT_WRITE:
        return 0;
      case SSL_ERROR_WANT_CLIENT_HELLO_CB:
        return NGTCP2_CRYPTO_ERR_TLS_WANT_CLIENT_HELLO_CB;
      case SSL_ERROR_WANT_X509_LOOKUP:
        return NGTCP2_CRYPTO_ERR_TLS_WANT_X509_LOOKUP;
      case SSL_ERROR_SSL:
        return -1;
      default:
        return -1;
      }
    }

    ngtcp2_conn_handshake_completed(conn);
  }

  rv = SSL_process_quic_post_handshake(ssl);
  if (rv != 1) {
    err = SSL_get_error(ssl, rv);
    switch (err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      return 0;
    case SSL_ERROR_SSL:
    case SSL_ERROR_ZERO_RETURN:
      return -1;
    default:
      return -1;
    }
  }

  return 0;
}

int ngtcp2_crypto_set_remote_transport_params(ngtcp2_conn *conn, void *tls,
                                              ngtcp2_crypto_side side) {
  SSL *ssl = tls;
  ngtcp2_transport_params_type exttype =
      side == NGTCP2_CRYPTO_SIDE_CLIENT
          ? NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS
          : NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO;
  const uint8_t *tp;
  size_t tplen;
  ngtcp2_transport_params params;
  int rv;

  SSL_get_peer_quic_transport_params(ssl, &tp, &tplen);

  rv = ngtcp2_decode_transport_params(&params, exttype, tp, tplen);
  if (rv != 0) {
    return -1;
  }

  rv = ngtcp2_conn_set_remote_transport_params(conn, &params);
  if (rv != 0) {
    return -1;
  }

  return 0;
}
