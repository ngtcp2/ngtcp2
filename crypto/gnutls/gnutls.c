/*
 * ngtcp2
 *
 * Copyright (c) 2020 ngtcp2 contributors
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
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <string.h>

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_initial(ngtcp2_crypto_ctx *ctx) {
  ctx->aead.native_handle = (void *)GNUTLS_CIPHER_AES_128_GCM;
  ctx->md.native_handle = (void *)GNUTLS_DIG_SHA256;
  ctx->hp.native_handle = (void *)GNUTLS_CIPHER_AES_128_CBC;
  return ctx;
}

ngtcp2_crypto_aead *ngtcp2_crypto_aead_retry(ngtcp2_crypto_aead *aead) {
  aead->native_handle = (void *)GNUTLS_CIPHER_AES_128_GCM;
  return aead;
}

static gnutls_cipher_algorithm_t crypto_get_hp(gnutls_session_t session) {
  switch (gnutls_cipher_get(session)) {
  case GNUTLS_CIPHER_AES_128_GCM:
  case GNUTLS_CIPHER_AES_128_CCM:
    return GNUTLS_CIPHER_AES_128_CBC;
  case GNUTLS_CIPHER_AES_256_GCM:
  case GNUTLS_CIPHER_AES_256_CCM:
    return GNUTLS_CIPHER_AES_256_CBC;
  case GNUTLS_CIPHER_CHACHA20_POLY1305:
    return GNUTLS_CIPHER_CHACHA20_32;
  default:
    return GNUTLS_CIPHER_UNKNOWN;
  }
}

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_tls(ngtcp2_crypto_ctx *ctx,
                                         void *tls_native_handle) {
  gnutls_session_t session = tls_native_handle;
  gnutls_cipher_algorithm_t cipher;
  gnutls_digest_algorithm_t hash;
  gnutls_cipher_algorithm_t hp_cipher;

  cipher = gnutls_cipher_get(session);
  if (cipher != GNUTLS_CIPHER_UNKNOWN && cipher != GNUTLS_CIPHER_NULL) {
    ctx->aead.native_handle = (void *)cipher;
  }

  hash = gnutls_prf_hash_get(session);
  if (hash != GNUTLS_DIG_UNKNOWN && hash != GNUTLS_DIG_NULL) {
    ctx->md.native_handle = (void *)hash;
  }

  hp_cipher = crypto_get_hp(session);
  if (hp_cipher != GNUTLS_CIPHER_UNKNOWN) {
    ctx->hp.native_handle = (void *)hp_cipher;
  }

  return ctx;
}

size_t ngtcp2_crypto_md_hashlen(const ngtcp2_crypto_md *md) {
  return gnutls_hash_get_len((gnutls_digest_algorithm_t)md->native_handle);
}

size_t ngtcp2_crypto_aead_keylen(const ngtcp2_crypto_aead *aead) {
  return gnutls_cipher_get_key_size(
      (gnutls_cipher_algorithm_t)aead->native_handle);
}

size_t ngtcp2_crypto_aead_noncelen(const ngtcp2_crypto_aead *aead) {
  return gnutls_cipher_get_iv_size(
      (gnutls_cipher_algorithm_t)aead->native_handle);
}

size_t ngtcp2_crypto_aead_taglen(const ngtcp2_crypto_aead *aead) {
  return gnutls_cipher_get_tag_size(
      (gnutls_cipher_algorithm_t)aead->native_handle);
}

int ngtcp2_crypto_hkdf_extract(uint8_t *dest, const ngtcp2_crypto_md *md,
                               const uint8_t *secret, size_t secretlen,
                               const uint8_t *salt, size_t saltlen) {
  gnutls_mac_algorithm_t prf = (gnutls_mac_algorithm_t)md->native_handle;
  gnutls_datum_t _secret = {(void *)secret, (unsigned int)secretlen};
  gnutls_datum_t _salt = {(void *)salt, (unsigned int)saltlen};

  if (gnutls_hkdf_extract(prf, &_secret, &_salt, dest) != 0) {
    return -1;
  }

  return 0;
}

int ngtcp2_crypto_hkdf_expand(uint8_t *dest, size_t destlen,
                              const ngtcp2_crypto_md *md, const uint8_t *secret,
                              size_t secretlen, const uint8_t *info,
                              size_t infolen) {
  gnutls_mac_algorithm_t prf = (gnutls_mac_algorithm_t)md->native_handle;
  gnutls_datum_t _secret = {(void *)secret, (unsigned int)secretlen};
  gnutls_datum_t _info = {(void *)info, (unsigned int)infolen};

  if (gnutls_hkdf_expand(prf, &_secret, &_info, dest, destlen) != 0) {
    return -1;
  }

  return 0;
}

int ngtcp2_crypto_encrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                          const uint8_t *plaintext, size_t plaintextlen,
                          const uint8_t *key, const uint8_t *nonce,
                          size_t noncelen, const uint8_t *ad, size_t adlen) {
  gnutls_cipher_algorithm_t cipher =
      (gnutls_cipher_algorithm_t)aead->native_handle;
  gnutls_aead_cipher_hd_t hd = NULL;
  gnutls_datum_t _key;
  size_t taglen = ngtcp2_crypto_aead_taglen(aead);
  size_t ciphertextlen = plaintextlen + taglen;
  int rv = 0;

  _key.data = (void *)key;
  _key.size = (unsigned int)ngtcp2_crypto_aead_keylen(aead);

  if (gnutls_aead_cipher_init(&hd, cipher, &_key) != 0 ||
      gnutls_aead_cipher_encrypt(hd, nonce, noncelen, ad, adlen, taglen,
                                 plaintext, plaintextlen, dest,
                                 &ciphertextlen) != 0) {
    rv = -1;
  }

  gnutls_aead_cipher_deinit(hd);

  return rv;
}

int ngtcp2_crypto_decrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                          const uint8_t *ciphertext, size_t ciphertextlen,
                          const uint8_t *key, const uint8_t *nonce,
                          size_t noncelen, const uint8_t *ad, size_t adlen) {
  gnutls_cipher_algorithm_t cipher =
      (gnutls_cipher_algorithm_t)aead->native_handle;
  size_t taglen = gnutls_cipher_get_tag_size(cipher);
  gnutls_aead_cipher_hd_t hd = NULL;
  gnutls_datum_t _key;
  int rv = 0;
  size_t plaintextlen;

  if (taglen > ciphertextlen) {
    return -1;
  }

  plaintextlen = ciphertextlen - taglen;

  _key.data = (void *)key;
  _key.size = (unsigned int)ngtcp2_crypto_aead_keylen(aead);

  if (gnutls_aead_cipher_init(&hd, cipher, &_key) != 0 ||
      gnutls_aead_cipher_decrypt(hd, nonce, noncelen, ad, adlen, taglen,
                                 ciphertext, ciphertextlen, dest,
                                 &plaintextlen) != 0) {
    rv = -1;
  }

  gnutls_aead_cipher_deinit(hd);

  return rv;
}

int ngtcp2_crypto_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                          const uint8_t *hp_key, const uint8_t *sample) {
  gnutls_cipher_algorithm_t cipher =
      (gnutls_cipher_algorithm_t)hp->native_handle;
  int rv = 0;

  switch (cipher) {
  case GNUTLS_CIPHER_AES_128_CBC:
  case GNUTLS_CIPHER_AES_256_CBC: {
    gnutls_cipher_hd_t hd = NULL;
    gnutls_datum_t _hp_key;
    uint8_t iv[16];
    gnutls_datum_t _iv;
    uint8_t buf[16];

    _hp_key.data = (void *)hp_key;
    _hp_key.size = (unsigned int)gnutls_cipher_get_key_size(cipher);

    /* Emulate one block AES-ECB by invalidating the effect of IV */
    memset(iv, 0, sizeof(iv));
    _iv.data = iv;
    _iv.size = 16;

    if (gnutls_cipher_init(&hd, cipher, &_hp_key, &_iv) != 0 ||
        gnutls_cipher_encrypt2(hd, sample, 16, buf, sizeof(buf)) != 0) {
      rv = -1;
    }

    memcpy(dest, buf, 5);
    gnutls_cipher_deinit(hd);
  } break;

  case GNUTLS_CIPHER_CHACHA20_32: {
    gnutls_cipher_hd_t hd = NULL;
    static const uint8_t PLAINTEXT[] = "\x00\x00\x00\x00\x00";
    gnutls_datum_t _hp_key;
    gnutls_datum_t _iv;
    uint8_t buf[5 + 16];
    size_t buflen = sizeof(buf);

    _hp_key.data = (void *)hp_key;
    _hp_key.size = (unsigned int)gnutls_cipher_get_key_size(cipher);

    _iv.data = (void *)sample;
    _iv.size = 16;

    if (gnutls_cipher_init(&hd, cipher, &_hp_key, &_iv) != 0 ||
        gnutls_cipher_encrypt2(hd, PLAINTEXT, sizeof(PLAINTEXT) - 1, buf,
                               buflen) != 0) {
      rv = -1;
    }

    memcpy(dest, buf, 5);
    gnutls_cipher_deinit(hd);
  } break;
  default:
    assert(0);
  }

  return rv;
}

static gnutls_record_encryption_level_t
from_ngtcp2_level(ngtcp2_crypto_level crypto_level) {
  switch (crypto_level) {
  case NGTCP2_CRYPTO_LEVEL_INITIAL:
    return GNUTLS_ENCRYPTION_LEVEL_INITIAL;
  case NGTCP2_CRYPTO_LEVEL_HANDSHAKE:
    return GNUTLS_ENCRYPTION_LEVEL_HANDSHAKE;
  case NGTCP2_CRYPTO_LEVEL_APP:
    return GNUTLS_ENCRYPTION_LEVEL_APPLICATION;
  case NGTCP2_CRYPTO_LEVEL_EARLY:
    return GNUTLS_ENCRYPTION_LEVEL_EARLY;
  default:
    assert(0);
  }
}

int ngtcp2_crypto_read_write_crypto_data(ngtcp2_conn *conn, void *tls,
                                         ngtcp2_crypto_level crypto_level,
                                         const uint8_t *data, size_t datalen) {
  gnutls_session_t session = tls;
  int rv;

  if (datalen > 0) {
    if (gnutls_handshake_write(session, from_ngtcp2_level(crypto_level), data,
                               datalen) != 0) {
      return -1;
    }
  }

  if (!ngtcp2_conn_get_handshake_completed(conn)) {
    rv = gnutls_handshake(session);
    if (rv < 0) {
      if (!gnutls_error_is_fatal(rv)) {
        return 0;
      }
      gnutls_alert_send_appropriate(session, rv);
      return -1;
    }

    ngtcp2_conn_handshake_completed(conn);
  }

  return 0;
}

int ngtcp2_crypto_set_remote_transport_params(ngtcp2_conn *conn, void *tls) {
  (void)conn;
  (void)tls;
  /* Nothing to do; GnuTLS applications are supposed to register the
     quic_transport_parameters extension with
     gnutls_session_ext_register. */
  return 0;
}
