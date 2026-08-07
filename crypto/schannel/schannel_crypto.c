/*
 * ngtcp2
 *
 * Copyright (c) 2026 ngtcp2 contributors
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
#endif /* defined(HAVE_CONFIG_H) */

#include "schannel_internal.h"
#include "shared.h"

#include <ngtcp2/ngtcp2_crypto.h>

#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct ngtcp2_schannel_key_ctx {
  BCRYPT_ALG_HANDLE alg;
  BCRYPT_KEY_HANDLE key;
  uint8_t *object;
  ULONG objectlen;
} ngtcp2_schannel_key_ctx;

static void *id_to_native_handle(int id) {
  return (void *)(intptr_t)id;
}

static int native_handle_to_id(const void *native_handle) {
  return (int)(intptr_t)native_handle;
}

static LPCWSTR md_algorithm(ngtcp2_schannel_md_id md_id) {
  switch (md_id) {
  case NGTCP2_SCHANNEL_MD_SHA256:
    return BCRYPT_SHA256_ALGORITHM;
  case NGTCP2_SCHANNEL_MD_SHA384:
    return BCRYPT_SHA384_ALGORITHM;
  default:
    return NULL;
  }
}

static size_t md_hashlen(ngtcp2_schannel_md_id md_id) {
  switch (md_id) {
  case NGTCP2_SCHANNEL_MD_SHA256:
    return 32;
  case NGTCP2_SCHANNEL_MD_SHA384:
    return 48;
  default:
    return 0;
  }
}

static size_t aead_keylen(ngtcp2_schannel_aead_id aead_id) {
  switch (aead_id) {
  case NGTCP2_SCHANNEL_AEAD_AES_128_GCM:
    return 16;
  case NGTCP2_SCHANNEL_AEAD_AES_256_GCM:
    return 32;
  default:
    return 0;
  }
}

static int size_to_ulong(ULONG *dest, size_t n) {
  if (n > ULONG_MAX) {
    return -1;
  }

  *dest = (ULONG)n;
  return 0;
}

static void key_ctx_free(ngtcp2_schannel_key_ctx *ctx) {
  if (ctx == NULL) {
    return;
  }

  if (ctx->key != NULL) {
    BCryptDestroyKey(ctx->key);
  }
  if (ctx->object != NULL) {
    SecureZeroMemory(ctx->object, ctx->objectlen);
    free(ctx->object);
  }
  if (ctx->alg != NULL) {
    BCryptCloseAlgorithmProvider(ctx->alg, 0);
  }

  SecureZeroMemory(ctx, sizeof(*ctx));
  free(ctx);
}

static int key_ctx_new(ngtcp2_schannel_key_ctx **pctx,
                       ngtcp2_schannel_aead_id aead_id, const uint8_t *key,
                       LPCWSTR chaining_mode) {
  ngtcp2_schannel_key_ctx *ctx;
  ULONG keylen, cbresult;
  NTSTATUS status;

  if (size_to_ulong(&keylen, aead_keylen(aead_id)) != 0 || keylen == 0) {
    return -1;
  }

  ctx = calloc(1, sizeof(*ctx));
  if (ctx == NULL) {
    return -1;
  }

  status = BCryptOpenAlgorithmProvider(&ctx->alg, BCRYPT_AES_ALGORITHM, NULL, 0);
  if (status < 0) {
    goto fail;
  }

  status = BCryptSetProperty(ctx->alg, BCRYPT_CHAINING_MODE,
                             (PUCHAR)chaining_mode,
                             (ULONG)((wcslen(chaining_mode) + 1) *
                                     sizeof(*chaining_mode)),
                             0);
  if (status < 0) {
    goto fail;
  }

  status = BCryptGetProperty(ctx->alg, BCRYPT_OBJECT_LENGTH,
                             (PUCHAR)&ctx->objectlen,
                             sizeof(ctx->objectlen), &cbresult, 0);
  if (status < 0) {
    goto fail;
  }

  ctx->object = malloc(ctx->objectlen);
  if (ctx->object == NULL) {
    goto fail;
  }

  status = BCryptGenerateSymmetricKey(ctx->alg, &ctx->key, ctx->object,
                                      ctx->objectlen, (PUCHAR)key, keylen, 0);
  if (status < 0) {
    goto fail;
  }

  *pctx = ctx;
  return 0;

fail:
  key_ctx_free(ctx);
  return -1;
}

static int hmac(uint8_t *dest, ngtcp2_schannel_md_id md_id,
                const uint8_t *key, size_t keylen, const uint8_t *part1,
                size_t part1len, const uint8_t *part2, size_t part2len,
                const uint8_t *part3, size_t part3len) {
  BCRYPT_ALG_HANDLE alg = NULL;
  BCRYPT_HASH_HANDLE hash = NULL;
  uint8_t *object = NULL;
  ULONG objectlen = 0, cbresult, ulen;
  size_t hashlen = md_hashlen(md_id);
  LPCWSTR algorithm = md_algorithm(md_id);
  NTSTATUS status;
  int rv = -1;

  if (algorithm == NULL || size_to_ulong(&ulen, keylen) != 0) {
    return -1;
  }

  status = BCryptOpenAlgorithmProvider(&alg, algorithm, NULL,
                                       BCRYPT_ALG_HANDLE_HMAC_FLAG);
  if (status < 0) {
    goto cleanup;
  }

  status = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objectlen,
                             sizeof(objectlen), &cbresult, 0);
  if (status < 0) {
    goto cleanup;
  }

  object = malloc(objectlen);
  if (object == NULL) {
    goto cleanup;
  }

  status = BCryptCreateHash(alg, &hash, object, objectlen, (PUCHAR)key, ulen, 0);
  if (status < 0) {
    goto cleanup;
  }

#define HASH_PART(part, partlen)                                                \
  do {                                                                         \
    if ((partlen) != 0) {                                                       \
      if (size_to_ulong(&ulen, (partlen)) != 0) {                               \
        goto cleanup;                                                           \
      }                                                                         \
      status = BCryptHashData(hash, (PUCHAR)(part), ulen, 0);                   \
      if (status < 0) {                                                         \
        goto cleanup;                                                           \
      }                                                                         \
    }                                                                           \
  } while (0)

  HASH_PART(part1, part1len);
  HASH_PART(part2, part2len);
  HASH_PART(part3, part3len);

#undef HASH_PART

  status = BCryptFinishHash(hash, dest, (ULONG)hashlen, 0);
  if (status < 0) {
    goto cleanup;
  }

  rv = 0;

cleanup:
  if (hash != NULL) {
    BCryptDestroyHash(hash);
  }
  if (object != NULL) {
    SecureZeroMemory(object, objectlen);
    free(object);
  }
  if (alg != NULL) {
    BCryptCloseAlgorithmProvider(alg, 0);
  }
  return rv;
}

ngtcp2_crypto_aead *ngtcp2_crypto_aead_aes_128_gcm(ngtcp2_crypto_aead *aead) {
  return ngtcp2_crypto_aead_init(
    aead, id_to_native_handle(NGTCP2_SCHANNEL_AEAD_AES_128_GCM));
}

ngtcp2_crypto_md *ngtcp2_crypto_md_sha256(ngtcp2_crypto_md *md) {
  md->native_handle = id_to_native_handle(NGTCP2_SCHANNEL_MD_SHA256);
  return md;
}

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_initial(ngtcp2_crypto_ctx *ctx) {
  ngtcp2_crypto_aead_aes_128_gcm(&ctx->aead);
  ngtcp2_crypto_md_sha256(&ctx->md);
  ctx->hp.native_handle =
    id_to_native_handle(NGTCP2_SCHANNEL_AEAD_AES_128_GCM);
  ctx->max_encryption = 0;
  ctx->max_decryption_failure = 0;
  return ctx;
}

ngtcp2_crypto_aead *ngtcp2_crypto_aead_init(ngtcp2_crypto_aead *aead,
                                            void *aead_native_handle) {
  aead->native_handle = aead_native_handle;
  aead->max_overhead = 16;
  return aead;
}

ngtcp2_crypto_aead *ngtcp2_crypto_aead_retry(ngtcp2_crypto_aead *aead) {
  return ngtcp2_crypto_aead_aes_128_gcm(aead);
}

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_tls(ngtcp2_crypto_ctx *ctx,
                                         void *tls_native_handle) {
  ngtcp2_crypto_schannel *schannel = tls_native_handle;

  if (schannel == NULL || schannel->aead_id == NGTCP2_SCHANNEL_AEAD_NONE ||
      schannel->md_id == NGTCP2_SCHANNEL_MD_NONE) {
    return NULL;
  }

  ngtcp2_crypto_aead_init(&ctx->aead,
                          id_to_native_handle(schannel->aead_id));
  ctx->md.native_handle = id_to_native_handle(schannel->md_id);
  ctx->hp.native_handle = id_to_native_handle(schannel->aead_id);
  ctx->max_encryption = NGTCP2_CRYPTO_MAX_ENCRYPTION_AES_GCM;
  ctx->max_decryption_failure =
    NGTCP2_CRYPTO_MAX_DECRYPTION_FAILURE_AES_GCM;
  return ctx;
}

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_tls_early(ngtcp2_crypto_ctx *ctx,
                                               void *tls_native_handle) {
  (void)ctx;
  (void)tls_native_handle;
  return NULL;
}

size_t ngtcp2_crypto_md_hashlen(const ngtcp2_crypto_md *md) {
  return md_hashlen((ngtcp2_schannel_md_id)native_handle_to_id(
    md->native_handle));
}

size_t ngtcp2_crypto_aead_keylen(const ngtcp2_crypto_aead *aead) {
  return aead_keylen((ngtcp2_schannel_aead_id)native_handle_to_id(
    aead->native_handle));
}

size_t ngtcp2_crypto_aead_noncelen(const ngtcp2_crypto_aead *aead) {
  (void)aead;
  return 12;
}

int ngtcp2_crypto_aead_ctx_encrypt_init(ngtcp2_crypto_aead_ctx *aead_ctx,
                                        const ngtcp2_crypto_aead *aead,
                                        const uint8_t *key, size_t noncelen) {
  ngtcp2_schannel_key_ctx *ctx;

  if (noncelen != 12 ||
      key_ctx_new(&ctx,
                  (ngtcp2_schannel_aead_id)native_handle_to_id(
                    aead->native_handle),
                  key, BCRYPT_CHAIN_MODE_GCM) != 0) {
    return -1;
  }

  aead_ctx->native_handle = ctx;
  return 0;
}

int ngtcp2_crypto_aead_ctx_decrypt_init(ngtcp2_crypto_aead_ctx *aead_ctx,
                                        const ngtcp2_crypto_aead *aead,
                                        const uint8_t *key, size_t noncelen) {
  return ngtcp2_crypto_aead_ctx_encrypt_init(aead_ctx, aead, key, noncelen);
}

void ngtcp2_crypto_aead_ctx_free(ngtcp2_crypto_aead_ctx *aead_ctx) {
  key_ctx_free(aead_ctx->native_handle);
  aead_ctx->native_handle = NULL;
}

int ngtcp2_crypto_cipher_ctx_encrypt_init(ngtcp2_crypto_cipher_ctx *cipher_ctx,
                                          const ngtcp2_crypto_cipher *cipher,
                                          const uint8_t *key) {
  ngtcp2_schannel_key_ctx *ctx;

  if (key_ctx_new(&ctx,
                  (ngtcp2_schannel_aead_id)native_handle_to_id(
                    cipher->native_handle),
                  key, BCRYPT_CHAIN_MODE_ECB) != 0) {
    return -1;
  }

  cipher_ctx->native_handle = ctx;
  return 0;
}

void ngtcp2_crypto_cipher_ctx_free(ngtcp2_crypto_cipher_ctx *cipher_ctx) {
  key_ctx_free(cipher_ctx->native_handle);
  cipher_ctx->native_handle = NULL;
}

int ngtcp2_crypto_hkdf_extract(uint8_t *dest, const ngtcp2_crypto_md *md,
                               const uint8_t *secret, size_t secretlen,
                               const uint8_t *salt, size_t saltlen) {
  ngtcp2_schannel_md_id md_id =
    (ngtcp2_schannel_md_id)native_handle_to_id(md->native_handle);
  uint8_t zero_salt[64] = {0};
  size_t hashlen = md_hashlen(md_id);

  if (hashlen == 0) {
    return -1;
  }

  if (saltlen == 0) {
    salt = zero_salt;
    saltlen = hashlen;
  }

  return hmac(dest, md_id, salt, saltlen, secret, secretlen, NULL, 0, NULL,
              0);
}

int ngtcp2_crypto_hkdf_expand(uint8_t *dest, size_t destlen,
                              const ngtcp2_crypto_md *md, const uint8_t *secret,
                              size_t secretlen, const uint8_t *info,
                              size_t infolen) {
  ngtcp2_schannel_md_id md_id =
    (ngtcp2_schannel_md_id)native_handle_to_id(md->native_handle);
  uint8_t t[64] = {0}, counter;
  size_t hashlen = md_hashlen(md_id), tlen = 0, nwrite;
  uint16_t block = 1;

  if (hashlen == 0 || destlen > 255 * hashlen) {
    return -1;
  }

  while (destlen != 0) {
    counter = (uint8_t)block++;
    if (hmac(t, md_id, secret, secretlen, t, tlen, info, infolen, &counter,
             1) != 0) {
      SecureZeroMemory(t, sizeof(t));
      return -1;
    }

    nwrite = destlen < hashlen ? destlen : hashlen;
    memcpy(dest, t, nwrite);
    dest += nwrite;
    destlen -= nwrite;
    tlen = hashlen;
  }

  SecureZeroMemory(t, sizeof(t));
  return 0;
}

int ngtcp2_crypto_hkdf(uint8_t *dest, size_t destlen,
                       const ngtcp2_crypto_md *md, const uint8_t *secret,
                       size_t secretlen, const uint8_t *salt, size_t saltlen,
                       const uint8_t *info, size_t infolen) {
  uint8_t prk[64];
  size_t hashlen = ngtcp2_crypto_md_hashlen(md);
  int rv;

  if (hashlen == 0 || ngtcp2_crypto_hkdf_extract(prk, md, secret, secretlen,
                                                 salt, saltlen) != 0) {
    return -1;
  }

  rv = ngtcp2_crypto_hkdf_expand(dest, destlen, md, prk, hashlen, info,
                                 infolen);
  SecureZeroMemory(prk, sizeof(prk));
  return rv;
}

int ngtcp2_crypto_encrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                          const ngtcp2_crypto_aead_ctx *aead_ctx,
                          const uint8_t *plaintext, size_t plaintextlen,
                          const uint8_t *nonce, size_t noncelen,
                          const uint8_t *aad, size_t aadlen) {
  ngtcp2_schannel_key_ctx *ctx = aead_ctx->native_handle;
  BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
  ULONG plaintextlen32, noncelen32, aadlen32, result;
  NTSTATUS status;

  (void)aead;

  if (ctx == NULL || size_to_ulong(&plaintextlen32, plaintextlen) != 0 ||
      size_to_ulong(&noncelen32, noncelen) != 0 ||
      size_to_ulong(&aadlen32, aadlen) != 0) {
    return -1;
  }

  BCRYPT_INIT_AUTH_MODE_INFO(auth);
  auth.pbNonce = (PUCHAR)nonce;
  auth.cbNonce = noncelen32;
  auth.pbAuthData = (PUCHAR)aad;
  auth.cbAuthData = aadlen32;
  auth.pbTag = dest + plaintextlen;
  auth.cbTag = 16;

  status = BCryptEncrypt(ctx->key, (PUCHAR)plaintext, plaintextlen32, &auth,
                         NULL, 0, dest, plaintextlen32, &result, 0);
  return status < 0 || result != plaintextlen32 ? -1 : 0;
}

int ngtcp2_crypto_decrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                          const ngtcp2_crypto_aead_ctx *aead_ctx,
                          const uint8_t *ciphertext, size_t ciphertextlen,
                          const uint8_t *nonce, size_t noncelen,
                          const uint8_t *aad, size_t aadlen) {
  ngtcp2_schannel_key_ctx *ctx = aead_ctx->native_handle;
  BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
  ULONG plaintextlen32, noncelen32, aadlen32, result;
  size_t plaintextlen;
  NTSTATUS status;

  (void)aead;

  if (ctx == NULL || ciphertextlen < 16) {
    return -1;
  }

  plaintextlen = ciphertextlen - 16;
  if (size_to_ulong(&plaintextlen32, plaintextlen) != 0 ||
      size_to_ulong(&noncelen32, noncelen) != 0 ||
      size_to_ulong(&aadlen32, aadlen) != 0) {
    return -1;
  }

  BCRYPT_INIT_AUTH_MODE_INFO(auth);
  auth.pbNonce = (PUCHAR)nonce;
  auth.cbNonce = noncelen32;
  auth.pbAuthData = (PUCHAR)aad;
  auth.cbAuthData = aadlen32;
  auth.pbTag = (PUCHAR)ciphertext + plaintextlen;
  auth.cbTag = 16;

  status = BCryptDecrypt(ctx->key, (PUCHAR)ciphertext, plaintextlen32, &auth,
                         NULL, 0, dest, plaintextlen32, &result, 0);
  return status < 0 || result != plaintextlen32 ? -1 : 0;
}

int ngtcp2_crypto_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                          const ngtcp2_crypto_cipher_ctx *hp_ctx,
                          const uint8_t *sample) {
  ngtcp2_schannel_key_ctx *ctx = hp_ctx->native_handle;
  uint8_t block[16];
  ULONG result;
  NTSTATUS status;

  (void)hp;

  if (ctx == NULL) {
    return -1;
  }

  status = BCryptEncrypt(ctx->key, (PUCHAR)sample, 16, NULL, NULL, 0, block,
                         sizeof(block), &result, 0);
  if (status < 0 || result != sizeof(block)) {
    SecureZeroMemory(block, sizeof(block));
    return -1;
  }

  memcpy(dest, block, 5);
  SecureZeroMemory(block, sizeof(block));
  return 0;
}

int ngtcp2_crypto_random(uint8_t *data, size_t datalen) {
  ULONG nwrite;

  while (datalen != 0) {
    nwrite = datalen > ULONG_MAX ? ULONG_MAX : (ULONG)datalen;
    if (BCryptGenRandom(NULL, data, nwrite,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
      return -1;
    }
    data += nwrite;
    datalen -= nwrite;
  }

  return 0;
}

int ngtcp2_crypto_get_path_challenge_data_cb(ngtcp2_conn *conn, uint8_t *data,
                                             void *user_data) {
  (void)conn;
  (void)user_data;
  return ngtcp2_crypto_random(data, NGTCP2_PATH_CHALLENGE_DATALEN) == 0
           ? 0
           : NGTCP2_ERR_CALLBACK_FAILURE;
}

int ngtcp2_crypto_get_path_challenge_data2_cb(ngtcp2_conn *conn,
                                              ngtcp2_path_challenge_data *data,
                                              void *user_data) {
  return ngtcp2_crypto_get_path_challenge_data_cb(conn, data->data, user_data);
}

int ngtcp2_schannel_set_algorithm(
  ngtcp2_crypto_schannel *schannel,
  const SEC_TRAFFIC_SECRETS *traffic_secret) {
  ngtcp2_schannel_aead_id aead_id;
  ngtcp2_schannel_md_id md_id;

  if (wcscmp(traffic_secret->SymmetricAlgId, BCRYPT_AES_ALGORITHM) != 0 ||
      wcscmp(traffic_secret->ChainingMode, BCRYPT_CHAIN_MODE_GCM) != 0 ||
      traffic_secret->IvSize != 12) {
    return -1;
  }

  switch (traffic_secret->KeySize) {
  case 16:
    aead_id = NGTCP2_SCHANNEL_AEAD_AES_128_GCM;
    break;
  case 32:
    aead_id = NGTCP2_SCHANNEL_AEAD_AES_256_GCM;
    break;
  default:
    return -1;
  }

  if (wcscmp(traffic_secret->HashAlgId, BCRYPT_SHA256_ALGORITHM) == 0) {
    md_id = NGTCP2_SCHANNEL_MD_SHA256;
  } else if (wcscmp(traffic_secret->HashAlgId, BCRYPT_SHA384_ALGORITHM) == 0) {
    md_id = NGTCP2_SCHANNEL_MD_SHA384;
  } else {
    return -1;
  }

  if ((schannel->aead_id != NGTCP2_SCHANNEL_AEAD_NONE &&
       schannel->aead_id != aead_id) ||
      (schannel->md_id != NGTCP2_SCHANNEL_MD_NONE &&
       schannel->md_id != md_id)) {
    return -1;
  }

  schannel->aead_id = aead_id;
  schannel->md_id = md_id;
  return 0;
}
