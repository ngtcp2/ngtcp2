/*
 * ngtcp2
 *
 * Copyright (c) 2025 ngtcp2 contributors
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
#include <stdlib.h>
#include <assert.h>
#include <sys/queue.h>
#include <assert.h>

#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_openssl.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#  include <openssl/core_names.h>

#include "shared.h"

#ifdef OPENSSL_DEBUG
#define DBG(format, args...) fprintf(stderr, "OPENSSL: " format, ##args)
#else
#define DBG(format, ...)
#endif

static int crypto_initialized;
static EVP_CIPHER *crypto_aes_128_gcm;
static EVP_CIPHER *crypto_aes_256_gcm;
static EVP_CIPHER *crypto_chacha20_poly1305;
static EVP_CIPHER *crypto_aes_128_ccm;
static EVP_CIPHER *crypto_aes_128_ctr;
static EVP_CIPHER *crypto_aes_256_ctr;
static EVP_CIPHER *crypto_chacha20;
static EVP_MD *crypto_sha256;
static EVP_MD *crypto_sha384;
static EVP_KDF *crypto_hkdf;
static ngtcp2_encryption_level enc_level;

/**
 * @struct record_entry
 * @brief Represents a single record in a queue of SSL records.
 *
 * This structure holds the data and metadata for an individual record
 * processed in an SSL context. It is typically used in a linked list.
 */
struct record_entry {
  /**
   * @brief Pointer to the record data.
   */
  uint8_t *record;

  /**
   * @brief Length of the record data in bytes.
   */
  size_t rec_len;

  /**
   * @brief Indicates if the record is incomplete.
   *
   * 0 means complete, non-zero means incomplete.
   */
  uint8_t incomplete;

  /**
   * @brief Pointer to the SSL connection context associated with the record.
   */
  SSL *ssl;

  /**
   * @brief Queue entry to link multiple record entries together.
   */
  STAILQ_ENTRY(record_entry) entries;
};

/**
 * @brief Head of a singly-linked tail queue of record_entry structures.
 *
 * This list holds all record entries currently managed or processed.
 */
STAILQ_HEAD(record_list, record_entry);

#define get_ssl_rx_queue(s) (struct record_list *)BIO_get_app_data(SSL_get_rbio(s))

/**
 * @brief Initializes cryptographic primitives using OpenSSL.
 *
 * This function fetches and initializes various cryptographic algorithms
 * required by ngtcp2, including AES-GCM, ChaCha20-Poly1305, AES-CCM,
 * AES-CTR ciphers, SHA-256 and SHA-384 message digests, and the HKDF
 * key derivation function.
 *
 * @return
 * - 0 on successful initialization.
 * - -1 if any of the required algorithms fail to load.
 */
int ngtcp2_crypto_openssl_init(void) {
  crypto_aes_128_gcm = EVP_CIPHER_fetch(NULL, "AES-128-GCM", NULL);
  if (crypto_aes_128_gcm == NULL) {
    return -1;
  }

  crypto_aes_256_gcm = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
  if (crypto_aes_256_gcm == NULL) {
    return -1;
  }

  crypto_chacha20_poly1305 = EVP_CIPHER_fetch(NULL, "ChaCha20-Poly1305", NULL);
  if (crypto_chacha20_poly1305 == NULL) {
    return -1;
  }

  crypto_aes_128_ccm = EVP_CIPHER_fetch(NULL, "AES-128-CCM", NULL);
  if (crypto_aes_128_ccm == NULL) {
    return -1;
  }

  crypto_aes_128_ctr = EVP_CIPHER_fetch(NULL, "AES-128-CTR", NULL);
  if (crypto_aes_128_ctr == NULL) {
    return -1;
  }

  crypto_aes_256_ctr = EVP_CIPHER_fetch(NULL, "AES-256-CTR", NULL);
  if (crypto_aes_256_ctr == NULL) {
    return -1;
  }

  crypto_chacha20 = EVP_CIPHER_fetch(NULL, "ChaCha20", NULL);
  if (crypto_chacha20 == NULL) {
    return -1;
  }

  crypto_sha256 = EVP_MD_fetch(NULL, "sha256", NULL);
  if (crypto_sha256 == NULL) {
    return -1;
  }

  crypto_sha384 = EVP_MD_fetch(NULL, "sha384", NULL);
  if (crypto_sha384 == NULL) {
    return -1;
  }

  crypto_hkdf = EVP_KDF_fetch(NULL, "hkdf", NULL);
  if (crypto_hkdf == NULL) {
    return -1;
  }

  crypto_initialized = 1;

  return 0;
}

/**
 * @brief Returns the EVP_CIPHER for AES-128-GCM.
 *
 * This function returns a pointer to the cached EVP_CIPHER object for
 * AES-128-GCM if it has been initialized. If not, it falls back to the
 * built-in EVP_aes_128_gcm() implementation.
 *
 * @return A pointer to the EVP_CIPHER for AES-128-GCM.
 */
static const EVP_CIPHER *crypto_aead_aes_128_gcm(void) {
  if (crypto_aes_128_gcm) {
  return crypto_aes_128_gcm;
  }

  return EVP_aes_128_gcm();
}

/**
 * @brief Returns the EVP_CIPHER for AES-256-GCM.
 *
 * This function returns a pointer to the cached EVP_CIPHER object for
 * AES-256-GCM if it has been initialized. If not, it returns the default
 * built-in EVP_aes_256_gcm() implementation.
 *
 * @return A pointer to the EVP_CIPHER for AES-256-GCM.
 */
static const EVP_CIPHER *crypto_aead_aes_256_gcm(void) {
  if (crypto_aes_256_gcm) {
    return crypto_aes_256_gcm;
  }

  return EVP_aes_256_gcm();
}

/**
 * @brief Returns the EVP_CIPHER for ChaCha20-Poly1305.
 *
 * This function returns a pointer to the cached EVP_CIPHER object for
 * ChaCha20-Poly1305 if it has been initialized. If not, it returns the
 * built-in EVP_chacha20_poly1305() implementation.
 *
 * @return A pointer to the EVP_CIPHER for ChaCha20-Poly1305.
 */
static const EVP_CIPHER *crypto_aead_chacha20_poly1305(void) {
  if (crypto_chacha20_poly1305) {
    return crypto_chacha20_poly1305;
  }

  return EVP_chacha20_poly1305();
}

/**
 * @brief Returns the EVP_CIPHER for AES-128-CCM.
 *
 * This function returns a pointer to the cached EVP_CIPHER object for
 * AES-128-CCM if it has been initialized. If not, it returns the default
 * built-in EVP_aes_128_ccm() implementation.
 *
 * @return A pointer to the EVP_CIPHER for AES-128-CCM.
 */
static const EVP_CIPHER *crypto_aead_aes_128_ccm(void) {
  if (crypto_aes_128_ccm) {
    return crypto_aes_128_ccm;
  }

  return EVP_aes_128_ccm();
}

/**
 * @brief Returns the EVP_CIPHER for AES-128-CTR.
 *
 * This function returns a pointer to the cached EVP_CIPHER object for
 * AES-128-CTR if it has been initialized. If not, it returns the default
 * built-in EVP_aes_128_ctr() implementation.
 *
 * @return A pointer to the EVP_CIPHER for AES-128-CTR.
 */
static const EVP_CIPHER *crypto_cipher_aes_128_ctr(void) {
  if (crypto_aes_128_ctr) {
    return crypto_aes_128_ctr;
  }

  return EVP_aes_128_ctr();
}

/**
 * @brief Returns the EVP_CIPHER for AES-256-CTR.
 *
 * This function returns a pointer to the cached EVP_CIPHER object for
 * AES-256-CTR if it has been initialized. If not, it returns the default
 * built-in EVP_aes_256_ctr() implementation.
 *
 * @return A pointer to the EVP_CIPHER for AES-256-CTR.
 */
static const EVP_CIPHER *crypto_cipher_aes_256_ctr(void) {
  if (crypto_aes_256_ctr) {
    return crypto_aes_256_ctr;
  }

  return EVP_aes_256_ctr();
}

/**
 * @brief Returns the EVP_CIPHER for ChaCha20.
 *
 * This function returns a pointer to the cached EVP_CIPHER object for
 * ChaCha20 if it has been initialized. If not, it returns the default
 * built-in EVP_chacha20() implementation.
 *
 * @return A pointer to the EVP_CIPHER for ChaCha20.
 */
static const EVP_CIPHER *crypto_cipher_chacha20(void) {
  if (crypto_chacha20) {
    return crypto_chacha20;
  }

  return EVP_chacha20();
}

/**
 * @brief Returns the EVP_MD for SHA-256.
 *
 * This function returns a pointer to the cached EVP_MD object for
 * SHA-256 if it has been initialized. If not, it returns the default
 * built-in EVP_sha256() implementation.
 *
 * @return A pointer to the EVP_MD for SHA-256.
 */
static const EVP_MD *crypto_md_sha256(void) {
  if (crypto_sha256) {
    return crypto_sha256;
  }

  return EVP_sha256();
}

/**
 * @brief Returns the EVP_MD for SHA-384.
 *
 * This function returns a pointer to the cached EVP_MD object for
 * SHA-384 if it has been initialized. If not, it returns the default
 * built-in EVP_sha384() implementation.
 *
 * @return A pointer to the EVP_MD for SHA-384.
 */
static const EVP_MD *crypto_md_sha384(void) {
  if (crypto_sha384) {
    return crypto_sha384;
  }

  return EVP_sha384();
}

/**
 * @brief Returns the EVP_KDF for HKDF.
 *
 * This function returns a pointer to the cached EVP_KDF object for
 * HKDF if it has been initialized. If not, it fetches and returns a
 * new HKDF instance using EVP_KDF_fetch().
 *
 * @return A pointer to the EVP_KDF for HKDF.
 */
static EVP_KDF *crypto_kdf_hkdf(void) {
  if (crypto_hkdf) {
    return crypto_hkdf;
  }

  return EVP_KDF_fetch(NULL, "hkdf", NULL);
}

/**
 * @brief Returns the maximum overhead of the given AEAD cipher.
 *
 * This function returns the maximum number of additional bytes that an
 * AEAD cipher may add to the ciphertext for authentication tags.
 *
 * Supported ciphers:
 * - AES-128-GCM and AES-256-GCM: EVP_GCM_TLS_TAG_LEN bytes.
 * - ChaCha20-Poly1305: EVP_CHACHAPOLY_TLS_TAG_LEN bytes.
 * - AES-128-CCM: EVP_CCM_TLS_TAG_LEN bytes.
 *
 * If an unsupported cipher is provided, the function aborts.
 *
 * @param aead Pointer to the EVP_CIPHER AEAD cipher.
 * @return Maximum overhead in bytes.
 */
static size_t crypto_aead_max_overhead(const EVP_CIPHER *aead) {
  switch (EVP_CIPHER_nid(aead)) {
  case NID_aes_128_gcm:
  case NID_aes_256_gcm:
    return EVP_GCM_TLS_TAG_LEN;
  case NID_chacha20_poly1305:
    return EVP_CHACHAPOLY_TLS_TAG_LEN;
  case NID_aes_128_ccm:
    return EVP_CCM_TLS_TAG_LEN;
  default:
    assert(0);
    abort(); /* if NDEBUG is set */
  }
}

/**
 * @brief Initializes an ngtcp2_crypto_aead object with AES-128-GCM.
 *
 * This function initializes the provided ngtcp2_crypto_aead structure
 * with the AES-128-GCM cipher.
 *
 * @param aead Pointer to the ngtcp2_crypto_aead to initialize.
 * @return The initialized ngtcp2_crypto_aead pointer.
 */
ngtcp2_crypto_aead *ngtcp2_crypto_aead_aes_128_gcm(ngtcp2_crypto_aead *aead) {
  return ngtcp2_crypto_aead_init(aead, (void *)crypto_aead_aes_128_gcm());
}

/**
 * @brief Initializes an ngtcp2_crypto_md object with SHA-256.
 *
 * This function sets the native_handle of the provided
 * ngtcp2_crypto_md structure to the SHA-256 message digest.
 *
 * @param md Pointer to the ngtcp2_crypto_md to initialize.
 * @return The initialized ngtcp2_crypto_md pointer.
 */
ngtcp2_crypto_md *ngtcp2_crypto_md_sha256(ngtcp2_crypto_md *md) {
  md->native_handle = (void *)crypto_md_sha256();
  return md;
}

/**
 * @brief Initializes an ngtcp2_crypto_ctx object for Initial secrets.
 *
 * This function initializes the provided ngtcp2_crypto_ctx structure
 * using ciphers and digests required for QUIC Initial packets:
 * - AEAD: AES-128-GCM
 * - Hash: SHA-256
 * - Header protection: AES-128-CTR
 *
 * It also sets max_encryption and max_decryption_failure to zero.
 *
 * @param ctx Pointer to the ngtcp2_crypto_ctx to initialize.
 * @return The initialized ngtcp2_crypto_ctx pointer.
 */
ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_initial(ngtcp2_crypto_ctx *ctx) {
  ngtcp2_crypto_aead_init(&ctx->aead, (void *)crypto_aead_aes_128_gcm());
  ctx->md.native_handle = (void *)crypto_md_sha256();
  ctx->hp.native_handle = (void *)crypto_cipher_aes_128_ctr();
  ctx->max_encryption = 0;
  ctx->max_decryption_failure = 0;
  return ctx;
}

/**
 * @brief Initializes an ngtcp2_crypto_aead object with a native handle.
 *
 * This function sets the native_handle and max_overhead fields of the
 * ngtcp2_crypto_aead structure using the provided AEAD cipher handle.
 *
 * @param aead Pointer to the ngtcp2_crypto_aead to initialize.
 * @param aead_native_handle Native handle to the AEAD cipher.
 * @return The initialized ngtcp2_crypto_aead pointer.
 */
ngtcp2_crypto_aead *ngtcp2_crypto_aead_init(ngtcp2_crypto_aead *aead,
                                          void *aead_native_handle) {
  aead->native_handle = aead_native_handle;
  aead->max_overhead = crypto_aead_max_overhead(aead_native_handle);
  return aead;
}

/**
 * @brief Initializes an ngtcp2_crypto_aead object for Retry packet protection.
 *
 * This function initializes the provided ngtcp2_crypto_aead structure
 * using AES-128-GCM, as required for protecting Retry packets.
 *
 * @param aead Pointer to the ngtcp2_crypto_aead to initialize.
 * @return The initialized ngtcp2_crypto_aead pointer.
 */
ngtcp2_crypto_aead *ngtcp2_crypto_aead_retry(ngtcp2_crypto_aead *aead) {
  return ngtcp2_crypto_aead_init(aead, (void *)crypto_aead_aes_128_gcm());
}

/**
 * @brief Returns the EVP_CIPHER AEAD cipher for the given cipher ID.
 *
 * This function returns a pointer to the AEAD EVP_CIPHER implementation
 * corresponding to the provided TLS 1.3 cipher suite ID.
 *
 * Supported cipher IDs:
 * - TLS1_3_CK_AES_128_GCM_SHA256
 * - TLS1_3_CK_AES_256_GCM_SHA384
 * - TLS1_3_CK_CHACHA20_POLY1305_SHA256
 * - TLS1_3_CK_AES_128_CCM_SHA256
 *
 * If the cipher ID is not recognized, returns NULL.
 *
 * @param cipher_id TLS 1.3 cipher suite ID.
 * @return Pointer to the corresponding EVP_CIPHER, or NULL if not found.
 */
static const EVP_CIPHER *crypto_cipher_id_get_aead(uint32_t cipher_id) {
  switch (cipher_id) {
  case TLS1_3_CK_AES_128_GCM_SHA256:
    return crypto_aead_aes_128_gcm();
  case TLS1_3_CK_AES_256_GCM_SHA384:
    return crypto_aead_aes_256_gcm();
  case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
    return crypto_aead_chacha20_poly1305();
  case TLS1_3_CK_AES_128_CCM_SHA256:
    return crypto_aead_aes_128_ccm();
  default:
    return NULL;
  }
}

/**
 * @brief Returns the maximum encryption limit for the given cipher ID.
 *
 * This function returns the maximum number of packets that can be safely
 * encrypted with a given TLS 1.3 cipher suite. Different AEAD algorithms
 * have different limits.
 *
 * Supported cipher IDs and their limits:
 * - AES-GCM (AES-128/256): NGTCP2_CRYPTO_MAX_ENCRYPTION_AES_GCM
 * - ChaCha20-Poly1305: NGTCP2_CRYPTO_MAX_ENCRYPTION_CHACHA20_POLY1305
 * - AES-CCM: NGTCP2_CRYPTO_MAX_ENCRYPTION_AES_CCM
 *
 * If the cipher ID is not recognized, returns 0.
 *
 * @param cipher_id TLS 1.3 cipher suite ID.
 * @return Maximum encryption limit, or 0 if the cipher is unsupported.
 */
static uint64_t crypto_cipher_id_get_aead_max_encryption(uint32_t cipher_id) {
  switch (cipher_id) {
  case TLS1_3_CK_AES_128_GCM_SHA256:
  case TLS1_3_CK_AES_256_GCM_SHA384:
    return NGTCP2_CRYPTO_MAX_ENCRYPTION_AES_GCM;
  case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
    return NGTCP2_CRYPTO_MAX_ENCRYPTION_CHACHA20_POLY1305;
  case TLS1_3_CK_AES_128_CCM_SHA256:
    return NGTCP2_CRYPTO_MAX_ENCRYPTION_AES_CCM;
  default:
    return 0;
  }
}

/**
 * @brief Returns the maximum allowed decryption failures for the cipher ID.
 *
 * This function returns the maximum number of tolerated decryption failures
 * before a connection should be closed. The limits vary depending on the AEAD
 * algorithm used in the specified TLS 1.3 cipher suite.
 *
 * Supported cipher IDs and their limits:
 * - AES-GCM (AES-128/256): NGTCP2_CRYPTO_MAX_DECRYPTION_FAILURE_AES_GCM
 * - ChaCha20-Poly1305: NGTCP2_CRYPTO_MAX_DECRYPTION_FAILURE_CHACHA20_POLY1305
 * - AES-CCM: NGTCP2_CRYPTO_MAX_DECRYPTION_FAILURE_AES_CCM
 *
 * If the cipher ID is not recognized, returns 0.
 *
 * @param cipher_id TLS 1.3 cipher suite ID.
 * @return Maximum number of allowed decryption failures, or 0 if unsupported.
 */
static uint64_t
crypto_cipher_id_get_aead_max_decryption_failure(uint32_t cipher_id) {
  switch (cipher_id) {
  case TLS1_3_CK_AES_128_GCM_SHA256:
  case TLS1_3_CK_AES_256_GCM_SHA384:
    return NGTCP2_CRYPTO_MAX_DECRYPTION_FAILURE_AES_GCM;
  case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
    return NGTCP2_CRYPTO_MAX_DECRYPTION_FAILURE_CHACHA20_POLY1305;
  case TLS1_3_CK_AES_128_CCM_SHA256:
    return NGTCP2_CRYPTO_MAX_DECRYPTION_FAILURE_AES_CCM;
  default:
    return 0;
  }
}

/**
 * @brief Returns the header protection cipher for the given cipher ID.
 *
 * This function returns a pointer to the EVP_CIPHER used for header protection
 * based on the specified TLS 1.3 cipher suite.
 *
 * Supported cipher IDs and their header protection ciphers:
 * - AES-128-GCM and AES-128-CCM: AES-128-CTR
 * - AES-256-GCM: AES-256-CTR
 * - ChaCha20-Poly1305: ChaCha20
 *
 * If the cipher ID is not recognized, returns NULL.
 *
 * @param cipher_id TLS 1.3 cipher suite ID.
 * @return Pointer to the EVP_CIPHER used for header protection, or NULL.
 */
static const EVP_CIPHER *crypto_cipher_id_get_hp(uint32_t cipher_id) {
  switch (cipher_id) {
  case TLS1_3_CK_AES_128_GCM_SHA256:
  case TLS1_3_CK_AES_128_CCM_SHA256:
    return crypto_cipher_aes_128_ctr();
  case TLS1_3_CK_AES_256_GCM_SHA384:
    return crypto_cipher_aes_256_ctr();
  case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
    return crypto_cipher_chacha20();
  default:
    return NULL;
  }
}

/**
 * @brief Returns the message digest for the given cipher ID.
 *
 * This function returns a pointer to the EVP_MD (message digest) used by
 * the specified TLS 1.3 cipher suite.
 *
 * Supported cipher IDs and their message digests:
 * - AES-128-GCM, ChaCha20-Poly1305, AES-128-CCM: SHA-256
 * - AES-256-GCM: SHA-384
 *
 * If the cipher ID is not recognized, returns NULL.
 *
 * @param cipher_id TLS 1.3 cipher suite ID.
 * @return Pointer to the EVP_MD, or NULL if the cipher ID is unsupported.
 */
static const EVP_MD *crypto_cipher_id_get_md(uint32_t cipher_id) {
  switch (cipher_id) {
  case TLS1_3_CK_AES_128_GCM_SHA256:
  case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
  case TLS1_3_CK_AES_128_CCM_SHA256:
    return crypto_md_sha256();
  case TLS1_3_CK_AES_256_GCM_SHA384:
    return crypto_md_sha384();
  default:
    return NULL;
  }
}

/**
 * @brief Checks if the given cipher ID is supported.
 *
 * This function returns 1 if the provided TLS 1.3 cipher suite ID is
 * supported by the crypto implementation. Otherwise, it returns 0.
 *
 * Supported cipher IDs:
 * - TLS1_3_CK_AES_128_GCM_SHA256
 * - TLS1_3_CK_AES_256_GCM_SHA384
 * - TLS1_3_CK_CHACHA20_POLY1305_SHA256
 * - TLS1_3_CK_AES_128_CCM_SHA256
 *
 * @param cipher_id TLS 1.3 cipher suite ID to check.
 * @return 1 if the cipher is supported, 0 otherwise.
 */
static int supported_cipher_id(uint32_t cipher_id) {
  switch (cipher_id) {
  case TLS1_3_CK_AES_128_GCM_SHA256:
  case TLS1_3_CK_AES_256_GCM_SHA384:
  case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
  case TLS1_3_CK_AES_128_CCM_SHA256:
    return 1;
  default:
    return 0;
  }
}

/**
 * @brief Initializes the crypto context for the given cipher ID.
 *
 * This function initializes the provided ngtcp2_crypto_ctx structure
 * based on the specified TLS 1.3 cipher suite ID. It sets the AEAD,
 * message digest, and header protection algorithms, along with their
 * maximum encryption and decryption failure limits.
 *
 * @param ctx Pointer to the ngtcp2_crypto_ctx to initialize.
 * @param cipher_id TLS 1.3 cipher suite ID.
 * @return The initialized ngtcp2_crypto_ctx pointer.
 */
static ngtcp2_crypto_ctx *crypto_ctx_cipher_id(ngtcp2_crypto_ctx *ctx,
                                               uint32_t cipher_id) {
  ngtcp2_crypto_aead_init(&ctx->aead,
                         (void *)crypto_cipher_id_get_aead(cipher_id));
  ctx->md.native_handle = (void *)crypto_cipher_id_get_md(cipher_id);
  ctx->hp.native_handle = (void *)crypto_cipher_id_get_hp(cipher_id);
  ctx->max_encryption = crypto_cipher_id_get_aead_max_encryption(cipher_id);
  ctx->max_decryption_failure =
    crypto_cipher_id_get_aead_max_decryption_failure(cipher_id);

  return ctx;
}

/**
 * @brief Initializes the crypto context from a TLS session.
 *
 * This function initializes the provided ngtcp2_crypto_ctx structure
 * based on the negotiated cipher suite of the given TLS connection.
 *
 * It retrieves the current cipher from the TLS session and initializes
 * the crypto context with corresponding algorithms and parameters.
 * If the cipher is not supported or unavailable, returns NULL.
 *
 * @param ctx Pointer to the ngtcp2_crypto_ctx to initialize.
 * @param tls_native_handle Pointer to the native TLS handle (SSL *).
 * @return The initialized ngtcp2_crypto_ctx pointer, or NULL on failure.
 */
ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_tls(ngtcp2_crypto_ctx *ctx,
                                         void *tls_native_handle) {
  SSL *ssl = tls_native_handle;
  const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
  uint32_t cipher_id;

  if (cipher == NULL) {
    return NULL;
  }

  cipher_id = (uint32_t)SSL_CIPHER_get_id(cipher);

  if (!supported_cipher_id(cipher_id)) {
    return NULL;
  }

  return crypto_ctx_cipher_id(ctx, cipher_id);
}

/**
 * @brief Initializes the crypto context for early data from a TLS session.
 *
 * This function initializes the provided ngtcp2_crypto_ctx structure for
 * early data encryption, using the cipher suite from the given TLS session.
 *
 * It is equivalent to ngtcp2_crypto_ctx_tls().
 *
 * @param ctx Pointer to the ngtcp2_crypto_ctx to initialize.
 * @param tls_native_handle Pointer to the native TLS handle (SSL *).
 * @return The initialized ngtcp2_crypto_ctx pointer, or NULL on failure.
 */
ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_tls_early(ngtcp2_crypto_ctx *ctx,
                                               void *tls_native_handle) {
  return ngtcp2_crypto_ctx_tls(ctx, tls_native_handle);
}

/**
 * @brief Returns the length of the hash output for the given EVP_MD.
 *
 * This function returns the length in bytes of the message digest
 * produced by the given EVP_MD structure.
 *
 * @param md Pointer to the EVP_MD.
 * @return The length of the hash output in bytes.
 */
static size_t crypto_md_hashlen(const EVP_MD *md) {
  return (size_t)EVP_MD_size(md);
}

/**
 * @brief Returns the length of the hash output for the given crypto_md object.
 *
 * This function returns the length in bytes of the message digest associated
 * with the provided ngtcp2_crypto_md structure.
 *
 * @param md Pointer to the ngtcp2_crypto_md.
 * @return The length of the hash output in bytes.
 */
size_t ngtcp2_crypto_md_hashlen(const ngtcp2_crypto_md *md) {
  return crypto_md_hashlen(md->native_handle);
}

/**
 * @brief Returns the key length for the given AEAD EVP_CIPHER.
 *
 * This function returns the length in bytes of the key required by the given
 * AEAD EVP_CIPHER structure.
 *
 * @param aead Pointer to the EVP_CIPHER.
 * @return The key length in bytes.
 */
static size_t crypto_aead_keylen(const EVP_CIPHER *aead) {
  return (size_t)EVP_CIPHER_key_length(aead);
}

/**
 * @brief Returns the key length for the given crypto_aead object.
 *
 * This function returns the length in bytes of the key required by the
 * ngtcp2_crypto_aead structure.
 *
 * @param aead Pointer to the ngtcp2_crypto_aead.
 * @return The key length in bytes.
 */
size_t ngtcp2_crypto_aead_keylen(const ngtcp2_crypto_aead *aead) {
  return crypto_aead_keylen(aead->native_handle);
}

/**
 * @brief Returns the length of the nonce (IV) for the given AEAD cipher.
 *
 * This function returns the length in bytes of the nonce (initialization
 * vector) used by the provided AEAD EVP_CIPHER.
 *
 * @param aead Pointer to the EVP_CIPHER AEAD cipher.
 * @return The nonce length in bytes.
 */
static size_t crypto_aead_noncelen(const EVP_CIPHER *aead) {
  return (size_t)EVP_CIPHER_iv_length(aead);
}

/**
 * @brief Returns the length of the nonce (IV) for the given crypto_aead object.
 *
 * This function returns the length in bytes of the nonce (initialization
 * vector) used by the provided ngtcp2_crypto_aead structure.
 *
 * @param aead Pointer to the ngtcp2_crypto_aead structure.
 * @return The nonce length in bytes.
 */
size_t ngtcp2_crypto_aead_noncelen(const ngtcp2_crypto_aead *aead) {
  return crypto_aead_noncelen(aead->native_handle);
}

/**
 * @brief Initializes an AEAD encryption context with the given key and nonce length.
 *
 * This function initializes the provided ngtcp2_crypto_aead_ctx structure
 * for encryption using the specified AEAD cipher, key, and nonce length.
 *
 * It creates and configures a new EVP_CIPHER_CTX for the cipher provided in
 * the ngtcp2_crypto_aead structure. If the cipher requires specific parameters
 * (e.g., AES-128-CCM needs the tag length), they are set accordingly.
 *
 * @param[out] aead_ctx Pointer to the ngtcp2_crypto_aead_ctx to initialize.
 * @param[in]  aead     Pointer to the ngtcp2_crypto_aead describing the cipher.
 * @param[in]  key      Pointer to the encryption key.
 * @param[in]  noncelen Length of the nonce (IV) in bytes.
 *
 * @return 0 if the initialization succeeds; -1 if an error occurs.
 */
int ngtcp2_crypto_aead_ctx_encrypt_init(ngtcp2_crypto_aead_ctx *aead_ctx,
                                        const ngtcp2_crypto_aead *aead,
                                        const uint8_t *key, size_t noncelen) {

  const EVP_CIPHER *cipher = aead->native_handle;
  int cipher_nid = EVP_CIPHER_nid(cipher);
  EVP_CIPHER_CTX *actx;
  size_t taglen = crypto_aead_max_overhead(cipher);
  OSSL_PARAM params[3];

  actx = EVP_CIPHER_CTX_new();
  if (actx == NULL) {
    return -1;
  }

  params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, &noncelen);
  
  if (cipher_nid == NID_aes_128_ccm) {
  params[1] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                NULL, taglen);
  params[2] = OSSL_PARAM_construct_end();
  } else {
  params[1] = OSSL_PARAM_construct_end();
  }

  if (!EVP_EncryptInit_ex(actx, cipher, NULL, NULL, NULL) ||
      !EVP_CIPHER_CTX_set_params(actx, params) ||
      !EVP_EncryptInit_ex(actx, NULL, NULL, key, NULL)) {
    EVP_CIPHER_CTX_free(actx);
    return -1;
  }

  aead_ctx->native_handle = actx;

  return 0;
}

/**
 * @brief Initializes an AEAD decryption context with the given key and nonce length.
 *
 * This function initializes the provided ngtcp2_crypto_aead_ctx structure
 * for decryption using the specified AEAD cipher, key, and nonce length.
 *
 * It creates and configures a new EVP_CIPHER_CTX for the cipher provided in
 * the ngtcp2_crypto_aead structure. If the cipher requires specific parameters
 * (e.g., AES-128-CCM needs the tag length), they are set accordingly.
 *
 * @param[out] aead_ctx Pointer to the ngtcp2_crypto_aead_ctx to initialize.
 * @param[in]  aead     Pointer to the ngtcp2_crypto_aead describing the cipher.
 * @param[in]  key      Pointer to the decryption key.
 * @param[in]  noncelen Length of the nonce (IV) in bytes.
 *
 * @return 0 if the initialization succeeds; -1 if an error occurs.
 */
int ngtcp2_crypto_aead_ctx_decrypt_init(ngtcp2_crypto_aead_ctx *aead_ctx,
                                        const ngtcp2_crypto_aead *aead,
                                        const uint8_t *key, size_t noncelen) {
  const EVP_CIPHER *cipher = aead->native_handle;
  int cipher_nid = EVP_CIPHER_nid(cipher);
  EVP_CIPHER_CTX *actx;
  size_t taglen = crypto_aead_max_overhead(cipher);
  OSSL_PARAM params[3];

  actx = EVP_CIPHER_CTX_new();
  if (actx == NULL) {
    return -1;
  }

  params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, &noncelen);

  if (cipher_nid == NID_aes_128_ccm) {
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                NULL, taglen);
    params[2] = OSSL_PARAM_construct_end();
  } else {
    params[1] = OSSL_PARAM_construct_end();
  }

  if (!EVP_DecryptInit_ex(actx, cipher, NULL, NULL, NULL) ||
      !EVP_CIPHER_CTX_set_params(actx, params) ||
      !EVP_DecryptInit_ex(actx, NULL, NULL, key, NULL)) {
    EVP_CIPHER_CTX_free(actx);
    return -1;
  }

  aead_ctx->native_handle = actx;

  return 0;
}

/**
 * @brief Frees the AEAD context resources.
 *
 * This function frees any resources allocated for the provided
 * ngtcp2_crypto_aead_ctx structure. If the context has an active
 * EVP_CIPHER_CTX, it is freed.
 *
 * @param[in,out] aead_ctx Pointer to the ngtcp2_crypto_aead_ctx to free.
 */
void ngtcp2_crypto_aead_ctx_free(ngtcp2_crypto_aead_ctx *aead_ctx) {
  if (aead_ctx->native_handle) {
    EVP_CIPHER_CTX_free(aead_ctx->native_handle);
  }
}

/**
 * @brief Initializes a cipher context for encryption with the given key.
 *
 * This function initializes the provided ngtcp2_crypto_cipher_ctx structure
 * for encryption using the specified cipher and key. It creates a new
 * EVP_CIPHER_CTX and sets up the encryption operation.
 *
 * @param[out] cipher_ctx Pointer to the ngtcp2_crypto_cipher_ctx to initialize.
 * @param[in]  cipher     Pointer to the ngtcp2_crypto_cipher describing the cipher.
 * @param[in]  key        Pointer to the encryption key.
 *
 * @return 0 if initialization succeeds; -1 if an error occurs.
 */
int ngtcp2_crypto_cipher_ctx_encrypt_init(ngtcp2_crypto_cipher_ctx *cipher_ctx,
                                          const ngtcp2_crypto_cipher *cipher,
                                          const uint8_t *key) {
  EVP_CIPHER_CTX *actx;

  actx = EVP_CIPHER_CTX_new();
  if (actx == NULL) {
    return -1;
  }

  if (!EVP_EncryptInit_ex(actx, cipher->native_handle, NULL, key, NULL)) {
    EVP_CIPHER_CTX_free(actx);
    return -1;
  }

  cipher_ctx->native_handle = actx;

  return 0;
}

/**
 * @brief Frees the cipher context resources.
 *
 * This function frees any resources allocated for the provided
 * ngtcp2_crypto_cipher_ctx structure. If an EVP_CIPHER_CTX has been
 * allocated, it will be freed.
 *
 * @param[in,out] cipher_ctx Pointer to the ngtcp2_crypto_cipher_ctx to free.
 */
void ngtcp2_crypto_cipher_ctx_free(ngtcp2_crypto_cipher_ctx *cipher_ctx) {
  if (cipher_ctx->native_handle) {
    EVP_CIPHER_CTX_free(cipher_ctx->native_handle);
  }
}

/**
 * @brief Performs HKDF extract operation and writes the pseudorandom key.
 *
 * This function performs the HKDF extract step using the specified hash
 * algorithm and writes the resulting pseudorandom key (PRK) to the `dest`
 * buffer. It uses the given `salt` and `secret` as inputs to the extract
 * phase.
 *
 * Internally, it creates an HKDF context and sets the appropriate OpenSSL
 * parameters to perform the extract operation only.
 *
 * @param[out] dest      Buffer to store the pseudorandom key (PRK).
 * @param[in]  md        Pointer to the ngtcp2_crypto_md specifying the hash.
 * @param[in]  secret    Pointer to the input keying material.
 * @param[in]  secretlen Length of the secret in bytes.
 * @param[in]  salt      Pointer to the salt value.
 * @param[in]  saltlen   Length of the salt in bytes.
 *
 * @return 0 on success, or -1 if the HKDF extract operation fails.
 */
int ngtcp2_crypto_hkdf_extract(uint8_t *dest, const ngtcp2_crypto_md *md,
                               const uint8_t *secret, size_t secretlen,
                               const uint8_t *salt, size_t saltlen) {
  const EVP_MD *prf = md->native_handle;
  EVP_KDF *kdf = crypto_kdf_hkdf();
  EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
  int mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
  OSSL_PARAM params[] = {
    OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
    OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                     (char *)EVP_MD_get0_name(prf), 0),
    OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)secret,
                                      secretlen),
    OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt,
                                      saltlen),
    OSSL_PARAM_construct_end(),
  };
  int rv = 0;

  if (!crypto_initialized) {
    EVP_KDF_free(kdf);
  }

  if (EVP_KDF_derive(kctx, dest, (size_t)EVP_MD_size(prf), params) <= 0) {
    rv = -1;
  }

  EVP_KDF_CTX_free(kctx);

  return rv;
}

/**
 * @brief Performs HKDF extract operation and writes the pseudorandom key.
 *
 * This function performs the HKDF extract step using the specified hash
 * algorithm and writes the resulting pseudorandom key (PRK) to the `dest`
 * buffer. It uses the given `salt` and `secret` as inputs to the extract
 * phase.
 *
 * Internally, it creates an HKDF context and sets the appropriate OpenSSL
 * parameters to perform the extract operation only.
 *
 * @param[out] dest      Buffer to store the pseudorandom key (PRK).
 * @param[in]  md        Pointer to the ngtcp2_crypto_md specifying the hash.
 * @param[in]  secret    Pointer to the input keying material.
 * @param[in]  secretlen Length of the secret in bytes.
 * @param[in]  salt      Pointer to the salt value.
 * @param[in]  saltlen   Length of the salt in bytes.
 *
 * @return 0 on success, or -1 if the HKDF extract operation fails.
 */
int ngtcp2_crypto_hkdf_expand(uint8_t *dest, size_t destlen,
                              const ngtcp2_crypto_md *md, const uint8_t *secret,
                              size_t secretlen, const uint8_t *info,
                              size_t infolen) {
  const EVP_MD *prf = md->native_handle;
  EVP_KDF *kdf = crypto_kdf_hkdf();
  EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
  int mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
  OSSL_PARAM params[] = {
    OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
    OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                     (char *)EVP_MD_get0_name(prf), 0),
    OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)secret,
                                      secretlen),
    OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info,
                                      infolen),
    OSSL_PARAM_construct_end(),
  };
  int rv = 0;

  if (!crypto_initialized) {
    EVP_KDF_free(kdf);
  }

  if (EVP_KDF_derive(kctx, dest, destlen, params) <= 0) {
    rv = -1;
  }

  EVP_KDF_CTX_free(kctx);

  return rv;
}

/**
 * @brief Performs the HKDF extract-and-expand operation.
 *
 * This function performs a complete HKDF operation using the specified
 * hash algorithm. It runs both the extract and expand phases, producing
 * output keying material of length `destlen` and writing it to `dest`.
 *
 * The function uses the provided `salt`, `secret`, and `info` as inputs.
 * Internally, it creates an HKDF context and configures it with the
 * relevant parameters to derive the output key material.
 *
 * @param[out] dest      Buffer to store the derived keying material.
 * @param[in]  destlen   Length of the output keying material in bytes.
 * @param[in]  md        Pointer to the ngtcp2_crypto_md specifying the hash.
 * @param[in]  secret    Pointer to the input keying material.
 * @param[in]  secretlen Length of the secret in bytes.
 * @param[in]  salt      Pointer to the salt value.
 * @param[in]  saltlen   Length of the salt in bytes.
 * @param[in]  info      Pointer to the context/application-specific info.
 * @param[in]  infolen   Length of the info in bytes.
 *
 * @return 0 on success, or -1 if the HKDF operation fails.
 */
int ngtcp2_crypto_hkdf(uint8_t *dest, size_t destlen,
                       const ngtcp2_crypto_md *md, const uint8_t *secret,
                       size_t secretlen, const uint8_t *salt, size_t saltlen,
                       const uint8_t *info, size_t infolen) {
  const EVP_MD *prf = md->native_handle;
  EVP_KDF *kdf = crypto_kdf_hkdf();
  EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
  OSSL_PARAM params[] = {
    OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                     (char *)EVP_MD_get0_name(prf), 0),
    OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)secret,
                                      secretlen),
    OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt,
                                      saltlen),
    OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info,
                                      infolen),
    OSSL_PARAM_construct_end(),
  };
  int rv = 0;

  if (!crypto_initialized) {
    EVP_KDF_free(kdf);
  }

  if (EVP_KDF_derive(kctx, dest, destlen, params) <= 0) {
    rv = -1;
  }

  EVP_KDF_CTX_free(kctx);

  return rv;
}

/**
 * @brief Performs AEAD encryption and outputs ciphertext with authentication tag.
 *
 * This function encrypts the given plaintext using the provided AEAD cipher
 * and encryption context. It also authenticates additional data (AAD), and
 * appends the authentication tag to the ciphertext in the output buffer `dest`.
 *
 * The output buffer must have enough space to hold the ciphertext and the
 * authentication tag, which is determined by the AEAD cipher's overhead.
 *
 * @param[out] dest        Buffer to store the ciphertext and authentication tag.
 *                         The tag is appended immediately after the ciphertext.
 * @param[in]  aead        Pointer to the ngtcp2_crypto_aead structure describing
 *                         the AEAD cipher.
 * @param[in]  aead_ctx    Pointer to the initialized AEAD encryption context.
 * @param[in]  plaintext   Pointer to the plaintext to encrypt.
 * @param[in]  plaintextlen Length of the plaintext in bytes.
 * @param[in]  nonce       Pointer to the nonce (IV) used for encryption.
 * @param[in]  noncelen    Length of the nonce in bytes. (Currently unused)
 * @param[in]  aad         Pointer to the additional authenticated data (AAD).
 * @param[in]  aadlen      Length of the AAD in bytes.
 *
 * @return 0 if encryption succeeds; -1 if an error occurs.
 */
int ngtcp2_crypto_encrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                          const ngtcp2_crypto_aead_ctx *aead_ctx,
                          const uint8_t *plaintext, size_t plaintextlen,
                          const uint8_t *nonce, size_t noncelen,
                          const uint8_t *aad, size_t aadlen) {
  const EVP_CIPHER *cipher = aead->native_handle;
  size_t taglen = crypto_aead_max_overhead(cipher);
  EVP_CIPHER_CTX *actx = aead_ctx->native_handle;
  int len = 0;
  int cipher_nid = EVP_CIPHER_nid(cipher);

  DBG("in ngtcp2_crypto_encrypt\n");
  (void)noncelen;

  if (!EVP_EncryptInit_ex(actx, NULL, NULL, NULL, nonce)) {
    DBG("Failed to init aead context\n");
    ERR_print_errors_fp(stderr);
    return -1;
  }

  if (cipher_nid == NID_aes_128_ccm) {
    if (!EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_TAG,
                             (int)taglen, NULL)) {
      DBG("Failed to set tag lenth\n");
      return -1;
    }
  }

  if (cipher_nid == NID_aes_128_ccm) {
    if (!EVP_EncryptUpdate(actx, NULL, &len, NULL, (int)plaintextlen)) {
      DBG("Failed to encrypt plaintext\n");
      return -1;
    }
  }

  if (!EVP_EncryptUpdate(actx, NULL, &len, aad, (int)aadlen)) {
    DBG("Failed to encrypt aad\n");
    ERR_print_errors_fp(stderr);
    return -1;
  }

  if (!EVP_EncryptUpdate(actx, dest, &len, plaintext, (int)plaintextlen)) {
    DBG("Failed to encrypt plaintext\n");
    ERR_print_errors_fp(stderr);
    return -1;
  }

  if (!EVP_EncryptFinal_ex(actx, dest + len, &len)) {
    DBG("Failed to do final encrypt\n");
    ERR_print_errors_fp(stderr);
    return -1;
  }

  if (!EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_GET_TAG, (int)taglen,
                           dest + plaintextlen)) {
    DBG("Failed to get AEAD tag\n");
    ERR_print_errors_fp(stderr);
    return -1;
  }

  return 0;
}

/**
 * @brief Performs AEAD decryption and verifies the authentication tag.
 *
 * This function decrypts the given ciphertext using the provided AEAD cipher
 * and decryption context. It also verifies the authentication tag, which is
 * expected to be appended to the ciphertext.
 *
 * If the authentication tag verification fails, the function returns -1.
 *
 * The output buffer `dest` must have enough space to hold the decrypted
 * plaintext (equal to the ciphertext length minus the tag length).
 *
 * @param[out] dest         Buffer to store the decrypted plaintext.
 * @param[in]  aead         Pointer to the ngtcp2_crypto_aead structure describing
 *                          the AEAD cipher.
 * @param[in]  aead_ctx     Pointer to the initialized AEAD decryption context.
 * @param[in]  ciphertext   Pointer to the ciphertext with the authentication tag
 *                          appended at the end.
 * @param[in]  ciphertextlen Length of the ciphertext, including the tag, in bytes.
 * @param[in]  nonce        Pointer to the nonce (IV) used for decryption.
 * @param[in]  noncelen     Length of the nonce in bytes. (Currently unused)
 * @param[in]  aad          Pointer to the additional authenticated data (AAD).
 * @param[in]  aadlen       Length of the AAD in bytes.
 *
 * @return 0 if decryption and authentication succeed; -1 on failure.
 */
int ngtcp2_crypto_decrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                          const ngtcp2_crypto_aead_ctx *aead_ctx,
                          const uint8_t *ciphertext, size_t ciphertextlen,
                          const uint8_t *nonce, size_t noncelen,
                          const uint8_t *aad, size_t aadlen) {
  const EVP_CIPHER *cipher = aead->native_handle;
  size_t taglen = crypto_aead_max_overhead(cipher);
  int cipher_nid = EVP_CIPHER_nid(cipher);
  EVP_CIPHER_CTX *actx = aead_ctx->native_handle;
  int len;
  uint8_t *tag;

  DBG("In ngtcp2_crypto_decrypt\n");

  (void)noncelen;

  if (taglen > ciphertextlen) {
    return -1;
  }

  ciphertextlen -= taglen;
  tag = (uint8_t *)(ciphertext + ciphertextlen);

  if (!EVP_DecryptInit_ex(actx, NULL, NULL, NULL, nonce))
    return -1;

  if (!EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_TAG, (int)taglen, tag))
    return -1;

  if (cipher_nid == NID_aes_128_ccm) {
    if (!EVP_DecryptUpdate(actx, NULL, &len, NULL, (int)ciphertextlen))
      return -1;
  }

  if (!EVP_DecryptUpdate(actx, NULL, &len, aad, (int)aadlen))
    return -1;

  if (!EVP_DecryptUpdate(actx, dest, &len, ciphertext, (int)ciphertextlen))
    return -1;

  if (!EVP_DecryptFinal_ex(actx, dest + ciphertextlen, &len))
    return -1;

  return 0;
}

/**
 * @brief Generates a header protection mask from the given sample.
 *
 * This function generates a mask used for QUIC header protection by
 * encrypting a fixed plaintext with the provided sample as input to
 * the header protection cipher. The result is written to `dest`.
 *
 * The header protection cipher context (`hp_ctx`) must be properly
 * initialized before calling this function.
 *
 * @param[out] dest     Buffer to store the resulting header protection mask.
 * @param[in]  hp       Pointer to the ngtcp2_crypto_cipher structure (unused).
 * @param[in]  hp_ctx   Pointer to the initialized cipher context used for
 *                      header protection encryption.
 * @param[in]  sample   Pointer to the sample used as input for mask generation.
 *
 * @return 0 if the mask is successfully generated; -1 on failure.
 */
int ngtcp2_crypto_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                          const ngtcp2_crypto_cipher_ctx *hp_ctx,
                          const uint8_t *sample) {
  static const uint8_t PLAINTEXT[] = "\x00\x00\x00\x00\x00";
  EVP_CIPHER_CTX *actx = hp_ctx->native_handle;
  int len;

  (void)hp;

  if (!EVP_EncryptInit_ex(actx, NULL, NULL, NULL, sample) ||
      !EVP_EncryptUpdate(actx, dest, &len, PLAINTEXT, sizeof(PLAINTEXT) - 1) ||
      !EVP_EncryptFinal_ex(actx, dest + sizeof(PLAINTEXT) - 1, &len)) {
    return -1;
  }

  return 0;
}

#ifdef OPENSSL_DEBUG
static const char *message_types[] = {
  "HelloRequest",
  "ClientHello",
  "ServerHello",
  "Unknown 3",
  "NewSessionTicket",
  "Unknown 5",
  "Unknown 6",
  "Unknown 7",
  "EncryptedExtensions",
  "Unknown 9",
  "Unknown 10",
  "Certificate",
  "Server Key Exchange",
  "Certificate Request",
  "ServerHelloDone",
  "CertificateVerify",
  "ClientKeyExchange",
  "Unknown 17",
  "Unknown 18",
  "Unknown 19",
  "Finished"
};
#endif

/**
 * @brief Creates a new record_entry and copies the given record data.
 *
 * Allocates and initializes a new record_entry structure. The function
 * copies the provided record data into newly allocated memory and associates
 * it with the given SSL context.
 *
 * @param record Pointer to the record data to copy.
 * @param rec_len Length of the record data in bytes.
 * @param ssl Pointer to the SSL connection context to associate with the record.
 *
 * @return Pointer to the newly created record_entry on success, or NULL on failure.
 */
static struct record_entry *make_new_record(const uint8_t *record, size_t rec_len, SSL *ssl)
{
  struct record_entry *new;

  /*
   * Allocate a new structure, make sure its zeroed out
   */
  new = calloc(1, sizeof(struct record_entry));
  if (new == NULL)
    return NULL;
  new->record = malloc(rec_len);
  if (new->record == NULL) {
    free(new);
    return NULL;
  }
  /*
   * Copy the record to its private buffer
   * save the length and ssl pointer for use in quic_tls_send
   */
  memcpy(new->record, record, rec_len);
  new->rec_len = rec_len;
  new->ssl = ssl;
  return new;
}

/**
 * @brief Processes a TLS record and creates record_entry nodes for each message.
 *
 * Parses the provided TLS record data, extracts individual messages, and creates
 * corresponding record_entry structures. Complete messages are inserted into the
 * rlist queue. Incomplete messages are marked and added for later reassembly.
 * If an incomplete record_entry was passed in, it may be replaced by a completed
 * message and then freed.
 *
 * @param record     Pointer to the TLS record data buffer.
 * @param rec_len    Length of the TLS record data in bytes.
 * @param ssl        Pointer to the SSL connection context associated with the record.
 * @param incomplete Pointer to a possibly incomplete record_entry, which may be
 *                   replaced if a complete message is found.
 *
 * @return None.
 */
static void make_new_records(const uint8_t *record, size_t rec_len, SSL *ssl,
                             struct record_entry *incomplete)
{
  struct record_entry *new;
  const uint8_t *idx;
  uint8_t message_type;
  size_t total_message_size = 0;
  uint32_t message_size;
  struct record_entry *to_delete = NULL;
  struct record_list *rlist;

  rlist = get_ssl_rx_queue(ssl);
  assert(rlist != NULL);

  /* set our cursor to the start of the message */
  idx = record;

  while (total_message_size < rec_len) {
    message_type = *idx;
    message_size = *((uint32_t *)idx);

    /* message size is just the lower 3 bytes of the TLS record */
    message_size = htonl(message_size) & 0x00ffffff;

    /* make sure our message type is valid */
    assert(message_type <= 20);
    DBG("message is %s, length %d\n", message_types[message_type], message_size);

    /*
     * Check to make sure that this record completely fits into
     * the amount of data we have left in this message, if it
     * does, great, otherwise, we have to mark it as incomplete
     * for later re-assembly
     */
    if ((total_message_size + (message_size + 4)) <= rec_len) {

        /* 
         * If the incomplete parameter that is passed to us is non-null
         * then we are reprocessing a previous message fragment on the list
         * save the record, as we reuse the incomplete pointer below, and we
         * will need to remove this from the list when we are done
         */
        if (to_delete == NULL)
            to_delete = incomplete;

        /* this record is complete, we can add it */
        new = make_new_record(idx, message_size + 4, ssl);
        assert(new != NULL);
        DBG("message %s being added as record with len %u\n", message_types[message_type], message_size + 4);

        /*
         * If we are reprocessing a previous message fragment, we don't
         * want to add the new record to the tail, in the event we have
         * other messages for this SSL behind it, and don't want to process
         * them out of order, instead, add the new record after the partial
         * message so it winds up in the same place in the queue
         * Update the incomplete pointer, so any subsequent records also
         * get added in order.
         * If, on the other hand, incomplete is NULL, then adding to the
         * tail of the queue is just fine
         */
        if (incomplete != NULL) {
            STAILQ_INSERT_AFTER(rlist, incomplete, new, entries);
            incomplete = new;
        } else {
            STAILQ_INSERT_TAIL(rlist, new, entries);
        }

    } else {
        /* This is an incomplete record, create and mark it as such */
        DBG("message %s is incomplete, marking as such for later reassembly\n", message_types[message_type]);
        new = make_new_record(idx, rec_len - total_message_size, ssl);
        assert(new != NULL);
        new->incomplete = 1;
        /*
         * Same as above, if we are reprocessing an incomplete message
         * add any leftovers after the last record we processed, which may
         * not be the absolute end of the queue
         */
        if (incomplete != NULL) {
            STAILQ_INSERT_AFTER(rlist, incomplete, new, entries);
            incomplete = new;
        } else {
            STAILQ_INSERT_TAIL(rlist, new, entries);
        }
    }

    /*
     * update our total_message size and cursor, to handle the next record
     */
    total_message_size += (message_size + 4);
    idx += (4 + message_size);
  }

  /*
   * If to_delete is not null, then we reprocessed a message fragment
   * and added more records to the queue right behind to_delete.  Because
   * those new records contain the data that was in this partial fragment,
   * we need to get rid of this one to avoid reading duplicate data
   */
  if (to_delete != NULL) {
    STAILQ_REMOVE(rlist, to_delete, record_entry, entries);
    free(to_delete->record);
    free(to_delete);
  }
}

/**
 * @brief Checks if an incomplete record_entry can now be completed.
 *
 * Calls make_new_records() on the provided record_entry to process its
 * contents. This may result in the record being split into one or more
 * complete record entries and the original record_entry being removed.
 *
 * @param rec Pointer to the record_entry to check and process.
 *
 * @return Always returns 1.
 */
static int check_record_completion(struct record_entry *rec)
{
  make_new_records(rec->record, rec->rec_len, rec->ssl, rec);
  return 1;
}

/**
 * @brief Searches for an incomplete record_entry associated with the given SSL.
 *
 * Iterates through the rlist queue to find an incomplete record_entry that
 * matches the specified SSL connection. If found, appends the new record data
 * to the incomplete record and updates its length. Marks the record as complete
 * for rechecking.
 *
 * @param new_record  Pointer to the new record data to append.
 * @param new_rec_len Length of the new record data in bytes.
 * @param new_ssl     Pointer to the SSL connection context to match.
 *
 * @return Pointer to the updated record_entry if an incomplete one was found
 *         and updated; otherwise, NULL.
 */
static struct record_entry *get_incomplete_record(const uint8_t *new_record,
                                                  size_t new_rec_len,
                                                  SSL *new_ssl)
{
  struct record_entry *entry;
  struct record_list *rlist;

  rlist = get_ssl_rx_queue(new_ssl);
  assert(rlist != NULL);

  STAILQ_FOREACH(entry, rlist, entries) {
    if (entry->ssl == new_ssl) {
      if (entry->incomplete) {
        /*
         * We have an incomplete record for this SSL
         * merge them
         */
        entry->record = realloc(entry->record, entry->rec_len + new_rec_len);
        assert(entry->record != NULL);
        memcpy(&entry->record[entry->rec_len], new_record, new_rec_len);
        entry->rec_len += new_rec_len;
        entry->incomplete = 0; /* need to recheck this */
          return entry;
      } else {
        /* current record is complete, nothing to coalesce */
        return NULL;
      }
    }
  }
  return NULL;
}

/**
 * @brief Processes a new TLS record for a given SSL connection.
 *
 * Handles a new incoming TLS record by either appending it to an existing
 * incomplete record_entry (if one exists for the given SSL connection), or by
 * creating new record_entry structures for the data. If an incomplete record
 * was merged with new data, its completion status is re-evaluated.
 *
 * @param ssl     Pointer to the SSL connection context associated with the record.
 * @param record  Pointer to the new TLS record data.
 * @param rec_len Length of the new TLS record data in bytes.
 *
 * @return 1 on successful processing, 0 otherwise.
 */
static int process_new_message(SSL *ssl, const uint8_t *record, size_t rec_len)
{
  struct record_entry *this_rec;
  int ret = 0;

  this_rec = get_incomplete_record(record, rec_len, ssl);
  if (this_rec == NULL) {
    /* No imcomplete records, just create a new one */
    make_new_records(record, rec_len, ssl, NULL);
    ret = 1;
    goto out;
  }

  /* if we got an incomplete record above, get_incomplete_record
   * will have merged the new record into it
   * and we need to recheck its completion status
   */
  assert(check_record_completion(this_rec) == 1);
  ret = 1;

out:
  return ret;
}

/**
 * @brief Processes incoming crypto data and drives the TLS handshake.
 *
 * This function processes the provided crypto data at the given encryption
 * level and advances the TLS handshake state for the QUIC connection. It calls
 * `SSL_do_handshake()` to progress the handshake and handles special cases
 * like client hello and X.509 lookup callbacks.
 *
 * If handshake completion is detected, the QUIC connection is updated to
 * reflect the completed state.
 *
 * @param[in,out] conn              The QUIC connection object.
 * @param[in]     encryption_level  The encryption level at which the crypto
 *                                  data was received.
 * @param[in]     data              Pointer to the crypto data to process.
 * @param[in]     datalen           Length of the crypto data in bytes.
 *
 * @return
 * - 0 on success or if SSL needs more reads/writes to continue.
 * - NGTCP2_CRYPTO_OPENSSL_ERR_TLS_WANT_CLIENT_HELLO_CB if the TLS handshake
 *   needs a client hello callback.
 * - NGTCP2_CRYPTO_OPENSSL_ERR_TLS_WANT_X509_LOOKUP if the handshake needs
 *   X.509 lookup.
 * - -1 on other fatal errors.
 */
int ngtcp2_crypto_read_write_crypto_data(
  ngtcp2_conn *conn, ngtcp2_encryption_level encryption_level,
  const uint8_t *data, size_t datalen) {
  SSL *ssl = ngtcp2_conn_get_tls_native_handle(conn);
  int rv;
  int err;

  enc_level = encryption_level;

  DBG("CALLING NGTCP2_CRYPTO_READ_WRITE_CRYPTO_DATA\n");
  if (data != NULL)
    process_new_message(ssl, data, datalen);

  if (!ngtcp2_conn_get_handshake_completed(conn)) {
    rv = SSL_do_handshake(ssl);
    if (rv <= 0) {
      err = SSL_get_error(ssl, rv);
      switch (err) {
      case SSL_ERROR_WANT_READ:
      case SSL_ERROR_WANT_WRITE:
        return 0;
      case SSL_ERROR_WANT_CLIENT_HELLO_CB:
        return NGTCP2_CRYPTO_OPENSSL_ERR_TLS_WANT_CLIENT_HELLO_CB;
      case SSL_ERROR_WANT_X509_LOOKUP:
        return NGTCP2_CRYPTO_OPENSSL_ERR_TLS_WANT_X509_LOOKUP;
      case SSL_ERROR_SSL:
        return -1;
      default:
        return -1;
      }
    }

    ngtcp2_conn_tls_handshake_completed(conn);
  }

  return 0;
}

/**
 * @brief Stub function for setting remote transport parameters.
 *
 * This function is a placeholder and does not perform any action. The
 * remote transport parameters are expected to be handled via the
 * `got_tp_params` callback instead.
 *
 * @param[in] conn Pointer to the QUIC connection object (unused).
 * @param[in] tls  Pointer to the TLS native handle (unused).
 *
 * @return Always returns 0.
 */
int ngtcp2_crypto_set_remote_transport_params(ngtcp2_conn __attribute__((unused)) *conn, void __attribute__((unused)) *tls) {
  /*
   * This gets handled from the got_tp_params callback below
   */
  DBG("Setting remote transport params\n");
  return 0;
}

/**
 * @brief Frees application data associated with a BIO object on free operation.
 *
 * This callback function is intended to be used with a BIO object to
 * clean up dynamically allocated application data when the BIO is freed.
 *
 * @param b        Pointer to the BIO object.
 * @param oper     Operation code indicating the current BIO operation.
 * @param argp     Unused parameter.
 * @param len      Unused parameter.
 * @param argi     Unused parameter.
 * @param arg1     Unused parameter.
 * @param ret      Return value from the previous BIO callback or operation.
 * @param processed Unused parameter.
 *
 * @return Returns the input @p ret value unchanged.
 */
static long free_bio_tp_data(BIO *b, int oper,
                              __attribute__((unused)) const char *argp,
                              __attribute__((unused)) size_t len,
                              __attribute__((unused)) int argi,
                              __attribute__((unused)) long arg1,
                              __attribute__((unused)) int ret,
                              __attribute__((unused)) size_t *processed)
{
    uint8_t *tp; 

    if (oper == BIO_CB_FREE) {
        tp = BIO_get_app_data(b);
        free(tp);
        BIO_set_app_data(b, NULL);
    }
    return ret;
}

/**
 * @brief Sets the local transport parameters in the TLS session.
 *
 * This function sets the local QUIC transport parameters to be sent in
 * the TLS handshake by calling `SSL_set_quic_tls_transport_params()`.
 *
 * @param[in] tls Pointer to the TLS native handle (SSL *).
 * @param[in] buf Pointer to the buffer containing transport parameters.
 * @param[in] len Length of the transport parameters buffer.
 *
 * @return 0 on success; -1 if setting the transport parameters fails.
 */
int ngtcp2_crypto_set_local_transport_params(void *tls, const uint8_t *buf,
                                             size_t len) {
  uint8_t *tp = malloc(len);

  if (tp == NULL)
    return -1;
  memcpy(tp, buf, len);

  /*
   * This deserves some explination
   * the passed in buf for the params is stack alocated.
   * Because calling SSL_set_quic_tls_transport_params records
   * that pointer in the tls stack, it may be used after this
   * call returns, causing an ASAN use after out-of-scope error
   * To fix that we just clone the buffer above with malloc/
   * memcpy, but then we need to remember to free it to avoid
   * a leak.  Because we don't have an SSL_get_quic_tls_transport_params
   * call to fetch the pointer, we need to save it someplace to free it later
   * do so my storing it int the app data of our write bio, and set a callback
   * to free it when the BIO itself is freed
   */
  BIO_set_app_data(SSL_get_wbio(tls), tp);
  BIO_set_callback_ex(SSL_get_wbio(tls), free_bio_tp_data);

  DBG("Setting local transport params\n");
  if (SSL_set_quic_tls_transport_params(tls, tp, len) != 1) {
    DBG("SSL_set_quic_tls_transport_params failed!\n");
    ERR_print_errors_fp(stderr);
    return -1;
  }

  return 0;
}

/**
 * @brief QUIC encryption levels.
 *
 * This enumeration defines the different encryption levels used in
 * QUIC. Each level corresponds to a distinct phase in the QUIC
 * handshake and data transmission process.
 *
 * @enum
 * @var QUIC_ENC_LEVEL_INITIAL
 *      Initial encryption level used for early handshake messages.
 * @var QUIC_ENC_LEVEL_0RTT
 *      0-RTT encryption level used for early data transmission before
 *      handshake completion.
 * @var QUIC_ENC_LEVEL_HANDSHAKE
 *      Handshake encryption level used for the handshake's later stages.
 * @var QUIC_ENC_LEVEL_1RTT
 *      1-RTT encryption level used for application data after the
 *      handshake is complete.
 * @var QUIC_ENC_LEVEL_NUM
 *      Sentinel value representing the total number of encryption levels.
 */
enum {
  QUIC_ENC_LEVEL_INITIAL = 0,
  QUIC_ENC_LEVEL_0RTT,
  QUIC_ENC_LEVEL_HANDSHAKE,
  QUIC_ENC_LEVEL_1RTT,
  QUIC_ENC_LEVEL_NUM       /* Must be the ultimate entry */
};

/**
 * @brief Converts OpenSSL QUIC encryption level to ngtcp2 encryption level.
 *
 * This function maps an OpenSSL-defined QUIC encryption level to the
 * corresponding ngtcp2 encryption level. If the provided level is not valid,
 * the function aborts.
 *
 * @param[in] ossl_level The OpenSSL QUIC encryption level.
 *
 * @return The corresponding ngtcp2_encryption_level.
 */
static ngtcp2_encryption_level ngtcp2_crypto_openssl_from_ossl_encryption_level(
                                                          uint32_t ossl_level) {
  switch (ossl_level) {
  case QUIC_ENC_LEVEL_INITIAL:
    return NGTCP2_ENCRYPTION_LEVEL_INITIAL;
  case QUIC_ENC_LEVEL_0RTT:
    return NGTCP2_ENCRYPTION_LEVEL_0RTT;
  case QUIC_ENC_LEVEL_HANDSHAKE:
    return NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE;
  case QUIC_ENC_LEVEL_1RTT:
    return NGTCP2_ENCRYPTION_LEVEL_1RTT;
  default:
    assert(0);
    abort(); /* if NDEBUG is set */
  }
}

/**
 * @brief Callback to generate data for QUIC path challenge frames.
 *
 * This callback generates random data to be used in a QUIC PATH_CHALLENGE
 * frame. The generated data helps validate a network path between the client
 * and server.
 *
 * @param[in]  conn      The QUIC connection (unused).
 * @param[out] data      Buffer to store the generated path challenge data.
 * @param[in]  user_data User-defined data (unused).
 *
 * @return 0 on success, or NGTCP2_ERR_CALLBACK_FAILURE on failure.
 */
int ngtcp2_crypto_get_path_challenge_data_cb(ngtcp2_conn *conn, uint8_t *data,
                                             void *user_data) {
  (void)conn;
  (void)user_data;

  if (RAND_bytes(data, NGTCP2_PATH_CHALLENGE_DATALEN) != 1) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

/**
 * @brief Generates cryptographically secure random bytes.
 *
 * This function fills the provided buffer with `datalen` bytes of
 * cryptographically secure random data using OpenSSL's RAND_bytes().
 *
 * @param[out] data     Buffer to store the random bytes.
 * @param[in]  datalen  Number of random bytes to generate.
 *
 * @return 0 on success; -1 on failure.
 */
int ngtcp2_crypto_random(uint8_t *data, size_t datalen) {
  if (RAND_bytes(data, (int)datalen) != 1) {
    return -1;
  }

  return 0;
}

/**
 * @brief Configures the OpenSSL SSL_CTX for QUIC with TLS 1.3.
 *
 * This function sets the minimum and maximum supported protocol versions
 * of the provided OpenSSL SSL_CTX to TLS 1.3. QUIC requires the exclusive
 * use of TLS 1.3 for its handshake, and this function ensures that no
 * other protocol versions are negotiated.
 *
 * @param[in,out] ssl_ctx Pointer to the OpenSSL SSL_CTX to configure.
 */
static void crypto_openssl_configure_context(SSL_CTX *ssl_ctx) {
  SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
}

/**
 * @brief Callback to send TLS handshake data to the QUIC stack.
 *
 * This function is called by OpenSSL to send handshake data over QUIC.
 * It submits the provided buffer to the QUIC connection for transmission.
 * If the submission fails, it sets the TLS error on the QUIC connection.
 *
 * @param[in]  s           Pointer to the SSL connection object.
 * @param[in]  buf         Pointer to the buffer containing data to send.
 * @param[in]  buf_len     Length of the data in @p buf.
 * @param[out] consumed    Number of bytes successfully consumed from @p buf.
 * @param[in]  arg         Unused argument (typically NULL).
 *
 * @return 1 on success, 0 on failure.
 */
static int quic_tls_send(SSL *s, const unsigned char *buf, size_t buf_len,
                         size_t *consumed, void __attribute__((unused)) *arg)
{
  ngtcp2_crypto_conn_ref *ref = SSL_get_app_data(s);
  int rv;

  DBG("Calling quic_tls_send\n");

  rv = ngtcp2_conn_submit_crypto_data(ref->get_conn(ref), enc_level, buf, buf_len);
  if (rv != 0) {
    ngtcp2_conn_set_tls_error(ref->get_conn(ref), rv);
    return 0;
  }
  *consumed = buf_len;
  return 1;
}

static struct record_entry *to_free = NULL;

/**
 * @brief Callback to provide a previously buffered TLS record to OpenSSL.
 *
 * This function is called by OpenSSL to retrieve a TLS record for further
 * processing. It searches the buffered records for one matching the given
 * SSL connection. If a complete record is found, it is returned via @p buf
 * and @p bytes_read. If the record is incomplete, it signals OpenSSL to
 * wait for more data.
 *
 * @param[in]  s            Pointer to the SSL connection object.
 * @param[out] buf          Pointer to the buffer containing the record data.
 *                          If no data is available, set to NULL.
 * @param[out] bytes_read   Length of the record returned in @p buf.
 *                          If no data is available, set to 0.
 * @param[in]  arg          Unused argument (typically NULL).
 *
 * @return Always returns 1.
 */
static int quic_tls_rcv_rec(SSL *s, const unsigned char **buf, size_t *bytes_read,
                            void __attribute__((unused)) *arg)
{
  struct record_entry *entry;
  struct record_list *rlist;

  rlist = get_ssl_rx_queue(s);
  assert(rlist != NULL);

  DBG("Calling quic_tls_rcv_rec\n");
  STAILQ_FOREACH(entry, rlist, entries) {
    if (entry->ssl == s) {
      if (entry->incomplete) {
        DBG("Entry is incomplete, wait for more data\n");
        *buf = NULL;
        *bytes_read = 0;
        return 1;
      }

      STAILQ_REMOVE(rlist, entry, record_entry, entries);
      DBG("Found record to push of size %lu\n", entry->rec_len);
      *buf = entry->record;
      *bytes_read = entry->rec_len;
      to_free = entry;
      return 1;
    }
  }
  return 1;
}

/**
 * @brief Callback to release a previously buffered TLS record.
 *
 * This function is called by OpenSSL after a TLS record has been fully
 * processed and can be safely released. It verifies the number of bytes
 * read matches the expected record length, frees the associated memory,
 * and resets the pointer.
 *
 * @param[in] bytes_read  The number of bytes processed in the TLS record.
 * @param[in] arg         Unused argument (typically NULL).
 *
 * @return Always returns 1.
 */
static int quic_tls_rls_rec(SSL *, size_t bytes_read, void __attribute__((unused)) *arg)
{
  DBG("Called quic_tls_rls_rec of %lu bytes\n", bytes_read);
  assert(to_free->rec_len == bytes_read);
  free(to_free->record);
  free(to_free);
  to_free = NULL;
  return 1;
}

/**
 * @brief Stores cryptographic secrets and metadata for a specific protection level.
 *
 * This structure holds the transmit and receive secrets associated with a given
 * QUIC protection level, along with their lengths. It also maintains a reference
 * to the associated SSL connection and provides linkage for inclusion in a
 * singly-linked tail queue.
 */
struct prot_level_keys {
  /**
   * @brief Queue entry for linked list of protection level keys.
   */
  STAILQ_ENTRY(prot_level_keys) entries;

  /**
   * @brief Pointer to the receive secret for this protection level.
   */
  unsigned char *rx_secret;

  /**
   * @brief Length of the receive secret in bytes.
   */
  size_t rx_len;

  /**
   * @brief Pointer to the transmit secret for this protection level.
   */
  unsigned char *tx_secret;

  /**
   * @brief Length of the transmit secret in bytes.
   */
  size_t tx_len;

  /**
   * @brief Pointer to the associated SSL connection.
   */
  SSL *ssl;

  /**
   * @brief Protection level identifier (e.g., Initial, Handshake, 1-RTT).
   */
  uint32_t prot_level;
};

/**
 * @brief Defines and initializes a singly-linked tail queue of protection level keys.
 *
 * This declaration creates a `prot_level_keys_list` queue named `plist`,
 * which holds a list of `prot_level_keys` structures. The queue is initialized
 * to an empty state using `STAILQ_HEAD_INITIALIZER`.
 *
 * `prot_level_keys_list` can be used to manage the collection of secrets and
 * metadata associated with different QUIC encryption levels.
 */
STAILQ_HEAD(prot_level_keys_list, prot_level_keys) plist = STAILQ_HEAD_INITIALIZER(plist);

/**
 * @brief Removes and frees a prot_level_keys entry from the list.
 *
 * This function removes the specified `prot_level_keys` entry from the
 * `plist` queue, and frees its associated receive and transmit secrets
 * as well as the structure itself.
 *
 * @param[in] keyset Pointer to the prot_level_keys entry to remove and free.
 */
static void remove_keys(struct prot_level_keys *keyset)
{
  STAILQ_REMOVE(&plist, keyset, prot_level_keys, entries);
  free(keyset->rx_secret);
  free(keyset->tx_secret);
  free(keyset);
}

/**
 * @brief Creates and inserts a new prot_level_keys entry for the given SSL and protection level.
 *
 * This function allocates and initializes a new `prot_level_keys` structure for
 * the specified SSL connection and protection level. It inserts the new entry at
 * the tail of the `plist` queue.
 *
 * @param[in] ssl         Pointer to the SSL connection associated with the keys.
 * @param[in] prot_level  The protection level for the key entry (e.g., Initial, 1-RTT).
 *
 * @return Pointer to the newly created prot_level_keys entry.
 */
static struct prot_level_keys *make_key_entry(SSL *ssl, uint32_t prot_level)
{
  struct prot_level_keys *new = calloc(1, sizeof(struct prot_level_keys));
  assert(new != NULL);
  new->ssl = ssl;
  new->prot_level = prot_level;
  STAILQ_INSERT_TAIL(&plist, new, entries);
  return new;
}

/**
 * @brief Retrieves the prot_level_keys entry for the given SSL and protection level.
 *
 * This function searches the `plist` queue for a `prot_level_keys` entry that
 * matches the specified SSL connection and protection level. If no existing
 * entry is found, it creates a new one by calling `make_key_entry()` and inserts
 * it into the queue.
 *
 * @param[in] ssl         Pointer to the SSL connection to search for.
 * @param[in] prot_level  The protection level to match.
 *
 * @return Pointer to the found or newly created prot_level_keys entry.
 */
static struct prot_level_keys *get_keys(SSL *ssl, uint32_t prot_level)
{
  struct prot_level_keys *entry;

  STAILQ_FOREACH(entry, &plist, entries) {
    if (entry->ssl == ssl && entry->prot_level == prot_level)
      return entry;
  }
  /*
   * No existing key, make a new one
   */
  return make_key_entry(ssl, prot_level);
}

/**
 * @brief Identifiers for receive and transmit secrets.
 *
 * This enumeration defines indices used to identify receive and transmit
 * secrets within secret management structures or arrays. It helps distinguish
 * between secrets used for inbound and outbound encryption operations.
 *
 * @enum
 * @var RX_SECRET
 *      Index for the receive (RX) secret, used to decrypt incoming packets.
 * @var TX_SECRET
 *      Index for the transmit (TX) secret, used to encrypt outgoing packets.
 * @var SECRET_MAX
 *      The maximum number of secrets. Can be used to size arrays or
 *      validate indices.
 */
enum {
  RX_SECRET = 0,
  TX_SECRET,
  SECRET_MAX
};

/**
 * @brief Updates the receive or transmit secret for the given key entry.
 *
 * This function allocates memory and updates the receive (RX) or transmit (TX)
 * secret in the specified `prot_level_keys` entry with the provided secret data.
 * It also updates the length of the stored secret.
 *
 * If the opposite direction secret (RX vs. TX) is already set, the return value
 * is incremented to reflect that both secrets are now populated.
 *
 * @param[in,out] key     Pointer to the prot_level_keys entry to update.
 * @param[in]     secret  Pointer to the new secret data to store.
 * @param[in]     len     Length of the secret in bytes.
 * @param[in]     rx_tx   Direction identifier. Use RX_SECRET for receive or
 *                        TX_SECRET for transmit.
 *
 * @return A value indicating how many secrets have been set:
 *         - 1 if this is the first secret being set.
 *         - 2 if both RX and TX secrets are now set.
 */
static int update_secret(struct prot_level_keys *key,
                         const unsigned char *secret,
                         size_t len, uint8_t rx_tx)
{
  int ret = 0;
  unsigned char *lsecret;
  size_t *llen;

  assert(rx_tx < SECRET_MAX);

  if (rx_tx == RX_SECRET) {
    key->rx_secret = malloc(len);
    lsecret = key->rx_secret;
    llen = &key->rx_len;
    if (key->tx_secret != NULL)
      ret++;
  } else {
    key->tx_secret = malloc(len);
    lsecret = key->tx_secret;
    llen = &key->tx_len;
    if (key->rx_secret != NULL)
      ret++;
  }
  ret++;
  assert(lsecret != NULL);
  memcpy(lsecret, secret, len);
  *llen = len;
  return ret;
}

/**
 * @brief Callback to yield TLS secrets to the QUIC stack.
 *
 * This function is invoked by OpenSSL to provide traffic secrets during
 * the QUIC handshake. It installs the given secret into the ngtcp2 QUIC
 * connection, either as a read (RX) key or write (TX) key depending on
 * the direction.
 *
 * @param[in] s           Pointer to the SSL connection object.
 * @param[in] prot_level  OpenSSL encryption level of the secret.
 * @param[in] dir         Direction of the key. 1 for read (RX) key,
 *                        0 for write (TX) key.
 * @param[in] secret      Pointer to the secret to be installed.
 * @param[in] secret_len  Length of the secret.
 * @param[in] arg         Unused argument (typically NULL).
 *
 * @return 1 on success, 0 on failure.
 */
static int quic_tls_yield_secret(SSL *s, uint32_t prot_level, int dir,
                                 const unsigned char *secret,
                                 size_t secret_len, void __attribute__((unused)) *arg)
{
  ngtcp2_crypto_conn_ref *conn_ref;
  ngtcp2_conn *conn;
  ngtcp2_encryption_level level;
  int rv;
  struct prot_level_keys *keyset = get_keys(s, prot_level);

  DBG("Called quic_tls_yield_secret for %s level %d\n",
    dir == 1 ? "read" :"write", prot_level);

  rv = update_secret(keyset, secret, secret_len,
                     dir == 1 ? RX_SECRET : TX_SECRET);

  /*
   * We have both keys
   */
  if (rv == 2) {
    DBG("Both secrets acquired, installing to ngtcp2\n");
    conn_ref = SSL_get_app_data(s);
    conn = conn_ref->get_conn(conn_ref);
    level = ngtcp2_crypto_openssl_from_ossl_encryption_level(keyset->prot_level);
    rv = ngtcp2_crypto_derive_and_install_rx_key(conn, NULL, NULL, NULL,
                                                 level, keyset->rx_secret,
                                                 keyset->rx_len);
    if (rv == 1) {
      DBG("Failed to install rx key\n");
      return 0;
    }
    rv = ngtcp2_crypto_derive_and_install_tx_key(conn, NULL, NULL, NULL,
                                                 level, keyset->tx_secret,
                                                 keyset->tx_len);
    if (rv == 1) {
      DBG("Failed to install tx key\n");
      return 0;
    }

    remove_keys(keyset);
    return 1;
  }

  return 1;
}

/**
 * @brief Callback invoked when transport parameters are received from peer.
 *
 * This function is called by OpenSSL when remote QUIC transport parameters
 * are received during the TLS handshake. It decodes and applies these
 * parameters to the QUIC connection. If decoding fails, it sets a TLS
 * error on the connection.
 *
 * @param[in] s           Pointer to the SSL connection object.
 * @param[in] params      Pointer to the buffer containing transport
 *                        parameters from the peer.
 * @param[in] params_len  Length of the transport parameters buffer.
 * @param[in] arg         Unused argument (typically NULL).
 *
 * @return 1 on success, -1 on failure.
 */
static int quic_tls_got_tp(SSL *s, const unsigned char *params,
                           size_t params_len, __attribute__((unused)) void *arg)
{
  int rv;
  ngtcp2_crypto_conn_ref *conn_ref = SSL_get_app_data(s);
  ngtcp2_conn *conn = conn_ref->get_conn(conn_ref);

  DBG("Called quic_tls_got_tp\n");
  rv = ngtcp2_conn_decode_and_set_remote_transport_params(conn, params, params_len);
  if (rv != 0) {
    ngtcp2_conn_set_tls_error(conn, rv);
    return -1;
  }

  return 1;
}

/**
 * @brief Callback invoked when a TLS alert is generated or received.
 *
 * This function is called by OpenSSL when a TLS alert is triggered
 * during the handshake or connection. It logs the alert event for
 * debugging purposes.
 *
 * @param[in] s           Pointer to the SSL connection object (unused).
 * @param[in] alert_code  The TLS alert code (unused).
 * @param[in] arg         Unused argument (typically NULL).
 *
 * @return Always returns 1.
 */
static int quic_tls_alert(SSL __attribute__((unused)) *s,
                          unsigned int alert_code,
                          __attribute__((unused)) void *arg)
{
  ngtcp2_crypto_conn_ref *conn_ref = SSL_get_app_data(s);
  ngtcp2_conn *conn = conn_ref->get_conn(conn_ref);

  DBG("Called quic_tls_alert\n");
  ngtcp2_conn_set_tls_alert(conn, (uint8_t)alert_code);

  return 1;
}


/**
 * @brief OpenSSL QUIC TLS callback dispatch table.
 *
 * This array defines a set of function pointers that OpenSSL uses to
 * interact with the QUIC transport layer in a QUIC-enabled TLS session.
 * Each entry maps a specific OpenSSL QUIC operation to its corresponding
 * callback implementation.
 *
 * The dispatch table includes:
 * - @ref quic_tls_send: Sends handshake data to the QUIC stack.
 * - @ref quic_tls_rcv_rec: Provides received handshake data to OpenSSL.
 * - @ref quic_tls_rls_rec: Releases processed handshake records.
 * - @ref quic_tls_yield_secret: Supplies derived secrets to the QUIC stack.
 * - @ref quic_tls_got_tp: Handles received transport parameters.
 * - @ref quic_tls_alert: Processes TLS alerts.
 *
 * This table is registered with OpenSSL using SSL_set_quic_tls_cbs().
 */
static OSSL_DISPATCH openssl_quic_dispatch[] = {
  {OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND, (void (*)(void))quic_tls_send},
  {OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD, (void (*)(void))quic_tls_rcv_rec},
  {OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD, (void (*)(void))quic_tls_rls_rec},
  {OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET, (void (*)(void))quic_tls_yield_secret},
  {OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS, (void (*)(void))quic_tls_got_tp},
  {OSSL_FUNC_SSL_QUIC_TLS_ALERT, (void (*)(void))quic_tls_alert}
};

/**
 * @brief Frees the associated app data for our write biod
 *
 * This function is the registered callback for our write_bio
 * Its largely vestigual, simply returning whatever was passed to it
 * except when we get a free callback, in which case we free the associated
 * rx queue that we have set as its app data
 * This allows us to clean up that memory when the ngtcp2 library frees the 
 * associated ssl
 *
 * @param[in] b - bio being acted upon
 * @param[in] oper - the operation being conducted
 * @param[in] *argp - relevant arguments to the operation (unused)
 * @param[in] len - the size of the data being processed (unused)
 * @param[in] argi - context dependent argument (unused)
 * @param[in] arg1 - context dependent argument (unused)
 * @param[in] ret - the return code to return
 * @param[in] *processed - the amount of data consumed (unused)
 *
 * @returns ret always
 */
static long free_bio_app_data(BIO *b, int oper,
                              __attribute__((unused)) const char *argp,
                              __attribute__((unused)) size_t len,
                              __attribute__((unused)) int argi,
                              __attribute__((unused)) long arg1,
                              __attribute__((unused)) int ret,
                              __attribute__((unused)) size_t *processed)
{
    struct record_list *rlist;

    if (oper == BIO_CB_FREE) {
        rlist = BIO_get_app_data(b);
        free(rlist);
        BIO_set_app_data(b, NULL);
    }
    return ret;
}

/**
 * @brief Configures an OpenSSL QUIC TLS session for use with ngtcp2.
 *
 * This function sets up the OpenSSL QUIC TLS callbacks and attaches dummy
 * BIOs to the provided SSL session. The callbacks enable OpenSSL to
 * communicate with the QUIC transport layer, while the dummy BIOs prevent
 * OpenSSL from performing I/O directly, as data is managed by ngtcp2.
 *
 * Specifically:
 * - TLS callbacks are registered to handle sending, receiving, and other
 *   TLS events.
 * - NULL BIOs are attached to the SSL object to sink any data OpenSSL
 *   writes, since actual data transmission is handled by QUIC callbacks
 *   (e.g., quic_tls_send and quic_tls_rcv_rec).
 *
 * @param[in] ssl   Pointer to the SSL session to configure.
 */
static void crypto_openssl_configure_session(SSL *ssl) {
  BIO *ssl_read_bio = NULL;
  BIO *ssl_write_bio = NULL;
  struct record_list *rlist;

  if (!SSL_set_quic_tls_cbs(ssl, openssl_quic_dispatch, NULL))
    ERR_print_errors_fp(stderr);

  /*
   * We need to plug in two bios here
   * They can both be NULL bios as we're setup to push data back
   * to the ngtcp2 stack via qulc_tls_send, and pull data back in
   * via quic_tls_rcv_rec, so any data that the openssl stack tries to 
   * write to the bio can get immediately sunk
   */
  ssl_read_bio = BIO_new(BIO_s_null());
  if (ssl_read_bio == NULL)
    ERR_print_errors_fp(stderr);
  ssl_write_bio = BIO_new(BIO_s_null());
  if (ssl_write_bio == NULL)
    ERR_print_errors_fp(stderr);
  BIO_set_mem_eof_return(ssl_write_bio, -1);
  SSL_set_bio(ssl, ssl_write_bio, ssl_read_bio);

  rlist = calloc(1, sizeof(struct record_list));
  if (rlist == NULL)
    return;
  STAILQ_INIT(rlist);
  BIO_set_app_data(ssl_write_bio, rlist);
  BIO_set_callback_ex(ssl_write_bio, free_bio_app_data);
}

/**
 * @brief Configures an OpenSSL server-side TLS session for QUIC.
 *
 * This function applies QUIC-specific settings to the provided OpenSSL
 * `SSL` object for a server session. It calls an internal helper to
 * configure the session appropriately.
 *
 * @param[in,out] ssl  Pointer to the OpenSSL SSL object representing
 *                     the server session.
 *
 * @return Always returns 0.
 */
int ngtcp2_crypto_openssl_configure_server_session(SSL *ssl) {
  crypto_openssl_configure_session(ssl);
  return 0;
}

/**
 * @brief Configures an OpenSSL client-side TLS session for QUIC.
 *
 * This function applies QUIC-specific settings to the provided OpenSSL
 * `SSL` object for a client session. It calls an internal helper to
 * configure the session appropriately.
 *
 * @param[in,out] ssl  Pointer to the OpenSSL SSL object representing
 *                     the client session.
 *
 * @return Always returns 0.
 */
int ngtcp2_crypto_openssl_configure_client_session(SSL *ssl) {
  crypto_openssl_configure_session(ssl);
  return 0;
}

/**
 * @brief Configures an OpenSSL server-side SSL_CTX for use with QUIC.
 *
 * This function applies QUIC-specific settings to the provided OpenSSL
 * `SSL_CTX` object for server connections. It ensures that only TLS 1.3
 * is used as required by QUIC.
 *
 * @param[in,out] ssl_ctx  Pointer to the OpenSSL SSL_CTX object for the server.
 *
 * @return Always returns 0.
 */
int ngtcp2_crypto_openssl_configure_server_context(SSL_CTX *ssl_ctx) {
  crypto_openssl_configure_context(ssl_ctx);

  return 0;
}

/**
 * @brief Configures an OpenSSL client-side SSL_CTX for use with QUIC.
 *
 * This function applies QUIC-specific settings to the provided OpenSSL
 * `SSL_CTX` object for client connections. It ensures that only TLS 1.3
 * is used as required by QUIC.
 *
 * @param[in,out] ssl_ctx  Pointer to the OpenSSL SSL_CTX object for the client.
 *
 * @return Always returns 0.
 */
int ngtcp2_crypto_openssl_configure_client_context(SSL_CTX *ssl_ctx) {
  crypto_openssl_configure_context(ssl_ctx);

  return 0;
}
