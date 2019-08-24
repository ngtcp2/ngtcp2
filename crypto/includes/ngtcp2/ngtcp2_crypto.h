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
#ifndef NGTCP2_CRYPTO_H
#define NGTCP2_CRYPTO_H

#include <ngtcp2/ngtcp2.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @struct
 *
 * `ngtcp2_crypto_md` is a wrapper around native message digest
 * object.
 *
 * If libngtcp2_crypto_openssl is linked, native_handle must be a
 * pointer to EVP_MD.
 */
typedef struct ngtcp2_crypto_md {
  void *native_handle;
} ngtcp2_crypto_md;

/**
 * @struct
 *
 * `ngtcp2_crypto_aead` is a wrapper around native AEAD object.
 *
 * If libngtcp2_crypto_openssl is linked, native_handle must be a
 * pointer to EVP_CIPHER.
 */
typedef struct ngtcp2_crypto_aead {
  void *native_handle;
} ngtcp2_crypto_aead;

/**
 * @struct
 *
 * `ngtcp2_crypto_cipher` is a wrapper around native cipher object.
 *
 * If libngtcp2_crypto_openssl is linked, native_handle must be a
 * pointer to EVP_CIPHER.
 */
typedef struct ngtcp2_crypto_cipher {
  void *native_handle;
} ngtcp2_crypto_cipher;

/**
 * @function
 *
 * `ngtcp2_crypto_ctx` is a convenient structure to bind all crypto
 * related objects in one place.  Use `ngtcp2_crypto_ctx_initial` to
 * initialize this struct for Initial packet encryption.  For
 * Handshake and Shortpackets, use `ngtcp2_crypto_ctx_tls`.
 */
typedef struct ngtcp2_crypto_ctx {
  ngtcp2_crypto_aead aead;
  ngtcp2_crypto_md md;
  ngtcp2_crypto_cipher hp;
} ngtcp2_crypto_ctx;

/**
 * @function
 *
 * `ngtcp2_crypto_ctx_initial` initializes |ctx| for Initial packet
 * encryption and decryption.
 */
NGTCP2_EXTERN ngtcp2_crypto_ctx *
ngtcp2_crypto_ctx_initial(ngtcp2_crypto_ctx *ctx);

/**
 * @function
 *
 * `ngtcp2_crypto_ctx_tls` initializes |ctx| by extracting negotiated
 * ciphers and message digests from native TLS session
 * |tls_native_handle|.  This is used for encrypting/decrypting
 * Handshake and Short packets.
 *
 * If libngtcp2_crypto_openssl is linked, |tls_native_handle| must be
 * a pointer to SSL object.
 */
NGTCP2_EXTERN ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_tls(ngtcp2_crypto_ctx *ctx,
                                                       void *tls_native_handle);

/**
 * @function
 *
 * `ngtcp2_crypto_aead_keylen` returns the length of key for |aead|.
 */
NGTCP2_EXTERN size_t ngtcp2_crypto_aead_keylen(ngtcp2_crypto_aead *aead);

/**
 * @function
 *
 * `ngtcp2_crypto_aead_noncelen` returns the length of nonce for
 * |aead|.
 */
NGTCP2_EXTERN size_t ngtcp2_crypto_aead_noncelen(ngtcp2_crypto_aead *aead);

/**
 * @function
 *
 * `ngtcp2_crypto_aead_taglen` returns the length of tag for |aead|.
 */
NGTCP2_EXTERN size_t ngtcp2_crypto_aead_taglen(ngtcp2_crypto_aead *aead);

/**
 * @function
 *
 * `ngtcp2_crypto_hkdf_extract` performs HKDF extract operation.  The
 * result is |destlen| bytes long and is stored to the buffer pointed
 * by |dest|.
 *
 * This function returns 0 if it succeeds, or -1.
 */
NGTCP2_EXTERN int
ngtcp2_crypto_hkdf_extract(uint8_t *dest, size_t destlen, ngtcp2_crypto_md *md,
                           const uint8_t *secret, size_t secretlen,
                           const uint8_t *salt, size_t saltlen);

/**
 * @function
 *
 * `ngtcp2_crypto_hkdf_expand` performs HKDF expand operation.  The
 * result is |destlen| bytes long and is stored to the buffer pointed
 * by |dest|.
 *
 * This function returns 0 if it succeeds, or -1.
 */
NGTCP2_EXTERN int
ngtcp2_crypto_hkdf_expand(uint8_t *dest, size_t destlen, ngtcp2_crypto_md *md,
                          const uint8_t *secret, size_t secretlen,
                          const uint8_t *info, size_t infolen);

/**
 * @function
 *
 * `ngtcp2_crypto_hkdf_expand_label` performs HKDF expand label.  The
 * result is |destlen| bytes long and is stored to the buffer pointed
 * by |dest|.
 *
 * This function returns 0 if it succeeds, or -1.
 */
NGTCP2_EXTERN int ngtcp2_crypto_hkdf_expand_label(
    uint8_t *dest, size_t destlen, ngtcp2_crypto_md *md, const uint8_t *secret,
    size_t secretlen, const uint8_t *label, size_t labellen);

/**
 * @enum
 *
 * `ngtcp2_crypto_side` indicates which side the application
 * implements; client or server.
 */
typedef enum ngtcp2_crypto_side {
  /**
   * ``NGTCP2_CRYPTO_SIDE_CLIENT`` indicates that the application is
   * client.
   */
  NGTCP2_CRYPTO_SIDE_CLIENT,
  /**
   * ``NGTCP2_CRYPTO_SIDE_SERVER`` indicates that the application is
   * server.
   */
  NGTCP2_CRYPTO_SIDE_SERVER
} ngtcp2_crypto_side;

/**
 * @function
 *
 * `ngtcp2_crypto_derive_initial_secrets` derives initial secrets.
 * |rx_secret| and |tx_secret| must point to the buffer of at least 32
 * bytes capacity.  rx for read and tx for write.  This function
 * writes rx and tx secrets into |rx_secret| and |tx_secret|
 * respectively.  The length of secret is 32 bytes long.
 * |client_dcid| is the destination connection ID in first Initial
 * packet of client.  If |initial_secret| is not NULL, the initial
 * secret is written to it.  It must point to the buffer which has at
 * least 32 bytes capacity.  The initial secret is 32 bytes long.
 * |side| specifies the side of application.
 *
 * This function returns 0 if it succeeds, or -1.
 */
NGTCP2_EXTERN int ngtcp2_crypto_derive_initial_secrets(
    uint8_t *rx_secret, uint8_t *tx_secret, uint8_t *initial_secret,
    const ngtcp2_cid *client_dcid, ngtcp2_crypto_side side);

/**
 * @function
 *
 * `ngtcp2_crypto_packet_protection_ivlen` returns the length of IV
 * used to encrypt QUIC packet.
 */
NGTCP2_EXTERN size_t
ngtcp2_crypto_packet_protection_ivlen(ngtcp2_crypto_aead *aead);

/**
 * @function
 *
 * `ngtcp2_crypto_derive_packet_protection_key` dervies packet
 * protection key.  This function writes packet protection key into
 * the buffer pointed by |key|.  |key| must point to the buffer which
 * is at least ngtcp2_crypto_aead_keylen(aead) bytes long.  This
 * function writes packet protection IV into |iv|.  |iv| must point to
 * the buffer which is at least
 * ngtcp2_crypto_packet_protection_ivlen(aead).  |key| is
 * ngtcp2_crypto_aead_keylen(aead) bytes long.  |iv| is
 * ngtcp2_crypto_packet_protection_ivlen(aead) bytes long.
 *
 * This function returns 0 if it succeeds, or -1.
 */
NGTCP2_EXTERN int ngtcp2_crypto_derive_packet_protection_key(
    uint8_t *key, uint8_t *iv, ngtcp2_crypto_aead *aead, ngtcp2_crypto_md *md,
    const uint8_t *secret, size_t secretlen);

/**
 * @function
 *
 * `ngtcp2_crypto_derive_header_protection_key` derives packet header
 * protection key.  This function writes packet header protection key
 * into the buffer pointed by |key|.  |key| must point to the buffer
 * which is at least ngtcp2_crypto_aead_keylen(aead) bytes long.
 * |key| is ngtcp2_crypto_aead_keylen(aead) bytes long.
 *
 * This function returns 0 if it succeeds, or -1.
 */
NGTCP2_EXTERN int ngtcp2_crypto_derive_header_protection_key(
    uint8_t *key, ngtcp2_crypto_aead *aead, ngtcp2_crypto_md *md,
    const uint8_t *secret, size_t secretlen);

/**
 * @function
 *
 * `ngtcp2_crypto_encrypt` encrypts |plaintext| of length
 * |plaintextlen| and writes the ciphertext into the buffer pointed by
 * |dest|.  The length of ciphertext is plaintextlen +
 * ngtcp2_crypto_aead_taglen(aead) bytes long.  |dest| must have
 * enough capacity to store the ciphertext.  It is allowed to specify
 * the same value to |dest| and |plaintext|.
 *
 * This function returns 0 if it succeeds, or -1.
 */
NGTCP2_EXTERN int ngtcp2_crypto_encrypt(uint8_t *dest, ngtcp2_crypto_aead *aead,
                                        const uint8_t *plaintext,
                                        size_t plaintextlen, const uint8_t *key,
                                        const uint8_t *nonce, size_t noncelen,
                                        const uint8_t *ad, size_t adlen);

/**
 * @function
 *
 * `ngtcp2_crypto_decrypt` decrypts |ciphertext| of length
 * |ciphertextlen| and writes the plaintext into the buffer pointed by
 * |dest|.  The length of plaintext is ciphertextlen -
 * ngtcp2_crypto_aead_taglen(aead) bytes log.  |dest| must have enough
 * capacity to store the plaintext.  It is allowed to specify the same
 * value to |dest| and |ciphertext|.
 *
 * This function returns 0 if it succeeds, or -1.
 */
NGTCP2_EXTERN int ngtcp2_crypto_decrypt(uint8_t *dest, ngtcp2_crypto_aead *aead,
                                        const uint8_t *ciphertext,
                                        size_t ciphertextlen,
                                        const uint8_t *key,
                                        const uint8_t *nonce, size_t noncelen,
                                        const uint8_t *ad, size_t adlen);

/**
 * @function
 *
 * `ngtcp2_crypto_hp_mask` generates mask which is used in packet
 * header encryption.  The mask is written to the buffer pointed by
 * |dest|.  The length of mask is 5 bytes.  |dest| must have enough
 * capacity to store the mask.
 *
 * This function returns 0 if it succeeds, or -1.
 */
NGTCP2_EXTERN int ngtcp2_crypto_hp_mask(uint8_t *dest, ngtcp2_crypto_cipher *hp,
                                        const uint8_t *key,
                                        const uint8_t *sample);

/**
 * @function
 *
 * `ngtcp2_crypto_update_traffic_secret` derives the next generation
 * of the traffic secret.  |secret| specifies the current secret and
 * its length is given in |secretlen|.  The length of new key is the
 * same as the current key.  This function writes new key into the
 * buffer pointed by |dest|.  |dest| must have the enough capacity to
 * store the new key.
 */
NGTCP2_EXTERN int ngtcp2_crypto_update_traffic_secret(uint8_t *dest,
                                                      ngtcp2_crypto_md *md,
                                                      const uint8_t *secret,
                                                      size_t secretlen);

#ifdef __cplusplus
}
#endif

#endif /* NGTCP2_CRYPTO_H */
