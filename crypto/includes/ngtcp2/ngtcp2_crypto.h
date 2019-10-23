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

#define NGTCP2_CRYPTO_INITIAL_SECRETLEN 32
#define NGTCP2_CRYPTO_INITIAL_KEYLEN 16
#define NGTCP2_CRYPTO_INITIAL_IVLEN 12

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
NGTCP2_EXTERN size_t ngtcp2_crypto_aead_keylen(const ngtcp2_crypto_aead *aead);

/**
 * @function
 *
 * `ngtcp2_crypto_aead_noncelen` returns the length of nonce for
 * |aead|.
 */
NGTCP2_EXTERN size_t
ngtcp2_crypto_aead_noncelen(const ngtcp2_crypto_aead *aead);

/**
 * @function
 *
 * `ngtcp2_crypto_aead_taglen` returns the length of tag for |aead|.
 */
NGTCP2_EXTERN size_t ngtcp2_crypto_aead_taglen(const ngtcp2_crypto_aead *aead);

/**
 * @function
 *
 * `ngtcp2_crypto_hkdf_extract` performs HKDF extract operation.  The
 * result is |destlen| bytes long and is stored to the buffer pointed
 * by |dest|.
 *
 * This function returns 0 if it succeeds, or -1.
 */
NGTCP2_EXTERN int ngtcp2_crypto_hkdf_extract(uint8_t *dest, size_t destlen,
                                             const ngtcp2_crypto_md *md,
                                             const uint8_t *secret,
                                             size_t secretlen,
                                             const uint8_t *salt,
                                             size_t saltlen);

/**
 * @function
 *
 * `ngtcp2_crypto_hkdf_expand` performs HKDF expand operation.  The
 * result is |destlen| bytes long and is stored to the buffer pointed
 * by |dest|.
 *
 * This function returns 0 if it succeeds, or -1.
 */
NGTCP2_EXTERN int ngtcp2_crypto_hkdf_expand(uint8_t *dest, size_t destlen,
                                            const ngtcp2_crypto_md *md,
                                            const uint8_t *secret,
                                            size_t secretlen,
                                            const uint8_t *info,
                                            size_t infolen);

/**
 * @function
 *
 * `ngtcp2_crypto_hkdf_expand_label` performs HKDF expand label.  The
 * result is |destlen| bytes long and is stored to the buffer pointed
 * by |dest|.
 *
 * This function returns 0 if it succeeds, or -1.
 */
NGTCP2_EXTERN int ngtcp2_crypto_hkdf_expand_label(uint8_t *dest, size_t destlen,
                                                  const ngtcp2_crypto_md *md,
                                                  const uint8_t *secret,
                                                  size_t secretlen,
                                                  const uint8_t *label,
                                                  size_t labellen);

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
ngtcp2_crypto_packet_protection_ivlen(const ngtcp2_crypto_aead *aead);

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
 * If |hp| is not NULL, this function also derives packet header
 * protection key and writes the key into the buffer pointed by |hp|.
 * The length of key is ngtcp2_crypto_aead_keylen(aead) bytes long.
 * |hp|, if not NULL, must have enough capacity to store the key.
 *
 * This function returns 0 if it succeeds, or -1.
 */
NGTCP2_EXTERN int ngtcp2_crypto_derive_packet_protection_key(
    uint8_t *key, uint8_t *iv, uint8_t *hp, const ngtcp2_crypto_aead *aead,
    const ngtcp2_crypto_md *md, const uint8_t *secret, size_t secretlen);

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
NGTCP2_EXTERN int ngtcp2_crypto_encrypt(uint8_t *dest,
                                        const ngtcp2_crypto_aead *aead,
                                        const uint8_t *plaintext,
                                        size_t plaintextlen, const uint8_t *key,
                                        const uint8_t *nonce, size_t noncelen,
                                        const uint8_t *ad, size_t adlen);

/**
 * @function
 *
 * `ngtcp2_crypto_encrypt_cb` is a wrapper function around
 * `ngtcp2_crypto_encrypt`.  It can be directly passed to encrypt
 * callback to ngtcp2_callbacks.
 *
 * This function returns 0 if it succeeds, or
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE`.
 */
NGTCP2_EXTERN int ngtcp2_crypto_encrypt_cb(
    ngtcp2_conn *conn, uint8_t *dest, const ngtcp2_crypto_aead *aead,
    const uint8_t *plaintext, size_t plaintextlen, const uint8_t *key,
    const uint8_t *nonce, size_t noncelen, const uint8_t *ad, size_t adlen,
    void *user_data);

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
NGTCP2_EXTERN int
ngtcp2_crypto_decrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                      const uint8_t *ciphertext, size_t ciphertextlen,
                      const uint8_t *key, const uint8_t *nonce, size_t noncelen,
                      const uint8_t *ad, size_t adlen);

/**
 * @function
 *
 * `ngtcp2_crypto_decrypt_cb` is a wrapper function around
 * `ngtcp2_crypto_decrypt`.  It can be directly passed to decrypt
 * callback to ngtcp2_callbacks.
 *
 * This function returns 0 if it succeeds, or
 * :enum:`NGTCP2_ERR_TLS_DECRYPT`.
 */
NGTCP2_EXTERN int ngtcp2_crypto_decrypt_cb(
    ngtcp2_conn *conn, uint8_t *dest, const ngtcp2_crypto_aead *aead,
    const uint8_t *ciphertext, size_t ciphertextlen, const uint8_t *key,
    const uint8_t *nonce, size_t noncelen, const uint8_t *ad, size_t adlen,
    void *user_data);

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
NGTCP2_EXTERN int ngtcp2_crypto_hp_mask(uint8_t *dest,
                                        const ngtcp2_crypto_cipher *hp,
                                        const uint8_t *key,
                                        const uint8_t *sample);

/**
 * @function
 *
 * `ngtcp2_crypto_hp_mask_cb` is a wrapper function around
 * `ngtcp2_crypto_hp_mask`.  It can be directly passed to hp_mask
 * callback to ngtcp2_callbacks.
 *
 * This function returns 0 if it succeeds, or
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE`.
 */
NGTCP2_EXTERN int ngtcp2_crypto_hp_mask_cb(ngtcp2_conn *conn, uint8_t *dest,
                                           const ngtcp2_crypto_cipher *hp,
                                           const uint8_t *key,
                                           const uint8_t *sample,
                                           void *user_data);

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
NGTCP2_EXTERN int
ngtcp2_crypto_update_traffic_secret(uint8_t *dest, const ngtcp2_crypto_md *md,
                                    const uint8_t *secret, size_t secretlen);

/**
 * @function
 *
 * `ngtcp2_crypto_derive_and_install_key` derives the rx and tx keys
 * from |rx_secret| and |tx_secret| respectively and installs new keys
 * to |conn|.
 *
 * If |rx_key| is not NULL, the derived packet protection key for
 * decryption is written to the buffer pointed by |rx_key|.  If
 * |rx_iv| is not NULL, the derived packet protection IV for
 * decryption is written to the buffer pointed by |rx_iv|.  If |rx_hp|
 * is not NULL, the derived header protection key for decryption is
 * written to the buffer pointed by |rx_hp|.
 *
 * If |tx_key| is not NULL, the derived packet protection key for
 * encryption is written to the buffer pointed by |tx_key|.  If
 * |tx_iv| is not NULL, the derived packet protection IV for
 * encryption is written to the buffer pointed by |tx_iv|.  If |tx_hp|
 * is not NULL, the derived header protection key for encryption is
 * written to the buffer pointed by |tx_hp|.
 *
 * |level| specifies the encryption level.  If |level| is
 * NGTCP2_CRYPTO_LEVEL_EARLY, and if |side| is
 * NGTCP2_CRYPTO_SIDE_CLIENT, |rx_secret| must be NULL.  If |level| is
 * NGTCP2_CRYPTO_LEVEL_EARLY, and if |side| is
 * NGTCP2_CRYPTO_SIDE_SERVER, |tx_secret| must be NULL.  Otherwise,
 * |rx_secret| and |tx_secret| must not be NULL.
 *
 * |secretlen| specifies the length of |rx_secret| and |tx_secret|.
 *
 * The length of packet protection key and header protection key is
 * ngtcp2_crypto_aead(ctx->aead), and the length of packet protection
 * IV is ngtcp2_crypto_packet_protection_ivlen(ctx->aead) where ctx
 * can be obtained by `ngtcp2_crypto_ctx_tls`.
 *
 * In the first call of this function, it calls
 * `ngtcp2_conn_set_crypto_ctx` to set negotiated AEAD and message
 * digest algorithm.  After the successful call of this function,
 * application can use `ngtcp2_conn_get_crypto_ctx` to get the object.
 * It also calls `ngtcp2_conn_set_aead_overhead` to set AEAD tag
 * length.
 *
 * If |level| is NGTCP2_CRYPTO_LEVEL_APP, this function retrieves a
 * remote QUIC transport parameters extension from |tls| and sets it
 * to |conn|.
 *
 * This function returns 0 if it succeeds, or -1.
 */
NGTCP2_EXTERN int ngtcp2_crypto_derive_and_install_key(
    ngtcp2_conn *conn, void *tls, uint8_t *rx_key, uint8_t *rx_iv,
    uint8_t *rx_hp, uint8_t *tx_key, uint8_t *tx_iv, uint8_t *tx_hp,
    ngtcp2_crypto_level level, const uint8_t *rx_secret,
    const uint8_t *tx_secret, size_t secretlen, ngtcp2_crypto_side side);

/**
 * @function
 *
 * `ngtcp2_crypto_derive_and_install_initial_key` derives initial
 * keying materials and installs keys to |conn|.
 *
 * If |rx_secret| is not NULL, the secret for decryption is written to
 * the buffer pointed by |rx_secret|.  The length of secret is 32
 * bytes, and |rx_secret| must point to the buffer which has enough
 * capacity.
 *
 * If |tx_secret| is not NULL, the secret for encryption is written to
 * the buffer pointed by |tx_secret|.  The length of secret is 32
 * bytes, and |tx_secret| must point to the buffer which has enough
 * capacity.
 *
 * If |initial_secret| is not NULL, the initial secret is written to
 * the buffer pointed by |initial_secret|.  The length of secret is 32
 * bytes, and |initial_secret| must point to the buffer which has
 * enough capacity.
 *
 * |client_dcid| is the destination connection ID in first Initial
 * packet of client.
 *
 * If |rx_key| is not NULL, the derived packet protection key for
 * decryption is written to the buffer pointed by |rx_key|.  If
 * |rx_iv| is not NULL, the derived packet protection IV for
 * decryption is written to the buffer pointed by |rx_iv|.  If |rx_hp|
 * is not NULL, the derived header protection key for decryption is
 * written to the buffer pointed by |rx_hp|.
 *
 * If |tx_key| is not NULL, the derived packet protection key for
 * encryption is written to the buffer pointed by |tx_key|.  If
 * |tx_iv| is not NULL, the derived packet protection IV for
 * encryption is written to the buffer pointed by |tx_iv|.  If |tx_hp|
 * is not NULL, the derived header protection key for encryption is
 * written to the buffer pointed by |tx_hp|.
 *
 * The length of packet protection key and header protection key is 16
 * bytes long.  The length of packet protection IV is 12 bytes long.
 *
 * This function calls `ngtcp2_conn_set_initial_crypto_ctx` to set
 * initial AEAD and message digest algorithm.  After the successful
 * call of this function, application can use
 * `ngtcp2_conn_get_initial_crypto_ctx` to get the object.
 *
 * This function returns 0 if it succeeds, or -1.
 */
NGTCP2_EXTERN int ngtcp2_crypto_derive_and_install_initial_key(
    ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
    uint8_t *initial_secret, uint8_t *rx_key, uint8_t *rx_iv, uint8_t *rx_hp,
    uint8_t *tx_key, uint8_t *tx_iv, uint8_t *tx_hp,
    const ngtcp2_cid *client_dcid, ngtcp2_crypto_side side);

/**
 * @function
 *
 * `ngtcp2_crypto_update_and_install_key` updates traffic keying
 * materials and installs keys to |conn|.
 *
 * The new traffic secret for decryption is written to the buffer
 * pointed by |rx_secret|.  The length of secret is |secretlen| bytes,
 * and |rx_secret| must point to the buffer which has enough capacity.
 *
 * The new traffic secret for encryption is written to the buffer
 * pointed by |tx_secret|.  The length of secret is |secretlen| bytes,
 * and |tx_secret| must point to the buffer which has enough capacity.
 *
 * If |rx_key| is not NULL, the derived packet protection key for
 * decryption is written to the buffer pointed by |rx_key|.  If
 * |rx_iv| is not NULL, the derived packet protection IV for
 * decryption is written to the buffer pointed by |rx_iv|.  If |rx_hp|
 * is not NULL, the derived header protection key for decryption is
 * written to the buffer pointed by |rx_hp|.
 *
 * If |tx_key| is not NULL, the derived packet protection key for
 * encryption is written to the buffer pointed by |tx_key|.  If
 * |tx_iv| is not NULL, the derived packet protection IV for
 * encryption is written to the buffer pointed by |tx_iv|.  If |tx_hp|
 * is not NULL, the derived header protection key for encryption is
 * written to the buffer pointed by |tx_hp|.
 *
 * |current_rx_secret| and |current_tx_secret| are the current traffic
 * secrets for decryption and encryption.  |secretlen| specifies the
 * length of |rx_secret| and |tx_secret|.
 *
 * The length of packet protection key and header protection key is
 * ngtcp2_crypto_aead(ctx->aead), and the length of packet protection
 * IV is ngtcp2_crypto_packet_protection_ivlen(ctx->aead) where ctx
 * can be obtained by `ngtcp2_conn_get_crypto_ctx`.
 *
 * This function returns 0 if it succeeds, or -1.
 */
NGTCP2_EXTERN int ngtcp2_crypto_update_and_install_key(
    ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret, uint8_t *rx_key,
    uint8_t *rx_iv, uint8_t *tx_key, uint8_t *tx_iv,
    const uint8_t *current_rx_secret, const uint8_t *current_tx_secret,
    size_t secretlen);

/**
 * @function
 *
 * `ngtcp2_crypto_read_write_crypto_data` reads CRYPTO data |data| of
 * length |datalen| in encryption level |crypto_level| and may feed
 * outgoing CRYPTO data to |conn|.  This function can drive handshake.
 * This function can be also used after handshake completes.  It is
 * allowed to call this function with datalen == 0.  In this case, no
 * additional read operation is done.
 *
 * |tls| points to a implementation dependent TLS session object.  If
 * libngtcp2_crypto_openssl is linked, |tls| must be a pointer to SSL
 * object.
 *
 * This function returns 0 if it succeeds, or a negative error code.
 * The generic error code is -1 if a specific error code is not
 * suitable.  The error codes less than -10000 are specific to
 * underlying TLS implementation.  For OpenSSL, the error codes are
 * defined in ngtcp2_crypto_openssl.h.
 */
NGTCP2_EXTERN int
ngtcp2_crypto_read_write_crypto_data(ngtcp2_conn *conn, void *tls,
                                     ngtcp2_crypto_level crypto_level,
                                     const uint8_t *data, size_t datalen);

/**
 * @function
 *
 * `ngtcp2_crypto_set_remote_transport_params` retrieves a remote QUIC
 * transport parameters from |tls| and sets it to |conn| using
 * `ngtcp2_conn_set_remote_transport_params`.
 *
 * |tls| points to a implementation dependent TLS session object.  If
 * libngtcp2_crypto_openssl is linked, |tls| must be a pointer to SSL
 * object.
 *
 * This function returns 0 if it succeeds, or -1.
 */
NGTCP2_EXTERN int
ngtcp2_crypto_set_remote_transport_params(ngtcp2_conn *conn, void *tls,
                                          ngtcp2_crypto_side side);

#ifdef __cplusplus
}
#endif

#endif /* NGTCP2_CRYPTO_H */
