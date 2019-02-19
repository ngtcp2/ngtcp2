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
#ifndef CRYPTO_H
#define CRYPTO_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif // HAVE_CONFIG_H

#include <array>

#include <ngtcp2/ngtcp2.h>

#include <openssl/ssl.h>

namespace ngtcp2 {

namespace crypto {

struct Context {
#if defined(OPENSSL_IS_BORINGSSL)
  const EVP_AEAD *aead;
#else  // !OPENSSL_IS_BORINGSSL
  const EVP_CIPHER *aead;
#endif // !OPENSSL_IS_BORINGSSL
  const EVP_CIPHER *hp;
  const EVP_MD *prf;
  std::array<uint8_t, 64> tx_secret, rx_secret;
  size_t secretlen;
};

// negotiated_prf stores the negotiated PRF by TLS into |ctx|.  This
// function returns 0 if it succeeds, or -1.
int negotiated_prf(Context &ctx, SSL *ssl);

// negotiated_aead stores the negotiated AEAD by TLS into |ctx|.  This
// function returns 0 if it succeeds, or -1.
int negotiated_aead(Context &ctx, SSL *ssl);

// derive_initial_secret derives initial_secret.  |secret| is
// connection ID generated randomly by client.
int derive_initial_secret(uint8_t *dest, size_t destlen,
                          const ngtcp2_cid *secret, const uint8_t *salt,
                          size_t saltlen);

// derive_client_initial_secret derives client_initial_secret.
int derive_client_initial_secret(uint8_t *dest, size_t destlen,
                                 const uint8_t *secret, size_t secretlen);

// derive_server_initial_secret derives server_initial_secret.
int derive_server_initial_secret(uint8_t *dest, size_t destlen,
                                 const uint8_t *secret, size_t secretlen);

// update_traffic_secret stores new secret into |dest| of length
// |destlen| using the current secret |secret| of length |secretlen|.
// |destlen| must be at least |secretlen| bytes long.  This function
// returns the length of secret if it succeeds, or -1.
ssize_t update_traffic_secret(uint8_t *dest, size_t destlen,
                              const uint8_t *secret, size_t secretlen,
                              const Context &ctx);

// derive_packet_protection_key derives and stores the packet
// protection key in the buffer pointed by |dest| of length |destlen|,
// and the key size is returned.  This function returns the key length
// if it succeeds, or -1.
ssize_t derive_packet_protection_key(uint8_t *dest, size_t destlen,
                                     const uint8_t *secret, size_t secretlen,
                                     const Context &ctx);

// derive_packet_protection_iv derives and stores the packet
// protection IV in the buffer pointed by |dest| of length |destlen|.
// This function returns the length of IV if it succeeds, or -1.
ssize_t derive_packet_protection_iv(uint8_t *dest, size_t destlen,
                                    const uint8_t *secret, size_t secretlen,
                                    const Context &ctx);

// derive_header_protection_key derives and stores the header
// protection key in the buffer pointed by |dest| of length |destlen|,
// and the key size is returned.  This function returns the key length
// if it succeeds, or -1.
ssize_t derive_header_protection_key(uint8_t *dest, size_t destlen,
                                     const uint8_t *secret, size_t secretlen,
                                     const Context &ctx);

// encrypt encrypts |plaintext| of length |plaintextlen| and writes
// the encrypted data in the buffer pointed by |dest| of length
// |destlen|.  This function can encrypt data in-place.  In other
// words, |dest| == |plaintext| is allowed.  This function returns the
// number of bytes written if it succeeds, or -1.
ssize_t encrypt(uint8_t *dest, size_t destlen, const uint8_t *plaintext,
                size_t plaintextlen, const Context &ctx, const uint8_t *key,
                size_t keylen, const uint8_t *nonce, size_t noncelen,
                const uint8_t *ad, size_t adlen);

// decrypt decrypts |ciphertext| of length |ciphertextlen| and writes
// the decrypted data in the buffer pointed by |dest| of length
// |destlen|.  This function can decrypt data in-place.  In other
// words, |dest| == |ciphertext| is allowed.  This function returns
// the number of bytes written if it succeeds, or -1.
ssize_t decrypt(uint8_t *dest, size_t destlen, const uint8_t *ciphertext,
                size_t ciphertextlen, const Context &ctx, const uint8_t *key,
                size_t keylen, const uint8_t *nonce, size_t noncelen,
                const uint8_t *ad, size_t adlen);

// aead_max_overhead returns the maximum overhead of ctx.aead.
size_t aead_max_overhead(const Context &ctx);

// aead_key_length returns the key size of ctx.aead.
size_t aead_key_length(const Context &ctx);

// aead_nonce_length returns the nonce size of ctx.aead.
size_t aead_nonce_length(const Context &ctx);

// hp_mask writes mask into the buffer pointed by |dest| of length
// |destlen|.  This function returns the number of bytes written if it
// succeeds, or -1.
ssize_t hp_mask(uint8_t *dest, size_t destlen, const Context &ctx,
                const uint8_t *key, size_t keylen, const uint8_t *sample,
                size_t samplelen);

// hkdf_expand_label implements HKDF-Expand-Label function defined in
// https://tools.ietf.org/html/rfc8446#section-7.1.  It uses 0 length
// context.  This function returns 0 if it succeeds, or -1.
int hkdf_expand_label(uint8_t *dest, size_t destlen, const uint8_t *secret,
                      size_t secretlen, const uint8_t *label, size_t labellen,
                      const Context &ctx);

// hkdf_expand perhorms HKDF-Expand.  It returns 0 if it succeeds, or
// -1.
int hkdf_expand(uint8_t *dest, size_t destlen, const uint8_t *secret,
                size_t secretlen, const uint8_t *label, size_t labellen,
                const Context &ctx);

// hkdf_extract performs HKDF-Extract.  This function returns 0 if it
// succeeds, or -1.
int hkdf_extract(uint8_t *dest, size_t destlen, const uint8_t *secret,
                 size_t secretlen, const uint8_t *salt, size_t saltlen,
                 const Context &ctx);

// prf_sha256 sets sha256 to ctx.prf.
void prf_sha256(Context &ctx);

// aead_aes_128_gcm sets AEAD_AES_128_GCM to ctx.aead.
void aead_aes_128_gcm(Context &ctx);

// message_digest computes message digest over |data| of length |len|
// using a hash function |meth|.  The result is stored to the buffer
// pointed by |res| which must have enough capacity to store the
// result.  This function returns 0 if it succeeds, or -1.
int message_digest(uint8_t *res, const EVP_MD *meth, const uint8_t *data,
                   size_t len);

} // namespace crypto

} // namespace ngtcp2

#if defined(OPENSSL_IS_BORINGSSL)
inline void *BIO_get_data(BIO *bio) { return bio->ptr; }
inline void BIO_set_data(BIO *bio, void *ptr) { bio->ptr = ptr; }
inline void BIO_set_init(BIO *bio, int init) { bio->init = init; }

inline BIO_METHOD *BIO_meth_new(int type, const char *name) {
  return new BIO_METHOD{type, name};
}
inline int BIO_meth_set_write(BIO_METHOD *meth,
                              int (*write)(BIO *, const char *, int)) {
  meth->bwrite = write;
  return 1;
}
inline int BIO_meth_set_read(BIO_METHOD *meth,
                             int (*read)(BIO *, char *, int)) {
  meth->bread = read;
  return 1;
}
inline int BIO_meth_set_puts(BIO_METHOD *meth,
                             int (*puts)(BIO *, const char *)) {
  meth->bputs = puts;
  return 1;
}
inline int BIO_meth_set_gets(BIO_METHOD *meth,
                             int (*gets)(BIO *, char *, int)) {
  meth->bgets = gets;
  return 1;
}
inline int BIO_meth_set_ctrl(BIO_METHOD *meth,
                             long (*ctrl)(BIO *, int, long, void *)) {
  meth->ctrl = ctrl;
  return 1;
}
inline int BIO_meth_set_create(BIO_METHOD *meth, int (*create)(BIO *)) {
  meth->create = create;
  return 1;
}
inline int BIO_meth_set_destroy(BIO_METHOD *meth, int (*destroy)(BIO *)) {
  meth->destroy = destroy;
  return 1;
}
#endif // defined(OPENSSL_IS_BORINGSSL)

#endif // CRYPTO_H
