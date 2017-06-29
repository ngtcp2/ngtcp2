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
#include <config.h>
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

// export_secret exports secret with given label.  It returns 0 if it
// succeeds, or -1.
int export_secret(uint8_t *dest, size_t destlen, SSL *ssl, const uint8_t *label,
                  size_t labellen);

// export_client_secret exports secret, client_pp_secret_0, from |ssl|
// for client.  It returns 0 if it succeeds, or -1.
int export_client_secret(uint8_t *dest, size_t destlen, SSL *ssl);

// export_server_secret exports secret, server_pp_secret_0, from |ssl|
// for server.  It returns 0 if it succeeds, or -1.
int export_server_secret(uint8_t *dest, size_t destlen, SSL *ssl);

// hkdf_expand_label derives secret using HDKF-Expand-Label.  It
// returns 0 if it succeeds, or -1.
int hkdf_expand_label(uint8_t *dest, size_t destlen, const uint8_t *secret,
                      size_t secretlen, const uint8_t *qlabel, size_t qlabellen,
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

} // namespace crypto

} // namespace ngtcp2

#endif // CRYPTO_H
