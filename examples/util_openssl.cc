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
#include "util.h"

#include <cassert>
#include <iostream>
#include <array>

#include <ngtcp2/ngtcp2_crypto.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>

#include "template.h"

namespace ngtcp2 {

namespace util {

namespace {
auto randgen = make_mt19937();
} // namespace

int generate_secret(uint8_t *secret, size_t secretlen) {
  std::array<uint8_t, 16> rand;
  std::array<uint8_t, 32> md;

  assert(md.size() == secretlen);

  auto dis = std::uniform_int_distribution<uint8_t>(0, 255);
  std::generate_n(rand.data(), rand.size(), [&dis]() { return dis(randgen); });

  auto ctx = EVP_MD_CTX_new();
  if (ctx == nullptr) {
    return -1;
  }

  auto ctx_deleter = defer(EVP_MD_CTX_free, ctx);

  unsigned int mdlen = md.size();
  if (!EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) ||
      !EVP_DigestUpdate(ctx, rand.data(), rand.size()) ||
      !EVP_DigestFinal_ex(ctx, md.data(), &mdlen)) {
    return -1;
  }

  std::copy_n(std::begin(md), secretlen, secret);
  return 0;
}

std::optional<std::string> read_token(const std::string_view &filename) {
  auto f = BIO_new_file(filename.data(), "r");
  if (f == nullptr) {
    std::cerr << "Could not open token file " << filename << std::endl;
    return {};
  }

  auto f_d = defer(BIO_free, f);

  char *name, *header;
  unsigned char *data;
  long datalen;
  std::string token;
  if (PEM_read_bio(f, &name, &header, &data, &datalen) != 1) {
    std::cerr << "Could not read token file " << filename << std::endl;
    return {};
  }

  OPENSSL_free(name);
  OPENSSL_free(header);

  auto res = std::string{data, data + datalen};

  OPENSSL_free(data);

  return res;
}

int write_token(const std::string_view &filename, const uint8_t *token,
                size_t tokenlen) {
  auto f = BIO_new_file(filename.data(), "w");
  if (f == nullptr) {
    std::cerr << "Could not write token in " << filename << std::endl;
    return -1;
  }

  PEM_write_bio(f, "QUIC TOKEN", "", token, tokenlen);
  BIO_free(f);

  return 0;
}

ngtcp2_crypto_md crypto_md_sha256() {
  ngtcp2_crypto_md md;
  ngtcp2_crypto_md_init(&md, const_cast<EVP_MD *>(EVP_sha256()));
  return md;
}

const char *crypto_default_ciphers() {
  return "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_"
         "SHA256:TLS_AES_128_CCM_SHA256";
}

const char *crypto_default_groups() { return "X25519:P-256:P-384:P-521"; }

} // namespace util

} // namespace ngtcp2
