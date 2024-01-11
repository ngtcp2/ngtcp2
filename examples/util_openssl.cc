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
#include <openssl/rand.h>

#include "template.h"
#include "debug.h"

namespace ngtcp2 {

namespace util {

int generate_secure_random(uint8_t *data, size_t datalen) {
  if (RAND_bytes(data, static_cast<int>(datalen)) != 1) {
    return -1;
  }

  return 0;
}

int generate_secret(uint8_t *secret, size_t secretlen) {
  std::array<uint8_t, 16> rand;
  std::array<uint8_t, 32> md;

  assert(md.size() == secretlen);

  if (generate_secure_random(rand.data(), rand.size()) != 0) {
    return -1;
  }

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

namespace {
void openssl_free_wrap(void *ptr) { OPENSSL_free(ptr); }
} // namespace

std::optional<std::string> read_pem(const std::string_view &filename,
                                    const std::string_view &name,
                                    const std::string_view &type) {
  auto f = BIO_new_file(filename.data(), "r");
  if (f == nullptr) {
    debug::print("Could not open {} file {}\n", name, filename);
    return {};
  }

  auto f_d = defer(BIO_free, f);

  char *pem_type, *header;
  unsigned char *data;
  long datalen;

  if (PEM_read_bio(f, &pem_type, &header, &data, &datalen) != 1) {
    debug::print("Could not read {} file {}\n", name, filename);
    return {};
  }

  auto pem_type_d = defer(openssl_free_wrap, pem_type);
  auto pem_header = defer(openssl_free_wrap, header);
  auto data_d = defer(openssl_free_wrap, data);

  if (type != pem_type) {
    debug::print("{} file {} contains unexpected type\n", name, filename);
    return {};
  }

  return std::string{data, data + datalen};
}

int write_pem(const std::string_view &filename, const std::string_view &name,
              const std::string_view &type, const uint8_t *data,
              size_t datalen) {
  auto f = BIO_new_file(filename.data(), "w");
  if (f == nullptr) {
    debug::print("Could not write {} in {}\n", name, filename);
    return -1;
  }

  PEM_write_bio(f, type.data(), "", data, datalen);
  BIO_free(f);

  return 0;
}

const char *crypto_default_ciphers() {
  return "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_"
         "SHA256:TLS_AES_128_CCM_SHA256";
}

const char *crypto_default_groups() { return "X25519:P-256:P-384:P-521"; }

} // namespace util

} // namespace ngtcp2
