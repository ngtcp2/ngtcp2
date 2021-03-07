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
#include <fstream>
#include <array>

#include <ngtcp2/ngtcp2_crypto.h>

#include <gnutls/crypto.h>

#include "template.h"

// Based on https://github.com/ueno/ngtcp2-gnutls-examples

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

  if (gnutls_hash_fast(GNUTLS_DIG_SHA256, rand.data(), rand.size(),
                       md.data()) != 0) {
    return -1;
  }

  std::copy_n(std::begin(md), secretlen, secret);
  return 0;
}

std::optional<std::string> read_token(const std::string_view &filename) {
  auto f = std::ifstream(filename.data());
  if (!f) {
    std::cerr << "Could not read token file " << filename << std::endl;
    return {};
  }

  auto pos = f.tellg();
  std::vector<char> content(pos);
  f.seekg(0, std::ios::beg);
  f.read(content.data(), pos);

  gnutls_datum_t s;
  s.data = reinterpret_cast<unsigned char *>(content.data());
  s.size = content.size();

  gnutls_datum_t d;
  if (auto rv = gnutls_pem_base64_decode2("QUIC TOKEN", &s, &d); rv < 0) {
    std::cerr << "Could not read token in " << filename << std::endl;
    return {};
  }

  auto res = std::string{d.data, d.data + d.size};

  gnutls_free(d.data);

  return res;
}

int write_token(const std::string_view &filename, const uint8_t *token,
                size_t tokenlen) {
  auto f = std::ofstream(filename.data());
  if (!f) {
    std::cerr << "Could not write token in " << filename << std::endl;
    return -1;
  }

  gnutls_datum_t s;
  s.data = const_cast<uint8_t *>(token);
  s.size = tokenlen;

  gnutls_datum_t d;
  if (auto rv = gnutls_pem_base64_encode2("QUIC TOKEN", &s, &d); rv < 0) {
    std::cerr << "Could not encode token in " << filename << std::endl;
    return -1;
  }

  f.write(reinterpret_cast<const char *>(d.data), d.size);
  gnutls_free(d.data);

  return 0;
}

ngtcp2_crypto_aead crypto_aead_aes_128_gcm() {
  ngtcp2_crypto_aead aead;
  ngtcp2_crypto_aead_init(&aead,
                          reinterpret_cast<void *>(GNUTLS_CIPHER_AES_128_GCM));
  return aead;
}

ngtcp2_crypto_md crypto_md_sha256() {
  ngtcp2_crypto_md md;
  ngtcp2_crypto_md_init(&md, reinterpret_cast<void *>(GNUTLS_DIG_SHA256));
  return md;
}

const char *crypto_default_ciphers() {
  return "NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:"
         "+CHACHA20-POLY1305:+AES-128-CCM";
}

const char *crypto_default_groups() {
  return "-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519:+GROUP-SECP384R1:"
         "+GROUP-SECP521R1";
}

} // namespace util

} // namespace ngtcp2
