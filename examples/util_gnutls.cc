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
#include <algorithm>

#include <ngtcp2/ngtcp2_crypto.h>

#include <gnutls/crypto.h>

#include "template.h"

// Based on https://github.com/ueno/ngtcp2-gnutls-examples

namespace ngtcp2 {

namespace util {

int generate_secure_random(std::span<uint8_t> data) {
  if (gnutls_rnd(GNUTLS_RND_RANDOM, data.data(), data.size()) != 0) {
    return -1;
  }

  return 0;
}

int generate_secret(std::span<uint8_t> secret) {
  std::array<uint8_t, 16> rand;

  if (generate_secure_random(rand) != 0) {
    return -1;
  }

  if (gnutls_hash_fast(GNUTLS_DIG_SHA256, rand.data(), rand.size(),
                       secret.data()) != 0) {
    return -1;
  }

  return 0;
}

std::optional<std::string> read_pem(const std::string_view &filename,
                                    const std::string_view &name,
                                    const std::string_view &type) {
  auto f = std::ifstream(filename.data());
  if (!f) {
    std::cerr << "Could not read " << name << " file " << filename << std::endl;
    return {};
  }

  f.seekg(0, std::ios::end);
  auto pos = f.tellg();
  std::vector<char> content(pos);
  f.seekg(0, std::ios::beg);
  f.read(content.data(), pos);

  gnutls_datum_t s;
  s.data = reinterpret_cast<unsigned char *>(content.data());
  s.size = content.size();

  gnutls_datum_t d;
  if (auto rv = gnutls_pem_base64_decode2(type.data(), &s, &d); rv < 0) {
    std::cerr << "Could not read " << name << " file " << filename << std::endl;
    return {};
  }

  auto res = std::string{d.data, d.data + d.size};

  gnutls_free(d.data);

  return res;
}

int write_pem(const std::string_view &filename, const std::string_view &name,
              const std::string_view &type, std::span<const uint8_t> data) {
  auto f = std::ofstream(filename.data());
  if (!f) {
    std::cerr << "Could not write " << name << " in " << filename << std::endl;
    return -1;
  }

  gnutls_datum_t s;
  s.data = const_cast<uint8_t *>(data.data());
  s.size = data.size();

  gnutls_datum_t d;
  if (auto rv = gnutls_pem_base64_encode2(type.data(), &s, &d); rv < 0) {
    std::cerr << "Could not encode " << name << " in " << filename << std::endl;
    return -1;
  }

  f.write(reinterpret_cast<const char *>(d.data), d.size);
  gnutls_free(d.data);

  return 0;
}

const char *crypto_default_ciphers() {
  return "NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:"
         "+CHACHA20-POLY1305:+AES-128-CCM";
}

const char *crypto_default_groups() {
  return "-GROUP-ALL:+GROUP-X25519:+GROUP-SECP256R1:+GROUP-SECP384R1:"
         "+GROUP-SECP521R1";
}

} // namespace util

} // namespace ngtcp2
