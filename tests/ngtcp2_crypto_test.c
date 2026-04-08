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
#include "ngtcp2_crypto_test.h"

#include <stdlib.h>
#include <string.h>

#include "ngtcp2_crypto.h"
#include "ngtcp2_mem.h"
#include "ngtcp2_test_helper.h"

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_crypto_km_secret_zeroed),
  munit_test_end(),
};

const MunitSuite crypto_suite = {
  .prefix = "/crypto",
  .tests = tests,
};

static void *nofree_malloc(size_t size, void *user_data) {
  (void)user_data;
  return malloc(size);
}

static void nofree_free(void *ptr, void *user_data) {
  (void)ptr;
  (void)user_data;
}

static void *nofree_calloc(size_t nmemb, size_t size, void *user_data) {
  (void)user_data;
  return calloc(nmemb, size);
}

static void *nofree_realloc(void *ptr, size_t size, void *user_data) {
  (void)user_data;
  return realloc(ptr, size);
}

void test_ngtcp2_crypto_km_secret_zeroed(void) {
  ngtcp2_mem nofree_mem = {
    .user_data = NULL,
    .malloc = nofree_malloc,
    .free = nofree_free,
    .calloc = nofree_calloc,
    .realloc = nofree_realloc,
  };
  ngtcp2_crypto_km *ckm;
  uint8_t secret[32];
  uint8_t iv[12];
  uint8_t zero_secret[32];
  uint8_t zero_iv[12];
  uint8_t *secret_base;
  uint8_t *iv_base;
  int rv;

  memset(secret, 0xAB, sizeof(secret));
  memset(iv, 0xCD, sizeof(iv));
  memset(zero_secret, 0, sizeof(zero_secret));
  memset(zero_iv, 0, sizeof(zero_iv));

  rv = ngtcp2_crypto_km_new(&ckm, secret, sizeof(secret), NULL, iv,
                             sizeof(iv), &nofree_mem);

  assert_int(0, ==, rv);
  assert_memory_equal(sizeof(secret), ckm->secret.base, secret);
  assert_memory_equal(sizeof(iv), ckm->iv.base, iv);

  secret_base = ckm->secret.base;
  iv_base = ckm->iv.base;

  ngtcp2_crypto_km_del(ckm, &nofree_mem);

  /* The nofree allocator does not actually free memory, so we can
     safely inspect the buffer contents after ngtcp2_crypto_km_del. */
  assert_memory_equal(sizeof(secret), secret_base, zero_secret);
  assert_memory_equal(sizeof(iv), iv_base, zero_iv);

  /* Now actually free the allocation. */
  free(ckm);
}
