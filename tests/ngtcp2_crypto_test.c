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

void test_ngtcp2_crypto_km_secret_zeroed(void) {
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_crypto_km *ckm;
  uint8_t secret[32];
  uint8_t iv[12];
  uint8_t zero[32];
  uint8_t *secret_base;
  int rv;

  memset(secret, 0xAB, sizeof(secret));
  memset(iv, 0xCD, sizeof(iv));
  memset(zero, 0, sizeof(zero));

  rv = ngtcp2_crypto_km_new(&ckm, secret, sizeof(secret), NULL, iv,
                             sizeof(iv), mem);

  assert_int(0, ==, rv);
  assert_memory_equal(sizeof(secret), ckm->secret.base, secret);

  /* Save the pointer to the secret data region before freeing.
     After ngtcp2_crypto_km_del, the secret region should be zeroed. */
  secret_base = ckm->secret.base;

  ngtcp2_crypto_km_del(ckm, mem);

  /* Verify that the secret was zeroed before freeing.  Note: This
     accesses freed memory which is technically undefined behavior, but
     in practice the allocator does not immediately overwrite freed
     memory in test environments, so this check is a reasonable
     heuristic. */
  assert_memory_equal(sizeof(secret), secret_base, zero);
}
