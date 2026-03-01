/*
 * ngtcp2
 *
 * Copyright (c) 2026 ngtcp2 contributors
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
#include "ngtcp2_cid_test.h"

#include <stdio.h>

#include "ngtcp2_cid.h"
#include "ngtcp2_test_helper.h"

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_scid_copy),
  munit_void_test(test_ngtcp2_dcid_copy_cid_token),
  munit_test_end(),
};

const MunitSuite cid_suite = {
  .prefix = "/cid",
  .tests = tests,
};

void test_ngtcp2_scid_copy(void) {
  ngtcp2_cid cid = {
    .datalen = 8,
    .data = {0xFF},
  };
  ngtcp2_scid src, dest;

  ngtcp2_scid_init(&src, 981, &cid);
  src.retired_ts = 100 * NGTCP2_MILLISECONDS;
  src.flags = NGTCP2_SCID_FLAG_USED;

  ngtcp2_scid_copy(&dest, &src);

  assert_size(src.pe.index, ==, dest.pe.index);
  assert_uint64(src.seq, ==, dest.seq);
  assert_true(ngtcp2_cid_eq(&src.cid, &dest.cid));
  assert_uint64(src.retired_ts, ==, dest.retired_ts);
  assert_uint64(src.flags, ==, dest.flags);
}

void test_ngtcp2_dcid_copy_cid_token(void) {
  ngtcp2_cid cid = {
    .datalen = 8,
    .data = {0xE1},
  };
  static const ngtcp2_stateless_reset_token token = {
    .data = {0xDD},
  };
  ngtcp2_dcid src, dest = {0};

  /* With token */
  ngtcp2_dcid_init(&src, 776, &cid, &token);

  ngtcp2_dcid_copy_cid_token(&dest, &src);

  assert_uint64(src.seq, ==, dest.seq);
  assert_true(ngtcp2_cid_eq(&src.cid, &dest.cid));
  assert_true(dest.flags & NGTCP2_DCID_FLAG_TOKEN_PRESENT);
  assert_true(ngtcp2_stateless_reset_token_eq(&src.token, &dest.token));

  /* Without token */
  ngtcp2_dcid_init(&src, 776, &cid, NULL);
  dest = (ngtcp2_dcid){
    .flags = NGTCP2_DCID_FLAG_TOKEN_PRESENT,
  };

  ngtcp2_dcid_copy_cid_token(&dest, &src);

  assert_uint64(src.seq, ==, dest.seq);
  assert_true(ngtcp2_cid_eq(&src.cid, &dest.cid));
  assert_false(dest.flags & NGTCP2_DCID_FLAG_TOKEN_PRESENT);
}
