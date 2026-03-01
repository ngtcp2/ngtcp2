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
#include "ngtcp2_pv_test.h"

#include <stdio.h>

#include "ngtcp2_pv.h"
#include "ngtcp2_test_helper.h"

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_pv_add_entry),
  munit_void_test(test_ngtcp2_pv_validate),
  munit_void_test(test_ngtcp2_pv_cancel_expired_timer),
  munit_test_end(),
};

const MunitSuite pv_suite = {
  .prefix = "/pv",
  .tests = tests,
};

void test_ngtcp2_pv_add_entry(void) {
  ngtcp2_pv *pv;
  int rv;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  static const ngtcp2_cid cid = make_dcid();
  static const ngtcp2_stateless_reset_token token = {
    .data = {0xFF},
  };
  ngtcp2_dcid dcid;
  ngtcp2_log log;
  static const ngtcp2_path_challenge_data data = {0};
  size_t i;
  ngtcp2_duration timeout = 100ULL * NGTCP2_SECONDS;

  ngtcp2_dcid_init(&dcid, 1000000007, &cid, &token);
  ngtcp2_log_init(&log, NULL, NULL, 0, NULL);

  rv = ngtcp2_pv_new(&pv, &dcid, timeout, NGTCP2_PV_FLAG_NONE, &log, mem);

  assert_int(0, ==, rv);
  assert_false(ngtcp2_pv_validation_timed_out(pv, 0));

  ngtcp2_pv_handle_entry_expiry(pv, 0);

  assert_size(NGTCP2_PV_NUM_PROBE_PKT, ==, pv->probe_pkt_left);
  assert_true(ngtcp2_pv_should_send_probe(pv));

  for (i = 0; i < NGTCP2_PV_NUM_PROBE_PKT; ++i) {
    ngtcp2_pv_add_entry(pv, &data, 100, NGTCP2_PV_ENTRY_FLAG_NONE, 0);

    assert_size(i + 1, ==, ngtcp2_ringbuf_len(&pv->ents.rb));
  }

  assert_size(0, ==, pv->probe_pkt_left);
  assert_false(ngtcp2_pv_should_send_probe(pv));
  assert_size(NGTCP2_PV_NUM_PROBE_PKT, ==, ngtcp2_ringbuf_len(&pv->ents.rb));
  assert_uint64(100, ==, ngtcp2_pv_next_expiry(pv));

  ngtcp2_pv_handle_entry_expiry(pv, 99);

  assert_size(0, ==, pv->probe_pkt_left);
  assert_false(ngtcp2_pv_should_send_probe(pv));

  ngtcp2_pv_handle_entry_expiry(pv, 100);

  assert_size(2, ==, pv->probe_pkt_left);
  assert_true(ngtcp2_pv_should_send_probe(pv));
  assert_uint64(100, ==, ngtcp2_pv_next_expiry(pv));

  ngtcp2_pv_add_entry(pv, &data, 111, NGTCP2_PV_ENTRY_FLAG_NONE, 100);

  assert_size(1, ==, pv->probe_pkt_left);
  assert_true(ngtcp2_pv_should_send_probe(pv));
  assert_uint64(111, ==, ngtcp2_pv_next_expiry(pv));

  ngtcp2_pv_del(pv);
}

void test_ngtcp2_pv_validate(void) {
  ngtcp2_pv *pv;
  int rv;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  static const ngtcp2_cid cid = make_dcid();
  static const ngtcp2_stateless_reset_token token = {
    .data = {0xFF},
  };
  ngtcp2_dcid dcid;
  ngtcp2_log log;
  ngtcp2_path_challenge_data data = {0};
  ngtcp2_duration timeout = 100ULL * NGTCP2_SECONDS;
  ngtcp2_path_storage path;
  uint8_t flags;

  path_init(&path, 1, 0, 2, 0);
  ngtcp2_dcid_init(&dcid, 1000000007, &cid, &token);
  ngtcp2_path_copy(&dcid.ps.path, &path.path);
  ngtcp2_log_init(&log, NULL, NULL, 0, NULL);

  rv = ngtcp2_pv_new(&pv, &dcid, timeout, NGTCP2_PV_FLAG_NONE, &log, mem);

  assert_int(0, ==, rv);

  /* Validation fails if there is no outstanding entry. */
  rv = ngtcp2_pv_validate(pv, &flags, &data);

  assert_int(NGTCP2_ERR_INVALID_STATE, ==, rv);

  ngtcp2_pv_add_entry(pv, &data, 100, NGTCP2_PV_ENTRY_FLAG_NONE, 1);

  data = (ngtcp2_path_challenge_data){
    .data = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
  };
  ngtcp2_pv_add_entry(pv, &data, 100, NGTCP2_PV_ENTRY_FLAG_NONE, 1);

  rv = ngtcp2_pv_validate(pv, &flags, &data);

  assert_int(0, ==, rv);

  data = (ngtcp2_path_challenge_data){
    .data = {0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03},
  };
  rv = ngtcp2_pv_validate(pv, &flags, &data);

  assert_int(NGTCP2_ERR_INVALID_ARGUMENT, ==, rv);

  ngtcp2_pv_del(pv);
}

void test_ngtcp2_pv_cancel_expired_timer(void) {
  ngtcp2_pv *pv;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  static const ngtcp2_cid cid = make_dcid();
  ngtcp2_dcid dcid;
  static const ngtcp2_stateless_reset_token token = {
    .data = {0xFF},
  };
  static const ngtcp2_path_challenge_data data = {
    .data = {0xEE},
  };
  ngtcp2_log log;
  int rv;

  ngtcp2_dcid_init(&dcid, 9, &cid, &token);
  ngtcp2_log_init(&log, NULL, NULL, 0, NULL);

  rv = ngtcp2_pv_new(&pv, &dcid, 3 * NGTCP2_SECONDS, NGTCP2_PV_FLAG_NONE, &log,
                     mem);

  assert_int(0, ==, rv);

  ngtcp2_pv_add_entry(pv, &data, 30 * NGTCP2_MILLISECONDS,
                      NGTCP2_PV_ENTRY_FLAG_NONE, 0);

  assert_uint64(30 * NGTCP2_MILLISECONDS, ==, ngtcp2_pv_next_expiry(pv));

  ngtcp2_pv_cancel_expired_timer(pv, 30 * NGTCP2_MILLISECONDS - 1);

  assert_false(pv->flags & NGTCP2_PV_FLAG_CANCEL_TIMER);

  ngtcp2_pv_cancel_expired_timer(pv, 30 * NGTCP2_MILLISECONDS);

  assert_true(pv->flags & NGTCP2_PV_FLAG_CANCEL_TIMER);
  assert_uint64(UINT64_MAX, ==, ngtcp2_pv_next_expiry(pv));

  ngtcp2_pv_del(pv);
}
