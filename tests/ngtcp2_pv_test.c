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

#include <CUnit/CUnit.h>

#include "ngtcp2_pv.h"
#include "ngtcp2_test_helper.h"

void test_ngtcp2_pv_add_entry(void) {
  ngtcp2_pv *pv;
  int rv;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_cid cid;
  const uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN] = {0xff};
  ngtcp2_dcid dcid;
  ngtcp2_log log;
  uint8_t data[8];
  size_t i;
  ngtcp2_duration timeout = 100ULL * NGTCP2_SECONDS;

  dcid_init(&cid);
  ngtcp2_dcid_init(&dcid, 1000000007, &cid, token);
  ngtcp2_log_init(&log, NULL, NULL, 0, NULL);

  rv = ngtcp2_pv_new(&pv, &dcid, timeout, NGTCP2_PV_FLAG_NONE, &log, mem);

  CU_ASSERT(0 == rv);
  CU_ASSERT(0 == ngtcp2_pv_validation_timed_out(pv, 0));

  ngtcp2_pv_handle_entry_expiry(pv, 0);

  CU_ASSERT(NGTCP2_PV_NUM_PROBE_PKT == pv->probe_pkt_left);
  CU_ASSERT(ngtcp2_pv_should_send_probe(pv));

  for (i = 0; i < NGTCP2_PV_NUM_PROBE_PKT; ++i) {
    ngtcp2_pv_add_entry(pv, data, 100, NGTCP2_PV_ENTRY_FLAG_NONE, 0);

    CU_ASSERT(i + 1 == ngtcp2_ringbuf_len(&pv->ents.rb));
  }

  CU_ASSERT(0 == pv->probe_pkt_left);
  CU_ASSERT(!ngtcp2_pv_should_send_probe(pv));
  CU_ASSERT(NGTCP2_PV_NUM_PROBE_PKT == ngtcp2_ringbuf_len(&pv->ents.rb));
  CU_ASSERT(100 == ngtcp2_pv_next_expiry(pv));

  ngtcp2_pv_handle_entry_expiry(pv, 99);

  CU_ASSERT(0 == pv->probe_pkt_left);
  CU_ASSERT(!ngtcp2_pv_should_send_probe(pv));

  ngtcp2_pv_handle_entry_expiry(pv, 100);

  CU_ASSERT(2 == pv->probe_pkt_left);
  CU_ASSERT(ngtcp2_pv_should_send_probe(pv));
  CU_ASSERT(100 == ngtcp2_pv_next_expiry(pv));

  ngtcp2_pv_add_entry(pv, data, 111, NGTCP2_PV_ENTRY_FLAG_NONE, 100);

  CU_ASSERT(1 == pv->probe_pkt_left);
  CU_ASSERT(ngtcp2_pv_should_send_probe(pv));
  CU_ASSERT(111 == ngtcp2_pv_next_expiry(pv));

  ngtcp2_pv_del(pv);
}

void test_ngtcp2_pv_validate(void) {
  ngtcp2_pv *pv;
  int rv;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_cid cid;
  const uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN] = {0xff};
  ngtcp2_dcid dcid;
  ngtcp2_log log;
  uint8_t data[8];
  ngtcp2_duration timeout = 100ULL * NGTCP2_SECONDS;
  ngtcp2_path_storage path;
  uint8_t flags;

  path_init(&path, 1, 0, 2, 0);
  dcid_init(&cid);
  ngtcp2_dcid_init(&dcid, 1000000007, &cid, token);
  ngtcp2_path_copy(&dcid.ps.path, &path.path);
  ngtcp2_log_init(&log, NULL, NULL, 0, NULL);

  rv = ngtcp2_pv_new(&pv, &dcid, timeout, NGTCP2_PV_FLAG_NONE, &log, mem);

  CU_ASSERT(0 == rv);

  memset(data, 0, sizeof(data));
  ngtcp2_pv_add_entry(pv, data, 100, NGTCP2_PV_ENTRY_FLAG_NONE, 1);

  memset(data, 1, sizeof(data));
  ngtcp2_pv_add_entry(pv, data, 100, NGTCP2_PV_ENTRY_FLAG_NONE, 1);

  memset(data, 1, sizeof(data));
  rv = ngtcp2_pv_validate(pv, &flags, data);

  CU_ASSERT(0 == rv);

  memset(data, 3, sizeof(data));
  rv = ngtcp2_pv_validate(pv, &flags, data);

  CU_ASSERT(NGTCP2_ERR_INVALID_ARGUMENT == rv);

  ngtcp2_pv_del(pv);
}
