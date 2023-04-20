/*
 * ngtcp2
 *
 * Copyright (c) 2022 ngtcp2 contributors
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
#include "ngtcp2_pmtud_test.h"

#include <stdio.h>

#include <CUnit/CUnit.h>

#include "ngtcp2_pmtud.h"
#include "ngtcp2_test_helper.h"

void test_ngtcp2_pmtud_probe(void) {
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_pmtud *pmtud;
  int rv;

  /* Send probe and get success */
  rv = ngtcp2_pmtud_new(&pmtud, NGTCP2_MAX_UDP_PAYLOAD_SIZE, 1452, 0, mem);

  CU_ASSERT(0 == rv);
  CU_ASSERT(0 == pmtud->mtu_idx);
  CU_ASSERT(!ngtcp2_pmtud_finished(pmtud));
  CU_ASSERT(ngtcp2_pmtud_require_probe(pmtud));
  CU_ASSERT(1454 - 48 == ngtcp2_pmtud_probelen(pmtud));

  ngtcp2_pmtud_probe_sent(pmtud, 2, 0);

  CU_ASSERT(1 == pmtud->num_pkts_sent);
  CU_ASSERT(2 == pmtud->expiry);
  CU_ASSERT(!ngtcp2_pmtud_require_probe(pmtud));

  ngtcp2_pmtud_handle_expiry(pmtud, 1);

  CU_ASSERT(!ngtcp2_pmtud_require_probe(pmtud));

  ngtcp2_pmtud_handle_expiry(pmtud, 2);

  CU_ASSERT(ngtcp2_pmtud_require_probe(pmtud));

  ngtcp2_pmtud_probe_sent(pmtud, 2, 2);

  CU_ASSERT(2 == pmtud->num_pkts_sent);
  CU_ASSERT(4 == pmtud->expiry);
  CU_ASSERT(!ngtcp2_pmtud_require_probe(pmtud));

  ngtcp2_pmtud_handle_expiry(pmtud, 4);

  CU_ASSERT(ngtcp2_pmtud_require_probe(pmtud));

  ngtcp2_pmtud_probe_sent(pmtud, 2, 4);

  CU_ASSERT(3 == pmtud->num_pkts_sent);
  CU_ASSERT(10 == pmtud->expiry);
  CU_ASSERT(!ngtcp2_pmtud_require_probe(pmtud));

  ngtcp2_pmtud_probe_success(pmtud, ngtcp2_pmtud_probelen(pmtud));

  CU_ASSERT(3 == pmtud->mtu_idx);
  CU_ASSERT(UINT64_MAX == pmtud->expiry);
  CU_ASSERT(0 == pmtud->num_pkts_sent);
  CU_ASSERT(ngtcp2_pmtud_require_probe(pmtud));
  CU_ASSERT(1492 - 48 == ngtcp2_pmtud_probelen(pmtud));

  ngtcp2_pmtud_probe_sent(pmtud, 2, 10);
  ngtcp2_pmtud_handle_expiry(pmtud, 12);
  ngtcp2_pmtud_probe_sent(pmtud, 2, 12);
  ngtcp2_pmtud_handle_expiry(pmtud, 14);
  ngtcp2_pmtud_probe_sent(pmtud, 2, 14);
  ngtcp2_pmtud_handle_expiry(pmtud, 20);

  CU_ASSERT(1492 - 48 == pmtud->min_fail_udp_payload_size);
  CU_ASSERT(ngtcp2_pmtud_finished(pmtud));

  ngtcp2_pmtud_del(pmtud);

  /* Failing 2nd probe should skip the third probe */
  rv = ngtcp2_pmtud_new(&pmtud, NGTCP2_MAX_UDP_PAYLOAD_SIZE, 1452, 0, mem);

  ngtcp2_pmtud_probe_sent(pmtud, 2, 0);
  ngtcp2_pmtud_handle_expiry(pmtud, 2);
  ngtcp2_pmtud_probe_sent(pmtud, 2, 2);
  ngtcp2_pmtud_handle_expiry(pmtud, 4);
  ngtcp2_pmtud_probe_sent(pmtud, 2, 4);
  ngtcp2_pmtud_handle_expiry(pmtud, 10);

  CU_ASSERT(1454 - 48 == pmtud->min_fail_udp_payload_size);
  CU_ASSERT(1 == pmtud->mtu_idx);

  ngtcp2_pmtud_probe_sent(pmtud, 2, 10);
  ngtcp2_pmtud_handle_expiry(pmtud, 12);
  ngtcp2_pmtud_probe_sent(pmtud, 2, 12);
  ngtcp2_pmtud_handle_expiry(pmtud, 14);
  ngtcp2_pmtud_probe_sent(pmtud, 2, 14);
  ngtcp2_pmtud_handle_expiry(pmtud, 20);

  CU_ASSERT(1390 - 48 == pmtud->min_fail_udp_payload_size);
  CU_ASSERT(2 == pmtud->mtu_idx);

  ngtcp2_pmtud_probe_sent(pmtud, 2, 10);
  ngtcp2_pmtud_probe_success(pmtud, 1280 - 48);

  CU_ASSERT(ngtcp2_pmtud_finished(pmtud));

  ngtcp2_pmtud_del(pmtud);

  /* Skip 1st probe because it is larger than hard max. */
  rv = ngtcp2_pmtud_new(&pmtud, NGTCP2_MAX_UDP_PAYLOAD_SIZE, 1454 - 48 - 1, 0,
                        mem);

  CU_ASSERT(0 == rv);
  CU_ASSERT(1 == pmtud->mtu_idx);

  ngtcp2_pmtud_del(pmtud);

  /* PMTUD finishes immediately because we know that all candidates
     are lower than the current maximum. */
  rv = ngtcp2_pmtud_new(&pmtud, 1492 - 48, 1452, 0, mem);

  CU_ASSERT(0 == rv);
  CU_ASSERT(ngtcp2_pmtud_finished(pmtud));

  ngtcp2_pmtud_del(pmtud);

  /* PMTUD finishes immediately because the hard maximum size is lower
     than the candidates. */
  rv = ngtcp2_pmtud_new(&pmtud, NGTCP2_MAX_UDP_PAYLOAD_SIZE,
                        NGTCP2_MAX_UDP_PAYLOAD_SIZE, 0, mem);

  CU_ASSERT(0 == rv);
  CU_ASSERT(ngtcp2_pmtud_finished(pmtud));

  ngtcp2_pmtud_del(pmtud);
}
