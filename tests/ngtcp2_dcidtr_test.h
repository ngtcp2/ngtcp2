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
#ifndef NGTCP2_DCIDTR_TEST_H
#define NGTCP2_DCIDTR_TEST_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#define MUNIT_ENABLE_ASSERT_ALIASES

#include "munit.h"

extern const MunitSuite dcidtr_suite;

munit_void_test_decl(test_ngtcp2_dcidtr_track_retired_seq)
munit_void_test_decl(test_ngtcp2_dcidtr_bind_dcid)
munit_void_test_decl(test_ngtcp2_dcidtr_find_bound_dcid)
munit_void_test_decl(test_ngtcp2_dcidtr_bind_zerolen_dcid)
munit_void_test_decl(test_ngtcp2_dcidtr_verify_stateless_reset)
munit_void_test_decl(test_ngtcp2_dcidtr_verify_token_uniqueness)
munit_void_test_decl(test_ngtcp2_dcidtr_retire_inactive_dcid_prior_to)
munit_void_test_decl(test_ngtcp2_dcidtr_retire_active_dcid)
munit_void_test_decl(test_ngtcp2_dcidtr_retire_stale_bound_dcid)
munit_void_test_decl(test_ngtcp2_dcidtr_remove_stale_retired_dcid)
munit_void_test_decl(test_ngtcp2_dcidtr_pop_bound_dcid)
munit_void_test_decl(test_ngtcp2_dcidtr_earliest_bound_ts)
munit_void_test_decl(test_ngtcp2_dcidtr_earliest_retired_ts)
munit_void_test_decl(test_ngtcp2_dcidtr_pop_unused)
munit_void_test_decl(test_ngtcp2_dcidtr_check_path_retired)
munit_void_test_decl(test_ngtcp2_dcidtr_len)

#endif /* !defined(NGTCP2_DCIDTR_TEST_H) */
