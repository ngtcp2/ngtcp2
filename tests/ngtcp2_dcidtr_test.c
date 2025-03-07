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
#include "ngtcp2_dcidtr_test.h"

#include <stdio.h>

#include "ngtcp2_dcidtr.h"
#include "ngtcp2_test_helper.h"

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_dcidtr_track_retired_seq),
  munit_void_test(test_ngtcp2_dcidtr_bind_dcid),
  munit_void_test(test_ngtcp2_dcidtr_find_bound_dcid),
  munit_void_test(test_ngtcp2_dcidtr_bind_zerolen_dcid),
  munit_void_test(test_ngtcp2_dcidtr_verify_stateless_reset),
  munit_void_test(test_ngtcp2_dcidtr_verify_token_uniqueness),
  munit_void_test(test_ngtcp2_dcidtr_retire_inactive_dcid_prior_to),
  munit_void_test(test_ngtcp2_dcidtr_retire_active_dcid),
  munit_void_test(test_ngtcp2_dcidtr_retire_stale_bound_dcid),
  munit_void_test(test_ngtcp2_dcidtr_remove_stale_retired_dcid),
  munit_void_test(test_ngtcp2_dcidtr_pop_bound_dcid),
  munit_void_test(test_ngtcp2_dcidtr_earliest_bound_ts),
  munit_void_test(test_ngtcp2_dcidtr_earliest_retired_ts),
  munit_void_test(test_ngtcp2_dcidtr_pop_unused),
  munit_void_test(test_ngtcp2_dcidtr_check_path_retired),
  munit_void_test(test_ngtcp2_dcidtr_len),
  munit_test_end(),
};

const MunitSuite dcidtr_suite = {
  .prefix = "/dcidtr",
  .tests = tests,
};

typedef struct userdata {
  size_t cb_called;
} userdata;

static int dcidtr_cb(const ngtcp2_dcid *dcid, void *user_data) {
  userdata *ud = user_data;
  (void)dcid;

  ++ud->cb_called;

  return 0;
}

void test_ngtcp2_dcidtr_track_retired_seq(void) {
  ngtcp2_dcidtr dtr;
  size_t i;
  int rv;

  ngtcp2_dcidtr_init(&dtr);

  assert_false(ngtcp2_dcidtr_check_retired_seq_tracked(&dtr, 0));

  rv = ngtcp2_dcidtr_track_retired_seq(&dtr, 0);

  assert_int(0, ==, rv);
  assert_true(ngtcp2_dcidtr_check_retired_seq_tracked(&dtr, 0));
  assert_size(1, ==, dtr.retire_unacked.len);

  ngtcp2_dcidtr_untrack_retired_seq(&dtr, 0);

  assert_false(ngtcp2_dcidtr_check_retired_seq_tracked(&dtr, 0));
  assert_size(0, ==, dtr.retire_unacked.len);

  for (i = 0; i < NGTCP2_DCIDTR_MAX_UNUSED_DCID_SIZE * 2; ++i) {
    rv = ngtcp2_dcidtr_track_retired_seq(&dtr, i);

    assert_int(0, ==, rv);
  }

  rv = ngtcp2_dcidtr_track_retired_seq(&dtr, i);

  assert_int(NGTCP2_ERR_CONNECTION_ID_LIMIT, ==, rv);
}

void test_ngtcp2_dcidtr_bind_dcid(void) {
  ngtcp2_dcidtr dtr;
  ngtcp2_cid cid = {0};
  const uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN] = {5};
  ngtcp2_dcid *dcid = NULL;
  ngtcp2_path_storage ps;
  ngtcp2_tstamp t = 1000000007;
  size_t i;
  userdata ud;
  int rv;

  path_init(&ps, 0, 0, 0, 7);
  ngtcp2_dcidtr_init(&dtr);

  ngtcp2_dcidtr_push_unused(&dtr, 0, &cid, token);

  rv = ngtcp2_dcidtr_bind_dcid(&dtr, &dcid, &ps.path, t, NULL, NULL);

  assert_int(0, ==, rv);
  assert_ptr_equal(ngtcp2_ringbuf_get(&dtr.bound.rb, 0), dcid);
  assert_true(ngtcp2_path_eq(&ps.path, &dcid->ps.path));
  assert_size(0, ==, ngtcp2_ringbuf_len(&dtr.unused.rb));
  assert_size(1, ==, ngtcp2_ringbuf_len(&dtr.bound.rb));

  /* ngtcp2_dcid is retired when binding new Destination Connection ID
     and the bound buffer is full. */
  ngtcp2_dcidtr_init(&dtr);

  for (i = 0; i < NGTCP2_DCIDTR_MAX_BOUND_DCID_SIZE + 1; ++i) {
    ngtcp2_dcidtr_push_unused(&dtr, i, &cid, token);
  }

  for (i = 0; i < NGTCP2_DCIDTR_MAX_BOUND_DCID_SIZE; ++i) {
    ud.cb_called = 0;
    rv = ngtcp2_dcidtr_bind_dcid(&dtr, &dcid, &ps.path, t, dcidtr_cb, &ud);

    assert_int(0, ==, rv);
    assert_uint64((uint64_t)i, ==, dcid->seq);
    assert_size(0, ==, ud.cb_called);
  }

  rv = ngtcp2_dcidtr_bind_dcid(&dtr, &dcid, &ps.path, t, dcidtr_cb, &ud);

  assert_int(0, ==, rv);
  assert_uint64((uint64_t)i, ==, dcid->seq);
  assert_size(1, ==, ud.cb_called);
  assert_true(ngtcp2_dcidtr_check_retired_seq_tracked(&dtr, 0));
}

void test_ngtcp2_dcidtr_find_bound_dcid(void) {
  ngtcp2_dcidtr dtr;
  ngtcp2_cid cid = {0};
  const uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN] = {8};
  ngtcp2_dcid *dcid;
  ngtcp2_path_storage ps[2];
  ngtcp2_tstamp t = 0;
  int rv;
  size_t i;

  for (i = 0; i < ngtcp2_arraylen(ps); ++i) {
    path_init(&ps[i], 0, 0, 0, (uint16_t)i + 1);
  }

  ngtcp2_dcidtr_init(&dtr);

  ngtcp2_dcidtr_push_unused(&dtr, 0, &cid, token);

  rv = ngtcp2_dcidtr_bind_dcid(&dtr, &dcid, &ps[0].path, t, NULL, NULL);

  assert_int(0, ==, rv);
  assert_null(ngtcp2_dcidtr_find_bound_dcid(&dtr, &ps[1].path));

  dcid = ngtcp2_dcidtr_find_bound_dcid(&dtr, &ps[0].path);

  assert_true(ngtcp2_path_eq(&ps[0].path, &dcid->ps.path));
}

void test_ngtcp2_dcidtr_bind_zerolen_dcid(void) {
  ngtcp2_dcidtr dtr;
  ngtcp2_path_storage ps;
  ngtcp2_dcid *dcid;

  path_init(&ps, 0, 1, 0, 2);
  ngtcp2_dcidtr_init(&dtr);

  dcid = ngtcp2_dcidtr_bind_zerolen_dcid(&dtr, &ps.path);

  assert_uint64(0, ==, dcid->seq);
  assert_true(ngtcp2_path_eq(&ps.path, &dcid->ps.path));

  dcid = ngtcp2_dcidtr_bind_zerolen_dcid(&dtr, &ps.path);

  assert_uint64(0, ==, dcid->seq);
  assert_true(ngtcp2_path_eq(&ps.path, &dcid->ps.path));
}

void test_ngtcp2_dcidtr_verify_stateless_reset(void) {
  ngtcp2_dcidtr dtr;
  ngtcp2_path_storage ps[3];
  ngtcp2_cid cid[] = {
    {
      .data = {1},
      .datalen = 7,
    },
    {
      .data = {2},
      .datalen = 7,
    },
    {
      .data = {3},
      .datalen = 7,
    },
  };
  const uint8_t token[][NGTCP2_STATELESS_RESET_TOKENLEN] = {
    {1},
    {2},
    {3},
  };
  ngtcp2_dcid *dcid;
  ngtcp2_dcid active_dcid;
  size_t i;
  int rv;

  for (i = 0; i < ngtcp2_arraylen(ps); ++i) {
    path_init(&ps[i], 0, 0, 0, (uint16_t)i + 1);
  }

  ngtcp2_dcidtr_init(&dtr);

  for (i = 0; i < ngtcp2_arraylen(cid) - 1; ++i) {
    ngtcp2_dcidtr_push_unused(&dtr, i, &cid[i], token[i]);
  }

  rv = ngtcp2_dcidtr_bind_dcid(&dtr, &dcid, &ps[0].path, 0, NULL, NULL);

  assert_int(0, ==, rv);

  rv = ngtcp2_dcidtr_verify_stateless_reset(&dtr, &ps[0].path, token[0]);

  assert_int(0, ==, rv);

  rv = ngtcp2_dcidtr_verify_stateless_reset(&dtr, &ps[1].path, token[1]);

  assert_int(NGTCP2_ERR_INVALID_ARGUMENT, ==, rv);

  ngtcp2_dcid_init(&active_dcid, 2, &cid[2], token[2]);
  ngtcp2_dcid_set_path(&active_dcid, &ps[2].path);

  rv = ngtcp2_dcidtr_retire_active_dcid(&dtr, &active_dcid, 0, NULL, NULL);

  assert_int(0, ==, rv);

  rv = ngtcp2_dcidtr_verify_stateless_reset(&dtr, &ps[2].path, token[2]);

  assert_int(NGTCP2_ERR_INVALID_ARGUMENT, ==, rv);
}

void test_ngtcp2_dcidtr_verify_token_uniqueness(void) {
  ngtcp2_dcidtr dtr;
  ngtcp2_path_storage ps[3];
  ngtcp2_cid cid[] = {
    {
      .data = {1},
      .datalen = 7,
    },
    {
      .data = {2},
      .datalen = 7,
    },
    {
      .data = {3},
      .datalen = 7,
    },
  };
  const uint8_t token[][NGTCP2_STATELESS_RESET_TOKENLEN] = {
    {1},
    {2},
    {3},
  };
  ngtcp2_dcid *dcid;
  size_t i;
  int rv;
  int found;

  for (i = 0; i < ngtcp2_arraylen(ps); ++i) {
    path_init(&ps[i], 0, 0, 0, (uint16_t)i + 1);
  }

  ngtcp2_dcidtr_init(&dtr);

  for (i = 0; i < ngtcp2_arraylen(cid) - 1; ++i) {
    ngtcp2_dcidtr_push_unused(&dtr, i, &cid[i], token[i]);
  }

  rv = ngtcp2_dcidtr_bind_dcid(&dtr, &dcid, &ps[0].path, 0, NULL, NULL);

  assert_int(0, ==, rv);

  found = 0;
  rv =
    ngtcp2_dcidtr_verify_token_uniqueness(&dtr, &found, 0, &cid[0], token[0]);

  assert_int(0, ==, rv);
  assert_true(found);

  found = 0;
  rv =
    ngtcp2_dcidtr_verify_token_uniqueness(&dtr, &found, 1, &cid[1], token[1]);

  assert_int(0, ==, rv);
  assert_true(found);

  found = 0;
  rv =
    ngtcp2_dcidtr_verify_token_uniqueness(&dtr, &found, 2, &cid[2], token[2]);

  assert_int(0, ==, rv);
  assert_false(found);

  rv =
    ngtcp2_dcidtr_verify_token_uniqueness(&dtr, &found, 1, &cid[2], token[2]);

  assert_int(NGTCP2_ERR_PROTO, ==, rv);

  rv =
    ngtcp2_dcidtr_verify_token_uniqueness(&dtr, &found, 2, &cid[0], token[0]);

  assert_int(NGTCP2_ERR_PROTO, ==, rv);
}

void test_ngtcp2_dcidtr_retire_inactive_dcid_prior_to(void) {
  ngtcp2_dcidtr dtr;
  ngtcp2_path_storage ps[4];
  ngtcp2_cid cid[] = {
    {
      .data = {1},
      .datalen = 7,
    },
    {
      .data = {2},
      .datalen = 7,
    },
    {
      .data = {3},
      .datalen = 7,
    },
    {
      .data = {4},
      .datalen = 7,
    },
  };
  const uint8_t token[][NGTCP2_STATELESS_RESET_TOKENLEN] = {
    {1},
    {2},
    {3},
    {4},
  };
  ngtcp2_dcid *dcid;
  size_t i;
  int rv;
  userdata ud;

  for (i = 0; i < ngtcp2_arraylen(ps); ++i) {
    path_init(&ps[i], 0, 0, 0, (uint16_t)i + 1);
  }

  ngtcp2_dcidtr_init(&dtr);

  for (i = 0; i < ngtcp2_arraylen(cid); ++i) {
    ngtcp2_dcidtr_push_unused(&dtr, i, &cid[i], token[i]);
  }

  for (i = 0; i < 2; ++i) {
    rv = ngtcp2_dcidtr_bind_dcid(&dtr, &dcid, &ps[i].path, 0, NULL, NULL);

    assert_int(0, ==, rv);
  }

  ud.cb_called = 0;
  rv = ngtcp2_dcidtr_retire_inactive_dcid_prior_to(&dtr, 3, dcidtr_cb, &ud);

  assert_int(0, ==, rv);
  assert_size(3, ==, ud.cb_called);
  assert_size(1, ==, ngtcp2_dcidtr_unused_len(&dtr));
  assert_size(0, ==, ngtcp2_dcidtr_bound_len(&dtr));

  dcid = ngtcp2_ringbuf_get(&dtr.unused.rb, 0);

  assert_uint64(3, ==, dcid->seq);
}

void test_ngtcp2_dcidtr_retire_active_dcid(void) {
  ngtcp2_dcidtr dtr;
  ngtcp2_path_storage ps;
  ngtcp2_cid cid = {
    .data = {1},
    .datalen = 9,
  };
  const uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN] = {1};
  ngtcp2_dcid dcid, *retired_dcid;
  size_t i;
  userdata ud;
  int rv;

  path_init(&ps, 0, 0, 0, 1);
  ngtcp2_dcidtr_init(&dtr);

  for (i = 0; i < NGTCP2_DCIDTR_MAX_RETIRED_DCID_SIZE; ++i) {
    ngtcp2_dcid_init(&dcid, i, &cid, token);
    ud.cb_called = 0;
    rv = ngtcp2_dcidtr_retire_active_dcid(&dtr, &dcid, 1000000007 + i,
                                          dcidtr_cb, &ud);

    assert_int(0, ==, rv);
    assert_size(0, ==, ud.cb_called);

    retired_dcid = ngtcp2_ringbuf_get(&dtr.retired.rb,
                                      ngtcp2_ringbuf_len(&dtr.retired.rb) - 1);

    assert_uint64(i, ==, retired_dcid->seq);
    assert_true(ngtcp2_cid_eq(&cid, &retired_dcid->cid));
    assert_memory_equal(sizeof(token), token, retired_dcid->token);
  }

  ngtcp2_dcid_init(&dcid, i, &cid, token);
  ud.cb_called = 0;
  rv = ngtcp2_dcidtr_retire_active_dcid(&dtr, &dcid, 1000000007 + i, dcidtr_cb,
                                        &ud);

  assert_int(0, ==, rv);
  assert_size(1, ==, ud.cb_called);

  retired_dcid = ngtcp2_ringbuf_get(&dtr.retired.rb,
                                    ngtcp2_ringbuf_len(&dtr.retired.rb) - 1);

  assert_uint64(i, ==, retired_dcid->seq);
  assert_true(ngtcp2_cid_eq(&cid, &retired_dcid->cid));
  assert_memory_equal(sizeof(token), token, retired_dcid->token);
}

void test_ngtcp2_dcidtr_retire_stale_bound_dcid(void) {
  ngtcp2_dcidtr dtr;
  ngtcp2_path_storage ps;
  ngtcp2_cid cid = {
    .data = {1},
    .datalen = 11,
  };
  const uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN] = {0xfe};
  ngtcp2_dcid *dcid;
  size_t i;
  userdata ud;
  int rv;
  ngtcp2_tstamp t = 1000;

  path_init(&ps, 0, 0, 0, 1);
  ngtcp2_dcidtr_init(&dtr);

  for (i = 0; i < 3; ++i) {
    ngtcp2_dcidtr_push_unused(&dtr, i, &cid, token);

    rv = ngtcp2_dcidtr_bind_dcid(&dtr, &dcid, &ps.path, t + i, NULL, NULL);

    assert_int(0, ==, rv);
  }

  ud.cb_called = 0;
  rv = ngtcp2_dcidtr_retire_stale_bound_dcid(&dtr, 100, t + 99, dcidtr_cb, &ud);

  assert_int(0, ==, rv);
  assert_size(0, ==, ud.cb_called);

  ud.cb_called = 0;
  rv =
    ngtcp2_dcidtr_retire_stale_bound_dcid(&dtr, 100, t + 101, dcidtr_cb, &ud);

  assert_int(0, ==, rv);
  assert_size(2, ==, ud.cb_called);
  assert_true(ngtcp2_dcidtr_check_retired_seq_tracked(&dtr, 0));
  assert_true(ngtcp2_dcidtr_check_retired_seq_tracked(&dtr, 1));
}

void test_ngtcp2_dcidtr_remove_stale_retired_dcid(void) {
  ngtcp2_dcidtr dtr;
  ngtcp2_path_storage ps;
  ngtcp2_cid cid = {
    .data = {1},
    .datalen = 1,
  };
  const uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN] = {1};
  ngtcp2_dcid dcid, *retired_dcid;
  size_t i;
  userdata ud;
  int rv;
  ngtcp2_tstamp t = 1000000009;

  path_init(&ps, 0, 0, 0, 1);
  ngtcp2_dcidtr_init(&dtr);

  for (i = 0; i < NGTCP2_DCIDTR_MAX_RETIRED_DCID_SIZE; ++i) {
    ngtcp2_dcid_init(&dcid, i, &cid, token);
    ud.cb_called = 0;
    rv = ngtcp2_dcidtr_retire_active_dcid(&dtr, &dcid, t + i, dcidtr_cb, &ud);

    assert_int(0, ==, rv);
    assert_size(0, ==, ud.cb_called);
  }

  ud.cb_called = 0;
  rv =
    ngtcp2_dcidtr_remove_stale_retired_dcid(&dtr, 100, t + 99, dcidtr_cb, &ud);

  assert_int(0, ==, rv);
  assert_size(0, ==, ud.cb_called);

  ud.cb_called = 0;
  rv =
    ngtcp2_dcidtr_remove_stale_retired_dcid(&dtr, 100, t + 100, dcidtr_cb, &ud);

  assert_int(0, ==, rv);
  assert_size(1, ==, ud.cb_called);
  assert_size(1, ==, ngtcp2_ringbuf_len(&dtr.retired.rb));

  retired_dcid = ngtcp2_ringbuf_get(&dtr.retired.rb, 0);

  assert_uint64(1, ==, retired_dcid->seq);
}

void test_ngtcp2_dcidtr_pop_bound_dcid(void) {
  ngtcp2_dcidtr dtr;
  ngtcp2_path_storage ps[3];
  ngtcp2_cid cid = {
    .data = {1},
    .datalen = 11,
  };
  const uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN] = {0xfe};
  ngtcp2_dcid *dcid, bound_dcid;
  size_t i;
  int rv;

  for (i = 0; i < ngtcp2_arraylen(ps); ++i) {
    path_init(&ps[i], 0, 0, 0, (uint16_t)i + 1);
  }

  ngtcp2_dcidtr_init(&dtr);

  for (i = 0; i < 2; ++i) {
    ngtcp2_dcidtr_push_unused(&dtr, i, &cid, token);

    rv = ngtcp2_dcidtr_bind_dcid(&dtr, &dcid, &ps[i].path, 0, NULL, NULL);

    assert_int(0, ==, rv);
  }

  assert_int(NGTCP2_ERR_INVALID_ARGUMENT, ==,
             ngtcp2_dcidtr_pop_bound_dcid(&dtr, &bound_dcid, &ps[2].path));
  assert_int(0, ==,
             ngtcp2_dcidtr_pop_bound_dcid(&dtr, &bound_dcid, &ps[1].path));
  assert_uint64(1, ==, bound_dcid.seq);
  assert_true(ngtcp2_path_eq(&ps[1].path, &bound_dcid.ps.path));
}

void test_ngtcp2_dcidtr_earliest_bound_ts(void) {
  ngtcp2_dcidtr dtr;
  ngtcp2_path_storage ps;
  ngtcp2_cid cid = {
    .data = {1},
    .datalen = 11,
  };
  const uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN] = {0xfe};
  ngtcp2_dcid *dcid;
  size_t i;
  int rv;
  ngtcp2_tstamp t = 10000007;

  path_init(&ps, 0, 0, 0, 1);
  ngtcp2_dcidtr_init(&dtr);

  assert_uint64(UINT64_MAX, ==, ngtcp2_dcidtr_earliest_bound_ts(&dtr));

  for (i = 0; i < 3; ++i) {
    ngtcp2_dcidtr_push_unused(&dtr, i, &cid, token);

    rv = ngtcp2_dcidtr_bind_dcid(&dtr, &dcid, &ps.path, t + i, NULL, NULL);

    assert_int(0, ==, rv);
  }

  assert_uint64(t, ==, ngtcp2_dcidtr_earliest_bound_ts(&dtr));
}

void test_ngtcp2_dcidtr_earliest_retired_ts(void) {
  ngtcp2_dcidtr dtr;
  ngtcp2_path_storage ps;
  ngtcp2_cid cid = {
    .data = {1},
    .datalen = 1,
  };
  const uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN] = {1};
  ngtcp2_dcid dcid;
  int rv;
  ngtcp2_tstamp t = 1000000009;

  path_init(&ps, 0, 0, 0, 1);
  ngtcp2_dcidtr_init(&dtr);

  assert_uint64(UINT64_MAX, ==, ngtcp2_dcidtr_earliest_retired_ts(&dtr));

  ngtcp2_dcid_init(&dcid, 0, &cid, token);

  rv = ngtcp2_dcidtr_retire_active_dcid(&dtr, &dcid, t, NULL, NULL);

  assert_int(0, ==, rv);
  assert_uint64(t, ==, ngtcp2_dcidtr_earliest_retired_ts(&dtr));
}

void test_ngtcp2_dcidtr_pop_unused(void) {
  ngtcp2_dcidtr dtr;
  ngtcp2_path_storage ps;
  ngtcp2_cid cid = {
    .data = {1},
    .datalen = 11,
  };
  const uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN] = {0xfe};
  ngtcp2_dcid dcid;
  size_t i;

  ngtcp2_dcidtr_init(&dtr);

  assert_uint64(UINT64_MAX, ==, ngtcp2_dcidtr_earliest_bound_ts(&dtr));

  for (i = 0; i < 2; ++i) {
    ngtcp2_dcidtr_push_unused(&dtr, 9155421 + i, &cid, token);
  }

  path_init(&dcid.ps, 0, 0, 0, 1);
  ngtcp2_dcidtr_pop_unused(&dtr, &dcid);

  assert_uint64(9155421, ==, dcid.seq);
  assert_true(ngtcp2_cid_eq(&cid, &dcid.cid));
  assert_size(0, ==, (size_t)dcid.ps.path.local.addrlen);
  assert_size(0, ==, (size_t)dcid.ps.path.remote.addrlen);

  path_init(&dcid.ps, 0, 0, 0, 1);
  ngtcp2_path_storage_zero(&ps);
  ngtcp2_path_copy(&ps.path, &dcid.ps.path);
  ngtcp2_dcidtr_pop_unused_cid_token(&dtr, &dcid);

  assert_uint64(9155422, ==, dcid.seq);
  assert_true(ngtcp2_cid_eq(&cid, &dcid.cid));
  assert_true(ngtcp2_path_eq(&ps.path, &dcid.ps.path));
}

void test_ngtcp2_dcidtr_check_path_retired(void) {
  ngtcp2_dcidtr dtr;
  ngtcp2_path_storage ps[2];
  ngtcp2_cid cid = {
    .data = {1},
    .datalen = 1,
  };
  const uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN] = {1};
  ngtcp2_dcid dcid;
  size_t i;
  int rv;
  ngtcp2_tstamp t = 1000000009;

  for (i = 0; i < ngtcp2_arraylen(ps); ++i) {
    path_init(&ps[i], 0, 0, 0, (uint16_t)i + 1);
  }

  ngtcp2_dcidtr_init(&dtr);
  ngtcp2_dcid_init(&dcid, 0, &cid, token);
  ngtcp2_dcid_set_path(&dcid, &ps[1].path);

  rv = ngtcp2_dcidtr_retire_active_dcid(&dtr, &dcid, t, NULL, NULL);

  assert_int(0, ==, rv);
  assert_false(ngtcp2_dcidtr_check_path_retired(&dtr, &ps[0].path));
  assert_true(ngtcp2_dcidtr_check_path_retired(&dtr, &ps[1].path));
}

void test_ngtcp2_dcidtr_len(void) {
  ngtcp2_dcidtr dtr;
  ngtcp2_path_storage ps;
  ngtcp2_cid cid = {
    .data = {1},
    .datalen = 1,
  };
  const uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN] = {1};
  ngtcp2_dcid *dcid, retired_dcid;
  size_t i;
  int rv;

  path_init(&ps, 0, 0, 0, 1);
  ngtcp2_dcidtr_init(&dtr);

  assert_size(0, ==, ngtcp2_dcidtr_unused_len(&dtr));
  assert_size(0, ==, ngtcp2_dcidtr_bound_len(&dtr));
  assert_size(0, ==, ngtcp2_dcidtr_retired_len(&dtr));
  assert_size(0, ==, ngtcp2_dcidtr_inactive_len(&dtr));
  assert_true(ngtcp2_dcidtr_unused_empty(&dtr));
  assert_false(ngtcp2_dcidtr_unused_full(&dtr));
  assert_false(ngtcp2_dcidtr_bound_full(&dtr));

  for (i = 0; i < NGTCP2_DCIDTR_MAX_UNUSED_DCID_SIZE; ++i) {
    ngtcp2_dcidtr_push_unused(&dtr, 0, &cid, token);
  }

  assert_size(NGTCP2_DCIDTR_MAX_UNUSED_DCID_SIZE, ==,
              ngtcp2_dcidtr_unused_len(&dtr));
  assert_size(0, ==, ngtcp2_dcidtr_bound_len(&dtr));
  assert_size(0, ==, ngtcp2_dcidtr_retired_len(&dtr));
  assert_size(NGTCP2_DCIDTR_MAX_UNUSED_DCID_SIZE, ==,
              ngtcp2_dcidtr_inactive_len(&dtr));
  assert_false(ngtcp2_dcidtr_unused_empty(&dtr));
  assert_true(ngtcp2_dcidtr_unused_full(&dtr));
  assert_false(ngtcp2_dcidtr_bound_full(&dtr));

  for (i = 0; i < NGTCP2_DCIDTR_MAX_BOUND_DCID_SIZE; ++i) {
    rv = ngtcp2_dcidtr_bind_dcid(&dtr, &dcid, &ps.path, 0, NULL, NULL);

    assert_int(0, ==, rv);
  }

  assert_size(4, ==, ngtcp2_dcidtr_unused_len(&dtr));
  assert_size(NGTCP2_DCIDTR_MAX_BOUND_DCID_SIZE, ==,
              ngtcp2_dcidtr_bound_len(&dtr));
  assert_size(0, ==, ngtcp2_dcidtr_retired_len(&dtr));
  assert_size(4 + NGTCP2_DCIDTR_MAX_BOUND_DCID_SIZE, ==,
              ngtcp2_dcidtr_inactive_len(&dtr));
  assert_false(ngtcp2_dcidtr_unused_empty(&dtr));
  assert_false(ngtcp2_dcidtr_unused_full(&dtr));
  assert_true(ngtcp2_dcidtr_bound_full(&dtr));

  for (i = 0; i < NGTCP2_DCIDTR_MAX_RETIRED_DCID_SIZE; ++i) {
    ngtcp2_dcid_init(&retired_dcid, 0, &cid, token);

    rv = ngtcp2_dcidtr_retire_active_dcid(&dtr, &retired_dcid, 0, NULL, NULL);

    assert_int(0, ==, rv);
  }

  assert_size(4, ==, ngtcp2_dcidtr_unused_len(&dtr));
  assert_size(NGTCP2_DCIDTR_MAX_BOUND_DCID_SIZE, ==,
              ngtcp2_dcidtr_bound_len(&dtr));
  assert_size(NGTCP2_DCIDTR_MAX_RETIRED_DCID_SIZE, ==,
              ngtcp2_dcidtr_retired_len(&dtr));
  assert_size(4 + NGTCP2_DCIDTR_MAX_BOUND_DCID_SIZE, ==,
              ngtcp2_dcidtr_inactive_len(&dtr));
  assert_false(ngtcp2_dcidtr_unused_empty(&dtr));
  assert_false(ngtcp2_dcidtr_unused_full(&dtr));
  assert_true(ngtcp2_dcidtr_bound_full(&dtr));
}
