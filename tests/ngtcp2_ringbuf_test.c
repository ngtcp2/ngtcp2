/*
 * ngtcp2
 *
 * Copyright (c) 2017 ngtcp2 contributors
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
#include "ngtcp2_ringbuf_test.h"

#include <stdio.h>

#include "ngtcp2_ringbuf.h"
#include "ngtcp2_test_helper.h"

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_ringbuf_push_front),
  munit_void_test(test_ngtcp2_ringbuf_pop_front),
  munit_test_end(),
};

const MunitSuite ringbuf_suite = {
  .prefix = "/ringbuf",
  .tests = tests,
};

typedef struct {
  int32_t a;
  uint64_t b;
} ints;

void test_ngtcp2_ringbuf_push_front(void) {
  ngtcp2_ringbuf rb;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  size_t i;

  ngtcp2_ringbuf_init(&rb, 64, sizeof(ints), mem);

  for (i = 0; i < 64; ++i) {
    ints *p = ngtcp2_ringbuf_push_front(&rb);
    p->a = (int32_t)(i + 1);
    p->b = (i + 1) * 10;
  }

  assert_size(64, ==, ngtcp2_ringbuf_len(&rb));

  for (i = 0; i < 64; ++i) {
    ints *p = ngtcp2_ringbuf_get(&rb, i);
    assert_int32((int32_t)(64 - i), ==, p->a);
    assert_uint64((64 - i) * 10, ==, p->b);
  }

  ngtcp2_ringbuf_push_front(&rb);

  assert_size(64, ==, ngtcp2_ringbuf_len(&rb));
  assert_int32((int32_t)64, ==, ((ints *)ngtcp2_ringbuf_get(&rb, 1))->a);

  ngtcp2_ringbuf_free(&rb);
}

void test_ngtcp2_ringbuf_pop_front(void) {
  ngtcp2_ringbuf rb;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  size_t i;

  ngtcp2_ringbuf_init(&rb, 4, sizeof(ints), mem);

  for (i = 0; i < 5; ++i) {
    ints *p = ngtcp2_ringbuf_push_front(&rb);
    p->a = (int32_t)i;
  }

  assert_size(4, ==, ngtcp2_ringbuf_len(&rb));

  for (i = 4; i >= 1; --i) {
    ints *p = ngtcp2_ringbuf_get(&rb, 0);

    assert_int32((int32_t)i, ==, p->a);

    ngtcp2_ringbuf_pop_front(&rb);
  }

  assert_size(0, ==, ngtcp2_ringbuf_len(&rb));

  ngtcp2_ringbuf_free(&rb);
}
