/*
 * ngtcp2
 *
 * Copyright (c) 2018 ngtcp2 contributors
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
#include "ngtcp2_vec_test.h"

#include <stdio.h>

#include "ngtcp2_vec.h"
#include "ngtcp2_test_helper.h"

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_vec_split),
  munit_void_test(test_ngtcp2_vec_merge),
  munit_void_test(test_ngtcp2_vec_len_varint),
  munit_void_test(test_ngtcp2_vec_copy_at_most),
  munit_test_end(),
};

const MunitSuite vec_suite = {
  .prefix = "/vec",
  .tests = tests,
};

void test_ngtcp2_vec_split(void) {
  uint8_t nulldata[1024];
  ngtcp2_vec a[16], b[16];
  size_t acnt, bcnt;
  ngtcp2_ssize nsplit;

  /* No split occurs */
  acnt = 1;
  a[0].len = 135;
  a[0].base = nulldata;

  bcnt = 0;
  b[0].len = 0;
  b[0].base = NULL;

  nsplit = ngtcp2_vec_split(b, &bcnt, a, &acnt, 135, 16);

  assert_ptrdiff(0, ==, nsplit);
  assert_size(1, ==, acnt);
  assert_size(135, ==, a[0].len);
  assert_ptr_equal(nulldata, a[0].base);
  assert_size(0, ==, bcnt);
  assert_size(0, ==, b[0].len);
  assert_null(b[0].base);

  /* Split once */
  acnt = 1;
  a[0].len = 135;
  a[0].base = nulldata;

  bcnt = 0;
  b[0].len = 0;
  b[0].base = NULL;

  nsplit = ngtcp2_vec_split(b, &bcnt, a, &acnt, 87, 16);

  assert_ptrdiff(48, ==, nsplit);
  assert_size(1, ==, acnt);
  assert_size(87, ==, a[0].len);
  assert_ptr_equal(nulldata, a[0].base);
  assert_size(1, ==, bcnt);
  assert_size(48, ==, b[0].len);
  assert_ptr_equal(nulldata + 87, b[0].base);

  /* Multiple a vector; split at ngtcp2_vec boundary */
  acnt = 2;
  a[0].len = 33;
  a[0].base = nulldata;
  a[1].len = 89;
  a[1].base = nulldata + 33;

  bcnt = 0;
  b[0].len = 0;
  b[0].base = NULL;

  nsplit = ngtcp2_vec_split(b, &bcnt, a, &acnt, 33, 16);

  assert_ptrdiff(89, ==, nsplit);
  assert_size(1, ==, acnt);
  assert_size(33, ==, a[0].len);
  assert_ptr_equal(nulldata, a[0].base);
  assert_size(1, ==, bcnt);
  assert_size(89, ==, b[0].len);
  assert_ptr_equal(nulldata + 33, b[0].base);

  /* Multiple a vector; not split at ngtcp2_vec boundary */
  acnt = 3;
  a[0].len = 33;
  a[0].base = nulldata;
  a[1].len = 89;
  a[1].base = nulldata + 33;
  a[2].len = 211;
  a[2].base = nulldata + 33 + 89;

  bcnt = 0;
  b[0].len = 0;
  b[0].base = NULL;

  nsplit = ngtcp2_vec_split(b, &bcnt, a, &acnt, 34, 16);

  assert_ptrdiff(88 + 211, ==, nsplit);
  assert_size(2, ==, acnt);
  assert_size(33, ==, a[0].len);
  assert_ptr_equal(nulldata, a[0].base);
  assert_size(1, ==, a[1].len);
  assert_ptr_equal(nulldata + 33, a[1].base);
  assert_size(2, ==, bcnt);
  assert_size(88, ==, b[0].len);
  assert_ptr_equal(nulldata + 34, b[0].base);
  assert_size(211, ==, b[1].len);
  assert_ptr_equal(nulldata + 34 + 88, b[1].base);

  /* Multiple a vector; split at ngtcp2_vec boundary; continuous
     data */
  acnt = 2;
  a[0].len = 33;
  a[0].base = nulldata;
  a[1].len = 89;
  a[1].base = nulldata + 33;

  bcnt = 2;
  b[0].len = 17;
  b[0].base = nulldata + 33 + 89;
  b[1].len = 3;
  b[1].base = nulldata + 33 + 89 + 17;

  nsplit = ngtcp2_vec_split(b, &bcnt, a, &acnt, 33, 16);

  assert_ptrdiff(89, ==, nsplit);
  assert_size(1, ==, acnt);
  assert_size(33, ==, a[0].len);
  assert_ptr_equal(nulldata, a[0].base);
  assert_size(2, ==, bcnt);
  assert_size(89 + 17, ==, b[0].len);
  assert_ptr_equal(nulldata + 33, b[0].base);
  assert_size(3, ==, b[1].len);
  assert_ptr_equal(nulldata + 33 + 89 + 17, b[1].base);

  /* Multiple a vector; not split at ngtcp2_vec boundary; continuous
     data; nmove == 0 */
  acnt = 2;
  a[0].len = 33;
  a[0].base = nulldata;
  a[1].len = 89;
  a[1].base = nulldata + 33;

  bcnt = 2;
  b[0].len = 17;
  b[0].base = nulldata + 33 + 89;
  b[1].len = 3;
  b[1].base = nulldata + 33 + 89 + 17;

  nsplit = ngtcp2_vec_split(b, &bcnt, a, &acnt, 34, 16);

  assert_ptrdiff(88, ==, nsplit);
  assert_size(2, ==, acnt);
  assert_size(33, ==, a[0].len);
  assert_ptr_equal(nulldata, a[0].base);
  assert_size(1, ==, a[1].len);
  assert_ptr_equal(nulldata + 33, a[1].base);
  assert_size(2, ==, bcnt);
  assert_size(88 + 17, ==, b[0].len);
  assert_ptr_equal(nulldata + 34, b[0].base);
  assert_size(3, ==, b[1].len);
  assert_ptr_equal(nulldata + 33 + 89 + 17, b[1].base);

  /* Multiple a vector; not split at ngtcp2_vec boundary; continuous
     data */
  acnt = 3;
  a[0].len = 33;
  a[0].base = nulldata;
  a[1].len = 89;
  a[1].base = nulldata + 33;
  a[2].len = 211;
  a[2].base = nulldata + 33 + 89;

  bcnt = 2;
  b[0].len = 17;
  b[0].base = nulldata + 33 + 89 + 211;
  b[1].len = 3;
  b[1].base = nulldata + 33 + 89 + 211 + 17;

  nsplit = ngtcp2_vec_split(b, &bcnt, a, &acnt, 34, 16);

  assert_ptrdiff(88 + 211, ==, nsplit);
  assert_size(2, ==, acnt);
  assert_size(33, ==, a[0].len);
  assert_ptr_equal(nulldata, a[0].base);
  assert_size(1, ==, a[1].len);
  assert_ptr_equal(nulldata + 33, a[1].base);
  assert_size(3, ==, bcnt);
  assert_size(88, ==, b[0].len);
  assert_ptr_equal(nulldata + 34, b[0].base);
  assert_size(211 + 17, ==, b[1].len);
  assert_ptr_equal(nulldata + 34 + 88, b[1].base);
  assert_size(3, ==, b[2].len);
  assert_ptr_equal(nulldata + 33 + 89 + 211 + 17, b[2].base);

  /* Multiple a vector; split at ngtcp2_vec boundary; not continuous
     data */
  acnt = 2;
  a[0].len = 33;
  a[0].base = nulldata;
  a[1].len = 89;
  a[1].base = nulldata + 33;

  bcnt = 2;
  b[0].len = 17;
  b[0].base = nulldata + 256;
  b[1].len = 3;
  b[1].base = nulldata + 256 + 17;

  nsplit = ngtcp2_vec_split(b, &bcnt, a, &acnt, 33, 16);

  assert_ptrdiff(89, ==, nsplit);
  assert_size(1, ==, acnt);
  assert_size(33, ==, a[0].len);
  assert_ptr_equal(nulldata, a[0].base);
  assert_size(3, ==, bcnt);
  assert_size(89, ==, b[0].len);
  assert_ptr_equal(nulldata + 33, b[0].base);
  assert_size(17, ==, b[1].len);
  assert_ptr_equal(nulldata + 256, b[1].base);
  assert_size(3, ==, b[2].len);
  assert_ptr_equal(nulldata + 256 + 17, b[2].base);

  /* maxcnt exceeded; continuous */
  acnt = 2;
  a[0].len = 33;
  a[0].base = nulldata;
  a[1].len = 89;
  a[1].base = nulldata + 33;

  bcnt = 1;
  b[0].len = 17;
  b[0].base = nulldata + 33 + 89;

  nsplit = ngtcp2_vec_split(b, &bcnt, a, &acnt, 32, 1);

  assert_ptrdiff(-1, ==, nsplit);

  /* maxcnt exceeded; not continuous */
  acnt = 2;
  a[0].len = 33;
  a[0].base = nulldata;
  a[1].len = 89;
  a[1].base = nulldata + 33;

  bcnt = 1;
  b[0].len = 17;
  b[0].base = nulldata + 256;

  nsplit = ngtcp2_vec_split(b, &bcnt, a, &acnt, 33, 1);

  assert_ptrdiff(-1, ==, nsplit);
}

void test_ngtcp2_vec_merge(void) {
  uint8_t nulldata[1024];
  ngtcp2_vec a[16], b[16];
  size_t acnt, bcnt;
  size_t nmerged;

  /* Merge one ngtcp2_vec completely */
  acnt = 1;
  a[0].len = 33;
  a[0].base = nulldata;

  bcnt = 1;
  b[0].len = 11;
  b[0].base = nulldata + 33;

  nmerged = ngtcp2_vec_merge(a, &acnt, b, &bcnt, 11, 16);

  assert_size(11, ==, nmerged);
  assert_size(1, ==, acnt);
  assert_size(44, ==, a[0].len);
  assert_ptr_equal(nulldata, a[0].base);
  assert_size(0, ==, bcnt);

  /* Merge ngtcp2_vec partially */
  acnt = 1;
  a[0].len = 33;
  a[0].base = nulldata;

  bcnt = 1;
  b[0].len = 11;
  b[0].base = nulldata + 33;

  nmerged = ngtcp2_vec_merge(a, &acnt, b, &bcnt, 10, 16);

  assert_size(10, ==, nmerged);
  assert_size(1, ==, acnt);
  assert_size(43, ==, a[0].len);
  assert_ptr_equal(nulldata, a[0].base);
  assert_size(1, ==, bcnt);
  assert_size(1, ==, b[0].len);
  assert_ptr_equal(nulldata + 33 + 10, b[0].base);

  /* Merge one ngtcp2_vec completely; data is not continuous */
  acnt = 1;
  a[0].len = 33;
  a[0].base = nulldata;

  bcnt = 1;
  b[0].len = 11;
  b[0].base = nulldata + 256;

  nmerged = ngtcp2_vec_merge(a, &acnt, b, &bcnt, 11, 16);

  assert_size(11, ==, nmerged);
  assert_size(2, ==, acnt);
  assert_size(33, ==, a[0].len);
  assert_ptr_equal(nulldata, a[0].base);
  assert_size(11, ==, a[1].len);
  assert_ptr_equal(nulldata + 256, a[1].base);
  assert_size(0, ==, bcnt);

  /* Merge ngtcp2_vec partially; data is not continuous */
  acnt = 1;
  a[0].len = 33;
  a[0].base = nulldata;

  bcnt = 1;
  b[0].len = 11;
  b[0].base = nulldata + 256;

  nmerged = ngtcp2_vec_merge(a, &acnt, b, &bcnt, 10, 16);

  assert_size(10, ==, nmerged);
  assert_size(2, ==, acnt);
  assert_size(33, ==, a[0].len);
  assert_ptr_equal(nulldata, a[0].base);
  assert_size(10, ==, a[1].len);
  assert_ptr_equal(nulldata + 256, a[1].base);
  assert_size(1, ==, bcnt);
  assert_size(1, ==, b[0].len);
  assert_ptr_equal(nulldata + 256 + 10, b[0].base);

  /* Merge ends at the ngtcp2_vec boundary */
  acnt = 1;
  a[0].len = 33;
  a[0].base = nulldata;

  bcnt = 2;
  b[0].len = 11;
  b[0].base = nulldata + 256;
  b[1].len = 19;
  b[1].base = nulldata + 256 + 11;

  nmerged = ngtcp2_vec_merge(a, &acnt, b, &bcnt, 11, 16);

  assert_size(11, ==, nmerged);
  assert_size(2, ==, acnt);
  assert_size(33, ==, a[0].len);
  assert_ptr_equal(nulldata, a[0].base);
  assert_size(11, ==, a[1].len);
  assert_ptr_equal(nulldata + 256, a[1].base);
  assert_size(1, ==, bcnt);
  assert_size(19, ==, b[0].len);
  assert_ptr_equal(nulldata + 256 + 11, b[0].base);

  /* Merge occurs at the last object */
  acnt = 1;
  a[0].len = 33;
  a[0].base = nulldata;

  bcnt = 2;
  b[0].len = 11;
  b[0].base = nulldata + 33;
  b[1].len = 99;
  b[1].base = nulldata + 33 + 11;

  nmerged = ngtcp2_vec_merge(a, &acnt, b, &bcnt, 100, 1);

  assert_size(100, ==, nmerged);
  assert_size(1, ==, acnt);
  assert_size(133, ==, a[0].len);
  assert_ptr_equal(nulldata, a[0].base);
  assert_size(1, ==, bcnt);
  assert_size(10, ==, b[0].len);
  assert_ptr_equal(nulldata + 33 + 11 + 89, b[0].base);

  /* No merge occurs if object is full */
  acnt = 1;
  a[0].len = 33;
  a[0].base = nulldata;

  bcnt = 1;
  b[0].len = 3;
  b[0].base = nulldata + 100;

  nmerged = ngtcp2_vec_merge(a, &acnt, b, &bcnt, 3, 1);

  assert_size(0, ==, nmerged);

  /* both source and destination have 0 elements */
  acnt = 0;
  bcnt = 0;

  nmerged = ngtcp2_vec_merge(a, &acnt, b, &bcnt, 1, 16);

  assert_size(0, ==, nmerged);

  /* Empty destination; b[0] cannot be fully merged */
  acnt = 0;
  bcnt = 1;

  b[0].len = 100;
  b[0].base = nulldata;

  nmerged = ngtcp2_vec_merge(a, &acnt, b, &bcnt, 99, 1);

  assert_size(99, ==, nmerged);
  assert_ptr_equal(nulldata, a[0].base);
  assert_size(99, ==, a[0].len);
  assert_ptr_equal(nulldata + 99, b[0].base);
  assert_size(1, ==, b[0].len);

  /* Empty destination; b[0] can be fully merged */
  acnt = 0;
  bcnt = 2;

  b[0].len = 100;
  b[0].base = nulldata;
  b[1].len = 55;
  b[1].base = nulldata;

  nmerged = ngtcp2_vec_merge(a, &acnt, b, &bcnt, 103, 2);

  assert_size(103, ==, nmerged);
  assert_size(2, ==, acnt);
  assert_ptr_equal(nulldata, a[0].base);
  assert_size(100, ==, a[0].len);
  assert_ptr_equal(nulldata, a[1].base);
  assert_size(3, ==, a[1].len);
  assert_size(1, ==, bcnt);
  assert_ptr_equal(nulldata + 3, b[0].base);
  assert_size(52, ==, b[0].len);

  /* Empty destination; b[0] can be fully merged, and b[0] and b[1]
     are contiguous. */
  acnt = 0;
  bcnt = 2;

  b[0].len = 100;
  b[0].base = nulldata;
  b[1].len = 55;
  b[1].base = nulldata + 100;

  nmerged = ngtcp2_vec_merge(a, &acnt, b, &bcnt, 103, 2);

  assert_size(103, ==, nmerged);
  assert_size(1, ==, acnt);
  assert_ptr_equal(nulldata, a[0].base);
  assert_size(103, ==, a[0].len);
  assert_size(1, ==, bcnt);
  assert_ptr_equal(nulldata + 103, b[0].base);
  assert_size(52, ==, b[0].len);

  /* Empty destination; b[0] can be fully merged, and hit maxcnt */
  acnt = 0;
  bcnt = 2;

  b[0].len = 100;
  b[0].base = nulldata;
  b[1].len = 55;
  b[1].base = nulldata;

  nmerged = ngtcp2_vec_merge(a, &acnt, b, &bcnt, 103, 1);

  assert_size(100, ==, nmerged);
  assert_size(1, ==, acnt);
  assert_ptr_equal(nulldata, a[0].base);
  assert_size(100, ==, a[0].len);
  assert_size(1, ==, bcnt);
  assert_ptr_equal(nulldata, b[0].base);
  assert_size(55, ==, b[0].len);
}

void test_ngtcp2_vec_len_varint(void) {
  assert_int64(0, ==, ngtcp2_vec_len_varint(NULL, 0));

#if SIZE_MAX == UINT64_MAX
  {
    ngtcp2_vec v[] = {
      {
        .len = NGTCP2_MAX_VARINT,
      },
      {
        .len = 1,
      },
    };

    assert_int64(-1, ==, ngtcp2_vec_len_varint(v, ngtcp2_arraylen(v)));
  }

  {
    ngtcp2_vec v[] = {
      {
        .len = NGTCP2_MAX_VARINT - 1,
      },
      {
        .len = 1,
      },
    };

    assert_int64(NGTCP2_MAX_VARINT, ==,
                 ngtcp2_vec_len_varint(v, ngtcp2_arraylen(v)));
  }
#endif /* SIZE_MAX == UINT64_MAX */
}

void test_ngtcp2_vec_copy_at_most(void) {
  uint8_t nulldata[1024] = {0};
  size_t n;

  /* Skip 0 length vector */
  {
    ngtcp2_vec dst[4];
    const ngtcp2_vec src[] = {
      {
        .base = nulldata,
        .len = 1,
      },
      {
        .base = nulldata + 1,
        .len = 0,
      },
      {
        .base = nulldata + 1,
        .len = 77,
      },
      {
        .base = nulldata + 1 + 77,
        .len = 999,
      },
    };

    n = ngtcp2_vec_copy_at_most(dst, ngtcp2_arraylen(dst), src,
                                ngtcp2_arraylen(src), 1 + 77 + 999);

    assert_size(3, ==, n);
    assert_ptr_equal(src[0].base, dst[0].base);
    assert_size(src[0].len, ==, dst[0].len);
    assert_ptr_equal(src[2].base, dst[1].base);
    assert_size(src[2].len, ==, dst[1].len);
    assert_ptr_equal(src[3].base, dst[2].base);
    assert_size(src[3].len, ==, dst[2].len);
  }

  /* Cut last byte */
  {
    ngtcp2_vec dst[2];
    const ngtcp2_vec src[] = {
      {
        .base = nulldata,
        .len = 7,
      },
      {
        .base = nulldata + 7,
        .len = 100,
      },
    };

    n = ngtcp2_vec_copy_at_most(dst, ngtcp2_arraylen(dst), src,
                                ngtcp2_arraylen(src), 106);

    assert_size(2, ==, n);
    assert_ptr_equal(src[0].base, dst[0].base);
    assert_size(src[0].len, ==, dst[0].len);
    assert_ptr_equal(src[1].base, dst[1].base);
    assert_size(99, ==, dst[1].len);
  }

  /* 0 length vectors */
  {
    ngtcp2_vec dst[1];
    const ngtcp2_vec src[1];

    n = ngtcp2_vec_copy_at_most(dst, 0, src, 0, 100);

    assert_size(0, ==, n);
  }

  /* left == 0 */
  {
    ngtcp2_vec dst[1];
    const ngtcp2_vec src[] = {
      {
        .base = nulldata,
        .len = 999,
      },
    };

    n = ngtcp2_vec_copy_at_most(dst, ngtcp2_arraylen(dst), src,
                                ngtcp2_arraylen(src), 0);

    assert_size(0, ==, n);
  }
}
