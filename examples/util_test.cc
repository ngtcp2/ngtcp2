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
#include "util_test.h"

#include <CUnit/CUnit.h>

#include "util.h"

namespace ngtcp2 {

void test_util_format_duration() {
  CU_ASSERT("0ns" == util::format_duration(0));
  CU_ASSERT("999ns" == util::format_duration(999));
  CU_ASSERT("1.00us" == util::format_duration(1000));
  CU_ASSERT("1.00us" == util::format_duration(1004));
  CU_ASSERT("1.00us" == util::format_duration(1005));
  CU_ASSERT("1.02us" == util::format_duration(1015));
  CU_ASSERT("2.00us" == util::format_duration(1999));
  CU_ASSERT("1.00ms" == util::format_duration(999999));
  CU_ASSERT("3.50ms" == util::format_duration(3500111));
  CU_ASSERT("9999.99s" == util::format_duration(9999990000000llu));
}

} // namespace ngtcp2
