/*
 * ngtcp2
 *
 * Copyright (c) 2024 ngtcp2 contributors
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
#include <cassert>

#include <fuzzer/FuzzedDataProvider.h>

#ifdef __cplusplus
extern "C" {
#endif // defined(__cplusplus)

#include "ngtcp2_rob.h"

#ifdef __cplusplus
}
#endif // defined(__cplusplus)

namespace {
const uint8_t null_data[4096]{};
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data_provider(data, size);

  ngtcp2_rob rob;

  ngtcp2_rob_init(&rob, 8 << 10, ngtcp2_mem_default());

  uint64_t data_offset = 0;

  for (; fuzzed_data_provider.remaining_bytes();) {
    auto offset = fuzzed_data_provider.ConsumeIntegralInRange<uint64_t>(
      0, NGTCP2_MAX_VARINT);
    auto len =
      fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, sizeof(null_data));

    auto rv = ngtcp2_rob_push(&rob, offset, null_data, len);
    if (rv != 0) {
      break;
    }

    for (;;) {
      const uint8_t *data;

      auto datalen = ngtcp2_rob_data_at(&rob, &data, data_offset);
      if (datalen == 0) {
        break;
      }

      ngtcp2_rob_pop(&rob, data_offset, datalen);

      data_offset += datalen;
    }

    assert(data_offset == ngtcp2_rob_first_gap_offset(&rob));
  }

  ngtcp2_rob_free(&rob);

  return 0;
}
