#include <byteswap.h>

#include <cstring>
#include <memory>

#include <fuzzer/FuzzedDataProvider.h>

#ifdef __cplusplus
extern "C" {
#endif // defined(__cplusplus)

#include "ngtcp2_ksl.h"

#ifdef __cplusplus
}
#endif // defined(__cplusplus)

using KeyType = uint64_t;
using DataType = uint64_t;

namespace {
int less(const ngtcp2_ksl_key *lhs, const ngtcp2_ksl_key *rhs) {
  return *static_cast<const KeyType *>(lhs) <
         *static_cast<const KeyType *>(rhs);
}
} // namespace

ngtcp2_ksl_search_def(less, less)

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  constexpr size_t keylen = sizeof(KeyType);
  FuzzedDataProvider fuzzed_data_provider(data, size);

  ngtcp2_ksl ksl;

  ngtcp2_ksl_init(&ksl, less, ksl_less_search, keylen, ngtcp2_mem_default());

  for (; fuzzed_data_provider.remaining_bytes();) {
    auto add = fuzzed_data_provider.ConsumeBool();
    auto key = fuzzed_data_provider.ConsumeIntegral<uint64_t>();

    if (add) {
      auto data = std::make_unique<DataType>(key);
      auto rv = ngtcp2_ksl_insert(&ksl, nullptr, &key, data.get());
      if (rv == 0) {
        data.release();
      }
    } else {
      auto it = ngtcp2_ksl_lower_bound(&ksl, &key);

      if (!ngtcp2_ksl_it_end(&it)) {
        auto data = static_cast<DataType *>(ngtcp2_ksl_it_get(&it));
        int rv;

        if (*static_cast<const KeyType *>(ngtcp2_ksl_it_key(&it)) == key) {
          rv = ngtcp2_ksl_remove_hint(&ksl, nullptr, &it, &key);
        } else {
          rv = ngtcp2_ksl_remove(&ksl, nullptr, &key);
        }

        if (rv == 0) {
          delete data;
        }
      }
    }

    for (auto it = ngtcp2_ksl_begin(&ksl); !ngtcp2_ksl_it_end(&it);
         ngtcp2_ksl_it_next(&it))
      ;

    for (auto it = ngtcp2_ksl_end(&ksl); !ngtcp2_ksl_it_begin(&it);
         ngtcp2_ksl_it_prev(&it))
      ;
  }

  for (auto it = ngtcp2_ksl_begin(&ksl); !ngtcp2_ksl_it_end(&it);
       ngtcp2_ksl_it_next(&it)) {
    delete static_cast<DataType *>(ngtcp2_ksl_it_get(&it));
  }

  ngtcp2_ksl_free(&ksl);

  return 0;
}
