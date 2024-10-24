#include <byteswap.h>

#include <cstring>
#include <memory>

#ifdef __cplusplus
extern "C" {
#endif // defined(__cplusplus)

#include "ngtcp2_ksl.h"

#ifdef __cplusplus
}
#endif // defined(__cplusplus)

using KeyType = uint64_t;
using DataType = int64_t;

namespace {
int less(const ngtcp2_ksl_key *lhs, const ngtcp2_ksl_key *rhs) {
  return *static_cast<const KeyType *>(lhs) <
         *static_cast<const KeyType *>(rhs);
}
} // namespace

ngtcp2_ksl_search_def(less, less)

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  constexpr size_t keylen = sizeof(KeyType);

  ngtcp2_ksl ksl;

  ngtcp2_ksl_init(&ksl, less, ksl_less_search, keylen, ngtcp2_mem_default());

  for (; size >= keylen; ++data, --size) {
    KeyType d;

    memcpy(&d, data, keylen);

    for (size_t i = 0; i < 2; ++i, d = bswap_64(d)) {
      auto add = (d & 0x8000000000000000llu) != 0;
      auto rm = (d & 0x4000000000000000llu) != 0;
      auto key = static_cast<KeyType>(d & 0x7fffffffffffffffllu);

      if (add) {
        auto data = std::make_unique<DataType>(key);
        auto rv = ngtcp2_ksl_insert(&ksl, nullptr, &key, data.get());
        if (rv == 0) {
          data.release();
        }
      }

      auto it = ngtcp2_ksl_lower_bound(&ksl, &key);
      if (ngtcp2_ksl_it_end(&it)) {
        continue;
      }

      if (!rm) {
        continue;
      }

      delete static_cast<DataType *>(ngtcp2_ksl_it_get(&it));

      if (*static_cast<KeyType *>(ngtcp2_ksl_it_key(&it)) == key) {
        ngtcp2_ksl_remove(&ksl, nullptr, &key);
      } else {
        ngtcp2_ksl_remove_hint(&ksl, nullptr, &it, &key);
      }
    }
  }

  for (auto it = ngtcp2_ksl_begin(&ksl); !ngtcp2_ksl_it_end(&it);
       ngtcp2_ksl_it_next(&it)) {
    delete static_cast<DataType *>(ngtcp2_ksl_it_get(&it));
  }

  ngtcp2_ksl_free(&ksl);

  return 0;
}
