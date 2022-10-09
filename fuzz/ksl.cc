#include <byteswap.h>

#include <cstring>
#include <memory>

#ifdef __cplusplus
extern "C" {
#endif

#include "ngtcp2_ksl.h"

#ifdef __cplusplus
}
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  using KeyType = uint16_t;
  using DataType = int64_t;
  constexpr size_t keylen = sizeof(KeyType);

  auto compar = [](auto *lhs, auto *rhs) -> int {
    return *static_cast<const KeyType *>(lhs) <
           *static_cast<const KeyType *>(rhs);
  };

  ngtcp2_ksl ksl;

  ngtcp2_ksl_init(&ksl, compar, keylen, ngtcp2_mem_default());

  for (; size >= keylen; ++data, --size) {
    KeyType d;

    memcpy(&d, data, keylen);

    for (size_t i = 0; i < 2; ++i) {
      auto add = (d & 0x8000) != 0;
      auto key = static_cast<KeyType>(d & 0x7fff);

      if (add) {
        auto data = std::make_unique<DataType>(key);
        auto rv = ngtcp2_ksl_insert(&ksl, nullptr, &key, data.get());
        if (rv != 0) {
          continue;
        }

        data.release();
        ngtcp2_ksl_lower_bound(&ksl, &key);

        continue;
      }

      auto it = ngtcp2_ksl_lower_bound(&ksl, &key);
      if (ngtcp2_ksl_it_end(&it)) {
        continue;
      }

      if (*static_cast<KeyType *>(ngtcp2_ksl_it_key(&it)) != key) {
        continue;
      }

      delete static_cast<DataType *>(ngtcp2_ksl_it_get(&it));

      ngtcp2_ksl_remove(&ksl, nullptr, &key);

      d = bswap_16(d);
    }
  }

  for (auto it = ngtcp2_ksl_begin(&ksl); !ngtcp2_ksl_it_end(&it);
       ngtcp2_ksl_it_next(&it)) {
    delete static_cast<DataType *>(ngtcp2_ksl_it_get(&it));
  }

  ngtcp2_ksl_free(&ksl);

  return 0;
}
