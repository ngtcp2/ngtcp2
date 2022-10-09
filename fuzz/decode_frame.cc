#ifdef __cplusplus
extern "C" {
#endif

#include "ngtcp2_conn.h"

#ifdef __cplusplus
}
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  for (; size;) {
    ngtcp2_max_frame mfr{};

    auto nread = ngtcp2_pkt_decode_frame(&mfr.fr, data, size);
    if (nread < 0) {
      return 0;
    }

    data += nread;
    size -= nread;
  }

  return 0;
}
