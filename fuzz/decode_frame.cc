#ifdef __cplusplus
extern "C" {
#endif // defined(__cplusplus)

#include "ngtcp2_conn.h"

#ifdef __cplusplus
}
#endif // defined(__cplusplus)

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  ngtcp2_frame_decoder frd;

  for (; size;) {
    ngtcp2_frame fr;

    auto nread = ngtcp2_frame_decoder_decode(&frd, &fr, data, size);
    if (nread < 0) {
      return 0;
    }

    data += nread;
    size -= nread;
  }

  return 0;
}
