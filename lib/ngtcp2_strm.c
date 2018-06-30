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
#include "ngtcp2_strm.h"

#include <string.h>

int ngtcp2_strm_init(ngtcp2_strm *strm, uint64_t stream_id, uint32_t flags,
                     uint64_t max_rx_offset, uint64_t max_tx_offset,
                     void *stream_user_data, ngtcp2_mem *mem) {
  int rv;

  strm->tx_offset = 0;
  strm->last_rx_offset = 0;
  strm->nbuffered = 0;
  strm->stream_id = stream_id;
  strm->flags = flags;
  strm->stream_user_data = stream_user_data;
  strm->max_rx_offset = strm->unsent_max_rx_offset = max_rx_offset;
  strm->max_tx_offset = max_tx_offset;
  strm->me.key = stream_id;
  strm->me.next = NULL;
  strm->mem = mem;
  strm->fc_pprev = NULL;
  strm->fc_next = NULL;
  /* Initializing to 0 is a bit controversial because application
     error code 0 is STOPPING.  But STOPPING is only sent with
     RST_STREAM in response to STOP_SENDING, and it is not used to
     indicate the cause of closure.  So effectively, 0 means "no
     error." */
  strm->app_error_code = 0;
  memset(&strm->tx_buf, 0, sizeof(strm->tx_buf));

  rv = ngtcp2_gaptr_init(&strm->acked_tx_offset, mem);
  if (rv != 0) {
    goto fail_gaptr_init;
  }

  rv = ngtcp2_rob_init(&strm->rob, 8 * 1024, mem);
  if (rv != 0) {
    goto fail_rob_init;
  }

  return 0;

fail_rob_init:
  ngtcp2_gaptr_free(&strm->acked_tx_offset);
fail_gaptr_init:
  return rv;
}

void ngtcp2_strm_free(ngtcp2_strm *strm) {
  if (strm == NULL) {
    return;
  }

  ngtcp2_rob_free(&strm->rob);
  ngtcp2_gaptr_free(&strm->acked_tx_offset);
}

uint64_t ngtcp2_strm_rx_offset(ngtcp2_strm *strm) {
  return ngtcp2_rob_first_gap_offset(&strm->rob);
}

int ngtcp2_strm_recv_reordering(ngtcp2_strm *strm, const uint8_t *data,
                                size_t datalen, uint64_t offset) {
  return ngtcp2_rob_push(&strm->rob, offset, data, datalen);
}

void ngtcp2_strm_shutdown(ngtcp2_strm *strm, uint32_t flags) {
  strm->flags |= flags & NGTCP2_STRM_FLAG_SHUT_RDWR;
}
