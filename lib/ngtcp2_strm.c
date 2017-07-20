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

int ngtcp2_strm_init(ngtcp2_strm *strm, uint32_t stream_id,
                     void *stream_user_data, ngtcp2_mem *mem) {
  int rv;

  strm->tx_offset = 0;
  strm->nbuffered = 0;
  strm->stream_id = stream_id;
  strm->stream_user_data = stream_user_data;
  strm->me.key = stream_id;
  strm->me.next = NULL;
  strm->mem = mem;
  memset(&strm->tx_buf, 0, sizeof(strm->tx_buf));

  rv = ngtcp2_rob_init(&strm->rob, 8 * 1024, mem);
  if (rv != 0) {
    goto fail_rob_init;
  }

fail_rob_init:
  return rv;
}

void ngtcp2_strm_free(ngtcp2_strm *strm) {
  if (strm == NULL) {
    return;
  }

  ngtcp2_rob_free(&strm->rob);
}

uint64_t ngtcp2_strm_rx_offset(ngtcp2_strm *strm) {
  return ngtcp2_rob_first_gap_offset(&strm->rob);
}

int ngtcp2_strm_recv_reordering(ngtcp2_strm *strm, const ngtcp2_stream *fr) {
  return ngtcp2_rob_push(&strm->rob, fr->offset, fr->data, fr->datalen);
}
