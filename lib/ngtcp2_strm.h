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
#ifndef NGTCP2_STRM_H
#define NGTCP2_STRM_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <ngtcp2/ngtcp2.h>

#include "ngtcp2_rob.h"
#include "ngtcp2_buf.h"
#include "ngtcp2_map.h"
#include "ngtcp2_gaptr.h"

typedef enum {
  NGTCP2_STRM_FLAG_NONE = 0,
  /* NGTCP2_STRM_FLAG_SHUT_RD indicates that further reception of
     stream data is not allowed. */
  NGTCP2_STRM_FLAG_SHUT_RD = 0x01,
  /* NGTCP2_STRM_FLAG_SHUT_WR indicates that further transmission of
     stream data is not allowed. */
  NGTCP2_STRM_FLAG_SHUT_WR = 0x02,
  NGTCP2_STRM_FLAG_SHUT_RDWR =
      NGTCP2_STRM_FLAG_SHUT_RD | NGTCP2_STRM_FLAG_SHUT_WR,
  /* NGTCP2_STRM_FLAG_SENT_RST indicates that RST_STREAM is sent from
     the local endpoint.  In this case, NGTCP2_STRM_FLAG_SHUT_WR is
     also set. */
  NGTCP2_STRM_FLAG_SENT_RST = 0x04,
  /* NGTCP2_STRM_FLAG_SENT_RST indicates that RST_STREAM is received
     from the remote endpoint.  In this case, NGTCP2_STRM_FLAG_SHUT_RD
     is also set. */
  NGTCP2_STRM_FLAG_RECV_RST = 0x08,
  /* NGTCP2_STRM_FLAG_STOP_SENDING indicates that STOP_SENDING is sent
     from the local endpoint. */
  NGTCP2_STRM_FLAG_STOP_SENDING = 0x10,
} ngtcp2_strm_flags;

struct ngtcp2_strm;

typedef struct ngtcp2_strm ngtcp2_strm;

struct ngtcp2_strm {
  ngtcp2_map_entry me;
  uint64_t tx_offset;
  ngtcp2_gaptr acked_tx_offset;
  /* max_tx_offset is the maximum offset that local endpoint can send
     for this stream. */
  uint64_t max_tx_offset;
  /* last_rx_offset is the largest offset of stream data received for
     this stream. */
  uint64_t last_rx_offset;
  ngtcp2_rob rob;
  /* max_rx_offset is the maximum offset that remote endpoint can send
     to this stream. */
  uint64_t max_rx_offset;
  /* unsent_max_rx_offset is the maximum offset that remote endpoint
     can send to this stream, and it is not notified to the remote
     endpoint.  unsent_max_rx_offset >= max_rx_offset must be hold. */
  uint64_t unsent_max_rx_offset;
  ngtcp2_mem *mem;
  size_t nbuffered;
  ngtcp2_buf tx_buf;
  uint64_t stream_id;
  void *stream_user_data;
  /* flags is bit-wise OR of zero or more of ngtcp2_strm_flags. */
  uint32_t flags;
  ngtcp2_strm **fc_pprev, *fc_next;
  /* app_error_code is an error code the local endpoint sent in
     RST_STREAM or STOP_SENDING. */
  uint16_t app_error_code;
};

/*
 * ngtcp2_strm_init initializes |strm|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory
 */
int ngtcp2_strm_init(ngtcp2_strm *strm, uint64_t stream_id, uint32_t flags,
                     uint64_t max_rx_offset, uint64_t max_tx_offset,
                     void *stream_user_data, ngtcp2_mem *mem);

/*
 * ngtcp2_strm_free deallocates memory allocated for |strm|.  This
 * function does not free the memory pointed by |strm| itself.
 */
void ngtcp2_strm_free(ngtcp2_strm *strm);

/*
 * ngtcp2_strm_rx_offset returns the minimum offset of stream data
 * which is not received yet.
 */
uint64_t ngtcp2_strm_rx_offset(ngtcp2_strm *strm);

/*
 * ngtcp2_strm_recv_reordering handles reordered STREAM frame |fr|.
 *
 * It returns 0 if it succeeds, or one of the following negative error
 * codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory
 */
int ngtcp2_strm_recv_reordering(ngtcp2_strm *strm, const ngtcp2_stream *fr);

/*
 * ngtcp2_strm_shutdown shutdowns |strm|.  |flags| should be
 * NGTCP2_STRM_FLAG_SHUT_RD, and/or NGTCP2_STRM_FLAG_SHUT_WR.
 */
void ngtcp2_strm_shutdown(ngtcp2_strm *strm, uint32_t flags);

#endif /* NGTCP2_STRM_H */
