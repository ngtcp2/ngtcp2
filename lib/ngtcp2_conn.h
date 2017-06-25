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
#ifndef NGTCP2_CONN_H
#define NGTCP2_CONN_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <ngtcp2/ngtcp2.h>

#include "ngtcp2_mem.h"
#include "ngtcp2_buf.h"
#include "ngtcp2_rob.h"

typedef enum {
  /* Client specific handshake states */
  NGTCP2_CS_CLIENT_INITIAL,
  NGTCP2_CS_CLIENT_CI_SENT,
  NGTCP2_CS_CLIENT_CI_ACKED,
  NGTCP2_CS_CLIENT_SC_RECVED,
  NGTCP2_CS_CLIENT_CC_SENT,
  NGTCP2_CS_CLIENT_CC_ACKED,
  /* Server specific handshake states */
  NGTCP2_CS_SERVER_INITIAL,
  NGTCP2_CS_SERVER_CI_RECVED,
  NGTCP2_CS_SERVER_SC_SENT,
  NGTCP2_CS_SERVER_SC_ACKED,
  NGTCP2_CS_SERVER_CC_RECVED,
  /* Shared by both client and server */
  NGTCP2_CS_HANDSHAKE_COMPLETED,
} ngtcp2_conn_state;

typedef struct {
  uint64_t rx_offset;
  uint64_t tx_offset;
  ngtcp2_rob rob;
  ngtcp2_mem *mem;
  size_t nbuffered;
  ngtcp2_buf tx_buf;
} ngtcp2_strm;

int ngtcp2_strm_init(ngtcp2_strm *strm, ngtcp2_mem *mem);

void ngtcp2_strm_free(ngtcp2_strm *strm);

/*
 * ngtcp2_strm_recv_reordering handles reordered STREAM frame |fr|.
 *
 * It returns 0 if it succeeds, or one of the following negative error
 * codes:
 *
 * NGTCP2_ERR_INTERNAL_ERROR
 *     There are too many buffered data
 * NGTCP2_ERR_NOMEM
 *     Out of memory
 */
int ngtcp2_strm_recv_reordering(ngtcp2_strm *strm, ngtcp2_stream *fr);

/*
 * ngtcp2_rx_pkt records packet number and its reception timestamp for
 * its transmission of ACK.
 */
typedef struct {
  ngtcp2_pq_entry pq_entry;
  uint64_t pkt_num;
  ngtcp2_tstamp tstamp;
} ngtcp2_rx_pkt;

struct ngtcp2_conn {
  int state;
  ngtcp2_pq ackq;
  ngtcp2_conn_callbacks callbacks;
  ngtcp2_strm strm0;
  uint64_t conn_id;
  uint64_t next_tx_pkt_num;
  uint64_t max_rx_pkt_num;
  ngtcp2_mem *mem;
  void *user_data;
  uint32_t version;
  int handshake_completed;
  int server;
};

/*
 * ngtcp2_conn_emit_pending_recv_handshake delivers pending stream
 * data to the application due to packet reordering.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User callback failed
 */
int ngtcp2_conn_emit_pending_recv_handshake(ngtcp2_conn *conn,
                                            ngtcp2_strm *strm);

/*
 * ngtcp2_conn_sched_ack stores packet number |pkt_num| and its
 * reception timestamp |ts| in order to send its ACK.
 *
 * It returns 0 if it succeeds, or one of the following negative error
 * codes:
 *
 * NGTCP2_ERR_INTERNAL_ERROR
 *     There are too many unacked packets
 * NGTCP2_ERR_NOMEM
 *     Out of memory
 */
int ngtcp2_conn_sched_ack(ngtcp2_conn *conn, uint64_t pkt_num,
                          ngtcp2_tstamp ts);

#endif /* NGTCP2_CONN_H */
