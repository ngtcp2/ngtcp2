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
#include "ngtcp2_pq.h"

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
  NGTCP2_CS_SERVER_CC_RECVED
} ngtcp2_conn_state;

typedef struct {
  uint64_t offset;
  ngtcp2_pq pq;
  size_t nbuffered;
} ngtcp2_strm;

int ngtcp2_strm_init(ngtcp2_strm *strm, ngtcp2_mem *mem);

void ngtcp2_strm_free(ngtcp2_strm *strm, ngtcp2_mem *mem);

struct ngtcp2_conn {
  int state;
  ngtcp2_conn_callbacks callbacks;
  ngtcp2_strm strm0;
  uint64_t conn_id;
  uint64_t next_out_pkt_num;
  ngtcp2_mem *mem;
  void *user_data;
  uint32_t version;
  int server;
};

int ngtcp2_conn_recv_reordering(ngtcp2_conn *conn, ngtcp2_strm *strm,
                                ngtcp2_stream *fr);

int ngtcp2_conn_emit_pending_recv_handshake(ngtcp2_conn *conn,
                                            ngtcp2_strm *strm);

#endif /* NGTCP2_CONN_H */
