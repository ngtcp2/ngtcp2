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
#include "ngtcp2_conn.h"
#include "ngtcp2_upe.h"
#include "ngtcp2_pkt.h"

static int ngtcp2_conn_new(ngtcp2_conn **pconn, uint64_t conn_id,
                           uint32_t version,
                           const ngtcp2_conn_callbacks *callbacks,
                           void *user_data) {
  int rv;
  ngtcp2_mem *mem = ngtcp2_mem_default();

  *pconn = ngtcp2_mem_calloc(mem, 1, sizeof(ngtcp2_conn));
  if (*pconn == NULL) {
    rv = NGTCP2_ERR_NOMEM;
    goto fail_conn;
  }

  (*pconn)->callbacks = *callbacks;
  (*pconn)->conn_id = conn_id;
  (*pconn)->version = version;
  (*pconn)->mem = mem;
  (*pconn)->user_data = user_data;

  return 0;

fail_conn:
  return rv;
}

int ngtcp2_conn_client_new(ngtcp2_conn **pconn, uint64_t conn_id,
                           uint32_t version,
                           const ngtcp2_conn_callbacks *callbacks,
                           void *user_data) {
  int rv;

  rv = ngtcp2_conn_new(pconn, conn_id, version, callbacks, user_data);
  if (rv != 0) {
    return rv;
  }

  (*pconn)->state = NGTCP2_CS_CLIENT_INITIAL;

  return 0;
}

int ngtcp2_conn_server_new(ngtcp2_conn **pconn, uint64_t conn_id,
                           uint32_t version,
                           const ngtcp2_conn_callbacks *callbacks,
                           void *user_data) {
  int rv;

  rv = ngtcp2_conn_new(pconn, conn_id, version, callbacks, user_data);
  if (rv != 0) {
    return rv;
  }

  (*pconn)->state = NGTCP2_CS_SERVER_INITIAL;
  (*pconn)->server = 1;

  return 0;
}

void ngtcp2_conn_del(ngtcp2_conn *conn) {
  if (conn == NULL) {
    return;
  }

  ngtcp2_mem_free(conn->mem, conn);
}

int ngtcp2_conn_recv(ngtcp2_conn *conn, const uint8_t *pkt, size_t pktlen) {
  (void)conn;
  (void)pkt;
  (void)pktlen;
  return -1;
}

static ssize_t ngtcp2_conn_send_client_initial(ngtcp2_conn *conn, uint8_t *dest,
                                               size_t destlen) {
  int rv;
  uint64_t pkt_num = 0;
  const uint8_t *payload;
  size_t payloadlen;
  ngtcp2_upe upe;
  ngtcp2_pkt_hd hd;
  ngtcp2_frame fm;

  if (destlen < 1280) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  rv = conn->callbacks.client_initial_callback(conn, NGTCP2_CONN_FLAG_NONE,
                                               &pkt_num, &payload, &payloadlen,
                                               conn->user_data);

  if (rv != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  conn->next_out_pkt_num = pkt_num + 1;

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_LONG_FORM, NGTCP2_PKT_CLIENT_INITIAL,
                     conn->conn_id, pkt_num, conn->version);

  ngtcp2_upe_init(&upe, dest, destlen);

  rv = ngtcp2_upe_encode_hd(&upe, &hd);
  if (rv != 0) {
    return rv;
  }

  /* TODO Make a function to create STREAM frame */
  fm.type = NGTCP2_FRAME_STREAM;
  fm.stream.flags = 0;
  fm.stream.fin = 0;
  fm.stream.stream_id = 0;
  fm.stream.offset = 0;
  fm.stream.datalen = payloadlen;
  fm.stream.data = payload;

  rv = ngtcp2_upe_encode_frame(&upe, &fm);
  if (rv != 0) {
    return rv;
  }

  ngtcp2_upe_padding(&upe);

  return (ssize_t)ngtcp2_upe_final(&upe, NULL);
}

ssize_t ngtcp2_conn_send(ngtcp2_conn *conn, uint8_t *dest, size_t destlen) {
  switch (conn->state) {
  case NGTCP2_CS_CLIENT_INITIAL:
    return ngtcp2_conn_send_client_initial(conn, dest, destlen);
  }

  return -1;
}
