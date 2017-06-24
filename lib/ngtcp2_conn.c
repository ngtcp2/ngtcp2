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
#include "ngtcp2_macro.h"

static int conn_call_recv_pkt(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd) {
  int rv;

  if (!conn->callbacks.recv_pkt) {
    return 0;
  }

  rv = conn->callbacks.recv_pkt(conn, hd, conn->user_data);
  if (rv != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int conn_call_recv_frame(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                                const ngtcp2_frame *fr) {
  int rv;

  if (!conn->callbacks.recv_frame) {
    return 0;
  }

  rv = conn->callbacks.recv_frame(conn, hd, fr, conn->user_data);
  if (rv != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int conn_call_send_pkt(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd) {
  int rv;

  if (!conn->callbacks.send_pkt) {
    return 0;
  }

  rv = conn->callbacks.send_pkt(conn, hd, conn->user_data);
  if (rv != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int conn_call_send_frame(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                                const ngtcp2_frame *fr) {
  int rv;

  if (!conn->callbacks.send_frame) {
    return 0;
  }

  rv = conn->callbacks.send_frame(conn, hd, fr, conn->user_data);
  if (rv != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

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

  rv = ngtcp2_strm_init(&(*pconn)->strm0, mem);
  if (rv != 0) {
    goto fail_strm_init;
  }

  (*pconn)->callbacks = *callbacks;
  (*pconn)->conn_id = conn_id;
  (*pconn)->version = version;
  (*pconn)->mem = mem;
  (*pconn)->user_data = user_data;

  return 0;

fail_strm_init:
  ngtcp2_mem_free(mem, *pconn);
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

  ngtcp2_strm_free(&conn->strm0);
  ngtcp2_mem_free(conn->mem, conn);
}

static ssize_t conn_encode_handshake_pkt(ngtcp2_conn *conn, uint8_t *dest,
                                         size_t destlen, uint8_t type,
                                         const uint8_t *data, size_t datalen) {
  int rv;
  ngtcp2_upe upe;
  ngtcp2_pkt_hd hd;
  ngtcp2_frame fr;

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_LONG_FORM, type, conn->conn_id,
                     conn->next_tx_pkt_num, conn->version);

  ngtcp2_upe_init(&upe, dest, destlen);

  rv = ngtcp2_upe_encode_hd(&upe, &hd);
  if (rv != 0) {
    return rv;
  }

  rv = conn_call_send_pkt(conn, &hd);
  if (rv != 0) {
    return rv;
  }

  /* TODO Make a function to create STREAM frame */
  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.fin = 0;
  fr.stream.stream_id = 0;
  fr.stream.offset = conn->strm0.tx_offset;
  fr.stream.datalen = datalen;
  fr.stream.data = data;

  rv = ngtcp2_upe_encode_frame(&upe, &fr);
  if (rv != 0) {
    return rv;
  }

  rv = conn_call_send_frame(conn, &hd, &fr);
  if (rv != 0) {
    return rv;
  }

  ++conn->next_tx_pkt_num;
  conn->strm0.tx_offset += datalen;

  if (type == NGTCP2_PKT_CLIENT_INITIAL) {
    ngtcp2_upe_padding(&upe);
  }

  return (ssize_t)ngtcp2_upe_final(&upe, NULL);
}

static ssize_t ngtcp2_conn_send_client_initial(ngtcp2_conn *conn, uint8_t *dest,
                                               size_t destlen) {
  uint64_t pkt_num = 0;
  const uint8_t *payload;
  ssize_t payloadlen;
  size_t maxpayloadlen;

  if (destlen < 1280) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  maxpayloadlen = destlen - NGTCP2_LONG_HEADERLEN - NGTCP2_STREAM_OVERHEAD -
                  NGTCP2_PKT_MDLEN;

  payloadlen = conn->callbacks.send_client_initial(
      conn, NGTCP2_CONN_FLAG_NONE, &pkt_num, &payload, maxpayloadlen,
      conn->user_data);
  if (payloadlen <= 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  conn->next_tx_pkt_num = pkt_num;

  return conn_encode_handshake_pkt(conn, dest, destlen,
                                   NGTCP2_PKT_CLIENT_INITIAL, payload,
                                   (size_t)payloadlen);
}

static ssize_t ngtcp2_conn_send_client_cleartext(ngtcp2_conn *conn,
                                                 uint8_t *dest,
                                                 size_t destlen) {
  const uint8_t *payload;
  ssize_t payloadlen;
  size_t maxpayloadlen;

  if (destlen <
      NGTCP2_LONG_HEADERLEN + NGTCP2_STREAM_OVERHEAD + NGTCP2_PKT_MDLEN) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  maxpayloadlen = destlen - NGTCP2_LONG_HEADERLEN - NGTCP2_STREAM_OVERHEAD -
                  NGTCP2_PKT_MDLEN;

  payloadlen = conn->callbacks.send_client_cleartext(
      conn, NGTCP2_CONN_FLAG_NONE, &payload, maxpayloadlen, conn->user_data);
  if (payloadlen < 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  if (payloadlen == 0) {
    return 0;
  }

  return conn_encode_handshake_pkt(conn, dest, destlen,
                                   NGTCP2_PKT_CLIENT_CLEARTEXT, payload,
                                   (size_t)payloadlen);
}

static ssize_t ngtcp2_conn_send_server_cleartext(ngtcp2_conn *conn,
                                                 uint8_t *dest, size_t destlen,
                                                 int initial) {
  uint64_t pkt_num = 0;
  const uint8_t *payload;
  ssize_t payloadlen;
  size_t maxpayloadlen;

  if (destlen <
      NGTCP2_LONG_HEADERLEN + NGTCP2_STREAM_OVERHEAD + NGTCP2_PKT_MDLEN) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  maxpayloadlen = destlen - NGTCP2_LONG_HEADERLEN - NGTCP2_STREAM_OVERHEAD -
                  NGTCP2_PKT_MDLEN;

  payloadlen = conn->callbacks.send_server_cleartext(
      conn, NGTCP2_CONN_FLAG_NONE, initial ? &pkt_num : NULL, &payload,
      maxpayloadlen, conn->user_data);

  if (payloadlen == 0) {
    if (initial) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
  }

  if (payloadlen < 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  if (initial) {
    conn->next_tx_pkt_num = pkt_num;
  }

  return conn_encode_handshake_pkt(conn, dest, destlen,
                                   NGTCP2_PKT_SERVER_CLEARTEXT, payload,
                                   (size_t)payloadlen);
}

ssize_t ngtcp2_conn_send(ngtcp2_conn *conn, uint8_t *dest, size_t destlen) {
  ssize_t rv = 0;

  switch (conn->state) {
  case NGTCP2_CS_CLIENT_INITIAL:
    rv = ngtcp2_conn_send_client_initial(conn, dest, destlen);
    if (rv < 0) {
      break;
    }
    conn->state = NGTCP2_CS_CLIENT_CI_SENT;
    break;
  case NGTCP2_CS_CLIENT_SC_RECVED:
    rv = ngtcp2_conn_send_client_cleartext(conn, dest, destlen);
    if (rv < 0) {
      break;
    }
    /* TODO Ask crypto backend whether TLS handshake has finished or
       not. */
    break;
  case NGTCP2_CS_SERVER_CI_RECVED:
    rv = ngtcp2_conn_send_server_cleartext(conn, dest, destlen, 1);
    if (rv < 0) {
      break;
    }
    conn->state = NGTCP2_CS_SERVER_SC_SENT;
    break;
  case NGTCP2_CS_SERVER_SC_SENT:
    rv = ngtcp2_conn_send_server_cleartext(conn, dest, destlen, 0);
    if (rv < 0) {
      break;
    }
    break;
  }

  return rv;
}

static int ngtcp2_conn_recv_cleartext(ngtcp2_conn *conn, uint8_t exptype,
                                      const uint8_t *pkt, size_t pktlen,
                                      int server, int initial) {
  ssize_t nread;
  ngtcp2_pkt_hd hd;
  ngtcp2_frame fr;
  int rv;

  if (!(pkt[0] & NGTCP2_HEADER_FORM_BIT)) {
    return NGTCP2_ERR_PROTO;
  }

  nread = ngtcp2_pkt_decode_hd_long(&hd, pkt, pktlen);
  if (nread < 0) {
    return (int)nread;
  }

  pkt += nread;
  pktlen -= (size_t)nread;

  rv = conn_call_recv_pkt(conn, &hd);
  if (rv != 0) {
    return rv;
  }

  if (!initial) {
    if (conn->conn_id != hd.conn_id) {
      return NGTCP2_ERR_PROTO;
    }
  } else if (!server) {
    conn->conn_id = hd.conn_id;
  }

  if (exptype != hd.type) {
    return NGTCP2_ERR_PROTO;
  }

  for (; pktlen;) {
    nread = ngtcp2_pkt_decode_frame(&fr, pkt, pktlen);
    if (nread < 0) {
      return (int)nread;
    }

    pkt += nread;
    pktlen -= (size_t)nread;

    rv = conn_call_recv_frame(conn, &hd, &fr);
    if (rv != 0) {
      return rv;
    }

    if (fr.type != NGTCP2_FRAME_STREAM || fr.stream.stream_id != 0 ||
        conn->strm0.rx_offset >= fr.stream.offset + fr.stream.datalen) {
      continue;
    }

    if (conn->strm0.rx_offset == fr.stream.offset) {
      conn->strm0.rx_offset += fr.stream.datalen;

      rv = conn->callbacks.recv_handshake_data(
          conn, fr.stream.data, fr.stream.datalen, conn->user_data);
      if (rv != 0) {
        return rv;
      }

      rv = ngtcp2_conn_emit_pending_recv_handshake(conn, &conn->strm0);
      if (rv != 0) {
        return rv;
      }
    } else {
      rv = ngtcp2_strm_recv_reordering(&conn->strm0, &fr.stream);
      if (rv != 0) {
        return rv;
      }
    }
  }

  return 0;
}

int ngtcp2_conn_recv(ngtcp2_conn *conn, const uint8_t *pkt, size_t pktlen) {
  int rv;

  if (pktlen == 0) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  if (pkt[0] & NGTCP2_HEADER_FORM_BIT) {
    if (ngtcp2_pkt_verify(pkt, pktlen) != 0) {
      return NGTCP2_ERR_BAD_PKT_HASH;
    }
    pktlen -= NGTCP2_PKT_MDLEN;
  }

  switch (conn->state) {
  case NGTCP2_CS_CLIENT_CI_SENT:
    /* TODO Handle Version Negotiation */
    rv = ngtcp2_conn_recv_cleartext(conn, NGTCP2_PKT_SERVER_CLEARTEXT, pkt,
                                    pktlen, 0, 1);
    if (rv < 0) {
      break;
    }
    conn->state = NGTCP2_CS_CLIENT_SC_RECVED;
    break;
  case NGTCP2_CS_CLIENT_SC_RECVED:
    rv = ngtcp2_conn_recv_cleartext(conn, NGTCP2_PKT_SERVER_CLEARTEXT, pkt,
                                    pktlen, 0, 0);
    if (rv < 0) {
      break;
    }
    break;
  case NGTCP2_CS_SERVER_INITIAL:
    rv = ngtcp2_conn_recv_cleartext(conn, NGTCP2_PKT_CLIENT_INITIAL, pkt,
                                    pktlen, 1, 1);
    if (rv < 0) {
      break;
    }
    conn->state = NGTCP2_CS_SERVER_CI_RECVED;
    break;
  case NGTCP2_CS_SERVER_SC_SENT:
    rv = ngtcp2_conn_recv_cleartext(conn, NGTCP2_PKT_CLIENT_CLEARTEXT, pkt,
                                    pktlen, 1, 0);
    if (rv < 0) {
      break;
    }
    conn->state = NGTCP2_CS_SERVER_CC_RECVED;
    /* TODO Ask crypto backend whether TLS handshake has finished or
       not */
    break;
  }

  return rv;
}

int ngtcp2_conn_emit_pending_recv_handshake(ngtcp2_conn *conn,
                                            ngtcp2_strm *strm) {
  size_t datalen;
  const uint8_t *data;
  int rv;

  for (;;) {
    datalen = ngtcp2_rob_data_at(&strm->rob, &data, strm->rx_offset);
    if (datalen == 0) {
      return 0;
    }

    strm->rx_offset += datalen;

    rv = conn->callbacks.recv_handshake_data(conn, data, datalen,
                                             conn->user_data);
    if (rv != 0) {
      return rv;
    }

    ngtcp2_rob_pop(&strm->rob);
  }
}

int ngtcp2_strm_init(ngtcp2_strm *strm, ngtcp2_mem *mem) {
  strm->tx_offset = 0;
  strm->rx_offset = 0;
  strm->nbuffered = 0;
  strm->mem = mem;
  return ngtcp2_rob_init(&strm->rob, mem);
}

void ngtcp2_strm_free(ngtcp2_strm *strm) {
  if (strm == NULL) {
    return;
  }
  ngtcp2_rob_free(&strm->rob);
}

int ngtcp2_strm_recv_reordering(ngtcp2_strm *strm, ngtcp2_stream *fr) {
  if (strm->rob.bufferedlen >= 128 * 1024) {
    return NGTCP2_ERR_INTERNAL_ERROR;
  }

  return ngtcp2_rob_push(&strm->rob, fr->offset, fr->data, fr->datalen);
}
