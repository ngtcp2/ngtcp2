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

#include <string.h>

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

static int conn_call_handshake_completed(ngtcp2_conn *conn) {
  int rv;

  if (!conn->callbacks.handshake_completed) {
    return 0;
  }

  rv = conn->callbacks.handshake_completed(conn, conn->user_data);
  if (rv != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int conn_ackq_greater(const void *lhsx, const void *rhsx) {
  const ngtcp2_rx_pkt *lhs, *rhs;

  lhs = ngtcp2_struct_of(lhsx, ngtcp2_rx_pkt, pq_entry);
  rhs = ngtcp2_struct_of(rhsx, ngtcp2_rx_pkt, pq_entry);

  return lhs->pkt_num > rhs->pkt_num;
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

  rv = ngtcp2_pq_init(&(*pconn)->ackq, conn_ackq_greater, mem);
  if (rv != 0) {
    goto fail_pq_init;
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
  ngtcp2_pq_free(&(*pconn)->ackq);
fail_pq_init:
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

static int ackq_rx_pkt_free(ngtcp2_pq_entry *item, void *arg) {
  ngtcp2_rx_pkt *rpkt;
  ngtcp2_conn *conn;

  rpkt = ngtcp2_struct_of(item, ngtcp2_rx_pkt, pq_entry);
  conn = arg;

  ngtcp2_mem_free(conn->mem, rpkt);

  return 0;
}

void ngtcp2_conn_del(ngtcp2_conn *conn) {
  if (conn == NULL) {
    return;
  }

  ngtcp2_strm_free(&conn->strm0);

  ngtcp2_pq_each(&conn->ackq, ackq_rx_pkt_free, conn);
  ngtcp2_pq_free(&conn->ackq);
  ngtcp2_mem_free(conn->mem, conn);
}

static int conn_create_ack_frame(ngtcp2_conn *conn, ngtcp2_ack *ack,
                                 ngtcp2_tstamp ts) {
  uint64_t first_pkt_num;
  ngtcp2_tstamp ack_delay;
  uint64_t last_pkt_num;
  ngtcp2_rx_pkt *rpkt;
  ngtcp2_ack_blk *blk;
  int initial = 1;
  uint64_t gap;

  if (ngtcp2_pq_empty(&conn->ackq)) {
    return 0;
  }

  rpkt = ngtcp2_struct_of(ngtcp2_pq_top(&conn->ackq), ngtcp2_rx_pkt, pq_entry);
  ngtcp2_pq_pop(&conn->ackq);

  first_pkt_num = last_pkt_num = rpkt->pkt_num;
  ack_delay = ts - rpkt->tstamp;

  ngtcp2_mem_free(conn->mem, rpkt);

  ack->type = NGTCP2_FRAME_ACK;
  ack->num_ts = 0;
  ack->num_blks = 0;

  for (; !ngtcp2_pq_empty(&conn->ackq);) {
    rpkt =
        ngtcp2_struct_of(ngtcp2_pq_top(&conn->ackq), ngtcp2_rx_pkt, pq_entry);

    if (rpkt->pkt_num + 1 == last_pkt_num) {
      last_pkt_num = rpkt->pkt_num;
      ngtcp2_pq_pop(&conn->ackq);
      ngtcp2_mem_free(conn->mem, rpkt);
      continue;
    }

    if (initial) {
      initial = 0;
      ack->largest_ack = first_pkt_num;
      ack->ack_delay = (uint16_t)ack_delay;
      ack->first_ack_blklen = first_pkt_num - last_pkt_num;
    } else {
      blk = &ack->blks[ack->num_blks++];
      blk->gap = (uint8_t)gap;
      blk->blklen = first_pkt_num - last_pkt_num;
    }

    gap = last_pkt_num - rpkt->pkt_num;
    if (gap > 255) {
      /* TODO We need to encode next ack in the separate ACK frame or
         use the trick of 0 length ACK Block Length (not sure it is
         OK.  Anyway, this implementation will be rewritten soon, so
         we don't optimize this at the moment. */
      break;
    }

    first_pkt_num = last_pkt_num = rpkt->pkt_num;

    ngtcp2_pq_pop(&conn->ackq);
    ngtcp2_mem_free(conn->mem, rpkt);

    if (ack->num_blks == 255) {
      break;
    }
  }

  if (initial) {
    ack->largest_ack = first_pkt_num;
    ack->ack_delay = (uint16_t)ack_delay;
    ack->first_ack_blklen = first_pkt_num - last_pkt_num;
  }

  return 0;
}

static ssize_t conn_encode_handshake_pkt(ngtcp2_conn *conn, uint8_t *dest,
                                         size_t destlen, uint8_t type,
                                         const ngtcp2_frame *ackfr,
                                         ngtcp2_buf *tx_buf) {
  int rv;
  ngtcp2_upe upe;
  ngtcp2_pkt_hd hd;
  ngtcp2_frame fr;
  size_t nwrite;

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

  /* Encode ACK here */
  if (ackfr) {
    rv = ngtcp2_upe_encode_frame(&upe, ackfr);
    if (rv != 0) {
      return rv;
    }

    rv = conn_call_send_frame(conn, &hd, ackfr);
    if (rv != 0) {
      return rv;
    }
  }

  if (ngtcp2_upe_left(&upe) < NGTCP2_STREAM_OVERHEAD + 1) {
    if (ackfr) {
      ++conn->next_tx_pkt_num;
      return (ssize_t)ngtcp2_upe_final(&upe, NULL);
    }

    return NGTCP2_ERR_NOBUF;
  }

  nwrite = ngtcp2_min(ngtcp2_buf_len(tx_buf),
                      ngtcp2_upe_left(&upe) - NGTCP2_STREAM_OVERHEAD);

  if (nwrite > 0) {
    /* TODO Make a function to create STREAM frame */
    fr.type = NGTCP2_FRAME_STREAM;
    fr.stream.flags = 0;
    fr.stream.fin = 0;
    fr.stream.stream_id = 0;
    fr.stream.offset = conn->strm0.tx_offset;
    fr.stream.datalen = nwrite;
    fr.stream.data = tx_buf->pos;

    rv = ngtcp2_upe_encode_frame(&upe, &fr);
    if (rv != 0) {
      return rv;
    }

    rv = conn_call_send_frame(conn, &hd, &fr);
    if (rv != 0) {
      return rv;
    }

    tx_buf->pos += nwrite;
    conn->strm0.tx_offset += nwrite;
  }

  if (type == NGTCP2_PKT_CLIENT_INITIAL) {
    ngtcp2_upe_padding(&upe);
  }

  ++conn->next_tx_pkt_num;

  return (ssize_t)ngtcp2_upe_final(&upe, NULL);
}

static ssize_t ngtcp2_conn_send_client_initial(ngtcp2_conn *conn, uint8_t *dest,
                                               size_t destlen) {
  uint64_t pkt_num = 0;
  const uint8_t *payload;
  ssize_t payloadlen;
  ngtcp2_buf *tx_buf = &conn->strm0.tx_buf;

  if (destlen < 1280) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  payloadlen = conn->callbacks.send_client_initial(
      conn, NGTCP2_CONN_FLAG_NONE, &pkt_num, &payload, conn->user_data);

  if (payloadlen <= 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  ngtcp2_buf_init(tx_buf, (uint8_t *)payload, (size_t)payloadlen);
  tx_buf->last += payloadlen;

  conn->next_tx_pkt_num = pkt_num;

  return conn_encode_handshake_pkt(conn, dest, destlen,
                                   NGTCP2_PKT_CLIENT_INITIAL, NULL, tx_buf);
}

static ssize_t ngtcp2_conn_send_client_cleartext(ngtcp2_conn *conn,
                                                 uint8_t *dest, size_t destlen,
                                                 ngtcp2_tstamp ts) {
  const uint8_t *payload;
  ssize_t payloadlen;
  ngtcp2_frame ackfr;
  ngtcp2_buf *tx_buf = &conn->strm0.tx_buf;
  int rv;

  ackfr.type = 0;
  rv = conn_create_ack_frame(conn, &ackfr.ack, ts);
  if (rv != 0) {
    return rv;
  }

  if (ngtcp2_buf_len(tx_buf) == 0) {
    payloadlen = conn->callbacks.send_client_cleartext(
        conn, NGTCP2_CONN_FLAG_NONE, &payload, conn->user_data);

    if (payloadlen < 0) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    if (payloadlen == 0 && ackfr.type == 0) {
      return 0;
    }

    ngtcp2_buf_init(tx_buf, (uint8_t *)payload, (size_t)payloadlen);
    tx_buf->last += payloadlen;
  }

  return conn_encode_handshake_pkt(conn, dest, destlen,
                                   NGTCP2_PKT_CLIENT_CLEARTEXT,
                                   ackfr.type == 0 ? NULL : &ackfr, tx_buf);
}

static ssize_t ngtcp2_conn_send_server_cleartext(ngtcp2_conn *conn,
                                                 uint8_t *dest, size_t destlen,
                                                 int initial,
                                                 ngtcp2_tstamp ts) {
  uint64_t pkt_num = 0;
  const uint8_t *payload;
  ssize_t payloadlen;
  ngtcp2_frame ackfr;
  ngtcp2_buf *tx_buf = &conn->strm0.tx_buf;
  int rv;

  ackfr.type = 0;
  rv = conn_create_ack_frame(conn, &ackfr.ack, ts);
  if (rv != 0) {
    return rv;
  }

  if (ngtcp2_buf_len(tx_buf) == 0) {
    payloadlen = conn->callbacks.send_server_cleartext(
        conn, NGTCP2_CONN_FLAG_NONE, initial ? &pkt_num : NULL, &payload,
        conn->user_data);

    if (payloadlen < 0) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    if (payloadlen == 0) {
      if (initial) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
      }
      if (ackfr.type == 0) {
        return 0;
      }
    }

    ngtcp2_buf_init(tx_buf, (uint8_t *)payload, (size_t)payloadlen);
    tx_buf->last += payloadlen;
  }

  if (initial) {
    conn->next_tx_pkt_num = pkt_num;
  }

  return conn_encode_handshake_pkt(conn, dest, destlen,
                                   NGTCP2_PKT_SERVER_CLEARTEXT,
                                   ackfr.type == 0 ? NULL : &ackfr, tx_buf);
}

ssize_t ngtcp2_conn_send(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                         ngtcp2_tstamp ts) {
  ssize_t nwrite = 0;
  int rv;

  switch (conn->state) {
  case NGTCP2_CS_CLIENT_INITIAL:
    nwrite = ngtcp2_conn_send_client_initial(conn, dest, destlen);
    if (nwrite < 0) {
      break;
    }
    conn->state = NGTCP2_CS_CLIENT_CI_SENT;
    break;
  case NGTCP2_CS_CLIENT_SC_RECVED:
    nwrite = ngtcp2_conn_send_client_cleartext(conn, dest, destlen, ts);
    if (nwrite < 0) {
      break;
    }
    if (conn->handshake_completed) {
      rv = conn_call_handshake_completed(conn);
      if (rv != 0) {
        return rv;
      }
      conn->state = NGTCP2_CS_HANDSHAKE_COMPLETED;
    }
    break;
  case NGTCP2_CS_SERVER_CI_RECVED:
    nwrite = ngtcp2_conn_send_server_cleartext(conn, dest, destlen, 1, ts);
    if (nwrite < 0) {
      break;
    }
    conn->state = NGTCP2_CS_SERVER_SC_SENT;
    break;
  case NGTCP2_CS_SERVER_SC_SENT:
    nwrite = ngtcp2_conn_send_server_cleartext(conn, dest, destlen, 0, ts);
    if (nwrite < 0) {
      break;
    }
    break;
  }

  return nwrite;
}

static int ngtcp2_conn_recv_cleartext(ngtcp2_conn *conn, uint8_t exptype,
                                      const uint8_t *pkt, size_t pktlen,
                                      int server, int initial,
                                      ngtcp2_tstamp ts) {
  ssize_t nread;
  ngtcp2_pkt_hd hd;
  ngtcp2_frame fr;
  int rv;
  int require_ack = 0;

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

    /* We don't ack packet which contains ACK frames only. */
    /* TODO What about packet with PADDING frames only? */
    require_ack |= fr.type != NGTCP2_FRAME_ACK;

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

  if (require_ack) {
    rv = ngtcp2_conn_sched_ack(conn, hd.pkt_num, ts);
    if (rv != 0) {
      return rv;
    }
  }

  return 0;
}

int ngtcp2_conn_recv(ngtcp2_conn *conn, const uint8_t *pkt, size_t pktlen,
                     ngtcp2_tstamp ts) {
  int rv = 0;

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
                                    pktlen, 0, 1, ts);
    if (rv < 0) {
      break;
    }
    conn->state = NGTCP2_CS_CLIENT_SC_RECVED;
    break;
  case NGTCP2_CS_CLIENT_SC_RECVED:
    rv = ngtcp2_conn_recv_cleartext(conn, NGTCP2_PKT_SERVER_CLEARTEXT, pkt,
                                    pktlen, 0, 0, ts);
    if (rv < 0) {
      break;
    }
    break;
  case NGTCP2_CS_SERVER_INITIAL:
    rv = ngtcp2_conn_recv_cleartext(conn, NGTCP2_PKT_CLIENT_INITIAL, pkt,
                                    pktlen, 1, 1, ts);
    if (rv < 0) {
      break;
    }
    conn->state = NGTCP2_CS_SERVER_CI_RECVED;
    break;
  case NGTCP2_CS_SERVER_SC_SENT:
    rv = ngtcp2_conn_recv_cleartext(conn, NGTCP2_PKT_CLIENT_CLEARTEXT, pkt,
                                    pktlen, 1, 0, ts);
    if (rv < 0) {
      break;
    }
    if (conn->handshake_completed) {
      rv = conn_call_handshake_completed(conn);
      if (rv != 0) {
        return rv;
      }
      conn->state = NGTCP2_CS_HANDSHAKE_COMPLETED;
    }
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

int ngtcp2_conn_handshake_completed(ngtcp2_conn *conn) {
  switch (conn->state) {
  case NGTCP2_CS_CLIENT_SC_RECVED:
  case NGTCP2_CS_SERVER_SC_SENT:
    break;
  default:
    return NGTCP2_ERR_INVALID_STATE;
  }

  conn->handshake_completed = 1;

  return 0;
}

int ngtcp2_strm_init(ngtcp2_strm *strm, ngtcp2_mem *mem) {
  int rv;

  strm->tx_offset = 0;
  strm->rx_offset = 0;
  strm->nbuffered = 0;
  strm->mem = mem;
  memset(&strm->tx_buf, 0, sizeof(strm->tx_buf));

  rv = ngtcp2_rob_init(&strm->rob, mem);
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

int ngtcp2_strm_recv_reordering(ngtcp2_strm *strm, ngtcp2_stream *fr) {
  if (strm->rob.bufferedlen >= 128 * 1024) {
    return NGTCP2_ERR_INTERNAL_ERROR;
  }

  return ngtcp2_rob_push(&strm->rob, fr->offset, fr->data, fr->datalen);
}

/* TODO This is not efficient and not robust. */
int ngtcp2_conn_sched_ack(ngtcp2_conn *conn, uint64_t pkt_num,
                          ngtcp2_tstamp ts) {
  ngtcp2_rx_pkt *rpkt;
  int rv;

  if (ngtcp2_pq_size(&conn->ackq) > 1024) {
    return NGTCP2_ERR_INTERNAL_ERROR;
  }

  rpkt = ngtcp2_mem_malloc(conn->mem, sizeof(ngtcp2_rx_pkt));
  if (rpkt == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  rpkt->pkt_num = pkt_num;
  rpkt->tstamp = ts;

  rv = ngtcp2_pq_push(&conn->ackq, &rpkt->pq_entry);
  if (rv != 0) {
    ngtcp2_mem_free(conn->mem, rpkt);
    return rv;
  }

  return 0;
}
