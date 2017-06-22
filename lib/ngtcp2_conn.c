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
#include "ngtcp2_framebuf.h"
#include "ngtcp2_macro.h"

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

  ngtcp2_strm_free(&conn->strm0, conn->mem);
  ngtcp2_mem_free(conn->mem, conn);
}

static ssize_t ngtcp2_conn_send_client_initial(ngtcp2_conn *conn, uint8_t *dest,
                                               size_t destlen) {
  int rv;
  uint64_t pkt_num = 0;
  const uint8_t *payload;
  ssize_t payloadlen;
  ngtcp2_upe upe;
  ngtcp2_pkt_hd hd;
  ngtcp2_frame fm;
  size_t maxpayloadlen;

  if (destlen < 1280) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  maxpayloadlen = destlen - NGTCP2_LONG_HEADERLEN - NGTCP2_PKT_MDLEN;

  payloadlen = conn->callbacks.send_client_initial(
      conn, NGTCP2_CONN_FLAG_NONE, &pkt_num, &payload, maxpayloadlen,
      conn->user_data);
  if (payloadlen <= 0) {
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
  fm.stream.datalen = (size_t)payloadlen;
  fm.stream.data = payload;

  rv = ngtcp2_upe_encode_frame(&upe, &fm);
  if (rv != 0) {
    return rv;
  }

  ngtcp2_upe_padding(&upe);

  conn->strm0.offset += (size_t)payloadlen;

  return (ssize_t)ngtcp2_upe_final(&upe, NULL);
}

static ssize_t ngtcp2_conn_send_client_cleartext(ngtcp2_conn *conn,
                                                 uint8_t *dest,
                                                 size_t destlen) {
  int rv;
  const uint8_t *payload;
  ssize_t payloadlen;
  ngtcp2_upe upe;
  ngtcp2_pkt_hd hd;
  ngtcp2_frame fm;
  size_t maxpayloadlen;

  if (destlen < NGTCP2_LONG_HEADERLEN - NGTCP2_PKT_MDLEN) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  maxpayloadlen = destlen - NGTCP2_LONG_HEADERLEN - NGTCP2_PKT_MDLEN;

  payloadlen = conn->callbacks.send_client_cleartext(
      conn, NGTCP2_CONN_FLAG_NONE, &payload, maxpayloadlen, conn->user_data);
  if (payloadlen <= 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_LONG_FORM, NGTCP2_PKT_CLIENT_INITIAL,
                     conn->conn_id, conn->next_out_pkt_num++, conn->version);

  ngtcp2_upe_init(&upe, dest, destlen);

  rv = ngtcp2_upe_encode_hd(&upe, &hd);
  if (rv != 0) {
    return rv;
  }

  fm.type = NGTCP2_FRAME_STREAM;
  fm.stream.flags = 0;
  fm.stream.fin = 0;
  fm.stream.stream_id = 0;
  fm.stream.offset = conn->strm0.offset;
  fm.stream.datalen = (size_t)payloadlen;
  fm.stream.data = payload;

  rv = ngtcp2_upe_encode_frame(&upe, &fm);
  if (rv != 0) {
    return rv;
  }

  conn->strm0.offset += (size_t)payloadlen;

  return (ssize_t)ngtcp2_upe_final(&upe, NULL);
}

static ssize_t ngtcp2_conn_send_server_cleartext(ngtcp2_conn *conn,
                                                 uint8_t *dest, size_t destlen,
                                                 int initial) {
  int rv;
  uint64_t pkt_num = 0;
  const uint8_t *payload;
  ssize_t payloadlen;
  ngtcp2_upe upe;
  ngtcp2_pkt_hd hd;
  ngtcp2_frame fm;
  size_t maxpayloadlen;

  if (destlen < NGTCP2_LONG_HEADERLEN + NGTCP2_PKT_MDLEN) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  maxpayloadlen = destlen - NGTCP2_LONG_HEADERLEN - NGTCP2_PKT_MDLEN;

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
    conn->next_out_pkt_num = pkt_num + 1;
  } else {
    pkt_num = conn->next_out_pkt_num++;
  }

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_LONG_FORM,
                     NGTCP2_PKT_SERVER_CLEARTEXT, conn->conn_id, pkt_num,
                     conn->version);

  ngtcp2_upe_init(&upe, dest, destlen);

  rv = ngtcp2_upe_encode_hd(&upe, &hd);
  if (rv != 0) {
    return rv;
  }

  fm.type = NGTCP2_FRAME_STREAM;
  fm.stream.flags = 0;
  fm.stream.fin = 0;
  fm.stream.stream_id = 0;
  fm.stream.offset = conn->strm0.offset;
  fm.stream.datalen = (size_t)payloadlen;
  fm.stream.data = payload;

  rv = ngtcp2_upe_encode_frame(&upe, &fm);
  if (rv != 0) {
    return rv;
  }

  conn->strm0.offset += (size_t)payloadlen;

  return (ssize_t)ngtcp2_upe_final(&upe, NULL);
}

ssize_t ngtcp2_conn_send(ngtcp2_conn *conn, uint8_t *dest, size_t destlen) {
  ssize_t rv;

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

  return 0;
}

static int ngtcp2_conn_recv_cleartext(ngtcp2_conn *conn, const uint8_t *pkt,
                                      size_t pktlen, int server, int initial) {
  ssize_t nread;
  ngtcp2_pkt_hd hd;
  ngtcp2_frame fm;
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

  if (!initial) {
    if (conn->conn_id != hd.conn_id) {
      return NGTCP2_ERR_PROTO;
    }
  } else if (!server) {
    conn->conn_id = hd.conn_id;
  }

  for (;;) {
    nread = ngtcp2_pkt_decode_frame(&fm, pkt, pktlen);
    if (nread < 0) {
      return (int)nread;
    }

    pkt += nread;
    pktlen -= (size_t)nread;

    if (fm.type != NGTCP2_FRAME_STREAM || fm.stream.stream_id != 0 ||
        conn->strm0.offset > fm.stream.offset) {
      continue;
    }

    if (conn->strm0.offset == fm.stream.offset) {
      conn->strm0.offset += fm.stream.datalen;

      rv = conn->callbacks.recv_handshake_data(
          conn, fm.stream.data, fm.stream.datalen, conn->user_data);
      if (rv != 0) {
        return rv;
      }

      rv = ngtcp2_conn_emit_pending_recv_handshake(conn, &conn->strm0);
      if (rv != 0) {
        return rv;
      }
    } else {
      rv = ngtcp2_conn_recv_reordering(conn, &conn->strm0, &fm.stream);
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
    rv = ngtcp2_conn_recv_cleartext(conn, pkt, pktlen, 0, 1);
    if (rv < 0) {
      break;
    }
    conn->state = NGTCP2_CS_CLIENT_SC_RECVED;
    break;
  case NGTCP2_CS_CLIENT_SC_RECVED:
    rv = ngtcp2_conn_recv_cleartext(conn, pkt, pktlen, 0, 0);
    if (rv < 0) {
      break;
    }
    break;
  case NGTCP2_CS_SERVER_INITIAL:
    rv = ngtcp2_conn_recv_cleartext(conn, pkt, pktlen, 1, 1);
    if (rv < 0) {
      break;
    }
    conn->state = NGTCP2_CS_SERVER_CI_RECVED;
    break;
  case NGTCP2_CS_SERVER_SC_SENT:
    rv = ngtcp2_conn_recv_cleartext(conn, pkt, pktlen, 1, 0);
    if (rv < 0) {
      break;
    }
    conn->state = NGTCP2_CS_SERVER_CC_RECVED;
    /* TODO Ask crypto backend whether TLS handshake has finished or
       not */
    break;
  }

  return -1;
}

int ngtcp2_conn_recv_reordering(ngtcp2_conn *conn, ngtcp2_strm *strm,
                                ngtcp2_stream *fm) {
  ngtcp2_framebuf *fb;
  int rv;

  if (strm->nbuffered >= 65536) {
    return NGTCP2_ERR_INTERNAL_ERROR;
  }

  rv = ngtcp2_framebuf_new(&fb, fm, conn->mem);
  if (rv != 0) {
    return rv;
  }

  /* TODO This is not efficient.  Invent new way to store duplicated
     buffered data */
  strm->nbuffered += fm->datalen;

  return ngtcp2_pq_push(&strm->pq, &fb->pq_entry);
}

int ngtcp2_conn_emit_pending_recv_handshake(ngtcp2_conn *conn,
                                            ngtcp2_strm *strm) {
  ngtcp2_framebuf *fb;
  uint64_t delta;
  int rv;

  for (; !ngtcp2_pq_empty(&strm->pq);) {
    fb = ngtcp2_struct_of(ngtcp2_pq_top(&strm->pq), ngtcp2_framebuf, pq_entry);

    if (strm->offset < fb->fm.stream.offset) {
      return 0;
    }

    ngtcp2_pq_pop(&strm->pq);

    delta = strm->offset - fb->fm.stream.offset;

    if (delta < fb->fm.stream.datalen) {
      rv = conn->callbacks.recv_handshake_data(conn, fb->fm.stream.data + delta,
                                               fb->fm.stream.datalen - delta,
                                               conn->user_data);
      if (rv != 0) {
        return rv;
      }
    }

    ngtcp2_framebuf_del(fb, conn->mem);
  }

  return 0;
}

static int ngtcp2_stream_offset_less(const void *lhsx, const void *rhsx) {
  const ngtcp2_framebuf *lhs, *rhs;

  lhs = ngtcp2_struct_of(lhsx, ngtcp2_framebuf, pq_entry);
  rhs = ngtcp2_struct_of(rhsx, ngtcp2_framebuf, pq_entry);

  return lhs->fm.stream.offset < rhs->fm.stream.offset;
}

int ngtcp2_strm_init(ngtcp2_strm *strm, ngtcp2_mem *mem) {
  strm->offset = 0;
  strm->nbuffered = 0;
  return ngtcp2_pq_init(&strm->pq, ngtcp2_stream_offset_less, mem);
}

static int ngtcp2_framebuf_item_free(ngtcp2_pq_entry *item, void *arg) {
  ngtcp2_framebuf *fb;
  ngtcp2_mem *mem;

  fb = ngtcp2_struct_of(item, ngtcp2_framebuf, pq_entry);
  mem = arg;

  ngtcp2_framebuf_del(fb, mem);

  return 0;
}

void ngtcp2_strm_free(ngtcp2_strm *strm, ngtcp2_mem *mem) {
  if (strm == NULL) {
    return;
  }

  ngtcp2_pq_each(&strm->pq, ngtcp2_framebuf_item_free, mem);
  ngtcp2_pq_free(&strm->pq);
}
