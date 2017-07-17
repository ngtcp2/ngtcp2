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
#include <assert.h>

#include "ngtcp2_upe.h"
#include "ngtcp2_ppe.h"
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

static int conn_new(ngtcp2_conn **pconn, uint64_t conn_id, uint32_t version,
                    const ngtcp2_conn_callbacks *callbacks, void *user_data) {
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

  ngtcp2_acktr_init(&(*pconn)->acktr);

  rv = ngtcp2_rtb_init(&(*pconn)->rtb, mem);
  if (rv != 0) {
    goto fail_rtb_init;
  }

  (*pconn)->callbacks = *callbacks;
  (*pconn)->conn_id = conn_id;
  (*pconn)->version = version;
  (*pconn)->mem = mem;
  (*pconn)->user_data = user_data;

  return 0;

fail_rtb_init:
  ngtcp2_strm_free(&(*pconn)->strm0);
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

  rv = conn_new(pconn, conn_id, version, callbacks, user_data);
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

  rv = conn_new(pconn, conn_id, version, callbacks, user_data);
  if (rv != 0) {
    return rv;
  }

  (*pconn)->state = NGTCP2_CS_SERVER_INITIAL;
  (*pconn)->server = 1;

  return 0;
}

static void delete_acktr_entry(ngtcp2_acktr_entry *ent, ngtcp2_mem *mem) {
  ngtcp2_acktr_entry *next;

  for (; ent;) {
    next = ent->next;
    ngtcp2_acktr_entry_del(ent, mem);
    ent = next;
  }
}

static void delete_buffed_pkts(ngtcp2_pkt_chain *pc, ngtcp2_mem *mem) {
  ngtcp2_pkt_chain *next;

  for (; pc;) {
    next = pc->next;
    ngtcp2_pkt_chain_del(pc, mem);
    pc = next;
  }
}

void ngtcp2_conn_del(ngtcp2_conn *conn) {
  if (conn == NULL) {
    return;
  }

  delete_buffed_pkts(conn->buffed_rx_ppkts, conn->mem);

  delete_acktr_entry(conn->acktr.ent, conn->mem);
  ngtcp2_acktr_free(&conn->acktr);

  ngtcp2_crypto_km_del(conn->rx_ckm, conn->mem);
  ngtcp2_crypto_km_del(conn->tx_ckm, conn->mem);

  ngtcp2_rtb_free(&conn->rtb);
  ngtcp2_strm_free(&conn->strm0);

  ngtcp2_mem_free(conn->mem, conn);
}

static int conn_create_ack_frame(ngtcp2_conn *conn, ngtcp2_ack *ack,
                                 ngtcp2_tstamp ts) {
  uint64_t first_pkt_num;
  ngtcp2_tstamp ack_delay;
  uint64_t last_pkt_num;
  ngtcp2_ack_blk *blk;
  int initial = 1;
  uint64_t gap;
  ngtcp2_acktr_entry *rpkt;

  rpkt = ngtcp2_acktr_get(&conn->acktr);
  if (rpkt == NULL) {
    return 0;
  }

  first_pkt_num = last_pkt_num = rpkt->pkt_num;
  ack_delay = ts - rpkt->tstamp;

  ngtcp2_acktr_remove(&conn->acktr, rpkt);
  ngtcp2_acktr_entry_del(rpkt, conn->mem);

  ack->type = NGTCP2_FRAME_ACK;
  ack->num_ts = 0;
  ack->num_blks = 0;

  for (; (rpkt = ngtcp2_acktr_get(&conn->acktr));) {
    if (rpkt->pkt_num + 1 == last_pkt_num) {
      last_pkt_num = rpkt->pkt_num;
      ngtcp2_acktr_remove(&conn->acktr, rpkt);
      ngtcp2_acktr_entry_del(rpkt, conn->mem);
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

    ngtcp2_acktr_remove(&conn->acktr, rpkt);
    ngtcp2_acktr_entry_del(rpkt, conn->mem);

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

/*
 * conn_retransmit_unprotected performs retransmission of lost
 * unprotected packet.
 */
static ssize_t conn_retransmit_unprotected(ngtcp2_conn *conn, uint8_t *dest,
                                           size_t destlen,
                                           ngtcp2_rtb_entry *ent,
                                           ngtcp2_tstamp ts) {
  int rv;
  ngtcp2_upe upe;
  ngtcp2_pkt_hd hd = ent->hd;
  ngtcp2_frame_chain **pfrc;
  ngtcp2_rtb_entry *nent = NULL;
  ngtcp2_frame localfr;
  int pkt_empty = 1;

  /* This is required because ent->hd may have old client version. */
  hd.version = conn->version;
  hd.pkt_num = conn->next_tx_pkt_num;

  ngtcp2_upe_init(&upe, dest, destlen);

  rv = ngtcp2_upe_encode_hd(&upe, &hd);
  if (rv != 0) {
    return rv;
  }

  rv = conn_call_send_pkt(conn, &hd);
  if (rv != 0) {
    return rv;
  }

  /* TODO Don't include ACK in this unprotected packet in order not to
     ack protected packet here for now. */

  for (pfrc = &ent->frc; *pfrc; pfrc = &(*pfrc)->next) {
    rv = ngtcp2_upe_encode_frame(&upe, &(*pfrc)->fr);
    if (rv != 0) {
      if (rv == NGTCP2_ERR_NOBUF) {
        break;
      }
    }
    rv = conn_call_send_frame(conn, &hd, &(*pfrc)->fr);
    if (rv != 0) {
      return rv;
    }
  }

  if (*pfrc != ent->frc) {
    pkt_empty = 0;
  }

  if (pkt_empty) {
    return NGTCP2_ERR_NOBUF;
  }

  if (*pfrc == NULL) {
    /* We have retransmit complete packet.  Update ent with new packet
       header, and push it into rbt again. */
    ngtcp2_rtb_pop(&conn->rtb);
    ent->hd = hd;
    /* TODO Should we change expiry time in 2nd try? */
    ent->expiry = ts + NGTCP2_INITIAL_EXPIRY;
    rv = ngtcp2_rtb_add(&conn->rtb, ent);
    if (rv != 0) {
      ngtcp2_rtb_entry_del(ent, conn->mem);
      return rv;
    }

    if (hd.type == NGTCP2_PKT_CLIENT_INITIAL) {
      localfr.type = NGTCP2_FRAME_PADDING;
      localfr.padding.len = ngtcp2_upe_padding(&upe);

      rv = conn_call_send_frame(conn, &hd, &localfr);
      if (rv != 0) {
        return rv;
      }
    }

    ++conn->next_tx_pkt_num;
    return (ssize_t)ngtcp2_upe_final(&upe, NULL);
  }

  /* We have partially retransmitted lost frames.  Create new
     ngtcp2_rtb_entry to track down the sent packet. */
  rv = ngtcp2_rtb_entry_new(&nent, &hd, NULL, ts + NGTCP2_INITIAL_EXPIRY,
                            conn->mem);
  if (rv != 0) {
    return rv;
  }

  nent->frc = ent->frc;
  ent->frc = *pfrc;
  *pfrc = NULL;

  rv = ngtcp2_rtb_add(&conn->rtb, nent);
  if (rv != 0) {
    ngtcp2_rtb_entry_del(nent, conn->mem);
    return rv;
  }

  ++conn->next_tx_pkt_num;

  return (ssize_t)ngtcp2_upe_final(&upe, NULL);
}

static ssize_t conn_retransmit_protected(ngtcp2_conn *conn, uint8_t *dest,
                                         size_t destlen, ngtcp2_rtb_entry *ent,
                                         ngtcp2_tstamp ts) {
  (void)conn;
  (void)dest;
  (void)destlen;
  (void)ent;
  (void)ts;
  return -1;
}

static ssize_t conn_retransmit(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                               ngtcp2_tstamp ts) {
  ngtcp2_rtb_entry *ent;

  ent = ngtcp2_rtb_top(&conn->rtb);
  if (ent == NULL) {
    return 0;
  }

  if (ent->hd.flags & NGTCP2_PKT_FLAG_LONG_FORM) {
    switch (ent->hd.type) {
    case NGTCP2_PKT_CLIENT_INITIAL:
    case NGTCP2_PKT_SERVER_CLEARTEXT:
    case NGTCP2_PKT_CLIENT_CLEARTEXT:
      return conn_retransmit_unprotected(conn, dest, destlen, ent, ts);
    }
  } else {
    switch (ent->hd.type) {
    case NGTCP2_PKT_01:
    case NGTCP2_PKT_02:
    case NGTCP2_PKT_03:
      return conn_retransmit_protected(conn, dest, destlen, ent, ts);
    }
  }

  return NGTCP2_ERR_INVALID_ARGUMENT;
}

static ssize_t conn_encode_handshake_pkt(ngtcp2_conn *conn, uint8_t *dest,
                                         size_t destlen, uint8_t type,
                                         ngtcp2_buf *tx_buf, ngtcp2_tstamp ts) {
  int rv;
  ngtcp2_upe upe;
  ngtcp2_pkt_hd hd;
  ngtcp2_frame_chain *frc = NULL;
  ngtcp2_frame *fr, localfr;
  size_t nwrite;
  ngtcp2_rtb_entry *rtbent;
  int pkt_empty = 1;

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
  if (type != NGTCP2_PKT_CLIENT_INITIAL) {
    /* TODO Should we retransmit ACK frame? */
    rv = conn_create_ack_frame(conn, &localfr.ack, ts);
    if (rv != 0) {
      goto fail;
    }

    rv = ngtcp2_upe_encode_frame(&upe, &localfr);
    if (rv != 0) {
      goto fail;
    }

    rv = conn_call_send_frame(conn, &hd, &localfr);
    if (rv != 0) {
      goto fail;
    }

    pkt_empty = 0;
  }

  if (ngtcp2_upe_left(&upe) < NGTCP2_STREAM_OVERHEAD + 1) {
    if (!pkt_empty) {
      ++conn->next_tx_pkt_num;
      return (ssize_t)ngtcp2_upe_final(&upe, NULL);
    }

    rv = NGTCP2_ERR_NOBUF;
    goto fail;
  }

  nwrite = ngtcp2_min(ngtcp2_buf_len(tx_buf),
                      ngtcp2_upe_left(&upe) - NGTCP2_STREAM_OVERHEAD);

  if (nwrite > 0) {
    rv = ngtcp2_frame_chain_new(&frc, conn->mem);
    if (rv != 0) {
      goto fail;
    }

    fr = &frc->fr;

    /* TODO Make a function to create STREAM frame */
    fr->type = NGTCP2_FRAME_STREAM;
    fr->stream.flags = 0;
    fr->stream.fin = 0;
    fr->stream.stream_id = 0;
    fr->stream.offset = conn->strm0.tx_offset;
    fr->stream.datalen = nwrite;
    fr->stream.data = tx_buf->pos;

    rv = ngtcp2_upe_encode_frame(&upe, fr);
    if (rv != 0) {
      goto fail;
    }

    rv = conn_call_send_frame(conn, &hd, fr);
    if (rv != 0) {
      goto fail;
    }

    tx_buf->pos += nwrite;
    conn->strm0.tx_offset += nwrite;
  }

  if (type == NGTCP2_PKT_CLIENT_INITIAL) {
    localfr.type = NGTCP2_FRAME_PADDING;
    localfr.padding.len = ngtcp2_upe_padding(&upe);
    if (localfr.padding.len > 0) {
      rv = conn_call_send_frame(conn, &hd, &localfr);
      if (rv != 0) {
        goto fail;
      }
    }
  }

  ++conn->next_tx_pkt_num;

  if (frc) {
    rv = ngtcp2_rtb_entry_new(&rtbent, &hd, frc, ts + NGTCP2_INITIAL_EXPIRY,
                              conn->mem);
    if (rv != 0) {
      goto fail;
    }

    rv = ngtcp2_rtb_add(&conn->rtb, rtbent);
    if (rv != 0) {
      ngtcp2_rtb_entry_del(rtbent, conn->mem);
      return rv;
    }
  }

  return (ssize_t)ngtcp2_upe_final(&upe, NULL);

fail:
  ngtcp2_frame_chain_del(frc, conn->mem);

  return rv;
}

/*
 * conn_encode_unprotected_ack_if_any creates packet which only
 * includes ACK frame if any ack is required.
 */
static ssize_t conn_encode_unprotected_ack_if_any(ngtcp2_conn *conn,
                                                  uint8_t *dest, size_t destlen,
                                                  uint8_t type,
                                                  ngtcp2_tstamp ts) {
  int rv;
  ngtcp2_upe upe;
  ngtcp2_pkt_hd hd;
  ngtcp2_frame fr;

  if (ngtcp2_acktr_get(&conn->acktr) == NULL) {
    return 0;
  }

  rv = conn_create_ack_frame(conn, &fr.ack, ts);
  if (rv != 0) {
    return rv;
  }

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

  rv = ngtcp2_upe_encode_frame(&upe, &fr);
  if (rv != 0) {
    return rv;
  }

  rv = conn_call_send_frame(conn, &hd, &fr);
  if (rv != 0) {
    return rv;
  }

  ++conn->next_tx_pkt_num;

  return (ssize_t)ngtcp2_upe_final(&upe, NULL);
}

static ssize_t conn_send_client_initial(ngtcp2_conn *conn, uint8_t *dest,
                                        size_t destlen, ngtcp2_tstamp ts) {
  uint64_t pkt_num = 0;
  const uint8_t *payload;
  ssize_t payloadlen;
  ngtcp2_buf *tx_buf = &conn->strm0.tx_buf;

  payloadlen = conn->callbacks.send_client_initial(
      conn, NGTCP2_CONN_FLAG_NONE, &pkt_num, &payload, conn->user_data);

  if (payloadlen <= 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  ngtcp2_buf_init(tx_buf, (uint8_t *)payload, (size_t)payloadlen);
  tx_buf->last += payloadlen;

  conn->next_tx_pkt_num = pkt_num;

  return conn_encode_handshake_pkt(conn, dest, destlen,
                                   NGTCP2_PKT_CLIENT_INITIAL, tx_buf, ts);
}

static ssize_t conn_send_client_cleartext(ngtcp2_conn *conn, uint8_t *dest,
                                          size_t destlen, ngtcp2_tstamp ts) {
  const uint8_t *payload;
  ssize_t payloadlen;
  ngtcp2_buf *tx_buf = &conn->strm0.tx_buf;

  if (ngtcp2_buf_len(tx_buf) == 0) {
    payloadlen = conn->callbacks.send_client_cleartext(
        conn, NGTCP2_CONN_FLAG_NONE, &payload, conn->user_data);

    if (payloadlen < 0) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    if (payloadlen == 0) {
      return conn_encode_unprotected_ack_if_any(
          conn, dest, destlen, NGTCP2_PKT_CLIENT_CLEARTEXT, ts);
    }

    ngtcp2_buf_init(tx_buf, (uint8_t *)payload, (size_t)payloadlen);
    tx_buf->last += payloadlen;
  }

  return conn_encode_handshake_pkt(conn, dest, destlen,
                                   NGTCP2_PKT_CLIENT_CLEARTEXT, tx_buf, ts);
}

static ssize_t conn_send_server_cleartext(ngtcp2_conn *conn, uint8_t *dest,
                                          size_t destlen, int initial,
                                          ngtcp2_tstamp ts) {
  uint64_t pkt_num = 0;
  const uint8_t *payload;
  ssize_t payloadlen;
  ngtcp2_buf *tx_buf = &conn->strm0.tx_buf;

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
      return conn_encode_unprotected_ack_if_any(
          conn, dest, destlen, NGTCP2_PKT_SERVER_CLEARTEXT, ts);
    }

    ngtcp2_buf_init(tx_buf, (uint8_t *)payload, (size_t)payloadlen);
    tx_buf->last += payloadlen;
  }

  if (initial) {
    conn->next_tx_pkt_num = pkt_num;
  }

  return conn_encode_handshake_pkt(conn, dest, destlen,
                                   NGTCP2_PKT_SERVER_CLEARTEXT, tx_buf, ts);
}

static ssize_t conn_send_connection_close(ngtcp2_conn *conn, uint8_t *dest,
                                          size_t destlen, ngtcp2_tstamp ts) {
  int rv;
  ngtcp2_ppe ppe;
  ngtcp2_pkt_hd hd;
  ngtcp2_frame fr;
  ngtcp2_frame ackfr;
  ssize_t nwrite;
  ngtcp2_crypto_ctx ctx;

  ackfr.type = 0;
  rv = conn_create_ack_frame(conn, &ackfr.ack, ts);
  if (rv != 0) {
    return rv;
  }

  /* TODO Choose appropriate packet number size */
  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_CONN_ID, NGTCP2_PKT_03, conn->conn_id,
                     conn->next_tx_pkt_num, conn->version);

  ctx.ckm = conn->tx_ckm;
  ctx.aead_overhead = conn->aead_overhead;
  ctx.encrypt = conn->callbacks.encrypt;
  ctx.user_data = conn;

  ngtcp2_ppe_init(&ppe, dest, destlen, &ctx, conn->mem);

  rv = ngtcp2_ppe_encode_hd(&ppe, &hd);
  if (rv != 0) {
    return rv;
  }

  rv = conn_call_send_pkt(conn, &hd);
  if (rv != 0) {
    return rv;
  }

  if (ackfr.type) {
    rv = ngtcp2_ppe_encode_frame(&ppe, &ackfr);
    if (rv != 0) {
      return rv;
    }

    rv = conn_call_send_frame(conn, &hd, &ackfr);
    if (rv != 0) {
      return rv;
    }
  }

  /* TODO CONNECTION_CLOSE cannot be sent if ACK frame is too
     large. */

  fr.type = NGTCP2_FRAME_CONNECTION_CLOSE;
  fr.connection_close.error_code = NGTCP2_QUIC_INTERNAL_ERROR;
  fr.connection_close.reasonlen = 0;
  fr.connection_close.reason = NULL;

  rv = ngtcp2_ppe_encode_frame(&ppe, &fr);
  if (rv != 0) {
    return rv;
  }

  rv = conn_call_send_frame(conn, &hd, &fr);
  if (rv != 0) {
    return rv;
  }

  nwrite = ngtcp2_ppe_final(&ppe, NULL);
  if (nwrite < 0) {
    return nwrite;
  }

  ++conn->next_tx_pkt_num;

  return nwrite;
}

static ssize_t conn_send_pkt(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                             ngtcp2_tstamp ts) {
  int rv;
  ngtcp2_ppe ppe;
  ngtcp2_pkt_hd hd;
  ngtcp2_frame ackfr;
  ssize_t nwrite;
  ngtcp2_crypto_ctx ctx;

  /* TODO Just send ACK for now */
  ackfr.type = 0;
  rv = conn_create_ack_frame(conn, &ackfr.ack, ts);
  if (rv != 0) {
    return rv;
  }
  if (ackfr.type == 0) {
    return 0;
  }

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_CONN_ID, NGTCP2_PKT_03, conn->conn_id,
                     conn->next_tx_pkt_num, conn->version);

  ctx.ckm = conn->tx_ckm;
  ctx.aead_overhead = conn->aead_overhead;
  ctx.encrypt = conn->callbacks.encrypt;
  ctx.user_data = conn;

  ngtcp2_ppe_init(&ppe, dest, destlen, &ctx, conn->mem);

  rv = ngtcp2_ppe_encode_hd(&ppe, &hd);
  if (rv != 0) {
    return rv;
  }

  rv = conn_call_send_pkt(conn, &hd);
  if (rv != 0) {
    return rv;
  }

  rv = ngtcp2_ppe_encode_frame(&ppe, &ackfr);
  if (rv != 0) {
    return rv;
  }

  rv = conn_call_send_frame(conn, &hd, &ackfr);
  if (rv != 0) {
    return rv;
  }

  nwrite = ngtcp2_ppe_final(&ppe, NULL);
  if (nwrite < 0) {
    return nwrite;
  }

  ++conn->next_tx_pkt_num;

  return nwrite;
}

ssize_t ngtcp2_conn_send(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                         ngtcp2_tstamp ts) {
  ssize_t nwrite = 0;
  ngtcp2_rtb_entry *rtbent;

  rtbent = ngtcp2_rtb_top(&conn->rtb);
  if (rtbent && rtbent->expiry <= ts) {
    return conn_retransmit(conn, dest, destlen, ts);
  }

  switch (conn->state) {
  case NGTCP2_CS_CLIENT_INITIAL:
    nwrite = conn_send_client_initial(conn, dest, destlen, ts);
    if (nwrite < 0) {
      break;
    }
    conn->state = NGTCP2_CS_CLIENT_WAIT_HANDSHAKE;
    break;
  case NGTCP2_CS_CLIENT_WAIT_HANDSHAKE:
    nwrite = conn_send_client_cleartext(conn, dest, destlen, ts);
    if (nwrite < 0) {
      break;
    }
    break;
  case NGTCP2_CS_CLIENT_HANDSHAKE_ALMOST_FINISHED:
    nwrite = conn_send_client_cleartext(conn, dest, destlen, ts);
    if (nwrite < 0) {
      break;
    }
    if (nwrite == 0) {
      conn->state = NGTCP2_CS_POST_HANDSHAKE;
    }
    break;
  case NGTCP2_CS_SERVER_INITIAL:
    nwrite = conn_send_server_cleartext(conn, dest, destlen, 1, ts);
    if (nwrite < 0) {
      break;
    }
    conn->state = NGTCP2_CS_SERVER_WAIT_HANDSHAKE;
    break;
  case NGTCP2_CS_SERVER_WAIT_HANDSHAKE:
    nwrite = conn_send_server_cleartext(conn, dest, destlen, 0, ts);
    if (nwrite < 0) {
      break;
    }
    break;
  case NGTCP2_CS_POST_HANDSHAKE:
    nwrite = conn_send_connection_close(conn, dest, destlen, ts);
    if (nwrite < 0) {
      break;
    }
    conn->state = NGTCP2_CS_CLOSE_WAIT;
    break;
  case NGTCP2_CS_CLOSE_WAIT:
    nwrite = conn_send_pkt(conn, dest, destlen, ts);
    if (nwrite < 0) {
      break;
    }
  }

  return nwrite;
}

static int conn_on_version_negotiation(ngtcp2_conn *conn,
                                       const ngtcp2_pkt_hd *hd,
                                       const uint8_t *pkt, size_t pktlen) {
  uint32_t sv[16];
  uint32_t *p;
  int rv;
  size_t nsv;

  if (pktlen % sizeof(uint32_t)) {
    return NGTCP2_ERR_PROTO;
  }

  if (!conn->callbacks.recv_version_negotiation) {
    return 0;
  }

  if (pktlen > sizeof(sv)) {
    p = ngtcp2_mem_malloc(conn->mem, pktlen);
    if (p == NULL) {
      return NGTCP2_ERR_NOMEM;
    }
  } else {
    p = sv;
  }

  nsv = ngtcp2_pkt_decode_version_negotiation(p, pkt, pktlen);

  rv = conn->callbacks.recv_version_negotiation(conn, hd, sv, nsv,
                                                conn->user_data);

  if (p != sv) {
    ngtcp2_mem_free(conn->mem, p);
  }

  if (rv != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

/*
 * rtb_each_ack is called for each ngtcp2_rtb_entry when ACK frame is
 * received.  If the entry is acked by the frame, it will be removed
 * from |rtb|.
 */
static int rtb_each_ack(ngtcp2_rtb *rtb, ngtcp2_rtb_entry *ent, void *arg) {
  size_t i;
  const ngtcp2_ack *fr = arg;
  uint64_t pkt_num = ent->hd.pkt_num;
  uint64_t largest_ack = fr->largest_ack;

  if (fr->largest_ack < fr->first_ack_blklen) {
    /* TODO Badly encoded ACK frame */
    return -1;
  }

  if (largest_ack - fr->first_ack_blklen <= pkt_num && pkt_num <= largest_ack) {
    ngtcp2_rtb_remove(rtb, ent->hd.pkt_num);
    return 0;
  }

  for (i = 0; i < fr->num_blks; ++i) {
    /* TODO Badly encoded ACK frame */
    if (largest_ack < fr->blks[i].gap + fr->blks[i].blklen) {
      return -1;
    }
    largest_ack -= fr->blks[i].gap;

    if (largest_ack - fr->blks[i].blklen <= pkt_num && pkt_num <= largest_ack) {
      ngtcp2_rtb_remove(rtb, ent->hd.pkt_num);
      return 0;
    }
  }

  return 0;
}

static int conn_recv_ack(ngtcp2_conn *conn, ngtcp2_ack *fr) {
  ngtcp2_rtb_each(&conn->rtb, rtb_each_ack, fr);

  return 0;
}

static int conn_buffer_protected_pkt(ngtcp2_conn *conn, const uint8_t *pkt,
                                     size_t pktlen, ngtcp2_tstamp ts) {
  int rv;
  ngtcp2_pkt_chain **ppc = &conn->buffed_rx_ppkts;
  ngtcp2_pkt_chain *pc;
  size_t i;
  for (i = 0; *ppc && i < NGTCP2_MAX_NUM_BUFFED_RX_PPKTS;
       ppc = &(*ppc)->next, ++i)
    ;

  if (i == NGTCP2_MAX_NUM_BUFFED_RX_PPKTS) {
    return 0;
  }

  rv = ngtcp2_pkt_chain_new(&pc, pkt, pktlen, ts, conn->mem);
  if (rv != 0) {
    return rv;
  }

  *ppc = pc;

  return 0;
}

static int conn_recv_handshake_pkt(ngtcp2_conn *conn, const uint8_t *pkt,
                                   size_t pktlen, ngtcp2_tstamp ts) {
  ssize_t nread;
  ngtcp2_pkt_hd hd;
  ngtcp2_frame fr;
  int rv;
  int require_ack = 0;
  uint64_t rx_offset;

  if (!(pkt[0] & NGTCP2_HEADER_FORM_BIT)) {
    return conn_buffer_protected_pkt(conn, pkt, pktlen, ts);
  }

  nread = ngtcp2_pkt_decode_hd_long(&hd, pkt, pktlen);
  if (nread < 0) {
    return (int)nread;
  }

  pkt += nread;
  pktlen -= (size_t)nread;

  hd.pkt_num = ngtcp2_pkt_adjust_pkt_num(conn->max_rx_pkt_num, hd.pkt_num, 32);

  rv = conn_call_recv_pkt(conn, &hd);
  if (rv != 0) {
    return rv;
  }

  if (conn->version != hd.version) {
    return NGTCP2_ERR_PROTO;
  }

  /* TODO What happen if connection ID changes in mid handshake? */
  if (conn->server) {
    switch (hd.type) {
    case NGTCP2_PKT_CLIENT_INITIAL:
    case NGTCP2_PKT_CLIENT_CLEARTEXT:
      break;
    default:
      return NGTCP2_ERR_PROTO;
    }
  } else {
    conn->conn_id = hd.conn_id;

    switch (hd.type) {
    case NGTCP2_PKT_SERVER_CLEARTEXT:
      break;
    case NGTCP2_PKT_VERSION_NEGOTIATION:
      rv = conn_on_version_negotiation(conn, &hd, pkt, pktlen);
      if (rv != 0) {
        return rv;
      }
      return 0;
    default:
      return NGTCP2_ERR_PROTO;
    }
  }

  for (; pktlen;) {
    nread = ngtcp2_pkt_decode_frame(&fr, pkt, pktlen, conn->max_rx_pkt_num);
    if (nread < 0) {
      return (int)nread;
    }

    pkt += nread;
    pktlen -= (size_t)nread;

    rv = conn_call_recv_frame(conn, &hd, &fr);
    if (rv != 0) {
      return rv;
    }

    /* We don't ack packet which contains ACK and CONNECTION_CLOSE
       only. */
    /* TODO What about packet with PADDING frames only? */
    require_ack |=
        fr.type != NGTCP2_FRAME_ACK && fr.type != NGTCP2_FRAME_CONNECTION_CLOSE;

    if (fr.type == NGTCP2_FRAME_ACK) {
      rv = conn_recv_ack(conn, &fr.ack);
      if (rv != 0) {
        return rv;
      }
      continue;
    }

    if (fr.type != NGTCP2_FRAME_STREAM || fr.stream.stream_id != 0 ||
        fr.stream.datalen == 0) {
      continue;
    }

    if (hd.type == NGTCP2_PKT_CLIENT_INITIAL && fr.stream.offset != 0) {
      return NGTCP2_ERR_PROTO;
    }

    rx_offset = ngtcp2_strm_rx_offset(&conn->strm0);
    if (rx_offset >= fr.stream.offset + fr.stream.datalen) {
      continue;
    }

    /* TODO Refused to receive stream data which is more than 128KiB
       for now.  We can ditch this if flow control is implemented. */
    if (fr.stream.offset > 128 * 1024) {
      return NGTCP2_ERR_INTERNAL;
    }

    if (fr.stream.offset <= rx_offset) {
      size_t ncut = (rx_offset - fr.stream.offset);
      const uint8_t *data = fr.stream.data + ncut;
      size_t datalen = fr.stream.datalen - ncut;

      ngtcp2_rob_remove_prefix(&conn->strm0.rob, rx_offset + datalen);

      rv = conn->callbacks.recv_handshake_data(conn, data, datalen,
                                               conn->user_data);
      if (rv != 0) {
        return rv;
      }

      rv = ngtcp2_conn_emit_pending_recv_handshake(conn, &conn->strm0,
                                                   rx_offset + datalen);
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

  conn->max_rx_pkt_num = ngtcp2_max(conn->max_rx_pkt_num, hd.pkt_num);

  if (require_ack) {
    rv = ngtcp2_conn_sched_ack(conn, hd.pkt_num, ts);
    if (rv != 0) {
      return rv;
    }
  }

  return 0;
}

static ssize_t conn_decrypt_packet(ngtcp2_conn *conn, uint8_t *dest,
                                   size_t destlen, const uint8_t *pkt,
                                   size_t pktlen, const uint8_t *ad,
                                   size_t adlen, uint64_t pkt_num) {
  uint8_t nonce[64];
  ngtcp2_crypto_km *ckm = conn->rx_ckm;
  ssize_t nwrite;

  assert(sizeof(nonce) >= ckm->ivlen);

  ngtcp2_crypto_create_nonce(nonce, ckm->iv, ckm->ivlen, pkt_num);

  nwrite = conn->callbacks.decrypt(conn, dest, destlen, pkt, pktlen, ckm->key,
                                   ckm->keylen, nonce, ckm->ivlen, ad, adlen,
                                   conn->user_data);

  if (nwrite < 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return nwrite;
}

static int conn_recv_packet(ngtcp2_conn *conn, uint8_t *pkt, size_t pktlen,
                            ngtcp2_tstamp ts) {
  ngtcp2_pkt_hd hd;
  size_t pkt_num_bits;
  int encrypted = 0;
  int rv = 0;
  const uint8_t *hdpkt = pkt;
  ssize_t nread, nwrite;
  ngtcp2_frame fr;
  int require_ack = 0;

  if (pkt[0] & NGTCP2_HEADER_FORM_BIT) {
    nread = ngtcp2_pkt_decode_hd_long(&hd, pkt, pktlen);
  } else {
    nread = ngtcp2_pkt_decode_hd_short(&hd, pkt, pktlen);
  }
  if (nread < 0) {
    return (int)nread;
  }

  pkt += nread;
  pktlen -= (size_t)nread;

  if (hd.flags & NGTCP2_PKT_FLAG_LONG_FORM) {
    pkt_num_bits = 32;
    if (hd.type == NGTCP2_PKT_1RTT_PROTECTED_K0) {
      encrypted = 1;
    }
  } else {
    switch (hd.type) {
    case NGTCP2_PKT_01:
      pkt_num_bits = 8;
      break;
    case NGTCP2_PKT_02:
      pkt_num_bits = 16;
      break;
    case NGTCP2_PKT_03:
      pkt_num_bits = 32;
      break;
    default:
      assert(0);
    }
    if (!(hd.flags & NGTCP2_PKT_FLAG_KEY_PHASE)) {
      encrypted = 1;
    }
  }

  hd.pkt_num =
      ngtcp2_pkt_adjust_pkt_num(conn->max_rx_pkt_num, hd.pkt_num, pkt_num_bits);

  rv = conn_call_recv_pkt(conn, &hd);
  if (rv != 0) {
    return rv;
  }

  if (encrypted) {
    nwrite = conn_decrypt_packet(conn, pkt, pktlen, pkt, pktlen, hdpkt,
                                 (size_t)nread, hd.pkt_num);
    if (nwrite < 0) {
      return (int)nwrite;
    }
    pktlen = (size_t)nwrite;
  }

  for (; pktlen;) {
    nread = ngtcp2_pkt_decode_frame(&fr, pkt, pktlen, conn->max_rx_pkt_num);
    if (nread < 0) {
      return (int)nread;
    }

    pkt += nread;
    pktlen -= (size_t)nread;

    rv = conn_call_recv_frame(conn, &hd, &fr);
    if (rv != 0) {
      return rv;
    }

    /* We don't ack packet which contains ACK and CONNECTION_CLOSE
       only. */
    /* TODO What about packet with PADDING frames only? */
    require_ack |=
        fr.type != NGTCP2_FRAME_ACK && fr.type != NGTCP2_FRAME_CONNECTION_CLOSE;

    if (fr.type == NGTCP2_FRAME_ACK) {
      rv = conn_recv_ack(conn, &fr.ack);
      if (rv != 0) {
        return rv;
      }
    }
  }

  conn->max_rx_pkt_num = ngtcp2_max(conn->max_rx_pkt_num, hd.pkt_num);

  if (require_ack) {
    rv = ngtcp2_conn_sched_ack(conn, hd.pkt_num, ts);
    if (rv != 0) {
      return rv;
    }
  }

  return rv;
}

static int conn_process_buffered_protected_pkt(ngtcp2_conn *conn,
                                               ngtcp2_tstamp ts) {
  int rv;
  ngtcp2_pkt_chain *pc = conn->buffed_rx_ppkts, *next;

  for (; pc; pc = pc->next) {
    rv = conn_recv_packet(conn, pc->pkt, pc->pktlen, ts);
    if (rv != 0) {
      return rv;
    }
  }

  for (pc = conn->buffed_rx_ppkts; pc;) {
    next = pc->next;
    ngtcp2_pkt_chain_del(pc, conn->mem);
    pc = next;
  }

  conn->buffed_rx_ppkts = NULL;

  return 0;
}

int ngtcp2_conn_recv(ngtcp2_conn *conn, uint8_t *pkt, size_t pktlen,
                     ngtcp2_tstamp ts) {
  int rv = 0;

  if (pktlen == 0) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  if (pkt[0] & NGTCP2_HEADER_FORM_BIT) {
    switch (pkt[0] & NGTCP2_LONG_TYPE_MASK) {
    case NGTCP2_PKT_CLIENT_INITIAL:
    case NGTCP2_PKT_SERVER_STATELESS_RETRY:
    case NGTCP2_PKT_SERVER_CLEARTEXT:
    case NGTCP2_PKT_CLIENT_CLEARTEXT:
    case NGTCP2_PKT_PUBLIC_RESET:
      if (ngtcp2_pkt_verify(pkt, pktlen) != 0) {
        return NGTCP2_ERR_BAD_PKT_HASH;
      }
      pktlen -= NGTCP2_PKT_MDLEN;
      break;
    }
  }

  switch (conn->state) {
  case NGTCP2_CS_CLIENT_WAIT_HANDSHAKE:
    rv = conn_recv_handshake_pkt(conn, pkt, pktlen, ts);
    if (rv < 0) {
      break;
    }
    if (conn->handshake_completed) {
      rv = conn_call_handshake_completed(conn);
      if (rv != 0) {
        return rv;
      }
      conn->state = NGTCP2_CS_CLIENT_HANDSHAKE_ALMOST_FINISHED;

      rv = conn_process_buffered_protected_pkt(conn, ts);
      if (rv != 0) {
        return rv;
      }
    }
    break;
  case NGTCP2_CS_SERVER_INITIAL:
  case NGTCP2_CS_SERVER_WAIT_HANDSHAKE:
    rv = conn_recv_handshake_pkt(conn, pkt, pktlen, ts);
    if (rv < 0) {
      break;
    }
    if (conn->handshake_completed) {
      rv = conn_call_handshake_completed(conn);
      if (rv != 0) {
        return rv;
      }
      conn->state = NGTCP2_CS_POST_HANDSHAKE;

      rv = conn_process_buffered_protected_pkt(conn, ts);
      if (rv != 0) {
        return rv;
      }
    }
    break;
  case NGTCP2_CS_POST_HANDSHAKE:
  case NGTCP2_CS_CLOSE_WAIT:
    rv = conn_recv_packet(conn, pkt, pktlen, ts);
    if (rv < 0) {
      break;
    }
    break;
  }

  return rv;
}

int ngtcp2_conn_emit_pending_recv_handshake(ngtcp2_conn *conn,
                                            ngtcp2_strm *strm,
                                            uint64_t rx_offset) {
  size_t datalen;
  const uint8_t *data;
  int rv;

  for (;;) {
    datalen = ngtcp2_rob_data_at(&strm->rob, &data, rx_offset);
    if (datalen == 0) {
      assert(rx_offset == ngtcp2_strm_rx_offset(strm));
      return 0;
    }

    rx_offset += datalen;

    rv = conn->callbacks.recv_handshake_data(conn, data, datalen,
                                             conn->user_data);
    if (rv != 0) {
      return rv;
    }

    ngtcp2_rob_pop(&strm->rob, rx_offset - datalen, datalen);
  }
}

void ngtcp2_conn_handshake_completed(ngtcp2_conn *conn) {
  conn->handshake_completed = 1;
}

int ngtcp2_strm_init(ngtcp2_strm *strm, ngtcp2_mem *mem) {
  int rv;

  strm->tx_offset = 0;
  strm->nbuffered = 0;
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

int ngtcp2_strm_recv_reordering(ngtcp2_strm *strm, ngtcp2_stream *fr) {
  return ngtcp2_rob_push(&strm->rob, fr->offset, fr->data, fr->datalen);
}

int ngtcp2_conn_sched_ack(ngtcp2_conn *conn, uint64_t pkt_num,
                          ngtcp2_tstamp ts) {
  ngtcp2_acktr_entry *rpkt;
  int rv;

  rv = ngtcp2_acktr_entry_new(&rpkt, pkt_num, ts, conn->mem);
  if (rv != 0) {
    return rv;
  }

  /* TODO Ignore error for now */
  ngtcp2_acktr_add(&conn->acktr, rpkt);

  return 0;
}

int ngtcp2_accept(ngtcp2_pkt_hd *dest, const uint8_t *pkt, size_t pktlen) {
  ssize_t nread;
  ngtcp2_pkt_hd hd, *p;

  if (dest) {
    p = dest;
  } else {
    p = &hd;
  }

  if (pktlen == 0 || (pkt[0] & NGTCP2_HEADER_FORM_BIT) == 0) {
    return -1;
  }

  nread = ngtcp2_pkt_decode_hd_long(p, pkt, pktlen);
  if (nread < 0) {
    return -1;
  }

  if (p->type != NGTCP2_PKT_CLIENT_INITIAL) {
    return -1;
  }

  if (p->version != NGTCP2_PROTO_VERSION) {
    return 1;
  }

  return 0;
}

void ngtcp2_conn_set_aead_overhead(ngtcp2_conn *conn, size_t aead_overhead) {
  conn->aead_overhead = aead_overhead;
}

int ngtcp2_conn_update_tx_keys(ngtcp2_conn *conn, const uint8_t *key,
                               size_t keylen, const uint8_t *iv, size_t ivlen) {
  if (conn->tx_ckm) {
    return NGTCP2_ERR_INVALID_STATE;
  }

  return ngtcp2_crypto_km_new(&conn->tx_ckm, key, keylen, iv, ivlen, conn->mem);
}

int ngtcp2_conn_update_rx_keys(ngtcp2_conn *conn, const uint8_t *key,
                               size_t keylen, const uint8_t *iv, size_t ivlen) {
  if (conn->rx_ckm) {
    return NGTCP2_ERR_INVALID_STATE;
  }

  return ngtcp2_crypto_km_new(&conn->rx_ckm, key, keylen, iv, ivlen, conn->mem);
}

ngtcp2_tstamp ngtcp2_conn_earliest_expiry(ngtcp2_conn *conn) {
  ngtcp2_rtb_entry *ent = ngtcp2_rtb_top(&conn->rtb);

  if (ent == NULL) {
    return 0;
  }

  return ent->expiry;
}

int ngtcp2_pkt_chain_new(ngtcp2_pkt_chain **ppc, const uint8_t *pkt,
                         size_t pktlen, ngtcp2_tstamp ts, ngtcp2_mem *mem) {
  *ppc = ngtcp2_mem_malloc(mem, sizeof(ngtcp2_pkt_chain) + pktlen);
  if (*ppc == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  (*ppc)->next = NULL;
  (*ppc)->pkt = (uint8_t *)(*ppc) + sizeof(ngtcp2_pkt_chain);
  (*ppc)->pktlen = pktlen;
  (*ppc)->ts = ts;

  memcpy((*ppc)->pkt, pkt, pktlen);

  return 0;
}

void ngtcp2_pkt_chain_del(ngtcp2_pkt_chain *pc, ngtcp2_mem *mem) {
  ngtcp2_mem_free(mem, pc);
}
