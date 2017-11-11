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

#include "ngtcp2_ppe.h"
#include "ngtcp2_macro.h"

/*
 * conn_local_stream returns nonzero if |stream_id| indicates that it
 * is the stream initiated by local endpoint.
 */
static int conn_local_stream(ngtcp2_conn *conn, uint32_t stream_id) {
  if (conn->server) {
    return stream_id % 2 == 0;
  }
  return stream_id % 2 != 0;
}

static int conn_call_recv_client_initial(ngtcp2_conn *conn) {
  int rv;

  assert(conn->callbacks.recv_client_initial);

  rv = conn->callbacks.recv_client_initial(conn, conn->client_conn_id,
                                           conn->user_data);
  if (rv != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

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

static int conn_call_recv_stream_data(ngtcp2_conn *conn, ngtcp2_strm *strm,
                                      uint8_t fin, const uint8_t *data,
                                      size_t datalen) {
  int rv;

  if (!conn->callbacks.recv_stream_data) {
    return 0;
  }

  rv = conn->callbacks.recv_stream_data(conn, strm->stream_id, fin, data,
                                        datalen, conn->user_data,
                                        strm->stream_user_data);
  if (rv != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int conn_call_stream_close(ngtcp2_conn *conn, ngtcp2_strm *strm,
                                  uint16_t app_error_code) {
  int rv;

  if (!conn->callbacks.stream_close) {
    return 0;
  }

  rv = conn->callbacks.stream_close(conn, strm->stream_id, app_error_code,
                                    conn->user_data, strm->stream_user_data);
  if (rv != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int conn_call_extend_max_stream_id(ngtcp2_conn *conn,
                                          uint32_t max_stream_id) {
  int rv;

  if (!conn->callbacks.extend_max_stream_id) {
    return 0;
  }

  rv = conn->callbacks.extend_max_stream_id(conn, max_stream_id,
                                            conn->user_data);
  if (rv != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int conn_new(ngtcp2_conn **pconn, uint64_t conn_id, uint32_t version,
                    const ngtcp2_conn_callbacks *callbacks,
                    const ngtcp2_settings *settings, void *user_data,
                    int server) {
  int rv;
  ngtcp2_mem *mem = ngtcp2_mem_default();

  *pconn = ngtcp2_mem_calloc(mem, 1, sizeof(ngtcp2_conn));
  if (*pconn == NULL) {
    rv = NGTCP2_ERR_NOMEM;
    goto fail_conn;
  }

  (*pconn)->strm0 = ngtcp2_mem_malloc(mem, sizeof(ngtcp2_strm));
  if ((*pconn)->strm0 == NULL) {
    rv = NGTCP2_ERR_NOMEM;
    goto fail_strm0_malloc;
  }
  /* TODO Initial max_stream_data for stream 0? */
  rv = ngtcp2_strm_init((*pconn)->strm0, 0, NGTCP2_STRM_FLAG_NONE,
                        settings->max_stream_data, NGTCP2_STRM0_MAX_STREAM_DATA,
                        NULL, mem);
  if (rv != 0) {
    goto fail_strm0_init;
  }

  rv = ngtcp2_map_init(&(*pconn)->strms, mem);
  if (rv != 0) {
    goto fail_strms_init;
  }

  rv = ngtcp2_map_insert(&(*pconn)->strms, &(*pconn)->strm0->me);
  if (rv != 0) {
    goto fail_strms_insert;
  }

  rv = ngtcp2_idtr_init(&(*pconn)->local_idtr, server, mem);
  if (rv != 0) {
    goto fail_local_idtr_init;
  }

  rv = ngtcp2_idtr_init(&(*pconn)->remote_idtr, !server, mem);
  if (rv != 0) {
    goto fail_remote_idtr_init;
  }

  rv = ngtcp2_acktr_init(&(*pconn)->acktr, mem);
  if (rv != 0) {
    goto fail_acktr_init;
  }

  ngtcp2_rtb_init(&(*pconn)->rtb, mem);

  (*pconn)->callbacks = *callbacks;
  (*pconn)->conn_id = conn_id;
  (*pconn)->version = version;
  (*pconn)->mem = mem;
  (*pconn)->user_data = user_data;

  (*pconn)->local_settings = *settings;
  (*pconn)->max_remote_stream_id = settings->max_stream_id;
  (*pconn)->unsent_max_rx_offset_high = (*pconn)->max_rx_offset_high =
      settings->max_data;
  (*pconn)->server = server;
  (*pconn)->state =
      server ? NGTCP2_CS_SERVER_INITIAL : NGTCP2_CS_CLIENT_INITIAL;

  return 0;

fail_acktr_init:
  ngtcp2_idtr_free(&(*pconn)->remote_idtr);
fail_remote_idtr_init:
  ngtcp2_idtr_free(&(*pconn)->local_idtr);
fail_local_idtr_init:
fail_strms_insert:
  ngtcp2_map_free(&(*pconn)->strms);
fail_strms_init:
  ngtcp2_strm_free((*pconn)->strm0);
fail_strm0_init:
  ngtcp2_mem_free(mem, (*pconn)->strm0);
fail_strm0_malloc:
  ngtcp2_mem_free(mem, *pconn);
fail_conn:
  return rv;
}

int ngtcp2_conn_client_new(ngtcp2_conn **pconn, uint64_t conn_id,
                           uint32_t version,
                           const ngtcp2_conn_callbacks *callbacks,
                           const ngtcp2_settings *settings, void *user_data) {
  return conn_new(pconn, conn_id, version, callbacks, settings, user_data, 0);
}

int ngtcp2_conn_server_new(ngtcp2_conn **pconn, uint64_t conn_id,
                           uint32_t version,
                           const ngtcp2_conn_callbacks *callbacks,
                           const ngtcp2_settings *settings, void *user_data) {
  return conn_new(pconn, conn_id, version, callbacks, settings, user_data, 1);
}

static void delete_buffed_pkts(ngtcp2_pkt_chain *pc, ngtcp2_mem *mem) {
  ngtcp2_pkt_chain *next;

  for (; pc;) {
    next = pc->next;
    ngtcp2_pkt_chain_del(pc, mem);
    pc = next;
  }
}

static void delete_frq(ngtcp2_frame_chain *frc, ngtcp2_mem *mem) {
  ngtcp2_frame_chain *next;
  for (; frc;) {
    next = frc->next;
    ngtcp2_frame_chain_del(frc, mem);
    frc = next;
  }
}

static int delete_strms_each(ngtcp2_map_entry *ent, void *ptr) {
  ngtcp2_mem *mem = ptr;
  ngtcp2_strm *s = ngtcp2_struct_of(ent, ngtcp2_strm, me);

  ngtcp2_strm_free(s);
  ngtcp2_mem_free(mem, s);

  return 0;
}

void ngtcp2_conn_del(ngtcp2_conn *conn) {
  if (conn == NULL) {
    return;
  }

  free(conn->decrypt_buf.base);

  delete_buffed_pkts(conn->buffed_rx_ppkts, conn->mem);

  ngtcp2_acktr_free(&conn->acktr);

  ngtcp2_crypto_km_del(conn->rx_ckm, conn->mem);
  ngtcp2_crypto_km_del(conn->tx_ckm, conn->mem);

  ngtcp2_crypto_km_del(conn->hs_rx_ckm, conn->mem);
  ngtcp2_crypto_km_del(conn->hs_tx_ckm, conn->mem);

  delete_frq(conn->frq, conn->mem);

  ngtcp2_rtb_free(&conn->rtb);

  ngtcp2_idtr_free(&conn->remote_idtr);
  ngtcp2_idtr_free(&conn->local_idtr);
  ngtcp2_map_each_free(&conn->strms, delete_strms_each, conn->mem);
  ngtcp2_map_free(&conn->strms);

  ngtcp2_mem_free(conn->mem, conn);
}

/* conn_set_next_ack_expiry sets the next ACK timeout. */
static void conn_set_next_ack_expiry(ngtcp2_conn *conn, ngtcp2_tstamp ts) {
  conn->next_ack_expiry = ts + NGTCP2_DELAYED_ACK_TIMEOUT;
  conn->immediate_ack = 0;
}

/* conn_invalidate_next_ack_expiry invalidates ACK timeout.  It makes
   ACK timeout not expire. */
static void conn_invalidate_next_ack_expiry(ngtcp2_conn *conn) {
  conn->next_ack_expiry = 0;
  conn->immediate_ack = 0;
}

static void conn_immediate_ack(ngtcp2_conn *conn) { conn->immediate_ack = 1; }

/*
 * conn_next_ack_expired returns nonzero if the next delayed ack timer
 * is expired.
 */
static int conn_next_ack_expired(ngtcp2_conn *conn, ngtcp2_tstamp ts) {
  return conn->immediate_ack ||
         (conn->next_ack_expiry && conn->next_ack_expiry <= ts);
}

/*
 * conn_ensure_ack_blks makes sure that |(*pfr)->ack.blks| can contain
 * at least |n| ngtcp2_ack_blk.  |*pfr| points to the ngtcp2_frame
 * object.  |*pnum_blks_max| is the number of ngtpc2_ack_blk which
 * |*pfr| can contain.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 */
static int conn_ensure_ack_blks(ngtcp2_conn *conn, ngtcp2_frame **pfr,
                                size_t *pnum_blks_max, size_t n) {
  ngtcp2_frame *fr;

  if (n <= *pnum_blks_max) {
    return 0;
  }

  *pnum_blks_max *= 2;
  fr = ngtcp2_mem_realloc(conn->mem, *pfr,
                          sizeof(ngtcp2_ack) +
                              sizeof(ngtcp2_ack_blk) * (*pnum_blks_max - 1));
  if (fr == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  *pfr = fr;

  return 0;
}

/*
 * conn_create_ack_frame creates ACK frame, and assigns its pointer to
 * |*pfr| if there are any received packets to acknowledge.  If there
 * are no packets to acknowledge, this function returns 0, and |*pfr|
 * is untouched.  The caller is advised to set |*pfr| to NULL before
 * calling this function, and check it after this function returns.
 *
 * The memory for ACK frame is dynamically allocated by this function.
 * A caller is responsible to free it.
 *
 * Call conn_commit_tx_ack after a created ACK frame is successfully
 * serialized into a packet.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 */
static int conn_create_ack_frame(ngtcp2_conn *conn, ngtcp2_frame **pfr,
                                 ngtcp2_tstamp ts) {
  uint64_t first_pkt_num;
  uint64_t last_pkt_num;
  ngtcp2_ack_blk *blk;
  int initial = 1;
  uint64_t gap;
  ngtcp2_acktr_entry **prpkt;
  ngtcp2_frame *fr;
  ngtcp2_ack *ack;
  /* TODO Measure an actual size of ACK bloks to find the best default
     value. */
  size_t num_blks_max = 8;
  size_t blk_idx;
  int rv;

  if (!conn->acktr.active_ack) {
    conn_invalidate_next_ack_expiry(conn);
    return 0;
  }

  prpkt = ngtcp2_acktr_get(&conn->acktr);
  if (*prpkt == NULL) {
    /* TODO This might not be necessary if we don't forget ACK. */
    conn_invalidate_next_ack_expiry(conn);
    return 0;
  }

  fr = ngtcp2_mem_malloc(
      conn->mem, sizeof(ngtcp2_ack) + sizeof(ngtcp2_ack_blk) * num_blks_max);
  if (fr == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  ack = &fr->ack;

  first_pkt_num = last_pkt_num = (*prpkt)->pkt_num;

  ack->type = NGTCP2_FRAME_ACK;
  ack->largest_ack = first_pkt_num;
  ack->ack_delay =
      (ts - (*prpkt)->tstamp) >> conn->local_settings.ack_delay_exponent;
  ack->num_blks = 0;

  prpkt = &(*prpkt)->next;

  for (; *prpkt; prpkt = &(*prpkt)->next) {
    if ((*prpkt)->pkt_num + 1 == last_pkt_num) {
      last_pkt_num = (*prpkt)->pkt_num;
      continue;
    }

    if (initial) {
      initial = 0;
      ack->first_ack_blklen = first_pkt_num - last_pkt_num;
    } else {
      blk_idx = ack->num_blks++;
      rv = conn_ensure_ack_blks(conn, &fr, &num_blks_max, ack->num_blks);
      if (rv != 0) {
        ngtcp2_mem_free(conn->mem, fr);
        return rv;
      }
      ack = &fr->ack;
      blk = &ack->blks[blk_idx];
      blk->gap = gap;
      blk->blklen = first_pkt_num - last_pkt_num;
    }

    gap = last_pkt_num - (*prpkt)->pkt_num - 2;
    first_pkt_num = last_pkt_num = (*prpkt)->pkt_num;

    if (ack->num_blks == NGTCP2_MAX_ACK_BLKS) {
      break;
    }
  }

  if (initial) {
    ack->first_ack_blklen = first_pkt_num - last_pkt_num;
  } else if (first_pkt_num != last_pkt_num) {
    blk_idx = ack->num_blks++;
    rv = conn_ensure_ack_blks(conn, &fr, &num_blks_max, ack->num_blks);
    if (rv != 0) {
      ngtcp2_mem_free(conn->mem, fr);
      return rv;
    }
    ack = &fr->ack;
    blk = &ack->blks[blk_idx];
    blk->gap = gap;
    blk->blklen = first_pkt_num - last_pkt_num;
  }

  /* TODO Just remove entries which cannot be fit into a single ACK
     frame for now. */
  if (*prpkt) {
    ngtcp2_acktr_forget(&conn->acktr, *prpkt);
  }

  *pfr = fr;

  return 0;
}

/*
 * conn_commit_tx_ack should be called when creating ACK is
 * successful, and it is serialized in a packet.
 */
static void conn_commit_tx_ack(ngtcp2_conn *conn) {
  conn_invalidate_next_ack_expiry(conn);

  conn->acktr.active_ack = 0;
}

/*
 * conn_ppe_write_frame writes |fr| to |ppe|.  If
 * |*psend_pkt_cb_called| is zero, conn_call_send_pkt is called, and 1
 * is assigned to it.  Regardless of the value of
 * |*psend_pkt_cb_called|, conn_call_send_frame is called.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User-defined callback function failed.
 * NGTCP2_ERR_NOBUF
 *     Buffer is too small.
 */
static int conn_ppe_write_frame(ngtcp2_conn *conn, ngtcp2_ppe *ppe,
                                int *psend_pkt_cb_called,
                                const ngtcp2_pkt_hd *hd, ngtcp2_frame *fr) {
  int rv;

  rv = ngtcp2_ppe_encode_frame(ppe, fr);
  if (rv != 0) {
    return rv;
  }

  if (!*psend_pkt_cb_called) {
    rv = conn_call_send_pkt(conn, hd);
    if (rv != 0) {
      return rv;
    }
    *psend_pkt_cb_called = 1;
  }

  return conn_call_send_frame(conn, hd, fr);
}

/*
 * conn_retransmit_unprotected writes QUIC packet in the buffer
 * pointed by |dest| whose length is |destlen| to retransmit lost
 * unprotected packet.
 *
 * This function returns the number of bytes written into |dest| if it
 * succeeds, or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User-defined callback function failed
 * NGTCP2_ERR_NOBUF
 *     Buffer does not have enough capacity
 */
static ssize_t conn_retransmit_unprotected(ngtcp2_conn *conn, uint8_t *dest,
                                           size_t destlen,
                                           ngtcp2_rtb_entry *ent,
                                           ngtcp2_tstamp ts) {
  int rv;
  ngtcp2_ppe ppe;
  ngtcp2_pkt_hd hd = ent->hd;
  ngtcp2_frame_chain **pfrc;
  ngtcp2_rtb_entry *nent = NULL;
  ngtcp2_frame localfr;
  int pkt_empty = 1;
  int send_pkt_cb_called = 0;
  ssize_t nwrite;
  ngtcp2_crypto_ctx ctx;

  /* This is required because ent->hd may have old client version. */
  hd.version = conn->version;
  hd.conn_id = conn->conn_id;
  hd.pkt_num = conn->last_tx_pkt_num + 1;

  ctx.ckm = conn->hs_tx_ckm;
  ctx.aead_overhead = NGTCP2_HANDSHAKE_AEAD_OVERHEAD;
  ctx.encrypt = conn->callbacks.hs_encrypt;
  ctx.user_data = conn;

  ngtcp2_ppe_init(&ppe, dest, destlen, &ctx);

  rv = ngtcp2_ppe_encode_hd(&ppe, &hd);
  if (rv != 0) {
    return rv;
  }

  /* TODO Don't include ACK in this unprotected packet in order not to
     ack protected packet here for now. */

  for (pfrc = &ent->frc; *pfrc;) {
    rv = conn_ppe_write_frame(conn, &ppe, &send_pkt_cb_called, &hd,
                              &(*pfrc)->fr);
    if (rv != 0) {
      if (rv == NGTCP2_ERR_NOBUF) {
        break;
      }
      return rv;
    }

    pkt_empty = 0;
    pfrc = &(*pfrc)->next;
  }

  if (pkt_empty) {
    return rv;
  }

  if (*pfrc == NULL) {
    /* We have retransmit complete packet.  Update ent with new packet
       header, and push it into rtb again. */
    ent->hd = hd;
    ngtcp2_rtb_entry_extend_expiry(ent, ts);

    if (hd.type == NGTCP2_PKT_CLIENT_INITIAL) {
      localfr.type = NGTCP2_FRAME_PADDING;
      localfr.padding.len = ngtcp2_ppe_padding(&ppe);

      rv = conn_call_send_frame(conn, &hd, &localfr);
      if (rv != 0) {
        return rv;
      }
    }

    ++conn->last_tx_pkt_num;
    return ngtcp2_ppe_final(&ppe, NULL);
  }

  nwrite = ngtcp2_ppe_final(&ppe, NULL);
  if (nwrite < 0) {
    return nwrite;
  }

  if (*pfrc != ent->frc) {
    /* We have partially retransmitted lost frames.  Create new
       ngtcp2_rtb_entry to track down the sent packet. */
    rv = ngtcp2_rtb_entry_new(&nent, &hd, NULL, ts, ent->deadline,
                              (size_t)nwrite, NGTCP2_RTB_FLAG_UNPROTECTED,
                              conn->mem);
    if (rv != 0) {
      return rv;
    }

    nent->count = ent->count;
    ngtcp2_rtb_entry_extend_expiry(nent, ts);

    nent->frc = ent->frc;
    ent->frc = *pfrc;
    *pfrc = NULL;

    rv = ngtcp2_rtb_add(&conn->rtb, nent);
    if (rv != 0) {
      assert(NGTCP2_ERR_INVALID_ARGUMENT != rv);
      ngtcp2_rtb_entry_del(nent, conn->mem);
      return rv;
    }
  }

  ++conn->last_tx_pkt_num;

  return nwrite;
}

/*
 * conn_select_pkt_type selects shorted short packet type based on the
 * next packet number |pkt_num|.
 */
static uint8_t conn_select_pkt_type(ngtcp2_conn *conn, uint64_t pkt_num) {
  uint64_t n = pkt_num - conn->rtb.largest_acked;
  if (UINT64_MAX / 2 <= pkt_num) {
    return NGTCP2_PKT_03;
  }

  n = n * 2 + 1;

  if (n > 0xffff) {
    return NGTCP2_PKT_03;
  }
  if (n > 0xff) {
    return NGTCP2_PKT_02;
  }
  return NGTCP2_PKT_01;
}

/*
 * conn_retransmit_protected writes QUIC packet in the buffer pointed
 * by |dest| whose length is |destlen| to retransmit lost protected
 * packet.
 *
 * This function returns the number of bytes written in |dest| if it
 * succeeds, or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User-defined callback function failed.
 * NGTCP2_ERR_NOBUF
 *     Buffer is too small.
 */
static ssize_t conn_retransmit_protected(ngtcp2_conn *conn, uint8_t *dest,
                                         size_t destlen, ngtcp2_rtb_entry *ent,
                                         ngtcp2_tstamp ts) {
  int rv;
  ngtcp2_ppe ppe;
  ngtcp2_pkt_hd hd = ent->hd;
  ngtcp2_frame_chain **pfrc, *frc;
  ngtcp2_rtb_entry *nent = NULL;
  ngtcp2_frame *ackfr;
  int pkt_empty = 1;
  ssize_t nwrite;
  ngtcp2_crypto_ctx ctx;
  ngtcp2_strm *strm;
  int send_pkt_cb_called = 0;
  int ack_expired = conn_next_ack_expired(conn, ts);

  /* This is required because ent->hd may have old client version. */
  hd.version = conn->version;
  hd.conn_id = conn->conn_id;
  hd.pkt_num = conn->last_tx_pkt_num + 1;
  hd.type = conn_select_pkt_type(conn, hd.pkt_num);

  ctx.ckm = conn->tx_ckm;
  ctx.aead_overhead = conn->aead_overhead;
  ctx.encrypt = conn->callbacks.encrypt;
  ctx.user_data = conn;

  ngtcp2_ppe_init(&ppe, dest, destlen, &ctx);

  rv = ngtcp2_ppe_encode_hd(&ppe, &hd);
  if (rv != 0) {
    return rv;
  }

  for (pfrc = &ent->frc; *pfrc;) {
    switch ((*pfrc)->fr.type) {
    case NGTCP2_FRAME_STREAM:
      strm = ngtcp2_conn_find_stream(conn, (*pfrc)->fr.stream.stream_id);
      if (strm == NULL || (strm->flags & NGTCP2_STRM_FLAG_SENT_RST)) {
        frc = *pfrc;
        *pfrc = (*pfrc)->next;
        ngtcp2_frame_chain_del(frc, conn->mem);
        continue;
      }
      break;
    case NGTCP2_FRAME_STOP_SENDING:
      strm = ngtcp2_conn_find_stream(conn, (*pfrc)->fr.stop_sending.stream_id);
      if (strm == NULL || (strm->flags & NGTCP2_STRM_FLAG_SHUT_RD)) {
        frc = *pfrc;
        *pfrc = (*pfrc)->next;
        ngtcp2_frame_chain_del(frc, conn->mem);
      }
      break;
    case NGTCP2_FRAME_MAX_STREAM_ID:
      if ((*pfrc)->fr.max_stream_id.max_stream_id <
          conn->max_remote_stream_id) {
        frc = *pfrc;
        *pfrc = (*pfrc)->next;
        ngtcp2_frame_chain_del(frc, conn->mem);
        continue;
      }
      break;
    case NGTCP2_FRAME_MAX_STREAM_DATA:
      strm =
          ngtcp2_conn_find_stream(conn, (*pfrc)->fr.max_stream_data.stream_id);
      if (strm == NULL ||
          (*pfrc)->fr.max_stream_data.max_stream_data < strm->max_rx_offset) {
        frc = *pfrc;
        *pfrc = (*pfrc)->next;
        ngtcp2_frame_chain_del(frc, conn->mem);
        continue;
      }
      break;
    case NGTCP2_FRAME_MAX_DATA:
      if ((*pfrc)->fr.max_data.max_data < conn->max_rx_offset_high) {
        frc = *pfrc;
        *pfrc = (*pfrc)->next;
        ngtcp2_frame_chain_del(frc, conn->mem);
        continue;
      }
      break;
    }
    rv = conn_ppe_write_frame(conn, &ppe, &send_pkt_cb_called, &hd,
                              &(*pfrc)->fr);
    if (rv != 0) {
      if (rv == NGTCP2_ERR_NOBUF) {
        break;
      }
      return rv;
    }

    pkt_empty = 0;
    pfrc = &(*pfrc)->next;
  }

  if (pkt_empty) {
    return rv;
  }

  /* ACK is added last so that we don't send ACK only frame here. */
  ackfr = NULL;
  /* TODO Is it better to check the remaining space in packet? */
  if (ack_expired) {
    rv = conn_create_ack_frame(conn, &ackfr, ts);
    if (rv != 0) {
      return rv;
    }
    if (ackfr) {
      rv = conn_ppe_write_frame(conn, &ppe, &send_pkt_cb_called, &hd, ackfr);
      if (rv != 0) {
        ngtcp2_mem_free(conn->mem, ackfr);
        if (rv != NGTCP2_ERR_NOBUF) {
          return rv;
        }
      } else {
        conn_commit_tx_ack(conn);
        pkt_empty = 0;

        ngtcp2_acktr_add_ack(&conn->acktr, hd.pkt_num, &ackfr->ack, 0);
      }
    }
  }

  if (pkt_empty) {
    return rv;
  }

  if (*pfrc == NULL) {
    /* We have retransmit complete packet.  Update ent with new packet
       header, and push it into rtb again. */
    ent->hd = hd;
    ngtcp2_rtb_entry_extend_expiry(ent, ts);

    nwrite = ngtcp2_ppe_final(&ppe, NULL);
    if (nwrite < 0) {
      return nwrite;
    }

    ++conn->last_tx_pkt_num;

    return nwrite;
  }

  nwrite = ngtcp2_ppe_final(&ppe, NULL);
  if (nwrite < 0) {
    return nwrite;
  }

  if (*pfrc != ent->frc) {
    /* We have partially retransmitted lost frames.  Create new
       ngtcp2_rtb_entry to track down the sent packet. */
    rv = ngtcp2_rtb_entry_new(&nent, &hd, NULL, ts, ent->deadline,
                              (size_t)nwrite, NGTCP2_RTB_FLAG_NONE, conn->mem);
    if (rv != 0) {
      return rv;
    }

    nent->count = ent->count;
    ngtcp2_rtb_entry_extend_expiry(nent, ts);

    nent->frc = ent->frc;
    ent->frc = *pfrc;
    *pfrc = NULL;

    rv = ngtcp2_rtb_add(&conn->rtb, nent);
    if (rv != 0) {
      assert(NGTCP2_ERR_INVALID_ARGUMENT != rv);
      ngtcp2_rtb_entry_del(nent, conn->mem);
      return rv;
    }
  }

  ++conn->last_tx_pkt_num;

  return nwrite;
}

/*
 * conn_retransmit writes QUIC packet in the buffer pointed by |dest|
 * whose length is |destlen| to retransmit lost packet.
 *
 * This function returns the number of bytes written in |dest| if it
 * succeeds, or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User-defined callback function failed.
 * NGTCP2_ERR_NOBUF
 *     Buffer is too small.
 * NGTCP2_ERR_PKT_TIMEOUT
 *     Give up the retransmission of lost packet because of timeout.
 * NGTCP2_ERR_INVALID_ARGUMENT
 *     Packet type is unexpected.  TODO: This will be removed in the
 *     future.
 */
static ssize_t conn_retransmit(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                               ngtcp2_tstamp ts) {
  ngtcp2_rtb_entry *ent;
  ssize_t nwrite;
  int rv;

  for (;;) {
    ent = ngtcp2_rtb_top(&conn->rtb);
    if (ent == NULL || ent->expiry > ts) {
      return 0;
    }
    ngtcp2_rtb_pop(&conn->rtb);

    if (ent->deadline <= ts) {
      ngtcp2_rtb_entry_del(ent, conn->mem);
      return NGTCP2_ERR_PKT_TIMEOUT;
    }

    if (ent->hd.flags & NGTCP2_PKT_FLAG_LONG_FORM) {
      switch (ent->hd.type) {
      case NGTCP2_PKT_CLIENT_INITIAL:
      case NGTCP2_PKT_SERVER_CLEARTEXT:
      case NGTCP2_PKT_CLIENT_CLEARTEXT:
        /* Stop retransmitting cleartext packet after at least one
           protected packet is received, and decrypted
           successfully. */
        if (conn->flags & NGTCP2_CONN_FLAG_RECV_PROTECTED_PKT) {
          nwrite = 0;
          break;
        }
        nwrite = conn_retransmit_unprotected(conn, dest, destlen, ent, ts);
        break;
      default:
        /* TODO fix this */
        ngtcp2_rtb_entry_del(ent, conn->mem);
        return NGTCP2_ERR_INVALID_ARGUMENT;
      }
    } else {
      switch (ent->hd.type) {
      case NGTCP2_PKT_01:
      case NGTCP2_PKT_02:
      case NGTCP2_PKT_03:
        nwrite = conn_retransmit_protected(conn, dest, destlen, ent, ts);
        break;
      default:
        /* TODO fix this */
        ngtcp2_rtb_entry_del(ent, conn->mem);
        return NGTCP2_ERR_INVALID_ARGUMENT;
      }
    }

    if (nwrite <= 0) {
      if (nwrite == 0) {
        ngtcp2_rtb_entry_del(ent, conn->mem);
        continue;
      }
      if (nwrite == NGTCP2_ERR_NOBUF) {
        rv = ngtcp2_rtb_add(&conn->rtb, ent);
        if (rv != 0) {
          ngtcp2_rtb_entry_del(ent, conn->mem);
          assert(ngtcp2_err_fatal(rv));
          return rv;
        }
        return nwrite;
      }

      ngtcp2_rtb_entry_del(ent, conn->mem);
      return nwrite;
    }

    /* No retransmittable frame was written, and now ent is empty. */
    if (ent->frc == NULL) {
      ngtcp2_rtb_entry_del(ent, conn->mem);
      return nwrite;
    }

    ent->pktlen = (size_t)nwrite;
    rv = ngtcp2_rtb_add(&conn->rtb, ent);
    if (rv != 0) {
      ngtcp2_rtb_entry_del(ent, conn->mem);
      assert(ngtcp2_err_fatal(rv));
      return rv;
    }

    return nwrite;
  }
}

/*
 * conn_write_handshake_pkt writes handshake packet in the buffer
 * pointed by |dest| whose length is |destlen|.  |type| specifies long
 * packet type.  |tx_buf| contains cryptographic handshake data to
 * send.
 *
 * This function returns the number of bytes written in |dest| if it
 * succeeds, or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User-defined callback function failed.
 * NGTCP2_ERR_NOBUF
 *     Buffer is too small.
 */
static ssize_t conn_write_handshake_pkt(ngtcp2_conn *conn, uint8_t *dest,
                                        size_t destlen, uint8_t type,
                                        ngtcp2_buf *tx_buf, ngtcp2_tstamp ts) {
  int rv;
  ngtcp2_ppe ppe;
  ngtcp2_pkt_hd hd;
  ngtcp2_frame_chain *frc = NULL, **pfrc, *frc_head = NULL, *frc_next;
  ngtcp2_frame *fr, *ackfr, paddingfr;
  size_t nwrite;
  ssize_t spktlen;
  ngtcp2_crypto_ctx ctx;
  ngtcp2_rtb_entry *rtbent;
  int ack_expired = conn_next_ack_expired(conn, ts);

  pfrc = &frc_head;

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_LONG_FORM, type, conn->conn_id,
                     conn->last_tx_pkt_num + 1, conn->version);

  ctx.ckm = conn->hs_tx_ckm;
  ctx.aead_overhead = NGTCP2_HANDSHAKE_AEAD_OVERHEAD;
  ctx.encrypt = conn->callbacks.hs_encrypt;
  ctx.user_data = conn;

  ngtcp2_ppe_init(&ppe, dest, destlen, &ctx);

  rv = ngtcp2_ppe_encode_hd(&ppe, &hd);
  if (rv != 0) {
    return rv;
  }

  rv = conn_call_send_pkt(conn, &hd);
  if (rv != 0) {
    return rv;
  }

  /* Encode ACK here */
  if (type != NGTCP2_PKT_CLIENT_INITIAL && ack_expired) {
    ackfr = NULL;
    /* TODO Should we retransmit ACK frame? */
    rv = conn_create_ack_frame(conn, &ackfr, ts);
    if (rv != 0) {
      return rv;
    }
    if (ackfr) {
      rv = ngtcp2_ppe_encode_frame(&ppe, ackfr);
      if (rv != 0) {
        ngtcp2_mem_free(conn->mem, ackfr);
        return rv;
      }

      rv = conn_call_send_frame(conn, &hd, ackfr);
      if (rv != 0) {
        ngtcp2_mem_free(conn->mem, ackfr);
        return rv;
      }

      conn_commit_tx_ack(conn);

      ngtcp2_acktr_add_ack(&conn->acktr, hd.pkt_num, &ackfr->ack, 1);
    }

    if (ngtcp2_ppe_left(&ppe) < NGTCP2_STREAM_OVERHEAD + 1) {
      ++conn->last_tx_pkt_num;
      return ngtcp2_ppe_final(&ppe, NULL);
    }
  }

  nwrite = ngtcp2_min(ngtcp2_buf_len(tx_buf),
                      ngtcp2_ppe_left(&ppe) - NGTCP2_STREAM_OVERHEAD);

  if (nwrite != ngtcp2_buf_len(tx_buf) && type == NGTCP2_PKT_CLIENT_INITIAL) {
    rv = NGTCP2_ERR_NOBUF;
    goto fail;
  }

  if (nwrite > 0) {
    rv = ngtcp2_frame_chain_new(&frc, conn->mem);
    if (rv != 0) {
      goto fail;
    }

    *pfrc = frc;
    pfrc = &frc->next;

    fr = &frc->fr;

    /* TODO Make a function to create STREAM frame */
    fr->type = NGTCP2_FRAME_STREAM;
    fr->stream.flags = 0;
    fr->stream.fin = 0;
    fr->stream.stream_id = 0;
    fr->stream.offset = conn->strm0->tx_offset;
    fr->stream.datalen = nwrite;
    fr->stream.data = tx_buf->pos;

    rv = ngtcp2_ppe_encode_frame(&ppe, fr);
    if (rv != 0) {
      goto fail;
    }

    rv = conn_call_send_frame(conn, &hd, fr);
    if (rv != 0) {
      goto fail;
    }

    tx_buf->pos += nwrite;
    conn->strm0->tx_offset += nwrite;
  }

  if (type == NGTCP2_PKT_CLIENT_INITIAL) {
    paddingfr.type = NGTCP2_FRAME_PADDING;
    paddingfr.padding.len = ngtcp2_ppe_padding(&ppe);
    if (paddingfr.padding.len > 0) {
      rv = conn_call_send_frame(conn, &hd, &paddingfr);
      if (rv != 0) {
        goto fail;
      }
    }
  }

  spktlen = ngtcp2_ppe_final(&ppe, NULL);
  if (spktlen < 0) {
    rv = (int)spktlen;
    goto fail;
  }

  if (frc_head) {
    rv = ngtcp2_rtb_entry_new(&rtbent, &hd, frc_head, ts,
                              ts + NGTCP2_PKT_DEADLINE_PERIOD, (size_t)spktlen,
                              NGTCP2_RTB_FLAG_UNPROTECTED, conn->mem);
    if (rv != 0) {
      goto fail;
    }

    rv = ngtcp2_rtb_add(&conn->rtb, rtbent);
    if (rv != 0) {
      assert(NGTCP2_ERR_INVALID_ARGUMENT != rv);
      ngtcp2_rtb_entry_del(rtbent, conn->mem);
      return rv;
    }
  }

  ++conn->last_tx_pkt_num;

  return spktlen;

fail:
  for (frc = frc_head; frc;) {
    frc_next = frc->next;
    ngtcp2_frame_chain_del(frc, conn->mem);
    frc = frc_next;
  }
  return rv;
}

/*
 * conn_write_handshake_ack_pkt writes unprotected QUIC packet in the
 * buffer pointed by |dest| whose length is |destlen|.  The packet
 * only includes ACK frame if any ack is required.  |type| specifies
 * the long packet type.
 *
 * If there is no ACK frame to send, this function returns 0.
 *
 * This function returns the number of bytes written in |dest| if it
 * succeeds, or one of the following negative error codes:
 *
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User-defined callback function failed.
 * NGTCP2_ERR_NOBUF
 *     Buffer is too small.
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 */
static ssize_t conn_write_handshake_ack_pkt(ngtcp2_conn *conn, uint8_t *dest,
                                            size_t destlen, uint8_t type,
                                            ngtcp2_tstamp ts) {
  int rv;
  ngtcp2_ppe ppe;
  ngtcp2_pkt_hd hd;
  ngtcp2_frame *ackfr;
  ngtcp2_crypto_ctx ctx;
  int ack_expired = conn_next_ack_expired(conn, ts);

  if (!ack_expired) {
    return 0;
  }

  ackfr = NULL;
  rv = conn_create_ack_frame(conn, &ackfr, ts);
  if (rv != 0) {
    return rv;
  }
  if (!ackfr) {
    return 0;
  }

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_LONG_FORM, type, conn->conn_id,
                     conn->last_tx_pkt_num + 1, conn->version);

  ctx.ckm = conn->hs_tx_ckm;
  ctx.aead_overhead = NGTCP2_HANDSHAKE_AEAD_OVERHEAD;
  ctx.encrypt = conn->callbacks.hs_encrypt;
  ctx.user_data = conn;

  ngtcp2_ppe_init(&ppe, dest, destlen, &ctx);

  rv = ngtcp2_ppe_encode_hd(&ppe, &hd);
  if (rv != 0) {
    goto fail;
  }

  rv = conn_call_send_pkt(conn, &hd);
  if (rv != 0) {
    goto fail;
  }

  rv = ngtcp2_ppe_encode_frame(&ppe, ackfr);
  if (rv != 0) {
    goto fail;
  }

  rv = conn_call_send_frame(conn, &hd, ackfr);
  if (rv != 0) {
    goto fail;
  }

  conn_commit_tx_ack(conn);

  ngtcp2_acktr_add_ack(&conn->acktr, hd.pkt_num, &ackfr->ack, 1);

  ++conn->last_tx_pkt_num;

  return ngtcp2_ppe_final(&ppe, NULL);

fail:
  ngtcp2_mem_free(conn->mem, ackfr);
  return rv;
}

/*
 * conn_write_client_initial writes Client Initial packet in the
 * buffer pointed by |dest| whose length is |destlen|.
 *
 * This function returns the number of bytes written in |dest| if it
 * succeeds, or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User-defined callback function failed.
 * NGTCP2_ERR_NOBUF
 *     Buffer is too small.
 */
static ssize_t conn_write_client_initial(ngtcp2_conn *conn, uint8_t *dest,
                                         size_t destlen, ngtcp2_tstamp ts) {
  uint64_t pkt_num = 0;
  const uint8_t *payload;
  ssize_t payloadlen;
  ngtcp2_buf *tx_buf = &conn->strm0->tx_buf;

  payloadlen = conn->callbacks.send_client_initial(
      conn, NGTCP2_CONN_FLAG_NONE,
      (conn->flags & NGTCP2_CONN_FLAG_STATELESS_RETRY) ? NULL : &pkt_num,
      &payload, conn->user_data);

  if (payloadlen <= 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  ngtcp2_buf_init(tx_buf, (uint8_t *)payload, (size_t)payloadlen);
  tx_buf->last += payloadlen;

  if (!(conn->flags & NGTCP2_CONN_FLAG_STATELESS_RETRY)) {
    conn->last_tx_pkt_num = pkt_num - 1;
  }

  return conn_write_handshake_pkt(conn, dest, destlen,
                                  NGTCP2_PKT_CLIENT_INITIAL, tx_buf, ts);
}

/*
 * conn_write_client_cleartext writes Client Cleartext packet in the
 * buffer pointed by |dest| whose length is |destlen|.
 *
 * This function returns the number of bytes written in |dest| if it
 * succeeds, or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User-defined callback function failed.
 * NGTCP2_ERR_NOBUF
 *     Buffer is too small.
 */
static ssize_t conn_write_client_cleartext(ngtcp2_conn *conn, uint8_t *dest,
                                           size_t destlen, ngtcp2_tstamp ts) {
  const uint8_t *payload;
  ssize_t payloadlen;
  ngtcp2_buf *tx_buf = &conn->strm0->tx_buf;

  if (ngtcp2_buf_len(tx_buf) == 0) {
    payloadlen = conn->callbacks.send_client_cleartext(
        conn, NGTCP2_CONN_FLAG_NONE, &payload, conn->user_data);

    if (payloadlen < 0) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    if (payloadlen == 0) {
      if (conn->state == NGTCP2_CS_CLIENT_TLS_HANDSHAKE_FAILED) {
        return NGTCP2_ERR_TLS_ALERT;
      }

      return conn_write_handshake_ack_pkt(conn, dest, destlen,
                                          NGTCP2_PKT_CLIENT_CLEARTEXT, ts);
    }

    ngtcp2_buf_init(tx_buf, (uint8_t *)payload, (size_t)payloadlen);
    tx_buf->last += payloadlen;
  }

  return conn_write_handshake_pkt(conn, dest, destlen,
                                  NGTCP2_PKT_CLIENT_CLEARTEXT, tx_buf, ts);
}

/*
 * conn_write_server_cleartext writes Server Cleartext packet in the
 * buffer pointed by |dest| whose length is |destlen|.
 *
 * This function returns the number of bytes written in |dest| if it
 * succeeds, or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User-defined callback function failed.
 * NGTCP2_ERR_NOBUF
 *     Buffer is too small.
 */
static ssize_t conn_write_server_cleartext(ngtcp2_conn *conn, uint8_t *dest,
                                           size_t destlen, int initial,
                                           ngtcp2_tstamp ts) {
  uint64_t pkt_num = 0;
  const uint8_t *payload;
  ssize_t payloadlen;
  ngtcp2_buf *tx_buf = &conn->strm0->tx_buf;

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
      if (conn->state == NGTCP2_CS_SERVER_TLS_HANDSHAKE_FAILED) {
        return NGTCP2_ERR_TLS_ALERT;
      }
      return conn_write_handshake_ack_pkt(conn, dest, destlen,
                                          NGTCP2_PKT_SERVER_CLEARTEXT, ts);
    }

    ngtcp2_buf_init(tx_buf, (uint8_t *)payload, (size_t)payloadlen);
    tx_buf->last += payloadlen;
  }

  if (initial) {
    conn->last_tx_pkt_num = pkt_num - 1;
    conn->rtb.largest_acked = conn->last_tx_pkt_num;
  }

  return conn_write_handshake_pkt(conn, dest, destlen,
                                  NGTCP2_PKT_SERVER_CLEARTEXT, tx_buf, ts);
}

/*
 * conn_should_send_max_stream_data returns nonzero if MAX_STREAM_DATA
 * frame should be send for |strm|.
 */
static int conn_should_send_max_stream_data(ngtcp2_conn *conn,
                                            ngtcp2_strm *strm) {
  return conn->local_settings.max_stream_data / 2 <
         (strm->unsent_max_rx_offset - strm->max_rx_offset);
}

/*
 * conn_should_send_max_data returns nonzero if MAX_DATA frame should
 * be sent.
 */
static int conn_should_send_max_data(ngtcp2_conn *conn) {
  return conn->local_settings.max_data / 2 >=
         conn->max_rx_offset_high - conn->rx_offset_high;
}

/*
 * conn_write_pkt writes a protected packet in the buffer pointed by
 * |dest| whose length if |destlen|.
 *
 * This function returns the number of bytes written in |dest| if it
 * succeeds, or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User-defined callback function failed.
 * NGTCP2_ERR_NOBUF
 *     Buffer is too small.
 */
static ssize_t conn_write_pkt(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                              ngtcp2_tstamp ts) {
  int rv;
  ngtcp2_ppe ppe;
  ngtcp2_pkt_hd hd;
  ngtcp2_frame *ackfr;
  ssize_t nwrite;
  ngtcp2_crypto_ctx ctx;
  ngtcp2_frame_chain **pfrc, *nfrc, *frc;
  ngtcp2_rtb_entry *ent;
  ngtcp2_strm *strm, *strm_next;
  int send_pkt_cb_called = 0;
  int pkt_empty = 1;
  int ack_expired = conn_next_ack_expired(conn, ts);

  ackfr = NULL;
  if (ack_expired) {
    rv = conn_create_ack_frame(conn, &ackfr, ts);
    if (rv != 0) {
      return rv;
    }
  }

  if ((ackfr || conn->frq || conn_should_send_max_data(conn)) &&
      conn->unsent_max_rx_offset_high > conn->max_rx_offset_high) {
    rv = ngtcp2_frame_chain_new(&nfrc, conn->mem);
    if (rv != 0) {
      goto fail;
    }
    nfrc->fr.type = NGTCP2_FRAME_MAX_DATA;
    nfrc->fr.max_data.max_data = conn->unsent_max_rx_offset_high;
    nfrc->next = conn->frq;
    conn->frq = nfrc;

    conn->max_rx_offset_high = conn->unsent_max_rx_offset_high;
  }

  while (conn->fc_strms) {
    strm = conn->fc_strms;
    rv = ngtcp2_frame_chain_new(&nfrc, conn->mem);
    if (rv != 0) {
      goto fail;
    }
    nfrc->fr.type = NGTCP2_FRAME_MAX_STREAM_DATA;
    nfrc->fr.max_stream_data.stream_id = strm->stream_id;
    nfrc->fr.max_stream_data.max_stream_data = strm->unsent_max_rx_offset;
    nfrc->next = conn->frq;
    conn->frq = nfrc;

    strm->max_rx_offset = strm->unsent_max_rx_offset;

    strm_next = strm->fc_next;
    conn->fc_strms = strm_next;
    if (strm_next) {
      strm_next->fc_pprev = &conn->fc_strms;
    }
    strm->fc_next = NULL;
    strm->fc_pprev = NULL;
    strm = strm_next;
  }

  if (!ackfr &&
      conn->max_remote_stream_id <= conn->local_settings.max_stream_id &&
      conn->frq == NULL) {
    return 0;
  }

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_CONN_ID,
                     conn_select_pkt_type(conn, conn->last_tx_pkt_num + 1),
                     conn->conn_id, conn->last_tx_pkt_num + 1, conn->version);

  ctx.ckm = conn->tx_ckm;
  ctx.aead_overhead = conn->aead_overhead;
  ctx.encrypt = conn->callbacks.encrypt;
  ctx.user_data = conn;

  ngtcp2_ppe_init(&ppe, dest, destlen, &ctx);

  rv = ngtcp2_ppe_encode_hd(&ppe, &hd);
  if (rv != 0) {
    goto fail;
  }

  if (ackfr) {
    rv = conn_ppe_write_frame(conn, &ppe, &send_pkt_cb_called, &hd, ackfr);
    if (rv != 0) {
      goto fail;
    }
    conn_commit_tx_ack(conn);
    pkt_empty = 0;

    ngtcp2_acktr_add_ack(&conn->acktr, hd.pkt_num, &ackfr->ack, 0);
    /* Now ackfr is owned by conn->acktr. */
    ackfr = NULL;
  }

  for (pfrc = &conn->frq; *pfrc;) {
    switch ((*pfrc)->fr.type) {
    case NGTCP2_FRAME_RST_STREAM:
      strm = ngtcp2_conn_find_stream(conn, (*pfrc)->fr.rst_stream.stream_id);
      if (strm == NULL &&
          (*pfrc)->fr.rst_stream.app_error_code != NGTCP2_STOPPING) {
        frc = *pfrc;
        *pfrc = (*pfrc)->next;
        ngtcp2_frame_chain_del(frc, conn->mem);
        continue;
      }
      break;
    case NGTCP2_FRAME_STOP_SENDING:
      strm = ngtcp2_conn_find_stream(conn, (*pfrc)->fr.stop_sending.stream_id);
      if (strm == NULL || (strm->flags & NGTCP2_STRM_FLAG_SHUT_RD)) {
        frc = *pfrc;
        *pfrc = (*pfrc)->next;
        ngtcp2_frame_chain_del(frc, conn->mem);
        continue;
      }
      break;
    }

    rv = conn_ppe_write_frame(conn, &ppe, &send_pkt_cb_called, &hd,
                              &(*pfrc)->fr);
    if (rv != 0) {
      assert(NGTCP2_ERR_NOBUF == rv);
      break;
    }

    pkt_empty = 0;
    pfrc = &(*pfrc)->next;
  }

  /* Write MAX_STREAM_ID after RST_STREAM so that we can extend stream
     ID space in one packet. */
  if (rv != NGTCP2_ERR_NOBUF && *pfrc == NULL &&
      conn->max_remote_stream_id > conn->local_settings.max_stream_id) {
    rv = ngtcp2_frame_chain_new(&nfrc, conn->mem);
    if (rv != 0) {
      return rv;
    }
    nfrc->fr.type = NGTCP2_FRAME_MAX_STREAM_ID;
    nfrc->fr.max_stream_id.max_stream_id = conn->max_remote_stream_id;
    *pfrc = nfrc;

    conn->local_settings.max_stream_id = conn->max_remote_stream_id;

    rv = conn_ppe_write_frame(conn, &ppe, &send_pkt_cb_called, &hd,
                              &(*pfrc)->fr);
    if (rv != 0) {
      assert(NGTCP2_ERR_NOBUF == rv);
    } else {
      pkt_empty = 0;
      pfrc = &(*pfrc)->next;
    }
  }

  if (pkt_empty) {
    return rv;
  }

  nwrite = ngtcp2_ppe_final(&ppe, NULL);
  if (nwrite < 0) {
    return nwrite;
  }

  if (*pfrc != conn->frq) {
    rv = ngtcp2_rtb_entry_new(&ent, &hd, NULL, ts,
                              ts + NGTCP2_PKT_DEADLINE_PERIOD, (size_t)nwrite,
                              NGTCP2_RTB_FLAG_NONE, conn->mem);
    if (rv != 0) {
      return rv;
    }

    ent->frc = conn->frq;
    conn->frq = *pfrc;
    *pfrc = NULL;

    rv = ngtcp2_rtb_add(&conn->rtb, ent);
    if (rv != 0) {
      assert(NGTCP2_ERR_INVALID_ARGUMENT != rv);
      ngtcp2_rtb_entry_del(ent, conn->mem);
      return rv;
    }
  }

  ++conn->last_tx_pkt_num;

  return nwrite;

fail:
  ngtcp2_mem_free(conn->mem, ackfr);
  return rv;
}

/*
 * conn_write_single_frame_pkt writes a protected packet which
 * contains |fr| frame only in the buffer pointed by |dest| whose
 * length if |destlen|.
 *
 * This function returns the number of bytes written in |dest| if it
 * succeeds, or one of the following negative error codes:
 *
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User-defined callback function failed.
 * NGTCP2_ERR_NOBUF
 *     Buffer is too small.
 */
static ssize_t conn_write_single_frame_pkt(ngtcp2_conn *conn, uint8_t *dest,
                                           size_t destlen, ngtcp2_frame *fr) {
  int rv;
  ngtcp2_ppe ppe;
  ngtcp2_pkt_hd hd;
  ssize_t nwrite;
  ngtcp2_crypto_ctx ctx;

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_CONN_ID,
                     conn_select_pkt_type(conn, conn->last_tx_pkt_num + 1),
                     conn->conn_id, conn->last_tx_pkt_num + 1, conn->version);

  ctx.ckm = conn->tx_ckm;
  ctx.aead_overhead = conn->aead_overhead;
  ctx.encrypt = conn->callbacks.encrypt;
  ctx.user_data = conn;

  ngtcp2_ppe_init(&ppe, dest, destlen, &ctx);

  rv = ngtcp2_ppe_encode_hd(&ppe, &hd);
  if (rv != 0) {
    return rv;
  }

  rv = conn_call_send_pkt(conn, &hd);
  if (rv != 0) {
    return rv;
  }

  rv = ngtcp2_ppe_encode_frame(&ppe, fr);
  if (rv != 0) {
    return rv;
  }

  rv = conn_call_send_frame(conn, &hd, fr);
  if (rv != 0) {
    return rv;
  }

  nwrite = ngtcp2_ppe_final(&ppe, NULL);
  if (nwrite < 0) {
    return nwrite;
  }

  /* Do this when we are sure that there is no error. */
  if (fr->type == NGTCP2_FRAME_ACK) {
    ngtcp2_acktr_add_ack(&conn->acktr, hd.pkt_num, &fr->ack, 0);
  }

  ++conn->last_tx_pkt_num;

  return nwrite;
}

/*
 * conn_write_protected_ack_pkt writes a protected QUIC packet which
 * only includes ACK frame in the buffer pointed by |dest| whose
 * length is |destlen|.
 *
 * This function returns the number of bytes written in |dest| if it
 * succeeds, or one of the following negative error codes:
 *
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User-defined callback function failed.
 * NGTCP2_ERR_NOBUF
 *     Buffer is too small.
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 */
static ssize_t conn_write_protected_ack_pkt(ngtcp2_conn *conn, uint8_t *dest,
                                            size_t destlen, ngtcp2_tstamp ts) {
  int rv;
  ssize_t spktlen;
  ngtcp2_frame *ackfr;
  int ack_expired = conn_next_ack_expired(conn, ts);

  if (!ack_expired) {
    return 0;
  }

  ackfr = NULL;
  rv = conn_create_ack_frame(conn, &ackfr, ts);
  if (rv != 0) {
    return rv;
  }

  if (!ackfr) {
    return 0;
  }

  spktlen = conn_write_single_frame_pkt(conn, dest, destlen, ackfr);
  if (spktlen < 0) {
    ngtcp2_mem_free(conn->mem, ackfr);
    return spktlen;
  }

  conn_commit_tx_ack(conn);

  return spktlen;
}

ssize_t ngtcp2_conn_write_pkt(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                              ngtcp2_tstamp ts) {
  ssize_t nwrite = 0;

  if (conn->last_tx_pkt_num == UINT64_MAX) {
    return NGTCP2_ERR_PKT_NUM_EXHAUSTED;
  }

  nwrite = conn_retransmit(conn, dest, destlen, ts);
  if (nwrite != 0) {
    return nwrite;
  }

  switch (conn->state) {
  case NGTCP2_CS_CLIENT_INITIAL:
    nwrite = conn_write_client_initial(conn, dest, destlen, ts);
    if (nwrite < 0) {
      break;
    }
    conn->state = NGTCP2_CS_CLIENT_WAIT_HANDSHAKE;
    break;
  case NGTCP2_CS_CLIENT_WAIT_HANDSHAKE:
    nwrite = conn_write_client_cleartext(conn, dest, destlen, ts);
    if (nwrite < 0) {
      break;
    }
    break;
  case NGTCP2_CS_CLIENT_HANDSHAKE_ALMOST_FINISHED:
    nwrite = conn_write_client_cleartext(conn, dest, destlen, ts);
    if (nwrite < 0) {
      break;
    }
    if (nwrite == 0) {
      conn->state = NGTCP2_CS_POST_HANDSHAKE;
      if (!(conn->flags & NGTCP2_CONN_FLAG_TRANSPORT_PARAM_RECVED)) {
        nwrite = NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM;
      }
    }
    break;
  case NGTCP2_CS_CLIENT_TLS_HANDSHAKE_FAILED:
    nwrite = conn_write_client_cleartext(conn, dest, destlen, ts);
    if (nwrite < 0) {
      break;
    }
    break;
  case NGTCP2_CS_SERVER_INITIAL:
    nwrite = conn_write_server_cleartext(conn, dest, destlen, 1, ts);
    if (nwrite < 0) {
      break;
    }
    conn->state = NGTCP2_CS_SERVER_WAIT_HANDSHAKE;
    break;
  case NGTCP2_CS_SERVER_WAIT_HANDSHAKE:
    nwrite = conn_write_server_cleartext(conn, dest, destlen, 0, ts);
    if (nwrite < 0) {
      break;
    }
    break;
  case NGTCP2_CS_SERVER_TLS_HANDSHAKE_FAILED:
    nwrite = conn_write_server_cleartext(conn, dest, destlen,
                                         conn->strm0->tx_offset == 0, ts);
    if (nwrite < 0) {
      break;
    }
    break;
  case NGTCP2_CS_POST_HANDSHAKE:
    nwrite = conn_write_pkt(conn, dest, destlen, ts);
    if (nwrite < 0) {
      break;
    }
  }

  return nwrite;
}

ssize_t ngtcp2_conn_write_ack_pkt(ngtcp2_conn *conn, uint8_t *dest,
                                  size_t destlen, ngtcp2_tstamp ts) {
  ssize_t nwrite = 0;

  if (conn->last_tx_pkt_num == UINT64_MAX) {
    return NGTCP2_ERR_PKT_NUM_EXHAUSTED;
  }

  nwrite = conn_retransmit(conn, dest, destlen, ts);
  if (nwrite != 0) {
    return nwrite;
  }

  switch (conn->state) {
  case NGTCP2_CS_CLIENT_INITIAL:
  case NGTCP2_CS_CLIENT_WAIT_HANDSHAKE:
  case NGTCP2_CS_CLIENT_HANDSHAKE_ALMOST_FINISHED:
  case NGTCP2_CS_SERVER_INITIAL:
  case NGTCP2_CS_SERVER_WAIT_HANDSHAKE:
    nwrite =
        conn_write_handshake_ack_pkt(conn, dest, destlen,
                                     conn->server ? NGTCP2_PKT_SERVER_CLEARTEXT
                                                  : NGTCP2_PKT_CLIENT_CLEARTEXT,
                                     ts);
    break;
  case NGTCP2_CS_POST_HANDSHAKE:
    nwrite = conn_write_protected_ack_pkt(conn, dest, destlen, ts);
    break;
  }

  return nwrite;
}

/*
 * conn_on_version_negotiation is called when Version Negotiation
 * packet is received.  The function decodes the data in the buffer
 * pointed by |pkt| whose length is |pktlen| as Version Negotiation
 * packet payload.  The packet header is given in |hd|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User-defined callback function failed.
 * NGTCP2_ERR_PROTO
 *     Packet payload is badly formatted.
 */
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
 * conn_recv_ack processes received ACK frame |fr|.  |unprotected| is
 * nonzero if |fr| is received in an unprotected packet.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_ACK_FRAME
 *     ACK frame is malformed.
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User callback failed.
 */
static int conn_recv_ack(ngtcp2_conn *conn, ngtcp2_ack *fr,
                         uint8_t unprotected) {
  int rv;
  rv = ngtcp2_pkt_validate_ack(fr);
  if (rv != 0) {
    return rv;
  }

  ngtcp2_acktr_recv_ack(&conn->acktr, fr, unprotected);

  return ngtcp2_rtb_recv_ack(&conn->rtb, fr, unprotected, conn);
}

/*
 * conn_recv_max_stream_data processes received MAX_STREAM_DATA frame
 * |fr|.
 */
static void conn_recv_max_stream_data(ngtcp2_conn *conn,
                                      const ngtcp2_max_stream_data *fr) {
  ngtcp2_strm *strm;

  strm = ngtcp2_conn_find_stream(conn, fr->stream_id);
  if (strm == NULL) {
    return;
  }

  strm->max_tx_offset = ngtcp2_max(strm->max_tx_offset, fr->max_stream_data);
}

/*
 * conn_recv_max_data processes received MAX_DATA frame |fr|.
 */
static void conn_recv_max_data(ngtcp2_conn *conn, const ngtcp2_max_data *fr) {
  conn->max_tx_offset_high = ngtcp2_max(conn->max_tx_offset_high, fr->max_data);
}

/*
 * conn_buffer_protected_pkt buffers a protected packet |pkt| whose
 * length is |pktlen|.  This function is called when a protected
 * packet is received, but the local endpoint has not established
 * cryptographic context (e.g., Client/Server Cleartext packet is
 * lost or delayed).
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 */
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

/*
 * conn_recv_server_stateless_retry resets connection state.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User callback failed.
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 */
static int conn_recv_server_stateless_retry(ngtcp2_conn *conn) {
  ngtcp2_strm *strm0;
  int rv;

  conn->flags |= NGTCP2_CONN_FLAG_STATELESS_RETRY;

  if (conn->callbacks.recv_server_stateless_retry) {
    rv = conn->callbacks.recv_server_stateless_retry(conn, conn->user_data);
    if (rv != 0) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
  }

  strm0 = ngtcp2_mem_malloc(conn->mem, sizeof(ngtcp2_strm));
  if (strm0 == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  rv = ngtcp2_strm_init(strm0, 0, NGTCP2_STRM_FLAG_NONE,
                        conn->local_settings.max_stream_data,
                        NGTCP2_STRM0_MAX_STREAM_DATA, NULL, conn->mem);
  if (rv != 0) {
    ngtcp2_mem_free(conn->mem, strm0);
    return rv;
  }

  conn->last_tx_pkt_num = 0;
  conn->max_rx_pkt_num = 0;

  ngtcp2_rtb_free(&conn->rtb);
  ngtcp2_acktr_free(&conn->acktr);
  ngtcp2_map_remove(&conn->strms, 0);
  ngtcp2_strm_free(conn->strm0);
  ngtcp2_mem_free(conn->mem, conn->strm0);

  conn->strm0 = strm0;

  ngtcp2_acktr_init(&conn->acktr, conn->mem);
  ngtcp2_rtb_init(&conn->rtb, conn->mem);
  ngtcp2_map_insert(&conn->strms, &conn->strm0->me);

  conn->flags &= (uint8_t)~NGTCP2_CONN_FLAG_CONN_ID_NEGOTIATED;
  conn->state = NGTCP2_CS_CLIENT_INITIAL;

  return 0;
}

/*
 * conn_ensure_decrypt_buffer ensures that conn->decrypt_buf has at
 * least |pktlen| bytes space.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 */
static int conn_ensure_decrypt_buffer(ngtcp2_conn *conn, size_t pktlen) {
  uint8_t *nbuf;
  size_t len;

  if (conn->decrypt_buf.len >= pktlen) {
    return 0;
  }

  len = conn->decrypt_buf.len == 0 ? 2048 : conn->decrypt_buf.len * 2;
  for (; len < pktlen; len *= 2)
    ;
  nbuf = ngtcp2_mem_realloc(conn->mem, conn->decrypt_buf.base, len);
  if (nbuf == NULL) {
    return NGTCP2_ERR_NOMEM;
  }
  conn->decrypt_buf.base = nbuf;
  conn->decrypt_buf.len = len;

  return 0;
}

/*
 * conn_decrypt_pkt decrypts the data pointed by |pkt| whose length is
 * |pktlen|, and writes cleartext data to the buffer pointed by |dest|
 * whose capacity is |destlen|.  The buffer pointed by |ad| is the
 * Additional Data, and its length is |adlen|.  |pkt_num| is used to
 * create a nonce.  |ckm| is the cryptographic key, and iv to use.
 * |decrypt| is a callback function which actually decrypts a packet.
 *
 * This function returns the number of bytes written in |dest| if it
 * succeeds, or one of the following negative error codes:
 *
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User callback failed.
 * NGTCP2_ERR_TLS_DECRYPT
 *     TLS backend failed to decrypt data.
 */
static ssize_t conn_decrypt_pkt(ngtcp2_conn *conn, uint8_t *dest,
                                size_t destlen, const uint8_t *pkt,
                                size_t pktlen, const uint8_t *ad, size_t adlen,
                                uint64_t pkt_num, ngtcp2_crypto_km *ckm,
                                ngtcp2_decrypt decrypt) {
  /* TODO nonce is limited to 64 bytes. */
  uint8_t nonce[64];
  ssize_t nwrite;

  assert(sizeof(nonce) >= ckm->ivlen);

  ngtcp2_crypto_create_nonce(nonce, ckm->iv, ckm->ivlen, pkt_num);

  nwrite = decrypt(conn, dest, destlen, pkt, pktlen, ckm->key, ckm->keylen,
                   nonce, ckm->ivlen, ad, adlen, conn->user_data);

  if (nwrite < 0) {
    if (nwrite == NGTCP2_ERR_TLS_DECRYPT) {
      return nwrite;
    }
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return nwrite;
}

static void conn_extend_max_stream_offset(ngtcp2_conn *conn, ngtcp2_strm *strm,
                                          size_t datalen) {
  if (strm->unsent_max_rx_offset <= UINT64_MAX - datalen) {
    strm->unsent_max_rx_offset += datalen;
  }

  if (!(strm->flags &
        (NGTCP2_STRM_FLAG_SHUT_RD | NGTCP2_STRM_FLAG_STOP_SENDING)) &&
      !strm->fc_pprev && conn_should_send_max_stream_data(conn, strm)) {
    strm->fc_pprev = &conn->fc_strms;
    if (conn->fc_strms) {
      strm->fc_next = conn->fc_strms;
      conn->fc_strms->fc_pprev = &strm->fc_next;
    }
    conn->fc_strms = strm;
  }
}

/*
 * conn_emit_pending_stream0_data delivers pending stream
 * data to the application due to packet reordering.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User callback failed
 * NGTCP2_ERR_TLS_HANDSHAKE
 *     TLS handshake failed, and TLS alert was sent.
 */
static int conn_emit_pending_stream0_data(ngtcp2_conn *conn, ngtcp2_strm *strm,
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

    rv =
        conn->callbacks.recv_stream0_data(conn, data, datalen, conn->user_data);
    if (rv != 0) {
      return rv;
    }

    strm->unsent_max_rx_offset += datalen;
    conn_extend_max_stream_offset(conn, strm, datalen);

    ngtcp2_rob_pop(&strm->rob, rx_offset - datalen, datalen);
  }
}

/*
 * conn_recv_handshake_pkt processes received packet |pkt| whose
 * length if |pktlen| during handshake period.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 * NGTCP2_ERR_INVALID_ARGUMENT
 *     Packet is too short; or it is not a long header.
 * NGTCP2_ERR_UNKNOWN_PKT_TYPE
 *     Packet type is unknown
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User-defined callback function failed.
 * NGTCP2_ERR_PROTO
 *     Generic QUIC protocol error.
 * NGTCP2_ERR_ACK_FRAME
 *     ACK frame is malformed.
 * NGTCP2_ERR_TLS_ALERT
 *     TLS handshake failed, and TLS alert was sent.
 * NGTCP2_ERR_FRAME_FORMAT
 *     Frame is badly formatted.
 * NGTCP2_ERR_VERSION_NEGOTIATION
 *     Version Negotiation packet is received.
 * NGTCP2_ERR_TLS_DECRYPT
 *     Could not decrypt a packet.
 */
static int conn_recv_handshake_pkt(ngtcp2_conn *conn, const uint8_t *pkt,
                                   size_t pktlen, ngtcp2_tstamp ts) {
  ssize_t nread;
  ngtcp2_pkt_hd hd;
  ngtcp2_max_frame mfr;
  ngtcp2_frame *fr = &mfr.fr;
  int rv;
  int require_ack = 0;
  uint64_t rx_offset;
  int handshake_failed = 0;
  uint64_t fr_end_offset;
  const uint8_t *hdpkt = pkt;
  ssize_t nwrite;

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
      if ((conn->flags & NGTCP2_CONN_FLAG_CONN_ID_NEGOTIATED) == 0) {
        conn->flags |= NGTCP2_CONN_FLAG_CONN_ID_NEGOTIATED;
        conn->client_conn_id = hd.conn_id;
        rv = conn_call_recv_client_initial(conn);
        if (rv != 0) {
          return rv;
        }
      }
      break;
    case NGTCP2_PKT_CLIENT_CLEARTEXT:
      break;
    default:
      return NGTCP2_ERR_PROTO;
    }
  } else {
    switch (hd.type) {
    case NGTCP2_PKT_SERVER_CLEARTEXT:
      if (conn->flags & NGTCP2_CONN_FLAG_CONN_ID_NEGOTIATED) {
        if (conn->conn_id != hd.conn_id) {
          return NGTCP2_ERR_PROTO;
        }
      } else {
        conn->flags |= NGTCP2_CONN_FLAG_CONN_ID_NEGOTIATED;
        conn->conn_id = hd.conn_id;
      }
      break;
    case NGTCP2_PKT_SERVER_STATELESS_RETRY:
      if (conn->strm0->last_rx_offset != 0 || conn->conn_id != hd.conn_id) {
        return NGTCP2_ERR_PROTO;
      }
      break;
    case NGTCP2_PKT_VERSION_NEGOTIATION:
      if (conn->conn_id != hd.conn_id) {
        return NGTCP2_ERR_PROTO;
      }
      rv = conn_on_version_negotiation(conn, &hd, pkt, pktlen);
      if (rv != 0) {
        return rv;
      }
      return NGTCP2_ERR_VERSION_NEGOTIATION;
    default:
      return NGTCP2_ERR_PROTO;
    }
  }

  rv = conn_ensure_decrypt_buffer(conn, pktlen);
  if (rv != 0) {
    return rv;
  }

  nwrite = conn_decrypt_pkt(conn, conn->decrypt_buf.base, pktlen, pkt, pktlen,
                            hdpkt, (size_t)nread, hd.pkt_num, conn->hs_rx_ckm,
                            conn->callbacks.hs_decrypt);
  if (nwrite < 0) {
    return (int)nwrite;
  }

  pkt = conn->decrypt_buf.base;
  pktlen = (size_t)nwrite;

  for (; pktlen;) {
    nread = ngtcp2_pkt_decode_frame(fr, pkt, pktlen);
    if (nread < 0) {
      return (int)nread;
    }

    pkt += nread;
    pktlen -= (size_t)nread;

    rv = conn_call_recv_frame(conn, &hd, fr);
    if (rv != 0) {
      return rv;
    }

    switch (fr->type) {
    case NGTCP2_FRAME_ACK:
      switch (hd.type) {
      case NGTCP2_PKT_CLIENT_INITIAL:
      case NGTCP2_PKT_SERVER_STATELESS_RETRY:
        return NGTCP2_ERR_PROTO;
      }
      /* TODO Assume that all packets here are unprotected */
      rv = conn_recv_ack(conn, &fr->ack, 1);
      if (rv != 0) {
        return rv;
      }
      continue;
    case NGTCP2_FRAME_PADDING:
      if (hd.type == NGTCP2_PKT_SERVER_STATELESS_RETRY) {
        return NGTCP2_ERR_PROTO;
      }
      continue;
    case NGTCP2_FRAME_STREAM:
      require_ack = 1;
      break;
    default:
      return NGTCP2_ERR_PROTO;
    }

    assert(fr->type == NGTCP2_FRAME_STREAM);

    if (fr->stream.stream_id != 0) {
      continue;
    }

    if (fr->stream.datalen == 0) {
      return NGTCP2_ERR_FRAME_FORMAT;
    }

    if (hd.type == NGTCP2_PKT_CLIENT_INITIAL && fr->stream.offset != 0) {
      return NGTCP2_ERR_PROTO;
    }

    if (fr->stream.fin) {
      return NGTCP2_ERR_PROTO;
    }

    fr_end_offset = fr->stream.offset + fr->stream.datalen;
    rx_offset = ngtcp2_strm_rx_offset(conn->strm0);
    if (rx_offset >= fr_end_offset) {
      continue;
    }

    conn->strm0->last_rx_offset =
        ngtcp2_max(conn->strm0->last_rx_offset, fr_end_offset);

    /* Although there is no way to send MAX_STREAM_DATA frame during a
       handshake, stream 0 is subject to stream-level flow control, so
       we have to verify it here.  The current consensus is that the
       initial max stream data should be sufficient for a
       handshake. */
    if (conn->strm0->max_rx_offset < fr_end_offset) {
      return NGTCP2_ERR_FLOW_CONTROL;
    }

    if (fr->stream.offset <= rx_offset) {
      size_t ncut = (rx_offset - fr->stream.offset);
      const uint8_t *data = fr->stream.data + ncut;
      size_t datalen = fr->stream.datalen - ncut;

      rx_offset += datalen;
      ngtcp2_rob_remove_prefix(&conn->strm0->rob, rx_offset);

      rv = conn->callbacks.recv_stream0_data(conn, data, datalen,
                                             conn->user_data);
      switch (rv) {
      case 0:
        break;
      case NGTCP2_ERR_TLS_ALERT:
        handshake_failed = 1;
        break;
      default:
        return rv;
      }

      conn->strm0->unsent_max_rx_offset += datalen;

      if (!handshake_failed) {
        rv = conn_emit_pending_stream0_data(conn, conn->strm0, rx_offset);
        if (rv != 0) {
          return rv;
        }
      }
    } else if (!handshake_failed) {
      rv = ngtcp2_strm_recv_reordering(conn->strm0, &fr->stream);
      if (rv != 0) {
        return rv;
      }
    }
  }

  switch (hd.type) {
  case NGTCP2_PKT_CLIENT_INITIAL:
  case NGTCP2_PKT_SERVER_STATELESS_RETRY:
    if (ngtcp2_rob_first_gap_offset(&conn->strm0->rob) == 0) {
      return NGTCP2_ERR_PROTO;
    }
    break;
  }

  conn->max_rx_pkt_num = ngtcp2_max(conn->max_rx_pkt_num, hd.pkt_num);

  if (hd.type == NGTCP2_PKT_SERVER_STATELESS_RETRY) {
    if (handshake_failed) {
      return NGTCP2_ERR_PROTO;
    }

    rv = conn_recv_server_stateless_retry(conn);
    if (rv != 0) {
      return rv;
    }

    return 0;
  }

  rv = ngtcp2_conn_sched_ack(conn, hd.pkt_num, require_ack, ts);
  if (rv != 0) {
    return rv;
  }

  return handshake_failed ? NGTCP2_ERR_TLS_ALERT : 0;
}

int ngtcp2_conn_init_stream(ngtcp2_conn *conn, ngtcp2_strm *strm,
                            uint32_t stream_id, void *stream_user_data) {
  int rv;

  rv = ngtcp2_strm_init(strm, stream_id, NGTCP2_STRM_FLAG_NONE,
                        conn->local_settings.max_stream_data,
                        conn->remote_settings.max_stream_data, stream_user_data,
                        conn->mem);
  if (rv != 0) {
    ngtcp2_mem_free(conn->mem, strm);
    return rv;
  }

  rv = ngtcp2_map_insert(&conn->strms, &strm->me);
  if (rv != 0) {
    assert(rv != NGTCP2_ERR_INVALID_ARGUMENT);

    ngtcp2_strm_free(strm);
    ngtcp2_mem_free(conn->mem, strm);
    return rv;
  }

  return 0;
}

/*
 * conn_emit_pending_stream_data passes buffered ordered stream data
 * to the application.  |rx_offset| is the first offset to deliver to
 * the application.  This function assumes that the data up to
 * |rx_offset| has been delivered already.  This function only passes
 * the ordered data without any gap.  If there is a gap, it stops
 * providing the data to the application, and returns.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User callback failed.
 */
static int conn_emit_pending_stream_data(ngtcp2_conn *conn, ngtcp2_strm *strm,
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

    rv = conn_call_recv_stream_data(conn, strm,
                                    (strm->flags & NGTCP2_STRM_FLAG_SHUT_RD) &&
                                        rx_offset == strm->last_rx_offset,
                                    data, datalen);
    if (rv != 0) {
      return rv;
    }

    ngtcp2_rob_pop(&strm->rob, rx_offset - datalen, datalen);
  }
}

/*
 * conn_max_data_violated returns nonzero if receiving |datalen|
 * violates connection flow control on local endpoint.
 */
static int conn_max_data_violated(ngtcp2_conn *conn, size_t datalen) {
  uint64_t left_high = conn->max_rx_offset_high - conn->rx_offset_high;
  uint64_t low = conn->rx_offset_low + datalen;
  uint64_t from_low = low / 1024;

  if (left_high == from_low) {
    return (low & 0x3ff) > 0;
  }

  return left_high < from_low;
}

void ngtcp2_increment_offset(uint64_t *offset_high, uint32_t *offset_low,
                             uint64_t datalen) {
  uint64_t datalen_high = datalen / 1024;
  uint32_t datalen_low = datalen & 0x3ff;

  if (*offset_high > UINT64_MAX - datalen_high) {
    *offset_high = UINT64_MAX;
    *offset_low = 0x3ff;
    return;
  }

  *offset_high += datalen_high;
  *offset_low += datalen_low;

  if (*offset_low <= 0x3ff) {
    return;
  }

  if (*offset_high == UINT64_MAX) {
    *offset_low = 0x3ff;
    return;
  }

  *offset_low &= 0x3ff;
  ++*offset_high;
}

static int conn_recv_stream(ngtcp2_conn *conn, const ngtcp2_stream *fr) {
  int rv;
  ngtcp2_strm *strm;
  uint64_t rx_offset, fr_end_offset;
  int local_stream;

  if (fr->stream_id == 0 && fr->fin) {
    return NGTCP2_ERR_PROTO;
  }

  if (!fr->fin && fr->datalen == 0) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  local_stream = conn_local_stream(conn, fr->stream_id);

  if (!local_stream && conn->local_settings.max_stream_id < fr->stream_id) {
    return NGTCP2_ERR_STREAM_ID;
  }

  if (UINT64_MAX - fr->datalen < fr->offset) {
    return NGTCP2_ERR_PROTO;
  }

  strm = ngtcp2_conn_find_stream(conn, fr->stream_id);
  if (strm == NULL) {
    if (local_stream) {
      rv = ngtcp2_idtr_is_open(&conn->local_idtr, fr->stream_id);
    } else {
      rv = ngtcp2_idtr_open(&conn->remote_idtr, fr->stream_id);
    }
    if (rv != 0) {
      if (rv == NGTCP2_ERR_STREAM_IN_USE) {
        /* TODO The stream has been closed.  This should be responded
           with RST_STREAM, or simply ignored. */
        return 0;
      }
      return rv;
    }

    strm = ngtcp2_mem_malloc(conn->mem, sizeof(ngtcp2_strm));
    if (strm == NULL) {
      return NGTCP2_ERR_NOMEM;
    }
    /* TODO Perhaps, call new_stream callback? */
    rv = ngtcp2_conn_init_stream(conn, strm, fr->stream_id, NULL);
    if (rv != 0) {
      return rv;
    }
  }

  fr_end_offset = fr->offset + fr->datalen;

  if (strm->max_rx_offset < fr_end_offset) {
    return NGTCP2_ERR_FLOW_CONTROL;
  }

  if (strm->last_rx_offset < fr_end_offset) {
    size_t datalen = fr_end_offset - strm->last_rx_offset;

    if (strm->stream_id != 0) {
      if (conn_max_data_violated(conn, datalen)) {
        return NGTCP2_ERR_FLOW_CONTROL;
      }

      ngtcp2_increment_offset(&conn->rx_offset_high, &conn->rx_offset_low,
                              datalen);
    }
  }

  if (fr->fin) {
    if (strm->flags & NGTCP2_STRM_FLAG_SHUT_RD) {
      if (strm->last_rx_offset != fr_end_offset) {
        return NGTCP2_ERR_FINAL_OFFSET;
      }
      return 0;
    } else if (strm->last_rx_offset > fr_end_offset) {
      return NGTCP2_ERR_FINAL_OFFSET;
    }

    strm->last_rx_offset = fr_end_offset;

    ngtcp2_strm_shutdown(strm, NGTCP2_STRM_FLAG_SHUT_RD);

    if (strm->flags & NGTCP2_STRM_FLAG_STOP_SENDING) {
      return ngtcp2_conn_close_stream_if_shut_rdwr(conn, strm,
                                                   strm->app_error_code);
    }

    /* Since strm is now in closed (remote), we don't have to send
       MAX_STREAM_DATA anymore. */
    if (strm->fc_pprev) {
      *strm->fc_pprev = strm->fc_next;
      if (strm->fc_next) {
        strm->fc_next->fc_pprev = strm->fc_pprev;
      }
      strm->fc_pprev = NULL;
      strm->fc_next = NULL;
    }

    rx_offset = ngtcp2_strm_rx_offset(strm);
    if (fr_end_offset == rx_offset) {
      rv = conn_call_recv_stream_data(conn, strm, 1, NULL, 0);
      if (rv != 0) {
        return rv;
      }
      return ngtcp2_conn_close_stream_if_shut_rdwr(conn, strm, NGTCP2_NO_ERROR);
    }
  } else {
    if ((strm->flags & NGTCP2_STRM_FLAG_SHUT_RD) &&
        strm->last_rx_offset < fr_end_offset) {
      return NGTCP2_ERR_FINAL_OFFSET;
    }

    strm->last_rx_offset = ngtcp2_max(strm->last_rx_offset, fr_end_offset);

    rx_offset = ngtcp2_strm_rx_offset(strm);
    if (fr_end_offset <= rx_offset) {
      return 0;
    }

    if (strm->flags & NGTCP2_STRM_FLAG_STOP_SENDING) {
      return 0;
    }
  }

  if (fr->offset <= rx_offset) {
    size_t ncut = rx_offset - fr->offset;
    const uint8_t *data = fr->data + ncut;
    size_t datalen = fr->datalen - ncut;

    rx_offset += datalen;
    ngtcp2_rob_remove_prefix(&strm->rob, rx_offset);

    rv = conn_call_recv_stream_data(conn, strm, fr->fin, data, datalen);
    if (rv != 0) {
      return rv;
    }

    if (strm->stream_id == 0) {
      rv = conn_emit_pending_stream0_data(conn, conn->strm0, rx_offset);
    } else {
      rv = conn_emit_pending_stream_data(conn, strm, rx_offset);
    }
    if (rv != 0) {
      return rv;
    }
  } else {
    rv = ngtcp2_strm_recv_reordering(strm, fr);
    if (rv != 0) {
      return rv;
    }
  }
  return ngtcp2_conn_close_stream_if_shut_rdwr(conn, strm, NGTCP2_NO_ERROR);
}

/*
 * conn_rst_stream adds RST_STREAM frame to the transmission queue.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 */
static int conn_rst_stream(ngtcp2_conn *conn, ngtcp2_strm *strm,
                           uint16_t app_error_code) {
  int rv;
  ngtcp2_frame_chain *frc;

  rv = ngtcp2_frame_chain_new(&frc, conn->mem);
  if (rv != 0) {
    return rv;
  }

  frc->fr.type = NGTCP2_FRAME_RST_STREAM;
  frc->fr.rst_stream.stream_id = strm->stream_id;
  frc->fr.rst_stream.app_error_code = app_error_code;
  frc->fr.rst_stream.final_offset = strm->tx_offset;

  /* TODO This prepends RST_STREAM to conn->frq. */
  frc->next = conn->frq;
  conn->frq = frc;

  return 0;
}

static int conn_stop_sending(ngtcp2_conn *conn, ngtcp2_strm *strm,
                             uint16_t app_error_code) {
  int rv;
  ngtcp2_frame_chain *frc;

  rv = ngtcp2_frame_chain_new(&frc, conn->mem);
  if (rv != 0) {
    return rv;
  }

  frc->fr.type = NGTCP2_FRAME_STOP_SENDING;
  frc->fr.stop_sending.stream_id = strm->stream_id;
  frc->fr.stop_sending.app_error_code = app_error_code;

  /* TODO This prepends STOP_SENDING to conn->frq. */
  frc->next = conn->frq;
  conn->frq = frc;

  /* Since STREAM is being reset, we don't have to send
     MAX_STREAM_DATA anymore */
  if (strm->fc_pprev) {
    *strm->fc_pprev = strm->fc_next;
    if (strm->fc_next) {
      strm->fc_next->fc_pprev = strm->fc_pprev;
    }
    strm->fc_pprev = NULL;
    strm->fc_next = NULL;
  }

  return 0;
}

static int conn_recv_rst_stream(ngtcp2_conn *conn,
                                const ngtcp2_rst_stream *fr) {
  ngtcp2_strm *strm;
  int local_stream = conn_local_stream(conn, fr->stream_id);
  uint64_t datalen;

  if (fr->stream_id == 0) {
    return NGTCP2_ERR_PROTO;
  }

  if (local_stream) {
    /* If RST_STREAM is sent to a stream initiated by local endpoint,
       conn->local_idtr must indicate that it has opened already, */
    if (!ngtcp2_idtr_is_open(&conn->local_idtr, fr->stream_id)) {
      return NGTCP2_ERR_PROTO;
    }
  } else if (fr->stream_id > conn->max_remote_stream_id) {
    return NGTCP2_ERR_STREAM_ID;
  }

  strm = ngtcp2_conn_find_stream(conn, fr->stream_id);
  if (strm == NULL) {
    if (!local_stream &&
        !ngtcp2_idtr_is_open(&conn->remote_idtr, fr->stream_id)) {
      /* Stream is reset before we create ngtcp2_strm object. */
      if (conn->local_settings.max_stream_data < fr->final_offset ||
          conn_max_data_violated(conn, fr->final_offset)) {
        return NGTCP2_ERR_FLOW_CONTROL;
      }
      ngtcp2_idtr_open(&conn->remote_idtr, fr->stream_id);
      ngtcp2_increment_offset(&conn->rx_offset_high, &conn->rx_offset_low,
                              fr->final_offset);
    }
    return 0;
  }

  if ((strm->flags & NGTCP2_STRM_FLAG_SHUT_RD)) {
    if (strm->last_rx_offset != fr->final_offset) {
      return NGTCP2_ERR_FINAL_OFFSET;
    }
  } else if (strm->last_rx_offset > fr->final_offset) {
    return NGTCP2_ERR_FINAL_OFFSET;
  }

  datalen = fr->final_offset - strm->last_rx_offset;

  if (strm->max_rx_offset < fr->final_offset ||
      conn_max_data_violated(conn, datalen)) {
    return NGTCP2_ERR_FLOW_CONTROL;
  }

  ngtcp2_increment_offset(&conn->rx_offset_high, &conn->rx_offset_low, datalen);

  strm->flags |= NGTCP2_STRM_FLAG_SHUT_RD | NGTCP2_STRM_FLAG_RECV_RST;

  return ngtcp2_conn_close_stream_if_shut_rdwr(conn, strm, fr->app_error_code);
}

static int conn_recv_stop_sending(ngtcp2_conn *conn,
                                  const ngtcp2_stop_sending *fr) {
  int rv;
  ngtcp2_strm *strm;
  int local_stream = conn_local_stream(conn, fr->stream_id);

  if (fr->stream_id == 0) {
    return NGTCP2_ERR_PROTO;
  }

  if (local_stream) {
    /* If STOP_SENDING is sent to a stream initiated by local
       endpoint, conn->local_idtr must indicate that it has opened
       already, */
    if (!ngtcp2_idtr_is_open(&conn->local_idtr, fr->stream_id)) {
      return NGTCP2_ERR_PROTO;
    }
  } else if (fr->stream_id > conn->max_remote_stream_id) {
    return NGTCP2_ERR_STREAM_ID;
  }

  strm = ngtcp2_conn_find_stream(conn, fr->stream_id);
  if (strm == NULL) {
    if (!local_stream &&
        !ngtcp2_idtr_is_open(&conn->remote_idtr, fr->stream_id)) {
      /* Frame is received reset before we create ngtcp2_strm
         object. */
      ngtcp2_idtr_open(&conn->remote_idtr, fr->stream_id);
    }
    return 0;
  }

  rv = conn_rst_stream(conn, strm, NGTCP2_STOPPING);
  if (rv != 0) {
    return rv;
  }

  strm->flags |= NGTCP2_STRM_FLAG_SHUT_WR | NGTCP2_STRM_FLAG_SENT_RST;

  return ngtcp2_conn_close_stream_if_shut_rdwr(conn, strm, fr->app_error_code);
}

static void conn_recv_connection_close(ngtcp2_conn *conn) {
  conn->state = NGTCP2_CS_CLOSE_WAIT;
}

/*
 * conn_on_stateless_reset decodes Stateless Reset from the buffer
 * pointed by |pkt| whose length is |pktlen|.  |pkt| should start
 * after Packet Number.  The short packet header, optional connection
 * ID, and Packet number are already parsed and removed from the
 * buffer.
 *
 * If Stateless Reset is decoded, and the Stateless Reset Token is
 * validated, the connection is closed.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_INVALID_ARGUMENT
 *     Could not decode Stateless Reset; or Stateless Reset Token does
 *     not match.
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User callback failed.
 */
static int conn_on_stateless_reset(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                                   const uint8_t *pkt, size_t pktlen) {
  int rv;
  ngtcp2_pkt_stateless_reset sr;
  const uint8_t *token;
  size_t i;

  rv = ngtcp2_pkt_decode_stateless_reset(&sr, pkt, pktlen);
  if (rv != 0) {
    return rv;
  }

  if (conn->server) {
    token = conn->local_settings.stateless_reset_token;
  } else {
    token = conn->remote_settings.stateless_reset_token;
  }

  for (i = 0; i < NGTCP2_STATELESS_RESET_TOKENLEN; ++i) {
    rv |= token[i] ^ sr.stateless_reset_token[i];
  }

  if (rv != 0) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  conn->state = NGTCP2_CS_CLOSE_WAIT;

  if (!conn->callbacks.recv_stateless_reset) {
    return 0;
  }

  rv = conn->callbacks.recv_stateless_reset(conn, hd, &sr, conn->user_data);
  if (rv != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

/*
 * conn_recv_delayed_handshake_pkt processes the received handshake
 * packet which is received after handshake completed.  This function
 * does the minimal job, and its purpose is send acknowledgement of
 * this packet to the peer.  We assume that hd->type is one of Client
 * Initial, Client Cleartext, or Server Cleartext.  |ad| and |adlen|
 * is an additional data and its length to decrypt a packet.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_PROTO
 *     Packet type is unexpected; or same packet number has already
 *     been added.
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User callback failed.
 * NGTCP2_ERR_FRAME_FORMAT
 *     Frame is badly formatted; or frame type is unknown.
 * NGTCP2_ERR_NOMEM
 *     Out of memory
 * NGTCP2_ERR_TLS_DECRYPT
 *     Could not decrypt a packet.
 */
static int conn_recv_delayed_handshake_pkt(ngtcp2_conn *conn,
                                           const ngtcp2_pkt_hd *hd,
                                           const uint8_t *pkt, size_t pktlen,
                                           const uint8_t *ad, size_t adlen,
                                           ngtcp2_tstamp ts) {
  ssize_t nread;
  ngtcp2_frame fr;
  int rv;
  int require_ack = 0;
  ssize_t nwrite;

  if (conn->server) {
    if (hd->type == NGTCP2_PKT_SERVER_CLEARTEXT) {
      return NGTCP2_ERR_PROTO;
    }
  } else {
    switch (hd->type) {
    case NGTCP2_PKT_CLIENT_INITIAL:
    case NGTCP2_PKT_CLIENT_CLEARTEXT:
      return NGTCP2_ERR_PROTO;
    }
  }

  rv = conn_ensure_decrypt_buffer(conn, pktlen);
  if (rv != 0) {
    return rv;
  }

  nwrite = conn_decrypt_pkt(conn, conn->decrypt_buf.base, pktlen, pkt, pktlen,
                            ad, adlen, hd->pkt_num, conn->hs_rx_ckm,
                            conn->callbacks.hs_decrypt);
  if (nwrite < 0) {
    return (int)nwrite;
  }

  pkt = conn->decrypt_buf.base;
  pktlen = (size_t)nwrite;

  for (; pktlen;) {
    nread = ngtcp2_pkt_decode_frame(&fr, pkt, pktlen);
    if (nread < 0) {
      return (int)nread;
    }

    pkt += nread;
    pktlen -= (size_t)nread;

    rv = conn_call_recv_frame(conn, hd, &fr);
    if (rv != 0) {
      return rv;
    }

    switch (fr.type) {
    case NGTCP2_FRAME_ACK:
      if (hd->type == NGTCP2_PKT_CLIENT_INITIAL) {
        return NGTCP2_ERR_PROTO;
      }
      rv = conn_recv_ack(conn, &fr.ack, 1);
      if (rv != 0) {
        return rv;
      }
      continue;
    case NGTCP2_FRAME_PADDING:
      break;
    case NGTCP2_FRAME_STREAM:
      require_ack = 1;
      break;
    default:
      return NGTCP2_ERR_PROTO;
    }
  }

  conn->max_rx_pkt_num = ngtcp2_max(conn->max_rx_pkt_num, hd->pkt_num);

  return ngtcp2_conn_sched_ack(conn, hd->pkt_num, require_ack, ts);
}

/*
 * conn_recv_max_stream_id processes the incoming MAX_STREAM_ID frame
 * |fr|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User callback failed.
 */
static int conn_recv_max_stream_id(ngtcp2_conn *conn,
                                   const ngtcp2_max_stream_id *fr) {
  conn->remote_settings.max_stream_id =
      ngtcp2_max(conn->remote_settings.max_stream_id, fr->max_stream_id);

  return conn_call_extend_max_stream_id(conn, fr->max_stream_id);
}

static int conn_recv_pkt(ngtcp2_conn *conn, const uint8_t *pkt, size_t pktlen,
                         ngtcp2_tstamp ts) {
  ngtcp2_pkt_hd hd;
  size_t pkt_num_bits;
  int rv = 0;
  const uint8_t *hdpkt = pkt;
  ssize_t nread, nwrite;
  ngtcp2_max_frame mfr;
  ngtcp2_frame *fr = &mfr.fr;
  int require_ack = 0;

  if (pkt[0] & NGTCP2_HEADER_FORM_BIT) {
    nread = ngtcp2_pkt_decode_hd_long(&hd, pkt, pktlen);
    if (nread < 0) {
      return (int)nread;
    }

    if (conn->conn_id != hd.conn_id &&
        (!conn->server || conn->client_conn_id != hd.conn_id)) {
      return 0;
    }
  } else {
    nread = ngtcp2_pkt_decode_hd_short(&hd, pkt, pktlen);
    if (nread < 0) {
      return (int)nread;
    }
    if (!conn->local_settings.omit_connection_id &&
        !(hd.flags & NGTCP2_PKT_FLAG_CONN_ID)) {
      return NGTCP2_ERR_PROTO;
    }
  }

  pkt += nread;
  pktlen -= (size_t)nread;

  if (hd.flags & NGTCP2_PKT_FLAG_LONG_FORM) {
    pkt_num_bits = 32;
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
  }

  hd.pkt_num =
      ngtcp2_pkt_adjust_pkt_num(conn->max_rx_pkt_num, hd.pkt_num, pkt_num_bits);

  rv = conn_call_recv_pkt(conn, &hd);
  if (rv != 0) {
    return rv;
  }

  if (hd.flags & NGTCP2_PKT_FLAG_LONG_FORM) {
    switch (hd.type) {
    case NGTCP2_PKT_VERSION_NEGOTIATION:
      /* Parse, and ignore Version Negotiation packet after
         handshake */
      rv = conn_on_version_negotiation(conn, &hd, pkt, pktlen);
      if (rv < 0) {
        return rv;
      }
      return 0;
    case NGTCP2_PKT_CLIENT_INITIAL:
    case NGTCP2_PKT_CLIENT_CLEARTEXT:
    case NGTCP2_PKT_SERVER_CLEARTEXT:
      return conn_recv_delayed_handshake_pkt(conn, &hd, pkt, pktlen, hdpkt,
                                             (size_t)nread, ts);
    default:
      /* Ignore unprotected packet after handshake */
      return 0;
    }
  }

  rv = conn_ensure_decrypt_buffer(conn, pktlen);
  if (rv != 0) {
    return rv;
  }

  nwrite = conn_decrypt_pkt(conn, conn->decrypt_buf.base, pktlen, pkt, pktlen,
                            hdpkt, (size_t)nread, hd.pkt_num, conn->rx_ckm,
                            conn->callbacks.decrypt);
  if (nwrite < 0) {
    if (nwrite != NGTCP2_ERR_TLS_DECRYPT ||
        (hd.flags & NGTCP2_PKT_FLAG_LONG_FORM)) {
      return (int)nwrite;
    }

    rv = conn_on_stateless_reset(conn, &hd, pkt, pktlen);
    if (rv == 0) {
      return 0;
    }
    return (int)nwrite;
  }
  pkt = conn->decrypt_buf.base;
  pktlen = (size_t)nwrite;

  conn->flags |= NGTCP2_CONN_FLAG_RECV_PROTECTED_PKT;

  for (; pktlen;) {
    nread = ngtcp2_pkt_decode_frame(fr, pkt, pktlen);
    if (nread < 0) {
      return (int)nread;
    }

    pkt += nread;
    pktlen -= (size_t)nread;

    rv = conn_call_recv_frame(conn, &hd, fr);
    if (rv != 0) {
      return rv;
    }

    switch (fr->type) {
    case NGTCP2_FRAME_ACK:
    case NGTCP2_FRAME_PADDING:
    case NGTCP2_FRAME_CONNECTION_CLOSE:
      break;
    default:
      require_ack = 1;
    }

    switch (fr->type) {
    case NGTCP2_FRAME_ACK:
      rv = conn_recv_ack(conn, &fr->ack, 0);
      if (rv != 0) {
        return rv;
      }
      break;
    case NGTCP2_FRAME_STREAM:
      rv = conn_recv_stream(conn, &fr->stream);
      if (rv != 0) {
        return rv;
      }
      break;
    case NGTCP2_FRAME_RST_STREAM:
      rv = conn_recv_rst_stream(conn, &fr->rst_stream);
      if (rv != 0) {
        return rv;
      }
      break;
    case NGTCP2_FRAME_STOP_SENDING:
      rv = conn_recv_stop_sending(conn, &fr->stop_sending);
      if (rv != 0) {
        return rv;
      }
      break;
    case NGTCP2_FRAME_MAX_STREAM_DATA:
      conn_recv_max_stream_data(conn, &fr->max_stream_data);
      break;
    case NGTCP2_FRAME_MAX_DATA:
      conn_recv_max_data(conn, &fr->max_data);
      break;
    case NGTCP2_FRAME_MAX_STREAM_ID:
      rv = conn_recv_max_stream_id(conn, &fr->max_stream_id);
      if (rv != 0) {
        return rv;
      }
      break;
    case NGTCP2_FRAME_CONNECTION_CLOSE:
    case NGTCP2_FRAME_APPLICATION_CLOSE:
      conn_recv_connection_close(conn);
      break;
    }
  }

  conn->max_rx_pkt_num = ngtcp2_max(conn->max_rx_pkt_num, hd.pkt_num);

  return ngtcp2_conn_sched_ack(conn, hd.pkt_num, require_ack, ts);
}

static int conn_process_buffered_protected_pkt(ngtcp2_conn *conn,
                                               ngtcp2_tstamp ts) {
  int rv;
  ngtcp2_pkt_chain *pc = conn->buffed_rx_ppkts, *next;

  for (; pc; pc = pc->next) {
    rv = conn_recv_pkt(conn, pc->pkt, pc->pktlen, ts);
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

/*
 * conn_handshake_completed is called once cryptographic handshake has
 * completed.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User callback failed.
 */
static int conn_handshake_completed(ngtcp2_conn *conn) {
  int rv;

  rv = conn_call_handshake_completed(conn);
  if (rv != 0) {
    return rv;
  }

  if (conn->remote_settings.max_stream_id > 0) {
    rv = conn_call_extend_max_stream_id(conn,
                                        conn->remote_settings.max_stream_id);
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

  switch (conn->state) {
  case NGTCP2_CS_CLIENT_WAIT_HANDSHAKE:
    rv = conn_recv_handshake_pkt(conn, pkt, pktlen, ts);
    if (rv < 0) {
      if (rv == NGTCP2_ERR_TLS_ALERT) {
        conn->state = NGTCP2_CS_CLIENT_TLS_HANDSHAKE_FAILED;
        rv = 0;
      }
      break;
    }
    if (conn->flags & NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED) {
      rv = conn_handshake_completed(conn);
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
      if (rv == NGTCP2_ERR_TLS_ALERT) {
        conn->state = NGTCP2_CS_SERVER_TLS_HANDSHAKE_FAILED;
        rv = 0;
      }
      break;
    }
    if (conn->flags & NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED) {
      rv = conn_handshake_completed(conn);
      if (rv != 0) {
        return rv;
      }
      conn->state = NGTCP2_CS_POST_HANDSHAKE;

      if (!(conn->flags & NGTCP2_CONN_FLAG_TRANSPORT_PARAM_RECVED)) {
        return NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM;
      }

      rv = conn_process_buffered_protected_pkt(conn, ts);
      if (rv != 0) {
        return rv;
      }
    }
    break;
  case NGTCP2_CS_CLIENT_TLS_HANDSHAKE_FAILED:
  case NGTCP2_CS_SERVER_TLS_HANDSHAKE_FAILED:
    rv = conn_recv_handshake_pkt(conn, pkt, pktlen, ts);
    if (rv < 0) {
      break;
    }
    break;
  case NGTCP2_CS_POST_HANDSHAKE:
    rv = conn_recv_pkt(conn, pkt, pktlen, ts);
    if (rv < 0) {
      break;
    }
    break;
  }

  return rv;
}

void ngtcp2_conn_handshake_completed(ngtcp2_conn *conn) {
  conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;
}

int ngtcp2_conn_sched_ack(ngtcp2_conn *conn, uint64_t pkt_num, int active_ack,
                          ngtcp2_tstamp ts) {
  ngtcp2_acktr_entry *rpkt;
  int rv;

  rv = ngtcp2_acktr_entry_new(&rpkt, pkt_num, ts, conn->mem);
  if (rv != 0) {
    return rv;
  }

  rv = ngtcp2_acktr_add(&conn->acktr, rpkt, active_ack);
  if (rv != 0) {
    ngtcp2_acktr_entry_del(rpkt, conn->mem);
    return rv;
  }

  if (!conn->immediate_ack && conn->next_ack_expiry == 0 &&
      conn->acktr.active_ack) {
    conn_set_next_ack_expiry(conn, ts);
  }

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

  switch (p->version) {
  case NGTCP2_PROTO_VER_D7:
    break;
  default:
    return 1;
  }

  return 0;
}

void ngtcp2_conn_set_aead_overhead(ngtcp2_conn *conn, size_t aead_overhead) {
  conn->aead_overhead = aead_overhead;
}

int ngtcp2_conn_set_handshake_tx_keys(ngtcp2_conn *conn, const uint8_t *key,
                                      size_t keylen, const uint8_t *iv,
                                      size_t ivlen) {
  if (conn->hs_tx_ckm) {
    return NGTCP2_ERR_INVALID_STATE;
  }

  return ngtcp2_crypto_km_new(&conn->hs_tx_ckm, key, keylen, iv, ivlen,
                              conn->mem);
}

int ngtcp2_conn_set_handshake_rx_keys(ngtcp2_conn *conn, const uint8_t *key,
                                      size_t keylen, const uint8_t *iv,
                                      size_t ivlen) {
  if (conn->hs_rx_ckm) {
    return NGTCP2_ERR_INVALID_STATE;
  }

  return ngtcp2_crypto_km_new(&conn->hs_rx_ckm, key, keylen, iv, ivlen,
                              conn->mem);
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
    return conn->next_ack_expiry;
  }

  if (conn->next_ack_expiry > 0) {
    return ngtcp2_min(conn->next_ack_expiry, ent->expiry);
  } else {
    return ent->expiry;
  }
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

static void
settings_copy_from_transport_params(ngtcp2_settings *dest,
                                    const ngtcp2_transport_params *src) {
  dest->max_stream_data = src->initial_max_stream_data;
  dest->max_data = src->initial_max_data;
  dest->max_stream_id = src->initial_max_stream_id;
  dest->idle_timeout = src->idle_timeout;
  dest->omit_connection_id = src->omit_connection_id;
  dest->max_packet_size = src->max_packet_size;
  memcpy(dest->stateless_reset_token, src->stateless_reset_token,
         sizeof(dest->stateless_reset_token));
  dest->ack_delay_exponent = src->ack_delay_exponent;
}

static void transport_params_copy_from_settings(ngtcp2_transport_params *dest,
                                                const ngtcp2_settings *src) {
  dest->initial_max_stream_data = src->max_stream_data;
  dest->initial_max_data = (uint32_t)src->max_data;
  dest->initial_max_stream_id = src->max_stream_id;
  dest->idle_timeout = src->idle_timeout;
  dest->omit_connection_id = src->omit_connection_id;
  dest->max_packet_size = src->max_packet_size;
  memcpy(dest->stateless_reset_token, src->stateless_reset_token,
         sizeof(dest->stateless_reset_token));
  dest->ack_delay_exponent = src->ack_delay_exponent;
}

int ngtcp2_conn_set_remote_transport_params(
    ngtcp2_conn *conn, uint8_t exttype, const ngtcp2_transport_params *params) {
  switch (exttype) {
  case NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO:
    if (!conn->server) {
      return NGTCP2_ERR_INVALID_ARGUMENT;
    }
    /* TODO More extensive validation is required */
    if (conn->server && params->v.ch.negotiated_version != conn->version) {
      return NGTCP2_ERR_PROTO;
    }
    break;
  case NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS:
  case NGTCP2_TRANSPORT_PARAMS_TYPE_NEW_SESSION_TICKET:
    if (conn->server) {
      return NGTCP2_ERR_INVALID_ARGUMENT;
    }
    break;
  default:
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  settings_copy_from_transport_params(&conn->remote_settings, params);

  conn->max_tx_offset_high = conn->remote_settings.max_data;

  /* TODO Should we check that conn->max_remote_stream_id is larger
     than conn->remote_settings.max_stream_id here?  What happens for
     0-RTT stream? */

  conn->strm0->max_tx_offset = conn->remote_settings.max_stream_data;

  conn->flags |= NGTCP2_CONN_FLAG_TRANSPORT_PARAM_RECVED;

  return 0;
}

int ngtcp2_conn_get_local_transport_params(ngtcp2_conn *conn,
                                           ngtcp2_transport_params *params,
                                           uint8_t exttype) {
  switch (exttype) {
  case NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO:
    if (conn->server) {
      return NGTCP2_ERR_INVALID_ARGUMENT;
    }
    /* TODO Fix this; not sure how to handle them correctly */
    params->v.ch.initial_version = conn->version;
    params->v.ch.negotiated_version = conn->version;
    break;
  case NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS:
    if (!conn->server) {
      return NGTCP2_ERR_INVALID_ARGUMENT;
    }
    /* TODO Fix this; not sure how to handle them correctly */
    params->v.ee.len = 1;
    params->v.ee.supported_versions[0] = conn->version;
    break;
  case NGTCP2_TRANSPORT_PARAMS_TYPE_NEW_SESSION_TICKET:
    if (!conn->server) {
      return NGTCP2_ERR_INVALID_ARGUMENT;
    }
    break;
  default:
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }
  transport_params_copy_from_settings(params, &conn->local_settings);
  return 0;
}

int ngtcp2_conn_open_stream(ngtcp2_conn *conn, uint32_t stream_id,
                            void *stream_user_data) {
  int rv;
  ngtcp2_strm *strm;

  if (!conn_local_stream(conn, stream_id)) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  if (stream_id > conn->remote_settings.max_stream_id) {
    return NGTCP2_ERR_STREAM_ID_BLOCKED;
  }

  strm = ngtcp2_conn_find_stream(conn, stream_id);
  if (strm != NULL) {
    return NGTCP2_ERR_STREAM_IN_USE;
  }

  rv = ngtcp2_idtr_open(&conn->local_idtr, stream_id);
  if (rv != 0) {
    return rv;
  }

  strm = ngtcp2_mem_malloc(conn->mem, sizeof(ngtcp2_strm));
  if (strm == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  rv = ngtcp2_conn_init_stream(conn, strm, stream_id, stream_user_data);
  if (rv != 0) {
    return rv;
  }

  return 0;
}

ngtcp2_strm *ngtcp2_conn_find_stream(ngtcp2_conn *conn, uint32_t stream_id) {
  ngtcp2_map_entry *me;

  me = ngtcp2_map_find(&conn->strms, stream_id);
  if (me == NULL) {
    return NULL;
  }

  return ngtcp2_struct_of(me, ngtcp2_strm, me);
}

ssize_t ngtcp2_conn_write_stream(ngtcp2_conn *conn, uint8_t *dest,
                                 size_t destlen, size_t *pdatalen,
                                 uint32_t stream_id, uint8_t fin,
                                 const uint8_t *data, size_t datalen,
                                 ngtcp2_tstamp ts) {
  ngtcp2_strm *strm;
  ngtcp2_frame_chain *frc;
  ngtcp2_pkt_hd hd;
  ngtcp2_ppe ppe;
  ngtcp2_crypto_ctx ctx;
  ngtcp2_rtb_entry *ent;
  int rv;
  size_t ndatalen, left;
  ssize_t nwrite;

  if (conn->last_tx_pkt_num == UINT64_MAX) {
    return NGTCP2_ERR_PKT_NUM_EXHAUSTED;
  }

  strm = ngtcp2_conn_find_stream(conn, stream_id);
  if (strm == NULL) {
    return NGTCP2_ERR_STREAM_NOT_FOUND;
  }

  if (strm->flags & NGTCP2_STRM_FLAG_SHUT_WR) {
    return NGTCP2_ERR_STREAM_SHUT_WR;
  }

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_CONN_ID,
                     conn_select_pkt_type(conn, conn->last_tx_pkt_num + 1),
                     conn->conn_id, conn->last_tx_pkt_num + 1, conn->version);

  ctx.ckm = conn->tx_ckm;
  ctx.aead_overhead = conn->aead_overhead;
  ctx.encrypt = conn->callbacks.encrypt;
  ctx.user_data = conn;

  ngtcp2_ppe_init(&ppe, dest, destlen, &ctx);

  rv = ngtcp2_ppe_encode_hd(&ppe, &hd);
  if (rv != 0) {
    return rv;
  }

  left = ngtcp2_ppe_left(&ppe);
  if (left <= NGTCP2_STREAM_OVERHEAD) {
    return NGTCP2_ERR_NOBUF;
  }

  left -= NGTCP2_STREAM_OVERHEAD;

  /* TODO Take into account flow control credit here */
  ndatalen = ngtcp2_min(datalen, left);
  ndatalen = ngtcp2_min(ndatalen, strm->max_tx_offset - strm->tx_offset);
  if (conn->max_tx_offset_high - conn->tx_offset_high <=
      (ndatalen + conn->tx_offset_low) / 1024) {
    ndatalen =
        ngtcp2_min(ndatalen,
                   (conn->max_tx_offset_high - conn->tx_offset_high) * 1024 -
                       conn->tx_offset_low);
  }

  if (datalen > 0 && ndatalen == 0) {
    return NGTCP2_ERR_STREAM_DATA_BLOCKED;
  }

  fin = fin && ndatalen == datalen;

  rv = conn_call_send_pkt(conn, &hd);
  if (rv != 0) {
    return rv;
  }

  rv = ngtcp2_frame_chain_new(&frc, conn->mem);
  if (rv != 0) {
    return rv;
  }

  frc->fr.type = NGTCP2_FRAME_STREAM;
  frc->fr.stream.flags = 0;
  frc->fr.stream.fin = fin;
  frc->fr.stream.stream_id = stream_id;
  frc->fr.stream.offset = strm->tx_offset;
  frc->fr.stream.datalen = ndatalen;
  frc->fr.stream.data = data;

  rv = ngtcp2_ppe_encode_frame(&ppe, &frc->fr);
  if (rv != 0) {
    ngtcp2_frame_chain_del(frc, conn->mem);
    return rv;
  }

  rv = conn_call_send_frame(conn, &hd, &frc->fr);
  if (rv != 0) {
    ngtcp2_frame_chain_del(frc, conn->mem);
    return rv;
  }

  nwrite = ngtcp2_ppe_final(&ppe, NULL);
  if (nwrite < 0) {
    ngtcp2_frame_chain_del(frc, conn->mem);
    return nwrite;
  }

  rv = ngtcp2_rtb_entry_new(&ent, &hd, frc, ts, ts + NGTCP2_PKT_DEADLINE_PERIOD,
                            (size_t)nwrite, NGTCP2_RTB_FLAG_NONE, conn->mem);
  if (rv != 0) {
    ngtcp2_frame_chain_del(frc, conn->mem);
    return rv;
  }

  rv = ngtcp2_rtb_add(&conn->rtb, ent);
  if (rv != 0) {
    ngtcp2_rtb_entry_del(ent, conn->mem);
    return rv;
  }

  strm->tx_offset += ndatalen;
  if (stream_id != 0) {
    ngtcp2_increment_offset(&conn->tx_offset_high, &conn->tx_offset_low,
                            ndatalen);
  }
  ++conn->last_tx_pkt_num;

  if (pdatalen) {
    *pdatalen = ndatalen;
  }

  if (fin) {
    ngtcp2_strm_shutdown(strm, NGTCP2_STRM_FLAG_SHUT_WR);
  }

  return nwrite;
}

ssize_t ngtcp2_conn_write_connection_close(ngtcp2_conn *conn, uint8_t *dest,
                                           size_t destlen,
                                           uint16_t error_code) {
  ssize_t nwrite;
  ngtcp2_frame fr;

  if (conn->last_tx_pkt_num == UINT64_MAX) {
    return NGTCP2_ERR_PKT_NUM_EXHAUSTED;
  }

  switch (conn->state) {
  case NGTCP2_CS_POST_HANDSHAKE:
    fr.type = NGTCP2_FRAME_CONNECTION_CLOSE;
    fr.connection_close.error_code = error_code;
    fr.connection_close.reasonlen = 0;
    fr.connection_close.reason = NULL;

    nwrite = conn_write_single_frame_pkt(conn, dest, destlen, &fr);
    if (nwrite > 0) {
      conn->state = NGTCP2_CS_CLOSE_WAIT;
    }
    break;
  default:
    return NGTCP2_ERR_INVALID_STATE;
  }

  return nwrite;
}

ssize_t ngtcp2_conn_write_application_close(ngtcp2_conn *conn, uint8_t *dest,
                                            size_t destlen,
                                            uint16_t app_error_code) {
  ssize_t nwrite;
  ngtcp2_frame fr;

  if (app_error_code == NGTCP2_STOPPING) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  if (conn->last_tx_pkt_num == UINT64_MAX) {
    return NGTCP2_ERR_PKT_NUM_EXHAUSTED;
  }

  switch (conn->state) {
  case NGTCP2_CS_POST_HANDSHAKE:
    break;
  default:
    return NGTCP2_ERR_INVALID_STATE;
  }

  fr.type = NGTCP2_FRAME_APPLICATION_CLOSE;
  fr.application_close.app_error_code = app_error_code;
  fr.application_close.reasonlen = 0;
  fr.application_close.reason = NULL;

  nwrite = conn_write_single_frame_pkt(conn, dest, destlen, &fr);
  if (nwrite < 0) {
    return nwrite;
  }

  conn->state = NGTCP2_CS_CLOSE_WAIT;

  return nwrite;
}

int ngtcp2_conn_closed(ngtcp2_conn *conn) {
  return conn->state == NGTCP2_CS_CLOSE_WAIT;
}

int ngtcp2_conn_close_stream(ngtcp2_conn *conn, ngtcp2_strm *strm,
                             uint16_t app_error_code) {
  int rv;

  if (!strm->app_error_code) {
    app_error_code = strm->app_error_code;
  }

  rv = ngtcp2_map_remove(&conn->strms, strm->me.key);
  if (rv != 0) {
    return rv;
  }

  rv = conn_call_stream_close(conn, strm, app_error_code);
  if (rv != 0) {
    return rv;
  }

  if (!conn_local_stream(conn, strm->stream_id) &&
      conn->max_remote_stream_id <= UINT32_MAX - 2 &&
      conn->remote_stream_id_window_start <
          ngtcp2_idtr_first_gap(&conn->remote_idtr)) {
    conn->max_remote_stream_id += 2;
    ++conn->remote_stream_id_window_start;
  }

  if (strm->fc_pprev) {
    *strm->fc_pprev = strm->fc_next;
    if (strm->fc_next) {
      strm->fc_next->fc_pprev = strm->fc_pprev;
    }
  }

  ngtcp2_strm_free(strm);
  ngtcp2_mem_free(conn->mem, strm);

  /* Send the next ACK immediately.  This might acknowledge the
     incoming STREAM + FIN or RST_STREAM faster, and it helps for peer
     to send MAX_STREAM_ID timely. */
  conn_immediate_ack(conn);

  return 0;
}

int ngtcp2_conn_close_stream_if_shut_rdwr(ngtcp2_conn *conn, ngtcp2_strm *strm,
                                          uint16_t app_error_code) {
  if ((strm->flags & NGTCP2_STRM_FLAG_SHUT_RDWR) ==
          NGTCP2_STRM_FLAG_SHUT_RDWR &&
      ((strm->flags & NGTCP2_STRM_FLAG_RECV_RST) ||
       ngtcp2_rob_first_gap_offset(&strm->rob) == strm->last_rx_offset) &&
      ((strm->flags & NGTCP2_STRM_FLAG_SENT_RST) ||
       ngtcp2_gaptr_first_gap_offset(&strm->acked_tx_offset) ==
           strm->tx_offset)) {
    return ngtcp2_conn_close_stream(conn, strm, app_error_code);
  }
  return 0;
}

static int conn_shutdown_stream_write(ngtcp2_conn *conn, ngtcp2_strm *strm,
                                      uint16_t app_error_code) {
  if (strm->flags & NGTCP2_STRM_FLAG_SENT_RST) {
    return 0;
  }

  /* Set this flag so that we don't accidentally send DATA to this
     stream. */
  strm->flags |= NGTCP2_STRM_FLAG_SHUT_WR | NGTCP2_STRM_FLAG_SENT_RST;
  strm->app_error_code = app_error_code;

  return conn_rst_stream(conn, strm, app_error_code);
}

static int conn_shutdown_stream_read(ngtcp2_conn *conn, ngtcp2_strm *strm,
                                     uint16_t app_error_code) {
  if (strm->flags & NGTCP2_STRM_FLAG_STOP_SENDING) {
    return 0;
  }

  strm->flags |= NGTCP2_STRM_FLAG_STOP_SENDING;
  strm->app_error_code = app_error_code;

  return conn_stop_sending(conn, strm, app_error_code);
}

int ngtcp2_conn_shutdown_stream(ngtcp2_conn *conn, uint32_t stream_id,
                                uint16_t app_error_code) {
  int rv;
  ngtcp2_strm *strm;

  if (stream_id == 0 || app_error_code == NGTCP2_STOPPING) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  strm = ngtcp2_conn_find_stream(conn, stream_id);
  if (strm == NULL) {
    return NGTCP2_ERR_STREAM_NOT_FOUND;
  }

  rv = conn_shutdown_stream_read(conn, strm, app_error_code);
  if (rv != 0) {
    return rv;
  }

  rv = conn_shutdown_stream_write(conn, strm, app_error_code);
  if (rv != 0) {
    return rv;
  }

  return 0;
}

int ngtcp2_conn_shutdown_stream_write(ngtcp2_conn *conn, uint32_t stream_id,
                                      uint16_t app_error_code) {
  ngtcp2_strm *strm;

  if (stream_id == 0 || app_error_code == NGTCP2_STOPPING) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  strm = ngtcp2_conn_find_stream(conn, stream_id);
  if (strm == NULL) {
    return NGTCP2_ERR_STREAM_NOT_FOUND;
  }

  return conn_shutdown_stream_write(conn, strm, app_error_code);
}

int ngtcp2_conn_shutdown_stream_read(ngtcp2_conn *conn, uint32_t stream_id,
                                     uint16_t app_error_code) {
  ngtcp2_strm *strm;

  if (stream_id == 0 || app_error_code == NGTCP2_STOPPING) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  strm = ngtcp2_conn_find_stream(conn, stream_id);
  if (strm == NULL) {
    return NGTCP2_ERR_STREAM_NOT_FOUND;
  }

  return conn_shutdown_stream_read(conn, strm, app_error_code);
}

int ngtcp2_conn_extend_max_stream_offset(ngtcp2_conn *conn, uint32_t stream_id,
                                         size_t datalen) {
  ngtcp2_strm *strm;

  strm = ngtcp2_conn_find_stream(conn, stream_id);
  if (strm == NULL) {
    return NGTCP2_ERR_STREAM_NOT_FOUND;
  }

  conn_extend_max_stream_offset(conn, strm, datalen);

  return 0;
}

void ngtcp2_conn_extend_max_offset(ngtcp2_conn *conn, size_t datalen) {
  ngtcp2_increment_offset(&conn->unsent_max_rx_offset_high,
                          &conn->unsent_max_rx_offset_low, datalen);
}

size_t ngtcp2_conn_bytes_in_flight(ngtcp2_conn *conn) {
  return conn->rtb.bytes_in_flight;
}

uint64_t ngtcp2_conn_negotiated_conn_id(ngtcp2_conn *conn) {
  return conn->conn_id;
}

uint32_t ngtcp2_conn_negotiated_version(ngtcp2_conn *conn) {
  return conn->version;
}
