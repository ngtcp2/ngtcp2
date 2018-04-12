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
#include <math.h>

#include "ngtcp2_ppe.h"
#include "ngtcp2_macro.h"
#include "ngtcp2_log.h"

/*
 * conn_local_stream returns nonzero if |stream_id| indicates that it
 * is the stream initiated by local endpoint.
 */
static int conn_local_stream(ngtcp2_conn *conn, uint64_t stream_id) {
  return (uint8_t)(stream_id & 1) == conn->server;
}

/*
 * bidi_stream returns nonzero if |stream_id| is a bidirectional
 * stream ID.
 */
static int bidi_stream(uint64_t stream_id) { return (stream_id & 0x2) == 0; }

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
                                      uint8_t fin, uint64_t offset,
                                      const uint8_t *data, size_t datalen) {
  int rv;

  if (!conn->callbacks.recv_stream_data) {
    return 0;
  }

  rv = conn->callbacks.recv_stream_data(conn, strm->stream_id, fin, offset,
                                        data, datalen, conn->user_data,
                                        strm->stream_user_data);
  if (rv != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int conn_call_recv_stream0_data(ngtcp2_conn *conn, uint64_t offset,
                                       const uint8_t *data, size_t datalen) {
  int rv;

  rv = conn->callbacks.recv_stream0_data(conn, offset, data, datalen,
                                         conn->user_data);
  switch (rv) {
  case 0:
  case NGTCP2_ERR_TLS_HANDSHAKE:
  case NGTCP2_ERR_TLS_FATAL_ALERT_GENERATED:
  case NGTCP2_ERR_TLS_FATAL_ALERT_RECEIVED:
  case NGTCP2_ERR_CALLBACK_FAILURE:
    return rv;
  default:
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
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
                                          uint64_t max_stream_id) {
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

static int conn_call_rand(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                          ngtcp2_rand_ctx ctx) {
  int rv;

  rv = conn->callbacks.rand(conn, dest, destlen, ctx, conn->user_data);
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

  rv = ngtcp2_idtr_init(&(*pconn)->remote_bidi_idtr, !server, mem);
  if (rv != 0) {
    goto fail_remote_bidi_idtr_init;
  }

  rv = ngtcp2_idtr_init(&(*pconn)->remote_uni_idtr, !server, mem);
  if (rv != 0) {
    goto fail_remote_uni_idtr_init;
  }

  rv = ngtcp2_ringbuf_init(&(*pconn)->tx_path_challenge, 4,
                           sizeof(ngtcp2_path_challenge_entry), mem);
  if (rv != 0) {
    goto fail_tx_path_challenge_init;
  }

  rv = ngtcp2_ringbuf_init(&(*pconn)->rx_path_challenge, 4,
                           sizeof(ngtcp2_path_challenge_entry), mem);
  if (rv != 0) {
    goto fail_rx_path_challenge_init;
  }

  ngtcp2_log_init(&(*pconn)->log, &(*pconn)->conn_id, settings->log_printf,
                  settings->initial_ts, user_data);

  rv = ngtcp2_acktr_init(&(*pconn)->acktr, &(*pconn)->log, mem);
  if (rv != 0) {
    goto fail_acktr_init;
  }

  ngtcp2_rtb_init(&(*pconn)->rtb, &(*pconn)->log, mem);

  (*pconn)->callbacks = *callbacks;
  (*pconn)->conn_id = conn_id;
  (*pconn)->version = version;
  (*pconn)->mem = mem;
  (*pconn)->user_data = user_data;
  (*pconn)->largest_ack = -1;

  (*pconn)->local_settings = *settings;
  (*pconn)->unsent_max_remote_stream_id_bidi =
      (*pconn)->max_remote_stream_id_bidi = settings->max_stream_id_bidi;
  (*pconn)->unsent_max_remote_stream_id_uni =
      (*pconn)->max_remote_stream_id_uni = settings->max_stream_id_uni;
  (*pconn)->unsent_max_rx_offset = (*pconn)->max_rx_offset = settings->max_data;
  (*pconn)->server = server;
  (*pconn)->state =
      server ? NGTCP2_CS_SERVER_INITIAL : NGTCP2_CS_CLIENT_INITIAL;
  (*pconn)->rcs.min_rtt = UINT64_MAX;
  (*pconn)->rcs.reordering_threshold = NGTCP2_REORDERING_THRESHOLD;

  return 0;

fail_acktr_init:
  ngtcp2_ringbuf_free(&(*pconn)->rx_path_challenge);
fail_rx_path_challenge_init:
  ngtcp2_ringbuf_free(&(*pconn)->tx_path_challenge);
fail_tx_path_challenge_init:
  ngtcp2_idtr_free(&(*pconn)->remote_uni_idtr);
fail_remote_uni_idtr_init:
  ngtcp2_idtr_free(&(*pconn)->remote_bidi_idtr);
fail_remote_bidi_idtr_init:
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
  int rv;
  rv = conn_new(pconn, conn_id, version, callbacks, settings, user_data, 0);
  if (rv != 0) {
    return rv;
  }
  (*pconn)->client_conn_id = conn_id;
  (*pconn)->next_local_stream_id_bidi = 4;
  (*pconn)->next_local_stream_id_uni = 2;
  return 0;
}

int ngtcp2_conn_server_new(ngtcp2_conn **pconn, uint64_t conn_id,
                           uint32_t version,
                           const ngtcp2_conn_callbacks *callbacks,
                           const ngtcp2_settings *settings, void *user_data) {
  int rv;
  rv = conn_new(pconn, conn_id, version, callbacks, settings, user_data, 1);
  if (rv != 0) {
    return rv;
  }
  ngtcp2_idtr_open(&(*pconn)->remote_bidi_idtr, 0);
  (*pconn)->next_local_stream_id_bidi = 1;
  (*pconn)->next_local_stream_id_uni = 3;
  return 0;
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

static void delete_early_rtb(ngtcp2_rtb_entry *ent, ngtcp2_mem *mem) {
  ngtcp2_rtb_entry *next;

  while (ent) {
    next = ent->next;
    ngtcp2_rtb_entry_del(ent, mem);
    ent = next;
  }
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

  ngtcp2_crypto_km_del(conn->early_ckm, conn->mem);

  ngtcp2_crypto_km_del(conn->hs_rx_ckm, conn->mem);
  ngtcp2_crypto_km_del(conn->hs_tx_ckm, conn->mem);

  delete_frq(conn->frq, conn->mem);

  delete_early_rtb(conn->early_rtb, conn->mem);
  ngtcp2_rtb_free(&conn->rtb);

  ngtcp2_ringbuf_free(&conn->rx_path_challenge);
  ngtcp2_ringbuf_free(&conn->tx_path_challenge);

  ngtcp2_idtr_free(&conn->remote_uni_idtr);
  ngtcp2_idtr_free(&conn->remote_bidi_idtr);
  ngtcp2_map_each_free(&conn->strms, delete_strms_each, conn->mem);
  ngtcp2_map_free(&conn->strms);

  ngtcp2_mem_free(conn->mem, conn);
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
 * conn_compute_ack_delay computes ACK delay for outgoing protected
 * ACK.
 */
static uint64_t conn_compute_ack_delay(ngtcp2_conn *conn) {
  uint64_t ack_delay;

  if (conn->rcs.min_rtt == UINT64_MAX) {
    return NGTCP2_DEFAULT_ACK_DELAY;
  }

  ack_delay = (uint64_t)(conn->rcs.smoothed_rtt / 4);

  return ngtcp2_min(NGTCP2_DEFAULT_ACK_DELAY, ack_delay);
}

/*
 * conn_create_ack_frame creates ACK frame, and assigns its pointer to
 * |*pfr| if there are any received packets to acknowledge.  If there
 * are no packets to acknowledge, this function returns 0, and |*pfr|
 * is untouched.  The caller is advised to set |*pfr| to NULL before
 * calling this function, and check it after this function returns.
 * If |nodelay| is nonzero, delayed ACK timer is ignored.  If
 * |unprotected| is nonzero, delayed ACK timer is always ignored.
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
                                 ngtcp2_tstamp ts, int nodelay,
                                 int unprotected) {
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
  uint64_t max_ack_delay =
      (nodelay || unprotected) ? 0 : conn_compute_ack_delay(conn);

  if (!ngtcp2_acktr_require_active_ack(&conn->acktr, unprotected, max_ack_delay,
                                       ts)) {
    return 0;
  }

  prpkt = ngtcp2_acktr_get(&conn->acktr);
  if (unprotected) {
    for (; *prpkt && !(*prpkt)->unprotected; prpkt = &(*prpkt)->next)
      ;
  }
  if (*prpkt == NULL) {
    if (!unprotected) {
      conn->acktr.first_unacked_ts = UINT64_MAX;
    }
    return 0;
  }

  fr = ngtcp2_mem_malloc(conn->mem, sizeof(ngtcp2_ack) +
                                        sizeof(ngtcp2_ack_blk) * num_blks_max);
  if (fr == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  ack = &fr->ack;

  first_pkt_num = last_pkt_num = (*prpkt)->pkt_num;

  ack->type = NGTCP2_FRAME_ACK;
  ack->largest_ack = first_pkt_num;
  ack->ack_delay_unscaled = ts - (*prpkt)->tstamp;
  ack->ack_delay = (ack->ack_delay_unscaled / 1000) >>
                   (unprotected ? NGTCP2_DEFAULT_ACK_DELAY_EXPONENT
                                : conn->local_settings.ack_delay_exponent);
  ack->num_blks = 0;

  prpkt = &(*prpkt)->next;

  for (; *prpkt; prpkt = &(*prpkt)->next) {
    if (unprotected && !(*prpkt)->unprotected) {
      continue;
    }
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
static void conn_commit_tx_ack(ngtcp2_conn *conn, int unprotected) {
  ngtcp2_acktr_commit_ack(&conn->acktr, unprotected);
}

/*
 * conn_ppe_write_frame writes |fr| to |ppe|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOBUF
 *     Buffer is too small.
 */
static int conn_ppe_write_frame(ngtcp2_conn *conn, ngtcp2_ppe *ppe,
                                const ngtcp2_pkt_hd *hd, ngtcp2_frame *fr) {
  int rv;

  rv = ngtcp2_ppe_encode_frame(ppe, fr);
  if (rv != 0) {
    return rv;
  }

  ngtcp2_log_tx_fr(&conn->log, hd, fr);

  return 0;
}

static void conn_on_pkt_sent(ngtcp2_conn *conn, ngtcp2_rtb_entry *ent) {
  /* This function implements OnPacketSent, but it handles only
     retransmittable packet (non-ACK only packet). */
  ngtcp2_rtb_add(&conn->rtb, ent);
  if (ent->flags & NGTCP2_RTB_FLAG_UNPROTECTED) {
    conn->rcs.last_hs_tx_pkt_ts = ent->ts;
  }
  conn->rcs.last_tx_pkt_ts = ent->ts;
  ngtcp2_conn_set_loss_detection_alarm(conn);
}

/*
 * conn_retransmit_unprotected_once writes QUIC packet in the buffer
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
 */
static ssize_t conn_retransmit_unprotected_once(ngtcp2_conn *conn,
                                                uint8_t *dest, size_t destlen,
                                                ngtcp2_rtb_entry *ent,
                                                ngtcp2_tstamp ts) {
  int rv;
  ngtcp2_ppe ppe;
  ngtcp2_pkt_hd hd = ent->hd;
  ngtcp2_frame_chain **pfrc;
  ngtcp2_frame localfr;
  int pkt_empty = 1;
  ngtcp2_crypto_ctx ctx;
  ngtcp2_frame *ackfr;

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

  for (pfrc = &ent->frc; *pfrc;) {
    rv = conn_ppe_write_frame(conn, &ppe, &hd, &(*pfrc)->fr);
    if (rv != 0) {
      return rv;
    }

    pkt_empty = 0;
    pfrc = &(*pfrc)->next;
  }

  if (pkt_empty) {
    return rv;
  }

  if (hd.type != NGTCP2_PKT_INITIAL) {
    /* ACK is added last so that we don't send ACK only frame here. */
    ackfr = NULL;
    rv = conn_create_ack_frame(conn, &ackfr, ts, 0 /* nodelay */,
                               1 /* unprotected */);
    if (rv != 0) {
      return rv;
    }

    if (ackfr) {
      rv = conn_ppe_write_frame(conn, &ppe, &hd, ackfr);
      if (rv != 0) {
        ngtcp2_mem_free(conn->mem, ackfr);
        if (rv != NGTCP2_ERR_NOBUF) {
          return rv;
        }
      } else {
        conn_commit_tx_ack(conn, 1 /* unprotected */);

        ngtcp2_acktr_add_ack(&conn->acktr, hd.pkt_num, &ackfr->ack, ts, 0,
                             0 /* ack_only */);
      }
    }
  }

  assert(!*pfrc);

  ent->hd = hd;

  if (hd.type == NGTCP2_PKT_INITIAL) {
    localfr.type = NGTCP2_FRAME_PADDING;
    localfr.padding.len = ngtcp2_ppe_padding(&ppe);

    ngtcp2_log_tx_fr(&conn->log, &hd, &localfr);
  }

  ++conn->last_tx_pkt_num;

  return ngtcp2_ppe_final(&ppe, NULL);
}

/*
 * conn_retransmit_unprotected writes QUIC packet in the buffer
 * pointed by |dest| whose length is |destlen| to retransmit lost
 * unprotected packet.
 *
 * This function returns the number of bytes written in |dest| if it
 * succeeds, or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User-defined callback function failed.
 * NGTCP2_ERR_PKT_TIMEOUT
 *     Give up the retransmission of lost packet because of timeout.
 * NGTCP2_ERR_INVALID_ARGUMENT
 *     Packet type is unexpected.  TODO: This will be removed in the
 *     future.
 */
static ssize_t conn_retransmit_unprotected(ngtcp2_conn *conn, uint8_t *dest,
                                           size_t destlen, ngtcp2_tstamp ts) {
  ngtcp2_rtb_entry *ent;
  ssize_t nwrite;

  /* TODO We should not retransmit packets after we are in closing, or
     draining state */
  for (;;) {
    ent = ngtcp2_rtb_lost_unprotected_head(&conn->rtb);
    if (ent == NULL) {
      return 0;
    }

    ngtcp2_rtb_lost_unprotected_pop(&conn->rtb);

    assert(ent->hd.flags & NGTCP2_PKT_FLAG_LONG_FORM);

    switch (ent->hd.type) {
    case NGTCP2_PKT_INITIAL:
      /* If we have received stream 0 data from server, we don't
         have to send Initial anymore */
      if (conn->strm0->last_rx_offset > 0) {
        ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_RCV,
                        "no need to retransmit Initial packet");
        nwrite = 0;
        break;
      }
      nwrite = conn_retransmit_unprotected_once(conn, dest, destlen, ent, ts);
      break;
    case NGTCP2_PKT_HANDSHAKE:
      /* Stop retransmitting handshake packet after at least one
         protected packet is received, and decrypted successfully. */
      if (conn->flags & NGTCP2_CONN_FLAG_RECV_PROTECTED_PKT) {
        ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_RCV,
                        "no need to retransmit Handshake packet");
        nwrite = 0;
        break;
      }

      if (conn->server) {
        if (conn->flags & NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED) {
          ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_RCV,
                          "no need to retransmit Handshake packet");
          nwrite = 0;
          break;
        }
      } else if (conn->final_hs_tx_offset &&
                 ngtcp2_gaptr_first_gap_offset(&conn->strm0->acked_tx_offset) >=
                     conn->final_hs_tx_offset) {
        ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_RCV,
                        "no need to retransmit Handshake packet");
        nwrite = 0;
        break;
      }
      nwrite = conn_retransmit_unprotected_once(conn, dest, destlen, ent, ts);
      break;
    default:
      /* TODO fix this */
      ngtcp2_rtb_entry_del(ent, conn->mem);
      return NGTCP2_ERR_INVALID_ARGUMENT;
    }

    if (nwrite <= 0) {
      if (nwrite == 0) {
        ngtcp2_rtb_entry_del(ent, conn->mem);
        continue;
      }
      if (nwrite == NGTCP2_ERR_NOBUF) {
        /* TODO we might stack here if the same insufficiently small
           buffer size is specified repeatedly. */
        ngtcp2_rtb_lost_unprotected_insert(&conn->rtb, ent);
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
    ent->ts = ts;
    conn_on_pkt_sent(conn, ent);

    return nwrite;
  }
}

/*
 * conn_select_pkt_type selects shorted short packet type based on the
 * next packet number |pkt_num|.
 */
static uint8_t conn_select_pkt_type(ngtcp2_conn *conn, uint64_t pkt_num) {
  uint64_t n =
      (uint64_t)((int64_t)pkt_num - conn->rtb.largest_acked_tx_pkt_num);
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
 * conn_retransmit_protected_once writes QUIC packet in the buffer
 * pointed by |dest| whose length is |destlen| to retransmit lost
 * protected packet.
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
static ssize_t conn_retransmit_protected_once(ngtcp2_conn *conn, uint8_t *dest,
                                              size_t destlen,
                                              ngtcp2_rtb_entry *ent,
                                              ngtcp2_tstamp ts) {
  int rv;
  ngtcp2_ppe ppe;
  ngtcp2_pkt_hd hd = ent->hd;
  ngtcp2_frame_chain **pfrc, *frc;
  ngtcp2_frame *ackfr;
  int pkt_empty = 1;
  ssize_t nwrite;
  ngtcp2_crypto_ctx ctx;
  ngtcp2_strm *strm;

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
    case NGTCP2_FRAME_MAX_STREAM_ID: {
      int cancel;
      if (bidi_stream((*pfrc)->fr.max_stream_id.max_stream_id)) {
        cancel = (*pfrc)->fr.max_stream_id.max_stream_id <
                 conn->max_remote_stream_id_bidi;
      } else {
        cancel = (*pfrc)->fr.max_stream_id.max_stream_id <
                 conn->max_remote_stream_id_uni;
      }
      if (cancel) {
        frc = *pfrc;
        *pfrc = (*pfrc)->next;
        ngtcp2_frame_chain_del(frc, conn->mem);
        continue;
      }
      break;
    }
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
      if ((*pfrc)->fr.max_data.max_data < conn->max_rx_offset) {
        frc = *pfrc;
        *pfrc = (*pfrc)->next;
        ngtcp2_frame_chain_del(frc, conn->mem);
        continue;
      }
      break;
    }
    rv = conn_ppe_write_frame(conn, &ppe, &hd, &(*pfrc)->fr);
    if (rv != 0) {
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
  rv = conn_create_ack_frame(conn, &ackfr, ts, 1 /* nodelay */,
                             0 /* unprotected */);
  if (rv != 0) {
    return rv;
  }
  if (ackfr) {
    rv = conn_ppe_write_frame(conn, &ppe, &hd, ackfr);
    if (rv != 0) {
      ngtcp2_mem_free(conn->mem, ackfr);
      if (rv != NGTCP2_ERR_NOBUF) {
        return rv;
      }
    } else {
      conn_commit_tx_ack(conn, 0 /* unprotected */);

      ngtcp2_acktr_add_ack(&conn->acktr, hd.pkt_num, &ackfr->ack, ts, 0,
                           0 /* ack_only */);
    }
  }

  assert(!*pfrc);

  ent->hd = hd;

  nwrite = ngtcp2_ppe_final(&ppe, NULL);
  if (nwrite < 0) {
    return nwrite;
  }

  ++conn->last_tx_pkt_num;

  return nwrite;
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
 * NGTCP2_ERR_PKT_TIMEOUT
 *     Give up the retransmission of lost packet because of timeout.
 * NGTCP2_ERR_INVALID_ARGUMENT
 *     Packet type is unexpected.  TODO: This will be removed in the
 *     future.
 */
static ssize_t conn_retransmit_protected(ngtcp2_conn *conn, uint8_t *dest,
                                         size_t destlen, ngtcp2_tstamp ts) {
  ngtcp2_rtb_entry *ent;
  ssize_t nwrite;

  /* TODO We should not retransmit packets after we are in closing, or
     draining state */
  for (;;) {
    ent = ngtcp2_rtb_lost_protected_head(&conn->rtb);
    if (ent == NULL) {
      return 0;
    }

    ngtcp2_rtb_lost_protected_pop(&conn->rtb);

    assert(!(ent->hd.flags & NGTCP2_PKT_FLAG_LONG_FORM));
    switch (ent->hd.type) {
    case NGTCP2_PKT_01:
    case NGTCP2_PKT_02:
    case NGTCP2_PKT_03:
      nwrite = conn_retransmit_protected_once(conn, dest, destlen, ent, ts);
      break;
    default:
      /* TODO fix this */
      ngtcp2_rtb_entry_del(ent, conn->mem);
      return NGTCP2_ERR_INVALID_ARGUMENT;
    }

    if (nwrite <= 0) {
      if (nwrite == 0) {
        ngtcp2_rtb_entry_del(ent, conn->mem);
        continue;
      }
      if (nwrite == NGTCP2_ERR_NOBUF) {
        /* TODO we might stack here if the same insufficiently small
           buffer size is specified repeatedly. */
        ngtcp2_rtb_lost_protected_insert(&conn->rtb, ent);
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
    ent->ts = ts;
    conn_on_pkt_sent(conn, ent);

    return nwrite;
  }
}

/*
 * conn_cwnd_left returns the number of bytes the local endpoint can
 * sent at this time.
 */
static uint64_t conn_cwnd_left(ngtcp2_conn *conn) {
  ngtcp2_rtb *rtb = &conn->rtb;

  /* We might send more than bytes_in_flight if TLP/RTO packets are
     involved. */
  if (rtb->bytes_in_flight >= rtb->ccs.cwnd) {
    return 0;
  }
  return rtb->ccs.cwnd - rtb->bytes_in_flight;
}

/*
 * conn_retransmit performs retransmission for both protected and
 * unprotected packets.
 */
static ssize_t conn_retransmit(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                               ngtcp2_tstamp ts) {
  ssize_t nwrite;

  nwrite = conn_retransmit_unprotected(conn, dest, destlen, ts);
  if (nwrite != 0) {
    return nwrite;
  }
  return conn_retransmit_protected(conn, dest, destlen, ts);
}

/*
 * conn_retransmit_unacked retransmits unacknowledged protected packet
 * as a TLP/RTO probe packet.
 */
static ssize_t conn_retransmit_unacked(ngtcp2_conn *conn, uint8_t *dest,
                                       size_t destlen, ngtcp2_tstamp ts) {
  ngtcp2_rtb_entry *ent = ngtcp2_rtb_head(&conn->rtb);
  ssize_t nwrite;
  ngtcp2_frame_chain *nfrc;
  ngtcp2_rtb_entry *nent;
  int rv;

  for (; ent; ent = ent->next) {
    if (!ent->frc) {
      continue;
    }

    /* TODO It would be better to avoid copy here.*/
    nfrc = ngtcp2_frame_chain_list_copy(ent->frc, conn->mem);
    if (!nfrc) {
      return NGTCP2_ERR_NOMEM;
    }

    rv = ngtcp2_rtb_entry_new(&nent, &ent->hd, nfrc, ts, 0,
                              NGTCP2_RTB_FLAG_PROBE, conn->mem);
    if (rv != 0) {
      ngtcp2_frame_chain_list_del(nfrc, conn->mem);
      return rv;
    }

    nent->src_pkt_num = (int64_t)ent->hd.pkt_num;

    nwrite = conn_retransmit_protected_once(conn, dest, destlen, nent, ts);
    if (nwrite < 0) {
      ngtcp2_rtb_entry_del(nent, conn->mem);
      return nwrite;
    }
    if (nwrite == 0) {
      ngtcp2_rtb_entry_del(nent, conn->mem);
      continue;
    }

    nent->pktlen = (size_t)nwrite;
    nent->ts = ts;
    conn_on_pkt_sent(conn, nent);

    return nwrite;
  }

  return 0;
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
  ngtcp2_frame *fr, *ackfr, lfr;
  size_t nwrite;
  ssize_t spktlen;
  ngtcp2_crypto_ctx ctx;
  ngtcp2_rtb_entry *rtbent;
  ngtcp2_acktr_ack_entry *ack_ent = NULL;
  size_t pclen;
  int pr_encoded = 0;
  ngtcp2_path_challenge_entry *pc;

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

  /* Encode ACK here */
  if (type != NGTCP2_PKT_INITIAL) {
    ackfr = NULL;
    rv = conn_create_ack_frame(conn, &ackfr, ts, 0 /* nodelay */,
                               1 /* unprotected */);
    if (rv != 0) {
      return rv;
    }
    if (ackfr) {
      rv = ngtcp2_ppe_encode_frame(&ppe, ackfr);
      if (rv != 0) {
        ngtcp2_mem_free(conn->mem, ackfr);
        return rv;
      }

      ngtcp2_log_tx_fr(&conn->log, &hd, ackfr);

      conn_commit_tx_ack(conn, 1 /* unprotected */);

      ack_ent = ngtcp2_acktr_add_ack(&conn->acktr, hd.pkt_num, &ackfr->ack, ts,
                                     1, 0 /* ack_only */);
    }

    if (conn->server) {
      if (!(conn->flags & NGTCP2_CONN_FLAG_SADDR_VERIFIED)) {
        lfr.type = NGTCP2_FRAME_PATH_CHALLENGE;

        rv = conn_call_rand(conn, lfr.path_challenge.data,
                            sizeof(lfr.path_challenge.data),
                            NGTCP2_RAND_CTX_PATH_CHALLENGE);
        if (rv != 0) {
          return rv;
        }

        rv = ngtcp2_ppe_encode_frame(&ppe, &lfr);
        if (rv != 0) {
          if (rv != NGTCP2_ERR_NOBUF) {
            return rv;
          }
        } else {
          pr_encoded = 1;

          ngtcp2_log_tx_fr(&conn->log, &hd, &lfr);

          pc = ngtcp2_ringbuf_push_front(&conn->tx_path_challenge);
          ngtcp2_cpymem(pc->data, lfr.path_challenge.data, sizeof(pc->data));
        }
      }
    } else {
      pclen = ngtcp2_ringbuf_len(&conn->rx_path_challenge);
      while (ngtcp2_ringbuf_len(&conn->rx_path_challenge)) {
        pc = ngtcp2_ringbuf_get(&conn->rx_path_challenge, 0);

        lfr.type = NGTCP2_FRAME_PATH_RESPONSE;
        ngtcp2_cpymem(lfr.path_challenge.data, pc->data,
                      sizeof(lfr.path_challenge.data));

        rv = ngtcp2_ppe_encode_frame(&ppe, &lfr);
        if (rv != 0) {
          if (rv == NGTCP2_ERR_NOBUF) {
            break;
          }
          return rv;
        }

        ngtcp2_log_tx_fr(&conn->log, &hd, &lfr);

        ngtcp2_ringbuf_pop_front(&conn->rx_path_challenge);
      }

      pr_encoded = (pclen != ngtcp2_ringbuf_len(&conn->rx_path_challenge));
    }

    if (ngtcp2_ppe_left(&ppe) < NGTCP2_STREAM_OVERHEAD + 1) {
      spktlen = ngtcp2_ppe_final(&ppe, NULL);
      if (spktlen < 0) {
        return (int)spktlen;
      }

      if (pr_encoded) {
        rv = ngtcp2_rtb_entry_new(&rtbent, &hd, NULL, ts, (size_t)spktlen,
                                  NGTCP2_RTB_FLAG_UNPROTECTED, conn->mem);
        if (rv != 0) {
          return rv;
        }

        conn_on_pkt_sent(conn, rtbent);
      }

      ++conn->last_tx_pkt_num;

      return spktlen;
    }
  }

  nwrite = ngtcp2_min(ngtcp2_buf_len(tx_buf),
                      ngtcp2_ppe_left(&ppe) - NGTCP2_STREAM_OVERHEAD);

  if (nwrite != ngtcp2_buf_len(tx_buf) && type == NGTCP2_PKT_INITIAL) {
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

    ngtcp2_log_tx_fr(&conn->log, &hd, fr);

    tx_buf->pos += nwrite;
    conn->strm0->tx_offset += nwrite;
  }

  if (type == NGTCP2_PKT_INITIAL) {
    lfr.type = NGTCP2_FRAME_PADDING;
    lfr.padding.len = ngtcp2_ppe_padding(&ppe);
    if (lfr.padding.len > 0) {
      ngtcp2_log_tx_fr(&conn->log, &hd, &lfr);
    }
  } else if (conn->state == NGTCP2_CS_CLIENT_TLS_HANDSHAKE_FAILED ||
             conn->state == NGTCP2_CS_SERVER_TLS_HANDSHAKE_FAILED) {
    rv = ngtcp2_frame_chain_new(&frc, conn->mem);
    if (rv != 0) {
      goto fail;
    }

    *pfrc = frc;
    pfrc = &frc->next;

    fr = &frc->fr;

    fr->type = NGTCP2_FRAME_CONNECTION_CLOSE;
    fr->connection_close.error_code = NGTCP2_TLS_HANDSHAKE_FAILED;
    fr->connection_close.reasonlen = 0;
    fr->connection_close.reason = NULL;

    rv = ngtcp2_ppe_encode_frame(&ppe, fr);
    if (rv != 0) {
      goto fail;
    }

    ngtcp2_log_tx_fr(&conn->log, &hd, fr);
  }

  if (!frc_head && !pr_encoded && !ack_ent) {
    return 0;
  }

  spktlen = ngtcp2_ppe_final(&ppe, NULL);
  if (spktlen < 0) {
    rv = (int)spktlen;
    goto fail;
  }

  if (frc_head || pr_encoded) {
    rv = ngtcp2_rtb_entry_new(&rtbent, &hd, frc_head, ts, (size_t)spktlen,
                              NGTCP2_RTB_FLAG_UNPROTECTED, conn->mem);
    if (rv != 0) {
      goto fail;
    }

    conn_on_pkt_sent(conn, rtbent);
  } else if (ack_ent) {
    ack_ent->ack_only = 1;
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
 * only includes ACK frame if any ack is required.
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
                                            size_t destlen, ngtcp2_tstamp ts) {
  int rv;
  ngtcp2_ppe ppe;
  ngtcp2_pkt_hd hd;
  ngtcp2_frame *ackfr;
  ngtcp2_crypto_ctx ctx;

  ackfr = NULL;
  rv = conn_create_ack_frame(conn, &ackfr, ts, 0 /* nodelay */,
                             1 /* unprotected */);
  if (rv != 0) {
    return rv;
  }
  if (!ackfr) {
    return 0;
  }

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_LONG_FORM, NGTCP2_PKT_HANDSHAKE,
                     conn->conn_id, conn->last_tx_pkt_num + 1, conn->version);

  ctx.ckm = conn->hs_tx_ckm;
  ctx.aead_overhead = NGTCP2_HANDSHAKE_AEAD_OVERHEAD;
  ctx.encrypt = conn->callbacks.hs_encrypt;
  ctx.user_data = conn;

  ngtcp2_ppe_init(&ppe, dest, destlen, &ctx);

  rv = ngtcp2_ppe_encode_hd(&ppe, &hd);
  if (rv != 0) {
    goto fail;
  }

  rv = ngtcp2_ppe_encode_frame(&ppe, ackfr);
  if (rv != 0) {
    goto fail;
  }

  ngtcp2_log_tx_fr(&conn->log, &hd, ackfr);

  conn_commit_tx_ack(conn, 1 /* unprotected */);

  ngtcp2_acktr_add_ack(&conn->acktr, hd.pkt_num, &ackfr->ack, ts, 1,
                       1 /* ack_only*/);

  ++conn->last_tx_pkt_num;

  return ngtcp2_ppe_final(&ppe, NULL);

fail:
  ngtcp2_mem_free(conn->mem, ackfr);
  return rv;
}

/*
 * conn_write_client_initial writes Initial packet in the buffer
 * pointed by |dest| whose length is |destlen|.
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
    conn->rtb.largest_acked_tx_pkt_num = (int64_t)conn->last_tx_pkt_num;
  }

  return conn_write_handshake_pkt(conn, dest, destlen, NGTCP2_PKT_INITIAL,
                                  tx_buf, ts);
}

/*
 * conn_write_client_handshake writes Handshake packet in the buffer
 * pointed by |dest| whose length is |destlen|.
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
static ssize_t conn_write_client_handshake(ngtcp2_conn *conn, uint8_t *dest,
                                           size_t destlen, ngtcp2_tstamp ts) {
  const uint8_t *payload;
  ssize_t payloadlen;
  ngtcp2_buf *tx_buf = &conn->strm0->tx_buf;

  if (ngtcp2_buf_len(tx_buf) == 0) {
    payloadlen = conn->callbacks.send_client_handshake(
        conn, NGTCP2_CONN_FLAG_NONE, &payload, conn->user_data);

    if (payloadlen < 0) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    if (payloadlen == 0) {
      if (conn->state == NGTCP2_CS_CLIENT_TLS_HANDSHAKE_FAILED) {
        return NGTCP2_ERR_TLS_HANDSHAKE;
      }

      return conn_write_handshake_pkt(conn, dest, destlen, NGTCP2_PKT_HANDSHAKE,
                                      tx_buf, ts);
    }

    ngtcp2_buf_init(tx_buf, (uint8_t *)payload, (size_t)payloadlen);
    tx_buf->last += payloadlen;
  }

  return conn_write_handshake_pkt(conn, dest, destlen, NGTCP2_PKT_HANDSHAKE,
                                  tx_buf, ts);
}

static ssize_t conn_write_protected_ack_pkt(ngtcp2_conn *conn, uint8_t *dest,
                                            size_t destlen, ngtcp2_tstamp ts);

/*
 * conn_write_server_handshake writes Handshake packet in the buffer
 * pointed by |dest| whose length is |destlen|.
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
static ssize_t conn_write_server_handshake(ngtcp2_conn *conn, uint8_t *dest,
                                           size_t destlen, int initial,
                                           ngtcp2_tstamp ts) {
  uint64_t pkt_num = 0;
  const uint8_t *payload;
  ssize_t payloadlen;
  ngtcp2_buf *tx_buf = &conn->strm0->tx_buf;
  ssize_t nwrite;

  if (ngtcp2_buf_len(tx_buf) == 0) {
    payloadlen = conn->callbacks.send_server_handshake(
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
        return NGTCP2_ERR_TLS_HANDSHAKE;
      }

      if (conn->early_ckm && ngtcp2_acktr_include_protected_pkt(&conn->acktr)) {
        assert(conn->tx_ckm);

        nwrite = conn_write_protected_ack_pkt(conn, dest, destlen, ts);
        if (nwrite != 0) {
          return nwrite;
        }
      }

      return conn_write_handshake_ack_pkt(conn, dest, destlen, ts);
    }

    ngtcp2_buf_init(tx_buf, (uint8_t *)payload, (size_t)payloadlen);
    tx_buf->last += payloadlen;
  }

  if (initial) {
    conn->last_tx_pkt_num = pkt_num - 1;
    conn->rtb.largest_acked_tx_pkt_num = (int64_t)conn->last_tx_pkt_num;
  }

  return conn_write_handshake_pkt(conn, dest, destlen, NGTCP2_PKT_HANDSHAKE,
                                  tx_buf, ts);
}

/*
 * conn_should_send_max_stream_data returns nonzero if MAX_STREAM_DATA
 * frame should be send for |strm|.
 */
static int conn_should_send_max_stream_data(ngtcp2_conn *conn,
                                            ngtcp2_strm *strm) {
  return conn->local_settings.max_stream_data / 2 <
             (strm->unsent_max_rx_offset - strm->max_rx_offset) ||
         2 * conn->rx_bw * conn->rcs.smoothed_rtt >=
             strm->max_rx_offset - strm->last_rx_offset;
}

/*
 * conn_should_send_max_data returns nonzero if MAX_DATA frame should
 * be sent.
 */
static int conn_should_send_max_data(ngtcp2_conn *conn) {
  return conn->local_settings.max_data / 2 <
             conn->unsent_max_rx_offset - conn->max_rx_offset ||
         2 * conn->rx_bw * conn->rcs.smoothed_rtt >=
             conn->max_rx_offset - conn->rx_offset;
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
                              size_t *pdatalen, ngtcp2_strm *data_strm,
                              uint8_t fin, const uint8_t *data, size_t datalen,
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
  int pkt_empty = 1;
  ngtcp2_acktr_ack_entry *ack_ent = NULL;
  size_t ndatalen = 0;
  int send_stream = 0;
  int ack_only;

  if (data_strm) {
    ndatalen =
        ngtcp2_min(datalen, data_strm->max_tx_offset - data_strm->tx_offset);
    if (data_strm->stream_id) {
      ndatalen = ngtcp2_min(ndatalen, conn->max_tx_offset - conn->tx_offset);
    }
    if (ndatalen || (datalen == 0 && fin)) {
      send_stream = 1;
    }
  }

  if ((conn->frq || send_stream || conn_should_send_max_data(conn)) &&
      conn->unsent_max_rx_offset > conn->max_rx_offset) {
    rv = ngtcp2_frame_chain_new(&nfrc, conn->mem);
    if (rv != 0) {
      return rv;
    }
    nfrc->fr.type = NGTCP2_FRAME_MAX_DATA;
    nfrc->fr.max_data.max_data = conn->unsent_max_rx_offset;
    nfrc->next = conn->frq;
    conn->frq = nfrc;

    conn->max_rx_offset = conn->unsent_max_rx_offset;
  }

  while (conn->fc_strms) {
    strm = conn->fc_strms;
    rv = ngtcp2_frame_chain_new(&nfrc, conn->mem);
    if (rv != 0) {
      return rv;
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
  }

  ack_only =
      !send_stream &&
      conn->unsent_max_remote_stream_id_bidi ==
          conn->max_remote_stream_id_bidi &&
      conn->unsent_max_remote_stream_id_uni == conn->max_remote_stream_id_uni &&
      conn->frq == NULL;

  if (ack_only && conn->rcs.probe_pkt_left) {
    /* Sending ACK only packet does not elicit ACK, therefore it is
       not suitable for probe packet. */
    return 0;
  }

  ackfr = NULL;
  rv = conn_create_ack_frame(conn, &ackfr, ts, !ack_only /* nodelay */,
                             0 /* unprotected */);
  if (rv != 0) {
    return rv;
  }

  if (ackfr == NULL && ack_only) {
    return 0;
  }

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE,
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
    rv = conn_ppe_write_frame(conn, &ppe, &hd, ackfr);
    if (rv != 0) {
      goto fail;
    }
    conn_commit_tx_ack(conn, 0 /* unprotected */);
    pkt_empty = 0;

    if (conn->acktr.flags & NGTCP2_ACKTR_FLAG_PENDING_FINISHED_ACK) {
      conn->acktr.flags &= (uint8_t)~NGTCP2_ACKTR_FLAG_PENDING_FINISHED_ACK;
      conn->acktr.last_hs_ack_pkt_num = hd.pkt_num;
      /* TODO We don't have to send PING if we send a frame other than
         ACK. */
      rv = ngtcp2_frame_chain_new(&nfrc, conn->mem);
      if (rv != 0) {
        goto fail;
      }
      nfrc->fr.type = NGTCP2_FRAME_PING;
      nfrc->next = conn->frq;
      conn->frq = nfrc;
    }

    ack_ent = ngtcp2_acktr_add_ack(&conn->acktr, hd.pkt_num, &ackfr->ack, ts, 0,
                                   0 /*ack_only*/);
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

    rv = conn_ppe_write_frame(conn, &ppe, &hd, &(*pfrc)->fr);
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
      conn->unsent_max_remote_stream_id_bidi >
          conn->max_remote_stream_id_bidi) {
    rv = ngtcp2_frame_chain_new(&nfrc, conn->mem);
    if (rv != 0) {
      return rv;
    }
    nfrc->fr.type = NGTCP2_FRAME_MAX_STREAM_ID;
    nfrc->fr.max_stream_id.max_stream_id =
        conn->unsent_max_remote_stream_id_bidi;
    *pfrc = nfrc;

    conn->max_remote_stream_id_bidi = conn->unsent_max_remote_stream_id_bidi;

    rv = conn_ppe_write_frame(conn, &ppe, &hd, &(*pfrc)->fr);
    if (rv != 0) {
      assert(NGTCP2_ERR_NOBUF == rv);
    } else {
      pkt_empty = 0;
      pfrc = &(*pfrc)->next;
    }
  }

  if (rv != NGTCP2_ERR_NOBUF && *pfrc == NULL &&
      conn->unsent_max_remote_stream_id_uni > conn->max_remote_stream_id_uni) {
    rv = ngtcp2_frame_chain_new(&nfrc, conn->mem);
    if (rv != 0) {
      return rv;
    }
    nfrc->fr.type = NGTCP2_FRAME_MAX_STREAM_ID;
    nfrc->fr.max_stream_id.max_stream_id =
        conn->unsent_max_remote_stream_id_uni;
    *pfrc = nfrc;

    conn->max_remote_stream_id_uni = conn->unsent_max_remote_stream_id_uni;

    rv = conn_ppe_write_frame(conn, &ppe, &hd, &(*pfrc)->fr);
    if (rv != 0) {
      assert(NGTCP2_ERR_NOBUF == rv);
    } else {
      pkt_empty = 0;
      pfrc = &(*pfrc)->next;
    }
  }

  if (rv != NGTCP2_ERR_NOBUF && *pfrc == NULL && send_stream) {
    size_t left = ngtcp2_ppe_left(&ppe);

    if (left > NGTCP2_STREAM_OVERHEAD) {
      left -= NGTCP2_STREAM_OVERHEAD;

      ndatalen = ngtcp2_min(ndatalen, left);

      fin = fin && ndatalen == datalen;

      rv = ngtcp2_frame_chain_new(&nfrc, conn->mem);
      if (rv != 0) {
        return rv;
      }

      nfrc->fr.type = NGTCP2_FRAME_STREAM;
      nfrc->fr.stream.flags = 0;
      nfrc->fr.stream.fin = fin;
      nfrc->fr.stream.stream_id = data_strm->stream_id;
      nfrc->fr.stream.offset = data_strm->tx_offset;
      nfrc->fr.stream.datalen = ndatalen;
      nfrc->fr.stream.data = data;
      *pfrc = nfrc;
      pfrc = &(*pfrc)->next;

      rv = conn_ppe_write_frame(conn, &ppe, &hd, &nfrc->fr);
      if (rv != 0) {
        assert(NGTCP2_ERR_NOBUF == rv);
        assert(0);
      }

      pkt_empty = 0;
    } else {
      send_stream = 0;
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
    rv = ngtcp2_rtb_entry_new(&ent, &hd, NULL, ts, (size_t)nwrite,
                              NGTCP2_RTB_FLAG_NONE, conn->mem);
    if (rv != 0) {
      return rv;
    }

    ent->frc = conn->frq;
    conn->frq = *pfrc;
    *pfrc = NULL;

    conn_on_pkt_sent(conn, ent);

    if (send_stream) {
      data_strm->tx_offset += ndatalen;
      if (data_strm->stream_id != 0) {
        conn->tx_offset += ndatalen;
      }

      if (fin) {
        ngtcp2_strm_shutdown(data_strm, NGTCP2_STRM_FLAG_SHUT_WR);
      }
    }
  } else if (ack_ent) {
    ack_ent->ack_only = 1;
  }

  if (pdatalen) {
    *pdatalen = ndatalen;
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
                                           size_t destlen, ngtcp2_frame *fr,
                                           ngtcp2_tstamp ts) {
  int rv;
  ngtcp2_ppe ppe;
  ngtcp2_pkt_hd hd;
  ssize_t nwrite;
  ngtcp2_crypto_ctx ctx;

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE,
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

  rv = ngtcp2_ppe_encode_frame(&ppe, fr);
  if (rv != 0) {
    return rv;
  }

  ngtcp2_log_tx_fr(&conn->log, &hd, fr);

  nwrite = ngtcp2_ppe_final(&ppe, NULL);
  if (nwrite < 0) {
    return nwrite;
  }

  /* Do this when we are sure that there is no error. */
  if (fr->type == NGTCP2_FRAME_ACK) {
    ngtcp2_acktr_add_ack(&conn->acktr, hd.pkt_num, &fr->ack, ts, 0,
                         1 /* ack_only */);
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

  ackfr = NULL;
  rv = conn_create_ack_frame(conn, &ackfr, ts, 0 /* nodelay */,
                             0 /* unprotected */);
  if (rv != 0) {
    return rv;
  }

  if (!ackfr) {
    return 0;
  }

  spktlen = conn_write_single_frame_pkt(conn, dest, destlen, ackfr, ts);
  if (spktlen < 0) {
    ngtcp2_mem_free(conn->mem, ackfr);
    return spktlen;
  }

  conn_commit_tx_ack(conn, 0 /* unprotected */);

  return spktlen;
}

/*
 * conn_process_early_rtb adds ngtcp2_rtb_entry pointed by
 * conn->early_rtb, which are 0-RTT packets, to conn->rtb.  If things
 * go wrong, this function deletes ngtcp2_rtb_entry pointed by
 * conn->early_rtb excluding the ones which are already added to
 * conn->rtb.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 */
static int conn_process_early_rtb(ngtcp2_conn *conn) {
  ngtcp2_rtb_entry *ent, *next;
  ngtcp2_frame_chain *frc;

  if (conn->flags & NGTCP2_CONN_FLAG_EARLY_DATA_REJECTED) {
    for (ent = conn->early_rtb; ent;) {
      next = ent->next;
      frc = ent->frc;
      ent->frc = NULL;
      ngtcp2_rtb_entry_del(ent, conn->mem);

      assert(frc->next == NULL);
      frc->next = conn->frq;
      conn->frq = frc;

      ent = next;
    }
  } else {
    ngtcp2_rtb_insert_range(&conn->rtb, conn->early_rtb);
  }
  conn->early_rtb = NULL;
  return 0;
}

static ssize_t conn_write_probe_pkt(ngtcp2_conn *conn, uint8_t *dest,
                                    size_t destlen, size_t *pdatalen,
                                    ngtcp2_strm *strm, uint8_t fin,
                                    const uint8_t *data, size_t datalen,
                                    ngtcp2_tstamp ts) {
  ssize_t nwrite;

  ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_CON,
                  "transmit probe pkt left=%zu", conn->rcs.probe_pkt_left);

  /* a probe packet is not blocked by cwnd. */
  nwrite = conn_write_pkt(conn, dest, destlen, pdatalen, strm, fin, data,
                          datalen, ts);
  if (nwrite == 0) {
    nwrite = conn_retransmit_unacked(conn, dest, destlen, ts);
  }
  if (nwrite > 0) {
    --conn->rcs.probe_pkt_left;

    ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_CON, "probe pkt size=%zd",
                    nwrite);
  }
  return nwrite;
}

ssize_t ngtcp2_conn_write_pkt(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                              ngtcp2_tstamp ts) {
  ssize_t nwrite;
  uint64_t cwnd;

  conn->log.last_ts = ts;

  if (conn->last_tx_pkt_num == UINT64_MAX) {
    return NGTCP2_ERR_PKT_NUM_EXHAUSTED;
  }

  switch (conn->state) {
  case NGTCP2_CS_CLIENT_INITIAL:
  case NGTCP2_CS_CLIENT_WAIT_HANDSHAKE:
  case NGTCP2_CS_CLIENT_TLS_HANDSHAKE_FAILED:
  case NGTCP2_CS_SERVER_INITIAL:
  case NGTCP2_CS_SERVER_WAIT_HANDSHAKE:
  case NGTCP2_CS_SERVER_TLS_HANDSHAKE_FAILED:
    return NGTCP2_ERR_INVALID_STATE;
  case NGTCP2_CS_POST_HANDSHAKE:
    cwnd = conn_cwnd_left(conn);
    nwrite = conn_retransmit(conn, dest, ngtcp2_min(destlen, cwnd), ts);
    if (nwrite != 0 && nwrite != NGTCP2_ERR_NOBUF) {
      return nwrite;
    }

    if (conn->rcs.probe_pkt_left) {
      return conn_write_probe_pkt(conn, dest, destlen, NULL, NULL, 0, NULL, 0,
                                  ts);
    }

    if (cwnd < NGTCP2_MIN_PKTLEN) {
      return conn_write_protected_ack_pkt(conn, dest, destlen, ts);
    }

    if (ngtcp2_rtb_has_lost_pkt(&conn->rtb)) {
      /*
       * Failed to retransmit a packet because provided buffer is too
       * small, or congestion limited.  In this case, just return 0 so
       * that we don't add extra bytes_in_flight by sending new
       * packet.
       */
      return 0;
    }

    destlen = ngtcp2_min(destlen, cwnd);

    return conn_write_pkt(conn, dest, destlen, NULL, NULL, 0, NULL, 0, ts);
  case NGTCP2_CS_CLOSING:
    return NGTCP2_ERR_CLOSING;
  case NGTCP2_CS_DRAINING:
    return NGTCP2_ERR_DRAINING;
  default:
    return 0;
  }
}

/*
 * conn_on_version_negotiation is called when Version Negotiation
 * packet is received.  The function decodes the data in the buffer
 * pointed by |payload| whose length is |payloadlen| as Version
 * Negotiation packet payload.  The packet header is given in |hd|.
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
                                       const uint8_t *payload,
                                       size_t payloadlen) {
  uint32_t sv[16];
  uint32_t *p;
  int rv = 0;
  size_t nsv;

  if (payloadlen % sizeof(uint32_t)) {
    return NGTCP2_ERR_PROTO;
  }

  if (payloadlen > sizeof(sv)) {
    p = ngtcp2_mem_malloc(conn->mem, payloadlen);
    if (p == NULL) {
      return NGTCP2_ERR_NOMEM;
    }
  } else {
    p = sv;
  }

  nsv = ngtcp2_pkt_decode_version_negotiation(p, payload, payloadlen);

  ngtcp2_log_rx_vn(&conn->log, hd, sv, nsv);

  if (conn->callbacks.recv_version_negotiation) {
    rv = conn->callbacks.recv_version_negotiation(conn, hd, sv, nsv,
                                                  conn->user_data);
  }

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
static int conn_recv_ack(ngtcp2_conn *conn, ngtcp2_ack *fr, int unprotected,
                         ngtcp2_tstamp ts) {
  int rv;

  rv = ngtcp2_pkt_validate_ack(fr);
  if (rv != 0) {
    return rv;
  }

  rv = ngtcp2_acktr_recv_ack(&conn->acktr, fr, unprotected, conn, ts);
  if (rv != 0) {
    return rv;
  }

  rv = ngtcp2_rtb_recv_ack(&conn->rtb, fr, unprotected, conn, ts);
  if (rv != 0) {
    return rv;
  }

  conn->largest_ack = ngtcp2_max(conn->largest_ack, (int64_t)fr->largest_ack);

  ngtcp2_rtb_detect_lost_pkt(&conn->rtb, &conn->rcs, fr->largest_ack,
                             conn->last_tx_pkt_num, ts);

  ngtcp2_conn_set_loss_detection_alarm(conn);

  return 0;
}

/*
 * conn_assign_recved_ack_delay_unscaled assigns
 * fr->ack_delay_unscaled.
 */
static void conn_assign_recved_ack_delay_unscaled(ngtcp2_conn *conn,
                                                  ngtcp2_ack *fr,
                                                  int unprotected) {
  fr->ack_delay_unscaled =
      (fr->ack_delay << (unprotected
                             ? NGTCP2_DEFAULT_ACK_DELAY_EXPONENT
                             : conn->remote_settings.ack_delay_exponent)) *
      1000;
}

/*
 * conn_recv_max_stream_data processes received MAX_STREAM_DATA frame
 * |fr|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_STREAM_STATE
 *     Stream ID indicates that it is a local stream, and the local
 *     endpoint has not initiated it.
 * NGTCP2_ERR_STREAM_ID
 *     Stream ID exceeds allowed limit.
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 */
static int conn_recv_max_stream_data(ngtcp2_conn *conn,
                                     const ngtcp2_max_stream_data *fr) {
  ngtcp2_strm *strm;
  ngtcp2_idtr *idtr;
  int local_stream = conn_local_stream(conn, fr->stream_id);
  int bidi = bidi_stream(fr->stream_id);
  int rv;

  if (bidi) {
    if (local_stream) {
      if (conn->next_local_stream_id_bidi <= fr->stream_id) {
        return NGTCP2_ERR_STREAM_STATE;
      }
    } else if (conn->max_remote_stream_id_bidi < fr->stream_id) {
      return NGTCP2_ERR_STREAM_ID;
    }

    idtr = &conn->remote_bidi_idtr;
  } else {
    if (!local_stream) {
      return NGTCP2_ERR_PROTO;
    }
    if (conn->next_local_stream_id_uni <= fr->stream_id) {
      return NGTCP2_ERR_PROTO;
    }

    idtr = &conn->remote_uni_idtr;
  }

  strm = ngtcp2_conn_find_stream(conn, fr->stream_id);
  if (strm == NULL) {
    if (local_stream) {
      /* Stream has been closed. */
      return 0;
    }

    rv = ngtcp2_idtr_open(idtr, fr->stream_id);
    if (rv == NGTCP2_ERR_STREAM_IN_USE) {
      /* Stream has been closed. */
      return 0;
    }

    strm = ngtcp2_mem_malloc(conn->mem, sizeof(ngtcp2_strm));
    if (strm == NULL) {
      return NGTCP2_ERR_NOMEM;
    }
    rv = ngtcp2_conn_init_stream(conn, strm, fr->stream_id, NULL);
    if (rv != 0) {
      return rv;
    }
  }

  strm->max_tx_offset = ngtcp2_max(strm->max_tx_offset, fr->max_stream_data);

  return 0;
}

/*
 * conn_recv_max_data processes received MAX_DATA frame |fr|.
 */
static void conn_recv_max_data(ngtcp2_conn *conn, const ngtcp2_max_data *fr) {
  conn->max_tx_offset = ngtcp2_max(conn->max_tx_offset, fr->max_data);
}

/*
 * conn_buffer_protected_pkt buffers a protected packet |pkt| whose
 * length is |pktlen|.  This function is called when a protected
 * packet is received, but the local endpoint has not established
 * cryptographic context (e.g., Handshake packet is lost or delayed).
 *
 * This function also buffers 0-RTT Protected packet if it arrives
 * before Initial packet.
 *
 * The processing of 0-RTT Protected and Short packets take place in
 * their own stage, and we don't buffer them at the same time.
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

  conn->max_rx_pkt_num = 0;

  ngtcp2_rtb_free(&conn->rtb);
  ngtcp2_acktr_free(&conn->acktr);
  ngtcp2_map_remove(&conn->strms, 0);
  ngtcp2_strm_free(conn->strm0);
  ngtcp2_mem_free(conn->mem, conn->strm0);

  conn->strm0 = strm0;

  ngtcp2_acktr_init(&conn->acktr, &conn->log, conn->mem);
  ngtcp2_rtb_init(&conn->rtb, &conn->log, conn->mem);
  ngtcp2_map_insert(&conn->strms, &conn->strm0->me);

  conn->flags &= (uint8_t)~NGTCP2_CONN_FLAG_CONN_ID_NEGOTIATED;
  conn->state = NGTCP2_CS_CLIENT_INITIAL;

  return 0;
}

/*
 * conn_ensure_decrypt_buffer ensures that conn->decrypt_buf has at
 * least |n| bytes space.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 */
static int conn_ensure_decrypt_buffer(ngtcp2_conn *conn, size_t n) {
  uint8_t *nbuf;
  size_t len;

  if (conn->decrypt_buf.len >= n) {
    return 0;
  }

  len = conn->decrypt_buf.len == 0 ? 2048 : conn->decrypt_buf.len * 2;
  for (; len < n; len *= 2)
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
 * conn_decrypt_pkt decrypts the data pointed by |payload| whose
 * length is |payloadlen|, and writes plaintext data to the buffer
 * pointed by |dest| whose capacity is |destlen|.  The buffer pointed
 * by |ad| is the Additional Data, and its length is |adlen|.
 * |pkt_num| is used to create a nonce.  |ckm| is the cryptographic
 * key, and iv to use.  |decrypt| is a callback function which
 * actually decrypts a packet.
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
                                size_t destlen, const uint8_t *payload,
                                size_t payloadlen, const uint8_t *ad,
                                size_t adlen, uint64_t pkt_num,
                                ngtcp2_crypto_km *ckm, ngtcp2_decrypt decrypt) {
  /* TODO nonce is limited to 64 bytes. */
  uint8_t nonce[64];
  ssize_t nwrite;

  assert(sizeof(nonce) >= ckm->ivlen);

  ngtcp2_crypto_create_nonce(nonce, ckm->iv, ckm->ivlen, pkt_num);

  nwrite = decrypt(conn, dest, destlen, payload, payloadlen, ckm->key,
                   ckm->keylen, nonce, ckm->ivlen, ad, adlen, conn->user_data);

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
  if (strm->unsent_max_rx_offset <= NGTCP2_MAX_VARINT - datalen) {
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
 * NGTCP2_ERR_TLS_FATAL_ALERT_GENERATED
 *     After handshake has completed, TLS fatal alert is generated.
 * NGTCP2_ERR_TLS_FATAL_ALERT_RECEIVED
 *     After handshake has completed, TLS fatal alert is received.
 */
static int conn_emit_pending_stream0_data(ngtcp2_conn *conn, ngtcp2_strm *strm,
                                          uint64_t rx_offset) {
  size_t datalen;
  const uint8_t *data;
  int rv;
  uint64_t offset;

  for (;;) {
    datalen = ngtcp2_rob_data_at(&strm->rob, &data, rx_offset);
    if (datalen == 0) {
      assert(rx_offset == ngtcp2_strm_rx_offset(strm));
      return 0;
    }

    offset = rx_offset;
    rx_offset += datalen;

    rv = conn_call_recv_stream0_data(conn, offset, data, datalen);
    if (rv != 0) {
      return rv;
    }

    strm->unsent_max_rx_offset += datalen;
    conn_extend_max_stream_offset(conn, strm, datalen);

    ngtcp2_rob_pop(&strm->rob, rx_offset - datalen, datalen);
  }
}

/* conn_recv_connection_close is called when CONNECTION_CLOSE or
   APPLICATION_CLOSE frame is received. */
static void conn_recv_connection_close(ngtcp2_conn *conn) {
  conn->state = NGTCP2_CS_DRAINING;
}

static void conn_recv_path_challenge(ngtcp2_conn *conn,
                                     ngtcp2_path_challenge *fr,
                                     ngtcp2_tstamp ts) {
  ngtcp2_path_challenge_entry *ent;

  ent = ngtcp2_ringbuf_push_front(&conn->rx_path_challenge);
  ent->ts = ts;
  assert(sizeof(ent->data) == sizeof(fr->data));
  ngtcp2_cpymem(ent->data, fr->data, sizeof(ent->data));
}

static void conn_recv_path_response(ngtcp2_conn *conn,
                                    ngtcp2_path_response *fr) {
  size_t len = ngtcp2_ringbuf_len(&conn->tx_path_challenge);
  size_t i;
  ngtcp2_path_challenge_entry *ent;

  for (i = 0; i < len; ++i) {
    ent = ngtcp2_ringbuf_get(&conn->tx_path_challenge, i);
    if (memcmp(ent->data, fr->data, sizeof(ent->data)) == 0) {
      ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_CON,
                      "source address validated");
      conn->flags |= NGTCP2_CONN_FLAG_SADDR_VERIFIED;
      ngtcp2_ringbuf_resize(&conn->tx_path_challenge, 0);
      return;
    }
  }
}

/* conn_update_rx_bw updates rx bandwidth. */
static void conn_update_rx_bw(ngtcp2_conn *conn, size_t datalen,
                              ngtcp2_tstamp ts) {
  /* Reset bandwidth measurement after 1 second idle time. */
  if (ts - conn->first_rx_bw_ts > 1000000000) {
    conn->first_rx_bw_ts = ts;
    conn->rx_bw_datalen = datalen;
    conn->rx_bw = 0.;
    return;
  }

  conn->rx_bw_datalen += datalen;

  if (ts - conn->first_rx_bw_ts >= 25000000) {
    conn->rx_bw = (double)conn->rx_bw_datalen / (ts - conn->first_rx_bw_ts);

    ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_CON, "rx_bw=%.02fBs",
                    conn->rx_bw * 1000000000);
  }
}

static int conn_recv_pkt(ngtcp2_conn *conn, const uint8_t *pkt, size_t pktlen,
                         ngtcp2_tstamp ts);

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
 * NGTCP2_ERR_TLS_HANDSHAKE
 *     TLS handshake failed, and/or TLS alert was generated.
 * NGTCP2_ERR_FRAME_FORMAT
 *     Frame is badly formatted.
 * NGTCP2_ERR_RECV_VERSION_NEGOTIATION
 *     Version Negotiation packet is received.
 * NGTCP2_ERR_TLS_DECRYPT
 *     Could not decrypt a packet.
 *
 * In addition to the above error codes, error codes returned from
 * conn_recv_pkt are also returned.
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
  size_t hdpktlen;
  const uint8_t *payload;
  size_t payloadlen;
  ssize_t nwrite;

  if (pktlen == 0) {
    return 0;
  }

  if (!(pkt[0] & NGTCP2_HEADER_FORM_BIT)) {
    if (conn->state == NGTCP2_CS_SERVER_INITIAL) {
      /* Ignore Short packet unless server's first Handshake packet
         has been transmitted. */
      return 0;
    }
    return conn_buffer_protected_pkt(conn, pkt, pktlen, ts);
  }

  nread = ngtcp2_pkt_decode_hd_long(&hd, pkt, pktlen);
  if (nread < 0) {
    return (int)nread;
  }

  if (conn->server && conn->early_ckm && conn->client_conn_id == hd.conn_id &&
      hd.type == NGTCP2_PKT_0RTT_PROTECTED) {
    /* TODO Avoid to parse header twice. */
    return conn_recv_pkt(conn, pkt, pktlen, ts);
  }

  if (hd.version == 0) {
    hd.type = NGTCP2_PKT_VERSION_NEGOTIATION;
    hd.pkt_num = 0;

    hdpktlen = (size_t)nread - sizeof(uint32_t);
  } else {
    if (conn->version != hd.version) {
      return 0;
    }
    hd.pkt_num =
        ngtcp2_pkt_adjust_pkt_num(conn->max_rx_pkt_num, hd.pkt_num, 32);
    hdpktlen = (size_t)nread;
  }

  payload = pkt + hdpktlen;
  payloadlen = pktlen - hdpktlen;

  if (conn->server) {
    switch (hd.type) {
    case NGTCP2_PKT_INITIAL:
      if ((conn->flags & NGTCP2_CONN_FLAG_CONN_ID_NEGOTIATED) == 0) {
        conn->flags |= NGTCP2_CONN_FLAG_CONN_ID_NEGOTIATED;
        conn->client_conn_id = hd.conn_id;
        rv = conn_call_recv_client_initial(conn);
        if (rv != 0) {
          return rv;
        }
      }
      break;
    case NGTCP2_PKT_HANDSHAKE:
      if (conn->conn_id != hd.conn_id) {
        return 0;
      }
      break;
    case NGTCP2_PKT_0RTT_PROTECTED:
      if (!(conn->flags & NGTCP2_CONN_FLAG_CONN_ID_NEGOTIATED)) {
        /* Buffer re-ordered 0-RTT Protected packet. */
        return conn_buffer_protected_pkt(conn, pkt, pktlen, ts);
      }
      /* Discard 0-RTT packet if we don't have a key to decrypt it. */
      return 0;
    default:
      return NGTCP2_ERR_PROTO;
    }
  } else {
    switch (hd.type) {
    case NGTCP2_PKT_HANDSHAKE:
      if (conn->flags & NGTCP2_CONN_FLAG_CONN_ID_NEGOTIATED) {
        if (conn->conn_id != hd.conn_id) {
          return 0;
        }
      } else {
        conn->flags |= NGTCP2_CONN_FLAG_CONN_ID_NEGOTIATED;
        conn->conn_id = hd.conn_id;
      }
      break;
    case NGTCP2_PKT_RETRY:
      if (conn->strm0->last_rx_offset != 0) {
        return NGTCP2_ERR_PROTO;
      }
      /* hd.conn_id is a connection ID chosen by server, and client
         MUST choose it in a subsequent packets. */
      conn->conn_id = hd.conn_id;
      break;
    case NGTCP2_PKT_VERSION_NEGOTIATION:
      if (conn->client_conn_id != hd.conn_id) {
        /* Just discard invalid Version Negotiation packet */
        return 0;
      }
      rv = conn_on_version_negotiation(conn, &hd, payload, payloadlen);
      if (rv != 0) {
        return rv;
      }
      return NGTCP2_ERR_RECV_VERSION_NEGOTIATION;
    default:
      return NGTCP2_ERR_PROTO;
    }
  }

  rv = conn_ensure_decrypt_buffer(conn, payloadlen);
  if (rv != 0) {
    return rv;
  }

  nwrite = conn_decrypt_pkt(conn, conn->decrypt_buf.base, payloadlen, payload,
                            payloadlen, hdpkt, hdpktlen, hd.pkt_num,
                            conn->hs_rx_ckm, conn->callbacks.hs_decrypt);
  if (nwrite < 0) {
    return (int)nwrite;
  }

  payload = conn->decrypt_buf.base;
  payloadlen = (size_t)nwrite;

  for (; payloadlen;) {
    nread = ngtcp2_pkt_decode_frame(fr, payload, payloadlen);
    if (nread < 0) {
      return (int)nread;
    }

    payload += nread;
    payloadlen -= (size_t)nread;

    if (fr->type == NGTCP2_FRAME_ACK) {
      conn_assign_recved_ack_delay_unscaled(conn, &fr->ack, 1);
    }

    ngtcp2_log_rx_fr(&conn->log, &hd, fr);

    switch (fr->type) {
    case NGTCP2_FRAME_ACK:
      switch (hd.type) {
      case NGTCP2_PKT_INITIAL:
      case NGTCP2_PKT_RETRY:
        return NGTCP2_ERR_PROTO;
      }
      /* TODO Assume that all packets here are unprotected */
      rv = conn_recv_ack(conn, &fr->ack, 1, ts);
      if (rv != 0) {
        return rv;
      }
      continue;
    case NGTCP2_FRAME_PADDING:
      if (hd.type == NGTCP2_PKT_RETRY) {
        return NGTCP2_ERR_PROTO;
      }
      continue;
    case NGTCP2_FRAME_STREAM:
      require_ack = 1;
      break;
    case NGTCP2_FRAME_CONNECTION_CLOSE:
      if (hd.type == NGTCP2_PKT_HANDSHAKE) {
        require_ack = 1;
        conn_recv_connection_close(conn);
        continue;
      }
      return NGTCP2_ERR_PROTO;
    case NGTCP2_FRAME_PATH_CHALLENGE:
      conn_recv_path_challenge(conn, &fr->path_challenge, ts);
      continue;
    case NGTCP2_FRAME_PATH_RESPONSE:
      conn_recv_path_response(conn, &fr->path_response);
      continue;
    default:
      return NGTCP2_ERR_PROTO;
    }

    assert(fr->type == NGTCP2_FRAME_STREAM);

    if (fr->stream.stream_id != 0) {
      return NGTCP2_ERR_PROTO;
    }

    if (fr->stream.datalen == 0) {
      return NGTCP2_ERR_FRAME_FORMAT;
    }

    if (hd.type == NGTCP2_PKT_INITIAL && fr->stream.offset != 0) {
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

    /* Although stream 0 is exempted from flow contorl during
       handshake, peer can send data on any offset, and forces
       receiver to buffer unlimited data.  In order to avoid that
       situation, we have a fixed limit for handshake which is
       supposed to be large enough for handshake. */
    if (NGTCP2_MAX_HS_STREAM0_OFFSET < fr_end_offset) {
      return NGTCP2_ERR_PROTO;
    }

    if (fr->stream.offset <= rx_offset) {
      size_t ncut = (rx_offset - fr->stream.offset);
      const uint8_t *data = fr->stream.data + ncut;
      size_t datalen = fr->stream.datalen - ncut;
      uint64_t offset = rx_offset;

      rx_offset += datalen;
      ngtcp2_rob_remove_prefix(&conn->strm0->rob, rx_offset);

      rv = conn_call_recv_stream0_data(conn, offset, data, datalen);
      switch (rv) {
      case 0:
        break;
      case NGTCP2_ERR_TLS_HANDSHAKE:
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
  case NGTCP2_PKT_INITIAL:
  case NGTCP2_PKT_RETRY:
    if (ngtcp2_rob_first_gap_offset(&conn->strm0->rob) == 0) {
      return NGTCP2_ERR_PROTO;
    }
    break;
  }

  conn->max_rx_pkt_num = ngtcp2_max(conn->max_rx_pkt_num, hd.pkt_num);

  if (hd.type == NGTCP2_PKT_RETRY) {
    if (handshake_failed) {
      return NGTCP2_ERR_PROTO;
    }

    rv = conn_recv_server_stateless_retry(conn);
    if (rv != 0) {
      return rv;
    }

    return 0;
  }

  rv = ngtcp2_conn_sched_ack(conn, hd.pkt_num, require_ack, ts,
                             1 /*unprotected*/);
  if (rv != 0) {
    return rv;
  }

  return handshake_failed ? NGTCP2_ERR_TLS_HANDSHAKE : 0;
}

int ngtcp2_conn_init_stream(ngtcp2_conn *conn, ngtcp2_strm *strm,
                            uint64_t stream_id, void *stream_user_data) {
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
  uint64_t offset;

  for (;;) {
    datalen = ngtcp2_rob_data_at(&strm->rob, &data, rx_offset);
    if (datalen == 0) {
      assert(rx_offset == ngtcp2_strm_rx_offset(strm));
      return 0;
    }

    offset = rx_offset;
    rx_offset += datalen;

    rv = conn_call_recv_stream_data(conn, strm,
                                    (strm->flags & NGTCP2_STRM_FLAG_SHUT_RD) &&
                                        rx_offset == strm->last_rx_offset,
                                    offset, data, datalen);
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
  return conn->max_rx_offset - conn->rx_offset < datalen;
}

static int conn_recv_stream(ngtcp2_conn *conn, const ngtcp2_stream *fr) {
  int rv;
  ngtcp2_strm *strm;
  ngtcp2_idtr *idtr;
  uint64_t rx_offset, fr_end_offset;
  int local_stream;
  int bidi;

  if (fr->stream_id == 0 && fr->fin) {
    return NGTCP2_ERR_PROTO;
  }

  if (!fr->fin && fr->datalen == 0) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  local_stream = conn_local_stream(conn, fr->stream_id);
  bidi = bidi_stream(fr->stream_id);

  if (bidi) {
    if (local_stream) {
      if (conn->next_local_stream_id_bidi <= fr->stream_id) {
        return NGTCP2_ERR_STREAM_STATE;
      }
    } else if (conn->max_remote_stream_id_bidi < fr->stream_id) {
      return NGTCP2_ERR_STREAM_ID;
    }

    idtr = &conn->remote_bidi_idtr;
  } else {
    if (local_stream) {
      return NGTCP2_ERR_PROTO;
    }
    if (conn->max_remote_stream_id_uni < fr->stream_id) {
      return NGTCP2_ERR_STREAM_ID;
    }

    idtr = &conn->remote_uni_idtr;
  }

  if (NGTCP2_MAX_VARINT - fr->datalen < fr->offset) {
    return NGTCP2_ERR_PROTO;
  }

  strm = ngtcp2_conn_find_stream(conn, fr->stream_id);
  if (strm == NULL) {
    if (local_stream) {
      /* TODO The stream has been closed.  This should be responded
         with RST_STREAM, or simply ignored. */
      return 0;
    }

    rv = ngtcp2_idtr_open(idtr, fr->stream_id);
    if (rv == NGTCP2_ERR_STREAM_IN_USE) {
      /* TODO The stream has been closed.  This should be responded
         with RST_STREAM, or simply ignored. */
      return 0;
    }
    assert(0 == rv);

    strm = ngtcp2_mem_malloc(conn->mem, sizeof(ngtcp2_strm));
    if (strm == NULL) {
      return NGTCP2_ERR_NOMEM;
    }
    /* TODO Perhaps, call new_stream callback? */
    rv = ngtcp2_conn_init_stream(conn, strm, fr->stream_id, NULL);
    if (rv != 0) {
      return rv;
    }
    if (!bidi) {
      ngtcp2_strm_shutdown(strm, NGTCP2_STRM_FLAG_SHUT_WR);
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

      conn->rx_offset += datalen;
    }
  }

  rx_offset = ngtcp2_strm_rx_offset(strm);

  if (fr->fin) {
    if (strm->flags & NGTCP2_STRM_FLAG_SHUT_RD) {
      if (strm->last_rx_offset != fr_end_offset) {
        return NGTCP2_ERR_FINAL_OFFSET;
      }
    } else if (strm->last_rx_offset > fr_end_offset) {
      return NGTCP2_ERR_FINAL_OFFSET;
    } else {
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

      if (fr_end_offset == rx_offset) {
        rv = conn_call_recv_stream_data(conn, strm, 1, rx_offset, NULL, 0);
        if (rv != 0) {
          return rv;
        }
        return ngtcp2_conn_close_stream_if_shut_rdwr(conn, strm,
                                                     NGTCP2_NO_ERROR);
      }
    }
  } else {
    if ((strm->flags & NGTCP2_STRM_FLAG_SHUT_RD) &&
        strm->last_rx_offset < fr_end_offset) {
      return NGTCP2_ERR_FINAL_OFFSET;
    }

    strm->last_rx_offset = ngtcp2_max(strm->last_rx_offset, fr_end_offset);

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
    uint64_t offset = rx_offset;

    rx_offset += datalen;
    ngtcp2_rob_remove_prefix(&strm->rob, rx_offset);

    if (strm->stream_id == 0) {
      rv = conn_call_recv_stream0_data(conn, offset, data, datalen);
      if (rv != 0) {
        return rv;
      }

      rv = conn_emit_pending_stream0_data(conn, conn->strm0, rx_offset);
    } else {
      rv =
          conn_call_recv_stream_data(conn, strm,
                                     (strm->flags & NGTCP2_STRM_FLAG_SHUT_RD) &&
                                         rx_offset == strm->last_rx_offset,
                                     offset, data, datalen);
      if (rv != 0) {
        return rv;
      }

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
  int bidi = bidi_stream(fr->stream_id);
  uint64_t datalen;
  ngtcp2_idtr *idtr;

  if (fr->stream_id == 0) {
    return NGTCP2_ERR_PROTO;
  }

  if (bidi) {
    if (local_stream) {
      if (conn->next_local_stream_id_bidi <= fr->stream_id) {
        return NGTCP2_ERR_STREAM_STATE;
      }
    } else if (fr->stream_id > conn->max_remote_stream_id_bidi) {
      return NGTCP2_ERR_STREAM_ID;
    }

    idtr = &conn->remote_bidi_idtr;
  } else {
    if (local_stream) {
      return NGTCP2_ERR_PROTO;
    }
    if (fr->stream_id > conn->max_remote_stream_id_uni) {
      return NGTCP2_ERR_STREAM_ID;
    }

    idtr = &conn->remote_uni_idtr;
  }

  strm = ngtcp2_conn_find_stream(conn, fr->stream_id);
  if (strm == NULL) {
    if (!local_stream && !ngtcp2_idtr_is_open(idtr, fr->stream_id)) {
      /* Stream is reset before we create ngtcp2_strm object. */
      if (conn->local_settings.max_stream_data < fr->final_offset ||
          conn_max_data_violated(conn, fr->final_offset)) {
        return NGTCP2_ERR_FLOW_CONTROL;
      }
      ngtcp2_idtr_open(idtr, fr->stream_id);
      conn->rx_offset += fr->final_offset;
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

  conn->rx_offset += datalen;

  strm->flags |= NGTCP2_STRM_FLAG_SHUT_RD | NGTCP2_STRM_FLAG_RECV_RST;

  return ngtcp2_conn_close_stream_if_shut_rdwr(conn, strm, fr->app_error_code);
}

static int conn_recv_stop_sending(ngtcp2_conn *conn,
                                  const ngtcp2_stop_sending *fr) {
  int rv;
  ngtcp2_strm *strm;
  ngtcp2_idtr *idtr;
  int local_stream = conn_local_stream(conn, fr->stream_id);
  int bidi = bidi_stream(fr->stream_id);

  if (fr->stream_id == 0) {
    return NGTCP2_ERR_PROTO;
  }

  if (bidi) {
    if (local_stream) {
      if (conn->next_local_stream_id_bidi <= fr->stream_id) {
        return NGTCP2_ERR_STREAM_STATE;
      }
    } else if (fr->stream_id > conn->max_remote_stream_id_bidi) {
      return NGTCP2_ERR_STREAM_ID;
    }

    idtr = &conn->remote_bidi_idtr;
  } else {
    if (!local_stream) {
      return NGTCP2_ERR_PROTO;
    }
    if (conn->next_local_stream_id_uni <= fr->stream_id) {
      return NGTCP2_ERR_STREAM_STATE;
    }

    idtr = &conn->remote_uni_idtr;
  }

  strm = ngtcp2_conn_find_stream(conn, fr->stream_id);
  if (strm == NULL) {
    if (!local_stream && !ngtcp2_idtr_is_open(idtr, fr->stream_id)) {
      /* Frame is received reset before we create ngtcp2_strm
         object. */
      ngtcp2_idtr_open(idtr, fr->stream_id);
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

/*
 * conn_on_stateless_reset decodes Stateless Reset from the buffer
 * pointed by |payload| whose length is |payloadlen|.  |payload|
 * should start after Packet Number.  The short packet header,
 * optional connection ID, and Packet number are already parsed and
 * removed from the buffer.
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
                                   const uint8_t *payload, size_t payloadlen) {
  int rv;
  ngtcp2_pkt_stateless_reset sr;
  const uint8_t *token;
  size_t i;

  rv = ngtcp2_pkt_decode_stateless_reset(&sr, payload, payloadlen);
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

  conn->state = NGTCP2_CS_DRAINING;

  ngtcp2_log_rx_sr(&conn->log, hd, &sr);

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
 * this packet to the peer.  We assume that hd->type is one of
 * Initial, or Handshake.  |ad| and |adlen| is an additional data and
 * its length to decrypt a packet.
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
                                           const uint8_t *payload,
                                           size_t payloadlen, const uint8_t *ad,
                                           size_t adlen, ngtcp2_tstamp ts) {
  ssize_t nread;
  ngtcp2_max_frame mfr;
  ngtcp2_frame *fr = &mfr.fr;
  int rv;
  int require_ack = 0;
  ssize_t nwrite;

  if (hd->type == NGTCP2_PKT_INITIAL) {
    if (!conn->server || conn->client_conn_id != hd->conn_id) {
      return 0;
    }
  } else if (conn->conn_id != hd->conn_id) {
    return 0;
  }

  rv = conn_ensure_decrypt_buffer(conn, payloadlen);
  if (rv != 0) {
    return rv;
  }

  nwrite = conn_decrypt_pkt(conn, conn->decrypt_buf.base, payloadlen, payload,
                            payloadlen, ad, adlen, hd->pkt_num, conn->hs_rx_ckm,
                            conn->callbacks.hs_decrypt);
  if (nwrite < 0) {
    return (int)nwrite;
  }

  payload = conn->decrypt_buf.base;
  payloadlen = (size_t)nwrite;

  for (; payloadlen;) {
    nread = ngtcp2_pkt_decode_frame(fr, payload, payloadlen);
    if (nread < 0) {
      return (int)nread;
    }

    payload += nread;
    payloadlen -= (size_t)nread;

    if (fr->type == NGTCP2_FRAME_ACK) {
      conn_assign_recved_ack_delay_unscaled(conn, &fr->ack, 1);
    }

    ngtcp2_log_rx_fr(&conn->log, hd, fr);

    switch (fr->type) {
    case NGTCP2_FRAME_ACK:
      if (hd->type == NGTCP2_PKT_INITIAL) {
        return NGTCP2_ERR_PROTO;
      }
      rv = conn_recv_ack(conn, &fr->ack, 1, ts);
      if (rv != 0) {
        return rv;
      }
      continue;
    case NGTCP2_FRAME_PADDING:
      break;
    case NGTCP2_FRAME_STREAM:
      /* STREAM frame for stream 0 never be 0 length because it never
         have fin bit set. */
      if (fr->stream.stream_id != 0 || fr->stream.fin ||
          fr->stream.datalen == 0) {
        return NGTCP2_ERR_PROTO;
      }
      /* Handshake has completed.  Delayed STREAM frame should not
         advance offset which finished handshake. */
      if (fr->stream.offset + fr->stream.datalen > conn->final_hs_rx_offset) {
        return NGTCP2_ERR_PROTO;
      }
      require_ack = 1;
      break;
    default:
      return NGTCP2_ERR_PROTO;
    }
  }

  conn->max_rx_pkt_num = ngtcp2_max(conn->max_rx_pkt_num, hd->pkt_num);

  return ngtcp2_conn_sched_ack(conn, hd->pkt_num, require_ack, ts,
                               1 /* unprotected */);
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
  if (bidi_stream(fr->max_stream_id)) {
    conn->max_local_stream_id_bidi =
        ngtcp2_max(conn->max_local_stream_id_bidi, fr->max_stream_id);
  } else {
    conn->max_local_stream_id_uni =
        ngtcp2_max(conn->max_local_stream_id_uni, fr->max_stream_id);
  }

  return conn_call_extend_max_stream_id(conn, fr->max_stream_id);
}

static int conn_recv_pkt(ngtcp2_conn *conn, const uint8_t *pkt, size_t pktlen,
                         ngtcp2_tstamp ts) {
  ngtcp2_pkt_hd hd;
  size_t pkt_num_bits;
  int rv = 0;
  const uint8_t *hdpkt = pkt;
  size_t hdpktlen;
  const uint8_t *payload;
  size_t payloadlen;
  ssize_t nread, nwrite;
  ngtcp2_max_frame mfr;
  ngtcp2_frame *fr = &mfr.fr;
  int require_ack = 0;
  ngtcp2_crypto_km *ckm;

  if (pkt[0] & NGTCP2_HEADER_FORM_BIT) {
    nread = ngtcp2_pkt_decode_hd_long(&hd, pkt, pktlen);
    if (nread < 0) {
      return (int)nread;
    }

    if (hd.version == 0) {
      /* Ignore late VN. */
      return 0;
    }

    if (conn->version != hd.version) {
      return 0;
    }

    switch (hd.type) {
    case NGTCP2_PKT_INITIAL:
    case NGTCP2_PKT_HANDSHAKE:
      /* Ignore incoming unprotected packet after we get all
         acknowledgements to unprotected packet we sent so far. */
      if (conn->final_hs_tx_offset &&
          ngtcp2_gaptr_first_gap_offset(&conn->strm0->acked_tx_offset) >=
              conn->final_hs_tx_offset &&
          (!conn->server ||
           (conn->acktr.flags & NGTCP2_ACKTR_FLAG_ACK_FINISHED_ACK))) {
        ngtcp2_log_info(
            &conn->log, NGTCP2_LOG_EVENT_CON,
            "unprotected packet %" PRIu64
            " is ignored because handshake has finished",
            ngtcp2_pkt_adjust_pkt_num(conn->max_rx_pkt_num, hd.pkt_num, 32));

        return 0;
      }
      break;
    }
  } else {
    nread = ngtcp2_pkt_decode_hd_short(&hd, pkt, pktlen);
    if (nread < 0) {
      return (int)nread;
    }
    if (!conn->local_settings.omit_connection_id &&
        (hd.flags & NGTCP2_PKT_FLAG_OMIT_CONN_ID)) {
      return NGTCP2_ERR_PROTO;
    }
  }

  hdpktlen = (size_t)nread;
  payload = pkt + hdpktlen;
  payloadlen = pktlen - hdpktlen;

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

  if (hd.flags & NGTCP2_PKT_FLAG_LONG_FORM) {
    switch (hd.type) {
    case NGTCP2_PKT_INITIAL:
    case NGTCP2_PKT_HANDSHAKE:
      return conn_recv_delayed_handshake_pkt(conn, &hd, payload, payloadlen,
                                             hdpkt, hdpktlen, ts);
    case NGTCP2_PKT_0RTT_PROTECTED:
      if (!conn->server || conn->client_conn_id != hd.conn_id ||
          conn->version != hd.version) {
        return 0;
      }
      if (!conn->early_ckm) {
        return 0;
      }
      ckm = conn->early_ckm;
      break;
    default:
      /* Ignore unprotected packet after handshake */
      return 0;
    }
  } else {
    ckm = conn->rx_ckm;
  }

  rv = conn_ensure_decrypt_buffer(conn, payloadlen);
  if (rv != 0) {
    return rv;
  }

  nwrite = conn_decrypt_pkt(conn, conn->decrypt_buf.base, payloadlen, payload,
                            payloadlen, hdpkt, hdpktlen, hd.pkt_num, ckm,
                            conn->callbacks.decrypt);
  if (nwrite < 0) {
    if (nwrite != NGTCP2_ERR_TLS_DECRYPT ||
        (hd.flags & NGTCP2_PKT_FLAG_LONG_FORM)) {
      return (int)nwrite;
    }

    if (!(hd.flags & NGTCP2_PKT_FLAG_LONG_FORM)) {
      rv = conn_on_stateless_reset(conn, &hd, payload, payloadlen);
      if (rv == 0) {
        return 0;
      }
    }
    return (int)nwrite;
  }
  payload = conn->decrypt_buf.base;
  payloadlen = (size_t)nwrite;

  if (!(hd.flags & NGTCP2_PKT_FLAG_LONG_FORM)) {
    conn->flags |= NGTCP2_CONN_FLAG_RECV_PROTECTED_PKT;

    if (!(hd.flags & NGTCP2_PKT_FLAG_OMIT_CONN_ID) &&
        conn->conn_id != hd.conn_id) {
      return 0;
    }
  }

  for (; payloadlen;) {
    nread = ngtcp2_pkt_decode_frame(fr, payload, payloadlen);
    if (nread < 0) {
      return (int)nread;
    }

    payload += nread;
    payloadlen -= (size_t)nread;

    if (fr->type == NGTCP2_FRAME_ACK) {
      conn_assign_recved_ack_delay_unscaled(conn, &fr->ack, 0);
    }

    ngtcp2_log_rx_fr(&conn->log, &hd, fr);

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
      rv = conn_recv_ack(conn, &fr->ack, 0, ts);
      if (rv != 0) {
        return rv;
      }
      break;
    case NGTCP2_FRAME_STREAM:
      /* Stream 0 STREAM in 0-RTT Protected packet is not allowed. */
      if (fr->stream.stream_id == 0 && (hd.flags & NGTCP2_PKT_FLAG_LONG_FORM)) {
        return NGTCP2_ERR_PROTO;
      }
      rv = conn_recv_stream(conn, &fr->stream);
      if (rv != 0) {
        return rv;
      }
      conn_update_rx_bw(conn, fr->stream.datalen, ts);
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
      rv = conn_recv_max_stream_data(conn, &fr->max_stream_data);
      if (rv != 0) {
        return rv;
      }
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

  return ngtcp2_conn_sched_ack(conn, hd.pkt_num, require_ack, ts,
                               0 /* unprotected */);
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

static int conn_process_buffered_0rtt_pkt(ngtcp2_conn *conn, ngtcp2_tstamp ts) {
  int rv;
  ngtcp2_pkt_chain *pc = conn->buffed_rx_ppkts, *next;

  for (; pc; pc = pc->next) {
    rv = conn_recv_handshake_pkt(conn, pc->pkt, pc->pktlen, ts);
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

  if (conn->max_local_stream_id_bidi > 0) {
    rv = conn_call_extend_max_stream_id(conn, conn->max_local_stream_id_bidi);
    if (rv != 0) {
      return rv;
    }
  }
  if (conn->max_local_stream_id_uni > 0) {
    rv = conn_call_extend_max_stream_id(conn, conn->max_local_stream_id_uni);
    if (rv != 0) {
      return rv;
    }
  }

  return 0;
}

int ngtcp2_conn_recv(ngtcp2_conn *conn, const uint8_t *pkt, size_t pktlen,
                     ngtcp2_tstamp ts) {
  int rv = 0;

  conn->log.last_ts = ts;

  ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_CON, "recv packet len=%zu",
                  pktlen);

  if (pktlen == 0) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  switch (conn->state) {
  case NGTCP2_CS_CLIENT_INITIAL:
  case NGTCP2_CS_CLIENT_WAIT_HANDSHAKE:
  case NGTCP2_CS_CLIENT_TLS_HANDSHAKE_FAILED:
  case NGTCP2_CS_SERVER_INITIAL:
  case NGTCP2_CS_SERVER_WAIT_HANDSHAKE:
  case NGTCP2_CS_SERVER_TLS_HANDSHAKE_FAILED:
    return NGTCP2_ERR_INVALID_STATE;
  case NGTCP2_CS_CLOSING:
    return NGTCP2_ERR_CLOSING;
  case NGTCP2_CS_DRAINING:
    return NGTCP2_ERR_DRAINING;
  case NGTCP2_CS_POST_HANDSHAKE:
    rv = conn_recv_pkt(conn, pkt, pktlen, ts);
    if (rv < 0) {
      break;
    }
    if (conn->state == NGTCP2_CS_DRAINING) {
      return NGTCP2_ERR_DRAINING;
    }
    break;
  }

  return rv;
}

ssize_t ngtcp2_conn_handshake(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                              const uint8_t *pkt, size_t pktlen,
                              ngtcp2_tstamp ts) {
  int rv;
  ssize_t nwrite;
  uint64_t cwnd;
  size_t origlen = destlen;

  conn->log.last_ts = ts;

  if (pktlen > 0) {
    ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_CON, "recv packet len=%zu",
                    pktlen);
  }

  if (conn->last_tx_pkt_num == UINT64_MAX) {
    return NGTCP2_ERR_PKT_NUM_EXHAUSTED;
  }

  cwnd = conn_cwnd_left(conn);
  destlen = ngtcp2_min(destlen, cwnd);

  switch (conn->state) {
  case NGTCP2_CS_CLIENT_INITIAL:
    if (pktlen > 0) {
      return NGTCP2_ERR_INVALID_ARGUMENT;
    }
    if (cwnd < NGTCP2_MIN_PKTLEN) {
      return 0;
    }
    nwrite = conn_write_client_initial(conn, dest, destlen, ts);
    if (nwrite < 0) {
      return nwrite;
    }
    conn->state = NGTCP2_CS_CLIENT_WAIT_HANDSHAKE;

    return nwrite;
  case NGTCP2_CS_CLIENT_WAIT_HANDSHAKE:
    rv = conn_recv_handshake_pkt(conn, pkt, pktlen, ts);
    if (rv < 0) {
      if (rv != NGTCP2_ERR_TLS_HANDSHAKE) {
        return (ssize_t)rv;
      }
      conn->state = NGTCP2_CS_CLIENT_TLS_HANDSHAKE_FAILED;

      if (cwnd < NGTCP2_MIN_PKTLEN) {
        return conn_write_handshake_ack_pkt(conn, dest, origlen, ts);
      }

      return conn_write_client_handshake(conn, dest, destlen, ts);
    }

    /* Retry packet has received */
    if (conn->state == NGTCP2_CS_CLIENT_INITIAL) {
      if (cwnd < NGTCP2_MIN_PKTLEN) {
        return 0;
      }
      nwrite = conn_write_client_initial(conn, dest, destlen, ts);
      if (nwrite < 0) {
        return nwrite;
      }
      conn->state = NGTCP2_CS_CLIENT_WAIT_HANDSHAKE;

      return nwrite;
    }

    nwrite = conn_retransmit(conn, dest, destlen, ts);
    if (nwrite != 0 && nwrite != NGTCP2_ERR_NOBUF) {
      return nwrite;
    }

    if (cwnd < NGTCP2_MIN_PKTLEN) {
      return conn_write_handshake_ack_pkt(conn, dest, origlen, ts);
    }

    nwrite = conn_write_client_handshake(conn, dest, destlen, ts);
    if (nwrite < 0) {
      return nwrite;
    }

    if (!(conn->flags & NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED)) {
      return nwrite;
    }

    if (!(conn->flags & NGTCP2_CONN_FLAG_TRANSPORT_PARAM_RECVED)) {
      return NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM;
    }

    rv = conn_handshake_completed(conn);
    if (rv != 0) {
      return (ssize_t)rv;
    }

    conn->state = NGTCP2_CS_POST_HANDSHAKE;
    conn->final_hs_tx_offset = conn->strm0->tx_offset;
    conn->final_hs_rx_offset = ngtcp2_rob_first_gap_offset(&conn->strm0->rob);

    if (conn->early_rtb) {
      rv = conn_process_early_rtb(conn);
      if (rv != 0) {
        return (ssize_t)rv;
      }
    }

    rv = conn_process_buffered_protected_pkt(conn, ts);
    if (rv != 0) {
      return (ssize_t)rv;
    }

    return nwrite;
  case NGTCP2_CS_CLIENT_TLS_HANDSHAKE_FAILED:
    rv = conn_recv_handshake_pkt(conn, pkt, pktlen, ts);
    if (rv != 0) {
      return (ssize_t)rv;
    }

    if (cwnd < NGTCP2_MIN_PKTLEN) {
      return conn_write_handshake_ack_pkt(conn, dest, origlen, ts);
    }

    return conn_write_client_handshake(conn, dest, destlen, ts);
  case NGTCP2_CS_SERVER_INITIAL:
  case NGTCP2_CS_SERVER_WAIT_HANDSHAKE:
    rv = conn_recv_handshake_pkt(conn, pkt, pktlen, ts);
    if (rv < 0) {
      if (rv != NGTCP2_ERR_TLS_HANDSHAKE) {
        return (ssize_t)rv;
      }

      conn->state = NGTCP2_CS_SERVER_TLS_HANDSHAKE_FAILED;

      if (cwnd < NGTCP2_MIN_PKTLEN) {
        return conn_write_handshake_ack_pkt(conn, dest, origlen, ts);
      }

      return conn_write_server_handshake(conn, dest, destlen,
                                         conn->strm0->tx_offset == 0, ts);
    }

    if (conn->state == NGTCP2_CS_SERVER_INITIAL) {
      if (conn->flags & NGTCP2_CONN_FLAG_CONN_ID_NEGOTIATED) {
        conn->state = NGTCP2_CS_SERVER_WAIT_HANDSHAKE;

        /* Process re-ordered 0-RTT Protected packets which were
           arrived before Initial packet. */
        rv = conn_process_buffered_0rtt_pkt(conn, ts);
        if (rv != 0) {
          /* TODO Probably better to write a Handshake packet containing
             CONNECTION_CLOSE frame */
          return (ssize_t)rv;
        }
      }

      if (cwnd < NGTCP2_MIN_PKTLEN) {
        return conn_write_handshake_ack_pkt(conn, dest, origlen, ts);
      }

      return conn_write_server_handshake(conn, dest, destlen, 1, ts);
    }

    if (!(conn->flags & NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED)) {
      nwrite = conn_retransmit(conn, dest, destlen, ts);
      if (nwrite != 0 && nwrite != NGTCP2_ERR_NOBUF) {
        return nwrite;
      }

      if (cwnd < NGTCP2_MIN_PKTLEN) {
        return conn_write_handshake_ack_pkt(conn, dest, origlen, ts);
      }

      return conn_write_server_handshake(conn, dest, destlen,
                                         conn->strm0->tx_offset == 0, ts);
    }

    if (!(conn->flags & NGTCP2_CONN_FLAG_TRANSPORT_PARAM_RECVED)) {
      return NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM;
    }

    rv = conn_handshake_completed(conn);
    if (rv != 0) {
      return (ssize_t)rv;
    }
    conn->state = NGTCP2_CS_POST_HANDSHAKE;
    conn->final_hs_tx_offset = conn->strm0->tx_offset;
    conn->final_hs_rx_offset = ngtcp2_rob_first_gap_offset(&conn->strm0->rob);
    /* The receipt of the final cryptographic message from the client
       verifies source address. */
    conn->flags |= NGTCP2_CONN_FLAG_SADDR_VERIFIED;

    rv = conn_process_buffered_protected_pkt(conn, ts);
    if (rv != 0) {
      return (ssize_t)rv;
    }

    conn->acktr.flags |= NGTCP2_ACKTR_FLAG_PENDING_FINISHED_ACK;

    return 0;
  case NGTCP2_CS_SERVER_TLS_HANDSHAKE_FAILED:
    rv = conn_recv_handshake_pkt(conn, pkt, pktlen, ts);
    if (rv != 0) {
      return (ssize_t)rv;
    }

    if (cwnd < NGTCP2_MIN_PKTLEN) {
      return conn_write_handshake_ack_pkt(conn, dest, origlen, ts);
    }

    return conn_write_server_handshake(conn, dest, destlen, 0, ts);
  case NGTCP2_CS_CLOSING:
    return NGTCP2_ERR_CLOSING;
  case NGTCP2_CS_DRAINING:
    return NGTCP2_ERR_DRAINING;
  default:
    return 0;
  }
}

void ngtcp2_conn_handshake_completed(ngtcp2_conn *conn) {
  conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;
}

int ngtcp2_conn_get_handshake_completed(ngtcp2_conn *conn) {
  return (conn->flags & NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED) > 0;
}

int ngtcp2_conn_sched_ack(ngtcp2_conn *conn, uint64_t pkt_num, int active_ack,
                          ngtcp2_tstamp ts, int unprotected) {
  ngtcp2_acktr_entry *rpkt;
  int rv;

  rv = ngtcp2_acktr_entry_new(&rpkt, pkt_num, ts, unprotected, conn->mem);
  if (rv != 0) {
    return rv;
  }

  rv = ngtcp2_acktr_add(&conn->acktr, rpkt, active_ack, ts);
  if (rv != 0) {
    ngtcp2_acktr_entry_del(rpkt, conn->mem);
    return rv;
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

  switch (p->type) {
  case NGTCP2_PKT_INITIAL:
    /* 0-RTT Protected packet may arrive before Initial packet due to
       re-ordering. */
  case NGTCP2_PKT_0RTT_PROTECTED:
    break;
  default:
    return -1;
  }

  switch (p->version) {
  case NGTCP2_PROTO_VER_D10:
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
    ngtcp2_crypto_km_del(conn->hs_tx_ckm, conn->mem);
    conn->hs_tx_ckm = NULL;
  }

  return ngtcp2_crypto_km_new(&conn->hs_tx_ckm, key, keylen, iv, ivlen,
                              conn->mem);
}

int ngtcp2_conn_set_handshake_rx_keys(ngtcp2_conn *conn, const uint8_t *key,
                                      size_t keylen, const uint8_t *iv,
                                      size_t ivlen) {
  if (conn->hs_rx_ckm) {
    ngtcp2_crypto_km_del(conn->hs_rx_ckm, conn->mem);
    conn->hs_rx_ckm = NULL;
  }

  return ngtcp2_crypto_km_new(&conn->hs_rx_ckm, key, keylen, iv, ivlen,
                              conn->mem);
}

int ngtcp2_conn_update_early_keys(ngtcp2_conn *conn, const uint8_t *key,
                                  size_t keylen, const uint8_t *iv,
                                  size_t ivlen) {
  if (conn->early_ckm) {
    return NGTCP2_ERR_INVALID_STATE;
  }

  return ngtcp2_crypto_km_new(&conn->early_ckm, key, keylen, iv, ivlen,
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

ngtcp2_tstamp ngtcp2_conn_loss_detection_expiry(ngtcp2_conn *conn) {
  if (conn->rcs.loss_detection_alarm) {
    return conn->rcs.loss_detection_alarm;
  }
  return UINT64_MAX;
}

ngtcp2_tstamp ngtcp2_conn_ack_delay_expiry(ngtcp2_conn *conn) {
  if (conn->acktr.first_unacked_ts == UINT64_MAX) {
    return UINT64_MAX;
  }
  return conn->acktr.first_unacked_ts + conn_compute_ack_delay(conn);
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
  dest->max_stream_id_bidi = src->initial_max_stream_id_bidi;
  dest->max_stream_id_uni = src->initial_max_stream_id_uni;
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
  dest->initial_max_data = src->max_data;
  dest->initial_max_stream_id_bidi = src->max_stream_id_bidi;
  dest->initial_max_stream_id_uni = src->max_stream_id_uni;
  dest->idle_timeout = src->idle_timeout;
  dest->omit_connection_id = src->omit_connection_id;
  dest->max_packet_size = src->max_packet_size;
  memcpy(dest->stateless_reset_token, src->stateless_reset_token,
         sizeof(dest->stateless_reset_token));
  dest->ack_delay_exponent = src->ack_delay_exponent;
}

/*
 * conn_client_validate_transport_params validates |params| as client.
 * |params| must be sent with Encrypted Extensions.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_VERSION_NEGOTIATION
 *     The negotiated version is invalid.
 */
static int
conn_client_validate_transport_params(ngtcp2_conn *conn,
                                      const ngtcp2_transport_params *params) {
  size_t i;

  if (params->v.ee.negotiated_version != conn->version) {
    return NGTCP2_ERR_VERSION_NEGOTIATION;
  }

  for (i = 0; i < params->v.ee.len; ++i) {
    if (params->v.ee.supported_versions[i] == conn->version) {
      return 0;
    }
  }

  return NGTCP2_ERR_VERSION_NEGOTIATION;
}

int ngtcp2_conn_set_remote_transport_params(
    ngtcp2_conn *conn, uint8_t exttype, const ngtcp2_transport_params *params) {
  int rv;

  switch (exttype) {
  case NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO:
    if (!conn->server) {
      return NGTCP2_ERR_INVALID_ARGUMENT;
    }
    /* TODO At the moment, we only support one version, and there is
       no validation here. */
    break;
  case NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS:
    if (conn->server) {
      return NGTCP2_ERR_INVALID_ARGUMENT;
    }
    rv = conn_client_validate_transport_params(conn, params);
    if (rv != 0) {
      return rv;
    }
    break;
  default:
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  ngtcp2_log_remote_tp(&conn->log, exttype, params);

  settings_copy_from_transport_params(&conn->remote_settings, params);

  conn->max_local_stream_id_bidi = conn->remote_settings.max_stream_id_bidi;
  conn->max_local_stream_id_uni = conn->remote_settings.max_stream_id_uni;
  conn->max_tx_offset = conn->remote_settings.max_data;

  /* TODO Should we check that conn->max_remote_stream_id_bidi is larger
     than conn->remote_settings.max_stream_id_bidi here?  What happens
     for 0-RTT stream? */

  conn->strm0->max_tx_offset = conn->remote_settings.max_stream_data;

  conn->flags |= NGTCP2_CONN_FLAG_TRANSPORT_PARAM_RECVED;

  return 0;
}

int ngtcp2_conn_set_early_remote_transport_params(
    ngtcp2_conn *conn, const ngtcp2_transport_params *params) {
  if (conn->server) {
    return NGTCP2_ERR_INVALID_STATE;
  }

  settings_copy_from_transport_params(&conn->remote_settings, params);

  conn->max_local_stream_id_bidi = conn->remote_settings.max_stream_id_bidi;
  conn->max_local_stream_id_uni = conn->remote_settings.max_stream_id_uni;
  conn->max_tx_offset = conn->remote_settings.max_data;

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
    break;
  case NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS:
    if (!conn->server) {
      return NGTCP2_ERR_INVALID_ARGUMENT;
    }
    /* TODO Fix this; not sure how to handle them correctly */
    params->v.ee.negotiated_version = conn->version;
    params->v.ee.len = 1;
    params->v.ee.supported_versions[0] = conn->version;
    break;
  default:
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }
  transport_params_copy_from_settings(params, &conn->local_settings);
  return 0;
}

int ngtcp2_conn_open_bidi_stream(ngtcp2_conn *conn, uint64_t *pstream_id,
                                 void *stream_user_data) {
  int rv;
  ngtcp2_strm *strm;

  if (conn->next_local_stream_id_bidi > conn->max_local_stream_id_bidi) {
    return NGTCP2_ERR_STREAM_ID_BLOCKED;
  }

  strm = ngtcp2_mem_malloc(conn->mem, sizeof(ngtcp2_strm));
  if (strm == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  rv = ngtcp2_conn_init_stream(conn, strm, conn->next_local_stream_id_bidi,
                               stream_user_data);
  if (rv != 0) {
    return rv;
  }

  *pstream_id = conn->next_local_stream_id_bidi;
  conn->next_local_stream_id_bidi += 4;

  return 0;
}

int ngtcp2_conn_open_uni_stream(ngtcp2_conn *conn, uint64_t *pstream_id,
                                void *stream_user_data) {
  int rv;
  ngtcp2_strm *strm;

  if (conn->next_local_stream_id_uni > conn->max_local_stream_id_uni) {
    return NGTCP2_ERR_STREAM_ID_BLOCKED;
  }

  strm = ngtcp2_mem_malloc(conn->mem, sizeof(ngtcp2_strm));
  if (strm == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  rv = ngtcp2_conn_init_stream(conn, strm, conn->next_local_stream_id_uni,
                               stream_user_data);
  if (rv != 0) {
    return rv;
  }
  ngtcp2_strm_shutdown(strm, NGTCP2_STRM_FLAG_SHUT_RD);

  *pstream_id = conn->next_local_stream_id_uni;
  conn->next_local_stream_id_uni += 4;

  return 0;
}

ngtcp2_strm *ngtcp2_conn_find_stream(ngtcp2_conn *conn, uint64_t stream_id) {
  ngtcp2_map_entry *me;

  me = ngtcp2_map_find(&conn->strms, stream_id);
  if (me == NULL) {
    return NULL;
  }

  return ngtcp2_struct_of(me, ngtcp2_strm, me);
}

ssize_t ngtcp2_conn_write_stream(ngtcp2_conn *conn, uint8_t *dest,
                                 size_t destlen, size_t *pdatalen,
                                 uint64_t stream_id, uint8_t fin,
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
  uint8_t pkt_flags;
  uint8_t pkt_type;
  uint64_t conn_id;
  uint64_t cwnd;

  conn->log.last_ts = ts;

  if (pdatalen) {
    *pdatalen = 0;
  }

  switch (conn->state) {
  case NGTCP2_CS_CLOSING:
    return NGTCP2_ERR_CLOSING;
  case NGTCP2_CS_DRAINING:
    return NGTCP2_ERR_DRAINING;
  }

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

  cwnd = conn_cwnd_left(conn);

  nwrite = conn_retransmit(conn, dest, ngtcp2_min(destlen, cwnd), ts);
  if (nwrite != 0 && nwrite != NGTCP2_ERR_NOBUF) {
    return nwrite;
  }

  if (conn->tx_ckm && conn->rcs.probe_pkt_left) {
    return conn_write_probe_pkt(conn, dest, destlen, pdatalen, strm, fin, data,
                                datalen, ts);
  }

  if (cwnd < NGTCP2_MIN_PKTLEN) {
    return 0;
  }

  destlen = ngtcp2_min(destlen, cwnd);

  if (conn->tx_ckm) {
    nwrite = conn_write_pkt(conn, dest, destlen, pdatalen, strm, fin, data,
                            datalen, ts);
    if (nwrite == 0 && datalen > 0) {
      return NGTCP2_ERR_STREAM_DATA_BLOCKED;
    }
    return nwrite;
  }

  /* Send STREAM frame in 0-RTT packet. */
  if (conn->server || !conn->early_ckm) {
    return NGTCP2_ERR_NOKEY;
  }

  if (stream_id == 0) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  if (conn->flags & NGTCP2_CONN_FLAG_EARLY_DATA_REJECTED) {
    return NGTCP2_ERR_EARLY_DATA_REJECTED;
  }

  pkt_flags = NGTCP2_PKT_FLAG_LONG_FORM;
  pkt_type = NGTCP2_PKT_0RTT_PROTECTED;
  conn_id = conn->client_conn_id;
  ctx.ckm = conn->early_ckm;

  ngtcp2_pkt_hd_init(&hd, pkt_flags, pkt_type, conn_id,
                     conn->last_tx_pkt_num + 1, conn->version);

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

  ndatalen = ngtcp2_min(datalen, left);
  ndatalen = ngtcp2_min(ndatalen, strm->max_tx_offset - strm->tx_offset);
  ndatalen = ngtcp2_min(ndatalen, conn->max_tx_offset - conn->tx_offset);

  if (datalen > 0 && ndatalen == 0) {
    return NGTCP2_ERR_STREAM_DATA_BLOCKED;
  }

  fin = fin && ndatalen == datalen;

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

  ngtcp2_log_tx_fr(&conn->log, &hd, &frc->fr);

  nwrite = ngtcp2_ppe_final(&ppe, NULL);
  if (nwrite < 0) {
    ngtcp2_frame_chain_del(frc, conn->mem);
    return nwrite;
  }

  rv = ngtcp2_rtb_entry_new(&ent, &hd, frc, ts, (size_t)nwrite,
                            NGTCP2_RTB_FLAG_NONE, conn->mem);
  if (rv != 0) {
    ngtcp2_frame_chain_del(frc, conn->mem);
    return rv;
  }

  /* Retransmission of 0-RTT packet is postponed until handshake
     completes.  This covers the case that 0-RTT data is rejected by
     the peer.  0-RTT packet is retransmitted as a Short packet. */
  ent->hd.flags &= (uint8_t)~NGTCP2_PKT_FLAG_LONG_FORM;
  ent->hd.type = NGTCP2_PKT_01;

  ngtcp2_list_insert(ent, &conn->early_rtb);

  strm->tx_offset += ndatalen;
  conn->tx_offset += ndatalen;

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
                                           size_t destlen, uint16_t error_code,
                                           ngtcp2_tstamp ts) {
  ssize_t nwrite;
  ngtcp2_frame fr;

  conn->log.last_ts = ts;

  if (conn->last_tx_pkt_num == UINT64_MAX) {
    return NGTCP2_ERR_PKT_NUM_EXHAUSTED;
  }

  switch (conn->state) {
  case NGTCP2_CS_POST_HANDSHAKE:
    fr.type = NGTCP2_FRAME_CONNECTION_CLOSE;
    fr.connection_close.error_code = error_code;
    fr.connection_close.reasonlen = 0;
    fr.connection_close.reason = NULL;

    nwrite = conn_write_single_frame_pkt(conn, dest, destlen, &fr, ts);
    if (nwrite > 0) {
      conn->state = NGTCP2_CS_CLOSING;
    }
    break;
  default:
    return NGTCP2_ERR_INVALID_STATE;
  }

  return nwrite;
}

ssize_t ngtcp2_conn_write_application_close(ngtcp2_conn *conn, uint8_t *dest,
                                            size_t destlen,
                                            uint16_t app_error_code,
                                            ngtcp2_tstamp ts) {
  ssize_t nwrite;
  ngtcp2_frame fr;

  conn->log.last_ts = ts;

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

  nwrite = conn_write_single_frame_pkt(conn, dest, destlen, &fr, ts);
  if (nwrite < 0) {
    return nwrite;
  }

  conn->state = NGTCP2_CS_CLOSING;

  return nwrite;
}

int ngtcp2_conn_in_closing_period(ngtcp2_conn *conn) {
  return conn->state == NGTCP2_CS_CLOSING;
}

int ngtcp2_conn_in_draining_period(ngtcp2_conn *conn) {
  return conn->state == NGTCP2_CS_DRAINING;
}

/*
 * handle_remote_stream_id_extension extends
 * |*punsent_max_remote_stream_id| if a condition allows it.
 */
static void
handle_remote_stream_id_extension(uint64_t *punsent_max_remote_stream_id,
                                  uint64_t *premote_stream_id_window_start,
                                  ngtcp2_idtr *idtr) {
  if (*punsent_max_remote_stream_id <= NGTCP2_MAX_VARINT - 4 &&
      *premote_stream_id_window_start < ngtcp2_idtr_first_gap(idtr)) {
    *punsent_max_remote_stream_id += 4;
    ++premote_stream_id_window_start;
  }
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

  if (!conn_local_stream(conn, strm->stream_id)) {
    if (bidi_stream(strm->stream_id)) {
      handle_remote_stream_id_extension(
          &conn->unsent_max_remote_stream_id_bidi,
          &conn->remote_stream_id_bidi_window_start, &conn->remote_bidi_idtr);
    } else {
      handle_remote_stream_id_extension(
          &conn->unsent_max_remote_stream_id_uni,
          &conn->remote_stream_id_uni_window_start, &conn->remote_uni_idtr);
    }
  }

  if (strm->fc_pprev) {
    *strm->fc_pprev = strm->fc_next;
    if (strm->fc_next) {
      strm->fc_next->fc_pprev = strm->fc_pprev;
    }
  }

  ngtcp2_strm_free(strm);
  ngtcp2_mem_free(conn->mem, strm);

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

int ngtcp2_conn_shutdown_stream(ngtcp2_conn *conn, uint64_t stream_id,
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

int ngtcp2_conn_shutdown_stream_write(ngtcp2_conn *conn, uint64_t stream_id,
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

int ngtcp2_conn_shutdown_stream_read(ngtcp2_conn *conn, uint64_t stream_id,
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

int ngtcp2_conn_extend_max_stream_offset(ngtcp2_conn *conn, uint64_t stream_id,
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
  if (NGTCP2_MAX_VARINT < datalen ||
      conn->unsent_max_rx_offset > NGTCP2_MAX_VARINT - datalen) {
    conn->unsent_max_rx_offset = NGTCP2_MAX_VARINT;
    return;
  }

  conn->unsent_max_rx_offset += datalen;
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

void ngtcp2_conn_early_data_rejected(ngtcp2_conn *conn) {
  conn->flags |= NGTCP2_CONN_FLAG_EARLY_DATA_REJECTED;
}

void ngtcp2_conn_update_rtt(ngtcp2_conn *conn, uint64_t rtt, uint64_t ack_delay,
                            int ack_only) {
  ngtcp2_rcvry_stat *rcs = &conn->rcs;

  rcs->min_rtt = ngtcp2_min(rcs->min_rtt, rtt);
  if (rtt - rcs->min_rtt > ack_delay) {
    rtt -= ack_delay;
    if (!ack_only) {
      rcs->max_ack_delay = ngtcp2_max(rcs->max_ack_delay, ack_delay);
    }
  }

  rcs->latest_rtt = rtt;

  if (rcs->smoothed_rtt < 1e-9) {
    rcs->smoothed_rtt = (double)rtt;
    rcs->rttvar = (double)rtt / 2;
  } else {
    double sample = fabs(rcs->smoothed_rtt - (double)rtt);
    rcs->rttvar = rcs->rttvar * 3 / 4 + sample / 4;
    rcs->smoothed_rtt = rcs->smoothed_rtt * 7 / 8 + (double)rtt / 8;
  }

  ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_RCV,
                  "latest_rtt=%" PRIu64 " min_rtt=%" PRIu64
                  " smoothed_rtt=%.3f rttvar=%.3f max_ack_delay=%" PRIu64,
                  rcs->latest_rtt / 1000000, rcs->min_rtt / 1000000,
                  rcs->smoothed_rtt / 1000000, rcs->rttvar / 1000000,
                  rcs->max_ack_delay / 1000000);
}

void ngtcp2_conn_get_rcvry_stat(ngtcp2_conn *conn, ngtcp2_rcvry_stat *rcs) {
  *rcs = conn->rcs;
}

void ngtcp2_conn_set_loss_detection_alarm(ngtcp2_conn *conn) {
  ngtcp2_rcvry_stat *rcs = &conn->rcs;
  uint64_t alarm_duration;
  ngtcp2_rtb_entry *ent;

  ent = ngtcp2_rtb_head(&conn->rtb);

  if (!ent) {
    if (rcs->loss_detection_alarm) {
      ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_RCV,
                      "loss detection alarm canceled");
      rcs->loss_detection_alarm = 0;
    }
    return;
  }

  if (conn->rtb.num_unprotected) {
    if (rcs->smoothed_rtt < 1e-09) {
      alarm_duration = 2 * NGTCP2_DEFAULT_INITIAL_RTT;
    } else {
      alarm_duration = (uint64_t)(2 * rcs->smoothed_rtt);
    }

    alarm_duration =
        ngtcp2_max(alarm_duration + rcs->max_ack_delay, NGTCP2_MIN_TLP_TIMEOUT);
    alarm_duration *= 1ull << rcs->handshake_count;

    rcs->loss_detection_alarm = rcs->last_hs_tx_pkt_ts + alarm_duration;

    ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_RCV,
                    "loss_detection_alarm=%" PRIu64
                    " last_hs_tx_pkt_ts=%" PRIu64 " alarm_duration=%" PRIu64,
                    rcs->loss_detection_alarm, rcs->last_hs_tx_pkt_ts,
                    alarm_duration / 1000000);
    return;
  }

  if (rcs->loss_time) {
    assert(rcs->loss_time >= ent->ts);
    alarm_duration = rcs->loss_time - rcs->last_tx_pkt_ts;
  } else {
    alarm_duration = (uint64_t)(rcs->smoothed_rtt + 4 * rcs->rttvar +
                                (double)rcs->max_ack_delay);
    alarm_duration = ngtcp2_max(alarm_duration, NGTCP2_MIN_RTO_TIMEOUT);
    alarm_duration *= 1ull << rcs->rto_count;

    if (rcs->tlp_count < NGTCP2_MAX_TLP_COUNT) {
      uint64_t tlp_alarm_duration = ngtcp2_max(
          (uint64_t)(1.5 * rcs->smoothed_rtt + (double)rcs->max_ack_delay),
          NGTCP2_MIN_TLP_TIMEOUT);
      alarm_duration = ngtcp2_min(alarm_duration, tlp_alarm_duration);
    }
  }

  rcs->loss_detection_alarm = rcs->last_tx_pkt_ts + alarm_duration;
}

void ngtcp2_conn_on_loss_detection_alarm(ngtcp2_conn *conn, ngtcp2_tstamp ts) {
  ngtcp2_rcvry_stat *rcs = &conn->rcs;

  conn->log.last_ts = ts;

  if (!rcs->loss_detection_alarm) {
    return;
  }

  ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_RCV,
                  "loss detection alarm fired");

  if (conn->rtb.num_unprotected) {
    ngtcp2_rtb_mark_unprotected_lost(&conn->rtb);
    ++rcs->handshake_count;
  } else if (!ngtcp2_conn_get_handshake_completed(conn)) {
    assert(0);
    /* No TLP or RTO in handshake period.  Handshake packets are
       retransmitted in the above block. */
  } else if (rcs->loss_time) {
    ngtcp2_rtb_detect_lost_pkt(&conn->rtb, rcs, (uint64_t)conn->largest_ack,
                               conn->last_tx_pkt_num, ts);
  } else if (rcs->tlp_count < NGTCP2_MAX_TLP_COUNT) {
    rcs->probe_pkt_left = 1;
    ++rcs->tlp_count;
  } else {
    rcs->probe_pkt_left = 2;
    if (rcs->rto_count == 0) {
      rcs->largest_sent_before_rto = conn->last_tx_pkt_num;
    }
    ++rcs->rto_count;
  }

  ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_RCV,
                  "handshake_count=%zu tlp_count=%zu rto_count=%zu",
                  rcs->handshake_count, rcs->tlp_count, rcs->rto_count);

  ngtcp2_conn_set_loss_detection_alarm(conn);
}
