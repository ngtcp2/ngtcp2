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
#include "ngtcp2_cid.h"
#include "ngtcp2_conv.h"
#include "ngtcp2_vec.h"

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

static int conn_call_recv_client_initial(ngtcp2_conn *conn,
                                         const ngtcp2_cid *dcid) {
  int rv;

  assert(conn->callbacks.recv_client_initial);

  rv = conn->callbacks.recv_client_initial(conn, dcid, conn->user_data);
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
                                      int fin, uint64_t offset,
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

static int conn_call_recv_crypto_data(ngtcp2_conn *conn, uint64_t offset,
                                      const uint8_t *data, size_t datalen) {
  int rv;

  rv = conn->callbacks.recv_crypto_data(conn, offset, data, datalen,
                                        conn->user_data);
  switch (rv) {
  case 0:
  case NGTCP2_ERR_CRYPTO:
  case NGTCP2_ERR_PROTO:
  case NGTCP2_ERR_INTERNAL:
  case NGTCP2_ERR_CALLBACK_FAILURE:
    return rv;
  default:
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
}

static int conn_call_stream_open(ngtcp2_conn *conn, ngtcp2_strm *strm) {
  int rv;

  if (!conn->callbacks.stream_open) {
    return 0;
  }

  rv = conn->callbacks.stream_open(conn, strm->stream_id, conn->user_data);
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

static int crypto_offset_less(const ngtcp2_pq_entry *lhs,
                              const ngtcp2_pq_entry *rhs) {
  ngtcp2_crypto_frame_chain *lfrc =
      ngtcp2_struct_of(lhs, ngtcp2_crypto_frame_chain, pe);
  ngtcp2_crypto_frame_chain *rfrc =
      ngtcp2_struct_of(rhs, ngtcp2_crypto_frame_chain, pe);

  return lfrc->fr.offset < rfrc->fr.offset;
}

static int pktns_init(ngtcp2_pktns *pktns, ngtcp2_cc_stat *ccs, ngtcp2_log *log,
                      ngtcp2_mem *mem) {
  int rv;

  rv = ngtcp2_gaptr_init(&pktns->pngap, mem);
  if (rv != 0) {
    return rv;
  }

  pktns->last_tx_pkt_num = (uint64_t)-1;

  rv = ngtcp2_acktr_init(&pktns->acktr, log, mem);
  if (rv != 0) {
    ngtcp2_gaptr_free(&pktns->pngap);
    return rv;
  }

  ngtcp2_rtb_init(&pktns->rtb, ccs, log, mem);
  ngtcp2_pq_init(&pktns->cryptofrq, crypto_offset_less, mem);

  return 0;
}

static int cycle_less(const ngtcp2_pq_entry *lhs, const ngtcp2_pq_entry *rhs) {
  ngtcp2_strm *ls = ngtcp2_struct_of(lhs, ngtcp2_strm, pe);
  ngtcp2_strm *rs = ngtcp2_struct_of(rhs, ngtcp2_strm, pe);

  if (ls->cycle < rs->cycle) {
    return rs->cycle - ls->cycle <= 1;
  }

  return ls->cycle - rs->cycle > 1;
}

static void pktns_free(ngtcp2_pktns *pktns, ngtcp2_mem *mem) {
  ngtcp2_crypto_frame_chain *frc;

  ngtcp2_frame_chain_list_del(pktns->frq, mem);

  ngtcp2_crypto_km_del(pktns->rx_ckm, mem);
  ngtcp2_crypto_km_del(pktns->tx_ckm, mem);

  for (; !ngtcp2_pq_empty(&pktns->cryptofrq);) {
    frc = ngtcp2_struct_of(ngtcp2_pq_top(&pktns->cryptofrq),
                           ngtcp2_crypto_frame_chain, pe);
    ngtcp2_pq_pop(&pktns->cryptofrq);
    ngtcp2_crypto_frame_chain_del(frc, mem);
  }

  ngtcp2_pq_free(&pktns->cryptofrq);
  ngtcp2_rtb_free(&pktns->rtb);
  ngtcp2_acktr_free(&pktns->acktr);
  ngtcp2_gaptr_free(&pktns->pngap);
}

static int conn_new(ngtcp2_conn **pconn, const ngtcp2_cid *dcid,
                    const ngtcp2_cid *scid, uint32_t version,
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

  rv = ngtcp2_strm_init(&(*pconn)->crypto, 0, NGTCP2_STRM_FLAG_NONE, 0, 0, NULL,
                        mem);
  if (rv != 0) {
    goto fail_crypto_init;
  }

  rv = ngtcp2_map_init(&(*pconn)->strms, mem);
  if (rv != 0) {
    goto fail_strms_init;
  }

  ngtcp2_pq_init(&(*pconn)->tx_strmq, cycle_less, mem);

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

  (*pconn)->scid = *scid;
  (*pconn)->dcid = *dcid;

  ngtcp2_log_init(&(*pconn)->log, &(*pconn)->scid, settings->log_printf,
                  settings->initial_ts, user_data);

  rv = pktns_init(&(*pconn)->in_pktns, &(*pconn)->ccs, &(*pconn)->log, mem);
  if (rv != 0) {
    goto fail_in_pktns_init;
  }

  rv = pktns_init(&(*pconn)->hs_pktns, &(*pconn)->ccs, &(*pconn)->log, mem);
  if (rv != 0) {
    goto fail_hs_pktns_init;
  }

  rv = pktns_init(&(*pconn)->pktns, &(*pconn)->ccs, &(*pconn)->log, mem);
  if (rv != 0) {
    goto fail_pktns_init;
  }

  (*pconn)->callbacks = *callbacks;
  (*pconn)->version = version;
  (*pconn)->mem = mem;
  (*pconn)->user_data = user_data;
  (*pconn)->largest_ack = -1;
  (*pconn)->local_settings = *settings;
  (*pconn)->unsent_max_rx_offset = (*pconn)->max_rx_offset = settings->max_data;
  (*pconn)->rcs.min_rtt = UINT64_MAX;
  (*pconn)->rcs.reordering_threshold = NGTCP2_REORDERING_THRESHOLD;
  (*pconn)->ccs.cwnd = ngtcp2_min(10 * NGTCP2_MAX_DGRAM_SIZE,
                                  ngtcp2_max(2 * NGTCP2_MAX_DGRAM_SIZE, 14600));
  (*pconn)->ccs.eor_pkt_num = 0;
  (*pconn)->ccs.ssthresh = UINT64_MAX;

  return 0;

fail_pktns_init:
  pktns_free(&(*pconn)->hs_pktns, mem);
fail_hs_pktns_init:
  pktns_free(&(*pconn)->in_pktns, mem);
fail_in_pktns_init:
  ngtcp2_ringbuf_free(&(*pconn)->rx_path_challenge);
fail_rx_path_challenge_init:
  ngtcp2_ringbuf_free(&(*pconn)->tx_path_challenge);
fail_tx_path_challenge_init:
  ngtcp2_idtr_free(&(*pconn)->remote_uni_idtr);
fail_remote_uni_idtr_init:
  ngtcp2_idtr_free(&(*pconn)->remote_bidi_idtr);
fail_remote_bidi_idtr_init:
  ngtcp2_map_free(&(*pconn)->strms);
fail_strms_init:
  ngtcp2_strm_free(&(*pconn)->crypto);
fail_crypto_init:
  ngtcp2_mem_free(mem, *pconn);
fail_conn:
  return rv;
}

int ngtcp2_conn_client_new(ngtcp2_conn **pconn, const ngtcp2_cid *dcid,
                           const ngtcp2_cid *scid, uint32_t version,
                           const ngtcp2_conn_callbacks *callbacks,
                           const ngtcp2_settings *settings, void *user_data) {
  int rv;
  rv = conn_new(pconn, dcid, scid, version, callbacks, settings, user_data, 0);
  if (rv != 0) {
    return rv;
  }
  (*pconn)->rcid = *dcid;
  (*pconn)->unsent_max_remote_stream_id_bidi =
      (*pconn)->max_remote_stream_id_bidi =
          ngtcp2_nth_server_bidi_id(settings->max_bidi_streams);

  (*pconn)->unsent_max_remote_stream_id_uni =
      (*pconn)->max_remote_stream_id_uni =
          ngtcp2_nth_server_uni_id(settings->max_uni_streams);

  (*pconn)->state = NGTCP2_CS_CLIENT_INITIAL;
  (*pconn)->next_local_stream_id_bidi = 0;
  (*pconn)->next_local_stream_id_uni = 2;
  return 0;
}

int ngtcp2_conn_server_new(ngtcp2_conn **pconn, const ngtcp2_cid *dcid,
                           const ngtcp2_cid *scid, uint32_t version,
                           const ngtcp2_conn_callbacks *callbacks,
                           const ngtcp2_settings *settings, void *user_data) {
  int rv;
  rv = conn_new(pconn, dcid, scid, version, callbacks, settings, user_data, 1);
  if (rv != 0) {
    return rv;
  }
  (*pconn)->server = 1;
  (*pconn)->unsent_max_remote_stream_id_bidi =
      (*pconn)->max_remote_stream_id_bidi =
          ngtcp2_nth_client_bidi_id(settings->max_bidi_streams);

  (*pconn)->unsent_max_remote_stream_id_uni =
      (*pconn)->max_remote_stream_id_uni =
          ngtcp2_nth_client_uni_id(settings->max_uni_streams);

  (*pconn)->state = NGTCP2_CS_SERVER_INITIAL;
  (*pconn)->next_local_stream_id_bidi = 1;
  (*pconn)->next_local_stream_id_uni = 3;
  return 0;
}

/*
 * conn_fc_credits returns the number of bytes allowed to be sent to
 * the given stream.  Both connection and stream level flow control
 * credits are considered.
 */
static size_t conn_fc_credits(ngtcp2_conn *conn, ngtcp2_strm *strm) {
  return ngtcp2_min(strm->max_tx_offset - strm->tx_offset,
                    conn->max_tx_offset - conn->tx_offset);
}

/*
 * conn_enforce_flow_control returns the number of bytes allowed to be
 * sent to the given stream.  |len| might be shorted because of
 * available flow control credits.
 */
static size_t conn_enforce_flow_control(ngtcp2_conn *conn, ngtcp2_strm *strm,
                                        size_t len) {
  size_t fc_credits = conn_fc_credits(conn, strm);
  return ngtcp2_min(len, fc_credits);
}

static void delete_buffed_pkts(ngtcp2_pkt_chain *pc, ngtcp2_mem *mem) {
  ngtcp2_pkt_chain *next;

  for (; pc;) {
    next = pc->next;
    ngtcp2_pkt_chain_del(pc, mem);
    pc = next;
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

  ngtcp2_mem_free(conn->mem, conn->token.begin);
  ngtcp2_mem_free(conn->mem, conn->decrypt_buf.base);

  delete_buffed_pkts(conn->buffed_rx_ppkts, conn->mem);
  delete_buffed_pkts(conn->buffed_rx_hs_pkts, conn->mem);

  ngtcp2_crypto_km_del(conn->early_ckm, conn->mem);

  pktns_free(&conn->pktns, conn->mem);
  pktns_free(&conn->hs_pktns, conn->mem);
  pktns_free(&conn->in_pktns, conn->mem);

  ngtcp2_ringbuf_free(&conn->rx_path_challenge);
  ngtcp2_ringbuf_free(&conn->tx_path_challenge);

  ngtcp2_idtr_free(&conn->remote_uni_idtr);
  ngtcp2_idtr_free(&conn->remote_bidi_idtr);
  ngtcp2_pq_free(&conn->tx_strmq);
  ngtcp2_map_each_free(&conn->strms, delete_strms_each, conn->mem);
  ngtcp2_map_free(&conn->strms);

  ngtcp2_strm_free(&conn->crypto);

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
static ngtcp2_duration conn_compute_ack_delay(ngtcp2_conn *conn) {
  ngtcp2_duration initial_delay =
      (ngtcp2_duration)conn->local_settings.max_ack_delay *
      (NGTCP2_DURATION_TICK / NGTCP2_MILLISECONDS);

  if (conn->rcs.smoothed_rtt < 1e-9) {
    return initial_delay;
  }

  return ngtcp2_min(initial_delay,
                    (ngtcp2_duration)(conn->rcs.smoothed_rtt / 4));
}

/*
 * conn_create_ack_frame creates ACK frame, and assigns its pointer to
 * |*pfr| if there are any received packets to acknowledge.  If there
 * are no packets to acknowledge, this function returns 0, and |*pfr|
 * is untouched.  The caller is advised to set |*pfr| to NULL before
 * calling this function, and check it after this function returns.
 * If |nodelay| is nonzero, delayed ACK timer is ignored.
 *
 * The memory for ACK frame is dynamically allocated by this function.
 * A caller is responsible to free it.
 *
 * Call ngtcp2_acktr_commit_ack after a created ACK frame is
 * successfully serialized into a packet.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 */
static int conn_create_ack_frame(ngtcp2_conn *conn, ngtcp2_frame **pfr,
                                 ngtcp2_acktr *acktr, ngtcp2_tstamp ts,
                                 uint8_t ack_delay_exponent) {
  uint64_t last_pkt_num;
  ngtcp2_ack_blk *blk;
  ngtcp2_ksl_it it;
  ngtcp2_acktr_entry *rpkt;
  ngtcp2_frame *fr;
  ngtcp2_ack *ack;
  /* TODO Measure an actual size of ACK bloks to find the best default
     value. */
  size_t num_blks_max = 8;
  size_t blk_idx;
  int rv;
  uint64_t ack_delay = (acktr->flags & NGTCP2_ACKTR_FLAG_IMMEDIATE_ACK)
                           ? 0
                           : conn_compute_ack_delay(conn);

  if (!ngtcp2_acktr_require_active_ack(acktr, ack_delay, ts)) {
    return 0;
  }

  it = ngtcp2_acktr_get(acktr);
  if (ngtcp2_ksl_it_end(&it)) {
    ngtcp2_acktr_commit_ack(acktr);
    return 0;
  }

  fr = ngtcp2_mem_malloc(conn->mem, sizeof(ngtcp2_ack) +
                                        sizeof(ngtcp2_ack_blk) * num_blks_max);
  if (fr == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  ack = &fr->ack;

  rpkt = ngtcp2_ksl_it_get(&it);
  last_pkt_num = rpkt->pkt_num - (rpkt->len - 1);
  ack->type = NGTCP2_FRAME_ACK;
  ack->largest_ack = rpkt->pkt_num;
  ack->first_ack_blklen = rpkt->len - 1;
  ack->ack_delay_unscaled = ts - rpkt->tstamp;
  ack->ack_delay = ack->ack_delay_unscaled /
                   (NGTCP2_DURATION_TICK / NGTCP2_MICROSECONDS) /
                   (1UL << ack_delay_exponent);
  ack->num_blks = 0;

  ngtcp2_ksl_it_next(&it);

  for (; !ngtcp2_ksl_it_end(&it); ngtcp2_ksl_it_next(&it)) {
    rpkt = ngtcp2_ksl_it_get(&it);

    blk_idx = ack->num_blks++;
    rv = conn_ensure_ack_blks(conn, &fr, &num_blks_max, ack->num_blks);
    if (rv != 0) {
      ngtcp2_mem_free(conn->mem, fr);
      return rv;
    }
    ack = &fr->ack;
    blk = &ack->blks[blk_idx];
    blk->gap = last_pkt_num - rpkt->pkt_num - 2;
    blk->blklen = rpkt->len - 1;

    last_pkt_num = rpkt->pkt_num - (rpkt->len - 1);

    if (ack->num_blks == NGTCP2_MAX_ACK_BLKS) {
      break;
    }
  }

  /* TODO Just remove entries which cannot fit into a single ACK frame
     for now. */
  if (!ngtcp2_ksl_it_end(&it)) {
    rv = ngtcp2_acktr_forget(acktr, ngtcp2_ksl_it_get(&it));
    if (rv != 0) {
      return rv;
    }
  }

  *pfr = fr;

  return 0;
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
    assert(NGTCP2_ERR_NOBUF == rv);
    return rv;
  }

  ngtcp2_log_tx_fr(&conn->log, hd, fr);

  return 0;
}

/*
 * conn_on_pkt_sent is called when new retransmittable packet is sent.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory
 */
static int conn_on_pkt_sent(ngtcp2_conn *conn, ngtcp2_rtb *rtb,
                            ngtcp2_rtb_entry *ent) {
  int rv;

  /* This function implements OnPacketSent, but it handles only
     retransmittable packet (non-ACK only packet). */
  rv = ngtcp2_rtb_add(rtb, ent);
  if (rv != 0) {
    return rv;
  }

  if (ngtcp2_pkt_handshake_pkt(&ent->hd)) {
    conn->rcs.last_hs_tx_pkt_ts = ent->ts;
  } else {
    conn->rcs.last_tx_pkt_ts = ent->ts;
  }
  ngtcp2_conn_set_loss_detection_timer(conn);

  return 0;
}

/*
 * conn_select_pkt_numlen selects shortest packet number encoding
 * based on the next packet number |pkt_num| and the largest
 * acknowledged packet number.  It returns the number of bytes to
 * encode the packet number.
 */
static size_t rtb_select_pkt_numlen(ngtcp2_rtb *rtb, uint64_t pkt_num) {
  uint64_t n = (uint64_t)((int64_t)pkt_num - rtb->largest_acked_tx_pkt_num);
  if (UINT64_MAX / 2 <= pkt_num) {
    return 4;
  }

  n = n * 2 + 1;

  if (n > 0x3fff) {
    return 4;
  }
  if (n > 0x7f) {
    return 2;
  }
  return 1;
}

/*
 * conn_cwnd_left returns the number of bytes the local endpoint can
 * sent at this time.
 */
static uint64_t conn_cwnd_left(ngtcp2_conn *conn) {
  uint64_t bytes_in_flight = ngtcp2_conn_get_bytes_in_flight(conn);

  /* We might send more than bytes_in_flight if TLP/RTO packets are
     involved. */
  if (bytes_in_flight >= conn->ccs.cwnd) {
    return 0;
  }
  return conn->ccs.cwnd - bytes_in_flight;
}

/*
 * conn_retry_early_payloadlen returns the estimated wire length of
 * the first STREAM frame of 0-RTT packet which should be
 * retransmitted due to Retry frame
 */
static size_t conn_retry_early_payloadlen(ngtcp2_conn *conn) {
  ngtcp2_stream_frame_chain *sfrc;
  ngtcp2_strm *strm;

  for (; !ngtcp2_pq_empty(&conn->tx_strmq);) {
    strm = ngtcp2_conn_tx_strmq_top(conn);
    if (ngtcp2_strm_streamfrq_empty(strm)) {
      ngtcp2_conn_tx_strmq_pop(conn);
      continue;
    }

    sfrc = ngtcp2_strm_streamfrq_top(strm);
    return ngtcp2_vec_len(sfrc->fr.data, sfrc->fr.datacnt) +
           NGTCP2_STREAM_OVERHEAD;
  }

  return 0;
}

/*
 * conn_cryptofrq_top returns the element which sits on top of the
 * queue.  The queue must not be empty.
 */
static ngtcp2_crypto_frame_chain *conn_cryptofrq_top(ngtcp2_conn *conn,
                                                     ngtcp2_pktns *pktns) {
  (void)conn;
  assert(!ngtcp2_pq_empty(&pktns->cryptofrq));
  return ngtcp2_struct_of(ngtcp2_pq_top(&pktns->cryptofrq),
                          ngtcp2_crypto_frame_chain, pe);
}

static int conn_cryptofrq_pop(ngtcp2_conn *conn,
                              ngtcp2_crypto_frame_chain **pfrc,
                              ngtcp2_pktns *pktns, size_t left) {
  ngtcp2_crypto *fr, *nfr;
  ngtcp2_crypto_frame_chain *frc, *nfrc;
  int rv;
  ssize_t nsplit;
  size_t nmerged;
  size_t datalen;

  if (ngtcp2_pq_empty(&pktns->cryptofrq)) {
    *pfrc = NULL;
    return 0;
  }

  frc = ngtcp2_struct_of(ngtcp2_pq_top(&pktns->cryptofrq),
                         ngtcp2_crypto_frame_chain, pe);
  ngtcp2_pq_pop(&pktns->cryptofrq);
  frc->pe.index = NGTCP2_PQ_BAD_INDEX;

  fr = &frc->fr;

  datalen = ngtcp2_vec_len(fr->data, fr->datacnt);
  if (datalen > left) {
    if (!ngtcp2_pq_empty(&pktns->cryptofrq)) {
      nfrc = ngtcp2_struct_of(ngtcp2_pq_top(&pktns->cryptofrq),
                              ngtcp2_crypto_frame_chain, pe);
      nfr = &nfrc->fr;

      if (fr->offset + datalen == nfr->offset) {
        nsplit =
            ngtcp2_vec_split(fr->data, &fr->datacnt, nfr->data, &nfr->datacnt,
                             left, NGTCP2_MAX_CRYPTO_DATACNT);
        assert(nsplit);

        if (nsplit > 0) {
          ngtcp2_pq_pop(&pktns->cryptofrq);
          nfr->ordered_offset -= (size_t)nsplit;
          nfr->offset -= (size_t)nsplit;

          rv = ngtcp2_pq_push(&pktns->cryptofrq, &nfrc->pe);
          if (rv != 0) {
            assert(ngtcp2_err_is_fatal(rv));
            ngtcp2_crypto_frame_chain_del(nfrc, conn->mem);
            ngtcp2_crypto_frame_chain_del(frc, conn->mem);
            return rv;
          }

          *pfrc = frc;

          return 0;
        }
      }
    }

    rv = ngtcp2_crypto_frame_chain_new(&nfrc, conn->mem);
    if (rv != 0) {
      assert(ngtcp2_err_is_fatal(rv));
      ngtcp2_crypto_frame_chain_del(frc, conn->mem);
      return rv;
    }

    nfr = &nfrc->fr;
    nfr->type = NGTCP2_FRAME_CRYPTO;
    nfr->ordered_offset = fr->offset + left;
    nfr->offset = fr->offset + left;
    nfr->datacnt = 0;

    ngtcp2_vec_split(fr->data, &fr->datacnt, nfr->data, &nfr->datacnt, left,
                     NGTCP2_MAX_CRYPTO_DATACNT);

    rv = ngtcp2_pq_push(&pktns->cryptofrq, &nfrc->pe);
    if (rv != 0) {
      assert(ngtcp2_err_is_fatal(rv));
      ngtcp2_crypto_frame_chain_del(nfrc, conn->mem);
      ngtcp2_crypto_frame_chain_del(frc, conn->mem);
      return rv;
    }

    *pfrc = frc;

    return 0;
  }

  if (fr->datacnt == NGTCP2_MAX_CRYPTO_DATACNT) {
    *pfrc = frc;
    return 0;
  }

  left -= datalen;

  for (; left && fr->datacnt < NGTCP2_MAX_CRYPTO_DATACNT &&
         !ngtcp2_pq_empty(&pktns->cryptofrq);) {
    nfrc = ngtcp2_struct_of(ngtcp2_pq_top(&pktns->cryptofrq),
                            ngtcp2_crypto_frame_chain, pe);
    nfr = &nfrc->fr;

    if (nfr->offset != fr->offset + datalen) {
      assert(fr->offset + datalen < nfr->offset);
      break;
    }

    nmerged = ngtcp2_vec_merge(fr->data, &fr->datacnt, nfr->data, &nfr->datacnt,
                               left, NGTCP2_MAX_CRYPTO_DATACNT);
    if (nmerged == 0) {
      break;
    }

    ngtcp2_pq_pop(&pktns->cryptofrq);

    datalen += nmerged;
    nfr->offset += nmerged;
    left -= nmerged;

    if (nfr->datacnt == 0) {
      ngtcp2_crypto_frame_chain_del(nfrc, conn->mem);
      continue;
    }

    rv = ngtcp2_pq_push(&pktns->cryptofrq, &nfrc->pe);
    if (rv != 0) {
      ngtcp2_crypto_frame_chain_del(nfrc, conn->mem);
      ngtcp2_crypto_frame_chain_del(frc, conn->mem);
      return rv;
    }
  }

  *pfrc = frc;
  return 0;
}

/*
 * conn_should_pad_pkt returns nonzero if the packet should be padded.
 * |type| is the type of packet.  |left| is the space left in packet
 * buffer.  |early_datalen| is the number of bytes which will be sent
 * in the next, coalesced 0-RTT protected packet.
 */
static int conn_should_pad_pkt(ngtcp2_conn *conn, uint8_t type, size_t left,
                               size_t early_datalen) {
  size_t min_payloadlen;

  if (conn->server || conn->hs_pktns.tx_ckm) {
    return 0;
  }

  switch (type) {
  case NGTCP2_PKT_INITIAL:
    if (!conn->early_ckm || early_datalen == 0) {
      return 1;
    }
    min_payloadlen = ngtcp2_min(early_datalen, 128);

    return left <
           /* TODO Assuming that pkt_num is encoded in 1 byte. */
           NGTCP2_MIN_LONG_HEADERLEN + conn->dcid.datalen + conn->scid.datalen +
               1 /* payloadlen bytes - 1 */ + min_payloadlen +
               NGTCP2_MAX_AEAD_OVERHEAD;
  case NGTCP2_PKT_0RTT_PROTECTED:
    return conn->state == NGTCP2_CS_CLIENT_INITIAL;
  default:
    return 0;
  }
}

/*
 * conn_write_handshake_pkt writes handshake packet in the buffer
 * pointed by |dest| whose length is |destlen|.  |type| specifies long
 * packet type.
 *
 * This function returns the number of bytes written in |dest| if it
 * succeeds, or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User-defined callback function failed.
 */
static ssize_t conn_write_handshake_pkt(ngtcp2_conn *conn, uint8_t *dest,
                                        size_t destlen, uint8_t type,
                                        size_t early_datalen,
                                        ngtcp2_tstamp ts) {
  int rv;
  ngtcp2_ppe ppe;
  ngtcp2_pkt_hd hd;
  ngtcp2_frame_chain *frq = NULL, **pfrc = &frq;
  ngtcp2_stream_frame_chain *nsfrc;
  ngtcp2_crypto_frame_chain *ncfrc;
  ngtcp2_frame *ackfr = NULL, lfr;
  ngtcp2_strm *strm;
  ssize_t spktlen;
  ngtcp2_crypto_ctx ctx;
  ngtcp2_rtb_entry *rtbent;
  ngtcp2_acktr_ack_entry *ack_ent = NULL;
  ngtcp2_pktns *pktns;
  size_t left;
  uint8_t flags = NGTCP2_RTB_FLAG_NONE;
  int pkt_empty = 1;
  int padded = 0;

  switch (type) {
  case NGTCP2_PKT_INITIAL:
    if (!conn->in_pktns.tx_ckm) {
      /* This should be assert, but returning 0 is convenient for unit
         tests. */
      return 0;
    }
    pktns = &conn->in_pktns;
    ctx.ckm = pktns->tx_ckm;
    ctx.aead_overhead = NGTCP2_INITIAL_AEAD_OVERHEAD;
    ctx.encrypt = conn->callbacks.in_encrypt;
    ctx.encrypt_pn = conn->callbacks.in_encrypt_pn;
    break;
  case NGTCP2_PKT_HANDSHAKE:
    if (!conn->hs_pktns.tx_ckm) {
      return 0;
    }
    pktns = &conn->hs_pktns;
    ctx.ckm = pktns->tx_ckm;
    ctx.aead_overhead = conn->aead_overhead;
    ctx.encrypt = conn->callbacks.encrypt;
    ctx.encrypt_pn = conn->callbacks.encrypt_pn;
    ctx.user_data = conn;
    break;
  case NGTCP2_PKT_0RTT_PROTECTED:
    if (!conn->early_ckm || ngtcp2_pq_empty(&conn->tx_strmq)) {
      return 0;
    }
    pktns = &conn->pktns;
    ctx.ckm = conn->early_ckm;
    ctx.aead_overhead = conn->aead_overhead;
    ctx.encrypt = conn->callbacks.encrypt;
    ctx.encrypt_pn = conn->callbacks.encrypt_pn;
    ctx.user_data = conn;
    break;
  default:
    assert(0);
  }

  ngtcp2_pkt_hd_init(
      &hd, NGTCP2_PKT_FLAG_LONG_FORM, type, &conn->dcid, &conn->scid,
      pktns->last_tx_pkt_num + 1,
      rtb_select_pkt_numlen(&pktns->rtb, pktns->last_tx_pkt_num + 1),
      conn->version, 0);

  if (type == NGTCP2_PKT_INITIAL && ngtcp2_buf_len(&conn->token)) {
    hd.token = conn->token.pos;
    hd.tokenlen = ngtcp2_buf_len(&conn->token);
  }

  ctx.user_data = conn;

  if (type != NGTCP2_PKT_0RTT_PROTECTED) {
    rv = conn_create_ack_frame(conn, &ackfr, &pktns->acktr, ts,
                               NGTCP2_DEFAULT_ACK_DELAY_EXPONENT);
    if (rv != 0) {
      return rv;
    }
  }

  if (ngtcp2_pq_empty(&pktns->cryptofrq) && !ackfr &&
      type != NGTCP2_PKT_0RTT_PROTECTED) {
    return 0;
  }

  ngtcp2_ppe_init(&ppe, dest, destlen, &ctx);

  rv = ngtcp2_ppe_encode_hd(&ppe, &hd);
  if (rv != 0) {
    assert(NGTCP2_ERR_NOBUF == rv);
    ngtcp2_mem_free(conn->mem, ackfr);
    return 0;
  }

  ngtcp2_log_tx_pkt_hd(&conn->log, &hd);

  if (ackfr) {
    rv = conn_ppe_write_frame(conn, &ppe, &hd, ackfr);
    if (rv != 0) {
      assert(NGTCP2_ERR_NOBUF == rv);
      ngtcp2_mem_free(conn->mem, ackfr);
    } else {
      ngtcp2_acktr_commit_ack(&pktns->acktr);
      ack_ent = ngtcp2_acktr_add_ack(&pktns->acktr, hd.pkt_num, &ackfr->ack, ts,
                                     0 /* ack_only */);
      /* Now ackfr is owned by conn->acktr. */
      pkt_empty = 0;
    }
    ackfr = NULL;
  }

  /* TODO pktns->frq is not used during handshake */
  assert(pktns->frq == NULL);

  if (type != NGTCP2_PKT_0RTT_PROTECTED) {
    for (; !ngtcp2_pq_empty(&pktns->cryptofrq);) {
      left = ngtcp2_ppe_left(&ppe);
      left = ngtcp2_pkt_crypto_max_datalen(
          conn_cryptofrq_top(conn, pktns)->fr.offset, left, left);

      if (left == (size_t)-1) {
        break;
      }

      rv = conn_cryptofrq_pop(conn, &ncfrc, pktns, left);
      if (rv != 0) {
        assert(ngtcp2_err_is_fatal(rv));
        return rv;
      }

      if (ncfrc == NULL) {
        break;
      }

      rv = conn_ppe_write_frame(conn, &ppe, &hd, &ncfrc->frc.fr);
      if (rv != 0) {
        assert(0);
      }

      *pfrc = &ncfrc->frc;
      pfrc = &(*pfrc)->next;

      pkt_empty = 0;
    }
  } else if (!conn->pktns.tx_ckm) {
    for (; !ngtcp2_pq_empty(&conn->tx_strmq);) {
      strm = ngtcp2_conn_tx_strmq_top(conn);
      if (ngtcp2_strm_streamfrq_empty(strm)) {
        ngtcp2_conn_tx_strmq_pop(conn);
        continue;
      }

      left = ngtcp2_ppe_left(&ppe);
      /* What we handle here is retransmission of 0RTT STREAM frame
         after Retry packet.  The flow control credits have already
         been paid for these frames. */
      left = ngtcp2_pkt_stream_max_datalen(
          strm->stream_id, ngtcp2_strm_streamfrq_top(strm)->fr.offset, left,
          left);

      if (left == (size_t)-1) {
        break;
      }

      rv = ngtcp2_strm_streamfrq_pop(strm, &nsfrc, left);
      if (rv != 0) {
        return rv;
      }
      if (ngtcp2_strm_streamfrq_empty(strm)) {
        ngtcp2_conn_tx_strmq_pop(conn);
      }

      if (nsfrc == NULL) {
        break;
      }

      rv = conn_ppe_write_frame(conn, &ppe, &hd, &nsfrc->frc.fr);
      if (rv != 0) {
        assert(0);
      }

      *pfrc = &nsfrc->frc;
      pfrc = &(*pfrc)->next;

      pkt_empty = 0;

      break;
    }
  }

  if (pkt_empty) {
    ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_PKT,
                    "packet transmission canceled");
    return 0;
  }

  /* If we cannot write another packet, then we need to add padding to
     Initial here. */
  if (conn_should_pad_pkt(conn, type, ngtcp2_ppe_left(&ppe), early_datalen)) {
    lfr.type = NGTCP2_FRAME_PADDING;
    lfr.padding.len = ngtcp2_ppe_padding(&ppe);
    if (lfr.padding.len > 0) {
      ngtcp2_log_tx_fr(&conn->log, &hd, &lfr);
    }
    padded = 1;
  }

  spktlen = ngtcp2_ppe_final(&ppe, NULL);
  if (spktlen < 0) {
    assert(ngtcp2_err_is_fatal((int)spktlen));
    return spktlen;
  }

  if (*pfrc != frq || padded) {
    rv = ngtcp2_rtb_entry_new(&rtbent, &hd, frq, ts, (size_t)spktlen, flags,
                              conn->mem);
    if (rv != 0) {
      assert(ngtcp2_err_is_fatal(rv));
      ngtcp2_frame_chain_list_del(frq, conn->mem);
      return rv;
    }

    rv = conn_on_pkt_sent(conn, &pktns->rtb, rtbent);
    if (rv != 0) {
      ngtcp2_rtb_entry_del(rtbent, conn->mem);
      return rv;
    }
  } else if (ack_ent) {
    ack_ent->ack_only = 1;
  }

  ++pktns->last_tx_pkt_num;

  return spktlen;
}

/*
 * conn_write_handshake_ack_pkt writes unprotected QUIC packet in the
 * buffer pointed by |dest| whose length is |destlen|.  The packet
 * only includes ACK frame if any ack is required.
 *
 * This function might send PADDING only packet if it has no ACK frame
 * to send under certain condition.
 *
 * This function returns the number of bytes written in |dest| if it
 * succeeds, or one of the following negative error codes:
 *
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User-defined callback function failed.
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 */
static ssize_t conn_write_handshake_ack_pkt(ngtcp2_conn *conn, uint8_t *dest,
                                            size_t destlen, uint8_t type,
                                            int require_padding,
                                            ngtcp2_tstamp ts) {
  int rv;
  ngtcp2_ppe ppe;
  ngtcp2_pkt_hd hd;
  ngtcp2_frame *ackfr, lfr;
  ngtcp2_crypto_ctx ctx;
  ngtcp2_pktns *pktns;
  ngtcp2_rtb_entry *rtbent;
  ngtcp2_acktr_ack_entry *ack_ent = NULL;
  ssize_t spktlen;
  int force_initial;

  switch (type) {
  case NGTCP2_PKT_INITIAL:
    pktns = &conn->in_pktns;
    ctx.aead_overhead = NGTCP2_INITIAL_AEAD_OVERHEAD;
    ctx.encrypt = conn->callbacks.in_encrypt;
    ctx.encrypt_pn = conn->callbacks.in_encrypt_pn;
    break;
  case NGTCP2_PKT_HANDSHAKE:
    pktns = &conn->hs_pktns;
    ctx.aead_overhead = conn->aead_overhead;
    ctx.encrypt = conn->callbacks.encrypt;
    ctx.encrypt_pn = conn->callbacks.encrypt_pn;
    break;
  default:
    assert(0);
  }

  if (!pktns->tx_ckm) {
    return 0;
  }

  force_initial = type == NGTCP2_PKT_INITIAL && require_padding &&
                  (conn->flags & NGTCP2_CONN_FLAG_FORCE_SEND_INITIAL);

  ackfr = NULL;
  rv = conn_create_ack_frame(conn, &ackfr, &pktns->acktr, ts,
                             NGTCP2_DEFAULT_ACK_DELAY_EXPONENT);
  if (rv != 0) {
    return rv;
  }
  if (!ackfr && !force_initial) {
    return 0;
  }

  ngtcp2_pkt_hd_init(
      &hd, NGTCP2_PKT_FLAG_LONG_FORM, type, &conn->dcid, &conn->scid,
      pktns->last_tx_pkt_num + 1,
      rtb_select_pkt_numlen(&pktns->rtb, pktns->last_tx_pkt_num + 1),
      conn->version, 0);

  ctx.ckm = pktns->tx_ckm;
  ctx.user_data = conn;

  ngtcp2_ppe_init(&ppe, dest, destlen, &ctx);

  rv = ngtcp2_ppe_encode_hd(&ppe, &hd);
  if (rv != 0) {
    assert(NGTCP2_ERR_NOBUF == rv);
    ngtcp2_mem_free(conn->mem, ackfr);
    return 0;
  }

  ngtcp2_log_tx_pkt_hd(&conn->log, &hd);

  if (ackfr) {
    rv = conn_ppe_write_frame(conn, &ppe, &hd, ackfr);
    if (rv != 0) {
      assert(NGTCP2_ERR_NOBUF == rv);
      ngtcp2_mem_free(conn->mem, ackfr);
    } else {
      ngtcp2_acktr_commit_ack(&pktns->acktr);

      ack_ent = ngtcp2_acktr_add_ack(&pktns->acktr, hd.pkt_num, &ackfr->ack, ts,
                                     0 /* ack_only*/);
    }
    ackfr = NULL;
  }

  if (require_padding) {
    lfr.type = NGTCP2_FRAME_PADDING;
    lfr.padding.len = ngtcp2_ppe_padding(&ppe);
    if (lfr.padding.len > 0) {
      ngtcp2_log_tx_fr(&conn->log, &hd, &lfr);
    }

    spktlen = ngtcp2_ppe_final(&ppe, NULL);
    if (spktlen < 0) {
      return spktlen;
    }

    rv = ngtcp2_rtb_entry_new(&rtbent, &hd, NULL, ts, (size_t)spktlen,
                              NGTCP2_RTB_FLAG_NONE, conn->mem);
    if (rv != 0) {
      assert(ngtcp2_err_is_fatal(rv));
      return rv;
    }

    rv = conn_on_pkt_sent(conn, &pktns->rtb, rtbent);
    if (rv != 0) {
      ngtcp2_rtb_entry_del(rtbent, conn->mem);
      return rv;
    }

    assert(type == NGTCP2_PKT_INITIAL);
    conn->flags &= (uint16_t)~NGTCP2_CONN_FLAG_FORCE_SEND_INITIAL;
  } else {
    spktlen = ngtcp2_ppe_final(&ppe, NULL);
    if (spktlen < 0) {
      return spktlen;
    }

    ack_ent->ack_only = 1;
  }

  ++pktns->last_tx_pkt_num;

  return spktlen;
}

/*
 * conn_write_handshake_ack_pkts writes packets which contain ACK
 * frame only.  This function writes at most 2 packets for each
 * Initial and Handshake packet.
 */
static ssize_t conn_write_handshake_ack_pkts(ngtcp2_conn *conn, uint8_t *dest,
                                             size_t destlen, ngtcp2_tstamp ts) {
  ssize_t res = 0, nwrite;
  int require_padding = !conn->hs_pktns.tx_ckm;

  if (require_padding) {
    /* PADDING frame counts toward bytes_in_flight, thus destlen is
       constrained to cwnd */
    destlen = ngtcp2_min(destlen, conn_cwnd_left(conn));
  }

  nwrite = conn_write_handshake_ack_pkt(conn, dest, destlen, NGTCP2_PKT_INITIAL,
                                        require_padding, ts);
  if (nwrite < 0) {
    assert(nwrite != NGTCP2_ERR_NOBUF);
    return nwrite;
  }

  res += nwrite;
  dest += nwrite;
  destlen -= (size_t)nwrite;

  nwrite = conn_write_handshake_ack_pkt(
      conn, dest, destlen, NGTCP2_PKT_HANDSHAKE, 0 /* require_padding */, ts);
  if (nwrite < 0) {
    assert(nwrite != NGTCP2_ERR_NOBUF);
    return nwrite;
  }

  return res + nwrite;
}

/*
 * conn_retransmit_retry_early retransmits 0RTT Protected packet after
 * Retry is received from server.
 */
static ssize_t conn_retransmit_retry_early(ngtcp2_conn *conn, uint8_t *dest,
                                           size_t destlen, ngtcp2_tstamp ts) {
  return conn_write_handshake_pkt(conn, dest, destlen,
                                  NGTCP2_PKT_0RTT_PROTECTED, 0, ts);
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
 */
static ssize_t conn_write_client_initial(ngtcp2_conn *conn, uint8_t *dest,
                                         size_t destlen, size_t early_datalen,
                                         ngtcp2_tstamp ts) {
  int rv;

  rv = conn->callbacks.client_initial(conn, conn->user_data);
  if (rv != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return conn_write_handshake_pkt(conn, dest, destlen, NGTCP2_PKT_INITIAL,
                                  early_datalen, ts);
}

/*
 * conn_write_handshake_pkts writes Initial and Handshake packets in
 * the buffer pointed by |dest| whose length is |destlen|.
 *
 * This function returns the number of bytes written in |dest| if it
 * succeeds, or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User-defined callback function failed.
 */
static ssize_t conn_write_handshake_pkts(ngtcp2_conn *conn, uint8_t *dest,
                                         size_t destlen, size_t early_datalen,
                                         ngtcp2_tstamp ts) {
  ssize_t nwrite;
  ssize_t res = 0;

  nwrite = conn_write_handshake_pkt(conn, dest, destlen, NGTCP2_PKT_INITIAL,
                                    early_datalen, ts);
  if (nwrite < 0) {
    assert(nwrite != NGTCP2_ERR_NOBUF);
    return nwrite;
  }

  res += nwrite;
  dest += nwrite;
  destlen -= (size_t)nwrite;

  nwrite = conn_write_handshake_pkt(conn, dest, destlen, NGTCP2_PKT_HANDSHAKE,
                                    0, ts);
  if (nwrite < 0) {
    assert(nwrite != NGTCP2_ERR_NOBUF);
    return nwrite;
  }

  res += nwrite;
  dest += nwrite;
  destlen -= (size_t)nwrite;

  return res;
}

static ssize_t conn_write_protected_ack_pkt(ngtcp2_conn *conn, uint8_t *dest,
                                            size_t destlen, ngtcp2_tstamp ts);

static ssize_t conn_write_server_handshake(ngtcp2_conn *conn, uint8_t *dest,
                                           size_t destlen, ngtcp2_tstamp ts) {
  ssize_t nwrite;
  ssize_t res = 0;

  nwrite = conn_write_handshake_pkts(conn, dest, destlen, 0, ts);
  if (nwrite < 0) {
    assert(nwrite != NGTCP2_ERR_NOBUF);
    return nwrite;
  }

  res += nwrite;
  dest += nwrite;
  destlen -= (size_t)nwrite;

  /* Acknowledge 0-RTT packet here. */
  if (conn->pktns.tx_ckm) {
    nwrite = conn_write_protected_ack_pkt(conn, dest, destlen, ts);
    if (nwrite < 0) {
      assert(nwrite != NGTCP2_ERR_NOBUF);
      return nwrite;
    }
  }

  res += nwrite;
  dest += nwrite;
  destlen -= (size_t)nwrite;

  return res;
}

/*
 * conn_initial_stream_rx_offset returns the initial maximum offset of
 * data for a stream denoted by |stream_id|.
 */
static uint64_t conn_initial_stream_rx_offset(ngtcp2_conn *conn,
                                              uint64_t stream_id) {
  int local_stream = conn_local_stream(conn, stream_id);

  if (bidi_stream(stream_id)) {
    if (local_stream) {
      return conn->local_settings.max_stream_data_bidi_local;
    }
    return conn->local_settings.max_stream_data_bidi_remote;
  }

  if (local_stream) {
    return 0;
  }
  return conn->local_settings.max_stream_data_uni;
}

/*
 * conn_should_send_max_stream_data returns nonzero if MAX_STREAM_DATA
 * frame should be send for |strm|.
 */
static int conn_should_send_max_stream_data(ngtcp2_conn *conn,
                                            ngtcp2_strm *strm) {

  return conn_initial_stream_rx_offset(conn, strm->stream_id) / 2 <
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
 * NGTCP2_ERR_STREAM_DATA_BLOCKED
 *     Stream data could not be written because of flow control.
 */
static ssize_t conn_write_pkt(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                              ssize_t *pdatalen, ngtcp2_strm *data_strm,
                              uint8_t fin, const ngtcp2_vec *datav,
                              size_t datavcnt, ngtcp2_tstamp ts) {
  int rv;
  ngtcp2_ppe ppe;
  ngtcp2_pkt_hd hd;
  ngtcp2_frame *ackfr = NULL;
  ssize_t nwrite;
  ngtcp2_crypto_ctx ctx;
  ngtcp2_frame_chain **pfrc, *nfrc, *frc;
  ngtcp2_stream_frame_chain *nsfrc;
  ngtcp2_crypto_frame_chain *ncfrc;
  ngtcp2_rtb_entry *ent;
  ngtcp2_strm *strm;
  int pkt_empty = 1;
  ngtcp2_acktr_ack_entry *ack_ent = NULL;
  size_t ndatalen = 0;
  int send_stream = 0;
  int stream_blocked = 0;
  ngtcp2_pktns *pktns = &conn->pktns;
  size_t left;
  uint64_t written_stream_id = UINT64_MAX;
  size_t datalen = ngtcp2_vec_len(datav, datavcnt);

  if (data_strm) {
    ndatalen = conn_enforce_flow_control(conn, data_strm, datalen);
    /* 0 length STREAM frame is allowed */
    if (ndatalen || datalen == 0) {
      send_stream = 1;
    } else {
      stream_blocked = 1;
    }
  }

  /* TODO Take into account stream frames */
  if ((pktns->frq || send_stream || conn_should_send_max_data(conn)) &&
      conn->unsent_max_rx_offset > conn->max_rx_offset) {
    rv = ngtcp2_frame_chain_new(&nfrc, conn->mem);
    if (rv != 0) {
      return rv;
    }
    nfrc->fr.type = NGTCP2_FRAME_MAX_DATA;
    nfrc->fr.max_data.max_data = conn->unsent_max_rx_offset;
    nfrc->next = pktns->frq;
    pktns->frq = nfrc;

    conn->max_rx_offset = conn->unsent_max_rx_offset;
  }

  ngtcp2_pkt_hd_init(
      &hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_SHORT, &conn->dcid, &conn->scid,
      pktns->last_tx_pkt_num + 1,
      rtb_select_pkt_numlen(&pktns->rtb, pktns->last_tx_pkt_num + 1),
      conn->version, 0);

  ctx.ckm = pktns->tx_ckm;
  ctx.aead_overhead = conn->aead_overhead;
  ctx.encrypt = conn->callbacks.encrypt;
  ctx.encrypt_pn = conn->callbacks.encrypt_pn;
  ctx.user_data = conn;

  ngtcp2_ppe_init(&ppe, dest, destlen, &ctx);

  rv = ngtcp2_ppe_encode_hd(&ppe, &hd);
  if (rv != 0) {
    assert(NGTCP2_ERR_NOBUF == rv);
    return 0;
  }

  ngtcp2_log_tx_pkt_hd(&conn->log, &hd);

  for (pfrc = &pktns->frq; *pfrc;) {
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
    case NGTCP2_FRAME_STREAM:
      assert(0);
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
      if (strm == NULL || (strm->flags & NGTCP2_STRM_FLAG_SHUT_RD) ||
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
    case NGTCP2_FRAME_CRYPTO:
      assert(0);
      break;
    }

    rv = conn_ppe_write_frame(conn, &ppe, &hd, &(*pfrc)->fr);
    if (rv != 0) {
      assert(NGTCP2_ERR_NOBUF == rv);
      goto frame_write_finish;
    }

    pkt_empty = 0;
    pfrc = &(*pfrc)->next;
  }

  for (; !ngtcp2_pq_empty(&pktns->cryptofrq);) {
    left = ngtcp2_ppe_left(&ppe);

    left = ngtcp2_pkt_crypto_max_datalen(
        conn_cryptofrq_top(conn, pktns)->fr.offset, left, left);

    if (left == (size_t)-1) {
      goto frame_write_finish;
    }

    rv = conn_cryptofrq_pop(conn, &ncfrc, pktns, left);
    if (rv != 0) {
      assert(ngtcp2_err_is_fatal(rv));
      return rv;
    }

    if (ncfrc == NULL) {
      break;
    }

    rv = conn_ppe_write_frame(conn, &ppe, &hd, &ncfrc->frc.fr);
    if (rv != 0) {
      assert(0);
    }

    *pfrc = &ncfrc->frc;
    pfrc = &(*pfrc)->next;

    pkt_empty = 0;
  }

  /* Write MAX_STREAM_ID after RST_STREAM so that we can extend stream
     ID space in one packet. */
  if (*pfrc == NULL && conn->unsent_max_remote_stream_id_bidi >
                           conn->max_remote_stream_id_bidi) {
    rv = ngtcp2_frame_chain_new(&nfrc, conn->mem);
    if (rv != 0) {
      assert(ngtcp2_err_is_fatal(rv));
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
      goto frame_write_finish;
    }

    pkt_empty = 0;
    pfrc = &(*pfrc)->next;
  }

  if (*pfrc == NULL) {
    if (conn->unsent_max_remote_stream_id_uni >
        conn->max_remote_stream_id_uni) {
      rv = ngtcp2_frame_chain_new(&nfrc, conn->mem);
      if (rv != 0) {
        assert(ngtcp2_err_is_fatal(rv));
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
        goto frame_write_finish;
      }

      pkt_empty = 0;
      pfrc = &(*pfrc)->next;
    }

    for (; !ngtcp2_pq_empty(&conn->tx_strmq);) {
      strm = ngtcp2_conn_tx_strmq_top(conn);

      if (!(strm->flags & NGTCP2_STRM_FLAG_SHUT_RD) &&
          strm->max_rx_offset < strm->unsent_max_rx_offset) {
        rv = ngtcp2_frame_chain_new(&nfrc, conn->mem);
        if (rv != 0) {
          assert(ngtcp2_err_is_fatal(rv));
          return rv;
        }
        nfrc->fr.type = NGTCP2_FRAME_MAX_STREAM_DATA;
        nfrc->fr.max_stream_data.stream_id = strm->stream_id;
        nfrc->fr.max_stream_data.max_stream_data = strm->unsent_max_rx_offset;
        ngtcp2_list_insert(nfrc, pfrc);

        rv = conn_ppe_write_frame(conn, &ppe, &hd, &nfrc->fr);
        if (rv != 0) {
          assert(NGTCP2_ERR_NOBUF == rv);
          goto frame_write_finish;
        }

        pkt_empty = 0;
        pfrc = &(*pfrc)->next;
        strm->max_rx_offset = strm->unsent_max_rx_offset;
      }

      for (;;) {
        if (ngtcp2_strm_streamfrq_empty(strm)) {
          ngtcp2_conn_tx_strmq_pop(conn);
          if (written_stream_id == UINT64_MAX) {
            break;
          }
          goto tx_strmq_finish;
        }

        left = ngtcp2_ppe_left(&ppe);

        left = ngtcp2_pkt_stream_max_datalen(
            strm->stream_id, ngtcp2_strm_streamfrq_top(strm)->fr.offset, left,
            left);

        if (left == (size_t)-1) {
          if (written_stream_id != UINT64_MAX) {
            ngtcp2_conn_tx_strmq_pop(conn);
            ++strm->cycle;
            rv = ngtcp2_conn_tx_strmq_push(conn, strm);
            if (rv != 0) {
              assert(ngtcp2_err_is_fatal(rv));
              return rv;
            }
          }
          goto frame_write_finish;
        }

        rv = ngtcp2_strm_streamfrq_pop(strm, &nsfrc, left);
        if (rv != 0) {
          assert(ngtcp2_err_is_fatal(rv));
          return rv;
        }

        if (nsfrc == NULL) {
          goto frame_write_finish;
        }

        rv = conn_ppe_write_frame(conn, &ppe, &hd, &nsfrc->frc.fr);
        if (rv != 0) {
          assert(0);
        }

        *pfrc = &nsfrc->frc;
        pfrc = &(*pfrc)->next;

        written_stream_id = strm->stream_id;

        pkt_empty = 0;
      }
    }
  }

tx_strmq_finish:

  left = ngtcp2_ppe_left(&ppe);

  if (send_stream &&
      (written_stream_id == UINT64_MAX ||
       written_stream_id == data_strm->stream_id) &&
      *pfrc == NULL &&
      (ndatalen = ngtcp2_pkt_stream_max_datalen(data_strm->stream_id,
                                                data_strm->tx_offset, ndatalen,
                                                left)) != (size_t)-1) {
    fin = fin && ndatalen == datalen;

    rv = ngtcp2_stream_frame_chain_new(&nsfrc, conn->mem);
    if (rv != 0) {
      assert(ngtcp2_err_is_fatal(rv));
      return rv;
    }

    nsfrc->fr.type = NGTCP2_FRAME_STREAM;
    nsfrc->fr.flags = 0;
    nsfrc->fr.fin = fin;
    nsfrc->fr.stream_id = data_strm->stream_id;
    nsfrc->fr.offset = data_strm->tx_offset;
    nsfrc->fr.datacnt = ngtcp2_vec_copy(
        nsfrc->fr.data, NGTCP2_MAX_STREAM_DATACNT, datav, datavcnt, ndatalen);

    rv = conn_ppe_write_frame(conn, &ppe, &hd, &nsfrc->frc.fr);
    if (rv != 0) {
      assert(0);
    }

    *pfrc = &nsfrc->frc;
    pfrc = &(*pfrc)->next;

    pkt_empty = 0;
  } else {
    send_stream = 0;
  }

  /* It might be better to avoid ACK only packet here.  It can be sent
     without flow control limits later. */
  if (!pkt_empty) {
    rv = conn_create_ack_frame(conn, &ackfr, &pktns->acktr, ts,
                               conn->local_settings.ack_delay_exponent);
    if (rv != 0) {
      assert(ngtcp2_err_is_fatal(rv));
      return rv;
    }

    if (ackfr) {
      rv = conn_ppe_write_frame(conn, &ppe, &hd, ackfr);
      if (rv != 0) {
        assert(NGTCP2_ERR_NOBUF == rv);
        ngtcp2_mem_free(conn->mem, ackfr);
      } else {
        ngtcp2_acktr_commit_ack(&pktns->acktr);
        pkt_empty = 0;

        ack_ent = ngtcp2_acktr_add_ack(&pktns->acktr, hd.pkt_num, &ackfr->ack,
                                       ts, 0 /*ack_only*/);
        /* Now ackfr is owned by conn->acktr. */
        pkt_empty = 0;
      }
      ackfr = NULL;
    }
  }

frame_write_finish:
  if (pkt_empty) {
    assert(rv == 0 || NGTCP2_ERR_NOBUF == rv);
    ngtcp2_log_tx_cancel(&conn->log, &hd);
    if (rv == 0 && stream_blocked) {
      return NGTCP2_ERR_STREAM_DATA_BLOCKED;
    }
    return 0;
  }

  /* TODO Push STREAM frame back to ngtcp2_strm if there is an error
     before ngtcp2_rtb_entry is safely created and added. */

  nwrite = ngtcp2_ppe_final(&ppe, NULL);
  if (nwrite < 0) {
    assert(ngtcp2_err_is_fatal((int)nwrite));
    return nwrite;
  }

  if (*pfrc != pktns->frq) {
    rv = ngtcp2_rtb_entry_new(&ent, &hd, NULL, ts, (size_t)nwrite,
                              NGTCP2_RTB_FLAG_NONE, conn->mem);
    if (rv != 0) {
      assert(ngtcp2_err_is_fatal((int)nwrite));
      return rv;
    }

    ent->frc = pktns->frq;
    pktns->frq = *pfrc;
    *pfrc = NULL;

    rv = conn_on_pkt_sent(conn, &pktns->rtb, ent);
    if (rv != 0) {
      assert(ngtcp2_err_is_fatal(rv));
      ngtcp2_rtb_entry_del(ent, conn->mem);
      return rv;
    }

    if (send_stream) {
      data_strm->tx_offset += ndatalen;
      conn->tx_offset += ndatalen;

      if (fin) {
        ngtcp2_strm_shutdown(data_strm, NGTCP2_STRM_FLAG_SHUT_WR);
      }
    }
  } else if (ack_ent) {
    ack_ent->ack_only = 1;
  }

  if (pdatalen && send_stream) {
    *pdatalen = (ssize_t)ndatalen;
  }

  ++pktns->last_tx_pkt_num;

  return nwrite;
}

/*
 * conn_write_single_frame_pkt writes a packet which contains |fr|
 * frame only in the buffer pointed by |dest| whose length if
 * |destlen|.  |type| is a long packet type to send.  If |type| is 0,
 * Short packet is used.
 *
 * This function returns the number of bytes written in |dest| if it
 * succeeds, or one of the following negative error codes:
 *
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User-defined callback function failed.
 */
static ssize_t conn_write_single_frame_pkt(ngtcp2_conn *conn, uint8_t *dest,
                                           size_t destlen, uint8_t type,
                                           ngtcp2_frame *fr, ngtcp2_tstamp ts) {
  int rv;
  ngtcp2_ppe ppe;
  ngtcp2_pkt_hd hd;
  ssize_t nwrite;
  ngtcp2_crypto_ctx ctx;
  ngtcp2_pktns *pktns;
  uint8_t flags;

  switch (type) {
  case NGTCP2_PKT_INITIAL:
    pktns = &conn->in_pktns;
    ctx.aead_overhead = NGTCP2_INITIAL_AEAD_OVERHEAD;
    ctx.encrypt = conn->callbacks.in_encrypt;
    ctx.encrypt_pn = conn->callbacks.in_encrypt_pn;
    flags = NGTCP2_PKT_FLAG_LONG_FORM;
    break;
  case NGTCP2_PKT_HANDSHAKE:
    pktns = &conn->hs_pktns;
    ctx.aead_overhead = conn->aead_overhead;
    ctx.encrypt = conn->callbacks.encrypt;
    ctx.encrypt_pn = conn->callbacks.encrypt_pn;
    flags = NGTCP2_PKT_FLAG_LONG_FORM;
    break;
  case 0:
    /* 0 means Short packet. */
    pktns = &conn->pktns;
    ctx.aead_overhead = conn->aead_overhead;
    ctx.encrypt = conn->callbacks.encrypt;
    ctx.encrypt_pn = conn->callbacks.encrypt_pn;
    flags = NGTCP2_PKT_FLAG_NONE;
    break;
  default:
    /* We don't support 0-RTT Protected packet in this function. */
    assert(0);
  }

  ctx.ckm = pktns->tx_ckm;
  ctx.user_data = conn;

  ngtcp2_pkt_hd_init(
      &hd, flags, type, &conn->dcid, &conn->scid, pktns->last_tx_pkt_num + 1,
      rtb_select_pkt_numlen(&pktns->rtb, pktns->last_tx_pkt_num + 1),
      conn->version, 0);

  ngtcp2_ppe_init(&ppe, dest, destlen, &ctx);

  rv = ngtcp2_ppe_encode_hd(&ppe, &hd);
  if (rv != 0) {
    assert(NGTCP2_ERR_NOBUF == rv);
    return 0;
  }

  ngtcp2_log_tx_pkt_hd(&conn->log, &hd);

  rv = conn_ppe_write_frame(conn, &ppe, &hd, fr);
  if (rv != 0) {
    assert(NGTCP2_ERR_NOBUF == rv);
    return 0;
  }

  nwrite = ngtcp2_ppe_final(&ppe, NULL);
  if (nwrite < 0) {
    return nwrite;
  }

  /* Do this when we are sure that there is no error. */
  if (fr->type == NGTCP2_FRAME_ACK) {
    ngtcp2_acktr_commit_ack(&pktns->acktr);
    ngtcp2_acktr_add_ack(&pktns->acktr, hd.pkt_num, &fr->ack, ts,
                         1 /* ack_only */);
  }

  ++pktns->last_tx_pkt_num;

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
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 */
static ssize_t conn_write_protected_ack_pkt(ngtcp2_conn *conn, uint8_t *dest,
                                            size_t destlen, ngtcp2_tstamp ts) {
  int rv;
  ssize_t spktlen;
  ngtcp2_frame *ackfr;
  ngtcp2_acktr *acktr = &conn->pktns.acktr;

  ackfr = NULL;
  rv = conn_create_ack_frame(conn, &ackfr, acktr, ts,
                             conn->local_settings.ack_delay_exponent);
  if (rv != 0) {
    return rv;
  }

  if (!ackfr) {
    return 0;
  }

  spktlen = conn_write_single_frame_pkt(conn, dest, destlen, 0 /* Short */,
                                        ackfr, ts);
  if (spktlen < 0) {
    ngtcp2_mem_free(conn->mem, ackfr);
    return spktlen;
  }

  return spktlen;
}

/*
 * conn_process_early_rtb makes any pending 0RTT protected packet
 * Short packet.
 */
static void conn_process_early_rtb(ngtcp2_conn *conn) {
  ngtcp2_rtb_entry *ent;
  ngtcp2_rtb *rtb = &conn->pktns.rtb;
  ngtcp2_ksl_it it;

  for (it = ngtcp2_rtb_head(rtb); !ngtcp2_ksl_it_end(&it);
       ngtcp2_ksl_it_next(&it)) {
    ent = ngtcp2_ksl_it_get(&it);

    if ((ent->hd.flags & NGTCP2_PKT_FLAG_LONG_FORM) == 0 ||
        ent->hd.type != NGTCP2_PKT_0RTT_PROTECTED) {
      continue;
    }

    ent->hd.dcid = conn->dcid;

    /*  0-RTT packet is retransmitted as a Short packet. */
    ent->hd.flags &= (uint8_t)~NGTCP2_PKT_FLAG_LONG_FORM;
    ent->hd.type = NGTCP2_PKT_SHORT;
  }
}

/*
 * conn_write_probe_ping writes probe packet containing PING frame
 * (and optionally ACK frame).
 */
static ssize_t conn_write_probe_ping(ngtcp2_conn *conn, uint8_t *dest,
                                     size_t destlen, ngtcp2_tstamp ts) {
  ngtcp2_ppe ppe;
  ngtcp2_pkt_hd hd;
  ngtcp2_pktns *pktns = &conn->pktns;
  ngtcp2_crypto_ctx ctx;
  ngtcp2_frame_chain *frc = NULL;
  ngtcp2_rtb_entry *ent;
  ngtcp2_frame *ackfr = NULL;
  int rv;
  ssize_t nwrite;

  assert(pktns->tx_ckm);

  ctx.aead_overhead = conn->aead_overhead;
  ctx.encrypt = conn->callbacks.encrypt;
  ctx.encrypt_pn = conn->callbacks.encrypt_pn;
  ctx.ckm = pktns->tx_ckm;
  ctx.user_data = conn;

  ngtcp2_pkt_hd_init(
      &hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_SHORT, &conn->dcid, &conn->scid,
      pktns->last_tx_pkt_num + 1,
      rtb_select_pkt_numlen(&pktns->rtb, pktns->last_tx_pkt_num + 1),
      conn->version, 0);

  ngtcp2_ppe_init(&ppe, dest, destlen, &ctx);

  rv = ngtcp2_ppe_encode_hd(&ppe, &hd);
  if (rv != 0) {
    assert(NGTCP2_ERR_NOBUF == rv);
    return 0;
  }

  ngtcp2_log_tx_pkt_hd(&conn->log, &hd);

  rv = ngtcp2_frame_chain_new(&frc, conn->mem);
  if (rv != 0) {
    return rv;
  }

  frc->fr.type = NGTCP2_FRAME_PING;

  rv = conn_ppe_write_frame(conn, &ppe, &hd, &frc->fr);
  if (rv != 0) {
    assert(NGTCP2_ERR_NOBUF == rv);
    rv = 0;
    goto fail;
  }

  rv = conn_create_ack_frame(conn, &ackfr, &pktns->acktr, ts,
                             conn->local_settings.ack_delay_exponent);
  if (rv != 0) {
    goto fail;
  }

  if (ackfr) {
    rv = conn_ppe_write_frame(conn, &ppe, &hd, ackfr);
    if (rv != 0) {
      assert(NGTCP2_ERR_NOBUF == rv);
      ngtcp2_mem_free(conn->mem, ackfr);
    } else {
      ngtcp2_acktr_commit_ack(&pktns->acktr);
      ngtcp2_acktr_add_ack(&pktns->acktr, hd.pkt_num, &ackfr->ack, ts,
                           0 /* ack_only */);
    }
    ackfr = NULL;
  }

  nwrite = ngtcp2_ppe_final(&ppe, NULL);
  if (nwrite < 0) {
    rv = (int)nwrite;
    goto fail;
  }

  rv = ngtcp2_rtb_entry_new(&ent, &hd, frc, ts, (size_t)nwrite,
                            NGTCP2_RTB_FLAG_PROBE, conn->mem);
  if (rv != 0) {
    goto fail;
  }

  rv = conn_on_pkt_sent(conn, &pktns->rtb, ent);
  if (rv != 0) {
    ngtcp2_rtb_entry_del(ent, conn->mem);
    return rv;
  }

  ++pktns->last_tx_pkt_num;

  return nwrite;

fail:
  ngtcp2_frame_chain_del(frc, conn->mem);

  return rv;
}

static ssize_t conn_write_probe_pkt(ngtcp2_conn *conn, uint8_t *dest,
                                    size_t destlen, ssize_t *pdatalen,
                                    ngtcp2_strm *strm, uint8_t fin,
                                    const ngtcp2_vec *datav, size_t datavcnt,
                                    ngtcp2_tstamp ts) {
  ssize_t nwrite;

  ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_CON,
                  "transmit probe pkt left=%zu", conn->rcs.probe_pkt_left);

  /* a probe packet is not blocked by cwnd. */
  nwrite = conn_write_pkt(conn, dest, destlen, pdatalen, strm, fin, datav,
                          datavcnt, ts);
  if (nwrite == 0 || nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
    nwrite = conn_write_probe_ping(conn, dest, destlen, ts);
  }
  if (nwrite <= 0) {
    return nwrite;
  }

  --conn->rcs.probe_pkt_left;

  ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_CON, "probe pkt size=%zd",
                  nwrite);

  return nwrite;
}

ssize_t ngtcp2_conn_write_pkt(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                              ngtcp2_tstamp ts) {
  ssize_t nwrite;
  uint64_t cwnd;
  ngtcp2_pktns *pktns = &conn->pktns;
  size_t origlen = destlen;

  conn->log.last_ts = ts;

  if (pktns->last_tx_pkt_num == NGTCP2_MAX_PKT_NUM) {
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
    destlen = ngtcp2_min(destlen, cwnd);

    nwrite = conn_write_handshake_pkts(conn, dest, destlen, 0, ts);
    if (nwrite) {
      return nwrite;
    }
    nwrite = conn_write_handshake_ack_pkts(conn, dest, origlen, ts);
    if (nwrite) {
      return nwrite;
    }

    if (conn->rcs.probe_pkt_left) {
      return conn_write_probe_pkt(conn, dest, origlen, NULL, NULL, 0, NULL, 0,
                                  ts);
    }

    nwrite = conn_write_pkt(conn, dest, destlen, NULL, NULL, 0, NULL, 0, ts);
    if (nwrite < 0) {
      assert(nwrite != NGTCP2_ERR_NOBUF);
      return nwrite;
    }
    if (nwrite) {
      return nwrite;
    }
    return conn_write_protected_ack_pkt(conn, dest, origlen, ts);
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

  /* TODO Just move to the terminal state for now in order not to send
     CONNECTION_CLOSE frame. */
  conn->state = NGTCP2_CS_DRAINING;

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
 * conn_resched_frames reschedules frames linked from |*pfrc| for
 * retransmission.
 */
static int conn_resched_frames(ngtcp2_conn *conn, ngtcp2_pktns *pktns,
                               ngtcp2_frame_chain **pfrc) {
  ngtcp2_frame_chain **first = pfrc;
  ngtcp2_stream_frame_chain *sfrc;
  ngtcp2_stream *sfr;
  ngtcp2_crypto_frame_chain *cfrc;
  ngtcp2_strm *strm;
  int rv;

  if (*pfrc == NULL) {
    return 0;
  }

  for (; *pfrc;) {
    switch ((*pfrc)->fr.type) {
    case NGTCP2_FRAME_STREAM:
      sfrc = (ngtcp2_stream_frame_chain *)*pfrc;

      *pfrc = sfrc->next;
      sfrc->next = NULL;
      sfr = &sfrc->fr;

      strm = ngtcp2_conn_find_stream(conn, sfr->stream_id);
      if (!strm) {
        ngtcp2_stream_frame_chain_del(sfrc, conn->mem);
        break;
      }
      rv = ngtcp2_strm_streamfrq_push(strm, sfrc);
      if (rv != 0) {
        ngtcp2_stream_frame_chain_del(sfrc, conn->mem);
        return rv;
      }
      if (!ngtcp2_strm_is_tx_queued(strm)) {
        rv = ngtcp2_conn_tx_strmq_push(conn, strm);
        if (rv != 0) {
          return rv;
        }
      }
      break;
    case NGTCP2_FRAME_CRYPTO:
      cfrc = (ngtcp2_crypto_frame_chain *)*pfrc;

      *pfrc = cfrc->next;
      cfrc->next = NULL;

      rv = ngtcp2_pq_push(&pktns->cryptofrq, &cfrc->pe);
      if (rv != 0) {
        assert(ngtcp2_err_is_fatal(rv));
        ngtcp2_crypto_frame_chain_del(cfrc, conn->mem);
        return rv;
      }
      break;
    default:
      pfrc = &(*pfrc)->next;
    }
  }

  *pfrc = pktns->frq;
  pktns->frq = *first;

  return 0;
}

/*
 * conn_on_retry is called when Retry packet is received.  The
 * function decodes the data in the buffer pointed by |payload| whose
 * length is |payloadlen| as Retry packet payload.  The packet header
 * is given in |hd|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User-defined callback function failed.
 * NGTCP2_ERR_INVALID_ARGUMENT
 *     Packet payload is badly formatted.
 * NGTCP2_ERR_PROTO
 *     ODCID does not match; or Token is empty.
 */
static int conn_on_retry(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                         const uint8_t *payload, size_t payloadlen) {
  int rv;
  ngtcp2_pkt_retry retry;
  uint8_t *p;
  ngtcp2_rtb *rtb = &conn->pktns.rtb;
  uint8_t cidbuf[sizeof(retry.odcid.data) * 2 + 1];
  ngtcp2_frame_chain *frc = NULL;

  if (conn->flags & NGTCP2_CONN_FLAG_RECV_RETRY) {
    return 0;
  }

  rv = ngtcp2_pkt_decode_retry(&retry, payload, payloadlen);
  if (rv != 0) {
    return rv;
  }

  ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_PKT, "odcid=0x%s",
                  (const char *)ngtcp2_encode_hex(cidbuf, retry.odcid.data,
                                                  retry.odcid.datalen));

  if (!ngtcp2_cid_eq(&conn->dcid, &retry.odcid) || retry.tokenlen == 0) {
    return NGTCP2_ERR_PROTO;
  }

  /* DCID must be updated before invoking callback because client
     generates new initial keys there. */
  conn->dcid = hd->scid;

  conn->flags |= NGTCP2_CONN_FLAG_RECV_RETRY;

  assert(conn->callbacks.recv_retry);

  rv = conn->callbacks.recv_retry(conn, hd, &retry, conn->user_data);
  if (rv != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  conn->state = NGTCP2_CS_CLIENT_INITIAL;

  /* Just freeing memory is dangerous because we might free twice. */

  ngtcp2_crypto_km_del(conn->early_ckm, conn->mem);
  conn->early_ckm = NULL;

  rv = ngtcp2_rtb_remove_all(rtb, &frc);
  if (rv != 0) {
    assert(ngtcp2_err_is_fatal(rv));
    ngtcp2_frame_chain_list_del(frc, conn->mem);
    return rv;
  }

  rv = conn_resched_frames(conn, &conn->pktns, &frc);
  if (rv != 0) {
    assert(ngtcp2_err_is_fatal(rv));
    ngtcp2_frame_chain_list_del(frc, conn->mem);
    return rv;
  }

  conn->pktns.last_tx_pkt_num = (uint64_t)-1;
  conn->pktns.crypto_tx_offset = 0;
  ngtcp2_rtb_clear(&conn->pktns.rtb);

  conn->in_pktns.last_tx_pkt_num = (uint64_t)-1;
  conn->in_pktns.crypto_tx_offset = 0;
  ngtcp2_rtb_clear(&conn->in_pktns.rtb);

  ngtcp2_frame_chain_list_del(conn->in_pktns.frq, conn->mem);
  conn->in_pktns.frq = NULL;

  conn->crypto.tx_offset = 0;

  assert(conn->token.begin == NULL);

  p = ngtcp2_mem_malloc(conn->mem, retry.tokenlen);
  if (p == NULL) {
    return NGTCP2_ERR_NOMEM;
  }
  ngtcp2_buf_init(&conn->token, p, retry.tokenlen);

  ngtcp2_cpymem(conn->token.begin, retry.token, retry.tokenlen);
  conn->token.pos = conn->token.begin;
  conn->token.last = conn->token.pos + retry.tokenlen;

  return 0;
}

int ngtcp2_conn_detect_lost_pkt(ngtcp2_conn *conn, ngtcp2_pktns *pktns,
                                ngtcp2_rcvry_stat *rcs, uint64_t largest_ack,
                                ngtcp2_tstamp ts) {
  ngtcp2_frame_chain *frc = NULL;
  int rv;

  rv = ngtcp2_rtb_detect_lost_pkt(&pktns->rtb, &frc, rcs, largest_ack,
                                  pktns->last_tx_pkt_num, ts);
  if (rv != 0) {
    /* TODO assert this */
    assert(ngtcp2_err_is_fatal(rv));
    ngtcp2_frame_chain_list_del(frc, conn->mem);
    return rv;
  }

  rv = conn_resched_frames(conn, pktns, &frc);
  if (rv != 0) {
    ngtcp2_frame_chain_list_del(frc, conn->mem);
    return rv;
  }

  return 0;
}

static int conn_handshake_pkt_lost(ngtcp2_conn *conn, ngtcp2_pktns *pktns) {
  ngtcp2_frame_chain *frc = NULL;
  int rv;

  rv = ngtcp2_rtb_remove_all(&pktns->rtb, &frc);
  if (rv != 0) {
    assert(ngtcp2_err_is_fatal(rv));
    ngtcp2_frame_chain_list_del(frc, conn->mem);
    return rv;
  }

  rv = conn_resched_frames(conn, pktns, &frc);
  if (rv != 0) {
    ngtcp2_frame_chain_list_del(frc, conn->mem);
    return rv;
  }

  return 0;
}

/*
 * conn_recv_ack processes received ACK frame |fr|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory
 * NGTCP2_ERR_ACK_FRAME
 *     ACK frame is malformed.
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User callback failed.
 */
static int conn_recv_ack(ngtcp2_conn *conn, ngtcp2_pktns *pktns,
                         const ngtcp2_pkt_hd *hd, ngtcp2_ack *fr,
                         ngtcp2_tstamp ts) {
  int rv;
  ngtcp2_frame_chain *frc = NULL;

  rv = ngtcp2_pkt_validate_ack(fr);
  if (rv != 0) {
    return rv;
  }

  rv = ngtcp2_acktr_recv_ack(&pktns->acktr, fr, conn, ts);
  if (rv != 0) {
    return rv;
  }

  rv = ngtcp2_rtb_recv_ack(&pktns->rtb, &frc, hd, fr, conn, ts);
  if (rv != 0) {
    /* TODO assert this */
    assert(ngtcp2_err_is_fatal(rv));
    ngtcp2_frame_chain_list_del(frc, conn->mem);
    return rv;
  }

  /* TODO We don't need to do this for Initial and Handshake packet
     because they don't include STREAM frame. */
  rv = conn_resched_frames(conn, pktns, &frc);
  if (rv != 0) {
    ngtcp2_frame_chain_list_del(frc, conn->mem);
    return rv;
  }

  if (!ngtcp2_pkt_handshake_pkt(hd)) {
    conn->largest_ack = ngtcp2_max(conn->largest_ack, (int64_t)fr->largest_ack);

    rv = ngtcp2_conn_detect_lost_pkt(conn, pktns, &conn->rcs, fr->largest_ack,
                                     ts);
    if (rv != 0) {
      return rv;
    }
  }

  ngtcp2_conn_set_loss_detection_timer(conn);

  return 0;
}

/*
 * conn_assign_recved_ack_delay_unscaled assigns
 * fr->ack_delay_unscaled.
 */
static void assign_recved_ack_delay_unscaled(ngtcp2_ack *fr,
                                             uint8_t ack_delay_exponent) {
  fr->ack_delay_unscaled = fr->ack_delay * (1UL << ack_delay_exponent) *
                           (NGTCP2_DURATION_TICK / NGTCP2_MICROSECONDS);
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
    if (rv != 0) {
      if (ngtcp2_err_is_fatal(rv)) {
        return rv;
      }
      assert(rv == NGTCP2_ERR_STREAM_IN_USE);
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

static int conn_buffer_pkt(ngtcp2_conn *conn, ngtcp2_pkt_chain **ppc,
                           const uint8_t *pkt, size_t pktlen,
                           ngtcp2_tstamp ts) {
  int rv;
  ngtcp2_pkt_chain *pc;
  size_t i;
  for (i = 0; *ppc && i < NGTCP2_MAX_NUM_BUFFED_RX_PKTS;
       ppc = &(*ppc)->next, ++i)
    ;

  if (i == NGTCP2_MAX_NUM_BUFFED_RX_PKTS) {
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
  return conn_buffer_pkt(conn, &conn->buffed_rx_ppkts, pkt, pktlen, ts);
}

/*
 * conn_buffer_handshake_pkt buffers Handshake packet which comes
 * before Initial packet, in other words, before handshake rx key is
 * generated.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 */
static int conn_buffer_handshake_pkt(ngtcp2_conn *conn, const uint8_t *pkt,
                                     size_t pktlen, ngtcp2_tstamp ts) {
  return conn_buffer_pkt(conn, &conn->buffed_rx_hs_pkts, pkt, pktlen, ts);
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

/*
 * conn_decrypt_pn decryptes packet number which starts at |pkt| +
 * |pkt_num_offset|.  The entire plaintext QUIC packer header will be
 * written to the buffer pointed by |dest| whose capacity is
 * |destlen|.
 */
static ssize_t conn_decrypt_pn(ngtcp2_conn *conn, ngtcp2_pkt_hd *hd,
                               uint8_t *dest, size_t destlen,
                               const uint8_t *pkt, size_t pktlen,
                               size_t pkt_num_offset, ngtcp2_crypto_km *ckm,
                               ngtcp2_encrypt_pn enc, size_t aead_overhead) {
  ssize_t nwrite;
  size_t sample_offset;
  uint8_t *p = dest;

  assert(enc);
  assert(ckm);
  assert(aead_overhead >= NGTCP2_PN_SAMPLELEN);

  if (pkt_num_offset + 1 + aead_overhead > pktlen) {
    return NGTCP2_ERR_PROTO;
  }

  if (destlen < pkt_num_offset + 4) {
    return NGTCP2_ERR_INTERNAL;
  }

  p = ngtcp2_cpymem(p, pkt, pkt_num_offset);

  sample_offset = ngtcp2_min(pkt_num_offset + 4, pktlen - aead_overhead);

  nwrite = enc(conn, p, 4, pkt + pkt_num_offset, 4, ckm->pn, ckm->pnlen,
               pkt + sample_offset, NGTCP2_PN_SAMPLELEN, conn->user_data);
  if (nwrite != 4) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  hd->pkt_num = ngtcp2_get_pkt_num(&hd->pkt_numlen, p);

  p += hd->pkt_numlen;

  return p - dest;
}

/*
 * conn_emit_pending_crypto_data delivers pending stream data to the
 * application due to packet reordering.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User callback failed
 * NGTCP2_ERR_CRYPTO
 *     TLS backend reported error
 */
static int conn_emit_pending_crypto_data(ngtcp2_conn *conn, ngtcp2_strm *strm,
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

    rv = conn_call_recv_crypto_data(conn, offset, data, datalen);
    if (rv != 0) {
      return rv;
    }

    rv = ngtcp2_rob_pop(&strm->rob, rx_offset - datalen, datalen);
    if (rv != 0) {
      return rv;
    }
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
  if (ts - conn->first_rx_bw_ts > NGTCP2_SECONDS) {
    conn->first_rx_bw_ts = ts;
    conn->rx_bw_datalen = datalen;
    conn->rx_bw = 0.;
    return;
  }

  conn->rx_bw_datalen += datalen;

  if (ts - conn->first_rx_bw_ts >= 25 * NGTCP2_MILLISECONDS) {
    conn->rx_bw =
        (double)conn->rx_bw_datalen / (double)(ts - conn->first_rx_bw_ts);

    ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_CON, "rx_bw=%.02fBs",
                    conn->rx_bw * NGTCP2_DURATION_TICK);
  }
}

static ssize_t conn_recv_pkt(ngtcp2_conn *conn, const uint8_t *pkt,
                             size_t pktlen, ngtcp2_tstamp ts);

/*
 * pkt_num_bits returns the number of bits available when packet
 * number is encoded in |pkt_numlen| bytes.
 */
static size_t pkt_num_bits(size_t pkt_numlen) {
  switch (pkt_numlen) {
  case 1:
    return 7;
  case 2:
    return 14;
  case 4:
    return 30;
  default:
    assert(0);
  }
}

/*
 * pktns_pkt_num_is_duplicate returns nonzero if |pkt_num| is
 * duplicated packet number.
 */
static int pktns_pkt_num_is_duplicate(ngtcp2_pktns *pktns, uint64_t pkt_num) {
  return ngtcp2_gaptr_is_pushed(&pktns->pngap, pkt_num, 1);
}

/*
 * pktns_commit_recv_pkt_num marks packet number |pkt_num| as
 * received.
 */
static int pktns_commit_recv_pkt_num(ngtcp2_pktns *pktns, uint64_t pkt_num) {
  int rv;
  ngtcp2_psl_it it;
  ngtcp2_range key;

  if (pktns->max_rx_pkt_num + 1 != pkt_num) {
    ngtcp2_acktr_immediate_ack(&pktns->acktr);
  }
  if (pktns->max_rx_pkt_num < pkt_num) {
    pktns->max_rx_pkt_num = pkt_num;
  }

  rv = ngtcp2_gaptr_push(&pktns->pngap, pkt_num, 1);
  if (rv != 0) {
    return rv;
  }

  if (ngtcp2_psl_len(&pktns->pngap.gap) > 256) {
    it = ngtcp2_psl_begin(&pktns->pngap.gap);
    key = ngtcp2_psl_it_range(&it);
    return ngtcp2_psl_remove(&pktns->pngap.gap, NULL, &key);
  }

  return 0;
}

static int conn_recv_crypto(ngtcp2_conn *conn, uint64_t rx_offset_base,
                            uint64_t max_rx_offset, const ngtcp2_crypto *fr);

/*
 * conn_recv_handshake_pkt processes received packet |pkt| whose
 * length if |pktlen| during handshake period.  The buffer pointed by
 * |pkt| might contain multiple packets.  This function only processes
 * one packet.
 *
 * This function returns the number of bytes it reads if it succeeds,
 * or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 * NGTCP2_ERR_INVALID_ARGUMENT
 *     Packet is too short; or it is not a long header.
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User-defined callback function failed.
 * NGTCP2_ERR_PROTO
 *     Generic QUIC protocol error.
 * NGTCP2_ERR_ACK_FRAME
 *     ACK frame is malformed.
 * NGTCP2_ERR_RECV_VERSION_NEGOTIATION
 *     Version Negotiation packet is received.
 * NGTCP2_ERR_CRYPTO
 *     TLS stack reported error.
 * NGTCP2_ERR_DISCARD_PKT
 *     Packet was discarded because plain text header was malformed;
 *     or its payload could not be decrypted.
 *
 * In addition to the above error codes, error codes returned from
 * conn_recv_pkt are also returned.
 */
static ssize_t conn_recv_handshake_pkt(ngtcp2_conn *conn, const uint8_t *pkt,
                                       size_t pktlen, ngtcp2_tstamp ts) {
  ssize_t nread;
  ngtcp2_pkt_hd hd;
  ngtcp2_max_frame mfr;
  ngtcp2_frame *fr = &mfr.fr;
  int rv;
  int require_ack = 0;
  size_t hdpktlen;
  const uint8_t *payload;
  size_t payloadlen;
  ssize_t nwrite;
  uint8_t plain_hdpkt[1500];
  ngtcp2_crypto_km *ckm;
  ngtcp2_encrypt_pn encrypt_pn;
  ngtcp2_decrypt decrypt;
  size_t aead_overhead;
  ngtcp2_pktns *pktns;
  ngtcp2_strm *crypto = &conn->crypto;
  uint64_t max_crypto_rx_offset;

  if (pktlen == 0) {
    return 0;
  }

  if (!(pkt[0] & NGTCP2_HEADER_FORM_BIT)) {
    if (conn->state == NGTCP2_CS_SERVER_INITIAL) {
      /* Ignore Short packet unless server's first Handshake packet
         has been transmitted. */
      return (ssize_t)pktlen;
    }

    if (conn->pktns.rx_ckm) {
      nread = conn_recv_pkt(conn, pkt, pktlen, ts);
      if (nread < 0) {
        return nread;
      }

      return (ssize_t)pktlen;
    }

    ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_CON,
                    "buffering Short packet len=%zu", pktlen);

    rv = conn_buffer_protected_pkt(conn, pkt, pktlen, ts);
    if (rv != 0) {
      assert(ngtcp2_err_is_fatal(rv));
      return rv;
    }
    return (ssize_t)pktlen;
  }

  nread = ngtcp2_pkt_decode_hd_long(&hd, pkt, pktlen);
  if (nread < 0) {
    return NGTCP2_ERR_DISCARD_PKT;
  }

  switch (hd.type) {
  case NGTCP2_PKT_VERSION_NEGOTIATION:
    hdpktlen = (size_t)nread;

    ngtcp2_log_rx_pkt_hd(&conn->log, &hd);

    if (conn->server) {
      return NGTCP2_ERR_DISCARD_PKT;
    }

    /* Receiving Version Negotiation packet after getting Handshake
       packet from server is invalid. */
    if (conn->flags & NGTCP2_CONN_FLAG_CONN_ID_NEGOTIATED) {
      return NGTCP2_ERR_DISCARD_PKT;
    }
    if (!ngtcp2_cid_eq(&conn->scid, &hd.dcid) ||
        !ngtcp2_cid_eq(&conn->dcid, &hd.scid)) {
      /* Just discard invalid Version Negotiation packet */
      return NGTCP2_ERR_DISCARD_PKT;
    }
    rv = conn_on_version_negotiation(conn, &hd, pkt + hdpktlen,
                                     pktlen - hdpktlen);
    if (rv != 0) {
      if (ngtcp2_err_is_fatal(rv)) {
        return rv;
      }
      return NGTCP2_ERR_DISCARD_PKT;
    }
    return NGTCP2_ERR_RECV_VERSION_NEGOTIATION;
  case NGTCP2_PKT_RETRY:
    hdpktlen = (size_t)nread;

    ngtcp2_log_rx_pkt_hd(&conn->log, &hd);

    if (conn->server) {
      return NGTCP2_ERR_DISCARD_PKT;
    }

    /* Receiving Retry packet after getting Initial packet from server
       is invalid. */
    if (conn->flags & NGTCP2_CONN_FLAG_CONN_ID_NEGOTIATED) {
      return NGTCP2_ERR_DISCARD_PKT;
    }

    rv = conn_on_retry(conn, &hd, pkt + hdpktlen, pktlen - hdpktlen);
    if (rv != 0) {
      if (ngtcp2_err_is_fatal(rv)) {
        return rv;
      }
      return NGTCP2_ERR_DISCARD_PKT;
    }
    return (ssize_t)pktlen;
  }

  if (pktlen < (size_t)nread + hd.len) {
    return NGTCP2_ERR_DISCARD_PKT;
  }

  pktlen = (size_t)nread + hd.len;

  if (conn->version != hd.version) {
    return NGTCP2_ERR_DISCARD_PKT;
  }

  /* Quoted from spec: if subsequent packets of those types include a
     different Source Connection ID, they MUST be discarded. */
  if ((conn->flags & NGTCP2_CONN_FLAG_CONN_ID_NEGOTIATED) &&
      !ngtcp2_cid_eq(&conn->dcid, &hd.scid)) {
    ngtcp2_log_rx_pkt_hd(&conn->log, &hd);
    ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_PKT,
                    "packet was ignored because of mismatched SCID");
    return NGTCP2_ERR_DISCARD_PKT;
  }

  switch (hd.type) {
  case NGTCP2_PKT_0RTT_PROTECTED:
    if (!conn->server) {
      return NGTCP2_ERR_DISCARD_PKT;
    }
    if (conn->flags & NGTCP2_CONN_FLAG_CONN_ID_NEGOTIATED) {
      if (conn->early_ckm) {
        ssize_t nread2;
        /* TODO Avoid to parse header twice. */
        nread2 = conn_recv_pkt(conn, pkt, pktlen, ts);
        if (nread2 < 0) {
          return nread2;
        }
      }

      /* Discard 0-RTT packet if we don't have a key to decrypt it. */
      return (ssize_t)pktlen;
    }

    /* Buffer re-ordered 0-RTT Protected packet. */
    ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_CON,
                    "buffering 0-RTT Protected packet len=%zu", pktlen);

    rv = conn_buffer_protected_pkt(conn, pkt, pktlen, ts);
    if (rv != 0) {
      assert(ngtcp2_err_is_fatal(rv));
      return rv;
    }
    return (ssize_t)pktlen;
  case NGTCP2_PKT_INITIAL:
    if (conn->server) {
      if ((conn->flags & NGTCP2_CONN_FLAG_CONN_ID_NEGOTIATED) == 0) {
        rv = conn_call_recv_client_initial(conn, &hd.dcid);
        if (rv != 0) {
          return rv;
        }
      } else if (!ngtcp2_cid_eq(&conn->scid, &hd.dcid) &&
                 !ngtcp2_cid_eq(&conn->rcid, &hd.dcid)) {
        ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_PKT,
                        "packet was ignored because of mismatched DCID");
        return NGTCP2_ERR_DISCARD_PKT;
      }
    } else {
      if (!ngtcp2_cid_eq(&conn->scid, &hd.dcid)) {
        ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_PKT,
                        "packet was ignored because of mismatched DCID");
        return NGTCP2_ERR_DISCARD_PKT;
      }
      if (hd.tokenlen != 0) {
        ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_PKT,
                        "packet was ignored because token is not empty");
        return NGTCP2_ERR_DISCARD_PKT;
      }
    }

    pktns = &conn->in_pktns;
    encrypt_pn = conn->callbacks.in_encrypt_pn;
    decrypt = conn->callbacks.in_decrypt;
    aead_overhead = NGTCP2_INITIAL_AEAD_OVERHEAD;
    max_crypto_rx_offset = conn->hs_pktns.crypto_rx_offset_base;

    break;
  case NGTCP2_PKT_HANDSHAKE:
    if (!ngtcp2_cid_eq(&conn->scid, &hd.dcid)) {
      ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_PKT,
                      "packet was ignored because of mismatched DCID");
      return NGTCP2_ERR_DISCARD_PKT;
    }

    if (!conn->hs_pktns.rx_ckm) {
      ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_CON,
                      "buffering Handshake packet len=%zu", pktlen);

      rv = conn_buffer_handshake_pkt(conn, pkt, pktlen, ts);
      if (rv != 0) {
        assert(ngtcp2_err_is_fatal(rv));
        return rv;
      }
      return (ssize_t)pktlen;
    }

    pktns = &conn->hs_pktns;
    encrypt_pn = conn->callbacks.encrypt_pn;
    decrypt = conn->callbacks.decrypt;
    aead_overhead = conn->aead_overhead;
    max_crypto_rx_offset = conn->pktns.crypto_rx_offset_base;

    break;
  default:
    /* unknown packet type */
    ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_PKT,
                    "packet was ignored because of unknown packet type");
    return (ssize_t)pktlen;
  }

  ckm = pktns->rx_ckm;

  assert(ckm);
  assert(encrypt_pn);
  assert(decrypt);

  nwrite =
      conn_decrypt_pn(conn, &hd, plain_hdpkt, sizeof(plain_hdpkt), pkt, pktlen,
                      (size_t)nread, ckm, encrypt_pn, aead_overhead);
  if (nwrite < 0) {
    if (ngtcp2_err_is_fatal((int)nwrite)) {
      return nwrite;
    }
    ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_PKT,
                    "could not decrypt packet number");
    return NGTCP2_ERR_DISCARD_PKT;
  }

  hdpktlen = (size_t)nwrite;
  payload = pkt + hdpktlen;
  payloadlen = hd.len - hd.pkt_numlen;

  hd.pkt_num = ngtcp2_pkt_adjust_pkt_num(pktns->max_rx_pkt_num, hd.pkt_num,
                                         pkt_num_bits(hd.pkt_numlen));

  ngtcp2_log_rx_pkt_hd(&conn->log, &hd);

  if (pktns_pkt_num_is_duplicate(pktns, hd.pkt_num)) {
    ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_PKT,
                    "packet was discarded because of duplicated packet number");
    return NGTCP2_ERR_DISCARD_PKT;
  }

  rv = conn_ensure_decrypt_buffer(conn, payloadlen);
  if (rv != 0) {
    return rv;
  }

  nwrite = conn_decrypt_pkt(conn, conn->decrypt_buf.base, payloadlen, payload,
                            payloadlen, plain_hdpkt, hdpktlen, hd.pkt_num, ckm,
                            decrypt);
  if (nwrite < 0) {
    if (ngtcp2_err_is_fatal((int)nwrite)) {
      return nwrite;
    }
    ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_PKT,
                    "could not decrypt packet payload");
    return NGTCP2_ERR_DISCARD_PKT;
  }

  payload = conn->decrypt_buf.base;
  payloadlen = (size_t)nwrite;

  if (payloadlen == 0) {
    /* QUIC packet must contain at least one frame */
    return NGTCP2_ERR_DISCARD_PKT;
  }

  if (hd.type == NGTCP2_PKT_INITIAL &&
      !(conn->flags & NGTCP2_CONN_FLAG_CONN_ID_NEGOTIATED)) {
    conn->flags |= NGTCP2_CONN_FLAG_CONN_ID_NEGOTIATED;
    if (conn->server) {
      conn->rcid = hd.dcid;
    } else {
      conn->dcid = hd.scid;
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
      assign_recved_ack_delay_unscaled(&fr->ack,
                                       NGTCP2_DEFAULT_ACK_DELAY_EXPONENT);
    }

    ngtcp2_log_rx_fr(&conn->log, &hd, fr);

    switch (fr->type) {
    case NGTCP2_FRAME_ACK:
      rv = conn_recv_ack(conn, pktns, &hd, &fr->ack, ts);
      if (rv != 0) {
        return rv;
      }
      break;
    case NGTCP2_FRAME_PADDING:
      break;
    case NGTCP2_FRAME_CRYPTO:
      rv = conn_recv_crypto(conn, pktns->crypto_rx_offset_base,
                            max_crypto_rx_offset, &fr->crypto);
      if (rv != 0) {
        return rv;
      }
      require_ack = 1;
      break;
    case NGTCP2_FRAME_CONNECTION_CLOSE:
      conn_recv_connection_close(conn);
      break;
    case NGTCP2_FRAME_APPLICATION_CLOSE:
      if (fr->type != NGTCP2_PKT_HANDSHAKE) {
        return NGTCP2_ERR_PROTO;
      }
      conn_recv_connection_close(conn);
      break;
    default:
      return NGTCP2_ERR_PROTO;
    }
  }

  if (conn->server) {
    switch (hd.type) {
    case NGTCP2_PKT_INITIAL:
      if (ngtcp2_rob_first_gap_offset(&crypto->rob) == 0) {
        return NGTCP2_ERR_PROTO;
      }
      break;
    case NGTCP2_PKT_HANDSHAKE:
      if (conn->server && hd.type == NGTCP2_PKT_HANDSHAKE) {
        /* Successful processing of Handshake packet from client verifies
           source address. */
        conn->flags |= NGTCP2_CONN_FLAG_SADDR_VERIFIED;
      }
      break;
    }
  }

  rv = pktns_commit_recv_pkt_num(pktns, hd.pkt_num);
  if (rv != 0) {
    return rv;
  }

  if (require_ack && ++pktns->acktr.rx_npkt >= NGTCP2_NUM_IMMEDIATE_ACK_PKT) {
    ngtcp2_acktr_immediate_ack(&pktns->acktr);
  }

  rv = ngtcp2_conn_sched_ack(conn, &pktns->acktr, hd.pkt_num, require_ack, ts);
  if (rv != 0) {
    return rv;
  }

  return conn->state == NGTCP2_CS_DRAINING ? NGTCP2_ERR_DRAINING
                                           : (ssize_t)pktlen;
}

/*
 * conn_recv_handshake_cpkt processes compound packet during
 * handshake.  The buffer pointed by |pkt| might contain multiple
 * packets.  The Short packet must be the last one because it does not
 * have payload length field.
 */
static int conn_recv_handshake_cpkt(ngtcp2_conn *conn, const uint8_t *pkt,
                                    size_t pktlen, ngtcp2_tstamp ts) {
  ssize_t nread;
  size_t origlen = pktlen;

  while (pktlen) {
    nread = conn_recv_handshake_pkt(conn, pkt, pktlen, ts);
    if (nread < 0) {
      if (ngtcp2_err_is_fatal((int)nread)) {
        return (int)nread;
      }
      if (nread == NGTCP2_ERR_DISCARD_PKT) {
        return 0;
      }
      if (nread != NGTCP2_ERR_CRYPTO && (pkt[0] & NGTCP2_PKT_FLAG_LONG_FORM) &&
          (pkt[0] & NGTCP2_LONG_TYPE_MASK) == NGTCP2_PKT_INITIAL) {
        return 0;
      }
      return (int)nread;
    }

    assert(pktlen >= (size_t)nread);
    pkt += nread;
    pktlen -= (size_t)nread;

    ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_PKT,
                    "read packet %zd left %zu", nread, pktlen);
  }

  conn->hs_recved += origlen;

  return 0;
}

int ngtcp2_conn_init_stream(ngtcp2_conn *conn, ngtcp2_strm *strm,
                            uint64_t stream_id, void *stream_user_data) {
  int rv;
  uint64_t max_rx_offset;
  uint64_t max_tx_offset;
  int local_stream = conn_local_stream(conn, stream_id);

  if (bidi_stream(stream_id)) {
    if (local_stream) {
      max_rx_offset = conn->local_settings.max_stream_data_bidi_local;
      max_tx_offset = conn->remote_settings.max_stream_data_bidi_remote;
    } else {
      max_rx_offset = conn->local_settings.max_stream_data_bidi_remote;
      max_tx_offset = conn->remote_settings.max_stream_data_bidi_local;
    }
  } else if (local_stream) {
    max_rx_offset = 0;
    max_tx_offset = conn->remote_settings.max_stream_data_uni;
  } else {
    max_rx_offset = conn->local_settings.max_stream_data_uni;
    max_tx_offset = 0;
  }

  rv = ngtcp2_strm_init(strm, stream_id, NGTCP2_STRM_FLAG_NONE, max_rx_offset,
                        max_tx_offset, stream_user_data, conn->mem);
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

  if (!conn_local_stream(conn, stream_id)) {
    rv = conn_call_stream_open(conn, strm);
    if (rv != 0) {
      return rv;
    }
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

    rv = ngtcp2_rob_pop(&strm->rob, rx_offset - datalen, datalen);
    if (rv != 0) {
      return rv;
    }
  }
}

/*
 * conn_recv_crypto is called when CRYPTO frame |fr| is received.
 * |rx_offset_base| is the offset in the entire TLS handshake stream.
 * fr->offset specifies the offset in each encryption level.
 * |max_rx_offset| is, if it is nonzero, the maximum offset in the
 * entire TLS handshake stream that |fr| can carry.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * TBD
 */
static int conn_recv_crypto(ngtcp2_conn *conn, uint64_t rx_offset_base,
                            uint64_t max_rx_offset, const ngtcp2_crypto *fr) {
  ngtcp2_strm *crypto = &conn->crypto;
  uint64_t fr_end_offset;
  uint64_t rx_offset;
  int rv;

  if (fr->datacnt == 0) {
    return 0;
  }

  fr_end_offset = rx_offset_base + fr->offset + fr->data[0].len;

  if (max_rx_offset && max_rx_offset < fr_end_offset) {
    return NGTCP2_ERR_PROTO;
  }

  if (crypto->max_rx_offset && crypto->max_rx_offset < fr_end_offset) {
    return NGTCP2_ERR_INTERNAL;
  }

  rx_offset = ngtcp2_strm_rx_offset(crypto);

  if (fr_end_offset <= rx_offset) {
    return 0;
  }

  crypto->last_rx_offset = ngtcp2_max(crypto->last_rx_offset, fr_end_offset);

  /* TODO Before dispatching incoming data to TLS stack, make sure
     that previous data in previous encryption level has been
     completely sent to TLS stack.  Usually, if data is left, it is an
     error because key is generated after consuming all data in the
     previous encryption level. */
  if (rx_offset_base + fr->offset <= rx_offset) {
    size_t ncut = rx_offset - fr->offset - rx_offset_base;
    const uint8_t *data = fr->data[0].base + ncut;
    size_t datalen = fr->data[0].len - ncut;
    uint64_t offset = rx_offset;

    rx_offset += datalen;
    rv = ngtcp2_rob_remove_prefix(&crypto->rob, rx_offset);
    if (rv != 0) {
      return rv;
    }

    rv = conn_call_recv_crypto_data(conn, offset, data, datalen);
    if (rv != 0) {
      return rv;
    }

    rv = conn_emit_pending_crypto_data(conn, crypto, rx_offset);
    if (rv != 0) {
      return rv;
    }
  } else {
    rv = ngtcp2_strm_recv_reordering(crypto, fr->data[0].base, fr->data[0].len,
                                     rx_offset_base + fr->offset);
    if (rv != 0) {
      return rv;
    }
  }

  return 0;
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
  size_t datalen = ngtcp2_vec_len(fr->data, fr->datacnt);

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

  if (NGTCP2_MAX_VARINT - datalen < fr->offset) {
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
    if (rv != 0) {
      if (ngtcp2_err_is_fatal(rv)) {
        return rv;
      }
      assert(rv == NGTCP2_ERR_STREAM_IN_USE);
      /* TODO The stream has been closed.  This should be responded
         with RST_STREAM, or simply ignored. */
      return 0;
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
    if (!bidi) {
      ngtcp2_strm_shutdown(strm, NGTCP2_STRM_FLAG_SHUT_WR);
    }
  }

  fr_end_offset = fr->offset + datalen;

  if (strm->max_rx_offset < fr_end_offset) {
    return NGTCP2_ERR_FLOW_CONTROL;
  }

  if (strm->last_rx_offset < fr_end_offset) {
    size_t len = fr_end_offset - strm->last_rx_offset;

    if (conn_max_data_violated(conn, len)) {
      return NGTCP2_ERR_FLOW_CONTROL;
    }

    conn->rx_offset += len;
  }

  rx_offset = ngtcp2_strm_rx_offset(strm);

  if (fr->fin) {
    if (strm->flags & NGTCP2_STRM_FLAG_SHUT_RD) {
      if (strm->last_rx_offset != fr_end_offset) {
        return NGTCP2_ERR_FINAL_OFFSET;
      }

      if (strm->flags &
          (NGTCP2_STRM_FLAG_STOP_SENDING | NGTCP2_STRM_FLAG_RECV_RST)) {
        return 0;
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

    if (strm->flags &
        (NGTCP2_STRM_FLAG_STOP_SENDING | NGTCP2_STRM_FLAG_RECV_RST)) {
      return 0;
    }
  }

  if (fr->offset <= rx_offset) {
    size_t ncut = rx_offset - fr->offset;
    uint64_t offset = rx_offset;
    const uint8_t *data;
    int fin;

    if (fr->datacnt) {
      data = fr->data[0].base + ncut;
      datalen -= ncut;

      rx_offset += datalen;
      rv = ngtcp2_rob_remove_prefix(&strm->rob, rx_offset);
      if (rv != 0) {
        return rv;
      }
    } else {
      data = NULL;
      datalen = 0;
    }

    fin = (strm->flags & NGTCP2_STRM_FLAG_SHUT_RD) &&
          rx_offset == strm->last_rx_offset;

    if (fin || datalen) {
      rv = conn_call_recv_stream_data(conn, strm, fin, offset, data, datalen);
      if (rv != 0) {
        return rv;
      }

      rv = conn_emit_pending_stream_data(conn, strm, rx_offset);
      if (rv != 0) {
        return rv;
      }
    }
  } else if (fr->datacnt) {
    rv = ngtcp2_strm_recv_reordering(strm, fr->data[0].base, fr->data[0].len,
                                     fr->offset);
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
  ngtcp2_pktns *pktns = &conn->pktns;

  rv = ngtcp2_frame_chain_new(&frc, conn->mem);
  if (rv != 0) {
    return rv;
  }

  frc->fr.type = NGTCP2_FRAME_RST_STREAM;
  frc->fr.rst_stream.stream_id = strm->stream_id;
  frc->fr.rst_stream.app_error_code = app_error_code;
  frc->fr.rst_stream.final_offset = strm->tx_offset;

  /* TODO This prepends RST_STREAM to pktns->frq. */
  frc->next = pktns->frq;
  pktns->frq = frc;

  return 0;
}

static int conn_stop_sending(ngtcp2_conn *conn, ngtcp2_strm *strm,
                             uint16_t app_error_code) {
  int rv;
  ngtcp2_frame_chain *frc;
  ngtcp2_pktns *pktns = &conn->pktns;

  rv = ngtcp2_frame_chain_new(&frc, conn->mem);
  if (rv != 0) {
    return rv;
  }

  frc->fr.type = NGTCP2_FRAME_STOP_SENDING;
  frc->fr.stop_sending.stream_id = strm->stream_id;
  frc->fr.stop_sending.app_error_code = app_error_code;

  /* TODO This prepends STOP_SENDING to pktns->frq. */
  frc->next = pktns->frq;
  pktns->frq = frc;

  return 0;
}

/*
 * handle_remote_stream_id_extension extends
 * |*punsent_max_remote_stream_id| if a condition allows it.
 */
static void
handle_remote_stream_id_extension(uint64_t *punsent_max_remote_stream_id) {
  if (*punsent_max_remote_stream_id <= NGTCP2_MAX_VARINT - 4) {
    *punsent_max_remote_stream_id += 4;
  }
}

static int conn_recv_rst_stream(ngtcp2_conn *conn,
                                const ngtcp2_rst_stream *fr) {
  ngtcp2_strm *strm;
  int local_stream = conn_local_stream(conn, fr->stream_id);
  int bidi = bidi_stream(fr->stream_id);
  uint64_t datalen;
  ngtcp2_idtr *idtr;
  int rv;

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
    if (local_stream) {
      return 0;
    }

    if (conn_initial_stream_rx_offset(conn, fr->stream_id) < fr->final_offset ||
        conn_max_data_violated(conn, fr->final_offset)) {
      return NGTCP2_ERR_FLOW_CONTROL;
    }
    rv = ngtcp2_idtr_open(idtr, fr->stream_id);
    if (rv != 0) {
      if (ngtcp2_err_is_fatal(rv)) {
        return rv;
      }
      assert(rv == NGTCP2_ERR_STREAM_IN_USE);
      return 0;
    }

    /* Stream is reset before we create ngtcp2_strm object. */
    conn->rx_offset += fr->final_offset;

    /* There will be no activity in this stream because we got
       RST_STREAM and don't write stream data any further.  This
       effectively allows another new stream for peer. */
    if (bidi) {
      handle_remote_stream_id_extension(
          &conn->unsent_max_remote_stream_id_bidi);
    } else {
      handle_remote_stream_id_extension(&conn->unsent_max_remote_stream_id_uni);
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

  strm->last_rx_offset = fr->final_offset;
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
    if (local_stream) {
      return 0;
    }
    rv = ngtcp2_idtr_open(idtr, fr->stream_id);
    if (rv != 0) {
      if (ngtcp2_err_is_fatal(rv)) {
        return rv;
      }
      assert(rv == NGTCP2_ERR_STREAM_IN_USE);
      return 0;
    }

    /* Frame is received reset before we create ngtcp2_strm
       object. */
    strm = ngtcp2_mem_malloc(conn->mem, sizeof(ngtcp2_strm));
    if (strm == NULL) {
      return NGTCP2_ERR_NOMEM;
    }
    rv = ngtcp2_conn_init_stream(conn, strm, fr->stream_id, NULL);
    if (rv != 0) {
      return rv;
    }
  }

  rv = conn_rst_stream(conn, strm, NGTCP2_STOPPING);
  if (rv != 0) {
    return rv;
  }

  strm->flags |= NGTCP2_STRM_FLAG_SHUT_WR | NGTCP2_STRM_FLAG_SENT_RST;

  ngtcp2_strm_streamfrq_clear(strm);

  return ngtcp2_conn_close_stream_if_shut_rdwr(conn, strm, fr->app_error_code);
}

/*
 * conn_on_stateless_reset decodes Stateless Reset from the buffer
 * pointed by |payload| whose length is |payloadlen|.  |payload|
 * should start after first byte of packet.
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

  assert(!conn->server);

  rv = ngtcp2_pkt_decode_stateless_reset(&sr, payload, payloadlen);
  if (rv != 0) {
    return rv;
  }

  if (!conn->remote_settings.stateless_reset_token_present) {
    return NGTCP2_ERR_PROTO;
  }

  token = conn->remote_settings.stateless_reset_token;

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
 * Initial, or Handshake.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_PROTO
 *     Packet type is unexpected; or same packet number has already
 *     been added.
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User callback failed.
 * NGTCP2_ERR_FRAME_ENCODING
 *     Frame is badly formatted; or frame type is unknown.
 * NGTCP2_ERR_NOMEM
 *     Out of memory
 */
static int conn_recv_delayed_handshake_pkt(ngtcp2_conn *conn,
                                           const ngtcp2_pkt_hd *hd,
                                           const uint8_t *payload,
                                           size_t payloadlen,
                                           ngtcp2_tstamp ts) {
  ssize_t nread;
  ngtcp2_max_frame mfr;
  ngtcp2_frame *fr = &mfr.fr;
  int rv;
  int require_ack = 0;
  ngtcp2_pktns *pktns;

  switch (hd->type) {
  case NGTCP2_PKT_INITIAL:
    pktns = &conn->in_pktns;
    break;
  case NGTCP2_PKT_HANDSHAKE:
    pktns = &conn->hs_pktns;
    break;
  default:
    assert(0);
  }

  if (payloadlen == 0) {
    /* QUIC packet must contain at least one frame */
    return NGTCP2_ERR_DISCARD_PKT;
  }

  for (; payloadlen;) {
    nread = ngtcp2_pkt_decode_frame(fr, payload, payloadlen);
    if (nread < 0) {
      return (int)nread;
    }

    payload += nread;
    payloadlen -= (size_t)nread;

    if (fr->type == NGTCP2_FRAME_ACK) {
      assign_recved_ack_delay_unscaled(&fr->ack,
                                       NGTCP2_DEFAULT_ACK_DELAY_EXPONENT);
    }

    ngtcp2_log_rx_fr(&conn->log, hd, fr);

    switch (fr->type) {
    case NGTCP2_FRAME_ACK:
      rv = conn_recv_ack(conn, pktns, hd, &fr->ack, ts);
      if (rv != 0) {
        return rv;
      }
      break;
    case NGTCP2_FRAME_PADDING:
      break;
    case NGTCP2_FRAME_CONNECTION_CLOSE:
      if (hd->type != NGTCP2_PKT_HANDSHAKE) {
        break;
      }
      conn_recv_connection_close(conn);
      break;
    case NGTCP2_FRAME_APPLICATION_CLOSE:
      if (hd->type != NGTCP2_PKT_HANDSHAKE) {
        return NGTCP2_ERR_PROTO;
      }
      conn_recv_connection_close(conn);
      break;
    case NGTCP2_FRAME_CRYPTO:
      require_ack = 1;
      break;
    default:
      return NGTCP2_ERR_PROTO;
    }
  }

  rv = pktns_commit_recv_pkt_num(pktns, hd->pkt_num);
  if (rv != 0) {
    return rv;
  }

  if (require_ack && ++pktns->acktr.rx_npkt >= NGTCP2_NUM_IMMEDIATE_ACK_PKT) {
    ngtcp2_acktr_immediate_ack(&pktns->acktr);
  }

  return ngtcp2_conn_sched_ack(conn, &pktns->acktr, hd->pkt_num, require_ack,
                               ts);
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

static ssize_t conn_recv_pkt(ngtcp2_conn *conn, const uint8_t *pkt,
                             size_t pktlen, ngtcp2_tstamp ts) {
  ngtcp2_pkt_hd hd;
  int rv = 0;
  size_t hdpktlen;
  const uint8_t *payload;
  size_t payloadlen;
  ssize_t nread, nwrite;
  ngtcp2_max_frame mfr;
  ngtcp2_frame *fr = &mfr.fr;
  int require_ack = 0;
  ngtcp2_crypto_km *ckm;
  uint8_t plain_hdpkt[1500];
  ngtcp2_encrypt_pn encrypt_pn;
  ngtcp2_decrypt decrypt;
  size_t aead_overhead;
  ngtcp2_pktns *pktns;
  uint64_t max_crypto_rx_offset = 0;
  /* maybeSR becomes nonzero if an incoming packet has mismatched DCID
     and may be Stateless Reset packet. */
  int maybeSR = 0;

  if (pkt[0] & NGTCP2_HEADER_FORM_BIT) {
    nread = ngtcp2_pkt_decode_hd_long(&hd, pkt, pktlen);
    if (nread < 0) {
      ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_PKT,
                      "could not decode long header");
      return NGTCP2_ERR_DISCARD_PKT;
    }

    if (pktlen < (size_t)nread + hd.len) {
      return NGTCP2_ERR_DISCARD_PKT;
    }

    pktlen = (size_t)nread + hd.len;

    if (conn->version != hd.version) {
      return NGTCP2_ERR_DISCARD_PKT;
    }

    /* Quoted from spec: if subsequent packets of those types include
       a different Source Connection ID, they MUST be discarded. */
    if (!ngtcp2_cid_eq(&conn->dcid, &hd.scid)) {
      ngtcp2_log_rx_pkt_hd(&conn->log, &hd);
      ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_PKT,
                      "packet was ignored because of mismatched SCID");
      return NGTCP2_ERR_DISCARD_PKT;
    }

    switch (hd.type) {
    case NGTCP2_PKT_INITIAL:
      if (!ngtcp2_cid_eq(&conn->scid, &hd.dcid) &&
          (!conn->server || !ngtcp2_cid_eq(&conn->rcid, &hd.dcid))) {
        ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_PKT,
                        "packet was ignored because of mismatched DCID");
        return NGTCP2_ERR_DISCARD_PKT;
      }

      pktns = &conn->in_pktns;
      ckm = pktns->rx_ckm;
      encrypt_pn = conn->callbacks.in_encrypt_pn;
      decrypt = conn->callbacks.in_decrypt;
      aead_overhead = NGTCP2_INITIAL_AEAD_OVERHEAD;
      max_crypto_rx_offset = conn->hs_pktns.crypto_rx_offset_base;
      break;
    case NGTCP2_PKT_HANDSHAKE:
      if (!ngtcp2_cid_eq(&conn->scid, &hd.dcid)) {
        ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_PKT,
                        "packet was ignored because of mismatched DCID");
        return NGTCP2_ERR_DISCARD_PKT;
      }

      pktns = &conn->hs_pktns;
      ckm = pktns->rx_ckm;
      encrypt_pn = conn->callbacks.encrypt_pn;
      decrypt = conn->callbacks.decrypt;
      aead_overhead = conn->aead_overhead;
      max_crypto_rx_offset = conn->pktns.crypto_rx_offset_base;
      break;
    case NGTCP2_PKT_0RTT_PROTECTED:
      if (!conn->server) {
        return NGTCP2_ERR_DISCARD_PKT;
      }
      if (!ngtcp2_cid_eq(&conn->rcid, &hd.dcid) &&
          !ngtcp2_cid_eq(&conn->scid, &hd.dcid)) {
        ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_PKT,
                        "packet was ignored because of mismatched DCID");
        return NGTCP2_ERR_DISCARD_PKT;
      }

      pktns = &conn->pktns;
      if (!conn->early_ckm) {
        return NGTCP2_ERR_DISCARD_PKT;
      }
      ckm = conn->early_ckm;
      encrypt_pn = conn->callbacks.encrypt_pn;
      decrypt = conn->callbacks.decrypt;
      aead_overhead = conn->aead_overhead;
      break;
    default:
      ngtcp2_log_rx_pkt_hd(&conn->log, &hd);
      ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_PKT,
                      "packet type 0x%02x was ignored", hd.type);
      return (ssize_t)pktlen;
    }
  } else {
    nread = ngtcp2_pkt_decode_hd_short(&hd, pkt, pktlen, conn->scid.datalen);
    if (nread < 0) {
      ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_PKT,
                      "could not decode short header");
      return NGTCP2_ERR_DISCARD_PKT;
    }

    /* TODO If we check DCID here, we drop Stateless Reset packet. */
    if (!ngtcp2_cid_eq(&conn->scid, &hd.dcid)) {
      maybeSR = 1;
    }

    pktns = &conn->pktns;
    ckm = pktns->rx_ckm;
    encrypt_pn = conn->callbacks.encrypt_pn;
    decrypt = conn->callbacks.decrypt;
    aead_overhead = conn->aead_overhead;
  }

  nwrite =
      conn_decrypt_pn(conn, &hd, plain_hdpkt, sizeof(plain_hdpkt), pkt, pktlen,
                      (size_t)nread, ckm, encrypt_pn, aead_overhead);
  if (nwrite < 0) {
    if (ngtcp2_err_is_fatal((int)nwrite)) {
      return nwrite;
    }
    ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_PKT,
                    "could not decrypt packet number");
    return NGTCP2_ERR_DISCARD_PKT;
  }

  hdpktlen = (size_t)nwrite;
  payload = pkt + hdpktlen;
  payloadlen = pktlen - hdpktlen;

  hd.pkt_num = ngtcp2_pkt_adjust_pkt_num(pktns->max_rx_pkt_num, hd.pkt_num,
                                         pkt_num_bits(hd.pkt_numlen));

  ngtcp2_log_rx_pkt_hd(&conn->log, &hd);

  if (pktns_pkt_num_is_duplicate(pktns, hd.pkt_num)) {
    ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_PKT,
                    "packet was discarded because of duplicated packet number");
    return NGTCP2_ERR_DISCARD_PKT;
  }

  rv = conn_ensure_decrypt_buffer(conn, payloadlen);
  if (rv != 0) {
    return rv;
  }

  nwrite = conn_decrypt_pkt(conn, conn->decrypt_buf.base, payloadlen, payload,
                            payloadlen, plain_hdpkt, hdpktlen, hd.pkt_num, ckm,
                            decrypt);
  if (nwrite < 0) {
    if (ngtcp2_err_is_fatal((int)nwrite)) {
      return nwrite;
    }

    assert(NGTCP2_ERR_TLS_DECRYPT == nwrite);

    if (hd.flags & NGTCP2_PKT_FLAG_LONG_FORM) {
      ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_PKT,
                      "could not decrypt packet payload");
      return NGTCP2_ERR_DISCARD_PKT;
    }

    if (!conn->server) {
      rv = conn_on_stateless_reset(conn, &hd, pkt + 1, pktlen - 1);
      if (rv == 0) {
        return (ssize_t)pktlen;
      }
    }
    ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_PKT,
                    "could not decrypt packet payload");
    return NGTCP2_ERR_DISCARD_PKT;
  }

  if (maybeSR) {
    ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_PKT,
                    "packet was ignored because of mismatched DCID");
    return NGTCP2_ERR_DISCARD_PKT;
  }

  payload = conn->decrypt_buf.base;
  payloadlen = (size_t)nwrite;

  if (payloadlen == 0) {
    /* QUIC packet must contain at least one frame */
    return NGTCP2_ERR_DISCARD_PKT;
  }

  if (hd.flags & NGTCP2_PKT_FLAG_LONG_FORM) {
    switch (hd.type) {
    case NGTCP2_PKT_INITIAL:
    case NGTCP2_PKT_HANDSHAKE:
      /* TODO find a way when to ignore incoming handshake packet */
      rv = conn_recv_delayed_handshake_pkt(conn, &hd, payload, payloadlen, ts);
      if (rv < 0) {
        if (ngtcp2_err_is_fatal(rv)) {
          return rv;
        }
        return (ssize_t)rv;
      }
      return (ssize_t)pktlen;
    case NGTCP2_PKT_0RTT_PROTECTED:
      break;
    default:
      /* unreachable */
      assert(0);
    }
  }

  if (!(hd.flags & NGTCP2_PKT_FLAG_LONG_FORM)) {
    if (!ngtcp2_cid_eq(&conn->scid, &hd.dcid)) {
      return NGTCP2_ERR_DISCARD_PKT;
    }
    conn->flags |= NGTCP2_CONN_FLAG_RECV_PROTECTED_PKT;
  }

  for (; payloadlen;) {
    nread = ngtcp2_pkt_decode_frame(fr, payload, payloadlen);
    if (nread < 0) {
      return (int)nread;
    }

    payload += nread;
    payloadlen -= (size_t)nread;

    if (fr->type == NGTCP2_FRAME_ACK) {
      if ((hd.flags & NGTCP2_PKT_FLAG_LONG_FORM) &&
          hd.type == NGTCP2_PKT_0RTT_PROTECTED) {
        return NGTCP2_ERR_PROTO;
      }
      assign_recved_ack_delay_unscaled(
          &fr->ack, conn->remote_settings.ack_delay_exponent);
    }

    ngtcp2_log_rx_fr(&conn->log, &hd, fr);

    if (hd.type == NGTCP2_PKT_0RTT_PROTECTED) {
      switch (fr->type) {
      case NGTCP2_FRAME_PADDING:
      case NGTCP2_FRAME_STREAM:
        break;
      default:
        return NGTCP2_ERR_PROTO;
      }
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
      rv = conn_recv_ack(conn, pktns, &hd, &fr->ack, ts);
      if (rv != 0) {
        return rv;
      }
      break;
    case NGTCP2_FRAME_STREAM:
      rv = conn_recv_stream(conn, &fr->stream);
      if (rv != 0) {
        return rv;
      }
      conn_update_rx_bw(
          conn, ngtcp2_vec_len(fr->stream.data, fr->stream.datacnt), ts);
      break;
    case NGTCP2_FRAME_CRYPTO:
      rv = conn_recv_crypto(conn, pktns->crypto_rx_offset_base,
                            max_crypto_rx_offset, &fr->crypto);
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
    case NGTCP2_FRAME_PING:
      break;
    case NGTCP2_FRAME_PATH_CHALLENGE:
      conn_recv_path_challenge(conn, &fr->path_challenge, ts);
      break;
    case NGTCP2_FRAME_PATH_RESPONSE:
      conn_recv_path_response(conn, &fr->path_response);
      break;
    case NGTCP2_FRAME_BLOCKED:
    case NGTCP2_FRAME_STREAM_ID_BLOCKED:
    case NGTCP2_FRAME_NEW_CONNECTION_ID:
    case NGTCP2_FRAME_NEW_TOKEN:
    case NGTCP2_FRAME_RETIRE_CONNECTION_ID:
      /* TODO Not implemented yet */
      break;
    }
  }

  rv = pktns_commit_recv_pkt_num(pktns, hd.pkt_num);
  if (rv != 0) {
    return rv;
  }

  if (require_ack && ++pktns->acktr.rx_npkt >= NGTCP2_NUM_IMMEDIATE_ACK_PKT) {
    ngtcp2_acktr_immediate_ack(&pktns->acktr);
  }

  rv = ngtcp2_conn_sched_ack(conn, &pktns->acktr, hd.pkt_num, require_ack, ts);
  if (rv != 0) {
    return rv;
  }
  return (ssize_t)pktlen;
}

static int conn_process_buffered_protected_pkt(ngtcp2_conn *conn,
                                               ngtcp2_tstamp ts) {
  ssize_t nread;
  ngtcp2_pkt_chain *pc, *next;

  for (pc = conn->buffed_rx_ppkts; pc;) {
    next = pc->next;
    nread = conn_recv_pkt(conn, pc->pkt, pc->pktlen, ts);
    ngtcp2_pkt_chain_del(pc, conn->mem);
    pc = next;
    if (nread < 0) {
      if (nread == NGTCP2_ERR_DISCARD_PKT) {
        continue;
      }
      return (int)nread;
    }
  }

  conn->buffed_rx_ppkts = NULL;

  return 0;
}

static int conn_process_buffered_handshake_pkt(ngtcp2_conn *conn,
                                               ngtcp2_tstamp ts) {
  ssize_t nread;
  ngtcp2_pkt_chain *pc, *next;

  for (pc = conn->buffed_rx_hs_pkts; pc;) {
    next = pc->next;
    nread = conn_recv_handshake_pkt(conn, pc->pkt, pc->pktlen, ts);
    ngtcp2_pkt_chain_del(pc, conn->mem);
    pc = next;
    if (nread < 0) {
      if (nread == NGTCP2_ERR_DISCARD_PKT) {
        continue;
      }
      return (int)nread;
    }
  }

  conn->buffed_rx_hs_pkts = NULL;

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

  conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED_HANDLED;

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

/*
 * conn_recv_cpkt processes compound packet after handshake.  The
 * buffer pointed by |pkt| might contain multiple packets.  The Short
 * packet must be the last one because it does not have payload length
 * field.
 */
static int conn_recv_cpkt(ngtcp2_conn *conn, const uint8_t *pkt, size_t pktlen,
                          ngtcp2_tstamp ts) {
  ssize_t nread;

  while (pktlen) {
    nread = conn_recv_pkt(conn, pkt, pktlen, ts);
    if (nread < 0) {
      if (ngtcp2_err_is_fatal((int)nread)) {
        return (int)nread;
      }
      if (nread == NGTCP2_ERR_DISCARD_PKT) {
        return 0;
      }
      if (nread != NGTCP2_ERR_CRYPTO && (pkt[0] & NGTCP2_PKT_FLAG_LONG_FORM) &&
          (pkt[0] & NGTCP2_LONG_TYPE_MASK) == NGTCP2_PKT_INITIAL) {
        return 0;
      }
      return (int)nread;
    }

    assert(pktlen >= (size_t)nread);
    pkt += nread;
    pktlen -= (size_t)nread;

    ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_PKT,
                    "read packet %zd left %zu", nread, pktlen);
  }

  return 0;
}

int ngtcp2_conn_read_pkt(ngtcp2_conn *conn, const uint8_t *pkt, size_t pktlen,
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
    rv = conn_recv_cpkt(conn, pkt, pktlen, ts);
    if (rv != 0) {
      break;
    }
    if (conn->state == NGTCP2_CS_DRAINING) {
      return NGTCP2_ERR_DRAINING;
    }
    break;
  }

  return rv;
}

static int conn_check_pkt_num_exhausted(ngtcp2_conn *conn) {
  return conn->in_pktns.last_tx_pkt_num == NGTCP2_MAX_PKT_NUM ||
         conn->hs_pktns.last_tx_pkt_num == NGTCP2_MAX_PKT_NUM ||
         conn->pktns.last_tx_pkt_num == NGTCP2_MAX_PKT_NUM;
}

/*
 * conn_server_hs_tx_left returns the maximum number of bytes that
 * server is allowed to send during handshake.
 */
static size_t conn_server_hs_tx_left(ngtcp2_conn *conn) {
  if (conn->flags & NGTCP2_CONN_FLAG_SADDR_VERIFIED) {
    return SIZE_MAX;
  }
  /* From QUIC spec: Prior to validating the client address, servers
     MUST NOT send more than three times as many bytes as the number
     of bytes they have received. */
  return conn->hs_recved * 3 - conn->hs_sent;
}

int ngtcp2_conn_read_handshake(ngtcp2_conn *conn, const uint8_t *pkt,
                               size_t pktlen, ngtcp2_tstamp ts) {
  int rv;
  ngtcp2_pktns *hs_pktns = &conn->hs_pktns;

  conn->log.last_ts = ts;

  if (pktlen > 0) {
    ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_CON, "recv packet len=%zu",
                    pktlen);
  }

  switch (conn->state) {
  case NGTCP2_CS_CLIENT_INITIAL:
    /* TODO Better to log something when we ignore input */
    return 0;
  case NGTCP2_CS_CLIENT_WAIT_HANDSHAKE:
    rv = conn_recv_handshake_cpkt(conn, pkt, pktlen, ts);
    if (rv < 0) {
      return rv;
    }

    if (conn->state == NGTCP2_CS_CLIENT_INITIAL) {
      /* Retry packet was received */
      return 0;
    }

    if (hs_pktns->rx_ckm) {
      rv = conn_process_buffered_handshake_pkt(conn, ts);
      if (rv != 0) {
        return rv;
      }
    }

    return 0;
  case NGTCP2_CS_SERVER_INITIAL:
    rv = conn_recv_handshake_cpkt(conn, pkt, pktlen, ts);
    if (rv < 0) {
      return rv;
    }

    if (ngtcp2_rob_first_gap_offset(&conn->crypto.rob) == 0) {
      return 0;
    }

    /* Process re-ordered 0-RTT Protected packets which were
       arrived before Initial packet. */
    if (conn->early_ckm) {
      rv = conn_process_buffered_protected_pkt(conn, ts);
      if (rv != 0) {
        return rv;
      }
    } else {
      delete_buffed_pkts(conn->buffed_rx_ppkts, conn->mem);
      conn->buffed_rx_ppkts = NULL;
    }

    return 0;
  case NGTCP2_CS_SERVER_WAIT_HANDSHAKE:
    rv = conn_recv_handshake_cpkt(conn, pkt, pktlen, ts);
    if (rv < 0) {
      return rv;
    }

    if (hs_pktns->rx_ckm) {
      rv = conn_process_buffered_handshake_pkt(conn, ts);
      if (rv != 0) {
        return rv;
      }
    }

    if (!(conn->flags & NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED)) {
      return 0;
    }

    if (!(conn->flags & NGTCP2_CONN_FLAG_TRANSPORT_PARAM_RECVED)) {
      return NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM;
    }

    rv = conn_handshake_completed(conn);
    if (rv != 0) {
      return rv;
    }
    conn->state = NGTCP2_CS_POST_HANDSHAKE;

    rv = conn_process_buffered_protected_pkt(conn, ts);
    if (rv != 0) {
      return rv;
    }

    conn->hs_pktns.acktr.flags |= NGTCP2_ACKTR_FLAG_PENDING_FINISHED_ACK;

    return 0;
  case NGTCP2_CS_CLOSING:
    return NGTCP2_ERR_CLOSING;
  case NGTCP2_CS_DRAINING:
    return NGTCP2_ERR_DRAINING;
  default:
    return 0;
  }
}

static ssize_t conn_write_handshake(ngtcp2_conn *conn, uint8_t *dest,
                                    size_t destlen, size_t early_datalen,
                                    ngtcp2_tstamp ts) {
  int rv;
  ssize_t res = 0, nwrite, early_spktlen = 0;
  uint64_t cwnd;
  size_t origlen = destlen;
  size_t server_hs_tx_left;
  ngtcp2_rcvry_stat *rcs = &conn->rcs;
  size_t pending_early_datalen;

  conn->log.last_ts = ts;

  if (conn_check_pkt_num_exhausted(conn)) {
    return NGTCP2_ERR_PKT_NUM_EXHAUSTED;
  }

  cwnd = conn_cwnd_left(conn);
  destlen = ngtcp2_min(destlen, cwnd);

  switch (conn->state) {
  case NGTCP2_CS_CLIENT_INITIAL:
    pending_early_datalen = conn_retry_early_payloadlen(conn);
    if (pending_early_datalen) {
      early_datalen = pending_early_datalen;
    }

    nwrite = conn_write_client_initial(conn, dest, destlen, early_datalen, ts);
    if (nwrite <= 0) {
      return nwrite;
    }

    if (pending_early_datalen) {
      early_spktlen = conn_retransmit_retry_early(conn, dest + nwrite,
                                                  destlen - (size_t)nwrite, ts);

      if (early_spktlen < 0) {
        if (ngtcp2_err_is_fatal((int)early_spktlen)) {
          return early_spktlen;
        }
        conn->state = NGTCP2_CS_CLIENT_WAIT_HANDSHAKE;
        return nwrite;
      }
    }

    conn->state = NGTCP2_CS_CLIENT_WAIT_HANDSHAKE;

    return nwrite + early_spktlen;
  case NGTCP2_CS_CLIENT_WAIT_HANDSHAKE:
    if (!(conn->flags & NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED_HANDLED)) {
      pending_early_datalen = conn_retry_early_payloadlen(conn);
      if (pending_early_datalen) {
        early_datalen = pending_early_datalen;
      }
    }

    nwrite = conn_write_handshake_pkts(conn, dest, destlen, early_datalen, ts);
    if (nwrite < 0) {
      return nwrite;
    }

    res += nwrite;
    dest += nwrite;
    destlen -= (size_t)nwrite;

    if (!(conn->flags & NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED)) {
      nwrite = conn_retransmit_retry_early(conn, dest, destlen, ts);
      if (nwrite < 0) {
        return nwrite;
      }

      res += nwrite;

      if (res == 0) {
        /* This might send PADDING only Initial packet if client has
           nothing to send and does not have client handshake traffic
           key to prevent server from deadlocking. */
        nwrite = conn_write_handshake_ack_pkts(conn, dest, destlen, ts);
        if (nwrite < 0) {
          return nwrite;
        }
        res = nwrite;
      }
      if (res) {
        conn->flags &= (uint16_t)~NGTCP2_CONN_FLAG_FORCE_SEND_INITIAL;
      }
      return res;
    }

    if (!(conn->flags & NGTCP2_CONN_FLAG_TRANSPORT_PARAM_RECVED)) {
      return NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM;
    }

    rv = conn_handshake_completed(conn);
    if (rv != 0) {
      return (ssize_t)rv;
    }

    conn->state = NGTCP2_CS_POST_HANDSHAKE;

    conn_process_early_rtb(conn);

    rv = conn_process_buffered_protected_pkt(conn, ts);
    if (rv != 0) {
      return (ssize_t)rv;
    }

    return res;
  case NGTCP2_CS_SERVER_INITIAL:
    nwrite = conn_write_server_handshake(conn, dest, destlen, ts);
    if (nwrite < 0) {
      return nwrite;
    }

    if (nwrite) {
      conn->state = NGTCP2_CS_SERVER_WAIT_HANDSHAKE;
      conn->hs_sent += (size_t)nwrite;
    }

    return nwrite;
  case NGTCP2_CS_SERVER_WAIT_HANDSHAKE:
    if (!(conn->flags & NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED)) {
      server_hs_tx_left = conn_server_hs_tx_left(conn);
      if (server_hs_tx_left == 0) {
        if (rcs->loss_detection_timer) {
          ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_RCV,
                          "loss detection timer canceled");
          rcs->loss_detection_timer = 0;
        }
        return 0;
      }

      destlen = ngtcp2_min(destlen, server_hs_tx_left);
      nwrite = conn_write_server_handshake(conn, dest, destlen, ts);
      if (nwrite < 0) {
        return nwrite;
      }

      /* TODO Write 1RTT ACK packet if we have received 0RTT packet */

      res += nwrite;
      dest += nwrite;
      destlen -= (size_t)nwrite;

      nwrite = conn_write_handshake_ack_pkts(
          conn, dest,
          res == 0 ? ngtcp2_min(origlen, server_hs_tx_left) : destlen, ts);
      if (nwrite < 0) {
        return nwrite;
      }

      res += nwrite;
      conn->hs_sent += (size_t)res;
      return res;
    }

    nwrite = conn_write_handshake_ack_pkts(conn, dest, origlen, ts);
    if (nwrite < 0) {
      return nwrite;
    }

    res += nwrite;

    if (!(conn->flags & NGTCP2_CONN_FLAG_TRANSPORT_PARAM_RECVED)) {
      return NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM;
    }

    rv = conn_handshake_completed(conn);
    if (rv != 0) {
      return (ssize_t)rv;
    }
    conn->state = NGTCP2_CS_POST_HANDSHAKE;

    rv = conn_process_buffered_protected_pkt(conn, ts);
    if (rv != 0) {
      return (ssize_t)rv;
    }

    conn->hs_pktns.acktr.flags |= NGTCP2_ACKTR_FLAG_PENDING_FINISHED_ACK;

    return res;
  case NGTCP2_CS_CLOSING:
    return NGTCP2_ERR_CLOSING;
  case NGTCP2_CS_DRAINING:
    return NGTCP2_ERR_DRAINING;
  default:
    return 0;
  }
}

ssize_t ngtcp2_conn_write_handshake(ngtcp2_conn *conn, uint8_t *dest,
                                    size_t destlen, ngtcp2_tstamp ts) {
  return conn_write_handshake(conn, dest, destlen, 0, ts);
}

static ssize_t conn_write_stream_early(ngtcp2_conn *conn, uint8_t *dest,
                                       size_t destlen, ssize_t *pdatalen,
                                       ngtcp2_strm *strm, uint8_t fin,
                                       const ngtcp2_vec *datav, size_t datavcnt,
                                       int require_padding, ngtcp2_tstamp ts) {
  ngtcp2_crypto_ctx ctx;
  ngtcp2_ppe ppe;
  ngtcp2_rtb_entry *ent;
  ngtcp2_stream_frame_chain *frc;
  ngtcp2_frame localfr;
  ngtcp2_pkt_hd hd;
  int rv;
  size_t ndatalen, left;
  ssize_t nwrite;
  uint8_t pkt_flags;
  uint8_t pkt_type;
  ngtcp2_pktns *pktns = &conn->pktns;
  size_t datalen = ngtcp2_vec_len(datav, datavcnt);

  assert(!conn->server);
  assert(conn->early_ckm);

  pkt_flags = NGTCP2_PKT_FLAG_LONG_FORM;
  pkt_type = NGTCP2_PKT_0RTT_PROTECTED;
  ctx.ckm = conn->early_ckm;

  ngtcp2_pkt_hd_init(
      &hd, pkt_flags, pkt_type, &conn->dcid, &conn->scid,
      pktns->last_tx_pkt_num + 1,
      rtb_select_pkt_numlen(&pktns->rtb, pktns->last_tx_pkt_num + 1),
      conn->version, 0);

  ctx.aead_overhead = conn->aead_overhead;
  ctx.encrypt = conn->callbacks.encrypt;
  ctx.encrypt_pn = conn->callbacks.encrypt_pn;
  ctx.user_data = conn;

  ngtcp2_ppe_init(&ppe, dest, destlen, &ctx);

  rv = ngtcp2_ppe_encode_hd(&ppe, &hd);
  if (rv != 0) {
    assert(NGTCP2_ERR_NOBUF == rv);
    return 0;
  }

  ngtcp2_log_tx_pkt_hd(&conn->log, &hd);

  ndatalen = conn_enforce_flow_control(conn, strm, datalen);
  if (datalen > 0 && ndatalen == 0) {
    return NGTCP2_ERR_STREAM_DATA_BLOCKED;
  }

  left = ngtcp2_ppe_left(&ppe);
  ndatalen = ngtcp2_pkt_stream_max_datalen(strm->stream_id, strm->tx_offset,
                                           ndatalen, left);
  if (ndatalen == (size_t)-1) {
    return 0;
  }

  fin = fin && ndatalen == datalen;

  rv = ngtcp2_stream_frame_chain_new(&frc, conn->mem);
  if (rv != 0) {
    assert(ngtcp2_err_is_fatal(rv));
    return rv;
  }

  frc->fr.type = NGTCP2_FRAME_STREAM;
  frc->fr.flags = 0;
  frc->fr.fin = fin;
  frc->fr.stream_id = strm->stream_id;
  frc->fr.offset = strm->tx_offset;
  frc->fr.datacnt = ngtcp2_vec_copy(frc->fr.data, NGTCP2_MAX_STREAM_DATACNT,
                                    datav, datavcnt, ndatalen);

  rv = conn_ppe_write_frame(conn, &ppe, &hd, &frc->frc.fr);
  if (rv != 0) {
    assert(0);
  }

  if (require_padding && ngtcp2_ppe_left(&ppe)) {
    localfr.type = NGTCP2_FRAME_PADDING;
    localfr.padding.len = ngtcp2_ppe_padding(&ppe);

    ngtcp2_log_tx_fr(&conn->log, &hd, &localfr);
  }

  nwrite = ngtcp2_ppe_final(&ppe, NULL);
  if (nwrite < 0) {
    assert(ngtcp2_err_is_fatal((int)nwrite));
    ngtcp2_stream_frame_chain_del(frc, conn->mem);
    return nwrite;
  }

  rv = ngtcp2_rtb_entry_new(&ent, &hd, &frc->frc, ts, (size_t)nwrite,
                            NGTCP2_RTB_FLAG_NONE, conn->mem);
  if (rv != 0) {
    assert(ngtcp2_err_is_fatal(rv));
    ngtcp2_stream_frame_chain_del(frc, conn->mem);
    return rv;
  }

  rv = conn_on_pkt_sent(conn, &pktns->rtb, ent);
  if (rv != 0) {
    assert(ngtcp2_err_is_fatal(rv));
    ngtcp2_rtb_entry_del(ent, conn->mem);
    return rv;
  }

  strm->tx_offset += ndatalen;
  conn->tx_offset += ndatalen;

  ++pktns->last_tx_pkt_num;

  if (pdatalen) {
    *pdatalen = (ssize_t)ndatalen;
  }

  if (fin) {
    ngtcp2_strm_shutdown(strm, NGTCP2_STRM_FLAG_SHUT_WR);
  }

  return nwrite;
}

ssize_t ngtcp2_conn_client_write_handshake(ngtcp2_conn *conn, uint8_t *dest,
                                           size_t destlen, ssize_t *pdatalen,
                                           uint64_t stream_id, uint8_t fin,
                                           const ngtcp2_vec *datav,
                                           size_t datavcnt, ngtcp2_tstamp ts) {
  ngtcp2_strm *strm = NULL;
  int send_stream = 0;
  ssize_t spktlen, early_spktlen;
  uint64_t cwnd;
  int require_padding;
  int was_client_initial;
  size_t datalen = ngtcp2_vec_len(datav, datavcnt);
  size_t early_datalen = 0;

  if (pdatalen) {
    *pdatalen = -1;
  }

  if (conn->server) {
    return NGTCP2_ERR_INVALID_STATE;
  }

  /* conn->early_ckm might be created in the first call of
     conn_handshake().  Check it later. */
  if (stream_id != (uint64_t)-1 &&
      !(conn->flags & NGTCP2_CONN_FLAG_EARLY_DATA_REJECTED)) {
    strm = ngtcp2_conn_find_stream(conn, stream_id);
    if (strm == NULL) {
      return NGTCP2_ERR_STREAM_NOT_FOUND;
    }

    if (strm->flags & NGTCP2_STRM_FLAG_SHUT_WR) {
      return NGTCP2_ERR_STREAM_SHUT_WR;
    }

    send_stream = conn_retry_early_payloadlen(conn) == 0 &&
                  /* 0 length STREAM frame is allowed */
                  (datalen == 0 ||
                   (datalen > 0 && (strm->max_tx_offset - strm->tx_offset) &&
                    (conn->max_tx_offset - conn->tx_offset)));
    if (send_stream) {
      early_datalen =
          ngtcp2_min(datalen, strm->max_tx_offset - strm->tx_offset);
      early_datalen =
          ngtcp2_min(early_datalen, conn->max_tx_offset - conn->tx_offset) +
          NGTCP2_STREAM_OVERHEAD;
    }
  }

  was_client_initial = conn->state == NGTCP2_CS_CLIENT_INITIAL;
  spktlen = conn_write_handshake(conn, dest, destlen, early_datalen, ts);

  if (spktlen < 0) {
    return spktlen;
  }

  if (conn->pktns.tx_ckm || !conn->early_ckm || !send_stream) {
    return spktlen;
  }

  /* If spktlen > 0, we are making a compound packet.  If Initial
     packet is written, we have to pad bytes to 0-RTT Protected
     packet. */

  require_padding = spktlen && was_client_initial;

  cwnd = conn_cwnd_left(conn);

  dest += spktlen;
  destlen -= (size_t)spktlen;
  destlen = ngtcp2_min(destlen, cwnd);

  early_spktlen =
      conn_write_stream_early(conn, dest, destlen, pdatalen, strm, fin, datav,
                              datavcnt, require_padding, ts);

  if (early_spktlen < 0) {
    if (early_spktlen == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
      return spktlen;
    }
    return early_spktlen;
  }

  return spktlen + early_spktlen;
}

void ngtcp2_conn_handshake_completed(ngtcp2_conn *conn) {
  conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;
}

int ngtcp2_conn_get_handshake_completed(ngtcp2_conn *conn) {
  return (conn->flags & NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED) &&
         (conn->flags & NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED_HANDLED);
}

int ngtcp2_conn_sched_ack(ngtcp2_conn *conn, ngtcp2_acktr *acktr,
                          uint64_t pkt_num, int active_ack, ngtcp2_tstamp ts) {
  int rv;
  (void)conn;

  rv = ngtcp2_acktr_add(acktr, pkt_num, active_ack, ts);
  if (rv != 0) {
    /* NGTCP2_ERR_INVALID_ARGUMENT means duplicated packet number.
       Just ignore it for now. */
    if (rv != NGTCP2_ERR_INVALID_ARGUMENT) {
      return rv;
    }
    return 0;
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
  case NGTCP2_PROTO_VER_D15:
    break;
  default:
    return 1;
  }

  return 0;
}

void ngtcp2_conn_set_aead_overhead(ngtcp2_conn *conn, size_t aead_overhead) {
  conn->aead_overhead = aead_overhead;
}

int ngtcp2_conn_set_initial_tx_keys(ngtcp2_conn *conn, const uint8_t *key,
                                    size_t keylen, const uint8_t *iv,
                                    size_t ivlen, const uint8_t *pn,
                                    size_t pnlen) {
  ngtcp2_pktns *pktns = &conn->in_pktns;

  if (pktns->tx_ckm) {
    ngtcp2_crypto_km_del(pktns->tx_ckm, conn->mem);
    pktns->tx_ckm = NULL;
  }

  return ngtcp2_crypto_km_new(&pktns->tx_ckm, key, keylen, iv, ivlen, pn, pnlen,
                              conn->mem);
}

int ngtcp2_conn_set_initial_rx_keys(ngtcp2_conn *conn, const uint8_t *key,
                                    size_t keylen, const uint8_t *iv,
                                    size_t ivlen, const uint8_t *pn,
                                    size_t pnlen) {
  ngtcp2_pktns *pktns = &conn->in_pktns;

  if (pktns->rx_ckm) {
    ngtcp2_crypto_km_del(pktns->rx_ckm, conn->mem);
    pktns->rx_ckm = NULL;
  }

  return ngtcp2_crypto_km_new(&pktns->rx_ckm, key, keylen, iv, ivlen, pn, pnlen,
                              conn->mem);
}

int ngtcp2_conn_set_handshake_tx_keys(ngtcp2_conn *conn, const uint8_t *key,
                                      size_t keylen, const uint8_t *iv,
                                      size_t ivlen, const uint8_t *pn,
                                      size_t pnlen) {
  ngtcp2_pktns *pktns = &conn->hs_pktns;

  if (pktns->tx_ckm) {
    ngtcp2_crypto_km_del(pktns->tx_ckm, conn->mem);
    pktns->tx_ckm = NULL;
  }

  return ngtcp2_crypto_km_new(&pktns->tx_ckm, key, keylen, iv, ivlen, pn, pnlen,
                              conn->mem);
}

int ngtcp2_conn_set_handshake_rx_keys(ngtcp2_conn *conn, const uint8_t *key,
                                      size_t keylen, const uint8_t *iv,
                                      size_t ivlen, const uint8_t *pn,
                                      size_t pnlen) {
  ngtcp2_pktns *pktns = &conn->hs_pktns;

  if (pktns->rx_ckm) {
    ngtcp2_crypto_km_del(pktns->rx_ckm, conn->mem);
    pktns->rx_ckm = NULL;
  }

  conn->hs_pktns.crypto_rx_offset_base = conn->crypto.last_rx_offset;

  return ngtcp2_crypto_km_new(&pktns->rx_ckm, key, keylen, iv, ivlen, pn, pnlen,
                              conn->mem);
}

int ngtcp2_conn_set_early_keys(ngtcp2_conn *conn, const uint8_t *key,
                               size_t keylen, const uint8_t *iv, size_t ivlen,
                               const uint8_t *pn, size_t pnlen) {
  if (conn->early_ckm) {
    return NGTCP2_ERR_INVALID_STATE;
  }

  return ngtcp2_crypto_km_new(&conn->early_ckm, key, keylen, iv, ivlen, pn,
                              pnlen, conn->mem);
}

int ngtcp2_conn_update_tx_keys(ngtcp2_conn *conn, const uint8_t *key,
                               size_t keylen, const uint8_t *iv, size_t ivlen,
                               const uint8_t *pn, size_t pnlen) {
  ngtcp2_pktns *pktns = &conn->pktns;

  if (pktns->tx_ckm) {
    return NGTCP2_ERR_INVALID_STATE;
  }

  return ngtcp2_crypto_km_new(&pktns->tx_ckm, key, keylen, iv, ivlen, pn, pnlen,
                              conn->mem);
}

int ngtcp2_conn_update_rx_keys(ngtcp2_conn *conn, const uint8_t *key,
                               size_t keylen, const uint8_t *iv, size_t ivlen,
                               const uint8_t *pn, size_t pnlen) {
  ngtcp2_pktns *pktns = &conn->pktns;

  if (pktns->rx_ckm) {
    return NGTCP2_ERR_INVALID_STATE;
  }

  /* TODO This must be done once */
  if (conn->pktns.crypto_rx_offset_base == 0) {
    conn->pktns.crypto_rx_offset_base = conn->crypto.last_rx_offset;
  }

  return ngtcp2_crypto_km_new(&pktns->rx_ckm, key, keylen, iv, ivlen, pn, pnlen,
                              conn->mem);
}

ngtcp2_tstamp ngtcp2_conn_loss_detection_expiry(ngtcp2_conn *conn) {
  if (conn->rcs.loss_detection_timer) {
    return conn->rcs.loss_detection_timer;
  }
  return UINT64_MAX;
}

ngtcp2_tstamp ngtcp2_conn_ack_delay_expiry(ngtcp2_conn *conn) {
  ngtcp2_acktr *acktr = &conn->pktns.acktr;

  if (acktr->first_unacked_ts == UINT64_MAX) {
    return UINT64_MAX;
  }
  return acktr->first_unacked_ts + conn_compute_ack_delay(conn);
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
  dest->max_stream_data_bidi_local = src->initial_max_stream_data_bidi_local;
  dest->max_stream_data_bidi_remote = src->initial_max_stream_data_bidi_remote;
  dest->max_stream_data_uni = src->initial_max_stream_data_uni;
  dest->max_data = src->initial_max_data;
  dest->max_bidi_streams = src->initial_max_bidi_streams;
  dest->max_uni_streams = src->initial_max_uni_streams;
  dest->idle_timeout = src->idle_timeout;
  dest->max_packet_size = src->max_packet_size;
  dest->stateless_reset_token_present = src->stateless_reset_token_present;
  if (src->stateless_reset_token_present) {
    memcpy(dest->stateless_reset_token, src->stateless_reset_token,
           sizeof(dest->stateless_reset_token));
  } else {
    memset(dest->stateless_reset_token, 0, sizeof(dest->stateless_reset_token));
  }
  dest->ack_delay_exponent = src->ack_delay_exponent;
  dest->disable_migration = src->disable_migration;
  dest->max_ack_delay = src->max_ack_delay;
  dest->preferred_address = src->preferred_address;
}

static void transport_params_copy_from_settings(ngtcp2_transport_params *dest,
                                                const ngtcp2_settings *src) {
  dest->initial_max_stream_data_bidi_local = src->max_stream_data_bidi_local;
  dest->initial_max_stream_data_bidi_remote = src->max_stream_data_bidi_remote;
  dest->initial_max_stream_data_uni = src->max_stream_data_uni;
  dest->initial_max_data = src->max_data;
  dest->initial_max_bidi_streams = src->max_bidi_streams;
  dest->initial_max_uni_streams = src->max_uni_streams;
  dest->idle_timeout = src->idle_timeout;
  dest->max_packet_size = src->max_packet_size;
  dest->stateless_reset_token_present = src->stateless_reset_token_present;
  if (src->stateless_reset_token_present) {
    memcpy(dest->stateless_reset_token, src->stateless_reset_token,
           sizeof(dest->stateless_reset_token));
  } else {
    memset(dest->stateless_reset_token, 0, sizeof(dest->stateless_reset_token));
  }
  dest->ack_delay_exponent = src->ack_delay_exponent;
  dest->disable_migration = src->disable_migration;
  dest->max_ack_delay = src->max_ack_delay;
  dest->preferred_address = src->preferred_address;
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
      break;
    }
  }

  if (i == params->v.ee.len) {
    return NGTCP2_ERR_VERSION_NEGOTIATION;
  }

  if (conn->flags & NGTCP2_CONN_FLAG_RECV_RETRY) {
    if (!params->original_connection_id_present) {
      return NGTCP2_ERR_TRANSPORT_PARAM;
    }
    if (!ngtcp2_cid_eq(&conn->rcid, &params->original_connection_id)) {
      return NGTCP2_ERR_TRANSPORT_PARAM;
    }
  }

  return 0;
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

  if (conn->server) {
    conn->max_local_stream_id_bidi =
        ngtcp2_nth_server_bidi_id(conn->remote_settings.max_bidi_streams);
    conn->max_local_stream_id_uni =
        ngtcp2_nth_server_uni_id(conn->remote_settings.max_uni_streams);
  } else {
    conn->max_local_stream_id_bidi =
        ngtcp2_nth_client_bidi_id(conn->remote_settings.max_bidi_streams);
    conn->max_local_stream_id_uni =
        ngtcp2_nth_client_uni_id(conn->remote_settings.max_uni_streams);
  }

  conn->max_tx_offset = conn->remote_settings.max_data;

  conn->flags |= NGTCP2_CONN_FLAG_TRANSPORT_PARAM_RECVED;

  return 0;
}

int ngtcp2_conn_set_early_remote_transport_params(
    ngtcp2_conn *conn, const ngtcp2_transport_params *params) {
  if (conn->server) {
    return NGTCP2_ERR_INVALID_STATE;
  }

  settings_copy_from_transport_params(&conn->remote_settings, params);

  if (conn->server) {
    conn->max_local_stream_id_bidi =
        ngtcp2_nth_server_bidi_id(conn->remote_settings.max_bidi_streams);
    conn->max_local_stream_id_uni =
        ngtcp2_nth_server_uni_id(conn->remote_settings.max_uni_streams);
  } else {
    conn->max_local_stream_id_bidi =
        ngtcp2_nth_client_bidi_id(conn->remote_settings.max_bidi_streams);
    conn->max_local_stream_id_uni =
        ngtcp2_nth_client_uni_id(conn->remote_settings.max_uni_streams);
  }

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
  if (conn->server && (conn->flags & NGTCP2_CONN_FLAG_OCID_PRESENT)) {
    ngtcp2_cid_init(&params->original_connection_id, conn->ocid.data,
                    conn->ocid.datalen);
    params->original_connection_id_present = 1;
  } else {
    params->original_connection_id_present = 0;
  }

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
                                 size_t destlen, ssize_t *pdatalen,
                                 uint64_t stream_id, uint8_t fin,
                                 const uint8_t *data, size_t datalen,
                                 ngtcp2_tstamp ts) {
  ngtcp2_vec datav;

  datav.len = datalen;
  datav.base = (uint8_t *)data;

  return ngtcp2_conn_writev_stream(conn, dest, destlen, pdatalen, stream_id,
                                   fin, &datav, 1, ts);
}

ssize_t ngtcp2_conn_writev_stream(ngtcp2_conn *conn, uint8_t *dest,
                                  size_t destlen, ssize_t *pdatalen,
                                  uint64_t stream_id, uint8_t fin,
                                  const ngtcp2_vec *datav, size_t datavcnt,
                                  ngtcp2_tstamp ts) {
  ngtcp2_strm *strm;
  ssize_t nwrite;
  uint64_t cwnd;
  ngtcp2_pktns *pktns = &conn->pktns;
  size_t origlen = destlen;
  size_t server_hs_tx_left;
  ngtcp2_rcvry_stat *rcs = &conn->rcs;

  conn->log.last_ts = ts;

  if (pdatalen) {
    *pdatalen = -1;
  }

  switch (conn->state) {
  case NGTCP2_CS_CLOSING:
    return NGTCP2_ERR_CLOSING;
  case NGTCP2_CS_DRAINING:
    return NGTCP2_ERR_DRAINING;
  }

  if (conn_check_pkt_num_exhausted(conn)) {
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
  destlen = ngtcp2_min(destlen, cwnd);

  if (conn->server) {
    server_hs_tx_left = conn_server_hs_tx_left(conn);
    if (server_hs_tx_left == 0) {
      if (rcs->loss_detection_timer) {
        ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_RCV,
                        "loss detection timer canceled");
        rcs->loss_detection_timer = 0;
      }
      return 0;
    }
    destlen = ngtcp2_min(destlen, server_hs_tx_left);
  }

  nwrite = conn_write_handshake_pkts(conn, dest, destlen, 0, ts);
  if (nwrite) {
    return nwrite;
  }
  nwrite = conn_write_handshake_ack_pkts(conn, dest, origlen, ts);
  if (nwrite) {
    return nwrite;
  }

  if (pktns->tx_ckm) {
    if (conn->rcs.probe_pkt_left) {
      return conn_write_probe_pkt(conn, dest, origlen, pdatalen, strm, fin,
                                  datav, datavcnt, ts);
    }

    nwrite = conn_write_pkt(conn, dest, destlen, pdatalen, strm, fin, datav,
                            datavcnt, ts);
    if (nwrite < 0) {
      assert(nwrite != NGTCP2_ERR_NOBUF);
      return nwrite;
    }
    if (nwrite == 0) {
      return conn_write_protected_ack_pkt(conn, dest, origlen, ts);
    }
    return nwrite;
  }

  /* Send STREAM frame in 0-RTT packet. */
  if (conn->server || !conn->early_ckm) {
    return NGTCP2_ERR_NOKEY;
  }

  if (conn->flags & NGTCP2_CONN_FLAG_EARLY_DATA_REJECTED) {
    return NGTCP2_ERR_EARLY_DATA_REJECTED;
  }

  nwrite = conn_retransmit_retry_early(conn, dest, destlen, ts);
  if (nwrite) {
    return nwrite;
  }

  return conn_write_stream_early(conn, dest, destlen, pdatalen, strm, fin,
                                 datav, datavcnt, 0, ts);
}

ssize_t ngtcp2_conn_write_connection_close(ngtcp2_conn *conn, uint8_t *dest,
                                           size_t destlen, uint16_t error_code,
                                           ngtcp2_tstamp ts) {
  ssize_t nwrite;
  ngtcp2_frame fr;
  uint8_t pkt_type;

  conn->log.last_ts = ts;

  if (conn_check_pkt_num_exhausted(conn)) {
    return NGTCP2_ERR_PKT_NUM_EXHAUSTED;
  }

  switch (conn->state) {
  case NGTCP2_CS_CLOSING:
  case NGTCP2_CS_DRAINING:
    return NGTCP2_ERR_INVALID_STATE;
  }

  fr.type = NGTCP2_FRAME_CONNECTION_CLOSE;
  fr.connection_close.error_code = error_code;
  fr.connection_close.frame_type = 0;
  fr.connection_close.reasonlen = 0;
  fr.connection_close.reason = NULL;

  if (conn->state == NGTCP2_CS_POST_HANDSHAKE) {
    pkt_type = 0;
  } else if (conn->hs_pktns.tx_ckm) {
    pkt_type = NGTCP2_PKT_HANDSHAKE;
  } else {
    assert(conn->in_pktns.tx_ckm);
    pkt_type = NGTCP2_PKT_INITIAL;
  }

  nwrite = conn_write_single_frame_pkt(conn, dest, destlen, pkt_type, &fr, ts);

  if (nwrite > 0) {
    conn->state = NGTCP2_CS_CLOSING;
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

  if (conn_check_pkt_num_exhausted(conn)) {
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

  nwrite =
      conn_write_single_frame_pkt(conn, dest, destlen, 0 /* Short */, &fr, ts);
  if (nwrite < 0) {
    return nwrite;
  }

  conn->state = NGTCP2_CS_CLOSING;

  return nwrite;
}

int ngtcp2_conn_is_in_closing_period(ngtcp2_conn *conn) {
  return conn->state == NGTCP2_CS_CLOSING;
}

int ngtcp2_conn_is_in_draining_period(ngtcp2_conn *conn) {
  return conn->state == NGTCP2_CS_DRAINING;
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
          &conn->unsent_max_remote_stream_id_bidi);
    } else {
      handle_remote_stream_id_extension(&conn->unsent_max_remote_stream_id_uni);
    }
  }

  if (ngtcp2_strm_is_tx_queued(strm)) {
    ngtcp2_pq_remove(&conn->tx_strmq, &strm->pe);
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
      (((strm->flags & NGTCP2_STRM_FLAG_SENT_RST) &&
        (strm->flags & NGTCP2_STRM_FLAG_RST_ACKED)) ||
       (!(strm->flags & NGTCP2_STRM_FLAG_SENT_RST) &&
        ngtcp2_gaptr_first_gap_offset(&strm->acked_tx_offset) ==
            strm->tx_offset))) {
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

  ngtcp2_strm_streamfrq_clear(strm);

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

  if (app_error_code == NGTCP2_STOPPING) {
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

  if (app_error_code == NGTCP2_STOPPING) {
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

  if (app_error_code == NGTCP2_STOPPING) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  strm = ngtcp2_conn_find_stream(conn, stream_id);
  if (strm == NULL) {
    return NGTCP2_ERR_STREAM_NOT_FOUND;
  }

  return conn_shutdown_stream_read(conn, strm, app_error_code);
}

static int conn_extend_max_stream_offset(ngtcp2_conn *conn, ngtcp2_strm *strm,
                                         size_t datalen) {
  ngtcp2_strm *top;

  if (strm->unsent_max_rx_offset <= NGTCP2_MAX_VARINT - datalen) {
    strm->unsent_max_rx_offset += datalen;
  }

  if (!(strm->flags &
        (NGTCP2_STRM_FLAG_SHUT_RD | NGTCP2_STRM_FLAG_STOP_SENDING)) &&
      !ngtcp2_strm_is_tx_queued(strm) &&
      conn_should_send_max_stream_data(conn, strm)) {
    if (!ngtcp2_pq_empty(&conn->tx_strmq)) {
      top = ngtcp2_conn_tx_strmq_top(conn);
      strm->cycle = top->cycle;
    }
    return ngtcp2_conn_tx_strmq_push(conn, strm);
  }

  return 0;
}

int ngtcp2_conn_extend_max_stream_offset(ngtcp2_conn *conn, uint64_t stream_id,
                                         size_t datalen) {
  ngtcp2_strm *strm;

  strm = ngtcp2_conn_find_stream(conn, stream_id);
  if (strm == NULL) {
    return NGTCP2_ERR_STREAM_NOT_FOUND;
  }

  return conn_extend_max_stream_offset(conn, strm, datalen);
}

void ngtcp2_conn_extend_max_offset(ngtcp2_conn *conn, size_t datalen) {
  if (NGTCP2_MAX_VARINT < (uint64_t)datalen ||
      conn->unsent_max_rx_offset > NGTCP2_MAX_VARINT - datalen) {
    conn->unsent_max_rx_offset = NGTCP2_MAX_VARINT;
    return;
  }

  conn->unsent_max_rx_offset += datalen;
}

size_t ngtcp2_conn_get_bytes_in_flight(ngtcp2_conn *conn) {
  ngtcp2_pktns *in_pktns = &conn->in_pktns;
  ngtcp2_pktns *hs_pktns = &conn->hs_pktns;
  ngtcp2_pktns *pktns = &conn->pktns;

  return in_pktns->rtb.bytes_in_flight + hs_pktns->rtb.bytes_in_flight +
         pktns->rtb.bytes_in_flight;
}

const ngtcp2_cid *ngtcp2_conn_get_dcid(ngtcp2_conn *conn) {
  return &conn->dcid;
}

const ngtcp2_cid *ngtcp2_conn_get_scid(ngtcp2_conn *conn) {
  return &conn->scid;
}

uint32_t ngtcp2_conn_get_negotiated_version(ngtcp2_conn *conn) {
  return conn->version;
}

int ngtcp2_conn_early_data_rejected(ngtcp2_conn *conn) {
  ngtcp2_pktns *pktns = &conn->pktns;
  ngtcp2_rtb *rtb = &conn->pktns.rtb;
  ngtcp2_frame_chain *frc = NULL;
  int rv;

  conn->flags |= NGTCP2_CONN_FLAG_EARLY_DATA_REJECTED;

  rv = ngtcp2_rtb_remove_all(rtb, &frc);
  if (rv != 0) {
    assert(ngtcp2_err_is_fatal(rv));
    ngtcp2_frame_chain_list_del(frc, conn->mem);
    return rv;
  }

  rv = conn_resched_frames(conn, pktns, &frc);
  if (rv != 0) {
    assert(ngtcp2_err_is_fatal(rv));
    ngtcp2_frame_chain_list_del(frc, conn->mem);
    return rv;
  }

  return rv;
}

void ngtcp2_conn_update_rtt(ngtcp2_conn *conn, uint64_t rtt,
                            uint64_t ack_delay) {
  ngtcp2_rcvry_stat *rcs = &conn->rcs;

  rcs->min_rtt = ngtcp2_min(rcs->min_rtt, rtt);
  if (rtt - rcs->min_rtt > ack_delay) {
    rtt -= ack_delay;
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
                  rcs->latest_rtt / NGTCP2_MILLISECONDS,
                  rcs->min_rtt / NGTCP2_MILLISECONDS,
                  rcs->smoothed_rtt / NGTCP2_MILLISECONDS,
                  rcs->rttvar / NGTCP2_MILLISECONDS,
                  rcs->max_ack_delay / NGTCP2_MILLISECONDS);
}

void ngtcp2_conn_get_rcvry_stat(ngtcp2_conn *conn, ngtcp2_rcvry_stat *rcs) {
  *rcs = conn->rcs;
}

void ngtcp2_conn_set_loss_detection_timer(ngtcp2_conn *conn) {
  ngtcp2_rcvry_stat *rcs = &conn->rcs;
  uint64_t timeout;
  ngtcp2_ksl_it it;
  ngtcp2_pktns *in_pktns = &conn->in_pktns;
  ngtcp2_pktns *hs_pktns = &conn->hs_pktns;
  ngtcp2_pktns *pktns = &conn->pktns;

  if (!ngtcp2_rtb_empty(&in_pktns->rtb) || !ngtcp2_rtb_empty(&hs_pktns->rtb) ||
      (!conn->server && !conn->hs_pktns.tx_ckm)) {
    if (rcs->smoothed_rtt < 1e-09) {
      timeout = 2 * NGTCP2_DEFAULT_INITIAL_RTT;
    } else {
      timeout = (uint64_t)(2 * rcs->smoothed_rtt);
    }

    timeout = ngtcp2_max(timeout, NGTCP2_MIN_TLP_TIMEOUT);
    timeout *= 1ull << rcs->handshake_count;

    rcs->loss_detection_timer = rcs->last_hs_tx_pkt_ts + timeout;

    ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_RCV,
                    "loss_detection_timer=%" PRIu64
                    " last_hs_tx_pkt_ts=%" PRIu64 " timeout=%" PRIu64,
                    rcs->loss_detection_timer, rcs->last_hs_tx_pkt_ts,
                    timeout / NGTCP2_MILLISECONDS);
    return;
  }

  it = ngtcp2_rtb_head(&pktns->rtb);
  if (ngtcp2_ksl_it_end(&it) ||
      !(conn->flags & NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED)) {
    if (rcs->loss_detection_timer) {
      ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_RCV,
                      "loss detection timer canceled");
      rcs->loss_detection_timer = 0;
    }
    return;
  }

  /* We rarely gets assertion failure: assert(rcs->loss_time >=
     rcs->last_tx_pkt_ts).  So check the condition. */
  if (rcs->loss_time && rcs->loss_time < rcs->last_tx_pkt_ts) {
    ngtcp2_log_info(
        &conn->log, NGTCP2_LOG_EVENT_RCV,
        "assertion loss_time >= last_tx_pkt_ts failed: loss_time=%" PRIu64
        " last_tx_pkt_ts=%" PRIu64);
  }

  if (rcs->loss_time && rcs->loss_time >= rcs->last_tx_pkt_ts) {
    timeout = rcs->loss_time - rcs->last_tx_pkt_ts;
  } else {
    timeout = (uint64_t)(rcs->smoothed_rtt + 4 * rcs->rttvar +
                         (double)rcs->max_ack_delay);
    timeout = ngtcp2_max(timeout, NGTCP2_MIN_RTO_TIMEOUT);
    timeout *= 1ull << rcs->rto_count;

    if (rcs->tlp_count < NGTCP2_MAX_TLP_COUNT) {
      uint64_t tlp_timeout = ngtcp2_max(
          (uint64_t)(1.5 * rcs->smoothed_rtt + (double)rcs->max_ack_delay),
          NGTCP2_MIN_TLP_TIMEOUT);
      timeout = ngtcp2_min(timeout, tlp_timeout);
    }
  }

  rcs->loss_detection_timer = rcs->last_tx_pkt_ts + timeout;
}

int ngtcp2_conn_on_loss_detection_timer(ngtcp2_conn *conn, ngtcp2_tstamp ts) {
  ngtcp2_rcvry_stat *rcs = &conn->rcs;
  int rv;
  ngtcp2_pktns *in_pktns = &conn->in_pktns;
  ngtcp2_pktns *hs_pktns = &conn->hs_pktns;
  ngtcp2_pktns *pktns = &conn->pktns;

  conn->log.last_ts = ts;

  if (!rcs->loss_detection_timer) {
    return 0;
  }

  ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_RCV,
                  "loss detection timer fired");

  if (!ngtcp2_rtb_empty(&in_pktns->rtb) || !ngtcp2_rtb_empty(&hs_pktns->rtb)) {
    rv = conn_handshake_pkt_lost(conn, in_pktns);
    if (rv != 0) {
      return rv;
    }
    rv = conn_handshake_pkt_lost(conn, hs_pktns);
    if (rv != 0) {
      return rv;
    }
    if (!conn->server && !conn->hs_pktns.tx_ckm) {
      conn->flags |= NGTCP2_CONN_FLAG_FORCE_SEND_INITIAL;
    }
    ++rcs->handshake_count;
  } else if (!conn->server && !conn->hs_pktns.tx_ckm) {
    conn->flags |= NGTCP2_CONN_FLAG_FORCE_SEND_INITIAL;
    ++rcs->handshake_count;
  } else if (rcs->loss_time) {
    rv = ngtcp2_conn_detect_lost_pkt(conn, pktns, rcs,
                                     (uint64_t)conn->largest_ack, ts);
    if (rv != 0) {
      return rv;
    }
  } else if (rcs->tlp_count < NGTCP2_MAX_TLP_COUNT) {
    rcs->probe_pkt_left = 1;
    ++rcs->tlp_count;
  } else {
    rcs->probe_pkt_left = 2;
    if (rcs->rto_count == 0) {
      rcs->largest_sent_before_rto = pktns->last_tx_pkt_num;
    }
    ++rcs->rto_count;
  }

  ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_RCV,
                  "handshake_count=%zu tlp_count=%zu rto_count=%zu",
                  rcs->handshake_count, rcs->tlp_count, rcs->rto_count);

  ngtcp2_conn_set_loss_detection_timer(conn);

  return 0;
}

int ngtcp2_conn_submit_crypto_data(ngtcp2_conn *conn, const uint8_t *data,
                                   const size_t datalen) {
  ngtcp2_pktns *pktns;
  ngtcp2_crypto_frame_chain *frc;
  ngtcp2_crypto *fr;
  int rv;

  if (datalen == 0) {
    return 0;
  }

  if (conn->pktns.tx_ckm) {
    pktns = &conn->pktns;
  } else if (conn->hs_pktns.tx_ckm) {
    pktns = &conn->hs_pktns;
  } else {
    assert(conn->in_pktns.tx_ckm);
    pktns = &conn->in_pktns;
  }

  rv = ngtcp2_crypto_frame_chain_new(&frc, conn->mem);
  if (rv != 0) {
    return rv;
  }

  fr = &frc->fr;

  fr->type = NGTCP2_FRAME_CRYPTO;
  fr->ordered_offset = conn->crypto.tx_offset;
  fr->offset = pktns->crypto_tx_offset;
  fr->datacnt = 1;
  fr->data[0].len = datalen;
  fr->data[0].base = (uint8_t *)data;

  rv = ngtcp2_pq_push(&pktns->cryptofrq, &frc->pe);
  if (rv != 0) {
    ngtcp2_crypto_frame_chain_del(frc, conn->mem);
    return rv;
  }

  conn->crypto.tx_offset += datalen;
  pktns->crypto_tx_offset += datalen;

  return 0;
}

int ngtcp2_conn_set_retry_ocid(ngtcp2_conn *conn, const ngtcp2_cid *ocid) {
  if (!conn->server) {
    return NGTCP2_ERR_INVALID_STATE;
  }

  conn->flags |= NGTCP2_CONN_FLAG_OCID_PRESENT;
  conn->ocid = *ocid;

  return 0;
}

ngtcp2_strm *ngtcp2_conn_tx_strmq_top(ngtcp2_conn *conn) {
  assert(!ngtcp2_pq_empty(&conn->tx_strmq));
  return ngtcp2_struct_of(ngtcp2_pq_top(&conn->tx_strmq), ngtcp2_strm, pe);
}

void ngtcp2_conn_tx_strmq_pop(ngtcp2_conn *conn) {
  ngtcp2_strm *strm = ngtcp2_conn_tx_strmq_top(conn);
  assert(strm);
  ngtcp2_pq_pop(&conn->tx_strmq);
  strm->pe.index = NGTCP2_PQ_BAD_INDEX;
}

int ngtcp2_conn_tx_strmq_push(ngtcp2_conn *conn, ngtcp2_strm *strm) {
  return ngtcp2_pq_push(&conn->tx_strmq, &strm->pe);
}
