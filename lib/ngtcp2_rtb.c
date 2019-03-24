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
#include "ngtcp2_rtb.h"

#include <assert.h>
#include <string.h>

#include "ngtcp2_macro.h"
#include "ngtcp2_conn.h"
#include "ngtcp2_log.h"
#include "ngtcp2_vec.h"
#include "ngtcp2_cc.h"

int ngtcp2_frame_chain_new(ngtcp2_frame_chain **pfrc, ngtcp2_mem *mem) {
  *pfrc = ngtcp2_mem_malloc(mem, sizeof(ngtcp2_frame_chain));
  if (*pfrc == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  ngtcp2_frame_chain_init(*pfrc);

  return 0;
}

int ngtcp2_frame_chain_extralen_new(ngtcp2_frame_chain **pfrc, size_t extralen,
                                    ngtcp2_mem *mem) {
  *pfrc = ngtcp2_mem_malloc(mem, sizeof(ngtcp2_frame_chain) + extralen);
  if (*pfrc == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  ngtcp2_frame_chain_init(*pfrc);

  return 0;
}

void ngtcp2_frame_chain_del(ngtcp2_frame_chain *frc, ngtcp2_mem *mem) {
  ngtcp2_mem_free(mem, frc);
}

void ngtcp2_frame_chain_init(ngtcp2_frame_chain *frc) { frc->next = NULL; }

int ngtcp2_stream_frame_chain_new(ngtcp2_stream_frame_chain **pfrc,
                                  ngtcp2_mem *mem) {
  *pfrc = ngtcp2_mem_malloc(mem, sizeof(ngtcp2_stream_frame_chain));
  if (*pfrc == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  ngtcp2_frame_chain_init(&(*pfrc)->frc);
  (*pfrc)->pe.index = NGTCP2_PQ_BAD_INDEX;

  return 0;
}

void ngtcp2_stream_frame_chain_del(ngtcp2_stream_frame_chain *frc,
                                   ngtcp2_mem *mem) {
  ngtcp2_mem_free(mem, frc);
}

int ngtcp2_crypto_frame_chain_new(ngtcp2_crypto_frame_chain **pfrc,
                                  ngtcp2_mem *mem) {
  *pfrc = ngtcp2_mem_malloc(mem, sizeof(ngtcp2_crypto_frame_chain));
  if (*pfrc == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  ngtcp2_frame_chain_init(&(*pfrc)->frc);
  (*pfrc)->pe.index = NGTCP2_PQ_BAD_INDEX;

  return 0;
}

void ngtcp2_crypto_frame_chain_del(ngtcp2_crypto_frame_chain *frc,
                                   ngtcp2_mem *mem) {
  ngtcp2_mem_free(mem, frc);
}

void ngtcp2_frame_chain_list_del(ngtcp2_frame_chain *frc, ngtcp2_mem *mem) {
  ngtcp2_frame_chain *next;

  for (; frc;) {
    next = frc->next;
    ngtcp2_mem_free(mem, frc);
    frc = next;
  }
}

static void frame_chain_insert(ngtcp2_frame_chain **pfrc,
                               ngtcp2_frame_chain *frc) {
  ngtcp2_frame_chain **plast;

  for (plast = &frc; *plast; plast = &(*plast)->next)
    ;

  *plast = *pfrc;
  *pfrc = frc;
}

int ngtcp2_rtb_entry_new(ngtcp2_rtb_entry **pent, const ngtcp2_pkt_hd *hd,
                         ngtcp2_frame_chain *frc, ngtcp2_tstamp ts,
                         size_t pktlen, uint8_t flags, ngtcp2_mem *mem) {
  (*pent) = ngtcp2_mem_calloc(mem, 1, sizeof(ngtcp2_rtb_entry));
  if (*pent == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  (*pent)->hd = *hd;
  (*pent)->frc = frc;
  (*pent)->ts = ts;
  (*pent)->pktlen = pktlen;
  (*pent)->flags = flags;

  return 0;
}

void ngtcp2_rtb_entry_del(ngtcp2_rtb_entry *ent, ngtcp2_mem *mem) {
  if (ent == NULL) {
    return;
  }

  ngtcp2_frame_chain_list_del(ent->frc, mem);

  ngtcp2_mem_free(mem, ent);
}

static int greater(const ngtcp2_ksl_key *lhs, const ngtcp2_ksl_key *rhs) {
  return lhs->i > rhs->i;
}

void ngtcp2_rtb_init(ngtcp2_rtb *rtb, ngtcp2_default_cc *cc, ngtcp2_log *log,
                     ngtcp2_mem *mem) {
  ngtcp2_ksl_key inf_key = {-1};

  ngtcp2_ksl_init(&rtb->ents, greater, &inf_key, mem);
  rtb->cc = cc;
  rtb->log = log;
  rtb->mem = mem;
  rtb->largest_acked_tx_pkt_num = -1;
  rtb->num_ack_eliciting = 0;
}

void ngtcp2_rtb_free(ngtcp2_rtb *rtb) {
  ngtcp2_ksl_it it;

  if (rtb == NULL) {
    return;
  }

  it = ngtcp2_ksl_begin(&rtb->ents);

  for (; !ngtcp2_ksl_it_end(&it); ngtcp2_ksl_it_next(&it)) {
    ngtcp2_rtb_entry_del(ngtcp2_ksl_it_get(&it), rtb->mem);
  }

  ngtcp2_ksl_free(&rtb->ents);
}

static void rtb_on_add(ngtcp2_rtb *rtb, ngtcp2_rtb_entry *ent) {
  rtb->cc->ccs->bytes_in_flight += ent->pktlen;

  if (ent->flags & NGTCP2_RTB_FLAG_ACK_ELICITING) {
    ++rtb->num_ack_eliciting;
  }
}

static void rtb_on_remove(ngtcp2_rtb *rtb, ngtcp2_rtb_entry *ent) {
  if (ent->flags & NGTCP2_RTB_FLAG_ACK_ELICITING) {
    assert(rtb->num_ack_eliciting);
    --rtb->num_ack_eliciting;
  }

  assert(rtb->cc->ccs->bytes_in_flight >= ent->pktlen);
  rtb->cc->ccs->bytes_in_flight -= ent->pktlen;
}

static void rtb_on_pkt_lost(ngtcp2_rtb *rtb, ngtcp2_frame_chain **pfrc,
                            ngtcp2_rtb_entry *ent) {
  if (ent->flags & NGTCP2_RTB_FLAG_PROBE) {
    /* We don't care if probe packet is lost. */
  } else {
    ngtcp2_log_pkt_lost(rtb->log, &ent->hd, ent->ts);

    /* PADDING only (or PADDING + ACK ) packets will have NULL
       ent->frc. */
    if (ent->frc) {
      /* TODO Reconsider the order of pfrc */
      frame_chain_insert(pfrc, ent->frc);
      ent->frc = NULL;
    }
  }
  ngtcp2_rtb_entry_del(ent, rtb->mem);
}

int ngtcp2_rtb_add(ngtcp2_rtb *rtb, ngtcp2_rtb_entry *ent) {
  int rv;

  ent->next = NULL;

  rv = ngtcp2_ksl_insert(&rtb->ents, NULL,
                         (const ngtcp2_ksl_key *)&ent->hd.pkt_num, ent);
  if (rv != 0) {
    return rv;
  }

  rtb_on_add(rtb, ent);

  return 0;
}

ngtcp2_ksl_it ngtcp2_rtb_head(ngtcp2_rtb *rtb) {
  return ngtcp2_ksl_begin(&rtb->ents);
}

static int rtb_remove(ngtcp2_rtb *rtb, ngtcp2_ksl_it *it,
                      ngtcp2_rtb_entry *ent) {
  int rv;

  rv = ngtcp2_ksl_remove(&rtb->ents, it,
                         (const ngtcp2_ksl_key *)&ent->hd.pkt_num);
  if (rv != 0) {
    return rv;
  }
  rtb_on_remove(rtb, ent);
  ngtcp2_rtb_entry_del(ent, rtb->mem);
  return 0;
}

static int call_acked_stream_offset(ngtcp2_rtb_entry *ent, ngtcp2_conn *conn) {
  ngtcp2_frame_chain *frc;
  uint64_t prev_stream_offset, stream_offset;
  ngtcp2_strm *strm;
  int rv;
  size_t datalen;
  ngtcp2_strm *crypto = &conn->crypto.strm;

  for (frc = ent->frc; frc; frc = frc->next) {
    switch (frc->fr.type) {
    case NGTCP2_FRAME_STREAM:
      strm = ngtcp2_conn_find_stream(conn, frc->fr.stream.stream_id);
      if (strm == NULL) {
        break;
      }
      prev_stream_offset =
          ngtcp2_gaptr_first_gap_offset(&strm->tx.acked_offset);
      rv = ngtcp2_gaptr_push(
          &strm->tx.acked_offset, frc->fr.stream.offset,
          ngtcp2_vec_len(frc->fr.stream.data, frc->fr.stream.datacnt));
      if (rv != 0) {
        return rv;
      }

      if (conn->callbacks.acked_stream_data_offset) {
        stream_offset = ngtcp2_gaptr_first_gap_offset(&strm->tx.acked_offset);
        datalen = stream_offset - prev_stream_offset;
        if (datalen == 0 && !frc->fr.stream.fin) {
          break;
        }

        rv = conn->callbacks.acked_stream_data_offset(
            conn, strm->stream_id, prev_stream_offset, datalen, conn->user_data,
            strm->stream_user_data);
        if (rv != 0) {
          return NGTCP2_ERR_CALLBACK_FAILURE;
        }
      }

      rv = ngtcp2_conn_close_stream_if_shut_rdwr(conn, strm, NGTCP2_NO_ERROR);
      if (rv != 0) {
        return rv;
      }
      break;
    case NGTCP2_FRAME_CRYPTO:
      prev_stream_offset =
          ngtcp2_gaptr_first_gap_offset(&crypto->tx.acked_offset);
      rv = ngtcp2_gaptr_push(
          &crypto->tx.acked_offset, frc->fr.crypto.ordered_offset,
          ngtcp2_vec_len(frc->fr.crypto.data, frc->fr.crypto.datacnt));
      if (rv != 0) {
        return rv;
      }

      if (conn->callbacks.acked_crypto_offset) {
        stream_offset = ngtcp2_gaptr_first_gap_offset(&crypto->tx.acked_offset);
        datalen = stream_offset - prev_stream_offset;
        if (datalen == 0) {
          break;
        }

        rv = conn->callbacks.acked_crypto_offset(conn, prev_stream_offset,
                                                 datalen, conn->user_data);
        if (rv != 0) {
          return NGTCP2_ERR_CALLBACK_FAILURE;
        }
      }
      break;
    case NGTCP2_FRAME_RESET_STREAM:
      strm = ngtcp2_conn_find_stream(conn, frc->fr.reset_stream.stream_id);
      if (strm == NULL) {
        break;
      }
      strm->flags |= NGTCP2_STRM_FLAG_RST_ACKED;
      rv = ngtcp2_conn_close_stream_if_shut_rdwr(conn, strm, NGTCP2_NO_ERROR);
      if (rv != 0) {
        return rv;
      }
      break;
    }
  }
  return 0;
}

static void rtb_on_pkt_acked(ngtcp2_rtb *rtb, ngtcp2_rtb_entry *ent) {
  ngtcp2_cc_pkt pkt;

  if (!(ent->flags & NGTCP2_RTB_FLAG_ACK_ELICITING)) {
    return;
  }

  ngtcp2_default_cc_on_pkt_acked(
      rtb->cc, ngtcp2_cc_pkt_init(&pkt, ent->hd.pkt_num, ent->pktlen, ent->ts));
}

ssize_t ngtcp2_rtb_recv_ack(ngtcp2_rtb *rtb, const ngtcp2_ack *fr,
                            ngtcp2_conn *conn, ngtcp2_tstamp ts) {
  ngtcp2_rtb_entry *ent;
  int64_t largest_ack = fr->largest_ack, min_ack;
  size_t i;
  int rv;
  ngtcp2_ksl_it it;
  ngtcp2_ksl_key key;
  ssize_t num_acked = 0;

  rtb->largest_acked_tx_pkt_num =
      ngtcp2_max(rtb->largest_acked_tx_pkt_num, largest_ack);

  /* Assume that ngtcp2_pkt_validate_ack(fr) returns 0 */
  it = ngtcp2_ksl_lower_bound(&rtb->ents, (const ngtcp2_ksl_key *)&largest_ack);

  if (ngtcp2_ksl_it_end(&it)) {
    return 0;
  }

  min_ack = largest_ack - (int64_t)fr->first_ack_blklen;

  for (; !ngtcp2_ksl_it_end(&it);) {
    key = ngtcp2_ksl_it_key(&it);
    if (min_ack <= key.i && key.i <= largest_ack) {
      ent = ngtcp2_ksl_it_get(&it);
      if (conn) {
        rv = call_acked_stream_offset(ent, conn);
        if (rv != 0) {
          return rv;
        }
        if (largest_ack == key.i &&
            (ent->flags & NGTCP2_RTB_FLAG_ACK_ELICITING)) {
          ngtcp2_conn_update_rtt(conn, ts - ent->ts, fr->ack_delay_unscaled);
        }
        rtb_on_pkt_acked(rtb, ent);
        /* At this point, it is invalided because rtb->ents might be
           modified. */
      }
      rv = rtb_remove(rtb, &it, ent);
      if (rv != 0) {
        return rv;
      }
      ++num_acked;
      continue;
    }
    break;
  }

  for (i = 0; i < fr->num_blks;) {
    largest_ack = min_ack - (int64_t)fr->blks[i].gap - 2;
    min_ack = largest_ack - (int64_t)fr->blks[i].blklen;

    it = ngtcp2_ksl_lower_bound(&rtb->ents,
                                (const ngtcp2_ksl_key *)&largest_ack);
    if (ngtcp2_ksl_it_end(&it)) {
      break;
    }

    for (; !ngtcp2_ksl_it_end(&it);) {
      key = ngtcp2_ksl_it_key(&it);
      if (key.i < min_ack) {
        break;
      }
      ent = ngtcp2_ksl_it_get(&it);
      if (conn) {
        rv = call_acked_stream_offset(ent, conn);
        if (rv != 0) {
          return rv;
        }

        rtb_on_pkt_acked(rtb, ent);
      }
      rv = rtb_remove(rtb, &it, ent);
      if (rv != 0) {
        return rv;
      }
      ++num_acked;
    }

    ++i;
  }

  return num_acked;
}

static int pkt_lost(ngtcp2_rcvry_stat *rcs, const ngtcp2_rtb_entry *ent,
                    uint64_t loss_delay, ngtcp2_tstamp lost_send_time,
                    int64_t lost_pkt_num) {
  if (ent->ts <= lost_send_time || ent->hd.pkt_num <= lost_pkt_num) {
    return 1;
  }

  if (rcs->loss_time == 0) {
    rcs->loss_time = ent->ts + loss_delay;
  } else {
    rcs->loss_time = ngtcp2_min(rcs->loss_time, ent->ts + loss_delay);
  }

  return 0;
}

/*
 * rtb_compute_pkt_loss_delay computes delay until packet is
 * considered lost in NGTCP2_DURATION_TICK resolution.
 */
static uint64_t compute_pkt_loss_delay(const ngtcp2_rcvry_stat *rcs) {
  return (uint64_t)(ngtcp2_max((double)rcs->latest_rtt, rcs->smoothed_rtt) * 9 /
                    8);
}

int ngtcp2_rtb_detect_lost_pkt(ngtcp2_rtb *rtb, ngtcp2_frame_chain **pfrc,
                               ngtcp2_rcvry_stat *rcs, ngtcp2_tstamp ts) {
  ngtcp2_rtb_entry *ent;
  uint64_t loss_delay;
  ngtcp2_tstamp lost_send_time;
  ngtcp2_ksl_it it;
  int64_t lost_pkt_num;
  int rv;

  rcs->loss_time = 0;
  loss_delay = compute_pkt_loss_delay(rcs);
  lost_send_time = ts - loss_delay;
  lost_pkt_num = rtb->largest_acked_tx_pkt_num - NGTCP2_PACKET_THRESHOLD;

  it = ngtcp2_ksl_lower_bound(
      &rtb->ents, (const ngtcp2_ksl_key *)&rtb->largest_acked_tx_pkt_num);
  for (; !ngtcp2_ksl_it_end(&it); ngtcp2_ksl_it_next(&it)) {
    ent = ngtcp2_ksl_it_get(&it);

    if (pkt_lost(rcs, ent, loss_delay, lost_send_time, lost_pkt_num)) {
      /* All entries from ent are considered to be lost. */
      ngtcp2_default_cc_congestion_event(rtb->cc, ent->ts, rcs, ts);

      for (; !ngtcp2_ksl_it_end(&it);) {
        ent = ngtcp2_ksl_it_get(&it);
        rv = ngtcp2_ksl_remove(&rtb->ents, &it,
                               (const ngtcp2_ksl_key *)&ent->hd.pkt_num);
        if (rv != 0) {
          return rv;
        }
        rtb_on_remove(rtb, ent);
        rtb_on_pkt_lost(rtb, pfrc, ent);
      }

      return 0;
    }
  }

  return 0;
}

int ngtcp2_rtb_remove_all(ngtcp2_rtb *rtb, ngtcp2_frame_chain **pfrc) {
  ngtcp2_rtb_entry *ent;
  ngtcp2_ksl_it it;
  int rv;

  it = ngtcp2_ksl_begin(&rtb->ents);

  for (; !ngtcp2_ksl_it_end(&it);) {
    ent = ngtcp2_ksl_it_get(&it);

    /* TODO Should we check NGTCP2_RTB_FLAG_PROBE here? */

    ngtcp2_log_pkt_lost(rtb->log, &ent->hd, ent->ts);

    rtb_on_remove(rtb, ent);
    rv = ngtcp2_ksl_remove(&rtb->ents, &it,
                           (const ngtcp2_ksl_key *)&ent->hd.pkt_num);
    if (rv != 0) {
      return rv;
    }
    frame_chain_insert(pfrc, ent->frc);
    ent->frc = NULL;
    ngtcp2_rtb_entry_del(ent, rtb->mem);
  }

  return 0;
}

int ngtcp2_rtb_empty(ngtcp2_rtb *rtb) {
  return ngtcp2_ksl_len(&rtb->ents) == 0;
}

void ngtcp2_rtb_clear(ngtcp2_rtb *rtb) {
  ngtcp2_ksl_it it;
  ngtcp2_rtb_entry *ent;

  it = ngtcp2_ksl_begin(&rtb->ents);

  for (; !ngtcp2_ksl_it_end(&it); ngtcp2_ksl_it_next(&it)) {
    ent = ngtcp2_ksl_it_get(&it);
    rtb->cc->ccs->bytes_in_flight -= ent->pktlen;
    ngtcp2_rtb_entry_del(ent, rtb->mem);
  }
  ngtcp2_ksl_clear(&rtb->ents);

  rtb->largest_acked_tx_pkt_num = -1;
  rtb->num_ack_eliciting = 0;
}

size_t ngtcp2_rtb_num_ack_eliciting(ngtcp2_rtb *rtb) {
  return rtb->num_ack_eliciting;
}
