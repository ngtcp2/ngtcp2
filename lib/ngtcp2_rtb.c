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

int ngtcp2_frame_chain_new(ngtcp2_frame_chain **pfrc, ngtcp2_mem *mem) {
  *pfrc = ngtcp2_mem_malloc(mem, sizeof(ngtcp2_frame_chain));
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

ngtcp2_frame_chain *ngtcp2_frame_chain_list_copy(ngtcp2_frame_chain *frc,
                                                 ngtcp2_mem *mem) {
  ngtcp2_frame_chain *nfrc = NULL, **pfrc = &nfrc;
  int rv;

  for (; frc; frc = frc->next) {
    rv = ngtcp2_frame_chain_new(pfrc, mem);
    if (rv != 0) {
      *pfrc = NULL;
      ngtcp2_frame_chain_del(nfrc, mem);
      return NULL;
    }

    memcpy(&(*pfrc)->fr, &frc->fr, sizeof((*pfrc)->fr));

    pfrc = &(*pfrc)->next;
  }

  *pfrc = NULL;

  return nfrc;
}

void ngtcp2_frame_chain_list_del(ngtcp2_frame_chain *frc, ngtcp2_mem *mem) {
  ngtcp2_frame_chain *next;

  for (; frc;) {
    next = frc->next;
    ngtcp2_mem_free(mem, frc);
    frc = next;
  }
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
  (*pent)->src_pkt_num = -1;
  (*pent)->flags = flags;

  return 0;
}

void ngtcp2_rtb_entry_del(ngtcp2_rtb_entry *ent, ngtcp2_mem *mem) {
  ngtcp2_frame_chain *frc, *next;

  if (ent == NULL) {
    return;
  }

  for (frc = ent->frc; frc;) {
    next = frc->next;
    /* If ngtcp2_frame requires its free function, we have to call it
       here. */
    ngtcp2_mem_free(mem, frc);
    frc = next;
  }

  ngtcp2_mem_free(mem, ent);
}

void ngtcp2_rtb_init(ngtcp2_rtb *rtb, ngtcp2_log *log, ngtcp2_mem *mem) {
  rtb->ccs.cwnd = NGTCP2_INITIAL_CWND;
  rtb->ccs.eor_pkt_num = 0;
  rtb->ccs.ssthresh = UINT64_MAX;
  rtb->head = rtb->lost_unprotected_head = rtb->lost_protected_head = NULL;
  rtb->log = log;
  rtb->mem = mem;
  rtb->bytes_in_flight = 0;
  rtb->largest_acked_tx_pkt_num = -1;
  rtb->num_unprotected = 0;
}

static void rtb_entry_list_free(ngtcp2_rtb_entry *ent, ngtcp2_mem *mem) {
  ngtcp2_rtb_entry *next;

  for (; ent;) {
    next = ent->next;
    ngtcp2_rtb_entry_del(ent, mem);
    ent = next;
  }
}

void ngtcp2_rtb_free(ngtcp2_rtb *rtb) {
  if (rtb == NULL) {
    return;
  }

  rtb_entry_list_free(rtb->lost_protected_head, rtb->mem);
  rtb_entry_list_free(rtb->lost_unprotected_head, rtb->mem);
  rtb_entry_list_free(rtb->head, rtb->mem);
}

static void rtb_on_add(ngtcp2_rtb *rtb, ngtcp2_rtb_entry *ent) {
  rtb->bytes_in_flight += ent->pktlen;

  if (ent->flags & NGTCP2_RTB_FLAG_UNPROTECTED) {
    ++rtb->num_unprotected;
  }
}

static void rtb_on_remove(ngtcp2_rtb *rtb, ngtcp2_rtb_entry *ent) {
  if (ent->flags & NGTCP2_RTB_FLAG_UNPROTECTED) {
    assert(rtb->num_unprotected > 0);
    --rtb->num_unprotected;
  }

  assert(rtb->bytes_in_flight >= ent->pktlen);
  rtb->bytes_in_flight -= ent->pktlen;
}

void ngtcp2_rtb_add(ngtcp2_rtb *rtb, ngtcp2_rtb_entry *ent) {
  ngtcp2_list_insert(ent, &rtb->head);
  rtb_on_add(rtb, ent);
}

void ngtcp2_rtb_insert_range(ngtcp2_rtb *rtb, ngtcp2_rtb_entry *head) {
  ngtcp2_rtb_entry **pent, *ent;

  for (pent = &rtb->head; *pent && head; pent = &(*pent)->next) {
    if ((*pent)->hd.pkt_num > head->hd.pkt_num) {
      continue;
    }

    assert((*pent)->hd.pkt_num < head->hd.pkt_num);

    ent = head;
    head = head->next;

    ngtcp2_list_insert(ent, pent);
    rtb_on_add(rtb, ent);
  }

  if (!head) {
    return;
  }

  assert(!(*pent));

  *pent = head;

  for (ent = head; ent; ent = ent->next) {
    rtb_on_add(rtb, ent);
  }
}

ngtcp2_rtb_entry *ngtcp2_rtb_head(ngtcp2_rtb *rtb) { return rtb->head; }

void ngtcp2_rtb_pop(ngtcp2_rtb *rtb) {
  ngtcp2_rtb_entry *ent = rtb->head;

  if (!ent) {
    return;
  }

  ngtcp2_list_remove(&rtb->head);
  ent->next = NULL;
}

ngtcp2_rtb_entry *ngtcp2_rtb_lost_protected_head(ngtcp2_rtb *rtb) {
  return rtb->lost_protected_head;
}

void ngtcp2_rtb_lost_protected_pop(ngtcp2_rtb *rtb) {
  ngtcp2_rtb_entry *ent = rtb->lost_protected_head;

  if (!ent) {
    return;
  }

  ngtcp2_list_remove(&rtb->lost_protected_head);
  ent->next = NULL;
}

ngtcp2_rtb_entry *ngtcp2_rtb_lost_unprotected_head(ngtcp2_rtb *rtb) {
  return rtb->lost_unprotected_head;
}

void ngtcp2_rtb_lost_unprotected_pop(ngtcp2_rtb *rtb) {
  ngtcp2_rtb_entry *ent = rtb->lost_unprotected_head;

  if (!ent) {
    return;
  }

  ngtcp2_list_remove(&rtb->lost_unprotected_head);
  ent->next = NULL;
}

static void rtb_remove(ngtcp2_rtb *rtb, ngtcp2_rtb_entry **pent) {
  ngtcp2_rtb_entry *ent = *pent;

  ngtcp2_list_remove(pent);
  rtb_on_remove(rtb, ent);
  ngtcp2_rtb_entry_del(ent, rtb->mem);
}

static int call_acked_stream_offset(ngtcp2_rtb_entry *ent, ngtcp2_conn *conn) {
  ngtcp2_frame_chain *frc;
  uint64_t prev_stream_offset, stream_offset;
  ngtcp2_strm *strm;
  int rv;
  size_t datalen;

  for (frc = ent->frc; frc; frc = frc->next) {
    if (frc->fr.type != NGTCP2_FRAME_STREAM) {
      continue;
    }
    strm = ngtcp2_conn_find_stream(conn, frc->fr.stream.stream_id);
    if (strm == NULL) {
      continue;
    }
    prev_stream_offset = ngtcp2_gaptr_first_gap_offset(&strm->acked_tx_offset);
    rv = ngtcp2_gaptr_push(&strm->acked_tx_offset, frc->fr.stream.offset,
                           frc->fr.stream.datalen);
    if (rv != 0) {
      return rv;
    }
    stream_offset = ngtcp2_gaptr_first_gap_offset(&strm->acked_tx_offset);
    datalen = stream_offset - prev_stream_offset;
    if (datalen == 0 && !frc->fr.stream.fin) {
      continue;
    }

    rv = conn->callbacks.acked_stream_data_offset(
        conn, strm->stream_id, prev_stream_offset, datalen, conn->user_data,
        strm->stream_user_data);
    if (rv != 0) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    rv = ngtcp2_conn_close_stream_if_shut_rdwr(conn, strm, NGTCP2_NO_ERROR);
    if (rv != 0) {
      return rv;
    }
  }
  return 0;
}

static int rtb_in_rcvry(ngtcp2_rtb *rtb, uint64_t pkt_num) {
  return pkt_num <= rtb->ccs.eor_pkt_num;
}

static void rtb_on_retransmission_timeout_verified(ngtcp2_rtb *rtb) {
  rtb->ccs.cwnd = NGTCP2_MIN_CWND;
  ngtcp2_log_info(rtb->log, NGTCP2_LOG_EVENT_RCV,
                  "retransmission timeout verified cwnd=%lu", rtb->ccs.cwnd);
}

static void rtb_on_pkt_acked_cc(ngtcp2_rtb *rtb, ngtcp2_rtb_entry *ent) {
  /* bytes_in_flight is reduced in rtb_on_remove */
  if (rtb_in_rcvry(rtb, ent->hd.pkt_num)) {
    return;
  }

  if (rtb->ccs.cwnd < rtb->ccs.ssthresh) {
    rtb->ccs.cwnd += ent->pktlen;
    ngtcp2_log_info(rtb->log, NGTCP2_LOG_EVENT_RCV,
                    "packet %" PRIu64 " acked, slow start cwnd=%lu",
                    ent->hd.pkt_num, rtb->ccs.cwnd);
    return;
  }

  rtb->ccs.cwnd += NGTCP2_DEFAULT_MSS * ent->pktlen / rtb->ccs.cwnd;

  ngtcp2_log_info(rtb->log, NGTCP2_LOG_EVENT_RCV,
                  "packet %" PRIu64 " acked, cwnd=%lu", ent->hd.pkt_num,
                  rtb->ccs.cwnd);
}

/*
 * rtb_remove_src_ent removes ngtcp2_rtb_entry whose packet number is
 * dupent->src_pkt_num.  probe_ent is supposed to be TLP/RTO probe
 * packet.  We assume that src_pkt_num < probe_ent->src_pkt_num,
 * because probe packet is duplicate of unacknowledged packet.
 */
static void rtb_remove_src_ent(ngtcp2_rtb *rtb, ngtcp2_rtb_entry *probe_ent) {
  ngtcp2_rtb_entry **pent;

  for (pent = &probe_ent->next; *pent; pent = &(*pent)->next) {
    if ((*pent)->hd.pkt_num > (uint64_t)probe_ent->src_pkt_num) {
      continue;
    }
    if ((*pent)->hd.pkt_num < (uint64_t)probe_ent->src_pkt_num) {
      return;
    }
    rtb_remove(rtb, pent);
    return;
  }
}

static void rtb_on_pkt_acked(ngtcp2_rtb *rtb, ngtcp2_rcvry_stat *rcs,
                             ngtcp2_rtb_entry *ent) {
  if (ent->flags & NGTCP2_RTB_FLAG_PROBE) {
    rtb_remove_src_ent(rtb, ent);
  }
  rtb_on_pkt_acked_cc(rtb, ent);
  if (rcs->rto_count && ent->hd.pkt_num > rcs->largest_sent_before_rto) {
    rtb_on_retransmission_timeout_verified(rtb);
  }
  rcs->handshake_count = 0;
  rcs->tlp_count = 0;
  rcs->rto_count = 0;
  rcs->probe_pkt_left = 0;
}

int ngtcp2_rtb_recv_ack(ngtcp2_rtb *rtb, const ngtcp2_ack *fr, int unprotected,
                        ngtcp2_conn *conn, ngtcp2_tstamp ts) {
  ngtcp2_rtb_entry **pent;
  uint64_t largest_ack = fr->largest_ack, min_ack;
  size_t i;
  int rv;

  /* Assume that ngtcp2_pkt_validate_ack(fr) returns 0 */
  for (pent = &rtb->head; *pent; pent = &(*pent)->next) {
    if (largest_ack >= (*pent)->hd.pkt_num) {
      break;
    }
  }
  if (*pent == NULL) {
    return 0;
  }

  min_ack = largest_ack - fr->first_ack_blklen;

  for (; *pent;) {
    if (min_ack <= (*pent)->hd.pkt_num && (*pent)->hd.pkt_num <= largest_ack) {
      if (unprotected && !((*pent)->flags & NGTCP2_RTB_FLAG_UNPROTECTED)) {
        pent = &(*pent)->next;
        continue;
      }
      if (conn) {
        if (conn->callbacks.acked_stream_data_offset) {
          rv = call_acked_stream_offset(*pent, conn);
          if (rv != 0) {
            return rv;
          }
        }
        if (largest_ack == (*pent)->hd.pkt_num) {
          ngtcp2_conn_update_rtt(conn, ts - (*pent)->ts, fr->ack_delay_unscaled,
                                 0 /* ack_only */);
        }
        rtb_on_pkt_acked(rtb, &conn->rcs, *pent);
      }
      rtb->largest_acked_tx_pkt_num = ngtcp2_max(rtb->largest_acked_tx_pkt_num,
                                                 (int64_t)(*pent)->hd.pkt_num);
      rtb_remove(rtb, pent);
      continue;
    }
    break;
  }

  for (i = 0; i < fr->num_blks && *pent;) {
    largest_ack = min_ack - fr->blks[i].gap - 2;

    min_ack = largest_ack - fr->blks[i].blklen;

    for (; *pent;) {
      if ((*pent)->hd.pkt_num > largest_ack) {
        pent = &(*pent)->next;
        continue;
      }
      if ((*pent)->hd.pkt_num < min_ack) {
        break;
      }
      if (unprotected && !((*pent)->flags & NGTCP2_RTB_FLAG_UNPROTECTED)) {
        pent = &(*pent)->next;
        continue;
      }
      if (conn) {
        if (conn->callbacks.acked_stream_data_offset) {
          rv = call_acked_stream_offset(*pent, conn);
          if (rv != 0) {
            return rv;
          }
        }

        rtb_on_pkt_acked(rtb, &conn->rcs, *pent);
      }
      rtb->largest_acked_tx_pkt_num = ngtcp2_max(rtb->largest_acked_tx_pkt_num,
                                                 (int64_t)(*pent)->hd.pkt_num);
      rtb_remove(rtb, pent);
    }

    ++i;
  }

  return 0;
}

static int pkt_lost(ngtcp2_rcvry_stat *rcs, const ngtcp2_rtb_entry *ent,
                    uint64_t delay_until_lost, uint64_t largest_ack,
                    ngtcp2_tstamp ts) {
  uint64_t time_since_sent = ts - ent->ts;
  uint64_t delta = largest_ack - ent->hd.pkt_num;

  if (time_since_sent > delay_until_lost || delta > rcs->reordering_threshold) {
    return 1;
  }

  if (rcs->loss_time == 0 && delay_until_lost != UINT64_MAX) {
    rcs->loss_time = ts + delay_until_lost - time_since_sent;
  }

  return 0;
}

/*
 * rtb_compute_pkt_loss_delay computes delay until packet is
 * considered lost in nanoseconds resolution.
 */
static uint64_t compute_pkt_loss_delay(const ngtcp2_rcvry_stat *rcs,
                                       uint64_t largest_ack,
                                       uint64_t last_tx_pkt_num) {
  /* TODO Implement time loss detection */
  if (largest_ack == last_tx_pkt_num) {
    return (uint64_t)(ngtcp2_max((double)rcs->latest_rtt, rcs->smoothed_rtt) *
                      5 / 4);
  }

  return UINT64_MAX;
}

void ngtcp2_rtb_detect_lost_pkt(ngtcp2_rtb *rtb, ngtcp2_rcvry_stat *rcs,
                                uint64_t largest_ack, uint64_t last_tx_pkt_num,
                                ngtcp2_tstamp ts) {
  ngtcp2_rtb_entry **pent, **pdest_protected, **pdest_unprotected, *ent, *next;
  uint64_t delay_until_lost;
  int unprotected;
  ngtcp2_cc_stat *ccs = &rtb->ccs;

  rcs->loss_time = 0;
  delay_until_lost = compute_pkt_loss_delay(rcs, largest_ack, last_tx_pkt_num);
  pdest_protected = &rtb->lost_protected_head;
  pdest_unprotected = &rtb->lost_unprotected_head;

  for (pent = &rtb->head; *pent && (*pent)->hd.pkt_num >= largest_ack;
       pent = &(*pent)->next)
    ;

  for (; *pent; pent = &(*pent)->next) {
    if (pkt_lost(rcs, *pent, delay_until_lost, largest_ack, ts)) {
      /* All entries from *pent are considered to be lost. */
      ent = *pent;
      *pent = NULL;

      /* OnPacketsLost in recovery draft */
      /* TODO I'm not sure we should do this for handshake packets. */
      if (!rtb_in_rcvry(rtb, ent->hd.pkt_num)) {
        ccs->eor_pkt_num = ent->hd.pkt_num;
        ccs->cwnd =
            (uint64_t)((double)ccs->cwnd * NGTCP2_LOSS_REDUCTION_FACTOR);
        ccs->cwnd = ngtcp2_max(rtb->ccs.cwnd, NGTCP2_MIN_CWND);
        ccs->ssthresh = ccs->cwnd;

        ngtcp2_log_info(rtb->log, NGTCP2_LOG_EVENT_RCV,
                        "reduce cwnd because of packet loss cwnd=%lu",
                        rtb->ccs.cwnd);
      }

      for (; ent;) {
        next = ent->next;
        unprotected = ent->flags & NGTCP2_RTB_FLAG_UNPROTECTED;
        rtb_on_remove(rtb, ent);

        if (ent->flags & NGTCP2_RTB_FLAG_PROBE) {
          /* We don't care if probe packet is lost. */
          ngtcp2_rtb_entry_del(ent, rtb->mem);
        } else {
          ngtcp2_log_pkt_lost(rtb->log, &ent->hd, ent->ts, unprotected);

          /* TODO Reconsider the order of conn->lost_unprotected_head
             and conn->lost_protected_head */
          if (unprotected) {
            ngtcp2_list_insert(ent, pdest_unprotected);
          } else {
            ngtcp2_list_insert(ent, pdest_protected);
          }
        }

        ent = next;
      }

      return;
    }
  }
}

void ngtcp2_rtb_mark_unprotected_lost(ngtcp2_rtb *rtb) {
  ngtcp2_rtb_entry *ent, **pent, **pdest = &rtb->lost_unprotected_head;

  for (pent = &rtb->head; *pent;) {
    if (!((*pent)->flags & NGTCP2_RTB_FLAG_UNPROTECTED)) {
      pent = &(*pent)->next;
      continue;
    }

    ent = *pent;

    ngtcp2_log_pkt_lost(rtb->log, &ent->hd, ent->ts, 1 /* unprotected */);

    rtb_on_remove(rtb, ent);

    ngtcp2_list_remove(pent);
    ngtcp2_list_insert(ent, pdest);
  }
}

void ngtcp2_rtb_lost_protected_insert(ngtcp2_rtb *rtb, ngtcp2_rtb_entry *ent) {
  ngtcp2_list_insert(ent, &rtb->lost_protected_head);
}

void ngtcp2_rtb_lost_unprotected_insert(ngtcp2_rtb *rtb,
                                        ngtcp2_rtb_entry *ent) {
  ngtcp2_list_insert(ent, &rtb->lost_unprotected_head);
}

int ngtcp2_rtb_has_lost_pkt(ngtcp2_rtb *rtb) {
  return rtb->lost_unprotected_head || rtb->lost_protected_head;
}
