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

#include "ngtcp2_macro.h"
#include "ngtcp2_conn.h"

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

void ngtcp2_rtb_init(ngtcp2_rtb *rtb, ngtcp2_mem *mem) {
  rtb->head = rtb->lost_head = NULL;
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

  rtb_entry_list_free(rtb->head, rtb->mem);
  rtb_entry_list_free(rtb->lost_head, rtb->mem);
}

void ngtcp2_rtb_add(ngtcp2_rtb *rtb, ngtcp2_rtb_entry *ent) {
  ngtcp2_list_insert(ent, &rtb->head);

  rtb->bytes_in_flight += ent->pktlen;

  if (ent->flags & NGTCP2_RTB_FLAG_UNPROTECTED) {
    ++rtb->num_unprotected;
  }
}

ngtcp2_rtb_entry *ngtcp2_rtb_head(ngtcp2_rtb *rtb) { return rtb->head; }

ngtcp2_rtb_entry *ngtcp2_rtb_lost_head(ngtcp2_rtb *rtb) {
  return rtb->lost_head;
}

void ngtcp2_rtb_lost_pop(ngtcp2_rtb *rtb) {
  ngtcp2_rtb_entry *ent = rtb->lost_head;

  if (!rtb->lost_head) {
    return;
  }

  ngtcp2_list_remove(&rtb->lost_head);
  ent->next = NULL;
}

static void rtb_remove(ngtcp2_rtb *rtb, ngtcp2_rtb_entry **pent) {
  ngtcp2_rtb_entry *ent = *pent;

  ngtcp2_list_remove(pent);

  assert(rtb->bytes_in_flight >= ent->pktlen);

  rtb->bytes_in_flight -= ent->pktlen;

  if (ent->flags & NGTCP2_RTB_FLAG_UNPROTECTED) {
    assert(rtb->num_unprotected > 0);
    --rtb->num_unprotected;
  }

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

static void on_pkt_acked(ngtcp2_rcvry_stat *rcs) {
  /* TODO Do OnRetransmissionTimeoutVerified() */
  rcs->handshake_count = 0;
  rcs->tlp_count = 0;
  rcs->rto_count = 0;
}

int ngtcp2_rtb_recv_ack(ngtcp2_rtb *rtb, const ngtcp2_ack *fr,
                        uint8_t unprotected, ngtcp2_conn *conn,
                        ngtcp2_tstamp ts) {
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
          rv = ngtcp2_conn_update_rtt(conn, ts - (*pent)->ts,
                                      fr->ack_delay_unscaled, 0 /* ack_only */);
          if (rv != 0) {
            return rv;
          }
        }
        on_pkt_acked(&conn->rcs);
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

        on_pkt_acked(&conn->rcs);
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
    return (uint64_t)(ngtcp2_max(rcs->latest_rtt, rcs->smoothed_rtt) * 5 / 4);
  }

  return UINT64_MAX;
}

void ngtcp2_rtb_detect_lost_pkt(ngtcp2_rtb *rtb, ngtcp2_rcvry_stat *rcs,
                                uint64_t largest_ack, uint64_t last_tx_pkt_num,
                                ngtcp2_tstamp ts) {
  ngtcp2_rtb_entry **pent, *ent, *tail;
  uint64_t delay_until_lost;

  rcs->loss_time = 0;
  delay_until_lost = compute_pkt_loss_delay(rcs, largest_ack, last_tx_pkt_num);

  for (pent = &rtb->head; *pent && (*pent)->hd.pkt_num >= largest_ack;
       pent = &(*pent)->next)
    ;

  for (; *pent; pent = &(*pent)->next) {
    if (pkt_lost(rcs, *pent, delay_until_lost, largest_ack, ts)) {
      /* All entries from *pent are considered to be lost. */
      ent = *pent;
      *pent = NULL;

      for (tail = ent; tail->next; tail = tail->next) {
        rtb->bytes_in_flight -= tail->pktlen;
        if (tail->flags & NGTCP2_RTB_FLAG_UNPROTECTED) {
          --rtb->num_unprotected;
        }
      }
      rtb->bytes_in_flight -= tail->pktlen;
      if (tail->flags & NGTCP2_RTB_FLAG_UNPROTECTED) {
        --rtb->num_unprotected;
      }

      tail->next = rtb->lost_head;
      rtb->lost_head = ent;

      return;
    }
  }
}

void ngtcp2_rtb_mark_unprotected_lost(ngtcp2_rtb *rtb) {
  ngtcp2_rtb_entry *ent, **pent, **pdest = &rtb->lost_head;

  for (pent = &rtb->head; *pent;) {
    if (!((*pent)->flags & NGTCP2_RTB_FLAG_UNPROTECTED)) {
      pent = &(*pent)->next;
      continue;
    }

    ent = *pent;

    --rtb->num_unprotected;
    rtb->bytes_in_flight -= ent->pktlen;

    ngtcp2_list_remove(pent);
    ngtcp2_list_insert(ent, pdest);
  }
}

void ngtcp2_rtb_lost_add(ngtcp2_rtb *rtb, ngtcp2_rtb_entry *ent) {
  ngtcp2_list_insert(ent, &rtb->lost_head);
}
