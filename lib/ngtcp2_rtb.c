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

  (*pfrc)->next = NULL;

  return 0;
}

void ngtcp2_frame_chain_del(ngtcp2_frame_chain *frc, ngtcp2_mem *mem) {
  ngtcp2_mem_free(mem, frc);
}

int ngtcp2_rtb_entry_new(ngtcp2_rtb_entry **pent, const ngtcp2_pkt_hd *hd,
                         ngtcp2_frame_chain *frc, ngtcp2_tstamp expiry,
                         ngtcp2_tstamp deadline, size_t pktlen,
                         uint8_t unprotected, ngtcp2_mem *mem) {
  (*pent) = ngtcp2_mem_calloc(mem, 1, sizeof(ngtcp2_rtb_entry));
  if (*pent == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  (*pent)->hd = *hd;
  (*pent)->frc = frc;
  (*pent)->expiry = expiry;
  (*pent)->deadline = deadline;
  (*pent)->count = 0;
  (*pent)->pktlen = pktlen;
  (*pent)->unprotected = unprotected;

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

static int expiry_less(const void *lhsx, const void *rhsx) {
  ngtcp2_rtb_entry *lhs = ngtcp2_struct_of(lhsx, ngtcp2_rtb_entry, pe);
  ngtcp2_rtb_entry *rhs = ngtcp2_struct_of(rhsx, ngtcp2_rtb_entry, pe);

  return lhs->expiry < rhs->expiry;
}

void ngtcp2_rtb_init(ngtcp2_rtb *rtb, ngtcp2_mem *mem) {
  ngtcp2_pq_init(&rtb->pq, expiry_less, mem);

  rtb->head = NULL;
  rtb->mem = mem;
}

void ngtcp2_rtb_free(ngtcp2_rtb *rtb) {
  ngtcp2_rtb_entry *ent, *next;
  if (rtb == NULL) {
    return;
  }

  for (ent = rtb->head; ent;) {
    next = ent->next;
    ngtcp2_rtb_entry_del(ent, rtb->mem);
    ent = next;
  }

  ngtcp2_pq_free(&rtb->pq);
}

int ngtcp2_rtb_add(ngtcp2_rtb *rtb, ngtcp2_rtb_entry *ent) {
  int rv;

  rv = ngtcp2_pq_push(&rtb->pq, &ent->pe);
  if (rv != 0) {
    return rv;
  }

  ent->next = rtb->head;
  rtb->head = ent;
  rtb->bytes_in_flight += ent->pktlen;

  return 0;
}

ngtcp2_rtb_entry *ngtcp2_rtb_top(ngtcp2_rtb *rtb) {
  if (ngtcp2_pq_empty(&rtb->pq)) {
    return NULL;
  }

  return ngtcp2_struct_of(ngtcp2_pq_top(&rtb->pq), ngtcp2_rtb_entry, pe);
}

void ngtcp2_rtb_pop(ngtcp2_rtb *rtb) {
  ngtcp2_rtb_entry *ent, **pent;

  if (ngtcp2_pq_empty(&rtb->pq)) {
    return;
  }

  ent = ngtcp2_struct_of(ngtcp2_pq_top(&rtb->pq), ngtcp2_rtb_entry, pe);
  ngtcp2_pq_pop(&rtb->pq);

  assert(rtb->bytes_in_flight >= ent->pktlen);

  rtb->bytes_in_flight -= ent->pktlen;
  /* TODO Use doubly linked list to remove entry in O(1) if the
     current O(N) operation causes performance penalty. */
  for (pent = &rtb->head; *pent; pent = &(*pent)->next) {
    if (*pent == ent) {
      *pent = (*pent)->next;
      ent->next = NULL;
      break;
    }
  }
}

static void rtb_remove(ngtcp2_rtb *rtb, ngtcp2_rtb_entry **pent) {
  ngtcp2_rtb_entry *ent;

  ent = *pent;
  *pent = (*pent)->next;

  ngtcp2_pq_remove(&rtb->pq, &ent->pe);

  assert(rtb->bytes_in_flight >= ent->pktlen);

  rtb->bytes_in_flight -= ent->pktlen;

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
    if (datalen == 0) {
      if (stream_offset < strm->last_rx_offset ||
          (strm->flags & NGTCP2_STRM_FLAG_SHUT_RD) == 0) {
        continue;
      }
    } else {
      rv = conn->callbacks.acked_stream_data_offset(
          conn, strm->stream_id, prev_stream_offset, datalen, conn->user_data,
          strm->stream_user_data);
      if (rv != 0) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
      }
    }
    rv = ngtcp2_conn_close_stream_if_shut_rdwr(conn, strm);
    if (rv != 0) {
      return rv;
    }
  }
  return 0;
}

int ngtcp2_rtb_recv_ack(ngtcp2_rtb *rtb, const ngtcp2_ack *fr,
                        uint8_t unprotected, ngtcp2_conn *conn) {
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
      if (unprotected && !(*pent)->unprotected) {
        pent = &(*pent)->next;
        continue;
      }
      if (conn && conn->callbacks.acked_stream_data_offset) {
        rv = call_acked_stream_offset(*pent, conn);
        if (rv != 0) {
          return rv;
        }
      }
      rtb_remove(rtb, pent);
      continue;
    }
    break;
  }

  largest_ack = min_ack;

  for (i = 0; i < fr->num_blks && *pent;) {
    if (fr->blks[i].blklen == 0) {
      largest_ack -= (uint64_t)fr->blks[i].gap + 1;
      ++i;
      continue;
    }

    largest_ack -= (uint64_t)fr->blks[i].gap + 1;
    min_ack = largest_ack - (fr->blks[i].blklen - 1);

    for (; *pent;) {
      if ((*pent)->hd.pkt_num > largest_ack) {
        pent = &(*pent)->next;
        continue;
      }
      if ((*pent)->hd.pkt_num < min_ack) {
        break;
      }
      if (unprotected && !(*pent)->unprotected) {
        continue;
      }
      if (conn && conn->callbacks.acked_stream_data_offset) {
        rv = call_acked_stream_offset(*pent, conn);
        if (rv != 0) {
          return rv;
        }
      }
      rtb_remove(rtb, pent);
    }

    largest_ack = min_ack;
    ++i;
  }

  return 0;
}
