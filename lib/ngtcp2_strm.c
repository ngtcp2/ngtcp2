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
#include "ngtcp2_strm.h"

#include <string.h>
#include <assert.h>

#include "ngtcp2_rtb.h"
#include "ngtcp2_pkt.h"
#include "ngtcp2_vec.h"
#include "ngtcp2_macro.h"

static int offset_less(const ngtcp2_pq_entry *lhs, const ngtcp2_pq_entry *rhs) {
  ngtcp2_stream_frame_chain *lfrc =
      ngtcp2_struct_of(lhs, ngtcp2_stream_frame_chain, pe);
  ngtcp2_stream_frame_chain *rfrc =
      ngtcp2_struct_of(rhs, ngtcp2_stream_frame_chain, pe);

  return lfrc->fr.offset < rfrc->fr.offset;
}

int ngtcp2_strm_init(ngtcp2_strm *strm, int64_t stream_id, uint32_t flags,
                     uint64_t max_rx_offset, uint64_t max_tx_offset,
                     void *stream_user_data, ngtcp2_mem *mem) {
  int rv;

  strm->cycle = 0;
  strm->tx.offset = 0;
  strm->tx.max_offset = max_tx_offset;
  strm->rx.last_offset = 0;
  strm->stream_id = stream_id;
  strm->flags = flags;
  strm->stream_user_data = stream_user_data;
  strm->rx.max_offset = strm->rx.unsent_max_offset = max_rx_offset;
  strm->me.key = (uint64_t)stream_id;
  strm->me.next = NULL;
  strm->pe.index = NGTCP2_PQ_BAD_INDEX;
  strm->mem = mem;
  /* Initializing to 0 is a bit controversial because application
     error code 0 is STOPPING.  But STOPPING is only sent with
     RST_STREAM in response to STOP_SENDING, and it is not used to
     indicate the cause of closure.  So effectively, 0 means "no
     error." */
  strm->app_error_code = 0;

  rv = ngtcp2_gaptr_init(&strm->tx.acked_offset, mem);
  if (rv != 0) {
    goto fail_gaptr_init;
  }

  rv = ngtcp2_rob_init(&strm->rx.rob, 8 * 1024, mem);
  if (rv != 0) {
    goto fail_rob_init;
  }

  ngtcp2_pq_init(&strm->tx.streamfrq, offset_less, mem);

  return 0;

fail_rob_init:
  ngtcp2_gaptr_free(&strm->tx.acked_offset);
fail_gaptr_init:
  return rv;
}

void ngtcp2_strm_free(ngtcp2_strm *strm) {
  ngtcp2_stream_frame_chain *frc;

  if (strm == NULL) {
    return;
  }

  for (; !ngtcp2_pq_empty(&strm->tx.streamfrq);) {
    frc = ngtcp2_struct_of(ngtcp2_pq_top(&strm->tx.streamfrq),
                           ngtcp2_stream_frame_chain, pe);
    ngtcp2_pq_pop(&strm->tx.streamfrq);
    ngtcp2_stream_frame_chain_del(frc, strm->mem);
  }

  ngtcp2_pq_free(&strm->tx.streamfrq);
  ngtcp2_rob_free(&strm->rx.rob);
  ngtcp2_gaptr_free(&strm->tx.acked_offset);
}

uint64_t ngtcp2_strm_rx_offset(ngtcp2_strm *strm) {
  return ngtcp2_rob_first_gap_offset(&strm->rx.rob);
}

int ngtcp2_strm_recv_reordering(ngtcp2_strm *strm, const uint8_t *data,
                                size_t datalen, uint64_t offset) {
  return ngtcp2_rob_push(&strm->rx.rob, offset, data, datalen);
}

void ngtcp2_strm_shutdown(ngtcp2_strm *strm, uint32_t flags) {
  strm->flags |= flags & NGTCP2_STRM_FLAG_SHUT_RDWR;
}

int ngtcp2_strm_streamfrq_push(ngtcp2_strm *strm,
                               ngtcp2_stream_frame_chain *frc) {
  ngtcp2_stream *fr = &frc->fr;

  assert(fr->type == NGTCP2_FRAME_STREAM);
  assert(frc->next == NULL);

  return ngtcp2_pq_push(&strm->tx.streamfrq, &frc->pe);
}

int ngtcp2_strm_streamfrq_pop(ngtcp2_strm *strm,
                              ngtcp2_stream_frame_chain **pfrc, size_t left) {
  ngtcp2_stream *fr, *nfr;
  ngtcp2_stream_frame_chain *frc, *nfrc;
  int rv;
  ssize_t nsplit;
  size_t nmerged;
  size_t datalen;

  if (ngtcp2_pq_empty(&strm->tx.streamfrq)) {
    *pfrc = NULL;
    return 0;
  }

  frc = ngtcp2_struct_of(ngtcp2_pq_top(&strm->tx.streamfrq),
                         ngtcp2_stream_frame_chain, pe);

  fr = &frc->fr;

  datalen = ngtcp2_vec_len(fr->data, fr->datacnt);

  if (left == 0) {
    /* datalen could be zero if 0 length STREAM has been sent */
    if (datalen || !ngtcp2_pq_empty(&strm->tx.streamfrq)) {
      *pfrc = NULL;
      return 0;
    }
  }

  ngtcp2_pq_pop(&strm->tx.streamfrq);
  frc->pe.index = NGTCP2_PQ_BAD_INDEX;

  if (datalen > left) {
    if (!ngtcp2_pq_empty(&strm->tx.streamfrq)) {
      nfrc = ngtcp2_struct_of(ngtcp2_pq_top(&strm->tx.streamfrq),
                              ngtcp2_stream_frame_chain, pe);
      nfr = &nfrc->fr;

      if (fr->offset + datalen == nfr->offset) {
        nsplit =
            ngtcp2_vec_split(fr->data, &fr->datacnt, nfr->data, &nfr->datacnt,
                             left, NGTCP2_MAX_STREAM_DATACNT);
        assert(nsplit);

        if (nsplit > 0) {
          ngtcp2_pq_pop(&strm->tx.streamfrq);
          nfr->offset -= (size_t)nsplit;
          assert(!fr->fin);

          rv = ngtcp2_pq_push(&strm->tx.streamfrq, &nfrc->pe);
          if (rv != 0) {
            assert(ngtcp2_err_is_fatal(rv));
            ngtcp2_stream_frame_chain_del(nfrc, strm->mem);
            ngtcp2_stream_frame_chain_del(frc, strm->mem);
            return rv;
          }

          *pfrc = frc;

          return 0;
        }
      }
    }

    rv = ngtcp2_stream_frame_chain_new(&nfrc, strm->mem);
    if (rv != 0) {
      assert(ngtcp2_err_is_fatal(rv));
      ngtcp2_stream_frame_chain_del(frc, strm->mem);
      return rv;
    }

    nfr = &nfrc->fr;
    nfr->type = NGTCP2_FRAME_STREAM;
    nfr->flags = 0;
    nfr->fin = fr->fin;
    nfr->stream_id = fr->stream_id;
    nfr->offset = fr->offset + left;
    nfr->datacnt = 0;

    ngtcp2_vec_split(fr->data, &fr->datacnt, nfr->data, &nfr->datacnt, left,
                     NGTCP2_MAX_STREAM_DATACNT);

    fr->fin = 0;

    rv = ngtcp2_pq_push(&strm->tx.streamfrq, &nfrc->pe);
    if (rv != 0) {
      assert(ngtcp2_err_is_fatal(rv));
      ngtcp2_stream_frame_chain_del(nfrc, strm->mem);
      ngtcp2_stream_frame_chain_del(frc, strm->mem);
      return rv;
    }

    *pfrc = frc;

    return 0;
  }

  /* TODO We can merge data even if fr->datacnt ==
     NGTCP2_MAX_STREAM_DATACNT */
  if (fr->datacnt == NGTCP2_MAX_STREAM_DATACNT) {
    *pfrc = frc;
    return 0;
  }

  left -= datalen;

  for (; left && fr->datacnt < NGTCP2_MAX_STREAM_DATACNT &&
         !ngtcp2_pq_empty(&strm->tx.streamfrq);) {
    nfrc = ngtcp2_struct_of(ngtcp2_pq_top(&strm->tx.streamfrq),
                            ngtcp2_stream_frame_chain, pe);
    nfr = &nfrc->fr;

    if (nfr->offset != fr->offset + datalen) {
      assert(fr->offset + datalen < nfr->offset);
      break;
    }

    if (nfr->fin && nfr->datacnt == 0) {
      frc->fr.fin = 1;
      ngtcp2_pq_pop(&strm->tx.streamfrq);
      ngtcp2_stream_frame_chain_del(nfrc, strm->mem);
      break;
    }

    nmerged = ngtcp2_vec_merge(fr->data, &fr->datacnt, nfr->data, &nfr->datacnt,
                               left, NGTCP2_MAX_STREAM_DATACNT);
    if (nmerged == 0) {
      break;
    }

    ngtcp2_pq_pop(&strm->tx.streamfrq);

    datalen += nmerged;
    nfr->offset += nmerged;
    left -= nmerged;

    if (nfr->datacnt == 0) {
      frc->fr.fin = nfrc->fr.fin;
      ngtcp2_stream_frame_chain_del(nfrc, strm->mem);
      continue;
    }

    rv = ngtcp2_pq_push(&strm->tx.streamfrq, &nfrc->pe);
    if (rv != 0) {
      ngtcp2_stream_frame_chain_del(nfrc, strm->mem);
      ngtcp2_stream_frame_chain_del(frc, strm->mem);
      return rv;
    }

    break;
  }

  *pfrc = frc;
  return 0;
}

ngtcp2_stream_frame_chain *ngtcp2_strm_streamfrq_top(ngtcp2_strm *strm) {
  assert(!ngtcp2_pq_empty(&strm->tx.streamfrq));
  return ngtcp2_struct_of(ngtcp2_pq_top(&strm->tx.streamfrq),
                          ngtcp2_stream_frame_chain, pe);
}

int ngtcp2_strm_streamfrq_empty(ngtcp2_strm *strm) {
  return ngtcp2_pq_empty(&strm->tx.streamfrq);
}

void ngtcp2_strm_streamfrq_clear(ngtcp2_strm *strm) {
  ngtcp2_stream_frame_chain *frc;
  for (; !ngtcp2_pq_empty(&strm->tx.streamfrq);) {
    frc = ngtcp2_struct_of(ngtcp2_pq_top(&strm->tx.streamfrq),
                           ngtcp2_stream_frame_chain, pe);
    ngtcp2_pq_pop(&strm->tx.streamfrq);
    ngtcp2_stream_frame_chain_del(frc, strm->mem);
  }
}

int ngtcp2_strm_is_tx_queued(ngtcp2_strm *strm) {
  return strm->pe.index != NGTCP2_PQ_BAD_INDEX;
}

int ngtcp2_strm_is_all_tx_data_acked(ngtcp2_strm *strm) {
  return ngtcp2_gaptr_first_gap_offset(&strm->tx.acked_offset) ==
         strm->tx.offset;
}
