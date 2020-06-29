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

static int offset_less(const ngtcp2_ksl_key *lhs, const ngtcp2_ksl_key *rhs) {
  return *(int64_t *)lhs < *(int64_t *)rhs;
}

int ngtcp2_strm_init(ngtcp2_strm *strm, int64_t stream_id, uint32_t flags,
                     uint64_t max_rx_offset, uint64_t max_tx_offset,
                     void *stream_user_data, const ngtcp2_mem *mem) {
  strm->cycle = 0;
  strm->tx.acked_offset = NULL;
  strm->tx.cont_acked_offset = 0;
  strm->tx.streamfrq = NULL;
  strm->tx.offset = 0;
  strm->tx.max_offset = max_tx_offset;
  strm->rx.rob = NULL;
  strm->rx.cont_offset = 0;
  strm->rx.last_offset = 0;
  strm->stream_id = stream_id;
  strm->flags = flags;
  strm->stream_user_data = stream_user_data;
  strm->rx.max_offset = strm->rx.unsent_max_offset = max_rx_offset;
  strm->me.key = (uint64_t)stream_id;
  strm->me.next = NULL;
  strm->pe.index = NGTCP2_PQ_BAD_INDEX;
  strm->mem = mem;
  strm->app_error_code = 0;

  return 0;
}

void ngtcp2_strm_free(ngtcp2_strm *strm) {
  ngtcp2_ksl_it it;

  if (strm == NULL) {
    return;
  }

  if (strm->tx.streamfrq) {
    for (it = ngtcp2_ksl_begin(strm->tx.streamfrq); !ngtcp2_ksl_it_end(&it);
         ngtcp2_ksl_it_next(&it)) {
      ngtcp2_frame_chain_del(ngtcp2_ksl_it_get(&it), strm->mem);
    }

    ngtcp2_ksl_free(strm->tx.streamfrq);
    ngtcp2_mem_free(strm->mem, strm->tx.streamfrq);
  }

  ngtcp2_rob_free(strm->rx.rob);
  ngtcp2_mem_free(strm->mem, strm->rx.rob);
  ngtcp2_gaptr_free(strm->tx.acked_offset);
  ngtcp2_mem_free(strm->mem, strm->tx.acked_offset);
}

static int strm_rob_init(ngtcp2_strm *strm) {
  int rv;
  ngtcp2_rob *rob = ngtcp2_mem_malloc(strm->mem, sizeof(*rob));

  if (rob == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  rv = ngtcp2_rob_init(rob, 8 * 1024, strm->mem);
  if (rv != 0) {
    ngtcp2_mem_free(strm->mem, rob);
    return rv;
  }

  strm->rx.rob = rob;

  return 0;
}

uint64_t ngtcp2_strm_rx_offset(ngtcp2_strm *strm) {
  if (strm->rx.rob == NULL) {
    return strm->rx.cont_offset;
  }
  return ngtcp2_rob_first_gap_offset(strm->rx.rob);
}

int ngtcp2_strm_recv_reordering(ngtcp2_strm *strm, const uint8_t *data,
                                size_t datalen, uint64_t offset) {
  int rv;

  if (strm->rx.rob == NULL) {
    rv = strm_rob_init(strm);
    if (rv != 0) {
      return rv;
    }

    if (strm->rx.cont_offset) {
      rv = ngtcp2_rob_remove_prefix(strm->rx.rob, strm->rx.cont_offset);
      if (rv != 0) {
        return rv;
      }
    }
  }

  return ngtcp2_rob_push(strm->rx.rob, offset, data, datalen);
}

int ngtcp2_strm_update_rx_offset(ngtcp2_strm *strm, uint64_t offset) {
  if (strm->rx.rob == NULL) {
    strm->rx.cont_offset = offset;
    return 0;
  }

  return ngtcp2_rob_remove_prefix(strm->rx.rob, offset);
}

void ngtcp2_strm_shutdown(ngtcp2_strm *strm, uint32_t flags) {
  strm->flags |= flags & NGTCP2_STRM_FLAG_SHUT_RDWR;
}

static int strm_streamfrq_init(ngtcp2_strm *strm) {
  int rv;
  ngtcp2_ksl *streamfrq = ngtcp2_mem_malloc(strm->mem, sizeof(*streamfrq));
  if (streamfrq == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  rv = ngtcp2_ksl_init(streamfrq, offset_less, sizeof(uint64_t), strm->mem);
  if (rv != 0) {
    ngtcp2_mem_free(strm->mem, streamfrq);
    return rv;
  }

  strm->tx.streamfrq = streamfrq;

  return 0;
}

int ngtcp2_strm_streamfrq_push(ngtcp2_strm *strm, ngtcp2_frame_chain *frc) {
  int rv;

  assert(frc->fr.type == NGTCP2_FRAME_STREAM);
  assert(frc->next == NULL);

  if (strm->tx.streamfrq == NULL) {
    rv = strm_streamfrq_init(strm);
    if (rv != 0) {
      return rv;
    }
  }

  return ngtcp2_ksl_insert(strm->tx.streamfrq, NULL, &frc->fr.stream.offset,
                           frc);
}

int ngtcp2_strm_streamfrq_pop(ngtcp2_strm *strm, ngtcp2_frame_chain **pfrc,
                              size_t left) {
  ngtcp2_stream *fr, *nfr;
  ngtcp2_frame_chain *frc, *nfrc;
  int rv;
  size_t nmerged;
  size_t datalen;
  ngtcp2_vec a[NGTCP2_MAX_STREAM_DATACNT];
  ngtcp2_vec b[NGTCP2_MAX_STREAM_DATACNT];
  size_t acnt, bcnt;
  ngtcp2_ksl_it it;
  uint64_t old_offset;

  if (strm->tx.streamfrq == NULL || ngtcp2_ksl_len(strm->tx.streamfrq) == 0) {
    *pfrc = NULL;
    return 0;
  }

  it = ngtcp2_ksl_begin(strm->tx.streamfrq);
  frc = ngtcp2_ksl_it_get(&it);
  fr = &frc->fr.stream;

  datalen = ngtcp2_vec_len(fr->data, fr->datacnt);

  if (left == 0) {
    /* datalen could be zero if 0 length STREAM has been sent */
    if (datalen || ngtcp2_ksl_len(strm->tx.streamfrq) > 1) {
      *pfrc = NULL;
      return 0;
    }
  }

  ngtcp2_ksl_remove(strm->tx.streamfrq, NULL, &fr->offset);

  if (datalen > left) {
    ngtcp2_vec_copy(a, fr->data, fr->datacnt);
    acnt = fr->datacnt;

    bcnt = 0;
    ngtcp2_vec_split(a, &acnt, b, &bcnt, left, NGTCP2_MAX_STREAM_DATACNT);

    assert(acnt > 0);
    assert(bcnt > 0);

    rv = ngtcp2_frame_chain_stream_datacnt_new(&nfrc, bcnt, strm->mem);
    if (rv != 0) {
      assert(ngtcp2_err_is_fatal(rv));
      ngtcp2_frame_chain_del(frc, strm->mem);
      return rv;
    }

    nfr = &nfrc->fr.stream;
    nfr->type = NGTCP2_FRAME_STREAM;
    nfr->flags = 0;
    nfr->fin = fr->fin;
    nfr->stream_id = fr->stream_id;
    nfr->offset = fr->offset + left;
    nfr->datacnt = bcnt;
    ngtcp2_vec_copy(nfr->data, b, bcnt);

    rv = ngtcp2_ksl_insert(strm->tx.streamfrq, NULL, &nfr->offset, nfrc);
    if (rv != 0) {
      assert(ngtcp2_err_is_fatal(rv));
      ngtcp2_frame_chain_del(nfrc, strm->mem);
      ngtcp2_frame_chain_del(frc, strm->mem);
      return rv;
    }

    rv = ngtcp2_frame_chain_stream_datacnt_new(&nfrc, acnt, strm->mem);
    if (rv != 0) {
      assert(ngtcp2_err_is_fatal(rv));
      ngtcp2_frame_chain_del(frc, strm->mem);
      return rv;
    }

    nfr = &nfrc->fr.stream;
    *nfr = *fr;
    nfr->fin = 0;
    nfr->datacnt = acnt;
    ngtcp2_vec_copy(nfr->data, a, acnt);

    ngtcp2_frame_chain_del(frc, strm->mem);

    *pfrc = nfrc;

    return 0;
  }

  left -= datalen;

  ngtcp2_vec_copy(a, fr->data, fr->datacnt);
  acnt = fr->datacnt;

  for (; left && ngtcp2_ksl_len(strm->tx.streamfrq);) {
    it = ngtcp2_ksl_begin(strm->tx.streamfrq);
    nfrc = ngtcp2_ksl_it_get(&it);
    nfr = &nfrc->fr.stream;

    if (nfr->offset != fr->offset + datalen) {
      assert(fr->offset + datalen < nfr->offset);
      break;
    }

    if (nfr->fin && nfr->datacnt == 0) {
      fr->fin = 1;
      ngtcp2_ksl_remove(strm->tx.streamfrq, NULL, &nfr->offset);
      ngtcp2_frame_chain_del(nfrc, strm->mem);
      break;
    }

    nmerged = ngtcp2_vec_merge(a, &acnt, nfr->data, &nfr->datacnt, left,
                               NGTCP2_MAX_STREAM_DATACNT);
    if (nmerged == 0) {
      break;
    }

    datalen += nmerged;
    left -= nmerged;

    if (nfr->datacnt == 0) {
      fr->fin = nfr->fin;
      ngtcp2_ksl_remove(strm->tx.streamfrq, NULL, &nfr->offset);
      ngtcp2_frame_chain_del(nfrc, strm->mem);
      continue;
    }

    old_offset = nfr->offset;
    nfr->offset += nmerged;

    ngtcp2_ksl_update_key(strm->tx.streamfrq, &old_offset, &nfr->offset);

    break;
  }

  if (acnt == fr->datacnt) {
    if (acnt > 0) {
      fr->data[acnt - 1] = a[acnt - 1];
    }

    *pfrc = frc;
    return 0;
  }

  assert(acnt > fr->datacnt);

  rv = ngtcp2_frame_chain_stream_datacnt_new(&nfrc, acnt, strm->mem);
  if (rv != 0) {
    ngtcp2_frame_chain_del(frc, strm->mem);
    return rv;
  }

  nfr = &nfrc->fr.stream;
  *nfr = *fr;
  nfr->datacnt = acnt;
  ngtcp2_vec_copy(nfr->data, a, acnt);

  ngtcp2_frame_chain_del(frc, strm->mem);

  *pfrc = nfrc;

  return 0;
}

ngtcp2_frame_chain *ngtcp2_strm_streamfrq_top(ngtcp2_strm *strm) {
  ngtcp2_ksl_it it;

  assert(strm->tx.streamfrq);
  assert(ngtcp2_ksl_len(strm->tx.streamfrq));

  it = ngtcp2_ksl_begin(strm->tx.streamfrq);
  return ngtcp2_ksl_it_get(&it);
}

int ngtcp2_strm_streamfrq_empty(ngtcp2_strm *strm) {
  return strm->tx.streamfrq == NULL || ngtcp2_ksl_len(strm->tx.streamfrq) == 0;
}

void ngtcp2_strm_streamfrq_clear(ngtcp2_strm *strm) {
  ngtcp2_frame_chain *frc;
  ngtcp2_ksl_it it;

  if (strm->tx.streamfrq == NULL) {
    return;
  }

  for (it = ngtcp2_ksl_begin(strm->tx.streamfrq); !ngtcp2_ksl_it_end(&it);
       ngtcp2_ksl_it_next(&it)) {
    frc = ngtcp2_ksl_it_get(&it);
    ngtcp2_frame_chain_del(frc, strm->mem);
  }
  ngtcp2_ksl_clear(strm->tx.streamfrq);
}

int ngtcp2_strm_is_tx_queued(ngtcp2_strm *strm) {
  return strm->pe.index != NGTCP2_PQ_BAD_INDEX;
}

int ngtcp2_strm_is_all_tx_data_acked(ngtcp2_strm *strm) {
  if (strm->tx.acked_offset == NULL) {
    return strm->tx.cont_acked_offset == strm->tx.offset;
  }

  return ngtcp2_gaptr_first_gap_offset(strm->tx.acked_offset) ==
         strm->tx.offset;
}

ngtcp2_range ngtcp2_strm_get_unacked_range_after(ngtcp2_strm *strm,
                                                 uint64_t offset) {
  ngtcp2_ksl_it gapit;
  ngtcp2_range gap;

  if (strm->tx.acked_offset == NULL) {
    gap.begin = strm->tx.cont_acked_offset;
    gap.end = UINT64_MAX;
    return gap;
  }

  gapit = ngtcp2_gaptr_get_first_gap_after(strm->tx.acked_offset, offset);
  return *(ngtcp2_range *)ngtcp2_ksl_it_key(&gapit);
}

uint64_t ngtcp2_strm_get_acked_offset(ngtcp2_strm *strm) {
  if (strm->tx.acked_offset == NULL) {
    return strm->tx.cont_acked_offset;
  }

  return ngtcp2_gaptr_first_gap_offset(strm->tx.acked_offset);
}

static int strm_acked_offset_init(ngtcp2_strm *strm) {
  int rv;
  ngtcp2_gaptr *acked_offset =
      ngtcp2_mem_malloc(strm->mem, sizeof(*acked_offset));

  if (acked_offset == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  rv = ngtcp2_gaptr_init(acked_offset, strm->mem);
  if (rv != 0) {
    ngtcp2_mem_free(strm->mem, acked_offset);
    return rv;
  }

  strm->tx.acked_offset = acked_offset;

  return 0;
}

int ngtcp2_strm_ack_data(ngtcp2_strm *strm, uint64_t offset, uint64_t len) {
  int rv;

  if (strm->tx.acked_offset == NULL) {
    if (strm->tx.cont_acked_offset == offset) {
      strm->tx.cont_acked_offset += len;
      return 0;
    }

    rv = strm_acked_offset_init(strm);
    if (rv != 0) {
      return rv;
    }

    rv =
        ngtcp2_gaptr_push(strm->tx.acked_offset, 0, strm->tx.cont_acked_offset);
    if (rv != 0) {
      return rv;
    }
  }

  return ngtcp2_gaptr_push(strm->tx.acked_offset, offset, len);
}
