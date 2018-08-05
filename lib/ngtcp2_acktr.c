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
#include "ngtcp2_acktr.h"

#include <assert.h>

#include "ngtcp2_conn.h"
#include "ngtcp2_macro.h"

int ngtcp2_acktr_entry_new(ngtcp2_acktr_entry **ent, uint64_t pkt_num,
                           ngtcp2_tstamp tstamp, ngtcp2_mem *mem) {
  *ent = ngtcp2_mem_malloc(mem, sizeof(ngtcp2_acktr_entry));
  if (*ent == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  (*ent)->pkt_num = pkt_num;
  (*ent)->tstamp = tstamp;

  return 0;
}

void ngtcp2_acktr_entry_del(ngtcp2_acktr_entry *ent, ngtcp2_mem *mem) {
  ngtcp2_mem_free(mem, ent);
}

static int greater(int64_t lhs, int64_t rhs) { return lhs > rhs; }

int ngtcp2_acktr_init(ngtcp2_acktr *acktr, int delayed_ack, ngtcp2_log *log,
                      ngtcp2_mem *mem) {
  int rv;

  rv = ngtcp2_ringbuf_init(&acktr->acks, 128, sizeof(ngtcp2_acktr_ack_entry),
                           mem);
  if (rv != 0) {
    return rv;
  }

  rv = ngtcp2_ksl_init(&acktr->ents, greater, -1, mem);
  if (rv != 0) {
    ngtcp2_ringbuf_free(&acktr->acks);
    return rv;
  }

  acktr->log = log;
  acktr->mem = mem;
  acktr->flags =
      delayed_ack ? NGTCP2_ACKTR_FLAG_DELAYED_ACK : NGTCP2_ACKTR_FLAG_NONE;
  acktr->first_unacked_ts = UINT64_MAX;

  return 0;
}

void ngtcp2_acktr_free(ngtcp2_acktr *acktr) {
  ngtcp2_acktr_ack_entry *ack_ent;
  size_t i;
  ngtcp2_ksl_it it;

  if (acktr == NULL) {
    return;
  }

  for (it = ngtcp2_ksl_begin(&acktr->ents); !ngtcp2_ksl_it_end(&it);
       ngtcp2_ksl_it_next(&it)) {
    ngtcp2_acktr_entry_del(ngtcp2_ksl_it_get(&it), acktr->mem);
  }
  ngtcp2_ksl_free(&acktr->ents);

  for (i = 0; i < acktr->acks.len; ++i) {
    ack_ent = ngtcp2_ringbuf_get(&acktr->acks, i);
    ngtcp2_mem_free(acktr->mem, ack_ent->ack);
  }
  ngtcp2_ringbuf_free(&acktr->acks);
}

int ngtcp2_acktr_add(ngtcp2_acktr *acktr, ngtcp2_acktr_entry *ent,
                     int active_ack, ngtcp2_tstamp ts) {
  ngtcp2_ksl_it it;
  ngtcp2_acktr_entry *delent;
  int rv;

  it = ngtcp2_ksl_lower_bound(&acktr->ents, (int64_t)ent->pkt_num);
  if (!ngtcp2_ksl_it_end(&it) &&
      ngtcp2_ksl_it_key(&it) == (int64_t)ent->pkt_num) {
    /* TODO What to do if we receive duplicated packet number? */
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  rv = ngtcp2_ksl_insert(&acktr->ents, NULL, (int64_t)ent->pkt_num, ent);
  if (rv != 0) {
    return rv;
  }

  if (active_ack) {
    acktr->flags |= NGTCP2_ACKTR_FLAG_ACTIVE_ACK;
    if (acktr->first_unacked_ts == UINT64_MAX) {
      acktr->first_unacked_ts = ts;
    }
  }

  if (ngtcp2_ksl_len(&acktr->ents) > NGTCP2_ACKTR_MAX_ENT) {
    it = ngtcp2_ksl_end(&acktr->ents);
    ngtcp2_ksl_it_prev(&it);
    delent = ngtcp2_ksl_it_get(&it);
    ngtcp2_ksl_remove(&acktr->ents, NULL, (int64_t)delent->pkt_num);
    ngtcp2_acktr_entry_del(delent, acktr->mem);
  }

  return 0;
}

int ngtcp2_acktr_forget(ngtcp2_acktr *acktr, ngtcp2_acktr_entry *ent) {
  ngtcp2_ksl_it it;
  int rv;

  it = ngtcp2_ksl_lower_bound(&acktr->ents, (int64_t)ent->pkt_num);
  assert(ngtcp2_ksl_it_key(&it) == (int64_t)ent->pkt_num);

  for (; !ngtcp2_ksl_it_end(&it);) {
    ent = ngtcp2_ksl_it_get(&it);
    rv = ngtcp2_ksl_remove(&acktr->ents, &it, (int64_t)ent->pkt_num);
    if (rv != 0) {
      return rv;
    }
    ngtcp2_acktr_entry_del(ent, acktr->mem);
  }

  return 0;
}

ngtcp2_ksl_it ngtcp2_acktr_get(ngtcp2_acktr *acktr) {
  return ngtcp2_ksl_begin(&acktr->ents);
}

ngtcp2_acktr_ack_entry *ngtcp2_acktr_add_ack(ngtcp2_acktr *acktr,
                                             uint64_t pkt_num, ngtcp2_ack *fr,
                                             ngtcp2_tstamp ts, int ack_only) {
  ngtcp2_acktr_ack_entry *ent;

  if (ngtcp2_ringbuf_full(&acktr->acks)) {
    ent =
        ngtcp2_ringbuf_get(&acktr->acks, ngtcp2_ringbuf_len(&acktr->acks) - 1);
    ngtcp2_mem_free(acktr->mem, ent->ack);
  }
  ent = ngtcp2_ringbuf_push_front(&acktr->acks);

  ent->ack = fr;
  ent->pkt_num = pkt_num;
  ent->ts = ts;
  ent->ack_only = (uint8_t)ack_only;

  return ent;
}

/*
 * acktr_remove removes |ent| from |acktr|.  The iterator which points
 * to the entry next to |ent| is assigned to |it|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 */
static int acktr_remove(ngtcp2_acktr *acktr, ngtcp2_ksl_it *it,
                        ngtcp2_acktr_entry *ent) {
  int rv;

  rv = ngtcp2_ksl_remove(&acktr->ents, it, (int64_t)ent->pkt_num);
  if (rv != 0) {
    return rv;
  }

  ngtcp2_acktr_entry_del(ent, acktr->mem);

  return 0;
}

static int acktr_on_ack(ngtcp2_acktr *acktr, ngtcp2_ringbuf *rb,
                        size_t ack_ent_offset) {
  ngtcp2_acktr_ack_entry *ack_ent;
  ngtcp2_acktr_entry *ent;
  ngtcp2_ack *fr;
  uint64_t largest_ack, min_ack;
  size_t i;
  ngtcp2_ksl_it it;
  int rv;

  ack_ent = ngtcp2_ringbuf_get(rb, ack_ent_offset);
  fr = ack_ent->ack;
  largest_ack = fr->largest_ack;
  min_ack = largest_ack - fr->first_ack_blklen;

  /* Assume that ngtcp2_pkt_validate_ack(fr) returns 0 */
  it = ngtcp2_ksl_lower_bound(&acktr->ents, (int64_t)largest_ack);
  if (ngtcp2_ksl_it_end(&it)) {
    goto fin;
  }

  for (; !ngtcp2_ksl_it_end(&it);) {
    ent = ngtcp2_ksl_it_get(&it);
    if (ent->pkt_num < min_ack) {
      break;
    }
    rv = acktr_remove(acktr, &it, ent);
    if (rv != 0) {
      return rv;
    }
  }

  for (i = 0; i < fr->num_blks && !ngtcp2_ksl_it_end(&it); ++i) {
    largest_ack = min_ack - fr->blks[i].gap - 2;
    min_ack = largest_ack - fr->blks[i].blklen;

    it = ngtcp2_ksl_lower_bound(&acktr->ents, (int64_t)largest_ack);
    if (ngtcp2_ksl_it_end(&it)) {
      break;
    }

    for (; !ngtcp2_ksl_it_end(&it);) {
      ent = ngtcp2_ksl_it_get(&it);
      if (ent->pkt_num < min_ack) {
        break;
      }
      rv = acktr_remove(acktr, &it, ent);
      if (rv != 0) {
        return rv;
      }
    }
  }

fin:
  for (i = ack_ent_offset; i < rb->len; ++i) {
    ack_ent = ngtcp2_ringbuf_get(rb, i);
    ngtcp2_mem_free(acktr->mem, ack_ent->ack);
  }
  ngtcp2_ringbuf_resize(rb, ack_ent_offset);

  return 0;
}

int ngtcp2_acktr_recv_ack(ngtcp2_acktr *acktr, const ngtcp2_ack *fr,
                          ngtcp2_conn *conn, ngtcp2_tstamp ts) {
  ngtcp2_acktr_ack_entry *ent;
  uint64_t largest_ack = fr->largest_ack, min_ack;
  size_t i, j;
  ngtcp2_ringbuf *rb = &acktr->acks;
  size_t nacks = ngtcp2_ringbuf_len(rb);
  int rv;

  /* Assume that ngtcp2_pkt_validate_ack(fr) returns 0 */
  for (j = 0; j < nacks; ++j) {
    ent = ngtcp2_ringbuf_get(rb, j);
    if (largest_ack >= ent->pkt_num) {
      break;
    }
  }
  if (j == nacks) {
    return 0;
  }

  min_ack = largest_ack - fr->first_ack_blklen;

  for (;;) {
    if (min_ack <= ent->pkt_num && ent->pkt_num <= largest_ack) {
      rv = acktr_on_ack(acktr, rb, j);
      if (rv != 0) {
        return rv;
      }
      if (conn && largest_ack == ent->pkt_num && ent->ack_only) {
        ngtcp2_conn_update_rtt(conn, ts - ent->ts, fr->ack_delay_unscaled,
                               ent->ack_only);
      }
      return 0;
    }
    break;
  }

  for (i = 0; i < fr->num_blks && j < nacks; ++i) {
    largest_ack = min_ack - fr->blks[i].gap - 2;
    min_ack = largest_ack - fr->blks[i].blklen;

    for (;;) {
      if (ent->pkt_num > largest_ack) {
        ++j;
        if (j == nacks) {
          return 0;
        }
        ent = ngtcp2_ringbuf_get(rb, j);
        continue;
      }
      if (ent->pkt_num < min_ack) {
        break;
      }
      return acktr_on_ack(acktr, rb, j);
    }
  }

  return 0;
}

void ngtcp2_acktr_commit_ack(ngtcp2_acktr *acktr) {
  acktr->flags &= (uint16_t) ~(NGTCP2_ACKTR_FLAG_ACTIVE_ACK |
                               NGTCP2_ACKTR_FLAG_DELAYED_ACK_EXPIRED);
  acktr->first_unacked_ts = UINT64_MAX;
}

int ngtcp2_acktr_require_active_ack(ngtcp2_acktr *acktr, uint64_t max_ack_delay,
                                    ngtcp2_tstamp ts) {
  return (acktr->flags & NGTCP2_ACKTR_FLAG_ACTIVE_ACK) &&
         (!(acktr->flags & NGTCP2_ACKTR_FLAG_DELAYED_ACK) ||
          (acktr->flags & NGTCP2_ACKTR_FLAG_DELAYED_ACK_EXPIRED) ||
          acktr->first_unacked_ts <= ts - max_ack_delay);
}

void ngtcp2_acktr_expire_delayed_ack(ngtcp2_acktr *acktr) {
  acktr->flags |= NGTCP2_ACKTR_FLAG_DELAYED_ACK_EXPIRED;
  acktr->first_unacked_ts = UINT64_MAX;
}

int ngtcp2_acktr_delayed_ack(ngtcp2_acktr *acktr) {
  return acktr->flags & NGTCP2_ACKTR_FLAG_DELAYED_ACK;
}
