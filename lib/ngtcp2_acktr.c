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

#include "ngtcp2_macro.h"

int ngtcp2_acktr_entry_new(ngtcp2_acktr_entry **ent, uint64_t pkt_num,
                           ngtcp2_tstamp tstamp, ngtcp2_mem *mem) {
  *ent = ngtcp2_mem_malloc(mem, sizeof(ngtcp2_acktr_entry));
  if (*ent == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  (*ent)->next = NULL;
  (*ent)->pprev = NULL;
  (*ent)->pkt_num = pkt_num;
  (*ent)->tstamp = tstamp;

  return 0;
}

void ngtcp2_acktr_entry_del(ngtcp2_acktr_entry *ent, ngtcp2_mem *mem) {
  ngtcp2_mem_free(mem, ent);
}

int ngtcp2_acktr_init(ngtcp2_acktr *acktr, ngtcp2_mem *mem) {
  int rv;

  rv = ngtcp2_ringbuf_init(&acktr->acks, 128, sizeof(ngtcp2_acktr_ack_entry),
                           mem);
  if (rv != 0) {
    return rv;
  }

  acktr->ent = NULL;
  acktr->tail = NULL;
  acktr->mem = mem;
  acktr->nack = 0;
  acktr->active_ack = 0;

  return 0;
}

void ngtcp2_acktr_free(ngtcp2_acktr *acktr) {
  ngtcp2_acktr_entry *ent, *next;

  if (acktr == NULL) {
    return;
  }

  ngtcp2_ringbuf_free(&acktr->acks);

  for (ent = acktr->ent; ent;) {
    next = ent->next;
    ngtcp2_acktr_entry_del(ent, acktr->mem);
    ent = next;
  }
}

int ngtcp2_acktr_add(ngtcp2_acktr *acktr, ngtcp2_acktr_entry *ent,
                     int active_ack) {
  ngtcp2_acktr_entry **pent;
  ngtcp2_acktr_entry *tail;

  for (pent = &acktr->ent; *pent; pent = &(*pent)->next) {
    if ((*pent)->pkt_num > ent->pkt_num) {
      continue;
    }
    /* TODO What to do if we receive duplicated packet number? */
    if ((*pent)->pkt_num == ent->pkt_num) {
      return NGTCP2_ERR_PROTO;
    }
    break;
  }

  ent->next = *pent;
  ent->pprev = pent;
  if (ent->next) {
    ent->next->pprev = &ent->next;
  } else {
    acktr->tail = ent;
  }
  *pent = ent;

  if (active_ack) {
    acktr->active_ack = 1;
  }

  if (++acktr->nack > NGTCP2_ACKTR_MAX_ENT) {
    assert(acktr->tail);

    tail = acktr->tail;
    *tail->pprev = NULL;

    acktr->tail = ngtcp2_struct_of((ngtcp2_acktr_entry *)tail->pprev,
                                   ngtcp2_acktr_entry, next);

    ngtcp2_acktr_entry_del(tail, acktr->mem);
    --acktr->nack;
  }

  return 0;
}

void ngtcp2_acktr_forget(ngtcp2_acktr *acktr, ngtcp2_acktr_entry *ent) {
  ngtcp2_acktr_entry *next;

  if (ent->pprev != &acktr->ent) {
    *ent->pprev = NULL;
    acktr->tail = ngtcp2_struct_of((ngtcp2_acktr_entry *)ent->pprev,
                                   ngtcp2_acktr_entry, next);
  } else {
    acktr->ent = acktr->tail = NULL;
  }

  for (; ent;) {
    next = ent->next;
    ngtcp2_acktr_entry_del(ent, acktr->mem);
    ent = next;
    --acktr->nack;
  }
}

ngtcp2_acktr_entry **ngtcp2_acktr_get(ngtcp2_acktr *acktr) {
  return &acktr->ent;
}

void ngtcp2_acktr_pop(ngtcp2_acktr *acktr) {
  ngtcp2_acktr_entry *ent = acktr->ent;

  assert(acktr->ent);

  --acktr->nack;
  acktr->ent = acktr->ent->next;
  if (acktr->ent) {
    acktr->ent->pprev = &acktr->ent;
  } else {
    acktr->tail = NULL;
  }

  ngtcp2_acktr_entry_del(ent, acktr->mem);
}

void ngtcp2_acktr_add_ack(ngtcp2_acktr *acktr, uint64_t pkt_num,
                          const ngtcp2_ack *fr, uint8_t unprotected) {
  ngtcp2_acktr_ack_entry *ent;

  ent = ngtcp2_ringbuf_push_front(&acktr->acks);
  ent->ack = *fr;
  ent->pkt_num = pkt_num;
  ent->unprotected = unprotected;
}

static void acktr_remove(ngtcp2_acktr *acktr, ngtcp2_acktr_entry **pent) {
  ngtcp2_acktr_entry *ent;

  ent = *pent;
  *pent = (*pent)->next;
  if (*pent) {
    (*pent)->pprev = pent;
  } else {
    acktr->tail =
        ngtcp2_struct_of((ngtcp2_acktr_entry *)pent, ngtcp2_acktr_entry, next);
  }

  ngtcp2_acktr_entry_del(ent, acktr->mem);

  --acktr->nack;
}

static void acktr_on_ack(ngtcp2_acktr *acktr, size_t ack_ent_offset) {
  ngtcp2_acktr_ack_entry *ent;
  ngtcp2_ack *fr;
  ngtcp2_acktr_entry **pent;
  uint64_t largest_ack, min_ack;
  size_t i;

  ent = ngtcp2_ringbuf_get(&acktr->acks, ack_ent_offset);
  fr = &ent->ack;
  largest_ack = fr->largest_ack;

  /* Assume that ngtcp2_pkt_validate_ack(fr) returns 0 */
  for (pent = &acktr->ent; *pent; pent = &(*pent)->next) {
    if (largest_ack >= (*pent)->pkt_num) {
      break;
    }
  }
  if (*pent == NULL) {
    goto fin;
  }

  min_ack = largest_ack - fr->first_ack_blklen;

  for (; *pent;) {
    if (min_ack <= (*pent)->pkt_num && (*pent)->pkt_num <= largest_ack) {
      acktr_remove(acktr, pent);
      continue;
    }
    break;
  }

  largest_ack = min_ack;

  for (i = 0; i < fr->num_blks && *pent;) {
    largest_ack -= (uint64_t)fr->blks[i].gap + 1;
    if (fr->blks[i].blklen == 0) {
      ++i;
      continue;
    }

    min_ack = largest_ack - (fr->blks[i].blklen - 1);

    for (; *pent;) {
      if ((*pent)->pkt_num > largest_ack) {
        pent = &(*pent)->next;
        continue;
      }
      if ((*pent)->pkt_num < min_ack) {
        break;
      }
      acktr_remove(acktr, pent);
    }

    largest_ack = min_ack;
    ++i;
  }

fin:
  ngtcp2_ringbuf_resize(&acktr->acks, ack_ent_offset);
}

void ngtcp2_acktr_recv_ack(ngtcp2_acktr *acktr, const ngtcp2_ack *fr,
                           uint8_t unprotected) {
  ngtcp2_acktr_ack_entry *ent;
  uint64_t largest_ack = fr->largest_ack, min_ack;
  size_t i, j;
  size_t nacks = ngtcp2_ringbuf_len(&acktr->acks);

  /* Assume that ngtcp2_pkt_validate_ack(fr) returns 0 */
  for (j = 0; j < nacks; ++j) {
    ent = ngtcp2_ringbuf_get(&acktr->acks, j);
    if (largest_ack >= ent->pkt_num) {
      break;
    }
  }
  if (j == nacks) {
    return;
  }

  min_ack = largest_ack - fr->first_ack_blklen;

  for (;;) {
    if (min_ack <= ent->pkt_num && ent->pkt_num <= largest_ack) {
      if (unprotected && !ent->unprotected) {
        ++j;
        if (j == nacks) {
          return;
        }
        ent = ngtcp2_ringbuf_get(&acktr->acks, j);
        continue;
      }
      acktr_on_ack(acktr, j);
      return;
    }
    break;
  }

  largest_ack = min_ack;

  for (i = 0; i < fr->num_blks && j < nacks;) {
    largest_ack -= (uint64_t)fr->blks[i].gap + 1;
    if (fr->blks[i].blklen == 0) {
      ++i;
      continue;
    }

    min_ack = largest_ack - (fr->blks[i].blklen - 1);

    for (;;) {
      if (ent->pkt_num > largest_ack) {
        ++j;
        if (j == nacks) {
          return;
        }
        ent = ngtcp2_ringbuf_get(&acktr->acks, j);
        continue;
      }
      if (ent->pkt_num < min_ack) {
        break;
      }
      if (unprotected && !ent->unprotected) {
        ++j;
        if (j == nacks) {
          return;
        }
        ent = ngtcp2_ringbuf_get(&acktr->acks, j);
        continue;
      }
      acktr_on_ack(acktr, j);
      return;
    }

    largest_ack = min_ack;
    ++i;
  }
}
