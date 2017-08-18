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
                           ngtcp2_tstamp tstamp, uint8_t flags,
                           ngtcp2_mem *mem) {
  *ent = ngtcp2_mem_malloc(mem, sizeof(ngtcp2_acktr_entry));
  if (*ent == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  (*ent)->next = NULL;
  (*ent)->pprev = NULL;
  (*ent)->pkt_num = pkt_num;
  (*ent)->tstamp = tstamp;
  (*ent)->flags = flags;

  return 0;
}

void ngtcp2_acktr_entry_del(ngtcp2_acktr_entry *ent, ngtcp2_mem *mem) {
  ngtcp2_mem_free(mem, ent);
}

void ngtcp2_acktr_init(ngtcp2_acktr *acktr, ngtcp2_mem *mem) {
  acktr->ent = NULL;
  acktr->tail = NULL;
  acktr->mem = mem;
  acktr->nactive_ack = 0;
  acktr->nack = 0;
}

void ngtcp2_acktr_free(ngtcp2_acktr *acktr) { (void)acktr; }

int ngtcp2_acktr_add(ngtcp2_acktr *acktr, ngtcp2_acktr_entry *ent) {
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

  if (!(ent->flags & NGTCP2_ACKTR_FLAG_PASSIVE)) {
    ++acktr->nactive_ack;
  }
  ++acktr->nack;

  if (acktr->nack > NGTCP2_ACKTR_MAX_ENT) {
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

ngtcp2_acktr_entry *ngtcp2_acktr_get(ngtcp2_acktr *acktr) { return acktr->ent; }

void ngtcp2_acktr_pop(ngtcp2_acktr *acktr) {
  --acktr->nack;
  if (!(acktr->ent->flags & NGTCP2_ACKTR_FLAG_PASSIVE)) {
    assert(acktr->nactive_ack > 0);
    --acktr->nactive_ack;
  }
  acktr->ent = acktr->ent->next;
  if (acktr->ent) {
    acktr->ent->pprev = &acktr->ent;
  } else {
    acktr->tail = NULL;
  }
}
