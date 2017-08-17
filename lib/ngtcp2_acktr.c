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

int ngtcp2_acktr_entry_new(ngtcp2_acktr_entry **ent, uint64_t pkt_num,
                           ngtcp2_tstamp tstamp, uint8_t flags,
                           ngtcp2_mem *mem) {
  *ent = ngtcp2_mem_malloc(mem, sizeof(ngtcp2_acktr_entry));
  if (*ent == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  (*ent)->next = NULL;
  (*ent)->pkt_num = pkt_num;
  (*ent)->tstamp = tstamp;
  (*ent)->flags = flags;

  return 0;
}

void ngtcp2_acktr_entry_del(ngtcp2_acktr_entry *ent, ngtcp2_mem *mem) {
  ngtcp2_mem_free(mem, ent);
}

void ngtcp2_acktr_init(ngtcp2_acktr *acktr) {
  acktr->ent = NULL;
  acktr->nactive_ack = 0;
}

void ngtcp2_acktr_free(ngtcp2_acktr *acktr) { (void)acktr; }

int ngtcp2_acktr_add(ngtcp2_acktr *acktr, ngtcp2_acktr_entry *ent) {
  ngtcp2_acktr_entry **pent;

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
  *pent = ent;

  if (!(ent->flags & NGTCP2_ACKTR_FLAG_PASSIVE)) {
    ++acktr->nactive_ack;
  }

  return 0;
}

ngtcp2_acktr_entry *ngtcp2_acktr_get(ngtcp2_acktr *acktr) { return acktr->ent; }

void ngtcp2_acktr_remove(ngtcp2_acktr *acktr, const ngtcp2_acktr_entry *ent) {
  ngtcp2_acktr_entry **pent;

  for (pent = &acktr->ent; *pent; pent = &(*pent)->next) {
    if (ent->pkt_num != (*pent)->pkt_num) {
      continue;
    }

    *pent = (*pent)->next;

    if (!(ent->flags & NGTCP2_ACKTR_FLAG_PASSIVE)) {
      assert(acktr->nactive_ack > 0);
      --acktr->nactive_ack;
    }

    return;
  }
}
