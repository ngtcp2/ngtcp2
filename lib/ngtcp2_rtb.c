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
#include "ngtcp2_macro.h"

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
                         ngtcp2_mem *mem) {
  (*pent) = ngtcp2_mem_calloc(mem, 1, sizeof(ngtcp2_rtb_entry));
  if (*pent == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  (*pent)->hd = *hd;
  (*pent)->frc = frc;
  (*pent)->expiry = expiry;

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

int ngtcp2_rtb_init(ngtcp2_rtb *rtb, ngtcp2_mem *mem) {
  int rv;

  rv = ngtcp2_pq_init(&rtb->pq, expiry_less, mem);
  if (rv != 0) {
    goto fail;
  }

  rv = ngtcp2_map_init(&rtb->map, mem);
  if (rv != 0) {
    goto map_fail;
  }

  rtb->mem = mem;

  return 0;

map_fail:
  ngtcp2_pq_free(&rtb->pq);
fail:
  return rv;
}

static int pq_entry_free(ngtcp2_pq_entry *item, void *arg) {
  ngtcp2_rtb_entry *ent = ngtcp2_struct_of(item, ngtcp2_rtb_entry, pe);
  ngtcp2_mem *mem = arg;

  ngtcp2_rtb_entry_del(ent, mem);

  return 0;
}

void ngtcp2_rtb_free(ngtcp2_rtb *rtb) {
  if (rtb == NULL) {
    return;
  }

  ngtcp2_pq_each(&rtb->pq, pq_entry_free, rtb->mem);

  ngtcp2_map_free(&rtb->map);
  ngtcp2_pq_free(&rtb->pq);
}

int ngtcp2_rtb_add(ngtcp2_rtb *rtb, ngtcp2_rtb_entry *ent) {
  int rv;

  ent->me.key = ent->hd.pkt_num;

  rv = ngtcp2_map_insert(&rtb->map, &ent->me);
  if (rv != 0) {
    return rv;
  }

  rv = ngtcp2_pq_push(&rtb->pq, &ent->pe);
  if (rv != 0) {
    /* Ignore return value here */
    ngtcp2_map_remove(&rtb->map, ent->me.key);
    return rv;
  }

  return 0;
}

ngtcp2_rtb_entry *ngtcp2_rtb_top(ngtcp2_rtb *rtb) {
  if (ngtcp2_pq_empty(&rtb->pq)) {
    return NULL;
  }

  return ngtcp2_struct_of(ngtcp2_pq_top(&rtb->pq), ngtcp2_rtb_entry, pe);
}

void ngtcp2_rtb_pop(ngtcp2_rtb *rtb) {
  ngtcp2_rtb_entry *ent;

  if (ngtcp2_pq_empty(&rtb->pq)) {
    return;
  }

  ent = ngtcp2_struct_of(ngtcp2_pq_top(&rtb->pq), ngtcp2_rtb_entry, pe);
  ngtcp2_pq_pop(&rtb->pq);
  ngtcp2_map_remove(&rtb->map, ent->me.key);
}

void ngtcp2_rtb_remove(ngtcp2_rtb *rtb, uint64_t pkt_num) {
  ngtcp2_map_entry *me;
  ngtcp2_rtb_entry *ent;

  me = ngtcp2_map_find(&rtb->map, pkt_num);
  if (me == NULL) {
    return;
  }

  ent = ngtcp2_struct_of(me, ngtcp2_rtb_entry, me);

  ngtcp2_map_remove(&rtb->map, pkt_num);
  ngtcp2_pq_remove(&rtb->pq, &ent->pe);

  ngtcp2_rtb_entry_del(ent, rtb->mem);
}

typedef struct {
  ngtcp2_rtb *rtb;
  int (*f)(ngtcp2_rtb *rtb, ngtcp2_rtb_entry *ent, void *arg);
  void *arg;
} rtb_each_arg;

static int rtb_each(ngtcp2_map_entry *entry, void *ptr) {
  rtb_each_arg *param = ptr;

  return param->f(param->rtb, ngtcp2_struct_of(entry, ngtcp2_rtb_entry, me),
                  param->arg);
}

int ngtcp2_rtb_each(ngtcp2_rtb *rtb,
                    int (*f)(ngtcp2_rtb *rtb, ngtcp2_rtb_entry *ent, void *arg),
                    void *arg) {
  rtb_each_arg param;

  param.rtb = rtb;
  param.f = f;
  param.arg = arg;

  return ngtcp2_map_each(&rtb->map, rtb_each, &param);
}
