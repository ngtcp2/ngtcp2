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
#include "ngtcp2_gaptr.h"

#include <string.h>
#include <assert.h>

#include "ngtcp2_macro.h"

int ngtcp2_gaptr_gap_new(ngtcp2_gaptr_gap **pg, uint64_t begin, uint64_t end,
                         ngtcp2_mem *mem) {
  *pg = ngtcp2_mem_malloc(mem, sizeof(ngtcp2_gaptr_gap));
  if (*pg == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  ngtcp2_range_init(&(*pg)->range, begin, end);
  (*pg)->next = NULL;

  return 0;
}

void ngtcp2_gaptr_gap_del(ngtcp2_gaptr_gap *g, ngtcp2_mem *mem) {
  ngtcp2_mem_free(mem, g);
}

int ngtcp2_gaptr_init(ngtcp2_gaptr *gaptr, ngtcp2_mem *mem) {
  int rv;

  rv = ngtcp2_gaptr_gap_new(&gaptr->gap, 0, UINT64_MAX, mem);
  if (rv != 0) {
    return rv;
  }

  gaptr->mem = mem;

  return 0;
}

void ngtcp2_gaptr_free(ngtcp2_gaptr *gaptr) {
  ngtcp2_gaptr_gap *g, *ng;

  if (gaptr == NULL) {
    return;
  }

  for (g = gaptr->gap; g;) {
    ng = g->next;
    ngtcp2_gaptr_gap_del(g, gaptr->mem);
    g = ng;
  }
}

static void insert_gap(ngtcp2_gaptr_gap **pg, ngtcp2_gaptr_gap *g) {
  g->next = (*pg)->next;
  (*pg)->next = g;
}

static void remove_gap(ngtcp2_gaptr_gap **pg, ngtcp2_mem *mem) {
  ngtcp2_gaptr_gap *g = *pg;
  *pg = g->next;
  ngtcp2_gaptr_gap_del(g, mem);
}

int ngtcp2_gaptr_push(ngtcp2_gaptr *gaptr, uint64_t offset, size_t datalen) {
  int rv;
  ngtcp2_gaptr_gap **pg;
  ngtcp2_range m, l, r, q = {offset, offset + datalen};

  for (pg = &gaptr->gap; *pg;) {
    m = ngtcp2_range_intersect(&q, &(*pg)->range);
    if (ngtcp2_range_len(&m)) {
      if (ngtcp2_range_eq(&(*pg)->range, &m)) {
        remove_gap(pg, gaptr->mem);
        continue;
      }
      ngtcp2_range_cut(&l, &r, &(*pg)->range, &m);
      if (ngtcp2_range_len(&l)) {
        (*pg)->range = l;

        if (ngtcp2_range_len(&r)) {
          ngtcp2_gaptr_gap *ng;
          rv = ngtcp2_gaptr_gap_new(&ng, r.begin, r.end, gaptr->mem);
          if (rv != 0) {
            return rv;
          }
          insert_gap(pg, ng);
          pg = &((*pg)->next);
        }
      } else if (ngtcp2_range_len(&r)) {
        (*pg)->range = r;
      }
    }
    if (ngtcp2_range_not_after(&q, &(*pg)->range)) {
      break;
    }
    pg = &((*pg)->next);
  }
  return 0;
}

uint64_t ngtcp2_gaptr_first_gap_offset(ngtcp2_gaptr *gaptr) {
  if (gaptr->gap) {
    return gaptr->gap->range.begin;
  }
  return UINT64_MAX;
}
