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
#include "ngtcp2_idtr.h"

#include <assert.h>

int ngtcp2_idtr_gap_new(ngtcp2_idtr_gap **pg, uint64_t begin, uint64_t end,
                        ngtcp2_mem *mem) {
  *pg = ngtcp2_mem_malloc(mem, sizeof(ngtcp2_idtr_gap));
  if (*pg == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  ngtcp2_range_init(&(*pg)->range, begin, end);
  (*pg)->next = NULL;

  return 0;
}

void ngtcp2_idtr_gap_del(ngtcp2_idtr_gap *g, ngtcp2_mem *mem) {
  ngtcp2_mem_free(mem, g);
}

int ngtcp2_idtr_init(ngtcp2_idtr *idtr, int server, ngtcp2_mem *mem) {
  int rv;

  rv = ngtcp2_idtr_gap_new(&idtr->gap, 0, UINT64_MAX, mem);
  if (rv != 0) {
    return rv;
  }

  idtr->server = server;
  idtr->mem = mem;

  return 0;
}

void ngtcp2_idtr_free(ngtcp2_idtr *idtr) {
  ngtcp2_idtr_gap *g, *next;

  if (idtr == NULL) {
    return;
  }

  for (g = idtr->gap; g;) {
    next = g->next;
    ngtcp2_idtr_gap_del(g, idtr->mem);
    g = next;
  }
}

/*
 * id_from_stream_id translates |stream_id| to id space used by
 * ngtcp2_idtr.
 */
static uint64_t id_from_stream_id(uint64_t stream_id) { return stream_id >> 2; }

int ngtcp2_idtr_open(ngtcp2_idtr *idtr, uint64_t stream_id) {
  ngtcp2_idtr_gap *g, **pg;
  int rv;
  uint64_t q;

  assert((idtr->server && (stream_id % 2)) ||
         (!idtr->server && (stream_id % 2)) == 0);

  q = id_from_stream_id(stream_id);

  for (pg = &idtr->gap; *pg; pg = &(*pg)->next) {
    if (q < (*pg)->range.begin) {
      return NGTCP2_ERR_STREAM_IN_USE;
    }
    if ((*pg)->range.end <= q) {
      continue;
    }
    if (q == (*pg)->range.begin) {
      if (ngtcp2_range_len(&(*pg)->range) == 1) {
        g = *pg;
        *pg = (*pg)->next;
        ngtcp2_idtr_gap_del(g, idtr->mem);
        return 0;
      }
      ++(*pg)->range.begin;
      return 0;
    }

    rv = ngtcp2_idtr_gap_new(&g, (*pg)->range.begin, q, idtr->mem);
    if (rv != 0) {
      return rv;
    }

    (*pg)->range.begin = q + 1;

    g->next = *pg;
    *pg = g;

    return 0;
  }

  return NGTCP2_ERR_STREAM_IN_USE;
}

int ngtcp2_idtr_is_open(ngtcp2_idtr *idtr, uint64_t stream_id) {
  ngtcp2_idtr_gap **pg;
  uint64_t q;

  assert((idtr->server && (stream_id % 2)) ||
         (!idtr->server && (stream_id % 2)) == 0);

  q = id_from_stream_id(stream_id);

  for (pg = &idtr->gap; *pg; pg = &(*pg)->next) {
    if (q < (*pg)->range.begin) {
      return NGTCP2_ERR_STREAM_IN_USE;
    }
    if ((*pg)->range.end <= q) {
      continue;
    }
    break;
  }
  return 0;
}

uint64_t ngtcp2_idtr_first_gap(ngtcp2_idtr *idtr) {
  if (idtr->gap) {
    return idtr->gap->range.begin;
  }
  return UINT64_MAX;
}
