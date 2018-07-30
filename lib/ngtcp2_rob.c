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
#include "ngtcp2_rob.h"

#include <string.h>
#include <assert.h>

#include "ngtcp2_macro.h"

int ngtcp2_rob_gap_new(ngtcp2_rob_gap **pg, uint64_t begin, uint64_t end,
                       ngtcp2_mem *mem) {
  *pg = ngtcp2_mem_malloc(mem, sizeof(ngtcp2_rob_gap));
  if (*pg == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  ngtcp2_range_init(&(*pg)->range, begin, end);
  (*pg)->next = NULL;

  return 0;
}

void ngtcp2_rob_gap_del(ngtcp2_rob_gap *g, ngtcp2_mem *mem) {
  ngtcp2_mem_free(mem, g);
}

static int ngtcp2_rob_data_new_nul(ngtcp2_rob_data **pd, uint64_t offset,
                                   size_t chunk, ngtcp2_mem *mem) {
  *pd = ngtcp2_mem_malloc(mem, sizeof(ngtcp2_rob_data));
  if (*pd == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  (*pd)->begin = NULL;
  (*pd)->end = (uint8_t*)chunk;
  (*pd)->offset = offset;
  (*pd)->next = NULL;

  return 0;
}

int ngtcp2_rob_data_new(ngtcp2_rob_data **pd, uint64_t offset, size_t chunk,
                        ngtcp2_mem *mem) {
  *pd = ngtcp2_mem_malloc(mem, sizeof(ngtcp2_rob_data) + chunk);
  if (*pd == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  (*pd)->begin = (uint8_t *)(*pd) + sizeof(ngtcp2_rob_data);
  (*pd)->end = (*pd)->begin + chunk;
  (*pd)->offset = offset;
  (*pd)->next = NULL;

  return 0;
}

void ngtcp2_rob_data_del(ngtcp2_rob_data *d, ngtcp2_mem *mem) {
  ngtcp2_mem_free(mem, d);
}

int ngtcp2_rob_init(ngtcp2_rob *rob, size_t chunk, ngtcp2_mem *mem) {
  int rv;

  rv = ngtcp2_rob_gap_new(&rob->gap, 0, UINT64_MAX, mem);
  if (rv != 0) {
    return rv;
  }

  rob->data = NULL;
  rob->chunk = chunk;
  rob->mem = mem;

  return 0;
}

void ngtcp2_rob_free(ngtcp2_rob *rob) {
  ngtcp2_rob_gap *g, *ng;
  ngtcp2_rob_data *d, *nd;

  if (rob == NULL) {
    return;
  }

  for (g = rob->gap; g;) {
    ng = g->next;
    ngtcp2_rob_gap_del(g, rob->mem);
    g = ng;
  }
  for (d = rob->data; d;) {
    nd = d->next;
    ngtcp2_rob_data_del(d, rob->mem);
    d = nd;
  }
}

static void insert_gap(ngtcp2_rob_gap **pg, ngtcp2_rob_gap *g) {
  g->next = (*pg)->next;
  (*pg)->next = g;
}

static void remove_gap(ngtcp2_rob_gap **pg, ngtcp2_mem *mem) {
  ngtcp2_rob_gap *g = *pg;
  *pg = g->next;
  ngtcp2_rob_gap_del(g, mem);
}

static void remove_data(ngtcp2_rob_data **pd, ngtcp2_mem *mem) {
  ngtcp2_rob_data *d = *pd;
  *pd = d->next;
  ngtcp2_rob_data_del(d, mem);
}

static int rob_write_data(ngtcp2_rob *rob, ngtcp2_rob_data **pd,
                          uint64_t offset, const uint8_t *data, size_t len) {
  size_t n;
  int rv;
  ngtcp2_rob_data *nd;

  for (;;) {
    if (*pd == NULL || offset < (*pd)->offset) {
      rv = ngtcp2_rob_data_new(&nd, (offset / rob->chunk) * rob->chunk,
                               rob->chunk, rob->mem);
      if (rv != 0) {
        return rv;
      }
      /* insert before *pd */
      nd->next = *pd;
      *pd = nd;
    } else if ((*pd)->offset + rob->chunk < offset) {
      pd = &(*pd)->next;
      continue;
    }
    n = ngtcp2_min(len, (*pd)->offset + rob->chunk - offset);
    memcpy((*pd)->begin + (offset - (*pd)->offset), data, n);
    offset += n;
    data += n;
    len -= n;
    if (len == 0) {
      return 0;
    }
    pd = &(*pd)->next;
  }

  return 0;
}

int ngtcp2_rob_push(ngtcp2_rob *rob, uint64_t offset, const uint8_t *data,
                    size_t datalen) {
  int rv;
  ngtcp2_rob_gap **pg;
  ngtcp2_range m, l, r, q = {offset, offset + datalen};
  ngtcp2_rob_data **pd = &rob->data;

  for (pg = &rob->gap; *pg;) {
    m = ngtcp2_range_intersect(&q, &(*pg)->range);
    if (ngtcp2_range_len(&m)) {
      if (ngtcp2_range_equal(&(*pg)->range, &m)) {
        remove_gap(pg, rob->mem);
        rv = rob_write_data(rob, pd, m.begin, data + (m.begin - offset),
                            ngtcp2_range_len(&m));
        if (rv != 0) {
          return rv;
        }
        continue;
      }
      ngtcp2_range_cut(&l, &r, &(*pg)->range, &m);
      if (ngtcp2_range_len(&l)) {
        (*pg)->range = l;

        if (ngtcp2_range_len(&r)) {
          ngtcp2_rob_gap *ng;
          rv = ngtcp2_rob_gap_new(&ng, r.begin, r.end, rob->mem);
          if (rv != 0) {
            return rv;
          }
          insert_gap(pg, ng);
          pg = &((*pg)->next);
        }
      } else if (ngtcp2_range_len(&r)) {
        (*pg)->range = r;
      }
      rv = rob_write_data(rob, pd, m.begin, data + (m.begin - offset),
                          ngtcp2_range_len(&m));
      if (rv != 0) {
        return rv;
      }
    }
    if (ngtcp2_range_not_after(&q, &(*pg)->range)) {
      break;
    }
    pg = &((*pg)->next);
  }
  return 0;
}

void ngtcp2_rob_remove_prefix(ngtcp2_rob *rob, uint64_t offset) {
  ngtcp2_rob_gap **pg;
  ngtcp2_rob_data **pd;

  for (pg = &rob->gap; *pg;) {
    if (offset <= (*pg)->range.begin) {
      break;
    }
    if (offset < (*pg)->range.end) {
      (*pg)->range.begin = offset;
      break;
    }
    remove_gap(pg, rob->mem);
  }

  for (pd = &rob->data; *pd;) {
    if (offset <= (*pd)->offset) {
      return;
    }
    if (offset < (*pd)->offset + rob->chunk) {
      return;
    }
    remove_data(pd, rob->mem);
  }
}

void ngtcp2_rob_remove_gap(ngtcp2_rob *rob, uint64_t offset, size_t datalen) {
  ngtcp2_rob_gap **pg;
  ngtcp2_rob_data **pd;
  int rv;

  for (pg = &rob->gap; *pg;) {
    if (offset + datalen <= (*pg)->range.begin) {
      break;
    }
    if (offset > (*pg)->range.end) {
      pg = &(*pg)->next;
      continue;
    }
    if (offset <= (*pg)->range.begin && offset + datalen >= (*pg)->range.end) {
      // pg is completely within [offset, offset+datalen), just delete
      remove_gap(pg, rob->mem);
      continue;
    }
    if (offset <= (*pg)->range.begin) {
      // [offset, offset+datalen) overlaps the start of pg, trim pg
      (*pg)->range.begin = offset + datalen;
    } else if (offset + datalen >= (*pg)->range.end) {
      // [offset, offset+datalen) overlaps the end of pg, trim pg
      (*pg)->range.end = offset;
    } else {
      // [offset, offset+datalen) is in the middle of pg, split pg
      ngtcp2_rob_gap *new_pg;
      rv = ngtcp2_rob_gap_new (&new_pg, offset + datalen, (*pg)->range.end,
                          rob->mem);
      if (rv != 0) {
        return;
      }
      (*pg)->range.end = offset;
      insert_gap (pg, new_pg);
      pg = &(*pg)->next;
    }
    pg = &(*pg)->next;
  }

  // Find insert/append point for nul data
  for (pd = &rob->data; *pd; pd = &(*pd)->next) {
    if (offset < (*pd)->offset) {
      break;
    }
    if (offset >= (*pd)->offset &&
        offset < (*pd)->offset + ((*pd)->end - (*pd)->begin)) {
      break;
    }
  }

  if (!*pd || offset < (*pd)->offset) {
    // insert new nul data
    size_t new_datalen = datalen;
    ngtcp2_rob_data *new_data;

    if (*pd && datalen > (*pd)->offset - offset) {
      new_datalen = (*pd)->offset - offset;
    }

    rv = ngtcp2_rob_data_new_nul (&new_data, offset, new_datalen, rob->mem);
    if (rv != 0) {
      return;
    }

    new_data->next = *pd;
    (*pd) = new_data;

  } else if (!(*pd)->begin) {
    // extend current entry if needed
    if ((*pd)->end < offset + (uint8_t*)datalen - (*pd)->offset) {
      (*pd)->end = offset + (uint8_t*)datalen - (*pd)->offset;
    }
  } else {
    // fit new nul data entry around existing non-nul data
    if ((*pd)->offset + ((*pd)->end - (*pd)->begin) < offset + datalen) {
      size_t new_datalen = datalen;
      ngtcp2_rob_data *new_data;

      if ((*pd)->offset + ((*pd)->end - (*pd)->begin) > offset) {
        new_datalen -= (*pd)->offset + ((*pd)->end - (*pd)->begin) - offset;
        offset = (*pd)->offset + ((*pd)->end - (*pd)->begin);
      }

      rv = ngtcp2_rob_data_new_nul (&new_data, offset, new_datalen, rob->mem);
      if (rv != 0) {
        return;
      }

      new_data->next = (*pd)->next;
      (*pd)->next = new_data;
      pd = &(*pd)->next;
    }
  }

  // merge with or trim by next entry if adjacent or overlapping
  if ((*pd)->next &&
      (*pd)->offset + ((*pd)->end - (*pd)->begin) >= (*pd)->next->offset) {
    ngtcp2_rob_data *next_data = (*pd)->next;
    if (!(*pd)->next->begin) {
      // merge
      if ((*pd)->offset + (*pd)->end < next_data->offset + next_data->end) {
        (*pd)->end = next_data->offset + next_data->end - (*pd)->offset;
      }
      (*pd)->next = next_data->next;
      ngtcp2_rob_data_del (next_data, rob->mem);
    } else {
      // trim
      if ((*pd)->offset + (*pd)->end > (uint8_t*)(next_data->offset)) {
        (*pd)->end = (uint8_t*)(next_data->offset) - (*pd)->offset;
      }
    }
  }
}

size_t ngtcp2_rob_data_at(ngtcp2_rob *rob, const uint8_t **pdest,
                          uint64_t offset) {
  ngtcp2_rob_gap *g = rob->gap;
  ngtcp2_rob_data *d = rob->data;

  if (g->range.begin <= offset) {
    return 0;
  }

  assert(d);
  assert(d->offset <= offset);
  assert(offset < d->offset + rob->chunk);

  if (d->begin) {
    *pdest = d->begin + (offset - d->offset);
  } else {
    *pdest = NULL;
  }

  return ngtcp2_min(g->range.begin, d->offset + rob->chunk) - offset;
}

void ngtcp2_rob_pop(ngtcp2_rob *rob, uint64_t offset, size_t len) {
  ngtcp2_rob_data **pd = &rob->data;

  assert(*pd);

  if (offset + len < (*pd)->offset + rob->chunk) {
    return;
  }

  remove_data(pd, rob->mem);
}

uint64_t ngtcp2_rob_first_gap_offset(ngtcp2_rob *rob) {
  if (rob->gap) {
    return rob->gap->range.begin;
  }
  return UINT64_MAX;
}
