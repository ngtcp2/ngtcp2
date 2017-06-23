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

#include "ngtcp2_macro.h"

int ngtcp2_rob_data_new(ngtcp2_rob_data **prdat, uint64_t offset,
                        const uint8_t *data, size_t datalen, ngtcp2_mem *mem) {
  uint8_t *dest;

  *prdat = ngtcp2_mem_malloc(mem, sizeof(ngtcp2_rob_data) + datalen);
  if (*prdat == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  dest = ((uint8_t *)*prdat) + sizeof(ngtcp2_rob_data);
  memcpy(dest, data, datalen);

  (*prdat)->offset = offset;
  (*prdat)->data = dest;
  (*prdat)->datalen = datalen;

  return 0;
}

void ngtcp2_rob_data_del(ngtcp2_rob_data *rdat, ngtcp2_mem *mem) {
  ngtcp2_mem_free(mem, rdat);
}

static int offset_less(const void *lhsx, const void *rhsx) {
  const ngtcp2_rob_data *lhs, *rhs;

  lhs = ngtcp2_struct_of(lhsx, ngtcp2_rob_data, pq_entry);
  rhs = ngtcp2_struct_of(rhsx, ngtcp2_rob_data, pq_entry);

  return lhs->offset < rhs->offset;
}

int ngtcp2_rob_init(ngtcp2_rob *rob, ngtcp2_mem *mem) {
  int rv;

  rv = ngtcp2_pq_init(&rob->pq, offset_less, mem);
  if (rv != 0) {
    return rv;
  }

  rob->bufferedlen = 0;
  rob->mem = mem;

  return 0;
}

static int pq_rob_data_free(ngtcp2_pq_entry *item, void *arg) {
  ngtcp2_rob_data *rdat;
  ngtcp2_rob *rob;

  rdat = ngtcp2_struct_of(item, ngtcp2_rob_data, pq_entry);
  rob = arg;

  ngtcp2_rob_data_del(rdat, rob->mem);

  return 0;
}

void ngtcp2_rob_free(ngtcp2_rob *rob) {
  ngtcp2_pq_each(&rob->pq, pq_rob_data_free, rob);
  ngtcp2_pq_free(&rob->pq);
}

int ngtcp2_rob_push(ngtcp2_rob *rob, uint64_t offset, const uint8_t *data,
                    size_t datalen) {
  ngtcp2_rob_data *rdat;
  int rv;

  rv = ngtcp2_rob_data_new(&rdat, offset, data, datalen, rob->mem);
  if (rv != 0) {
    return rv;
  }

  rv = ngtcp2_pq_push(&rob->pq, &rdat->pq_entry);
  if (rv != 0) {
    ngtcp2_rob_data_del(rdat, rob->mem);
    return rv;
  }

  rob->bufferedlen += datalen;

  return 0;
}

size_t ngtcp2_rob_data_at(ngtcp2_rob *rob, const uint8_t **pdest,
                          uint64_t offset) {
  ngtcp2_rob_data *rdat;
  uint64_t delta;

  for (; !ngtcp2_pq_empty(&rob->pq);) {
    rdat = ngtcp2_struct_of(ngtcp2_pq_top(&rob->pq), ngtcp2_rob_data, pq_entry);
    if (offset < rdat->offset) {
      return 0;
    }

    delta = offset - rdat->offset;
    if (delta >= rdat->datalen) {
      ngtcp2_pq_pop(&rob->pq);
      rob->bufferedlen -= rdat->datalen;

      ngtcp2_rob_data_del(rdat, rob->mem);

      continue;
    }

    *pdest = rdat->data + delta;
    return rdat->datalen - delta;
  }

  return 0;
}

void ngtcp2_rob_pop(ngtcp2_rob *rob) {
  ngtcp2_rob_data *rdat;

  if (ngtcp2_pq_empty(&rob->pq)) {
    return;
  }

  rdat = ngtcp2_struct_of(ngtcp2_pq_top(&rob->pq), ngtcp2_rob_data, pq_entry);
  ngtcp2_pq_pop(&rob->pq);
  rob->bufferedlen -= rdat->datalen;

  ngtcp2_rob_data_del(rdat, rob->mem);
}
