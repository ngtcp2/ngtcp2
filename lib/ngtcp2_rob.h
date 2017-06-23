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
#ifndef NGTCP2_ROB_H
#define NGTCP2_ROB_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <ngtcp2/ngtcp2.h>

#include "ngtcp2_mem.h"
#include "ngtcp2_pq.h"

typedef struct {
  ngtcp2_pq_entry pq_entry;
  uint64_t offset;
  uint8_t *data;
  size_t datalen;
} ngtcp2_rob_data;

int ngtcp2_rob_data_new(ngtcp2_rob_data **prdat, uint64_t offset,
                        const uint8_t *data, size_t datalen, ngtcp2_mem *mem);

void ngtcp2_rob_data_del(ngtcp2_rob_data *rdat, ngtcp2_mem *mem);

/*
 * ngtcp2_rob reassembles stream data received in out of order.
 *
 * TODO The current implementation is very inefficient.  It should be
 * redesigned to reduce memory foot print, and avoid dead lock issue.
 */
typedef struct {
  ngtcp2_pq pq;
  ngtcp2_mem *mem;
  uint64_t bufferedlen;
} ngtcp2_rob;

int ngtcp2_rob_init(ngtcp2_rob *rob, ngtcp2_mem *mem);

void ngtcp2_rob_free(ngtcp2_rob *rob);

int ngtcp2_rob_push(ngtcp2_rob *rob, uint64_t offset, const uint8_t *data,
                    size_t datalen);

size_t ngtcp2_rob_data_at(ngtcp2_rob *rob, const uint8_t **pdest,
                          uint64_t offset);

void ngtcp2_rob_pop(ngtcp2_rob *rob);

#endif /* NGTCP2_ROB_H */
