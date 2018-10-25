/*
 * ngtcp2
 *
 * Copyright (c) 2018 ngtcp2 contributors
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
#include "ngtcp2_strm_test.h"

#include <CUnit/CUnit.h>

#include "ngtcp2_strm.h"
#include "ngtcp2_test_helper.h"

static uint8_t nulldata[1024];

static void setup_strm_streamfrq_fixture(ngtcp2_strm *strm, ngtcp2_mem *mem) {
  ngtcp2_stream_frame_chain *frc;
  ngtcp2_vec *data;

  ngtcp2_strm_init(strm, 0, NGTCP2_STRM_FLAG_NONE, 0, 0, NULL, mem);

  ngtcp2_stream_frame_chain_new(&frc, mem);
  frc->fr.type = NGTCP2_FRAME_STREAM;
  frc->fr.fin = 0;
  frc->fr.offset = 0;
  frc->fr.datacnt = 2;
  data = frc->fr.data;
  data[0].len = 11;
  data[0].base = nulldata;
  data[1].len = 19;
  data[1].base = nulldata + 11;

  ngtcp2_strm_streamfrq_push(strm, frc);

  ngtcp2_stream_frame_chain_new(&frc, mem);
  frc->fr.type = NGTCP2_FRAME_STREAM;
  frc->fr.fin = 0;
  frc->fr.offset = 30;
  frc->fr.datacnt = 2;
  data = frc->fr.data;
  data[0].len = 17;
  data[0].base = nulldata + 30;
  data[1].len = 29;
  data[1].base = nulldata + 30 + 17;

  ngtcp2_strm_streamfrq_push(strm, frc);

  ngtcp2_stream_frame_chain_new(&frc, mem);
  frc->fr.type = NGTCP2_FRAME_STREAM;
  frc->fr.fin = 0;
  frc->fr.offset = 76;
  frc->fr.datacnt = 2;
  data = frc->fr.data;
  data[0].len = 31;
  data[0].base = nulldata + 256;
  data[1].len = 1;
  data[1].base = nulldata + 512;

  ngtcp2_strm_streamfrq_push(strm, frc);
}

void test_ngtcp2_strm_streamfrq_pop(void) {
  ngtcp2_strm strm;
  ngtcp2_stream_frame_chain *frc;
  ngtcp2_mem *mem = ngtcp2_mem_default();
  int rv;
  ngtcp2_vec *data;

  /* Get first chain */
  setup_strm_streamfrq_fixture(&strm, mem);

  frc = NULL;
  rv = ngtcp2_strm_streamfrq_pop(&strm, &frc, 30);

  CU_ASSERT(0 == rv);
  CU_ASSERT(2 == frc->fr.datacnt);

  data = frc->fr.data;

  CU_ASSERT(11 == data[0].len);
  CU_ASSERT(19 == data[1].len);
  CU_ASSERT(2 == ngtcp2_pq_size(&strm.streamfrq));

  ngtcp2_stream_frame_chain_del(frc, mem);
  ngtcp2_strm_free(&strm);

  /* Get merged chain */
  setup_strm_streamfrq_fixture(&strm, mem);

  frc = NULL;
  rv = ngtcp2_strm_streamfrq_pop(&strm, &frc, 76);

  CU_ASSERT(0 == rv);
  CU_ASSERT(2 == frc->fr.datacnt);

  data = frc->fr.data;

  CU_ASSERT(11 == data[0].len);
  CU_ASSERT(19 + 46 == data[1].len);
  CU_ASSERT(1 == ngtcp2_pq_size(&strm.streamfrq));

  ngtcp2_stream_frame_chain_del(frc, mem);
  ngtcp2_strm_free(&strm);

  /* Get merged chain partially */
  setup_strm_streamfrq_fixture(&strm, mem);

  frc = NULL;
  rv = ngtcp2_strm_streamfrq_pop(&strm, &frc, 75);

  CU_ASSERT(0 == rv);
  CU_ASSERT(2 == frc->fr.datacnt);

  data = frc->fr.data;

  CU_ASSERT(11 == data[0].len);
  CU_ASSERT(19 + 45 == data[1].len);
  CU_ASSERT(2 == ngtcp2_pq_size(&strm.streamfrq));

  ngtcp2_stream_frame_chain_del(frc, mem);

  frc = NULL;
  rv = ngtcp2_strm_streamfrq_pop(&strm, &frc, 1);

  CU_ASSERT(0 == rv);
  CU_ASSERT(75 == frc->fr.offset);
  CU_ASSERT(1 == frc->fr.datacnt);
  CU_ASSERT(1 == frc->fr.data[0].len);
  CU_ASSERT(nulldata + 30 + 17 + 28 == frc->fr.data[0].base);

  ngtcp2_stream_frame_chain_del(frc, mem);
  ngtcp2_strm_free(&strm);

  /* Not continuous merge */
  setup_strm_streamfrq_fixture(&strm, mem);

  frc = NULL;
  rv = ngtcp2_strm_streamfrq_pop(&strm, &frc, 77);

  CU_ASSERT(0 == rv);
  CU_ASSERT(3 == frc->fr.datacnt);

  data = frc->fr.data;

  CU_ASSERT(11 == data[0].len);
  CU_ASSERT(19 + 46 == data[1].len);
  CU_ASSERT(1 == data[2].len);
  CU_ASSERT(nulldata + 256 == data[2].base);
  CU_ASSERT(1 == ngtcp2_pq_size(&strm.streamfrq));

  ngtcp2_stream_frame_chain_del(frc, mem);

  frc = NULL;
  rv = ngtcp2_strm_streamfrq_pop(&strm, &frc, 1024);

  CU_ASSERT(0 == rv);
  CU_ASSERT(77 == frc->fr.offset);
  CU_ASSERT(2 == frc->fr.datacnt);

  data = frc->fr.data;

  CU_ASSERT(30 == data[0].len);
  CU_ASSERT(nulldata + 256 + 1 == data[0].base);

  ngtcp2_stream_frame_chain_del(frc, mem);
  ngtcp2_strm_free(&strm);

  /* offset gap */
  ngtcp2_strm_init(&strm, 0, NGTCP2_STRM_FLAG_NONE, 0, 0, NULL, mem);

  ngtcp2_stream_frame_chain_new(&frc, mem);
  frc->fr.type = NGTCP2_FRAME_STREAM;
  frc->fr.fin = 0;
  frc->fr.offset = 0;
  frc->fr.datacnt = 1;
  data = frc->fr.data;
  data[0].len = 11;
  data[0].base = nulldata;

  ngtcp2_strm_streamfrq_push(&strm, frc);

  ngtcp2_stream_frame_chain_new(&frc, mem);
  frc->fr.type = NGTCP2_FRAME_STREAM;
  frc->fr.fin = 0;
  frc->fr.offset = 30;
  frc->fr.datacnt = 1;
  data = frc->fr.data;
  data[0].len = 17;
  data[0].base = nulldata + 30;

  ngtcp2_strm_streamfrq_push(&strm, frc);

  frc = NULL;
  rv = ngtcp2_strm_streamfrq_pop(&strm, &frc, 1024);

  CU_ASSERT(0 == rv);
  CU_ASSERT(1 == frc->fr.datacnt);
  CU_ASSERT(11 == frc->fr.data[0].len);
  CU_ASSERT(1 == ngtcp2_pq_size(&strm.streamfrq));

  ngtcp2_stream_frame_chain_del(frc, mem);
  ngtcp2_strm_free(&strm);

  /* fin */
  ngtcp2_strm_init(&strm, 0, NGTCP2_STRM_FLAG_NONE, 0, 0, NULL, mem);

  ngtcp2_stream_frame_chain_new(&frc, mem);
  frc->fr.type = NGTCP2_FRAME_STREAM;
  frc->fr.fin = 0;
  frc->fr.offset = 0;
  frc->fr.datacnt = 1;
  data = frc->fr.data;
  data[0].len = 11;
  data[0].base = nulldata;

  ngtcp2_strm_streamfrq_push(&strm, frc);

  ngtcp2_stream_frame_chain_new(&frc, mem);
  frc->fr.type = NGTCP2_FRAME_STREAM;
  frc->fr.fin = 1;
  frc->fr.offset = 11;
  frc->fr.datacnt = 0;

  ngtcp2_strm_streamfrq_push(&strm, frc);

  frc = NULL;
  rv = ngtcp2_strm_streamfrq_pop(&strm, &frc, 1024);

  CU_ASSERT(0 == rv);
  CU_ASSERT(1 == frc->fr.fin);
  CU_ASSERT(1 == frc->fr.datacnt);

  ngtcp2_stream_frame_chain_del(frc, mem);
  ngtcp2_strm_free(&strm);
}
