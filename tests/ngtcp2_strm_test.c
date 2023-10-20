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

#include <stdio.h>

#include <CUnit/CUnit.h>

#include "ngtcp2_strm.h"
#include "ngtcp2_test_helper.h"
#include "ngtcp2_vec.h"
#include "ngtcp2_frame_chain.h"

static uint8_t nulldata[1024];

static void setup_strm_streamfrq_fixture(ngtcp2_strm *strm,
                                         ngtcp2_objalloc *frc_objalloc,
                                         const ngtcp2_mem *mem) {
  ngtcp2_frame_chain *frc;
  ngtcp2_vec *data;

  ngtcp2_strm_init(strm, 0, NGTCP2_STRM_FLAG_NONE, 0, 0, NULL, frc_objalloc,
                   mem);

  ngtcp2_frame_chain_stream_datacnt_objalloc_new(&frc, 2, frc_objalloc, mem);
  frc->fr.stream.type = NGTCP2_FRAME_STREAM;
  frc->fr.stream.fin = 0;
  frc->fr.stream.offset = 0;
  frc->fr.stream.datacnt = 2;
  data = frc->fr.stream.data;
  data[0].len = 11;
  data[0].base = nulldata;
  data[1].len = 19;
  data[1].base = nulldata + 11;

  ngtcp2_strm_streamfrq_push(strm, frc);

  ngtcp2_frame_chain_stream_datacnt_objalloc_new(&frc, 2, frc_objalloc, mem);
  frc->fr.stream.type = NGTCP2_FRAME_STREAM;
  frc->fr.stream.fin = 0;
  frc->fr.stream.offset = 30;
  frc->fr.stream.datacnt = 2;
  data = frc->fr.stream.data;
  data[0].len = 17;
  data[0].base = nulldata + 30;
  data[1].len = 29;
  data[1].base = nulldata + 30 + 17;

  ngtcp2_strm_streamfrq_push(strm, frc);

  ngtcp2_frame_chain_stream_datacnt_objalloc_new(&frc, 2, frc_objalloc, mem);
  frc->fr.stream.type = NGTCP2_FRAME_STREAM;
  frc->fr.stream.fin = 0;
  frc->fr.stream.offset = 76;
  frc->fr.stream.datacnt = 2;
  data = frc->fr.stream.data;
  data[0].len = 31;
  data[0].base = nulldata + 256;
  data[1].len = 1;
  data[1].base = nulldata + 512;

  ngtcp2_strm_streamfrq_push(strm, frc);
}

void test_ngtcp2_strm_streamfrq_pop(void) {
  ngtcp2_strm strm;
  ngtcp2_frame_chain *frc;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  int rv;
  ngtcp2_vec *data;
  ngtcp2_objalloc frc_objalloc;

  ngtcp2_objalloc_init(&frc_objalloc, 1024, mem);

  /* Get first chain */
  setup_strm_streamfrq_fixture(&strm, &frc_objalloc, mem);

  frc = NULL;
  rv = ngtcp2_strm_streamfrq_pop(&strm, &frc, 30);

  CU_ASSERT(0 == rv);
  CU_ASSERT(2 == frc->fr.stream.datacnt);

  data = frc->fr.stream.data;

  CU_ASSERT(11 == data[0].len);
  CU_ASSERT(19 == data[1].len);
  CU_ASSERT(2 == ngtcp2_ksl_len(strm.tx.streamfrq));

  ngtcp2_frame_chain_objalloc_del(frc, &frc_objalloc, mem);
  ngtcp2_strm_free(&strm);

  /* Get merged chain */
  setup_strm_streamfrq_fixture(&strm, &frc_objalloc, mem);

  frc = NULL;
  rv = ngtcp2_strm_streamfrq_pop(&strm, &frc, 76);

  CU_ASSERT(0 == rv);
  CU_ASSERT(2 == frc->fr.stream.datacnt);

  data = frc->fr.stream.data;

  CU_ASSERT(11 == data[0].len);
  CU_ASSERT(19 + 46 == data[1].len);
  CU_ASSERT(1 == ngtcp2_ksl_len(strm.tx.streamfrq));

  ngtcp2_frame_chain_objalloc_del(frc, &frc_objalloc, mem);
  ngtcp2_strm_free(&strm);

  /* Get merged chain partially */
  setup_strm_streamfrq_fixture(&strm, &frc_objalloc, mem);

  frc = NULL;
  rv = ngtcp2_strm_streamfrq_pop(&strm, &frc, 75);

  CU_ASSERT(0 == rv);
  CU_ASSERT(2 == frc->fr.stream.datacnt);

  data = frc->fr.stream.data;

  CU_ASSERT(11 == data[0].len);
  CU_ASSERT(19 + 45 == data[1].len);
  CU_ASSERT(2 == ngtcp2_ksl_len(strm.tx.streamfrq));

  ngtcp2_frame_chain_objalloc_del(frc, &frc_objalloc, mem);

  frc = NULL;
  rv = ngtcp2_strm_streamfrq_pop(&strm, &frc, 1);

  CU_ASSERT(0 == rv);
  CU_ASSERT(75 == frc->fr.stream.offset);
  CU_ASSERT(1 == frc->fr.stream.datacnt);
  CU_ASSERT(1 == frc->fr.stream.data[0].len);
  CU_ASSERT(nulldata + 30 + 17 + 28 == frc->fr.stream.data[0].base);

  ngtcp2_frame_chain_objalloc_del(frc, &frc_objalloc, mem);
  ngtcp2_strm_free(&strm);

  /* Not continuous merge */
  setup_strm_streamfrq_fixture(&strm, &frc_objalloc, mem);

  frc = NULL;
  rv = ngtcp2_strm_streamfrq_pop(&strm, &frc, 77);

  CU_ASSERT(0 == rv);
  CU_ASSERT(3 == frc->fr.stream.datacnt);

  data = frc->fr.stream.data;

  CU_ASSERT(11 == data[0].len);
  CU_ASSERT(19 + 46 == data[1].len);
  CU_ASSERT(1 == data[2].len);
  CU_ASSERT(nulldata + 256 == data[2].base);
  CU_ASSERT(1 == ngtcp2_ksl_len(strm.tx.streamfrq));

  ngtcp2_frame_chain_objalloc_del(frc, &frc_objalloc, mem);

  frc = NULL;
  rv = ngtcp2_strm_streamfrq_pop(&strm, &frc, 1024);

  CU_ASSERT(0 == rv);
  CU_ASSERT(77 == frc->fr.stream.offset);
  CU_ASSERT(2 == frc->fr.stream.datacnt);

  data = frc->fr.stream.data;

  CU_ASSERT(30 == data[0].len);
  CU_ASSERT(nulldata + 256 + 1 == data[0].base);

  ngtcp2_frame_chain_objalloc_del(frc, &frc_objalloc, mem);
  ngtcp2_strm_free(&strm);

  /* split; continuous */
  setup_strm_streamfrq_fixture(&strm, &frc_objalloc, mem);

  frc = NULL;
  rv = ngtcp2_strm_streamfrq_pop(&strm, &frc, 12);

  CU_ASSERT(0 == rv);
  CU_ASSERT(0 == frc->fr.stream.offset);
  CU_ASSERT(2 == frc->fr.stream.datacnt);

  data = frc->fr.stream.data;

  CU_ASSERT(11 == data[0].len);
  CU_ASSERT(nulldata == data[0].base);
  CU_ASSERT(1 == data[1].len);
  CU_ASSERT(nulldata + 11 == data[1].base);

  ngtcp2_frame_chain_objalloc_del(frc, &frc_objalloc, mem);

  frc = NULL;
  rv = ngtcp2_strm_streamfrq_pop(&strm, &frc, 1024);

  CU_ASSERT(0 == rv);
  CU_ASSERT(12 == frc->fr.stream.offset);
  CU_ASSERT(3 == frc->fr.stream.datacnt);

  data = frc->fr.stream.data;

  CU_ASSERT(64 == data[0].len);
  CU_ASSERT(nulldata + 12 == data[0].base);
  CU_ASSERT(31 == data[1].len);
  CU_ASSERT(nulldata + 256 == data[1].base);
  CU_ASSERT(1 == data[2].len);
  CU_ASSERT(nulldata + 512 == data[2].base);

  ngtcp2_frame_chain_objalloc_del(frc, &frc_objalloc, mem);
  ngtcp2_strm_free(&strm);

  /* offset gap */
  ngtcp2_strm_init(&strm, 0, NGTCP2_STRM_FLAG_NONE, 0, 0, NULL, &frc_objalloc,
                   mem);

  ngtcp2_frame_chain_stream_datacnt_objalloc_new(&frc, 1, &frc_objalloc, mem);
  frc->fr.stream.type = NGTCP2_FRAME_STREAM;
  frc->fr.stream.fin = 0;
  frc->fr.stream.offset = 0;
  frc->fr.stream.datacnt = 1;
  data = frc->fr.stream.data;
  data[0].len = 11;
  data[0].base = nulldata;

  ngtcp2_strm_streamfrq_push(&strm, frc);

  ngtcp2_frame_chain_stream_datacnt_objalloc_new(&frc, 1, &frc_objalloc, mem);
  frc->fr.stream.type = NGTCP2_FRAME_STREAM;
  frc->fr.stream.fin = 0;
  frc->fr.stream.offset = 30;
  frc->fr.stream.datacnt = 1;
  data = frc->fr.stream.data;
  data[0].len = 17;
  data[0].base = nulldata + 30;

  ngtcp2_strm_streamfrq_push(&strm, frc);

  frc = NULL;
  rv = ngtcp2_strm_streamfrq_pop(&strm, &frc, 1024);

  CU_ASSERT(0 == rv);
  CU_ASSERT(1 == frc->fr.stream.datacnt);
  CU_ASSERT(11 == frc->fr.stream.data[0].len);
  CU_ASSERT(1 == ngtcp2_ksl_len(strm.tx.streamfrq));

  ngtcp2_frame_chain_objalloc_del(frc, &frc_objalloc, mem);
  ngtcp2_strm_free(&strm);

  /* fin */
  ngtcp2_strm_init(&strm, 0, NGTCP2_STRM_FLAG_NONE, 0, 0, NULL, &frc_objalloc,
                   mem);

  ngtcp2_frame_chain_stream_datacnt_objalloc_new(&frc, 1, &frc_objalloc, mem);
  frc->fr.stream.type = NGTCP2_FRAME_STREAM;
  frc->fr.stream.fin = 0;
  frc->fr.stream.offset = 0;
  frc->fr.stream.datacnt = 1;
  data = frc->fr.stream.data;
  data[0].len = 11;
  data[0].base = nulldata;

  ngtcp2_strm_streamfrq_push(&strm, frc);

  ngtcp2_frame_chain_stream_datacnt_objalloc_new(&frc, 0, &frc_objalloc, mem);
  frc->fr.stream.type = NGTCP2_FRAME_STREAM;
  frc->fr.stream.fin = 1;
  frc->fr.stream.offset = 11;
  frc->fr.stream.datacnt = 0;

  ngtcp2_strm_streamfrq_push(&strm, frc);

  frc = NULL;
  rv = ngtcp2_strm_streamfrq_pop(&strm, &frc, 1024);

  CU_ASSERT(0 == rv);
  CU_ASSERT(1 == frc->fr.stream.fin);
  CU_ASSERT(1 == frc->fr.stream.datacnt);

  ngtcp2_frame_chain_objalloc_del(frc, &frc_objalloc, mem);
  ngtcp2_strm_free(&strm);

  /* left == 0 and there is outstanding data */
  setup_strm_streamfrq_fixture(&strm, &frc_objalloc, mem);

  frc = NULL;
  rv = ngtcp2_strm_streamfrq_pop(&strm, &frc, 0);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL == frc);

  ngtcp2_strm_free(&strm);

  ngtcp2_objalloc_free(&frc_objalloc);
}

void test_ngtcp2_strm_streamfrq_unacked_offset(void) {
  ngtcp2_strm strm;
  ngtcp2_frame_chain *frc;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_vec *data;
  ngtcp2_objalloc frc_objalloc;

  ngtcp2_objalloc_init(&frc_objalloc, 1024, mem);

  /* Everything acknowledged including fin */
  ngtcp2_strm_init(&strm, 0, NGTCP2_STRM_FLAG_FIN_ACKED, 0, 0, NULL,
                   &frc_objalloc, mem);

  ngtcp2_frame_chain_stream_datacnt_objalloc_new(&frc, 1, &frc_objalloc, mem);
  frc->fr.stream.type = NGTCP2_FRAME_STREAM;
  frc->fr.stream.fin = 0;
  frc->fr.stream.offset = 0;
  frc->fr.stream.datacnt = 1;
  data = frc->fr.stream.data;
  data[0].len = 17;
  data[0].base = nulldata;

  ngtcp2_strm_streamfrq_push(&strm, frc);

  ngtcp2_frame_chain_stream_datacnt_objalloc_new(&frc, 1, &frc_objalloc, mem);
  frc->fr.stream.type = NGTCP2_FRAME_STREAM;
  frc->fr.stream.fin = 1;
  frc->fr.stream.offset = 443;
  frc->fr.stream.datacnt = 1;
  data = frc->fr.stream.data;
  data[0].len = 971;
  data[0].base = nulldata;

  ngtcp2_strm_streamfrq_push(&strm, frc);

  ngtcp2_strm_ack_data(&strm, 0, 443 + 971);

  CU_ASSERT((uint64_t)-1 == ngtcp2_strm_streamfrq_unacked_offset(&strm));

  ngtcp2_strm_free(&strm);

  /* Everything acknowledged but fin */
  ngtcp2_strm_init(&strm, 0, NGTCP2_STRM_FLAG_NONE, 0, 0, NULL, &frc_objalloc,
                   mem);

  ngtcp2_frame_chain_stream_datacnt_objalloc_new(&frc, 1, &frc_objalloc, mem);
  frc->fr.stream.type = NGTCP2_FRAME_STREAM;
  frc->fr.stream.fin = 0;
  frc->fr.stream.offset = 0;
  frc->fr.stream.datacnt = 1;
  data = frc->fr.stream.data;
  data[0].len = 17;
  data[0].base = nulldata;

  ngtcp2_strm_streamfrq_push(&strm, frc);

  ngtcp2_frame_chain_stream_datacnt_objalloc_new(&frc, 1, &frc_objalloc, mem);
  frc->fr.stream.type = NGTCP2_FRAME_STREAM;
  frc->fr.stream.fin = 1;
  frc->fr.stream.offset = 443;
  frc->fr.stream.datacnt = 1;
  data = frc->fr.stream.data;
  data[0].len = 971;
  data[0].base = nulldata;

  ngtcp2_strm_streamfrq_push(&strm, frc);

  ngtcp2_strm_ack_data(&strm, 0, 443 + 971);

  CU_ASSERT(443 + 971 == ngtcp2_strm_streamfrq_unacked_offset(&strm));

  ngtcp2_strm_free(&strm);

  /* Unacked gap starts in the middle of stream to resend */
  ngtcp2_strm_init(&strm, 0, NGTCP2_STRM_FLAG_NONE, 0, 0, NULL, &frc_objalloc,
                   mem);

  ngtcp2_frame_chain_stream_datacnt_objalloc_new(&frc, 1, &frc_objalloc, mem);
  frc->fr.stream.type = NGTCP2_FRAME_STREAM;
  frc->fr.stream.fin = 0;
  frc->fr.stream.offset = 0;
  frc->fr.stream.datacnt = 1;
  data = frc->fr.stream.data;
  data[0].len = 971;
  data[0].base = nulldata;

  ngtcp2_strm_streamfrq_push(&strm, frc);

  ngtcp2_strm_ack_data(&strm, 0, 443);

  CU_ASSERT(443 == ngtcp2_strm_streamfrq_unacked_offset(&strm));

  ngtcp2_strm_free(&strm);

  /* Unacked gap starts after stream to resend */
  ngtcp2_strm_init(&strm, 0, NGTCP2_STRM_FLAG_NONE, 0, 0, NULL, &frc_objalloc,
                   mem);

  ngtcp2_frame_chain_stream_datacnt_objalloc_new(&frc, 1, &frc_objalloc, mem);
  frc->fr.stream.type = NGTCP2_FRAME_STREAM;
  frc->fr.stream.fin = 0;
  frc->fr.stream.offset = 0;
  frc->fr.stream.datacnt = 1;
  data = frc->fr.stream.data;
  data[0].len = 971;
  data[0].base = nulldata;

  ngtcp2_strm_streamfrq_push(&strm, frc);

  ngtcp2_strm_ack_data(&strm, 0, 971);

  CU_ASSERT((uint64_t)-1 == ngtcp2_strm_streamfrq_unacked_offset(&strm));

  ngtcp2_strm_free(&strm);

  /* Unacked gap and stream overlap and gap starts before stream */
  ngtcp2_strm_init(&strm, 0, NGTCP2_STRM_FLAG_NONE, 0, 0, NULL, &frc_objalloc,
                   mem);

  ngtcp2_frame_chain_stream_datacnt_objalloc_new(&frc, 1, &frc_objalloc, mem);
  frc->fr.stream.type = NGTCP2_FRAME_STREAM;
  frc->fr.stream.fin = 0;
  frc->fr.stream.offset = 977;
  frc->fr.stream.datacnt = 1;
  data = frc->fr.stream.data;
  data[0].len = 971;
  data[0].base = nulldata;

  ngtcp2_strm_streamfrq_push(&strm, frc);

  ngtcp2_strm_ack_data(&strm, 0, 971);

  CU_ASSERT(977 == ngtcp2_strm_streamfrq_unacked_offset(&strm));

  ngtcp2_strm_free(&strm);

  ngtcp2_objalloc_free(&frc_objalloc);
}

void test_ngtcp2_strm_streamfrq_unacked_pop(void) {
  ngtcp2_strm strm;
  ngtcp2_frame_chain *frc;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_vec *data;
  int rv;
  ngtcp2_objalloc frc_objalloc;

  ngtcp2_objalloc_init(&frc_objalloc, 1024, mem);

  /* Everything acknowledged including fin */
  ngtcp2_strm_init(&strm, 0, NGTCP2_STRM_FLAG_FIN_ACKED, 0, 0, NULL,
                   &frc_objalloc, mem);

  ngtcp2_frame_chain_stream_datacnt_objalloc_new(&frc, 1, &frc_objalloc, mem);
  frc->fr.stream.type = NGTCP2_FRAME_STREAM;
  frc->fr.stream.fin = 0;
  frc->fr.stream.offset = 307;
  frc->fr.stream.datacnt = 1;
  data = frc->fr.stream.data;
  data[0].len = 149;
  data[0].base = nulldata;

  ngtcp2_strm_streamfrq_push(&strm, frc);

  ngtcp2_frame_chain_stream_datacnt_objalloc_new(&frc, 1, &frc_objalloc, mem);
  frc->fr.stream.type = NGTCP2_FRAME_STREAM;
  frc->fr.stream.fin = 1;
  frc->fr.stream.offset = 457;
  frc->fr.stream.datacnt = 1;
  data = frc->fr.stream.data;
  data[0].len = 307;
  data[0].base = nulldata;

  ngtcp2_strm_streamfrq_push(&strm, frc);

  ngtcp2_strm_ack_data(&strm, 0, 764);

  frc = NULL;
  rv = ngtcp2_strm_streamfrq_pop(&strm, &frc, 1024);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL == frc);

  ngtcp2_strm_free(&strm);

  /* Everything acknowledged but fin */
  ngtcp2_strm_init(&strm, 0, NGTCP2_STRM_FLAG_NONE, 0, 0, NULL, &frc_objalloc,
                   mem);

  ngtcp2_frame_chain_stream_datacnt_objalloc_new(&frc, 1, &frc_objalloc, mem);
  frc->fr.stream.type = NGTCP2_FRAME_STREAM;
  frc->fr.stream.fin = 0;
  frc->fr.stream.offset = 307;
  frc->fr.stream.datacnt = 1;
  data = frc->fr.stream.data;
  data[0].len = 149;
  data[0].base = nulldata;

  ngtcp2_strm_streamfrq_push(&strm, frc);

  ngtcp2_frame_chain_stream_datacnt_objalloc_new(&frc, 1, &frc_objalloc, mem);
  frc->fr.stream.type = NGTCP2_FRAME_STREAM;
  frc->fr.stream.fin = 1;
  frc->fr.stream.offset = 457;
  frc->fr.stream.datacnt = 1;
  data = frc->fr.stream.data;
  data[0].len = 307;
  data[0].base = nulldata;

  ngtcp2_strm_streamfrq_push(&strm, frc);

  ngtcp2_strm_ack_data(&strm, 0, 764);

  frc = NULL;
  rv = ngtcp2_strm_streamfrq_pop(&strm, &frc, 1024);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NGTCP2_FRAME_STREAM == frc->fr.type);
  CU_ASSERT(1 == frc->fr.stream.fin);
  CU_ASSERT(764 == frc->fr.stream.offset);
  CU_ASSERT(0 == ngtcp2_vec_len(frc->fr.stream.data, frc->fr.stream.datacnt));

  ngtcp2_frame_chain_objalloc_del(frc, &frc_objalloc, mem);
  ngtcp2_strm_free(&strm);

  /* Remove leading acknowledged data */
  setup_strm_streamfrq_fixture(&strm, &frc_objalloc, mem);

  ngtcp2_strm_ack_data(&strm, 0, 12);

  rv = ngtcp2_strm_streamfrq_pop(&strm, &frc, 43);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NGTCP2_FRAME_STREAM == frc->fr.type);
  CU_ASSERT(0 == frc->fr.stream.fin);
  CU_ASSERT(12 == frc->fr.stream.offset);
  CU_ASSERT(1 == frc->fr.stream.datacnt);
  CU_ASSERT(43 == ngtcp2_vec_len(frc->fr.stream.data, frc->fr.stream.datacnt));

  ngtcp2_frame_chain_objalloc_del(frc, &frc_objalloc, mem);
  ngtcp2_strm_free(&strm);

  /* Creating a gap of acknowledged data */
  setup_strm_streamfrq_fixture(&strm, &frc_objalloc, mem);

  ngtcp2_strm_ack_data(&strm, 32, 1);

  rv = ngtcp2_strm_streamfrq_pop(&strm, &frc, 43);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NGTCP2_FRAME_STREAM == frc->fr.type);
  CU_ASSERT(0 == frc->fr.stream.fin);
  CU_ASSERT(0 == frc->fr.stream.offset);
  CU_ASSERT(2 == frc->fr.stream.datacnt);
  CU_ASSERT(32 == ngtcp2_vec_len(frc->fr.stream.data, frc->fr.stream.datacnt));

  ngtcp2_frame_chain_objalloc_del(frc, &frc_objalloc, mem);
  ngtcp2_strm_free(&strm);

  ngtcp2_objalloc_free(&frc_objalloc);
}
