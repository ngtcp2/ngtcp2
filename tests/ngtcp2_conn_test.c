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
#include "ngtcp2_conn_test.h"

#include <CUnit/CUnit.h>

#include "ngtcp2_conn.h"
#include "ngtcp2_test_helper.h"
#include "ngtcp2_mem.h"

static ssize_t null_encrypt(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                            const uint8_t *plaintext, size_t plaintextlen,
                            const uint8_t *key, size_t keylen,
                            const uint8_t *nonce, size_t noncelen,
                            const uint8_t *ad, size_t adlen, void *user_data) {
  (void)conn;
  (void)dest;
  (void)destlen;
  (void)plaintext;
  (void)key;
  (void)keylen;
  (void)nonce;
  (void)noncelen;
  (void)ad;
  (void)adlen;
  (void)user_data;
  return (ssize_t)plaintextlen;
}

static ssize_t null_decrypt(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                            const uint8_t *ciphertext, size_t ciphertextlen,
                            const uint8_t *key, size_t keylen,
                            const uint8_t *nonce, size_t noncelen,
                            const uint8_t *ad, size_t adlen, void *user_data) {
  (void)conn;
  (void)dest;
  (void)destlen;
  (void)ciphertext;
  (void)key;
  (void)keylen;
  (void)nonce;
  (void)noncelen;
  (void)ad;
  (void)adlen;
  (void)user_data;
  return (ssize_t)ciphertextlen;
}

static void server_default_settings(ngtcp2_settings *settings) {
  settings->max_stream_data = 65536;
  settings->max_data = 128;
  settings->max_stream_id = 3;
  settings->idle_timeout = 60;
  settings->omit_connection_id = 0;
  settings->max_packet_size = 65535;
}

static uint8_t null_key[16];
static uint8_t null_iv[16];
static uint8_t null_data[4096];

void test_ngtcp2_conn_stream_open_close(void) {
  ngtcp2_conn *conn;
  ngtcp2_conn_callbacks cb;
  ngtcp2_settings settings;
  uint8_t buf[2048];
  size_t pktlen;
  ssize_t spktlen;
  int rv;
  ngtcp2_frame fr;
  ngtcp2_strm *strm;

  cb.decrypt = null_decrypt;
  cb.encrypt = null_encrypt;
  server_default_settings(&settings);

  ngtcp2_conn_server_new(&conn, 0x1, NGTCP2_PROTO_VERSION, &cb, &settings,
                         NULL);
  ngtcp2_conn_update_tx_keys(conn, null_key, sizeof(null_key), null_iv,
                             sizeof(null_iv));
  ngtcp2_conn_update_rx_keys(conn, null_key, sizeof(null_key), null_iv,
                             sizeof(null_iv));
  conn->state = NGTCP2_CS_POST_HANDSHAKE;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 1;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datalen = 17;
  fr.stream.data = null_data;

  pktlen = write_stream_pkt(conn, buf, sizeof(buf), 0xc, 1, &fr);

  rv = ngtcp2_conn_recv(conn, buf, pktlen, 1);

  CU_ASSERT(0 == rv);

  strm = ngtcp2_conn_find_stream(conn, 1);

  CU_ASSERT(NGTCP2_STRM_FLAG_NONE == strm->flags);

  fr.stream.fin = 1;
  fr.stream.offset = 17;
  fr.stream.datalen = 0;

  pktlen = write_stream_pkt(conn, buf, sizeof(buf), 0xc, 2, &fr);

  rv = ngtcp2_conn_recv(conn, buf, pktlen, 2);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NGTCP2_STRM_FLAG_SHUT_RD == strm->flags);
  CU_ASSERT(fr.stream.offset == strm->last_rx_offset);
  CU_ASSERT(fr.stream.offset == ngtcp2_strm_rx_offset(strm));

  spktlen =
      ngtcp2_conn_write_stream(conn, buf, sizeof(buf), NULL, 1, 1, NULL, 0, 3);

  CU_ASSERT(spktlen > 0);

  strm = ngtcp2_conn_find_stream(conn, 1);

  CU_ASSERT(NULL == strm);

  ngtcp2_conn_del(conn);
}
