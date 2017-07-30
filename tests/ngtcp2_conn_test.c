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
  settings->max_stream_data = 65535;
  settings->max_data = 128;
  settings->max_stream_id = 5;
  settings->idle_timeout = 60;
  settings->omit_connection_id = 0;
  settings->max_packet_size = 65535;
}

static void client_default_settings(ngtcp2_settings *settings) {
  settings->max_stream_data = 65535;
  settings->max_data = 128;
  settings->max_stream_id = 0;
  settings->idle_timeout = 60;
  settings->omit_connection_id = 0;
  settings->max_packet_size = 65535;
}

static uint8_t null_key[16];
static uint8_t null_iv[16];
static uint8_t null_data[4096];

static void setup_default_server(ngtcp2_conn **pconn) {
  ngtcp2_conn_callbacks cb;
  ngtcp2_settings settings;

  memset(&cb, 0, sizeof(cb));
  cb.decrypt = null_decrypt;
  cb.encrypt = null_encrypt;
  server_default_settings(&settings);

  ngtcp2_conn_server_new(pconn, 0x1, NGTCP2_PROTO_VERSION, &cb, &settings,
                         NULL);
  ngtcp2_conn_update_tx_keys(*pconn, null_key, sizeof(null_key), null_iv,
                             sizeof(null_iv));
  ngtcp2_conn_update_rx_keys(*pconn, null_key, sizeof(null_key), null_iv,
                             sizeof(null_iv));
  (*pconn)->state = NGTCP2_CS_POST_HANDSHAKE;
}

static void setup_default_client(ngtcp2_conn **pconn) {
  ngtcp2_conn_callbacks cb;
  ngtcp2_settings settings;

  memset(&cb, 0, sizeof(cb));
  cb.decrypt = null_decrypt;
  cb.encrypt = null_encrypt;
  client_default_settings(&settings);

  ngtcp2_conn_client_new(pconn, 0x1, NGTCP2_PROTO_VERSION, &cb, &settings,
                         NULL);
  ngtcp2_conn_update_tx_keys(*pconn, null_key, sizeof(null_key), null_iv,
                             sizeof(null_iv));
  ngtcp2_conn_update_rx_keys(*pconn, null_key, sizeof(null_key), null_iv,
                             sizeof(null_iv));
  (*pconn)->state = NGTCP2_CS_POST_HANDSHAKE;
}

void test_ngtcp2_conn_stream_open_close(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ssize_t spktlen;
  int rv;
  ngtcp2_frame fr;
  ngtcp2_strm *strm;

  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 1;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datalen = 17;
  fr.stream.data = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 1, &fr);

  rv = ngtcp2_conn_recv(conn, buf, pktlen, 1);

  CU_ASSERT(0 == rv);

  strm = ngtcp2_conn_find_stream(conn, 1);

  CU_ASSERT(NGTCP2_STRM_FLAG_NONE == strm->flags);

  fr.stream.fin = 1;
  fr.stream.offset = 17;
  fr.stream.datalen = 0;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 2, &fr);

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

void test_ngtcp2_conn_stream_rx_flow_control(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ssize_t spktlen;
  int rv;
  ngtcp2_frame fr;
  ngtcp2_strm *strm;
  size_t i;

  setup_default_server(&conn);

  conn->local_settings.max_stream_data = 2047;
  conn->local_settings.max_stream_id = 5;

  for (i = 0; i < 3; ++i) {
    uint32_t stream_id = (uint32_t)(i * 2 + 1);
    fr.type = NGTCP2_FRAME_STREAM;
    fr.stream.flags = 0;
    fr.stream.stream_id = stream_id;
    fr.stream.fin = 0;
    fr.stream.offset = 0;
    fr.stream.datalen = 1024;
    fr.stream.data = null_data;

    pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, i, &fr);
    rv = ngtcp2_conn_recv(conn, buf, pktlen, 1);

    CU_ASSERT(0 == rv);

    strm = ngtcp2_conn_find_stream(conn, stream_id);

    CU_ASSERT(NULL != strm);

    rv = ngtcp2_conn_extend_max_stream_offset(conn, stream_id,
                                              fr.stream.datalen);

    CU_ASSERT(0 == rv);
  }

  strm = conn->fc_strms;

  CU_ASSERT(5 == strm->stream_id);

  strm = strm->fc_next;

  CU_ASSERT(3 == strm->stream_id);

  strm = strm->fc_next;

  CU_ASSERT(1 == strm->stream_id);

  strm = strm->fc_next;

  CU_ASSERT(NULL == strm);

  spktlen = ngtcp2_conn_send(conn, buf, sizeof(buf), 2);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(NULL == conn->fc_strms);

  for (i = 0; i < 3; ++i) {
    uint32_t stream_id = (uint32_t)(i * 2 + 1);
    strm = ngtcp2_conn_find_stream(conn, stream_id);

    CU_ASSERT(2047 + 1024 == strm->max_rx_offset);
  }

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_stream_rx_flow_control_error(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  int rv;
  ngtcp2_frame fr;

  setup_default_server(&conn);

  conn->local_settings.max_stream_data = 1023;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 1;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datalen = 1024;
  fr.stream.data = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 1, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 1);

  CU_ASSERT(NGTCP2_ERR_FLOW_CONTROL == rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_stream_tx_flow_control(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ssize_t spktlen;
  int rv;
  ngtcp2_frame fr;
  ngtcp2_strm *strm;
  size_t nwrite;

  setup_default_client(&conn);

  conn->remote_settings.max_stream_data = 2047;
  conn->remote_settings.max_stream_id = 5;

  rv = ngtcp2_conn_open_stream(conn, 1, NULL);

  CU_ASSERT(0 == rv);

  strm = ngtcp2_conn_find_stream(conn, 1);
  spktlen = ngtcp2_conn_write_stream(conn, buf, sizeof(buf), &nwrite, 1, 0,
                                     null_data, 1024, 1);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(1024 == nwrite);
  CU_ASSERT(1024 == strm->tx_offset);

  spktlen = ngtcp2_conn_write_stream(conn, buf, sizeof(buf), &nwrite, 1, 0,
                                     null_data, 1024, 2);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(1023 == nwrite);
  CU_ASSERT(2047 == strm->tx_offset);

  spktlen = ngtcp2_conn_write_stream(conn, buf, sizeof(buf), &nwrite, 1, 0,
                                     null_data, 1024, 3);

  CU_ASSERT(NGTCP2_ERR_STREAM_DATA_BLOCKED == spktlen);

  fr.type = NGTCP2_FRAME_MAX_STREAM_DATA;
  fr.max_stream_data.stream_id = 1;
  fr.max_stream_data.max_stream_data = 2048;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 1, &fr);

  rv = ngtcp2_conn_recv(conn, buf, pktlen, 4);

  CU_ASSERT(0 == rv);
  CU_ASSERT(2048 == strm->max_tx_offset);

  spktlen = ngtcp2_conn_write_stream(conn, buf, sizeof(buf), &nwrite, 1, 0,
                                     null_data, 1024, 5);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(1 == nwrite);
  CU_ASSERT(2048 == strm->tx_offset);

  ngtcp2_conn_del(conn);
}
