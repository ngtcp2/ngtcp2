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

#include <assert.h>

#include <CUnit/CUnit.h>

#include "ngtcp2_conn.h"
#include "ngtcp2_test_helper.h"
#include "ngtcp2_mem.h"
#include "ngtcp2_pkt.h"

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
  assert(destlen >= ciphertextlen);
  memcpy(dest, ciphertext, ciphertextlen);
  return (ssize_t)ciphertextlen;
}

static ssize_t fail_decrypt(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                            const uint8_t *ciphertext, size_t ciphertextlen,
                            const uint8_t *key, size_t keylen,
                            const uint8_t *nonce, size_t noncelen,
                            const uint8_t *ad, size_t adlen, void *user_data) {
  (void)conn;
  (void)dest;
  (void)destlen;
  (void)ciphertext;
  (void)ciphertextlen;
  (void)key;
  (void)keylen;
  (void)nonce;
  (void)noncelen;
  (void)ad;
  (void)adlen;
  (void)user_data;
  return NGTCP2_ERR_TLS_DECRYPT;
}

static uint8_t null_key[16];
static uint8_t null_iv[16];
static uint8_t null_data[4096];

typedef struct { uint64_t pkt_num; } my_user_data;

static ssize_t send_client_initial(ngtcp2_conn *conn, uint32_t flags,
                                   uint64_t *ppkt_num, const uint8_t **pdest,
                                   void *user_data) {
  my_user_data *ud = user_data;
  (void)conn;
  (void)flags;

  *pdest = null_data;

  if (ud) {
    *ppkt_num = ++ud->pkt_num;
  } else {
    *ppkt_num = 1000000007;
  }

  return 217;
}

static ssize_t send_client_cleartext_zero(ngtcp2_conn *conn, uint32_t flags,
                                          const uint8_t **pdest,
                                          void *user_data) {
  (void)conn;
  (void)flags;
  (void)pdest;
  (void)user_data;
  return 0;
}

static int recv_client_initial(ngtcp2_conn *conn, uint64_t conn_id,
                               void *user_data) {
  (void)conn;
  (void)conn_id;
  (void)user_data;
  return 0;
}

static ssize_t send_server_cleartext(ngtcp2_conn *conn, uint32_t flags,
                                     uint64_t *ppkt_num, const uint8_t **pdest,
                                     void *user_data) {
  (void)conn;
  (void)flags;
  (void)user_data;
  *pdest = null_data;
  if (ppkt_num) {
    *ppkt_num = 1000000009;
  }

  return 218;
}

static ssize_t send_server_cleartext_zero(ngtcp2_conn *conn, uint32_t flags,
                                          uint64_t *ppkt_num,
                                          const uint8_t **pdest,
                                          void *user_data) {
  (void)conn;
  (void)flags;
  (void)ppkt_num;
  (void)pdest;
  (void)user_data;
  return 0;
}

static int recv_handshake_data(ngtcp2_conn *conn, const uint8_t *data,
                               size_t datalen, void *user_data) {
  (void)conn;
  (void)data;
  (void)datalen;
  (void)user_data;
  return 0;
}

static int recv_handshake_data_error(ngtcp2_conn *conn, const uint8_t *data,
                                     size_t datalen, void *user_data) {
  (void)conn;
  (void)data;
  (void)datalen;
  (void)user_data;
  return NGTCP2_ERR_TLS_HANDSHAKE;
}

static void server_default_settings(ngtcp2_settings *settings) {
  size_t i;

  settings->max_stream_data = 65535;
  settings->max_data = 128;
  settings->max_stream_id = 5;
  settings->idle_timeout = 60;
  settings->omit_connection_id = 0;
  settings->max_packet_size = 65535;
  for (i = 0; i < NGTCP2_STATELESS_RESET_TOKENLEN; ++i) {
    settings->stateless_reset_token[i] = (uint8_t)i;
  }
}

static void client_default_settings(ngtcp2_settings *settings) {
  settings->max_stream_data = 65535;
  settings->max_data = 128;
  settings->max_stream_id = 0;
  settings->idle_timeout = 60;
  settings->omit_connection_id = 0;
  settings->max_packet_size = 65535;
}

static void setup_default_server(ngtcp2_conn **pconn) {
  ngtcp2_conn_callbacks cb;
  ngtcp2_settings settings;

  memset(&cb, 0, sizeof(cb));
  cb.hs_decrypt = null_decrypt;
  cb.hs_encrypt = null_encrypt;
  cb.decrypt = null_decrypt;
  cb.encrypt = null_encrypt;
  server_default_settings(&settings);

  ngtcp2_conn_server_new(pconn, 0x1, NGTCP2_PROTO_VER_MAX, &cb, &settings,
                         NULL);
  ngtcp2_conn_set_handshake_tx_keys(*pconn, null_key, sizeof(null_key), null_iv,
                                    sizeof(null_iv));
  ngtcp2_conn_set_handshake_rx_keys(*pconn, null_key, sizeof(null_key), null_iv,
                                    sizeof(null_iv));
  ngtcp2_conn_update_tx_keys(*pconn, null_key, sizeof(null_key), null_iv,
                             sizeof(null_iv));
  ngtcp2_conn_update_rx_keys(*pconn, null_key, sizeof(null_key), null_iv,
                             sizeof(null_iv));
  (*pconn)->state = NGTCP2_CS_POST_HANDSHAKE;
  (*pconn)->remote_settings.max_stream_data = 64 * 1024;
  (*pconn)->remote_settings.max_stream_id = 0;
  (*pconn)->remote_settings.max_data = 64;
  (*pconn)->max_tx_offset_high = (*pconn)->remote_settings.max_data;
}

static void setup_default_client(ngtcp2_conn **pconn) {
  ngtcp2_conn_callbacks cb;
  ngtcp2_settings settings;

  memset(&cb, 0, sizeof(cb));
  cb.hs_decrypt = null_decrypt;
  cb.hs_encrypt = null_encrypt;
  cb.decrypt = null_decrypt;
  cb.encrypt = null_encrypt;
  client_default_settings(&settings);

  ngtcp2_conn_client_new(pconn, 0x1, NGTCP2_PROTO_VER_MAX, &cb, &settings,
                         NULL);
  ngtcp2_conn_set_handshake_tx_keys(*pconn, null_key, sizeof(null_key), null_iv,
                                    sizeof(null_iv));
  ngtcp2_conn_set_handshake_rx_keys(*pconn, null_key, sizeof(null_key), null_iv,
                                    sizeof(null_iv));
  ngtcp2_conn_update_tx_keys(*pconn, null_key, sizeof(null_key), null_iv,
                             sizeof(null_iv));
  ngtcp2_conn_update_rx_keys(*pconn, null_key, sizeof(null_key), null_iv,
                             sizeof(null_iv));
  (*pconn)->state = NGTCP2_CS_POST_HANDSHAKE;
  (*pconn)->remote_settings.max_stream_data = 64 * 1024;
  (*pconn)->remote_settings.max_stream_id = 1;
  (*pconn)->remote_settings.max_data = 64;
  (*pconn)->max_tx_offset_high = (*pconn)->remote_settings.max_data;
}

static void setup_handshake_server(ngtcp2_conn **pconn) {
  ngtcp2_conn_callbacks cb;
  ngtcp2_settings settings;

  memset(&cb, 0, sizeof(cb));
  cb.recv_client_initial = recv_client_initial;
  cb.send_server_cleartext = send_server_cleartext;
  cb.recv_handshake_data = recv_handshake_data;
  cb.hs_decrypt = null_decrypt;
  cb.hs_encrypt = null_encrypt;
  server_default_settings(&settings);

  ngtcp2_conn_server_new(pconn, 0x1, NGTCP2_PROTO_VER_MAX, &cb, &settings,
                         NULL);
  ngtcp2_conn_set_handshake_tx_keys(*pconn, null_key, sizeof(null_key), null_iv,
                                    sizeof(null_iv));
  ngtcp2_conn_set_handshake_rx_keys(*pconn, null_key, sizeof(null_key), null_iv,
                                    sizeof(null_iv));
}

static void setup_handshake_client(ngtcp2_conn **pconn) {
  ngtcp2_conn_callbacks cb;
  ngtcp2_settings settings;

  memset(&cb, 0, sizeof(cb));
  cb.send_client_initial = send_client_initial;
  cb.recv_handshake_data = recv_handshake_data;
  cb.hs_decrypt = null_decrypt;
  cb.hs_encrypt = null_encrypt;
  client_default_settings(&settings);

  ngtcp2_conn_client_new(pconn, 0x1, NGTCP2_PROTO_VER_MAX, &cb, &settings,
                         NULL);
  ngtcp2_conn_set_handshake_tx_keys(*pconn, null_key, sizeof(null_key), null_iv,
                                    sizeof(null_iv));
  ngtcp2_conn_set_handshake_rx_keys(*pconn, null_key, sizeof(null_key), null_iv,
                                    sizeof(null_iv));
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

  CU_ASSERT(NULL != strm);

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

  spktlen = ngtcp2_conn_write_pkt(conn, buf, sizeof(buf), 2);

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

void test_ngtcp2_conn_rx_flow_control(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ssize_t spktlen;
  int rv;
  ngtcp2_frame fr;

  setup_default_server(&conn);

  conn->local_settings.max_data = 1;
  conn->max_rx_offset_high = 1;
  conn->unsent_max_rx_offset_high = 1;
  conn->unsent_max_rx_offset_low = 0;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 1;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datalen = 1023;
  fr.stream.data = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 1, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 1);

  CU_ASSERT(0 == rv);

  ngtcp2_conn_extend_max_offset(conn, 1023);

  CU_ASSERT(1 == conn->unsent_max_rx_offset_high);
  CU_ASSERT(1023 == conn->unsent_max_rx_offset_low);
  CU_ASSERT(1 == conn->max_rx_offset_high);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 1;
  fr.stream.fin = 0;
  fr.stream.offset = 1023;
  fr.stream.datalen = 1;
  fr.stream.data = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 2, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 2);

  CU_ASSERT(0 == rv);

  ngtcp2_conn_extend_max_offset(conn, 1);

  CU_ASSERT(2 == conn->unsent_max_rx_offset_high);
  CU_ASSERT(0 == conn->unsent_max_rx_offset_low);
  CU_ASSERT(1 == conn->max_rx_offset_high);

  spktlen = ngtcp2_conn_write_pkt(conn, buf, sizeof(buf), 3);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(2 == conn->max_rx_offset_high);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_rx_flow_control_error(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  int rv;
  ngtcp2_frame fr;

  setup_default_server(&conn);

  conn->local_settings.max_data = 1;
  conn->max_rx_offset_high = 1;
  conn->unsent_max_rx_offset_high = 1;
  conn->unsent_max_rx_offset_low = 0;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 1;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datalen = 1025;
  fr.stream.data = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 1, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 1);

  CU_ASSERT(NGTCP2_ERR_FLOW_CONTROL == rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_tx_flow_control(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ssize_t spktlen;
  int rv;
  ngtcp2_frame fr;
  size_t nwrite;

  setup_default_client(&conn);

  conn->remote_settings.max_data = 2;
  conn->max_tx_offset_high = 2;

  rv = ngtcp2_conn_open_stream(conn, 1, NULL);

  CU_ASSERT(0 == rv);

  spktlen = ngtcp2_conn_write_stream(conn, buf, sizeof(buf), &nwrite, 1, 0,
                                     null_data, 1024, 1);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(1024 == nwrite);
  CU_ASSERT(1 == conn->tx_offset_high);
  CU_ASSERT(0 == conn->tx_offset_low);

  spktlen = ngtcp2_conn_write_stream(conn, buf, sizeof(buf), &nwrite, 1, 0,
                                     null_data, 1023, 2);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(1023 == nwrite);
  CU_ASSERT(1 == conn->tx_offset_high);
  CU_ASSERT(1023 == conn->tx_offset_low);

  spktlen = ngtcp2_conn_write_stream(conn, buf, sizeof(buf), &nwrite, 1, 0,
                                     null_data, 1024, 3);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(1 == nwrite);
  CU_ASSERT(2 == conn->tx_offset_high);
  CU_ASSERT(0 == conn->tx_offset_low);

  spktlen = ngtcp2_conn_write_stream(conn, buf, sizeof(buf), &nwrite, 1, 0,
                                     null_data, 1024, 4);

  CU_ASSERT(NGTCP2_ERR_STREAM_DATA_BLOCKED == spktlen);

  fr.type = NGTCP2_FRAME_MAX_DATA;
  fr.max_data.max_data = 3;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 1, &fr);

  rv = ngtcp2_conn_recv(conn, buf, pktlen, 5);

  CU_ASSERT(0 == rv);
  CU_ASSERT(3 == conn->max_tx_offset_high);

  spktlen = ngtcp2_conn_write_stream(conn, buf, sizeof(buf), &nwrite, 1, 0,
                                     null_data, 1024, 4);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(1024 == nwrite);
  CU_ASSERT(3 == conn->tx_offset_high);
  CU_ASSERT(0 == conn->tx_offset_low);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_shutdown_stream_write(void) {
  ngtcp2_conn *conn;
  int rv;
  ngtcp2_frame_chain *frc;
  uint8_t buf[2048];
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_strm *strm;

  /* Stream not found */
  setup_default_server(&conn);

  rv = ngtcp2_conn_shutdown_stream_write(conn, 1, NGTCP2_NO_ERROR);

  CU_ASSERT(NGTCP2_ERR_STREAM_NOT_FOUND == rv);

  ngtcp2_conn_del(conn);

  /* Check final_offset */
  setup_default_client(&conn);

  ngtcp2_conn_open_stream(conn, 1, NULL);
  ngtcp2_conn_write_stream(conn, buf, sizeof(buf), NULL, 1, 0, null_data, 1239,
                           1);
  rv = ngtcp2_conn_shutdown_stream_write(conn, 1, NGTCP2_PROTOCOL_VIOLATION);

  CU_ASSERT(0 == rv);

  for (frc = conn->frq; frc; frc = frc->next) {
    if (frc->fr.type == NGTCP2_FRAME_RST_STREAM) {
      break;
    }
  }

  CU_ASSERT(NULL != frc);
  CU_ASSERT(1 == frc->fr.rst_stream.stream_id);
  CU_ASSERT(NGTCP2_PROTOCOL_VIOLATION == frc->fr.rst_stream.error_code);
  CU_ASSERT(1239 == frc->fr.rst_stream.final_offset);

  strm = ngtcp2_conn_find_stream(conn, 1);

  CU_ASSERT(NULL != strm);
  CU_ASSERT(NGTCP2_PROTOCOL_VIOLATION == strm->error_code);

  fr.type = NGTCP2_FRAME_RST_STREAM;
  fr.rst_stream.stream_id = 1;
  fr.rst_stream.error_code = NGTCP2_QUIC_RECEIVED_RST;
  fr.rst_stream.final_offset = 100;

  pktlen =
      write_single_frame_pkt(conn, buf, sizeof(buf), conn->conn_id, 890, &fr);

  rv = ngtcp2_conn_recv(conn, buf, pktlen, 2);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL == ngtcp2_conn_find_stream(conn, 1));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_rst_stream(void) {
  ngtcp2_conn *conn;
  int rv;
  uint8_t buf[2048];
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_strm *strm;

  /* Receive RST_STREAM */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 1;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datalen = 955;
  fr.stream.data = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 1, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 1);

  CU_ASSERT(0 == rv);

  ngtcp2_conn_write_stream(conn, buf, sizeof(buf), NULL, 1, 0, null_data, 354,
                           2);

  fr.type = NGTCP2_FRAME_RST_STREAM;
  fr.rst_stream.stream_id = 1;
  fr.rst_stream.error_code = NGTCP2_FLOW_CONTROL_ERROR;
  fr.rst_stream.final_offset = 955;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 2, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 3);

  CU_ASSERT(0 == rv);

  strm = ngtcp2_conn_find_stream(conn, 1);

  CU_ASSERT(strm->flags & NGTCP2_STRM_FLAG_SHUT_RD);
  CU_ASSERT(strm->flags & NGTCP2_STRM_FLAG_RECV_RST);

  ngtcp2_conn_del(conn);

  /* Receive RST_STREAM after sending STOP_SENDING */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 1;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datalen = 955;
  fr.stream.data = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 1, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 1);

  CU_ASSERT(0 == rv);

  ngtcp2_conn_write_stream(conn, buf, sizeof(buf), NULL, 1, 0, null_data, 354,
                           2);
  ngtcp2_conn_shutdown_stream_read(conn, 1, NGTCP2_PROTOCOL_VIOLATION);
  ngtcp2_conn_write_pkt(conn, buf, sizeof(buf), 3);

  fr.type = NGTCP2_FRAME_RST_STREAM;
  fr.rst_stream.stream_id = 1;
  fr.rst_stream.error_code = NGTCP2_FLOW_CONTROL_ERROR;
  fr.rst_stream.final_offset = 955;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 2, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 4);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL != ngtcp2_conn_find_stream(conn, 1));

  ngtcp2_conn_del(conn);

  /* Receive RST_STREAM after sending RST_STREAM */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 1;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datalen = 955;
  fr.stream.data = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 1, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 1);

  CU_ASSERT(0 == rv);

  ngtcp2_conn_write_stream(conn, buf, sizeof(buf), NULL, 1, 0, null_data, 354,
                           2);
  ngtcp2_conn_shutdown_stream_write(conn, 1, NGTCP2_PROTOCOL_VIOLATION);
  ngtcp2_conn_write_pkt(conn, buf, sizeof(buf), 3);

  fr.type = NGTCP2_FRAME_RST_STREAM;
  fr.rst_stream.stream_id = 1;
  fr.rst_stream.error_code = NGTCP2_FLOW_CONTROL_ERROR;
  fr.rst_stream.final_offset = 955;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 2, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 4);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL == ngtcp2_conn_find_stream(conn, 1));

  ngtcp2_conn_del(conn);

  /* Receive RST_STREAM after receiving STOP_SENDING */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 1;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datalen = 955;
  fr.stream.data = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 1, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 1);

  CU_ASSERT(0 == rv);

  ngtcp2_conn_write_stream(conn, buf, sizeof(buf), NULL, 1, 0, null_data, 354,
                           2);

  fr.type = NGTCP2_FRAME_STOP_SENDING;
  fr.stop_sending.stream_id = 1;
  fr.stop_sending.error_code = NGTCP2_PROTOCOL_VIOLATION;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 2, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 3);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL != ngtcp2_conn_find_stream(conn, 1));

  fr.type = NGTCP2_FRAME_RST_STREAM;
  fr.rst_stream.stream_id = 1;
  fr.rst_stream.error_code = NGTCP2_FLOW_CONTROL_ERROR;
  fr.rst_stream.final_offset = 955;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 3, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 4);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL == ngtcp2_conn_find_stream(conn, 1));

  ngtcp2_conn_del(conn);

  /* final_offset in RST_STREAM exceeds the already received offset */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 1;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datalen = 955;
  fr.stream.data = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 1, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 1);

  CU_ASSERT(0 == rv);

  fr.type = NGTCP2_FRAME_RST_STREAM;
  fr.rst_stream.stream_id = 1;
  fr.rst_stream.error_code = NGTCP2_FLOW_CONTROL_ERROR;
  fr.rst_stream.final_offset = 954;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 2, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 2);

  CU_ASSERT(NGTCP2_ERR_FINAL_OFFSET == rv);

  ngtcp2_conn_del(conn);

  /* final_offset in RST_STREAM differs from the final offset which
     STREAM frame with fin indicated. */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 1;
  fr.stream.fin = 1;
  fr.stream.offset = 0;
  fr.stream.datalen = 955;
  fr.stream.data = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 1, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 1);

  CU_ASSERT(0 == rv);

  fr.type = NGTCP2_FRAME_RST_STREAM;
  fr.rst_stream.stream_id = 1;
  fr.rst_stream.error_code = NGTCP2_FLOW_CONTROL_ERROR;
  fr.rst_stream.final_offset = 956;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 2, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 2);

  CU_ASSERT(NGTCP2_ERR_FINAL_OFFSET == rv);

  ngtcp2_conn_del(conn);

  /* RST_STREAM against local stream which has not been initiated. */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_RST_STREAM;
  fr.rst_stream.stream_id = 2;
  fr.rst_stream.error_code = NGTCP2_NO_ERROR;
  fr.rst_stream.final_offset = 0;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 1, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 1);

  CU_ASSERT(NGTCP2_ERR_PROTO == rv);

  ngtcp2_conn_del(conn);

  /* RST_STREAM against remote stream which is larger than allowed
     maximum */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_RST_STREAM;
  fr.rst_stream.stream_id = 7;
  fr.rst_stream.error_code = NGTCP2_NO_ERROR;
  fr.rst_stream.final_offset = 0;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 1, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 1);

  CU_ASSERT(NGTCP2_ERR_STREAM_ID == rv);

  ngtcp2_conn_del(conn);

  /* RST_STREAM against remote stream which is allowed, and no
     ngtcp2_strm object has been created */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_RST_STREAM;
  fr.rst_stream.stream_id = 1;
  fr.rst_stream.error_code = NGTCP2_NO_ERROR;
  fr.rst_stream.final_offset = 0;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 1, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 1);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NGTCP2_ERR_STREAM_IN_USE ==
            ngtcp2_idtr_is_open(&conn->remote_idtr, fr.rst_stream.stream_id));

  ngtcp2_conn_del(conn);

  /* RST_STREAM against remote stream which is allowed, and no
     ngtcp2_strm object has been created, and final_offset violates
     connection-level flow control. */
  setup_default_server(&conn);

  conn->local_settings.max_stream_data = 1 << 21;

  fr.type = NGTCP2_FRAME_RST_STREAM;
  fr.rst_stream.stream_id = 1;
  fr.rst_stream.error_code = NGTCP2_NO_ERROR;
  fr.rst_stream.final_offset = 1 << 20;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 1, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 1);

  CU_ASSERT(NGTCP2_ERR_FLOW_CONTROL == rv);

  ngtcp2_conn_del(conn);

  /* RST_STREAM against remote stream which is allowed, and no
      ngtcp2_strm object has been created, and final_offset violates
      stream-level flow control. */
  setup_default_server(&conn);

  conn->max_rx_offset_high = 1 << 11;

  fr.type = NGTCP2_FRAME_RST_STREAM;
  fr.rst_stream.stream_id = 1;
  fr.rst_stream.error_code = NGTCP2_NO_ERROR;
  fr.rst_stream.final_offset = 1 << 20;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 1, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 1);

  CU_ASSERT(NGTCP2_ERR_FLOW_CONTROL == rv);

  ngtcp2_conn_del(conn);

  /* final_offset in RST_STREAM violates connection-level flow
     control */
  setup_default_server(&conn);

  conn->local_settings.max_stream_data = 1 << 21;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 1;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datalen = 955;
  fr.stream.data = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 1, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 1);

  CU_ASSERT(0 == rv);

  fr.type = NGTCP2_FRAME_RST_STREAM;
  fr.rst_stream.stream_id = 1;
  fr.rst_stream.error_code = NGTCP2_FLOW_CONTROL_ERROR;
  fr.rst_stream.final_offset = 1024 * 1024;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 2, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 2);

  CU_ASSERT(NGTCP2_ERR_FLOW_CONTROL == rv);

  ngtcp2_conn_del(conn);

  /* final_offset in RST_STREAM violates stream-level flow
     control */
  setup_default_server(&conn);

  conn->max_rx_offset_high = 1 << 11;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 1;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datalen = 955;
  fr.stream.data = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 1, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 1);

  CU_ASSERT(0 == rv);

  fr.type = NGTCP2_FRAME_RST_STREAM;
  fr.rst_stream.stream_id = 1;
  fr.rst_stream.error_code = NGTCP2_FLOW_CONTROL_ERROR;
  fr.rst_stream.final_offset = 1024 * 1024;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 2, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 2);

  CU_ASSERT(NGTCP2_ERR_FLOW_CONTROL == rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_stop_sending(void) {
  ngtcp2_conn *conn;
  int rv;
  uint8_t buf[2048];
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_strm *strm;
  ngtcp2_tstamp t = 0;
  uint64_t pkt_num = 0;
  ngtcp2_frame_chain *frc;

  /* Receive STOP_SENDING */
  setup_default_client(&conn);

  ngtcp2_conn_open_stream(conn, 1, NULL);
  ngtcp2_conn_write_stream(conn, buf, sizeof(buf), NULL, 1, 0, null_data, 333,
                           ++t);

  fr.type = NGTCP2_FRAME_STOP_SENDING;
  fr.stop_sending.stream_id = 1;
  fr.stop_sending.error_code = NGTCP2_PROTOCOL_VIOLATION;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, ++pkt_num, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  strm = ngtcp2_conn_find_stream(conn, 1);

  CU_ASSERT(strm->flags & NGTCP2_STRM_FLAG_SHUT_WR);
  CU_ASSERT(strm->flags & NGTCP2_STRM_FLAG_SENT_RST);

  for (frc = conn->frq; frc; frc = frc->next) {
    if (frc->fr.type == NGTCP2_FRAME_RST_STREAM) {
      break;
    }
  }

  CU_ASSERT(NULL != frc);
  CU_ASSERT(NGTCP2_QUIC_RECEIVED_RST == frc->fr.rst_stream.error_code);
  CU_ASSERT(333 == frc->fr.rst_stream.final_offset);

  ngtcp2_conn_del(conn);

  /* Receive STOP_SENDING after receiving RST_STREAM */
  setup_default_client(&conn);

  ngtcp2_conn_open_stream(conn, 1, NULL);
  ngtcp2_conn_write_stream(conn, buf, sizeof(buf), NULL, 1, 0, null_data, 333,
                           ++t);

  fr.type = NGTCP2_FRAME_RST_STREAM;
  fr.rst_stream.stream_id = 1;
  fr.rst_stream.error_code = NGTCP2_PROTOCOL_VIOLATION;
  fr.rst_stream.final_offset = 0;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, ++pkt_num, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  fr.type = NGTCP2_FRAME_STOP_SENDING;
  fr.stop_sending.stream_id = 1;
  fr.stop_sending.error_code = NGTCP2_PROTOCOL_VIOLATION;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, ++pkt_num, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL == ngtcp2_conn_find_stream(conn, 1));

  for (frc = conn->frq; frc; frc = frc->next) {
    if (frc->fr.type == NGTCP2_FRAME_RST_STREAM) {
      break;
    }
  }

  CU_ASSERT(NULL != frc);
  CU_ASSERT(NGTCP2_QUIC_RECEIVED_RST == frc->fr.rst_stream.error_code);
  CU_ASSERT(333 == frc->fr.rst_stream.final_offset);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_conn_id_omitted(void) {
  ngtcp2_conn *conn;
  int rv;
  uint8_t buf[2048];
  ngtcp2_frame fr;
  size_t pktlen;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 1;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datalen = 100;
  fr.stream.data = null_data;

  /* Receiving packet which has no connection ID while local_settings
     does not allow it. */
  setup_default_server(&conn);

  pktlen =
      write_single_frame_pkt_without_conn_id(conn, buf, sizeof(buf), 1, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 1);

  CU_ASSERT(NGTCP2_ERR_PROTO == rv);

  ngtcp2_conn_del(conn);

  /* Allow omission of connection ID */
  setup_default_server(&conn);
  conn->local_settings.omit_connection_id = 1;

  pktlen =
      write_single_frame_pkt_without_conn_id(conn, buf, sizeof(buf), 1, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 1);

  CU_ASSERT(0 == rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_short_pkt_type(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  ssize_t spktlen;

  /* 1 octet pkt num */
  setup_default_client(&conn);

  ngtcp2_conn_open_stream(conn, 1, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, buf, sizeof(buf), NULL, 1, 0,
                                     null_data, 19, 1);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(NGTCP2_PKT_01 == (buf[0] & NGTCP2_SHORT_TYPE_MASK));

  ngtcp2_conn_del(conn);

  /* 2 octet pkt num */
  setup_default_client(&conn);
  conn->rtb.largest_acked = 0x6afa2f;
  conn->last_tx_pkt_num = 0x6b4263;

  ngtcp2_conn_open_stream(conn, 1, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, buf, sizeof(buf), NULL, 1, 0,
                                     null_data, 19, 1);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(NGTCP2_PKT_02 == (buf[0] & NGTCP2_SHORT_TYPE_MASK));

  ngtcp2_conn_del(conn);

  /* 3 octet pkt num */
  setup_default_client(&conn);
  conn->rtb.largest_acked = 0x6afa2f;
  conn->last_tx_pkt_num = 0x6bc106;

  ngtcp2_conn_open_stream(conn, 1, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, buf, sizeof(buf), NULL, 1, 0,
                                     null_data, 19, 1);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(NGTCP2_PKT_03 == (buf[0] & NGTCP2_SHORT_TYPE_MASK));

  ngtcp2_conn_del(conn);

  /* 1 octet pkt num (largest)*/
  setup_default_client(&conn);
  conn->rtb.largest_acked = 1;
  conn->last_tx_pkt_num = 127;

  ngtcp2_conn_open_stream(conn, 1, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, buf, sizeof(buf), NULL, 1, 0,
                                     null_data, 19, 1);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(NGTCP2_PKT_01 == (buf[0] & NGTCP2_SHORT_TYPE_MASK));

  ngtcp2_conn_del(conn);

  /* 2 octet pkt num (shortest)*/
  setup_default_client(&conn);
  conn->rtb.largest_acked = 1;
  conn->last_tx_pkt_num = 128;

  ngtcp2_conn_open_stream(conn, 1, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, buf, sizeof(buf), NULL, 1, 0,
                                     null_data, 19, 1);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(NGTCP2_PKT_02 == (buf[0] & NGTCP2_SHORT_TYPE_MASK));

  ngtcp2_conn_del(conn);

  /* 2 octet pkt num (largest)*/
  setup_default_client(&conn);
  conn->rtb.largest_acked = 1;
  conn->last_tx_pkt_num = 32767;

  ngtcp2_conn_open_stream(conn, 1, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, buf, sizeof(buf), NULL, 1, 0,
                                     null_data, 19, 1);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(NGTCP2_PKT_02 == (buf[0] & NGTCP2_SHORT_TYPE_MASK));

  ngtcp2_conn_del(conn);

  /* 3 octet pkt num (shortest)*/
  setup_default_client(&conn);
  conn->rtb.largest_acked = 1;
  conn->last_tx_pkt_num = 32768;

  ngtcp2_conn_open_stream(conn, 1, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, buf, sizeof(buf), NULL, 1, 0,
                                     null_data, 19, 1);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(NGTCP2_PKT_03 == (buf[0] & NGTCP2_SHORT_TYPE_MASK));

  ngtcp2_conn_del(conn);

  /* Overflow */
  setup_default_client(&conn);
  conn->rtb.largest_acked = 1;
  conn->last_tx_pkt_num = 0x8000000000000000llu;

  ngtcp2_conn_open_stream(conn, 1, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, buf, sizeof(buf), NULL, 1, 0,
                                     null_data, 19, 1);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(NGTCP2_PKT_03 == (buf[0] & NGTCP2_SHORT_TYPE_MASK));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_stateless_reset(void) {
  ngtcp2_conn *conn;
  uint8_t buf[256];
  ssize_t spktlen;
  int rv;
  size_t i;
  uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN];

  for (i = 0; i < NGTCP2_STATELESS_RESET_TOKENLEN; ++i) {
    token[i] = (uint8_t)~i;
  }

  /* server */
  setup_default_server(&conn);
  conn->callbacks.decrypt = fail_decrypt;
  conn->max_rx_pkt_num = 24324325;

  spktlen = ngtcp2_pkt_write_stateless_reset(
      buf, sizeof(buf), NGTCP2_PKT_FLAG_CONN_ID, conn->conn_id,
      conn->local_settings.stateless_reset_token, null_data, 17);

  CU_ASSERT(spktlen > 0);

  rv = ngtcp2_conn_recv(conn, buf, (size_t)spktlen, 1);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NGTCP2_CS_CLOSE_WAIT == conn->state);

  ngtcp2_conn_del(conn);

  /* client */
  setup_default_client(&conn);
  conn->callbacks.decrypt = fail_decrypt;
  conn->max_rx_pkt_num = 3255454;
  memcpy(conn->remote_settings.stateless_reset_token, token,
         NGTCP2_STATELESS_RESET_TOKENLEN);

  spktlen = ngtcp2_pkt_write_stateless_reset(
      buf, sizeof(buf), NGTCP2_PKT_FLAG_CONN_ID, conn->conn_id, token,
      null_data, 19);

  CU_ASSERT(spktlen > 0);

  rv = ngtcp2_conn_recv(conn, buf, (size_t)spktlen, 1);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NGTCP2_CS_CLOSE_WAIT == conn->state);

  ngtcp2_conn_del(conn);

  /* token does not match */
  setup_default_server(&conn);
  conn->callbacks.decrypt = fail_decrypt;
  conn->max_rx_pkt_num = 24324325;

  spktlen = ngtcp2_pkt_write_stateless_reset(
      buf, sizeof(buf), NGTCP2_PKT_FLAG_CONN_ID, conn->conn_id, token,
      null_data, 17);

  CU_ASSERT(spktlen > 0);

  rv = ngtcp2_conn_recv(conn, buf, (size_t)spktlen, 1);

  CU_ASSERT(NGTCP2_ERR_TLS_DECRYPT == rv);
  CU_ASSERT(NGTCP2_CS_CLOSE_WAIT != conn->state);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_server_stateless_retry(void) {
  ngtcp2_conn *conn;
  my_user_data ud;
  uint8_t buf[2048];
  ssize_t spktlen;
  size_t pktlen;
  ngtcp2_frame fr;
  int rv;

  memset(&ud, 0, sizeof(ud));
  ud.pkt_num = 0;
  setup_handshake_client(&conn);
  conn->user_data = &ud;

  spktlen = ngtcp2_conn_write_pkt(conn, buf, sizeof(buf), 1);

  CU_ASSERT(spktlen > 0);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 0;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datalen = 333;
  fr.stream.data = null_data;

  pktlen = write_single_frame_handshake_pkt(
      buf, sizeof(buf), NGTCP2_PKT_SERVER_STATELESS_RETRY, conn->conn_id,
      conn->last_tx_pkt_num, conn->version, &fr);

  rv = ngtcp2_conn_recv(conn, buf, pktlen, 2);

  CU_ASSERT(0 == rv);
  CU_ASSERT(0 == conn->last_tx_pkt_num);

  spktlen = ngtcp2_conn_write_pkt(conn, buf, sizeof(buf), 3);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(2 == conn->last_tx_pkt_num);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_delayed_handshake_pkt(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_frame fr;
  int rv;

  /* STREAM frame */
  setup_default_client(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 0;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datalen = 567;
  fr.stream.data = null_data;

  pktlen = write_single_frame_handshake_pkt(
      buf, sizeof(buf), NGTCP2_PKT_SERVER_CLEARTEXT, conn->conn_id, 1,
      NGTCP2_PROTO_VER_MAX, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 1);

  CU_ASSERT(0 == rv);
  CU_ASSERT(1 == conn->acktr.nack);
  CU_ASSERT(1 == conn->acktr.active_ack);

  ngtcp2_conn_del(conn);

  /* ACK frame only */
  setup_default_client(&conn);

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = 1000000007;
  fr.ack.ack_delay = 122;
  fr.ack.first_ack_blklen = 0;
  fr.ack.num_blks = 0;
  fr.ack.num_ts = 0;

  pktlen = write_single_frame_handshake_pkt(
      buf, sizeof(buf), NGTCP2_PKT_SERVER_CLEARTEXT, conn->conn_id, 1,
      NGTCP2_PROTO_VER_MAX, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 1);

  CU_ASSERT(0 == rv);
  CU_ASSERT(1 == conn->acktr.nack);
  CU_ASSERT(0 == conn->acktr.active_ack);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_max_stream_id(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  int rv;
  ngtcp2_frame fr;

  setup_default_client(&conn);

  fr.type = NGTCP2_FRAME_MAX_STREAM_ID;
  fr.max_stream_id.max_stream_id = 999;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), 0xc, 1, &fr);
  rv = ngtcp2_conn_recv(conn, buf, pktlen, 1);

  CU_ASSERT(0 == rv);
  CU_ASSERT(999 == conn->remote_settings.max_stream_id);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_handshake_error(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ssize_t spktlen;
  ngtcp2_frame fr;
  int rv;
  uint64_t pkt_num = 107, t = 0;

  /* client side */
  setup_handshake_client(&conn);
  conn->callbacks.recv_handshake_data = recv_handshake_data_error;
  conn->callbacks.send_client_cleartext = send_client_cleartext_zero;
  spktlen = ngtcp2_conn_write_pkt(conn, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 0;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datalen = 333;
  fr.stream.data = null_data;

  pktlen = write_single_frame_handshake_pkt(
      buf, sizeof(buf), NGTCP2_PKT_SERVER_CLEARTEXT, conn->conn_id, ++pkt_num,
      conn->version, &fr);

  rv = ngtcp2_conn_recv(conn, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  spktlen = ngtcp2_conn_write_pkt(conn, buf, sizeof(buf), ++t);

  CU_ASSERT(NGTCP2_ERR_TLS_HANDSHAKE == spktlen);

  ngtcp2_conn_del(conn);

  /* server side */
  setup_handshake_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 0;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datalen = 551;
  fr.stream.data = null_data;

  pktlen = write_single_frame_handshake_pkt(
      buf, sizeof(buf), NGTCP2_PKT_CLIENT_INITIAL, conn->conn_id, ++pkt_num,
      conn->version, &fr);

  rv = ngtcp2_conn_recv(conn, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  spktlen = ngtcp2_conn_write_pkt(conn, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 0;
  fr.stream.fin = 0;
  fr.stream.offset = 551;
  fr.stream.datalen = 87;
  fr.stream.data = null_data;

  pktlen = write_single_frame_handshake_pkt(
      buf, sizeof(buf), NGTCP2_PKT_CLIENT_CLEARTEXT, conn->conn_id, ++pkt_num,
      conn->version, &fr);

  conn->callbacks.recv_handshake_data = recv_handshake_data_error;
  rv = ngtcp2_conn_recv(conn, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  conn->callbacks.send_server_cleartext = send_server_cleartext_zero;
  spktlen = ngtcp2_conn_write_pkt(conn, buf, sizeof(buf), ++t);

  CU_ASSERT(NGTCP2_ERR_TLS_HANDSHAKE == spktlen);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_retransmit_protected(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ssize_t spktlen;
  int rv;
  uint64_t pkt_num = 890;
  ngtcp2_tstamp t = 0;
  ngtcp2_frame fr;
  ngtcp2_rtb_entry *ent;

  /* Retransmit a packet completely */
  setup_default_client(&conn);

  ngtcp2_conn_open_stream(conn, 1, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, buf, sizeof(buf), NULL, 1, 0,
                                     null_data, 126, ++t);

  CU_ASSERT(spktlen > 0);

  /* Kick delayed ACK timer */
  t += 1000000;

  ent = ngtcp2_rtb_top(&conn->rtb);
  spktlen = ngtcp2_conn_write_pkt(conn, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(ent == ngtcp2_rtb_top(&conn->rtb));
  CU_ASSERT(1 == ent->count);
  CU_ASSERT(t + ((uint64_t)NGTCP2_INITIAL_EXPIRY << ent->count) == ent->expiry);

  ngtcp2_conn_del(conn);

  /* Retransmit a packet partially */
  setup_default_client(&conn);
  conn->remote_settings.max_stream_id = 3;

  ngtcp2_conn_open_stream(conn, 1, NULL);
  ngtcp2_conn_open_stream(conn, 3, NULL);

  ngtcp2_conn_shutdown_stream_write(conn, 1, NGTCP2_NO_ERROR);
  ngtcp2_conn_shutdown_stream_write(conn, 3, NGTCP2_NO_ERROR);

  spktlen = ngtcp2_conn_write_pkt(conn, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);

  /* Kick delayed ACK timer */
  t += 1000000;

  ent = ngtcp2_rtb_top(&conn->rtb);
  spktlen = ngtcp2_conn_write_pkt(conn, buf, (size_t)(spktlen - 1), ++t);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(ent == ngtcp2_rtb_top(&conn->rtb));
  CU_ASSERT(0 == ent->count);

  ent = ent->next;

  CU_ASSERT(1 == ent->count);
  CU_ASSERT(t + ((uint64_t)NGTCP2_INITIAL_EXPIRY << ent->count) == ent->expiry);

  ngtcp2_conn_del(conn);

  /* ngtcp2_rtb_entry is reused because buffer was too small */
  setup_default_client(&conn);

  fr.type = NGTCP2_FRAME_PING;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), conn->conn_id,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_recv(conn, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  ngtcp2_conn_open_stream(conn, 1, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, buf, sizeof(buf), NULL, 1, 0,
                                     null_data, 1000, ++t);

  CU_ASSERT(spktlen > 0);

  /* Kick delayed ACK timer */
  t += 1000000;

  ent = ngtcp2_rtb_top(&conn->rtb);

  /* This should not send ACK only packet */
  spktlen = ngtcp2_conn_write_pkt(conn, buf, 999, ++t);

  CU_ASSERT(NGTCP2_ERR_NOBUF == (int)spktlen);
  CU_ASSERT(ent == ngtcp2_rtb_top(&conn->rtb));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_send_max_stream_data(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_strm *strm;
  uint64_t pkt_num = 890;
  ngtcp2_tstamp t = 0;
  ngtcp2_frame fr;
  int rv;
  const uint32_t datalen = 1024;

  /* MAX_STREAM_DATA should be sent */
  setup_default_server(&conn);
  conn->local_settings.max_stream_data = datalen;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 1;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datalen = datalen;
  fr.stream.data = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), conn->conn_id,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_recv(conn, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  rv = ngtcp2_conn_extend_max_stream_offset(conn, 1, datalen);

  CU_ASSERT(0 == rv);

  strm = ngtcp2_conn_find_stream(conn, 1);

  CU_ASSERT(NULL != strm->fc_pprev);

  ngtcp2_conn_del(conn);

  /* MAX_STREAM_DATA should not be sent on incoming fin */
  setup_default_server(&conn);
  conn->local_settings.max_stream_data = datalen;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 1;
  fr.stream.fin = 1;
  fr.stream.offset = 0;
  fr.stream.datalen = datalen;
  fr.stream.data = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), conn->conn_id,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_recv(conn, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  rv = ngtcp2_conn_extend_max_stream_offset(conn, 1, datalen);

  CU_ASSERT(0 == rv);

  strm = ngtcp2_conn_find_stream(conn, 1);

  CU_ASSERT(NULL == strm->fc_pprev);

  ngtcp2_conn_del(conn);

  /* MAX_STREAM_DATA should not be sent if STOP_SENDING frame is being
     reset by local endpoint */
  setup_default_server(&conn);
  conn->local_settings.max_stream_data = datalen;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 1;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datalen = datalen;
  fr.stream.data = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), conn->conn_id,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_recv(conn, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  rv = ngtcp2_conn_shutdown_stream_read(conn, 1, NGTCP2_NO_ERROR);

  CU_ASSERT(0 == rv);

  rv = ngtcp2_conn_extend_max_stream_offset(conn, 1, datalen);

  CU_ASSERT(0 == rv);

  strm = ngtcp2_conn_find_stream(conn, 1);

  CU_ASSERT(NULL == strm->fc_pprev);

  ngtcp2_conn_del(conn);

  /* MAX_STREAM_DATA should not be sent if stream is being reset by
     remote endpoint */
  setup_default_server(&conn);
  conn->local_settings.max_stream_data = datalen;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 1;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datalen = datalen;
  fr.stream.data = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), conn->conn_id,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_recv(conn, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  fr.type = NGTCP2_FRAME_RST_STREAM;
  fr.rst_stream.stream_id = 1;
  fr.rst_stream.error_code = NGTCP2_NO_ERROR;
  fr.rst_stream.final_offset = datalen;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), conn->conn_id,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_recv(conn, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  rv = ngtcp2_conn_extend_max_stream_offset(conn, 1, datalen);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL == conn->fc_strms);

  ngtcp2_conn_del(conn);
}
