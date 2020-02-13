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
#include "ngtcp2_cid.h"
#include "ngtcp2_conv.h"
#include "ngtcp2_vec.h"
#include "ngtcp2_rcvry.h"

static int null_encrypt(ngtcp2_conn *conn, uint8_t *dest,
                        const ngtcp2_crypto_aead *aead,
                        const uint8_t *plaintext, size_t plaintextlen,
                        const uint8_t *key, const uint8_t *nonce,
                        size_t noncelen, const uint8_t *ad, size_t adlen,
                        void *user_data) {
  (void)conn;
  (void)dest;
  (void)aead;
  (void)plaintext;
  (void)plaintextlen;
  (void)key;
  (void)nonce;
  (void)noncelen;
  (void)ad;
  (void)adlen;
  (void)user_data;

  if (plaintextlen && plaintext != dest) {
    memcpy(dest, plaintext, plaintextlen);
  }
  memset(dest + plaintextlen, 0, NGTCP2_FAKE_AEAD_OVERHEAD);

  return 0;
}

static int null_decrypt(ngtcp2_conn *conn, uint8_t *dest,
                        const ngtcp2_crypto_aead *aead,
                        const uint8_t *ciphertext, size_t ciphertextlen,
                        const uint8_t *key, const uint8_t *nonce,
                        size_t noncelen, const uint8_t *ad, size_t adlen,
                        void *user_data) {
  (void)conn;
  (void)dest;
  (void)aead;
  (void)ciphertext;
  (void)key;
  (void)nonce;
  (void)noncelen;
  (void)ad;
  (void)adlen;
  (void)user_data;
  assert(ciphertextlen >= NGTCP2_FAKE_AEAD_OVERHEAD);
  memmove(dest, ciphertext, ciphertextlen - NGTCP2_FAKE_AEAD_OVERHEAD);
  return 0;
}

static int fail_decrypt(ngtcp2_conn *conn, uint8_t *dest,
                        const ngtcp2_crypto_aead *aead,
                        const uint8_t *ciphertext, size_t ciphertextlen,
                        const uint8_t *key, const uint8_t *nonce,
                        size_t noncelen, const uint8_t *ad, size_t adlen,
                        void *user_data) {
  (void)conn;
  (void)dest;
  (void)aead;
  (void)ciphertext;
  (void)ciphertextlen;
  (void)key;
  (void)nonce;
  (void)noncelen;
  (void)ad;
  (void)adlen;
  (void)user_data;
  return NGTCP2_ERR_TLS_DECRYPT;
}

static int null_hp_mask(ngtcp2_conn *conn, uint8_t *dest,
                        const ngtcp2_crypto_cipher *hp, const uint8_t *hp_key,
                        const uint8_t *sample, void *user_data) {
  (void)conn;
  (void)hp;
  (void)hp_key;
  (void)user_data;
  (void)sample;
  memcpy(dest, NGTCP2_FAKE_HP_MASK, sizeof(NGTCP2_FAKE_HP_MASK) - 1);
  return 0;
}

static int get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                 uint8_t *token, size_t cidlen,
                                 void *user_data) {
  (void)user_data;
  memset(cid->data, 0, cidlen);
  cid->data[0] = (uint8_t)(conn->scid.last_seq + 1);
  cid->datalen = cidlen;
  memset(token, 0, NGTCP2_STATELESS_RESET_TOKENLEN);
  return 0;
}

static uint8_t null_secret[32];
static uint8_t null_key[16];
static uint8_t null_iv[16];
static uint8_t null_hp_key[16];
static uint8_t null_data[4096];
static ngtcp2_path null_path = {};
static ngtcp2_path new_path = {{1, (uint8_t *)"1", NULL},
                               {1, (uint8_t *)"2", NULL}};

static ngtcp2_vec *null_datav(ngtcp2_vec *datav, size_t len) {
  datav->base = null_data;
  datav->len = len;
  return datav;
}

typedef struct {
  uint64_t pkt_num;
  /* stream_data is intended to store the arguments passed in
     recv_stream_data callback. */
  struct {
    int64_t stream_id;
    int fin;
    size_t datalen;
  } stream_data;
} my_user_data;

static int client_initial(ngtcp2_conn *conn, void *user_data) {
  (void)user_data;

  ngtcp2_conn_submit_crypto_data(conn, NGTCP2_CRYPTO_LEVEL_INITIAL, null_data,
                                 217);

  return 0;
}

static int client_initial_early_data(ngtcp2_conn *conn, void *user_data) {
  (void)user_data;

  ngtcp2_conn_submit_crypto_data(conn, NGTCP2_CRYPTO_LEVEL_INITIAL, null_data,
                                 217);

  ngtcp2_conn_install_early_key(conn, null_key, null_iv, null_hp_key,
                                sizeof(null_key), sizeof(null_iv));

  return 0;
}

static int recv_client_initial(ngtcp2_conn *conn, const ngtcp2_cid *dcid,
                               void *user_data) {
  (void)conn;
  (void)dcid;
  (void)user_data;

  ngtcp2_conn_install_early_key(conn, null_key, null_iv, null_hp_key,
                                sizeof(null_key), sizeof(null_iv));

  return 0;
}

static int recv_crypto_data(ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level,
                            uint64_t offset, const uint8_t *data,
                            size_t datalen, void *user_data) {
  (void)conn;
  (void)crypto_level;
  (void)offset;
  (void)data;
  (void)datalen;
  (void)user_data;
  return 0;
}

static int recv_crypto_data_server_early_data(ngtcp2_conn *conn,
                                              ngtcp2_crypto_level crypto_level,
                                              uint64_t offset,
                                              const uint8_t *data,
                                              size_t datalen, void *user_data) {
  (void)offset;
  (void)crypto_level;
  (void)data;
  (void)datalen;
  (void)user_data;

  assert(conn->server);

  ngtcp2_conn_submit_crypto_data(conn, NGTCP2_CRYPTO_LEVEL_INITIAL, null_data,
                                 179);

  ngtcp2_conn_install_handshake_key(conn, null_key, null_iv, null_hp_key,
                                    null_key, null_iv, null_hp_key,
                                    sizeof(null_key), sizeof(null_iv));

  ngtcp2_conn_install_key(conn, null_secret, null_secret, null_key, null_iv,
                          null_hp_key, null_key, null_iv, null_hp_key,
                          sizeof(null_secret), sizeof(null_key),
                          sizeof(null_iv));

  conn->callbacks.recv_crypto_data = recv_crypto_data;

  return 0;
}

static int update_key(ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
                      uint8_t *rx_key, uint8_t *rx_iv, uint8_t *tx_key,
                      uint8_t *tx_iv, const uint8_t *current_rx_secret,
                      const uint8_t *current_tx_secret, size_t secretlen,
                      void *user_data) {
  (void)conn;
  (void)current_rx_secret;
  (void)current_tx_secret;
  (void)user_data;

  assert(sizeof(null_secret) == secretlen);

  memset(rx_secret, 0xff, sizeof(null_secret));
  memset(tx_secret, 0xff, sizeof(null_secret));
  memset(rx_key, 0xff, sizeof(null_key));
  memset(rx_iv, 0xff, sizeof(null_iv));
  memset(tx_key, 0xff, sizeof(null_key));
  memset(tx_iv, 0xff, sizeof(null_iv));

  return 0;
}

static int recv_crypto_handshake_error(ngtcp2_conn *conn,
                                       ngtcp2_crypto_level crypto_level,
                                       uint64_t offset, const uint8_t *data,
                                       size_t datalen, void *user_data) {
  (void)conn;
  (void)crypto_level;
  (void)offset;
  (void)data;
  (void)datalen;
  (void)user_data;
  return NGTCP2_ERR_CRYPTO;
}

static int recv_crypto_fatal_alert_generated(ngtcp2_conn *conn,
                                             ngtcp2_crypto_level crypto_level,
                                             uint64_t offset,
                                             const uint8_t *data,
                                             size_t datalen, void *user_data) {
  (void)conn;
  (void)crypto_level;
  (void)offset;
  (void)data;
  (void)datalen;
  (void)user_data;
  return NGTCP2_ERR_CRYPTO;
}

static int recv_crypto_data_server(ngtcp2_conn *conn,
                                   ngtcp2_crypto_level crypto_level,
                                   uint64_t offset, const uint8_t *data,
                                   size_t datalen, void *user_data) {
  (void)offset;
  (void)data;
  (void)datalen;
  (void)user_data;

  ngtcp2_conn_submit_crypto_data(conn,
                                 crypto_level == NGTCP2_CRYPTO_LEVEL_INITIAL
                                     ? NGTCP2_CRYPTO_LEVEL_INITIAL
                                     : NGTCP2_CRYPTO_LEVEL_HANDSHAKE,
                                 null_data, 218);

  return 0;
}

static int recv_stream_data(ngtcp2_conn *conn, int64_t stream_id, int fin,
                            uint64_t offset, const uint8_t *data,
                            size_t datalen, void *user_data,
                            void *stream_user_data) {
  my_user_data *ud = user_data;
  (void)conn;
  (void)offset;
  (void)data;
  (void)stream_user_data;

  if (ud) {
    ud->stream_data.stream_id = stream_id;
    ud->stream_data.fin = fin;
    ud->stream_data.datalen = datalen;
  }

  return 0;
}

static int
recv_stream_data_shutdown_stream_read(ngtcp2_conn *conn, int64_t stream_id,
                                      int fin, uint64_t offset,
                                      const uint8_t *data, size_t datalen,
                                      void *user_data, void *stream_user_data) {
  int rv;

  recv_stream_data(conn, stream_id, fin, offset, data, datalen, user_data,
                   stream_user_data);

  rv = ngtcp2_conn_shutdown_stream_read(conn, stream_id, NGTCP2_APP_ERR01);
  if (rv != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int recv_retry(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                      const ngtcp2_pkt_retry *retry, void *user_data) {
  (void)conn;
  (void)hd;
  (void)retry;
  (void)user_data;
  return 0;
}

static int genrand(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                   ngtcp2_rand_ctx ctx, void *user_data) {
  (void)conn;
  (void)ctx;
  (void)user_data;

  memset(dest, 0, destlen);

  return 0;
}

static void server_default_settings(ngtcp2_settings *settings) {
  size_t i;
  ngtcp2_transport_params *params = &settings->transport_params;

  memset(settings, 0, sizeof(*settings));
  settings->log_printf = NULL;
  settings->initial_ts = 0;
  params->initial_max_stream_data_bidi_local = 65535;
  params->initial_max_stream_data_bidi_remote = 65535;
  params->initial_max_stream_data_uni = 65535;
  params->initial_max_data = 128 * 1024;
  params->initial_max_streams_bidi = 3;
  params->initial_max_streams_uni = 2;
  params->max_idle_timeout = 60;
  params->max_packet_size = 65535;
  params->stateless_reset_token_present = 1;
  params->active_connection_id_limit = 8;
  for (i = 0; i < NGTCP2_STATELESS_RESET_TOKENLEN; ++i) {
    params->stateless_reset_token[i] = (uint8_t)i;
  }
}

static void client_default_settings(ngtcp2_settings *settings) {
  ngtcp2_transport_params *params = &settings->transport_params;

  memset(settings, 0, sizeof(*settings));
  settings->log_printf = NULL;
  settings->initial_ts = 0;
  params->initial_max_stream_data_bidi_local = 65535;
  params->initial_max_stream_data_bidi_remote = 65535;
  params->initial_max_stream_data_uni = 65535;
  params->initial_max_data = 128 * 1024;
  params->initial_max_streams_bidi = 0;
  params->initial_max_streams_uni = 2;
  params->max_idle_timeout = 60;
  params->max_packet_size = 65535;
  params->stateless_reset_token_present = 0;
  params->active_connection_id_limit = 8;
}

static void setup_default_server(ngtcp2_conn **pconn) {
  ngtcp2_conn_callbacks cb;
  ngtcp2_settings settings;
  ngtcp2_cid dcid, scid;
  ngtcp2_transport_params *params;

  dcid_init(&dcid);
  scid_init(&scid);

  memset(&cb, 0, sizeof(cb));
  cb.decrypt = null_decrypt;
  cb.encrypt = null_encrypt;
  cb.hp_mask = null_hp_mask;
  cb.recv_crypto_data = recv_crypto_data;
  cb.get_new_connection_id = get_new_connection_id;
  cb.rand = genrand;
  cb.update_key = update_key;
  server_default_settings(&settings);

  ngtcp2_conn_server_new(pconn, &dcid, &scid, &null_path, NGTCP2_PROTO_VER_MAX,
                         &cb, &settings, /* mem = */ NULL, NULL);
  ngtcp2_conn_install_handshake_key(*pconn, null_key, null_iv, null_hp_key,
                                    null_key, null_iv, null_hp_key,
                                    sizeof(null_key), sizeof(null_iv));
  ngtcp2_conn_install_key(*pconn, null_secret, null_secret, null_key, null_iv,
                          null_hp_key, null_key, null_iv, null_hp_key,
                          sizeof(null_secret), sizeof(null_key),
                          sizeof(null_iv));
  ngtcp2_conn_set_aead_overhead(*pconn, NGTCP2_FAKE_AEAD_OVERHEAD);
  (*pconn)->state = NGTCP2_CS_POST_HANDSHAKE;
  (*pconn)->flags |= NGTCP2_CONN_FLAG_CONN_ID_NEGOTIATED |
                     NGTCP2_CONN_FLAG_SADDR_VERIFIED |
                     NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED |
                     NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED_HANDLED |
                     NGTCP2_CONN_FLAG_HANDSHAKE_CONFIRMED;
  params = &(*pconn)->remote.transport_params;
  params->initial_max_stream_data_bidi_local = 64 * 1024;
  params->initial_max_stream_data_bidi_remote = 64 * 1024;
  params->initial_max_stream_data_uni = 64 * 1024;
  params->initial_max_streams_bidi = 0;
  params->initial_max_streams_uni = 1;
  params->initial_max_data = 64 * 1024;
  params->active_connection_id_limit = 8;
  (*pconn)->local.bidi.max_streams = params->initial_max_streams_bidi;
  (*pconn)->local.uni.max_streams = params->initial_max_streams_uni;
  (*pconn)->tx.max_offset = params->initial_max_data;
  (*pconn)->odcid = dcid;
}

static void setup_default_client(ngtcp2_conn **pconn) {
  ngtcp2_conn_callbacks cb;
  ngtcp2_settings settings;
  ngtcp2_cid dcid, scid;
  ngtcp2_transport_params *params;

  dcid_init(&dcid);
  scid_init(&scid);

  memset(&cb, 0, sizeof(cb));
  cb.decrypt = null_decrypt;
  cb.encrypt = null_encrypt;
  cb.hp_mask = null_hp_mask;
  cb.recv_crypto_data = recv_crypto_data;
  cb.get_new_connection_id = get_new_connection_id;
  cb.update_key = update_key;
  client_default_settings(&settings);

  ngtcp2_conn_client_new(pconn, &dcid, &scid, &null_path, NGTCP2_PROTO_VER_MAX,
                         &cb, &settings, /* mem = */ NULL, NULL);
  ngtcp2_conn_install_handshake_key(*pconn, null_key, null_iv, null_hp_key,
                                    null_key, null_iv, null_hp_key,
                                    sizeof(null_key), sizeof(null_iv));
  ngtcp2_conn_install_key(*pconn, null_secret, null_secret, null_key, null_iv,
                          null_hp_key, null_key, null_iv, null_hp_key,
                          sizeof(null_secret), sizeof(null_key),
                          sizeof(null_iv));
  ngtcp2_conn_set_aead_overhead(*pconn, NGTCP2_FAKE_AEAD_OVERHEAD);
  (*pconn)->state = NGTCP2_CS_POST_HANDSHAKE;
  (*pconn)->flags |= NGTCP2_CONN_FLAG_CONN_ID_NEGOTIATED |
                     NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED |
                     NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED_HANDLED |
                     NGTCP2_CONN_FLAG_HANDSHAKE_CONFIRMED;
  params = &(*pconn)->remote.transport_params;
  params->initial_max_stream_data_bidi_local = 64 * 1024;
  params->initial_max_stream_data_bidi_remote = 64 * 1024;
  params->initial_max_stream_data_uni = 64 * 1024;
  params->initial_max_streams_bidi = 1;
  params->initial_max_streams_uni = 1;
  params->initial_max_data = 64 * 1024;
  params->active_connection_id_limit = 8;
  (*pconn)->local.bidi.max_streams = params->initial_max_streams_bidi;
  (*pconn)->local.uni.max_streams = params->initial_max_streams_uni;
  (*pconn)->tx.max_offset = params->initial_max_data;
  (*pconn)->odcid = dcid;

  memset((*pconn)->dcid.current.token, 0xf1, NGTCP2_STATELESS_RESET_TOKENLEN);
}

static void setup_handshake_server(ngtcp2_conn **pconn) {
  ngtcp2_conn_callbacks cb;
  ngtcp2_settings settings;
  ngtcp2_cid dcid, scid;

  dcid_init(&dcid);
  scid_init(&scid);

  memset(&cb, 0, sizeof(cb));
  cb.recv_client_initial = recv_client_initial;
  cb.recv_crypto_data = recv_crypto_data_server;
  cb.decrypt = null_decrypt;
  cb.encrypt = null_encrypt;
  cb.hp_mask = null_hp_mask;
  cb.get_new_connection_id = get_new_connection_id;
  cb.rand = genrand;
  server_default_settings(&settings);

  ngtcp2_conn_server_new(pconn, &dcid, &scid, &null_path, NGTCP2_PROTO_VER_MAX,
                         &cb, &settings, /* mem = */ NULL, NULL);
  ngtcp2_conn_install_initial_key(*pconn, null_key, null_iv, null_hp_key,
                                  null_key, null_iv, null_hp_key,
                                  sizeof(null_key), sizeof(null_iv));
  ngtcp2_conn_install_handshake_key(*pconn, null_key, null_iv, null_hp_key,
                                    null_key, null_iv, null_hp_key,
                                    sizeof(null_key), sizeof(null_iv));
  ngtcp2_conn_set_aead_overhead(*pconn, NGTCP2_FAKE_AEAD_OVERHEAD);
}

static void setup_handshake_client(ngtcp2_conn **pconn) {
  ngtcp2_conn_callbacks cb;
  ngtcp2_settings settings;
  ngtcp2_cid rcid, scid;
  ngtcp2_crypto_aead retry_aead = {0};

  rcid_init(&rcid);
  scid_init(&scid);

  memset(&cb, 0, sizeof(cb));
  cb.client_initial = client_initial;
  cb.recv_crypto_data = recv_crypto_data;
  cb.decrypt = null_decrypt;
  cb.encrypt = null_encrypt;
  cb.hp_mask = null_hp_mask;
  cb.get_new_connection_id = get_new_connection_id;
  client_default_settings(&settings);

  ngtcp2_conn_client_new(pconn, &rcid, &scid, &null_path, NGTCP2_PROTO_VER_MAX,
                         &cb, &settings, /* mem = */ NULL, NULL);
  ngtcp2_conn_install_initial_key(*pconn, null_key, null_iv, null_hp_key,
                                  null_key, null_iv, null_hp_key,
                                  sizeof(null_key), sizeof(null_iv));
  ngtcp2_conn_set_retry_aead(*pconn, &retry_aead);
}

static void setup_early_server(ngtcp2_conn **pconn) {
  ngtcp2_conn_callbacks cb;
  ngtcp2_settings settings;
  ngtcp2_transport_params *params;
  ngtcp2_cid dcid, scid;

  dcid_init(&dcid);
  scid_init(&scid);

  memset(&cb, 0, sizeof(cb));
  cb.recv_client_initial = recv_client_initial;
  cb.recv_crypto_data = recv_crypto_data_server_early_data;
  cb.decrypt = null_decrypt;
  cb.encrypt = null_encrypt;
  cb.hp_mask = null_hp_mask;
  cb.get_new_connection_id = get_new_connection_id;
  cb.rand = genrand;
  server_default_settings(&settings);

  ngtcp2_conn_server_new(pconn, &dcid, &scid, &null_path, NGTCP2_PROTO_VER_MAX,
                         &cb, &settings, /* mem = */ NULL, NULL);
  ngtcp2_conn_install_initial_key(*pconn, null_key, null_iv, null_hp_key,
                                  null_key, null_iv, null_hp_key,
                                  sizeof(null_key), sizeof(null_iv));
  ngtcp2_conn_set_aead_overhead(*pconn, NGTCP2_FAKE_AEAD_OVERHEAD);
  params = &(*pconn)->remote.transport_params;
  params->initial_max_stream_data_bidi_local = 64 * 1024;
  params->initial_max_stream_data_bidi_remote = 64 * 1024;
  params->initial_max_stream_data_uni = 64 * 1024;
  params->initial_max_streams_bidi = 0;
  params->initial_max_streams_uni = 1;
  params->initial_max_data = 64 * 1024;
  (*pconn)->local.bidi.max_streams = params->initial_max_streams_bidi;
  (*pconn)->local.uni.max_streams = params->initial_max_streams_uni;
  (*pconn)->tx.max_offset = params->initial_max_data;
}

static void setup_early_client(ngtcp2_conn **pconn) {
  ngtcp2_conn_callbacks cb;
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  ngtcp2_cid rcid, scid;

  rcid_init(&rcid);
  scid_init(&scid);

  memset(&cb, 0, sizeof(cb));
  cb.client_initial = client_initial_early_data;
  cb.recv_crypto_data = recv_crypto_data;
  cb.decrypt = null_decrypt;
  cb.encrypt = null_encrypt;
  cb.hp_mask = null_hp_mask;
  cb.get_new_connection_id = get_new_connection_id;
  client_default_settings(&settings);

  ngtcp2_conn_client_new(pconn, &rcid, &scid, &null_path, NGTCP2_PROTO_VER_MAX,
                         &cb, &settings, /* mem = */ NULL, NULL);
  ngtcp2_conn_install_initial_key(*pconn, null_key, null_iv, null_hp_key,
                                  null_key, null_iv, null_hp_key,
                                  sizeof(null_key), sizeof(null_iv));
  ngtcp2_conn_set_aead_overhead(*pconn, NGTCP2_FAKE_AEAD_OVERHEAD);

  memset(&params, 0, sizeof(params));
  params.initial_max_stream_data_bidi_local = 64 * 1024;
  params.initial_max_stream_data_bidi_remote = 64 * 1024;
  params.initial_max_stream_data_uni = 64 * 1024;
  params.initial_max_streams_bidi = 1;
  params.initial_max_streams_uni = 1;
  params.initial_max_data = 64 * 1024;

  ngtcp2_conn_set_early_remote_transport_params(*pconn, &params);
}

void test_ngtcp2_conn_stream_open_close(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  int rv;
  ngtcp2_frame fr;
  ngtcp2_strm *strm;
  int64_t stream_id;

  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 17;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 1, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(0 == rv);

  strm = ngtcp2_conn_find_stream(conn, 4);

  CU_ASSERT(NGTCP2_STRM_FLAG_NONE == strm->flags);

  fr.stream.fin = 1;
  fr.stream.offset = 17;
  fr.stream.datacnt = 0;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 2, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 2);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NGTCP2_STRM_FLAG_SHUT_RD == strm->flags);
  CU_ASSERT(fr.stream.offset == strm->rx.last_offset);
  CU_ASSERT(fr.stream.offset == ngtcp2_strm_rx_offset(strm));

  spktlen =
      ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), NULL,
                               NGTCP2_WRITE_STREAM_FLAG_NONE, 4, 1, NULL, 0, 3);

  CU_ASSERT(spktlen > 0);

  strm = ngtcp2_conn_find_stream(conn, 4);

  CU_ASSERT(NULL != strm);

  /* Open a remote unidirectional stream */
  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 2;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 19;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 3, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 3);

  CU_ASSERT(0 == rv);

  strm = ngtcp2_conn_find_stream(conn, 2);

  CU_ASSERT(NGTCP2_STRM_FLAG_SHUT_WR == strm->flags);
  CU_ASSERT(fr.stream.data[0].len == strm->rx.last_offset);
  CU_ASSERT(fr.stream.data[0].len == ngtcp2_strm_rx_offset(strm));

  /* Open a local unidirectional stream */
  rv = ngtcp2_conn_open_uni_stream(conn, &stream_id, NULL);

  CU_ASSERT(0 == rv);
  CU_ASSERT(3 == stream_id);

  rv = ngtcp2_conn_open_uni_stream(conn, &stream_id, NULL);

  CU_ASSERT(NGTCP2_ERR_STREAM_ID_BLOCKED == rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_stream_rx_flow_control(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  int rv;
  ngtcp2_frame fr;
  ngtcp2_strm *strm;
  size_t i;
  int64_t stream_id;

  setup_default_server(&conn);

  conn->local.settings.transport_params.initial_max_stream_data_bidi_remote =
      2047;

  for (i = 0; i < 3; ++i) {
    stream_id = (int64_t)(i * 4);
    fr.type = NGTCP2_FRAME_STREAM;
    fr.stream.flags = 0;
    fr.stream.stream_id = stream_id;
    fr.stream.fin = 0;
    fr.stream.offset = 0;
    fr.stream.datacnt = 1;
    fr.stream.data[0].len = 1024;
    fr.stream.data[0].base = null_data;

    pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                    (int64_t)i, &fr);
    rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

    CU_ASSERT(0 == rv);

    strm = ngtcp2_conn_find_stream(conn, stream_id);

    CU_ASSERT(NULL != strm);

    rv = ngtcp2_conn_extend_max_stream_offset(conn, stream_id,
                                              fr.stream.data[0].len);

    CU_ASSERT(0 == rv);
  }

  CU_ASSERT(3 == ngtcp2_pq_size(&conn->tx.strmq));

  strm = ngtcp2_conn_find_stream(conn, 0);

  CU_ASSERT(ngtcp2_strm_is_tx_queued(strm));

  strm = ngtcp2_conn_find_stream(conn, 4);

  CU_ASSERT(ngtcp2_strm_is_tx_queued(strm));

  strm = ngtcp2_conn_find_stream(conn, 8);

  CU_ASSERT(ngtcp2_strm_is_tx_queued(strm));

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), 2);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(ngtcp2_pq_empty(&conn->tx.strmq));

  for (i = 0; i < 3; ++i) {
    stream_id = (int64_t)(i * 4);
    strm = ngtcp2_conn_find_stream(conn, stream_id);

    CU_ASSERT(2047 + 1024 == strm->rx.max_offset);
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

  conn->local.settings.transport_params.initial_max_stream_data_bidi_remote =
      1023;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1024;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 1, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(NGTCP2_ERR_FLOW_CONTROL == rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_stream_tx_flow_control(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  int rv;
  ngtcp2_frame fr;
  ngtcp2_strm *strm;
  ngtcp2_ssize nwrite;
  int64_t stream_id;

  setup_default_client(&conn);

  conn->remote.transport_params.initial_max_stream_data_bidi_remote = 2047;

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  CU_ASSERT(0 == rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);
  spktlen = ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), &nwrite,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     0, null_data, 1024, 1);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(1024 == nwrite);
  CU_ASSERT(1024 == strm->tx.offset);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), &nwrite,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     0, null_data, 1024, 2);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(1023 == nwrite);
  CU_ASSERT(2047 == strm->tx.offset);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), &nwrite,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     0, null_data, 1024, 3);

  CU_ASSERT(NGTCP2_ERR_STREAM_DATA_BLOCKED == spktlen);

  /* We can write 0 length STREAM frame */
  spktlen = ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), &nwrite,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     0, null_data, 0, 3);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(0 == nwrite);
  CU_ASSERT(2047 == strm->tx.offset);

  fr.type = NGTCP2_FRAME_MAX_STREAM_DATA;
  fr.max_stream_data.stream_id = stream_id;
  fr.max_stream_data.max_stream_data = 2048;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 1, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 4);

  CU_ASSERT(0 == rv);
  CU_ASSERT(2048 == strm->tx.max_offset);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), &nwrite,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     0, null_data, 1024, 5);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(1 == nwrite);
  CU_ASSERT(2048 == strm->tx.offset);

  ngtcp2_conn_del(conn);

  /* CWND is too small */
  setup_default_client(&conn);

  conn->ccs.cwnd = 1;

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  CU_ASSERT(0 == rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), &nwrite,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     1, null_data, 1024, 1);

  CU_ASSERT(0 == spktlen);
  CU_ASSERT(-1 == nwrite);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_rx_flow_control(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  int rv;
  ngtcp2_frame fr;

  setup_default_server(&conn);

  conn->local.settings.transport_params.initial_max_data = 1024;
  conn->rx.max_offset = 1024;
  conn->rx.unsent_max_offset = 1024;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1023;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 1, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(0 == rv);

  ngtcp2_conn_extend_max_offset(conn, 1023);

  CU_ASSERT(1024 + 1023 == conn->rx.unsent_max_offset);
  CU_ASSERT(1024 == conn->rx.max_offset);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 1023;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 2, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 2);

  CU_ASSERT(0 == rv);

  ngtcp2_conn_extend_max_offset(conn, 1);

  CU_ASSERT(2048 == conn->rx.unsent_max_offset);
  CU_ASSERT(1024 == conn->rx.max_offset);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), 3);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(2048 == conn->rx.max_offset);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_rx_flow_control_error(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  int rv;
  ngtcp2_frame fr;

  setup_default_server(&conn);

  conn->local.settings.transport_params.initial_max_data = 1024;
  conn->rx.max_offset = 1024;
  conn->rx.unsent_max_offset = 1024;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1025;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 1, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(NGTCP2_ERR_FLOW_CONTROL == rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_tx_flow_control(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  int rv;
  ngtcp2_frame fr;
  ngtcp2_ssize nwrite;
  int64_t stream_id;

  setup_default_client(&conn);

  conn->remote.transport_params.initial_max_data = 2048;
  conn->tx.max_offset = 2048;

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  CU_ASSERT(0 == rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), &nwrite,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     0, null_data, 1024, 1);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(1024 == nwrite);
  CU_ASSERT(1024 == conn->tx.offset);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), &nwrite,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     0, null_data, 1023, 2);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(1023 == nwrite);
  CU_ASSERT(1024 + 1023 == conn->tx.offset);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), &nwrite,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     0, null_data, 1024, 3);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(1 == nwrite);
  CU_ASSERT(2048 == conn->tx.offset);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), &nwrite,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     0, null_data, 1024, 4);

  CU_ASSERT(NGTCP2_ERR_STREAM_DATA_BLOCKED == spktlen);
  CU_ASSERT(-1 == nwrite);

  fr.type = NGTCP2_FRAME_MAX_DATA;
  fr.max_data.max_data = 3072;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 1, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 5);

  CU_ASSERT(0 == rv);
  CU_ASSERT(3072 == conn->tx.max_offset);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), &nwrite,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     0, null_data, 1024, 4);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(1024 == nwrite);
  CU_ASSERT(3072 == conn->tx.offset);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_shutdown_stream_write(void) {
  ngtcp2_conn *conn;
  int rv;
  ngtcp2_frame_chain *frc;
  uint8_t buf[2048];
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_strm *strm;
  int64_t stream_id;

  /* Stream not found */
  setup_default_server(&conn);

  rv = ngtcp2_conn_shutdown_stream_write(conn, 4, NGTCP2_APP_ERR01);

  CU_ASSERT(NGTCP2_ERR_STREAM_NOT_FOUND == rv);

  ngtcp2_conn_del(conn);

  /* Check final_size */
  setup_default_client(&conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), NULL,
                           NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id, 0,
                           null_data, 1239, 1);
  rv = ngtcp2_conn_shutdown_stream_write(conn, stream_id, NGTCP2_APP_ERR01);

  CU_ASSERT(0 == rv);

  for (frc = conn->pktns.tx.frq; frc; frc = frc->next) {
    if (frc->fr.type == NGTCP2_FRAME_RESET_STREAM) {
      break;
    }
  }

  CU_ASSERT(NULL != frc);
  CU_ASSERT(stream_id == frc->fr.reset_stream.stream_id);
  CU_ASSERT(NGTCP2_APP_ERR01 == frc->fr.reset_stream.app_error_code);
  CU_ASSERT(1239 == frc->fr.reset_stream.final_size);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  CU_ASSERT(NULL != strm);
  CU_ASSERT(NGTCP2_APP_ERR01 == strm->app_error_code);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), 2);

  CU_ASSERT(spktlen > 0);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = stream_id;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR02;
  fr.reset_stream.final_size = 100;

  pktlen =
      write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 890, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 2);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL != ngtcp2_conn_find_stream(conn, stream_id));

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = conn->pktns.tx.last_pkt_num;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_blklen = 0;
  fr.ack.num_blks = 0;

  pktlen =
      write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 899, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 2);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL == ngtcp2_conn_find_stream(conn, stream_id));

  ngtcp2_conn_del(conn);

  /* Check that stream is closed when RESET_STREAM is acknowledged */
  setup_default_client(&conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = stream_id;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 0;

  pktlen =
      write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 119, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL != ngtcp2_conn_find_stream(conn, stream_id));

  rv = ngtcp2_conn_shutdown_stream_write(conn, stream_id, NGTCP2_APP_ERR01);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL != ngtcp2_conn_find_stream(conn, stream_id));

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), 2);

  CU_ASSERT(spktlen > 0);

  /* Incoming FIN does not close stream */
  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.fin = 1;
  fr.stream.offset = 0;
  fr.stream.datacnt = 0;

  pktlen =
      write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 121, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 2);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL != ngtcp2_conn_find_stream(conn, stream_id));

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = conn->pktns.tx.last_pkt_num;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_blklen = 0;
  fr.ack.num_blks = 0;

  pktlen =
      write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 332, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 3);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL == ngtcp2_conn_find_stream(conn, stream_id));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_reset_stream(void) {
  ngtcp2_conn *conn;
  int rv;
  uint8_t buf[2048];
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_strm *strm;
  int64_t stream_id;

  /* Receive RESET_STREAM */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 955;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 1, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(0 == rv);

  ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), NULL,
                           NGTCP2_WRITE_STREAM_FLAG_NONE, 4, 0, null_data, 354,
                           2);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 4;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR02;
  fr.reset_stream.final_size = 955;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 2, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 3);

  CU_ASSERT(0 == rv);

  strm = ngtcp2_conn_find_stream(conn, 4);

  CU_ASSERT(strm->flags & NGTCP2_STRM_FLAG_SHUT_RD);
  CU_ASSERT(strm->flags & NGTCP2_STRM_FLAG_RECV_RST);

  ngtcp2_conn_del(conn);

  /* Receive RESET_STREAM after sending STOP_SENDING */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 955;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 1, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(0 == rv);

  ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), NULL,
                           NGTCP2_WRITE_STREAM_FLAG_NONE, 4, 0, null_data, 354,
                           2);
  ngtcp2_conn_shutdown_stream_read(conn, 4, NGTCP2_APP_ERR01);
  ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), 3);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 4;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR02;
  fr.reset_stream.final_size = 955;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 2, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 4);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL != ngtcp2_conn_find_stream(conn, 4));

  ngtcp2_conn_del(conn);

  /* Receive RESET_STREAM after sending RESET_STREAM */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 955;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 1, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(0 == rv);

  ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), NULL,
                           NGTCP2_WRITE_STREAM_FLAG_NONE, 4, 0, null_data, 354,
                           2);
  ngtcp2_conn_shutdown_stream_write(conn, 4, NGTCP2_APP_ERR01);
  ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), 3);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 4;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR02;
  fr.reset_stream.final_size = 955;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 2, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 4);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL != ngtcp2_conn_find_stream(conn, 4));

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = conn->pktns.tx.last_pkt_num;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_blklen = 0;
  fr.ack.num_blks = 0;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 3, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 5);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL == ngtcp2_conn_find_stream(conn, 4));

  ngtcp2_conn_del(conn);

  /* Receive RESET_STREAM after receiving STOP_SENDING */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 955;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 1, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(0 == rv);

  ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), NULL,
                           NGTCP2_WRITE_STREAM_FLAG_NONE, 4, 0, null_data, 354,
                           2);

  fr.type = NGTCP2_FRAME_STOP_SENDING;
  fr.stop_sending.stream_id = 4;
  fr.stop_sending.app_error_code = NGTCP2_APP_ERR01;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 2, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 3);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL != ngtcp2_conn_find_stream(conn, 4));

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), 4);

  CU_ASSERT(spktlen > 0);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 4;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR02;
  fr.reset_stream.final_size = 955;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 3, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 4);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL != ngtcp2_conn_find_stream(conn, 4));

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = conn->pktns.tx.last_pkt_num;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_blklen = 0;
  fr.ack.num_blks = 0;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 4, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 5);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL == ngtcp2_conn_find_stream(conn, 4));

  ngtcp2_conn_del(conn);

  /* final_size in RESET_STREAM exceeds the already received offset */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 955;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 1, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(0 == rv);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 4;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR02;
  fr.reset_stream.final_size = 954;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 2, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 2);

  CU_ASSERT(NGTCP2_ERR_FINAL_SIZE == rv);

  ngtcp2_conn_del(conn);

  /* final_size in RESET_STREAM differs from the final offset which
     STREAM frame with fin indicated. */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 1;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 955;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 1, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(0 == rv);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 4;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR02;
  fr.reset_stream.final_size = 956;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 2, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 2);

  CU_ASSERT(NGTCP2_ERR_FINAL_SIZE == rv);

  ngtcp2_conn_del(conn);

  /* RESET_STREAM against local stream which has not been initiated. */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 1;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR01;
  fr.reset_stream.final_size = 0;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 1, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(NGTCP2_ERR_STREAM_STATE == rv);

  ngtcp2_conn_del(conn);

  /* RESET_STREAM against remote stream which has not been initiated */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 0;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR01;
  fr.reset_stream.final_size = 1999;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 1, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL == ngtcp2_conn_find_stream(conn, 0));
  CU_ASSERT(4 == conn->remote.bidi.unsent_max_streams);

  ngtcp2_conn_del(conn);

  /* RESET_STREAM against remote stream which is larger than allowed
     maximum */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 16;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR01;
  fr.reset_stream.final_size = 0;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 1, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(NGTCP2_ERR_STREAM_LIMIT == rv);

  ngtcp2_conn_del(conn);

  /* RESET_STREAM against remote stream which is allowed, and no
     ngtcp2_strm object has been created */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 4;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR01;
  fr.reset_stream.final_size = 0;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 1, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(0 == rv);
  CU_ASSERT(
      ngtcp2_idtr_is_open(&conn->remote.bidi.idtr, fr.reset_stream.stream_id));

  ngtcp2_conn_del(conn);

  /* RESET_STREAM against remote stream which is allowed, and no
     ngtcp2_strm object has been created, and final_size violates
     connection-level flow control. */
  setup_default_server(&conn);

  conn->local.settings.transport_params.initial_max_stream_data_bidi_remote =
      1 << 21;

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 4;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR01;
  fr.reset_stream.final_size = 1 << 20;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 1, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(NGTCP2_ERR_FLOW_CONTROL == rv);

  ngtcp2_conn_del(conn);

  /* RESET_STREAM against remote stream which is allowed, and no
      ngtcp2_strm object has been created, and final_size violates
      stream-level flow control. */
  setup_default_server(&conn);

  conn->rx.max_offset = 1 << 21;

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 4;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR01;
  fr.reset_stream.final_size = 1 << 20;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 1, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(NGTCP2_ERR_FLOW_CONTROL == rv);

  ngtcp2_conn_del(conn);

  /* final_size in RESET_STREAM violates connection-level flow
     control */
  setup_default_server(&conn);

  conn->local.settings.transport_params.initial_max_stream_data_bidi_remote =
      1 << 21;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 955;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 1, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(0 == rv);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 4;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR02;
  fr.reset_stream.final_size = 1024 * 1024;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 2, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 2);

  CU_ASSERT(NGTCP2_ERR_FLOW_CONTROL == rv);

  ngtcp2_conn_del(conn);

  /* final_size in RESET_STREAM violates stream-level flow control */
  setup_default_server(&conn);

  conn->rx.max_offset = 1 << 21;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 955;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 1, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(0 == rv);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 4;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR02;
  fr.reset_stream.final_size = 1024 * 1024;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 2, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 2);

  CU_ASSERT(NGTCP2_ERR_FLOW_CONTROL == rv);

  ngtcp2_conn_del(conn);

  /* Receiving RESET_STREAM for a local unidirectional stream is a
     protocol violation. */
  setup_default_server(&conn);

  rv = ngtcp2_conn_open_uni_stream(conn, &stream_id, NULL);

  CU_ASSERT(0 == rv);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = stream_id;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR02;
  fr.reset_stream.final_size = 0;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 1, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(NGTCP2_ERR_PROTO == rv);

  ngtcp2_conn_del(conn);

  /* RESET_STREAM extends connection window including buffered data */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 1;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 955;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 1, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(0 == rv);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 4;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR02;
  fr.reset_stream.final_size = 1024;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 2, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 2);

  CU_ASSERT(0 == rv);
  CU_ASSERT(128 * 1024 + 1024 == conn->rx.unsent_max_offset);

  ngtcp2_conn_del(conn);

  /* Verify that connection window is properly updated when
     RESET_STREAM is received after sending STOP_SENDING */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 1;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 955;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 1, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(0 == rv);

  ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), NULL,
                           NGTCP2_WRITE_STREAM_FLAG_NONE, 4, 0, null_data, 354,
                           2);
  ngtcp2_conn_shutdown_stream_read(conn, 4, NGTCP2_APP_ERR01);
  ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), 3);

  CU_ASSERT(128 * 1024 + 956 == conn->rx.unsent_max_offset);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 4;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR02;
  fr.reset_stream.final_size = 957;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 2, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 4);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL != ngtcp2_conn_find_stream(conn, 4));
  CU_ASSERT(128 * 1024 + 956 + 1 == conn->rx.unsent_max_offset);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_stop_sending(void) {
  ngtcp2_conn *conn;
  int rv;
  uint8_t buf[2048];
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_strm *strm;
  ngtcp2_tstamp t = 0;
  int64_t pkt_num = 0;
  ngtcp2_frame_chain *frc;
  int64_t stream_id;

  /* Receive STOP_SENDING */
  setup_default_client(&conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), NULL,
                           NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id, 0,
                           null_data, 333, ++t);

  fr.type = NGTCP2_FRAME_STOP_SENDING;
  fr.stop_sending.stream_id = stream_id;
  fr.stop_sending.app_error_code = NGTCP2_APP_ERR01;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  CU_ASSERT(strm->flags & NGTCP2_STRM_FLAG_SHUT_WR);
  CU_ASSERT(strm->flags & NGTCP2_STRM_FLAG_SENT_RST);

  for (frc = conn->pktns.tx.frq; frc; frc = frc->next) {
    if (frc->fr.type == NGTCP2_FRAME_RESET_STREAM) {
      break;
    }
  }

  CU_ASSERT(NULL != frc);
  CU_ASSERT(NGTCP2_APP_ERR01 == frc->fr.reset_stream.app_error_code);
  CU_ASSERT(333 == frc->fr.reset_stream.final_size);

  ngtcp2_conn_del(conn);

  /* Receive STOP_SENDING after receiving RESET_STREAM */
  setup_default_client(&conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), NULL,
                           NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id, 0,
                           null_data, 333, ++t);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = stream_id;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR01;
  fr.reset_stream.final_size = 0;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  fr.type = NGTCP2_FRAME_STOP_SENDING;
  fr.stop_sending.stream_id = stream_id;
  fr.stop_sending.app_error_code = NGTCP2_APP_ERR01;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL != ngtcp2_conn_find_stream(conn, stream_id));

  for (frc = conn->pktns.tx.frq; frc; frc = frc->next) {
    if (frc->fr.type == NGTCP2_FRAME_RESET_STREAM) {
      break;
    }
  }

  CU_ASSERT(NULL != frc);
  CU_ASSERT(NGTCP2_APP_ERR01 == frc->fr.reset_stream.app_error_code);
  CU_ASSERT(333 == frc->fr.reset_stream.final_size);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = conn->pktns.tx.last_pkt_num;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_blklen = 0;
  fr.ack.num_blks = 0;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL == ngtcp2_conn_find_stream(conn, stream_id));

  ngtcp2_conn_del(conn);

  /* STOP_SENDING against remote bidirectional stream which has not
     been initiated. */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STOP_SENDING;
  fr.stop_sending.stream_id = 0;
  fr.stop_sending.app_error_code = NGTCP2_APP_ERR01;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 1, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(0 == rv);

  strm = ngtcp2_conn_find_stream(conn, 0);

  CU_ASSERT(NULL != strm);
  CU_ASSERT(strm->flags & NGTCP2_STRM_FLAG_SHUT_WR);

  ngtcp2_conn_del(conn);

  /* STOP_SENDING against local bidirectional stream which has not
     been initiated. */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STOP_SENDING;
  fr.stop_sending.stream_id = 1;
  fr.stop_sending.app_error_code = NGTCP2_APP_ERR01;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 1, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(NGTCP2_ERR_STREAM_STATE == rv);

  ngtcp2_conn_del(conn);

  /* Receiving STOP_SENDING for a local unidirectional stream */
  setup_default_server(&conn);

  rv = ngtcp2_conn_open_uni_stream(conn, &stream_id, NULL);

  CU_ASSERT(0 == rv);

  fr.type = NGTCP2_FRAME_STOP_SENDING;
  fr.stop_sending.stream_id = stream_id;
  fr.stop_sending.app_error_code = NGTCP2_APP_ERR01;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 1, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NGTCP2_FRAME_RESET_STREAM == conn->pktns.tx.frq->fr.type);

  ngtcp2_conn_del(conn);

  /* STOP_SENDING against local unidirectional stream which has not
     been initiated. */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STOP_SENDING;
  fr.stop_sending.stream_id = 3;
  fr.stop_sending.app_error_code = NGTCP2_APP_ERR01;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 1, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(NGTCP2_ERR_STREAM_STATE == rv);

  ngtcp2_conn_del(conn);

  /* STOP_SENDING against local bidirectional stream in Data Sent
     state.  Because all data have been acknowledged, and FIN is sent,
     RESET_STREAM is not necessary. */
  setup_default_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  CU_ASSERT(0 == rv);

  strm = ngtcp2_conn_find_stream(conn, stream_id);
  ngtcp2_strm_shutdown(strm, NGTCP2_STRM_FLAG_SHUT_WR);

  fr.type = NGTCP2_FRAME_STOP_SENDING;
  fr.stop_sending.stream_id = stream_id;
  fr.stop_sending.app_error_code = NGTCP2_APP_ERR01;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 1, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL == conn->pktns.tx.frq);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_conn_id_omitted(void) {
  ngtcp2_conn *conn;
  int rv;
  uint8_t buf[2048];
  ngtcp2_frame fr;
  size_t pktlen;
  ngtcp2_ksl_it it;
  ngtcp2_scid *scid;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.flags = 0;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 100;
  fr.stream.data[0].base = null_data;

  /* Receiving packet which has no connection ID while SCID of server
     is not empty. */
  setup_default_server(&conn);

  pktlen =
      write_single_frame_pkt_without_conn_id(conn, buf, sizeof(buf), 1, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  /* packet is just ignored */
  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL == ngtcp2_conn_find_stream(conn, 4));

  ngtcp2_conn_del(conn);

  /* Allow omission of connection ID */
  setup_default_server(&conn);
  ngtcp2_cid_zero(&conn->oscid);

  it = ngtcp2_ksl_begin(&conn->scid.set);
  scid = ngtcp2_ksl_it_get(&it);
  ngtcp2_cid_zero(&scid->cid);

  pktlen =
      write_single_frame_pkt_without_conn_id(conn, buf, sizeof(buf), 1, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL != ngtcp2_conn_find_stream(conn, 4));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_short_pkt_type(void) {
  ngtcp2_conn *conn;
  ngtcp2_pkt_hd hd;
  uint8_t buf[2048];
  ngtcp2_ssize spktlen;
  int64_t stream_id;

  /* 1 octet pkt num */
  setup_default_client(&conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     0, null_data, 19, 1);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(pkt_decode_hd_short_mask(&hd, buf, (size_t)spktlen,
                                     conn->oscid.datalen) > 0);
  CU_ASSERT(1 == hd.pkt_numlen);

  ngtcp2_conn_del(conn);

  /* 2 octets pkt num */
  setup_default_client(&conn);
  conn->pktns.rtb.largest_acked_tx_pkt_num = 0x6afa2f;
  conn->pktns.tx.last_pkt_num = 0x6afd78;

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     0, null_data, 19, 1);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(pkt_decode_hd_short_mask(&hd, buf, (size_t)spktlen,
                                     conn->oscid.datalen) > 0);
  CU_ASSERT(2 == hd.pkt_numlen);

  ngtcp2_conn_del(conn);

  /* 4 octets pkt num */
  setup_default_client(&conn);
  conn->pktns.rtb.largest_acked_tx_pkt_num = 0x6afa2f;
  conn->pktns.tx.last_pkt_num = 0x6bc106;

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     0, null_data, 19, 1);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(pkt_decode_hd_short_mask(&hd, buf, (size_t)spktlen,
                                     conn->oscid.datalen) > 0);
  CU_ASSERT(3 == hd.pkt_numlen);

  ngtcp2_conn_del(conn);

  /* 1 octet pkt num (largest)*/
  setup_default_client(&conn);
  conn->pktns.rtb.largest_acked_tx_pkt_num = 1;
  conn->pktns.tx.last_pkt_num = 127;

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     0, null_data, 19, 1);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(pkt_decode_hd_short_mask(&hd, buf, (size_t)spktlen,
                                     conn->oscid.datalen) > 0);
  CU_ASSERT(1 == hd.pkt_numlen);

  ngtcp2_conn_del(conn);

  /* 2 octet pkt num (shortest)*/
  setup_default_client(&conn);
  conn->pktns.rtb.largest_acked_tx_pkt_num = 1;
  conn->pktns.tx.last_pkt_num = 128;

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     0, null_data, 19, 1);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(pkt_decode_hd_short_mask(&hd, buf, (size_t)spktlen,
                                     conn->oscid.datalen) > 0);
  CU_ASSERT(2 == hd.pkt_numlen);

  ngtcp2_conn_del(conn);

  /* 2 octet pkt num (largest)*/
  setup_default_client(&conn);
  conn->pktns.rtb.largest_acked_tx_pkt_num = 1;
  conn->pktns.tx.last_pkt_num = 32767;

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     0, null_data, 19, 1);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(
      pkt_decode_hd_short(&hd, buf, (size_t)spktlen, conn->oscid.datalen) > 0);
  CU_ASSERT(2 == hd.pkt_numlen);

  ngtcp2_conn_del(conn);

  /* 3 octet pkt num (shortest) */
  setup_default_client(&conn);
  conn->pktns.rtb.largest_acked_tx_pkt_num = 1;
  conn->pktns.tx.last_pkt_num = 32768;

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     0, null_data, 19, 1);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(
      pkt_decode_hd_short(&hd, buf, (size_t)spktlen, conn->oscid.datalen) > 0);
  CU_ASSERT(3 == hd.pkt_numlen);

  ngtcp2_conn_del(conn);

  /* 3 octet pkt num (largest) */
  setup_default_client(&conn);
  conn->pktns.rtb.largest_acked_tx_pkt_num = 1;
  conn->pktns.tx.last_pkt_num = 8388607;

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     0, null_data, 19, 1);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(
      pkt_decode_hd_short(&hd, buf, (size_t)spktlen, conn->oscid.datalen) > 0);
  CU_ASSERT(3 == hd.pkt_numlen);

  ngtcp2_conn_del(conn);

  /* 4 octet pkt num (shortest)*/
  setup_default_client(&conn);
  conn->pktns.rtb.largest_acked_tx_pkt_num = 1;
  conn->pktns.tx.last_pkt_num = 8388608;

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     0, null_data, 19, 1);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(
      pkt_decode_hd_short(&hd, buf, (size_t)spktlen, conn->oscid.datalen) > 0);
  CU_ASSERT(4 == hd.pkt_numlen);

  ngtcp2_conn_del(conn);

  /* Overflow */
  setup_default_client(&conn);
  conn->pktns.rtb.largest_acked_tx_pkt_num = 1;
  conn->pktns.tx.last_pkt_num = NGTCP2_MAX_PKT_NUM - 1;

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     0, null_data, 19, 1);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(
      pkt_decode_hd_short(&hd, buf, (size_t)spktlen, conn->oscid.datalen) > 0);
  CU_ASSERT(4 == hd.pkt_numlen);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_stateless_reset(void) {
  ngtcp2_conn *conn;
  uint8_t buf[256];
  ngtcp2_ssize spktlen;
  int rv;
  size_t i;
  uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN];

  for (i = 0; i < NGTCP2_STATELESS_RESET_TOKENLEN; ++i) {
    token[i] = (uint8_t)~i;
  }

  /* server */
  setup_default_server(&conn);
  conn->callbacks.decrypt = fail_decrypt;
  conn->pktns.rx.max_pkt_num = 24324325;

  memcpy(conn->dcid.current.token, token, NGTCP2_STATELESS_RESET_TOKENLEN);

  spktlen = ngtcp2_pkt_write_stateless_reset(
      buf, sizeof(buf), token, null_data, NGTCP2_MIN_STATELESS_RESET_RANDLEN);

  CU_ASSERT(spktlen > 0);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, (size_t)spktlen, 1);

  CU_ASSERT(NGTCP2_ERR_DRAINING == rv);
  CU_ASSERT(NGTCP2_CS_DRAINING == conn->state);

  ngtcp2_conn_del(conn);

  /* client */
  setup_default_client(&conn);
  conn->callbacks.decrypt = fail_decrypt;
  conn->pktns.rx.max_pkt_num = 3255454;

  memcpy(conn->dcid.current.token, token, NGTCP2_STATELESS_RESET_TOKENLEN);

  spktlen =
      ngtcp2_pkt_write_stateless_reset(buf, sizeof(buf), token, null_data, 29);

  CU_ASSERT(spktlen > 0);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, (size_t)spktlen, 1);

  CU_ASSERT(NGTCP2_ERR_DRAINING == rv);
  CU_ASSERT(NGTCP2_CS_DRAINING == conn->state);

  ngtcp2_conn_del(conn);

  /* stateless reset in long packet */
  setup_default_server(&conn);
  conn->callbacks.decrypt = fail_decrypt;
  conn->pktns.rx.max_pkt_num = 754233;

  memcpy(conn->dcid.current.token, token, NGTCP2_STATELESS_RESET_TOKENLEN);

  spktlen = ngtcp2_pkt_write_stateless_reset(
      buf, sizeof(buf), token, null_data, NGTCP2_MIN_STATELESS_RESET_RANDLEN);

  CU_ASSERT(spktlen > 0);

  /* long packet */
  buf[0] |= NGTCP2_HEADER_FORM_BIT;

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, (size_t)spktlen, 1);

  CU_ASSERT(NGTCP2_ERR_DRAINING == rv);
  CU_ASSERT(NGTCP2_CS_DRAINING == conn->state);

  ngtcp2_conn_del(conn);

  /* stateless reset in long packet; parsing long header fails */
  setup_default_server(&conn);
  conn->callbacks.decrypt = fail_decrypt;
  conn->pktns.rx.max_pkt_num = 754233;

  memcpy(conn->dcid.current.token, token, NGTCP2_STATELESS_RESET_TOKENLEN);

  spktlen = ngtcp2_pkt_write_stateless_reset(
      buf, 41, token, null_data, NGTCP2_MIN_STATELESS_RESET_RANDLEN);

  CU_ASSERT(spktlen > 0);

  /* long packet */
  buf[0] |= NGTCP2_HEADER_FORM_BIT;
  buf[0] |= 0x30;
  /* Make version nonzero so that it does not look like Version
     Negotiation packet */
  buf[1] = 0xff;
  /* Make largest CID so that ngtcp2_pkt_decode_hd_long fails */
  buf[5] = 0xff;

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, (size_t)spktlen, 1);

  CU_ASSERT(NGTCP2_ERR_DRAINING == rv);
  CU_ASSERT(NGTCP2_CS_DRAINING == conn->state);

  ngtcp2_conn_del(conn);

  /* token does not match */
  setup_default_client(&conn);
  conn->callbacks.decrypt = fail_decrypt;
  conn->pktns.rx.max_pkt_num = 24324325;

  spktlen =
      ngtcp2_pkt_write_stateless_reset(buf, sizeof(buf), token, null_data, 29);

  CU_ASSERT(spktlen > 0);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, (size_t)spktlen, 1);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NGTCP2_CS_DRAINING != conn->state);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_retry(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  ngtcp2_ssize spktlen;
  uint64_t t = 0;
  ngtcp2_cid dcid;
  const uint8_t token[] = "address-validation-token";
  size_t i;
  int64_t stream_id;
  ngtcp2_ssize datalen;
  int rv;
  ngtcp2_vec datav;
  ngtcp2_strm *strm;
  ngtcp2_crypto_aead aead = {0};

  dcid_init(&dcid);
  setup_handshake_client(&conn);
  conn->callbacks.recv_retry = recv_retry;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);

  spktlen = ngtcp2_pkt_write_retry(buf, sizeof(buf), &conn->oscid, &dcid,
                                   ngtcp2_conn_get_dcid(conn), token,
                                   strsize(token), null_encrypt, &aead);

  CU_ASSERT(spktlen > 0);

  for (i = 0; i < 2; ++i) {
    rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, (size_t)spktlen, ++t);

    CU_ASSERT(0 == rv);

    spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

    if (i == 1) {
      /* Retry packet was ignored */
      CU_ASSERT(spktlen == 0);
    } else {
      CU_ASSERT(spktlen > 0);
      CU_ASSERT(1 == conn->in_pktns->tx.last_pkt_num);
      CU_ASSERT(ngtcp2_cid_eq(&dcid, ngtcp2_conn_get_dcid(conn)));
      CU_ASSERT(conn->flags & NGTCP2_CONN_FLAG_RECV_RETRY);
    }
  }

  ngtcp2_conn_del(conn);

  /* Retry packet with non-matching tag is rejected */
  setup_handshake_client(&conn);
  conn->callbacks.recv_retry = recv_retry;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);

  spktlen = ngtcp2_pkt_write_retry(buf, sizeof(buf), &conn->oscid, &dcid,
                                   ngtcp2_conn_get_dcid(conn), token,
                                   strsize(token), null_encrypt, &aead);

  CU_ASSERT(spktlen > 0);

  /* Change tag */
  buf[spktlen - 1] = 1;

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, (size_t)spktlen, ++t);

  CU_ASSERT(0 == rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(0 == spktlen);

  ngtcp2_conn_del(conn);

  /* Make sure that 0RTT packets are retransmitted */
  setup_early_client(&conn);
  conn->callbacks.recv_retry = recv_retry;

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  CU_ASSERT(0 == rv);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, buf, sizeof(buf), &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                      0, null_datav(&datav, 219), 1, ++t);

  CU_ASSERT(sizeof(buf) == spktlen);
  CU_ASSERT(219 == datalen);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, buf, sizeof(buf), &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                      0, null_datav(&datav, 119), 1, ++t);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(119 == datalen);

  spktlen = ngtcp2_pkt_write_retry(buf, sizeof(buf), &conn->oscid, &dcid,
                                   ngtcp2_conn_get_dcid(conn), token,
                                   strsize(token), null_encrypt, &aead);

  CU_ASSERT(spktlen > 0);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, (size_t)spktlen, ++t);

  CU_ASSERT(0 == rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 219 + 119);
  CU_ASSERT(2 == conn->pktns.tx.last_pkt_num);

  strm = ngtcp2_conn_find_stream(conn, stream_id);

  CU_ASSERT(0 == ngtcp2_ksl_len(&strm->tx.streamfrq));

  /* ngtcp2_conn_write_stream sends new 0RTT packet. */
  spktlen = ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), &datalen,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     0, null_data, 120, ++t);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(3 == conn->pktns.tx.last_pkt_num);
  CU_ASSERT(120 == datalen);
  CU_ASSERT(NULL == conn->pktns.tx.frq);
  CU_ASSERT(!ngtcp2_rtb_empty(&conn->pktns.rtb));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_delayed_handshake_pkt(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_frame fr;
  int rv;

  setup_default_client(&conn);

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.crypto.offset = 0;
  fr.crypto.datacnt = 1;
  fr.crypto.data[0].len = 567;
  fr.crypto.data[0].base = null_data;

  pktlen = write_single_frame_handshake_pkt(
      conn, buf, sizeof(buf), NGTCP2_PKT_HANDSHAKE, &conn->oscid,
      ngtcp2_conn_get_dcid(conn), 1, NGTCP2_PROTO_VER_MAX, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(0 == rv);
  CU_ASSERT(1 == ngtcp2_ksl_len(&conn->hs_pktns->acktr.ents));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_max_streams(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  int rv;
  ngtcp2_frame fr;

  setup_default_client(&conn);

  fr.type = NGTCP2_FRAME_MAX_STREAMS_UNI;
  fr.max_streams.max_streams = 999;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 1, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 1);

  CU_ASSERT(0 == rv);
  CU_ASSERT(999 == conn->local.uni.max_streams);

  fr.type = NGTCP2_FRAME_MAX_STREAMS_BIDI;
  fr.max_streams.max_streams = 997;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid, 2, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, 2);

  CU_ASSERT(0 == rv);
  CU_ASSERT(997 == conn->local.bidi.max_streams);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_handshake(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_frame fr;
  int64_t pkt_num = 12345689;
  ngtcp2_tstamp t = 0;
  ngtcp2_cid rcid;
  int rv;

  rcid_init(&rcid);

  setup_handshake_server(&conn);
  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.crypto.offset = 0;
  fr.crypto.datacnt = 1;
  fr.crypto.data[0].len = 45;
  fr.crypto.data[0].base = null_data;

  pktlen = write_single_frame_handshake_pkt(
      conn, buf, sizeof(buf), NGTCP2_PKT_INITIAL, &rcid,
      ngtcp2_conn_get_dcid(conn), ++pkt_num, conn->version, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_handshake_error(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_frame fr;
  int64_t pkt_num = 107;
  ngtcp2_tstamp t = 0;
  ngtcp2_cid rcid;
  int rv;

  rcid_init(&rcid);

  /* client side */
  setup_handshake_client(&conn);
  conn->callbacks.recv_crypto_data = recv_crypto_handshake_error;
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.crypto.offset = 0;
  fr.crypto.datacnt = 1;
  fr.crypto.data[0].len = 333;
  fr.crypto.data[0].base = null_data;

  pktlen = write_single_frame_handshake_pkt(
      conn, buf, sizeof(buf), NGTCP2_PKT_INITIAL, &conn->oscid,
      ngtcp2_conn_get_dcid(conn), ++pkt_num, conn->version, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(NGTCP2_ERR_CRYPTO == rv);

  ngtcp2_conn_del(conn);

  /* server side */
  setup_handshake_server(&conn);
  conn->callbacks.recv_crypto_data = recv_crypto_handshake_error;

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.crypto.offset = 0;
  fr.crypto.datacnt = 1;
  fr.crypto.data[0].len = 551;
  fr.crypto.data[0].base = null_data;

  pktlen = write_single_frame_handshake_pkt(
      conn, buf, sizeof(buf), NGTCP2_PKT_INITIAL, &rcid,
      ngtcp2_conn_get_dcid(conn), ++pkt_num, conn->version, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(NGTCP2_ERR_CRYPTO == rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_retransmit_protected(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 0;
  int64_t stream_id, stream_id_a, stream_id_b;
  ngtcp2_ksl_it it;

  /* Retransmit a packet completely */
  setup_default_client(&conn);

  ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  spktlen = ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     0, null_data, 126, ++t);

  CU_ASSERT(spktlen > 0);

  /* Kick delayed ACK timer */
  t += NGTCP2_SECONDS;

  conn->pktns.rtb.largest_acked_tx_pkt_num = 1000000007;
  it = ngtcp2_rtb_head(&conn->pktns.rtb);
  ngtcp2_conn_detect_lost_pkt(conn, &conn->pktns, &conn->rcs, ++t);
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(NULL == conn->pktns.tx.frq);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);

  CU_ASSERT(!ngtcp2_ksl_it_end(&it));

  ngtcp2_conn_del(conn);

  /* Retransmission takes place per frame basis. */
  setup_default_client(&conn);
  conn->local.bidi.max_streams = 3;

  ngtcp2_conn_open_bidi_stream(conn, &stream_id_a, NULL);
  ngtcp2_conn_open_bidi_stream(conn, &stream_id_b, NULL);

  ngtcp2_conn_shutdown_stream_write(conn, stream_id_a, NGTCP2_APP_ERR01);
  ngtcp2_conn_shutdown_stream_write(conn, stream_id_b, NGTCP2_APP_ERR01);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);

  /* Kick delayed ACK timer */
  t += NGTCP2_SECONDS;

  conn->pktns.rtb.largest_acked_tx_pkt_num = 1000000007;
  it = ngtcp2_rtb_head(&conn->pktns.rtb);
  ngtcp2_conn_detect_lost_pkt(conn, &conn->pktns, &conn->rcs, ++t);
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, (size_t)(spktlen - 1), ++t);

  CU_ASSERT(spktlen > 0);

  it = ngtcp2_rtb_head(&conn->pktns.rtb);

  CU_ASSERT(!ngtcp2_ksl_it_end(&it));
  CU_ASSERT(NULL != conn->pktns.tx.frq);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_send_max_stream_data(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_strm *strm;
  int64_t pkt_num = 890;
  ngtcp2_tstamp t = 0;
  ngtcp2_frame fr;
  int rv;
  const uint32_t datalen = 1024;

  /* MAX_STREAM_DATA should be sent */
  setup_default_server(&conn);
  conn->local.settings.transport_params.initial_max_stream_data_bidi_remote =
      datalen;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = datalen;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  rv = ngtcp2_conn_extend_max_stream_offset(conn, 4, datalen);

  CU_ASSERT(0 == rv);

  strm = ngtcp2_conn_find_stream(conn, 4);

  CU_ASSERT(ngtcp2_strm_is_tx_queued(strm));

  ngtcp2_conn_del(conn);

  /* MAX_STREAM_DATA should not be sent on incoming fin */
  setup_default_server(&conn);
  conn->local.settings.transport_params.initial_max_stream_data_bidi_remote =
      datalen;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 1;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = datalen;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  rv = ngtcp2_conn_extend_max_stream_offset(conn, 4, datalen);

  CU_ASSERT(0 == rv);

  strm = ngtcp2_conn_find_stream(conn, 4);

  CU_ASSERT(!ngtcp2_strm_is_tx_queued(strm));

  ngtcp2_conn_del(conn);

  /* MAX_STREAM_DATA should not be sent if STOP_SENDING frame is being
     sent by local endpoint */
  setup_default_server(&conn);
  conn->local.settings.transport_params.initial_max_stream_data_bidi_remote =
      datalen;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = datalen;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  rv = ngtcp2_conn_shutdown_stream_read(conn, 4, NGTCP2_APP_ERR01);

  CU_ASSERT(0 == rv);

  rv = ngtcp2_conn_extend_max_stream_offset(conn, 4, datalen);

  CU_ASSERT(0 == rv);

  strm = ngtcp2_conn_find_stream(conn, 4);

  CU_ASSERT(!ngtcp2_strm_is_tx_queued(strm));

  ngtcp2_conn_del(conn);

  /* MAX_STREAM_DATA should not be sent if stream is being reset by
     remote endpoint */
  setup_default_server(&conn);
  conn->local.settings.transport_params.initial_max_stream_data_bidi_remote =
      datalen;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = datalen;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 4;
  fr.reset_stream.app_error_code = NGTCP2_APP_ERR01;
  fr.reset_stream.final_size = datalen;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  rv = ngtcp2_conn_extend_max_stream_offset(conn, 4, datalen);

  CU_ASSERT(0 == rv);
  CU_ASSERT(ngtcp2_pq_empty(&conn->tx.strmq));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_stream_data(void) {
  uint8_t buf[1024];
  ngtcp2_conn *conn;
  my_user_data ud;
  int64_t pkt_num = 612;
  ngtcp2_tstamp t = 0;
  ngtcp2_frame fr;
  size_t pktlen;
  int rv;
  int64_t stream_id;
  size_t i;

  /* 2 STREAM frames are received in the correct order. */
  setup_default_server(&conn);
  conn->callbacks.recv_stream_data = recv_stream_data;
  conn->user_data = &ud;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 111;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(4 == ud.stream_data.stream_id);
  CU_ASSERT(0 == ud.stream_data.fin);
  CU_ASSERT(111 == ud.stream_data.datalen);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 1;
  fr.stream.offset = 111;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 99;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(4 == ud.stream_data.stream_id);
  CU_ASSERT(1 == ud.stream_data.fin);
  CU_ASSERT(99 == ud.stream_data.datalen);

  ngtcp2_conn_del(conn);

  /* 2 STREAM frames are received in the correct order, and 2nd STREAM
     frame has 0 length, and FIN bit set. */
  setup_default_server(&conn);
  conn->callbacks.recv_stream_data = recv_stream_data;
  conn->user_data = &ud;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 111;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(4 == ud.stream_data.stream_id);
  CU_ASSERT(0 == ud.stream_data.fin);
  CU_ASSERT(111 == ud.stream_data.datalen);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 1;
  fr.stream.offset = 111;
  fr.stream.datacnt = 0;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(4 == ud.stream_data.stream_id);
  CU_ASSERT(1 == ud.stream_data.fin);
  CU_ASSERT(0 == ud.stream_data.datalen);

  ngtcp2_conn_del(conn);

  /* 2 identical STREAM frames with FIN bit set are received.  The
     recv_stream_data callback should not be called for sencond STREAM
     frame. */
  setup_default_server(&conn);
  conn->callbacks.recv_stream_data = recv_stream_data;
  conn->user_data = &ud;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 1;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 111;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(4 == ud.stream_data.stream_id);
  CU_ASSERT(1 == ud.stream_data.fin);
  CU_ASSERT(111 == ud.stream_data.datalen);

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(0 == ud.stream_data.stream_id);
  CU_ASSERT(0 == ud.stream_data.fin);
  CU_ASSERT(0 == ud.stream_data.datalen);

  ngtcp2_conn_del(conn);

  /* Re-ordered STREAM frame; we first gets 0 length STREAM frame with
     FIN bit set. Then the remaining STREAM frame is received. */
  setup_default_server(&conn);
  conn->callbacks.recv_stream_data = recv_stream_data;
  conn->user_data = &ud;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 1;
  fr.stream.offset = 599;
  fr.stream.datacnt = 0;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(0 == ud.stream_data.stream_id);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 599;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(4 == ud.stream_data.stream_id);
  CU_ASSERT(1 == ud.stream_data.fin);
  CU_ASSERT(599 == ud.stream_data.datalen);

  ngtcp2_conn_del(conn);

  /* Simulate the case where packet is lost.  We first gets 0 length
     STREAM frame with FIN bit set.  Then the lost STREAM frame is
     retransmitted with FIN bit set is received. */
  setup_default_server(&conn);
  conn->callbacks.recv_stream_data = recv_stream_data;
  conn->user_data = &ud;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 1;
  fr.stream.offset = 599;
  fr.stream.datacnt = 0;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(0 == ud.stream_data.stream_id);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 1;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 599;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(4 == ud.stream_data.stream_id);
  CU_ASSERT(1 == ud.stream_data.fin);
  CU_ASSERT(599 == ud.stream_data.datalen);

  ngtcp2_conn_del(conn);

  /* Receive an unidirectional stream data */
  setup_default_client(&conn);
  conn->callbacks.recv_stream_data = recv_stream_data;
  conn->user_data = &ud;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 3;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 911;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(3 == ud.stream_data.stream_id);
  CU_ASSERT(0 == ud.stream_data.fin);
  CU_ASSERT(911 == ud.stream_data.datalen);

  ngtcp2_conn_del(conn);

  /* Receive an unidirectional stream which is beyond the limit. */
  setup_default_server(&conn);
  conn->callbacks.recv_stream_data = recv_stream_data;
  conn->remote.uni.max_streams = 0;
  conn->user_data = &ud;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 2;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 911;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(NGTCP2_ERR_STREAM_LIMIT == rv);

  ngtcp2_conn_del(conn);

  /* Receiving nonzero payload for an local unidirectional stream is a
     protocol violation. */
  setup_default_client(&conn);

  rv = ngtcp2_conn_open_uni_stream(conn, &stream_id, NULL);

  CU_ASSERT(0 == rv);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = stream_id;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 9;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(NGTCP2_ERR_STREAM_STATE == rv);

  ngtcp2_conn_del(conn);

  /* DATA on crypto stream, and TLS alert is generated. */
  setup_default_server(&conn);
  conn->callbacks.recv_crypto_data = recv_crypto_fatal_alert_generated;

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.crypto.offset = 0;
  fr.crypto.datacnt = 1;
  fr.crypto.data[0].len = 139;
  fr.crypto.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(NGTCP2_ERR_CRYPTO == rv);

  ngtcp2_conn_del(conn);

  /* 0 length STREAM frame is allowed */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 0;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL != ngtcp2_conn_find_stream(conn, 4));

  ngtcp2_conn_del(conn);

  /* After sending STOP_SENDING, receiving 2 STREAM frames with fin
     bit set must not invoke recv_stream_data callback. */
  setup_default_server(&conn);
  conn->callbacks.recv_stream_data = recv_stream_data;
  conn->user_data = &ud;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 0;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL != ngtcp2_conn_find_stream(conn, 4));

  rv = ngtcp2_conn_shutdown_stream_read(conn, 4, 99);

  CU_ASSERT(0 == rv);

  for (i = 0; i < 2; ++i) {
    fr.type = NGTCP2_FRAME_STREAM;
    fr.stream.stream_id = 4;
    fr.stream.fin = 1;
    fr.stream.offset = 0;
    fr.stream.datacnt = 1;
    fr.stream.data[0].base = null_data;
    fr.stream.data[0].len = 19;

    pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                    ++pkt_num, &fr);

    ud.stream_data.stream_id = 0;
    rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

    CU_ASSERT(0 == rv);
    CU_ASSERT(0 == ud.stream_data.stream_id);
    CU_ASSERT(19 == conn->rx.offset);
    CU_ASSERT(19 == conn->rx.unsent_max_offset -
                        conn->local.settings.transport_params.initial_max_data);
    CU_ASSERT(conn->local.settings.transport_params.initial_max_data ==
              conn->rx.max_offset);
  }

  ngtcp2_conn_del(conn);

  /* After receiving RESET_STREAM, recv_stream_data callback must not
     be invoked */
  setup_default_server(&conn);
  conn->callbacks.recv_stream_data = recv_stream_data;
  conn->user_data = &ud;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 0;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 0;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL != ngtcp2_conn_find_stream(conn, 0));

  fr.type = NGTCP2_FRAME_RESET_STREAM;
  fr.reset_stream.stream_id = 0;
  fr.reset_stream.app_error_code = 999;
  fr.reset_stream.final_size = 199;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL != ngtcp2_conn_find_stream(conn, 0));
  CU_ASSERT(199 == conn->rx.unsent_max_offset -
                       conn->local.settings.transport_params.initial_max_data);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 0;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].base = null_data;
  fr.stream.data[0].len = 198;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);
  ud.stream_data.stream_id = -1;
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(-1 == ud.stream_data.stream_id);
  CU_ASSERT(199 == conn->rx.unsent_max_offset -
                       conn->local.settings.transport_params.initial_max_data);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 0;
  fr.stream.fin = 1;
  fr.stream.offset = 198;
  fr.stream.datacnt = 1;
  fr.stream.data[0].base = null_data;
  fr.stream.data[0].len = 1;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);
  ud.stream_data.stream_id = -1;
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(-1 == ud.stream_data.stream_id);
  CU_ASSERT(199 == conn->rx.unsent_max_offset -
                       conn->local.settings.transport_params.initial_max_data);

  ngtcp2_conn_del(conn);

  /* ngtcp2_conn_shutdown_stream_read is called in recv_stream_data
     callback.  Further recv_stream_data callback must not be
     called. */
  setup_default_server(&conn);
  conn->callbacks.recv_stream_data = recv_stream_data_shutdown_stream_read;
  conn->user_data = &ud;

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 599;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 1;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(0 == ud.stream_data.stream_id);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 599;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  memset(&ud, 0, sizeof(ud));
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(4 == ud.stream_data.stream_id);
  CU_ASSERT(0 == ud.stream_data.fin);
  CU_ASSERT(599 == ud.stream_data.datalen);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_ping(void) {
  uint8_t buf[1024];
  ngtcp2_conn *conn;
  int64_t pkt_num = 133;
  ngtcp2_tstamp t = 0;
  ngtcp2_frame fr;
  size_t pktlen;
  int rv;

  setup_default_client(&conn);

  fr.type = NGTCP2_FRAME_PING;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL == conn->pktns.tx.frq);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_max_stream_data(void) {
  uint8_t buf[1024];
  ngtcp2_conn *conn;
  int64_t pkt_num = 1000000007;
  ngtcp2_tstamp t = 0;
  ngtcp2_frame fr;
  size_t pktlen;
  int rv;
  ngtcp2_strm *strm;

  /* Receiving MAX_STREAM_DATA to an uninitiated local bidirectional
     stream ID is an error */
  setup_default_client(&conn);

  fr.type = NGTCP2_FRAME_MAX_STREAM_DATA;
  fr.max_stream_data.stream_id = 4;
  fr.max_stream_data.max_stream_data = 8092;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(NGTCP2_ERR_STREAM_STATE == rv);

  ngtcp2_conn_del(conn);

  /* Receiving MAX_STREAM_DATA to an uninitiated local unidirectional
     stream ID is an error */
  setup_default_client(&conn);

  fr.type = NGTCP2_FRAME_MAX_STREAM_DATA;
  fr.max_stream_data.stream_id = 2;
  fr.max_stream_data.max_stream_data = 8092;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(NGTCP2_ERR_STREAM_STATE == rv);

  ngtcp2_conn_del(conn);

  /* Receiving MAX_STREAM_DATA to a remote bidirectional stream which
     exceeds limit */
  setup_default_client(&conn);

  fr.type = NGTCP2_FRAME_MAX_STREAM_DATA;
  fr.max_stream_data.stream_id = 1;
  fr.max_stream_data.max_stream_data = 1000000009;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(NGTCP2_ERR_STREAM_LIMIT == rv);

  ngtcp2_conn_del(conn);

  /* Receiving MAX_STREAM_DATA to a remote bidirectional stream which
     the local endpoint has not received yet. */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_MAX_STREAM_DATA;
  fr.max_stream_data.stream_id = 4;
  fr.max_stream_data.max_stream_data = 1000000009;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  strm = ngtcp2_conn_find_stream(conn, 4);

  CU_ASSERT(NULL != strm);
  CU_ASSERT(1000000009 == strm->tx.max_offset);

  ngtcp2_conn_del(conn);

  /* Receiving MAX_STREAM_DATA to a idle remote unidirectional stream
     is a protocol violation. */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_MAX_STREAM_DATA;
  fr.max_stream_data.stream_id = 2;
  fr.max_stream_data.max_stream_data = 1000000009;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(NGTCP2_ERR_STREAM_STATE == rv);

  ngtcp2_conn_del(conn);

  /* Receiving MAX_STREAM_DATA to an existing bidirectional stream */
  setup_default_server(&conn);

  strm = open_stream(conn, 4);

  fr.type = NGTCP2_FRAME_MAX_STREAM_DATA;
  fr.max_stream_data.stream_id = 4;
  fr.max_stream_data.max_stream_data = 1000000009;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(1000000009 == strm->tx.max_offset);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_send_early_data(void) {
  ngtcp2_conn *conn;
  ngtcp2_ssize spktlen;
  ngtcp2_ssize datalen;
  uint8_t buf[1024];
  int64_t stream_id;
  int rv;
  ngtcp2_tstamp t = 0;
  ngtcp2_vec datav;

  setup_early_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  CU_ASSERT(0 == rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), &datalen,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     1, null_data, 1024, ++t);

  CU_ASSERT((ngtcp2_ssize)sizeof(buf) == spktlen);
  CU_ASSERT(674 == datalen);

  ngtcp2_conn_del(conn);

  /* Verify that Handshake packet and 0-RTT packet are coalesced into
     one UDP packet. */
  setup_early_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  CU_ASSERT(0 == rv);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, buf, sizeof(buf), &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                      0, null_datav(&datav, 199), 1, ++t);

  CU_ASSERT(sizeof(buf) == spktlen);
  CU_ASSERT(199 == datalen);

  ngtcp2_conn_del(conn);

  /* 0 length 0-RTT packet with FIN bit set */
  setup_early_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  CU_ASSERT(0 == rv);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, buf, sizeof(buf), &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                      1, NULL, 0, ++t);

  CU_ASSERT(sizeof(buf) == spktlen);
  CU_ASSERT(0 == datalen);

  ngtcp2_conn_del(conn);

  /* Can write 0 length STREAM frame */
  setup_early_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  CU_ASSERT(0 == rv);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, buf, sizeof(buf), &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_NONE, -1, 0,
                                      NULL, 0, ++t);

  CU_ASSERT(spktlen > 0);

  /* We have written Initial.  Now check that STREAM frame is
     written. */
  spktlen = ngtcp2_conn_writev_stream(conn, NULL, buf, sizeof(buf), &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                      0, NULL, 0, ++t);

  CU_ASSERT(spktlen > 0);

  ngtcp2_conn_del(conn);

  /* Could not send 0-RTT data because buffer is too small. */
  setup_early_client(&conn);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  CU_ASSERT(0 == rv);

  spktlen = ngtcp2_conn_writev_stream(
      conn, NULL, buf,
      NGTCP2_MIN_LONG_HEADERLEN + 1 + ngtcp2_conn_get_dcid(conn)->datalen +
          conn->oscid.datalen + 300,
      &datalen, NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id, 1, NULL, 0, ++t);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(-1 == datalen);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_early_data(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_frame fr;
  int64_t pkt_num = 1;
  ngtcp2_tstamp t = 0;
  ngtcp2_strm *strm;
  ngtcp2_cid rcid;
  int rv;

  rcid_init(&rcid);

  setup_early_server(&conn);

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.crypto.offset = 0;
  fr.crypto.datacnt = 1;
  fr.crypto.data[0].len = 121;
  fr.crypto.data[0].base = null_data;

  pktlen = write_single_frame_handshake_pkt(
      conn, buf, sizeof(buf), NGTCP2_PKT_INITIAL, &rcid,
      ngtcp2_conn_get_dcid(conn), ++pkt_num, conn->version, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 1;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 911;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_0rtt_pkt(
      conn, buf, sizeof(buf), &rcid, ngtcp2_conn_get_dcid(conn), ++pkt_num,
      conn->version, &fr, null_key, null_iv, null_hp_key, sizeof(null_key),
      sizeof(null_iv));

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);

  strm = ngtcp2_conn_find_stream(conn, 4);

  CU_ASSERT(NULL != strm);
  CU_ASSERT(911 == strm->rx.last_offset);

  ngtcp2_conn_del(conn);

  /* Re-ordered 0-RTT packet */
  setup_early_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 1;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 119;
  fr.stream.data[0].base = null_data;

  pktlen = write_single_frame_0rtt_pkt(
      conn, buf, sizeof(buf), &rcid, ngtcp2_conn_get_dcid(conn), ++pkt_num,
      conn->version, &fr, null_key, null_iv, null_hp_key, sizeof(null_key),
      sizeof(null_iv));

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(NGTCP2_ERR_RETRY == rv);

  ngtcp2_conn_del(conn);

  /* Compound packet */
  setup_early_server(&conn);

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.crypto.offset = 0;
  fr.crypto.datacnt = 1;
  fr.crypto.data[0].len = 111;
  fr.crypto.data[0].base = null_data;

  pktlen = write_single_frame_handshake_pkt(
      conn, buf, sizeof(buf), NGTCP2_PKT_INITIAL, &rcid,
      ngtcp2_conn_get_dcid(conn), ++pkt_num, conn->version, &fr);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 1;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 999;
  fr.stream.data[0].base = null_data;

  pktlen += write_single_frame_0rtt_pkt(
      conn, buf + pktlen, sizeof(buf) - pktlen, &rcid,
      ngtcp2_conn_get_dcid(conn), ++pkt_num, conn->version, &fr, null_key,
      null_iv, null_hp_key, sizeof(null_key), sizeof(null_iv));

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);

  strm = ngtcp2_conn_find_stream(conn, 4);

  CU_ASSERT(NULL != strm);
  CU_ASSERT(999 == strm->rx.last_offset);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_compound_pkt(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_frame fr;
  int64_t pkt_num = 1;
  ngtcp2_tstamp t = 0;
  ngtcp2_acktr_entry *ackent;
  int rv;
  ngtcp2_ksl_it it;

  /* 2 QUIC long packets in one UDP packet */
  setup_handshake_server(&conn);

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.crypto.offset = 0;
  fr.crypto.datacnt = 1;
  fr.crypto.data[0].len = 131;
  fr.crypto.data[0].base = null_data;

  pktlen = write_single_frame_handshake_pkt(
      conn, buf, sizeof(buf), NGTCP2_PKT_INITIAL, &conn->oscid,
      ngtcp2_conn_get_dcid(conn), ++pkt_num, conn->version, &fr);

  pktlen += write_single_frame_handshake_pkt(
      conn, buf + pktlen, sizeof(buf) - pktlen, NGTCP2_PKT_INITIAL,
      &conn->oscid, ngtcp2_conn_get_dcid(conn), ++pkt_num, conn->version, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);

  it = ngtcp2_acktr_get(&conn->in_pktns->acktr);
  ackent = ngtcp2_ksl_it_get(&it);

  CU_ASSERT(pkt_num == ackent->pkt_num);
  CU_ASSERT(2 == ackent->len);

  ngtcp2_ksl_it_next(&it);
  ngtcp2_ksl_it_end(&it);

  ngtcp2_conn_del(conn);

  /* 1 long packet and 1 short packet in one UDP packet */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_PADDING;
  fr.padding.len = 1;

  pktlen = write_single_frame_handshake_pkt(
      conn, buf, sizeof(buf), NGTCP2_PKT_HANDSHAKE, &conn->oscid,
      ngtcp2_conn_get_dcid(conn), ++pkt_num, conn->version, &fr);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 4;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 426;
  fr.stream.data[0].base = null_data;

  pktlen += write_single_frame_pkt(conn, buf + pktlen, sizeof(buf) - pktlen,
                                   &conn->oscid, ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  it = ngtcp2_acktr_get(&conn->pktns.acktr);
  ackent = ngtcp2_ksl_it_get(&it);

  CU_ASSERT(ackent->pkt_num == pkt_num);

  it = ngtcp2_acktr_get(&conn->hs_pktns->acktr);

  CU_ASSERT(!ngtcp2_ksl_it_end(&it));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_pkt_payloadlen(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_frame fr;
  int64_t pkt_num = 1;
  ngtcp2_tstamp t = 0;
  uint64_t payloadlen;
  int rv;
  const ngtcp2_cid *dcid;

  /* Payload length is invalid */
  setup_handshake_server(&conn);

  fr.type = NGTCP2_FRAME_STREAM;
  fr.stream.stream_id = 0;
  fr.stream.fin = 0;
  fr.stream.offset = 0;
  fr.stream.datacnt = 1;
  fr.stream.data[0].len = 131;
  fr.stream.data[0].base = null_data;

  dcid = ngtcp2_conn_get_dcid(conn);

  pktlen = write_single_frame_handshake_pkt(
      conn, buf, sizeof(buf), NGTCP2_PKT_INITIAL, &conn->oscid, dcid, ++pkt_num,
      conn->version, &fr);

  payloadlen = read_pkt_payloadlen(buf, dcid, &conn->oscid);
  write_pkt_payloadlen(buf, dcid, &conn->oscid, payloadlen + 1);

  /* First packet which does not increase initial packet number space
     CRYPTO offset or it gets buffered as 0RTT is an error. */
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(NGTCP2_ERR_PROTO == rv);
  CU_ASSERT(NGTCP2_CS_SERVER_INITIAL == conn->state);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen == 0);
  CU_ASSERT(0 == ngtcp2_ksl_len(&conn->in_pktns->acktr.ents));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_writev_stream(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 0;
  int rv;
  int64_t stream_id;
  ngtcp2_vec datav = {null_data, 10};
  ngtcp2_ssize datalen;
  size_t left;

  /* 0 length STREAM should not be written if we supply nonzero length
     data. */
  setup_default_client(&conn);

  /* This will sends NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  CU_ASSERT(0 == rv);

  /*
   * Long header (1+18+1)
   * STREAM overhead (+3)
   * AEAD overhead (16)
   */
  spktlen = ngtcp2_conn_writev_stream(conn, NULL, buf, 39, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                      0, &datav, 1, ++t);

  CU_ASSERT(0 == spktlen);
  CU_ASSERT(-1 == datalen);

  ngtcp2_conn_del(conn);

  /* +1 buffer size */
  setup_default_client(&conn);

  /* This will sends NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  CU_ASSERT(0 == rv);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, buf, 40, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                      0, &datav, 1, ++t);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(1 == datalen);

  ngtcp2_conn_del(conn);

  /* Coalesces multiple STREAM frames */
  setup_default_client(&conn);
  conn->local.bidi.max_streams = 100;

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  CU_ASSERT(0 == rv);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, buf, 1200, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                      0, &datav, 1, ++t);

  CU_ASSERT(NGTCP2_ERR_WRITE_STREAM_MORE == spktlen);
  CU_ASSERT(10 == datalen);

  left = ngtcp2_ppe_left(&conn->pkt.ppe);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  CU_ASSERT(0 == rv);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, buf, 1200, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                      0, &datav, 1, ++t);

  CU_ASSERT(NGTCP2_ERR_WRITE_STREAM_MORE == spktlen);
  CU_ASSERT(10 == datalen);
  CU_ASSERT(ngtcp2_ppe_left(&conn->pkt.ppe) < left);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);

  ngtcp2_conn_del(conn);

  /* 0RTT: Coalesces multiple STREAM frames */
  setup_early_client(&conn);
  conn->local.bidi.max_streams = 100;

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  CU_ASSERT(0 == rv);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, buf, 1200, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                      0, &datav, 1, ++t);

  CU_ASSERT(NGTCP2_ERR_WRITE_STREAM_MORE == spktlen);
  CU_ASSERT(10 == datalen);

  left = ngtcp2_ppe_left(&conn->pkt.ppe);

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);

  CU_ASSERT(0 == rv);

  spktlen = ngtcp2_conn_writev_stream(conn, NULL, buf, 1200, &datalen,
                                      NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id,
                                      0, &datav, 1, ++t);

  CU_ASSERT(NGTCP2_ERR_WRITE_STREAM_MORE == spktlen);
  CU_ASSERT(10 == datalen);
  CU_ASSERT(ngtcp2_ppe_left(&conn->pkt.ppe) < left);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  /* Make sure that packet is padded */
  CU_ASSERT(1200 == spktlen);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_new_connection_id(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 0;
  int64_t pkt_num = 0;
  ngtcp2_frame fr;
  ngtcp2_frame frs[4];
  const uint8_t cid[] = {0xf0, 0xf1, 0xf2, 0xf3};
  const uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN] = {0xff};
  const uint8_t cid2[] = {0xf0, 0xf1, 0xf2, 0xf4};
  const uint8_t token2[NGTCP2_STATELESS_RESET_TOKENLEN] = {0xfe};
  const uint8_t cid3[] = {0xf0, 0xf1, 0xf2, 0xf5};
  const uint8_t token3[NGTCP2_STATELESS_RESET_TOKENLEN] = {0xfd};
  ngtcp2_dcid *dcid;
  int rv;
  ngtcp2_frame_chain *frc;

  setup_default_client(&conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);

  fr.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = 1;
  fr.new_connection_id.retire_prior_to = 0;
  ngtcp2_cid_init(&fr.new_connection_id.cid, cid, sizeof(cid));
  memcpy(fr.new_connection_id.stateless_reset_token, token, sizeof(token));

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(1 == ngtcp2_ringbuf_len(&conn->dcid.unused));

  assert(ngtcp2_ringbuf_len(&conn->dcid.unused));
  dcid = ngtcp2_ringbuf_get(&conn->dcid.unused, 0);

  CU_ASSERT(ngtcp2_cid_eq(&fr.new_connection_id.cid, &dcid->cid));
  CU_ASSERT(0 == memcmp(fr.new_connection_id.stateless_reset_token, dcid->token,
                        sizeof(fr.new_connection_id.stateless_reset_token)));

  fr.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = 2;
  fr.new_connection_id.retire_prior_to = 2;
  ngtcp2_cid_init(&fr.new_connection_id.cid, cid2, sizeof(cid2));
  memcpy(fr.new_connection_id.stateless_reset_token, token2, sizeof(token2));

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(0 == ngtcp2_ringbuf_len(&conn->dcid.unused));
  CU_ASSERT(2 == conn->dcid.current.seq);
  CU_ASSERT(NULL != conn->pktns.tx.frq);
  CU_ASSERT(2 == conn->dcid.retire_prior_to);

  frc = conn->pktns.tx.frq;

  CU_ASSERT(NGTCP2_FRAME_RETIRE_CONNECTION_ID == frc->fr.type);

  frc = frc->next;

  CU_ASSERT(NGTCP2_FRAME_RETIRE_CONNECTION_ID == frc->fr.type);
  CU_ASSERT(NULL == frc->next);

  /* This will send RETIRE_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);

  ngtcp2_conn_del(conn);

  /* Received connection ID is immediately retired due to packet
     reordering */
  setup_default_client(&conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);

  fr.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = 2;
  fr.new_connection_id.retire_prior_to = 2;
  ngtcp2_cid_init(&fr.new_connection_id.cid, cid, sizeof(cid));
  memcpy(fr.new_connection_id.stateless_reset_token, token, sizeof(token));

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(0 == ngtcp2_ringbuf_len(&conn->dcid.unused));
  CU_ASSERT(2 == conn->dcid.current.seq);
  CU_ASSERT(2 == conn->dcid.retire_prior_to);

  frc = conn->pktns.tx.frq;

  CU_ASSERT(NGTCP2_FRAME_RETIRE_CONNECTION_ID == frc->fr.type);
  CU_ASSERT(NULL == frc->next);

  /* This will send RETIRE_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);

  fr.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = 1;
  fr.new_connection_id.retire_prior_to = 0;
  ngtcp2_cid_init(&fr.new_connection_id.cid, cid2, sizeof(cid2));
  memcpy(fr.new_connection_id.stateless_reset_token, token2, sizeof(token2));

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(0 == ngtcp2_ringbuf_len(&conn->dcid.unused));
  CU_ASSERT(2 == conn->dcid.current.seq);
  CU_ASSERT(2 == conn->dcid.retire_prior_to);

  frc = conn->pktns.tx.frq;

  CU_ASSERT(NGTCP2_FRAME_RETIRE_CONNECTION_ID == frc->fr.type);
  CU_ASSERT(NULL == frc->next);

  ngtcp2_conn_del(conn);

  /* ngtcp2_pv contains DCIDs that should be retired. */
  setup_default_server(&conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);

  assert(NULL == conn->pv);

  frs[0].type = NGTCP2_FRAME_PING;
  frs[1].type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  frs[1].new_connection_id.seq = 1;
  frs[1].new_connection_id.retire_prior_to = 0;
  ngtcp2_cid_init(&frs[1].new_connection_id.cid, cid, sizeof(cid));
  memcpy(frs[1].new_connection_id.stateless_reset_token, token, sizeof(token));
  frs[2].type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  frs[2].new_connection_id.seq = 2;
  frs[2].new_connection_id.retire_prior_to = 0;
  ngtcp2_cid_init(&frs[2].new_connection_id.cid, cid2, sizeof(cid2));
  memcpy(frs[2].new_connection_id.stateless_reset_token, token2,
         sizeof(token2));
  frs[3].type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  frs[3].new_connection_id.seq = 3;
  frs[3].new_connection_id.retire_prior_to = 0;
  ngtcp2_cid_init(&frs[3].new_connection_id.cid, cid3, sizeof(cid3));
  memcpy(frs[3].new_connection_id.stateless_reset_token, token3,
         sizeof(token3));

  pktlen = write_pkt(conn, buf, sizeof(buf), &conn->oscid, ++pkt_num, frs, 4);
  rv = ngtcp2_conn_read_pkt(conn, &new_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  assert(NULL != conn->pv);

  CU_ASSERT(conn->pv->flags & NGTCP2_PV_FLAG_FALLBACK_ON_FAILURE);
  CU_ASSERT(1 == conn->pv->dcid.seq);
  CU_ASSERT(0 == conn->pv->fallback_dcid.seq);
  CU_ASSERT(2 == ngtcp2_ringbuf_len(&conn->dcid.unused));

  fr.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = 3;
  fr.new_connection_id.retire_prior_to = 2;
  ngtcp2_cid_init(&fr.new_connection_id.cid, cid3, sizeof(cid3));
  memcpy(fr.new_connection_id.stateless_reset_token, token3, sizeof(token3));

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &new_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(0 == ngtcp2_ringbuf_len(&conn->dcid.unused));
  CU_ASSERT(conn->pv->flags & NGTCP2_PV_FLAG_FALLBACK_ON_FAILURE);
  CU_ASSERT(2 == conn->pv->dcid.seq);
  CU_ASSERT(3 == conn->pv->fallback_dcid.seq);

  frc = conn->pktns.tx.frq;

  CU_ASSERT(NGTCP2_FRAME_RETIRE_CONNECTION_ID == frc->fr.type);
  CU_ASSERT(0 == frc->fr.retire_connection_id.seq);
  frc = frc->next;

  CU_ASSERT(NGTCP2_FRAME_RETIRE_CONNECTION_ID == frc->fr.type);
  CU_ASSERT(1 == frc->fr.retire_connection_id.seq);
  CU_ASSERT(NULL == frc->next);

  ngtcp2_conn_del(conn);

  /* ngtcp2_pv contains DCID in fallback that should be retired and
     there is not enough connection ID left.  */
  setup_default_server(&conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);

  assert(NULL == conn->pv);

  frs[0].type = NGTCP2_FRAME_PING;
  frs[1].type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  frs[1].new_connection_id.seq = 1;
  frs[1].new_connection_id.retire_prior_to = 0;
  ngtcp2_cid_init(&frs[1].new_connection_id.cid, cid, sizeof(cid));
  memcpy(frs[1].new_connection_id.stateless_reset_token, token, sizeof(token));

  pktlen = write_pkt(conn, buf, sizeof(buf), &conn->oscid, ++pkt_num, frs, 2);
  rv = ngtcp2_conn_read_pkt(conn, &new_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  assert(NULL != conn->pv);

  CU_ASSERT(conn->pv->flags & NGTCP2_PV_FLAG_FALLBACK_ON_FAILURE);
  CU_ASSERT(1 == conn->pv->dcid.seq);
  CU_ASSERT(0 == conn->pv->fallback_dcid.seq);
  CU_ASSERT(0 == ngtcp2_ringbuf_len(&conn->dcid.unused));

  fr.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = 2;
  fr.new_connection_id.retire_prior_to = 2;
  ngtcp2_cid_init(&fr.new_connection_id.cid, cid2, sizeof(cid2));
  memcpy(fr.new_connection_id.stateless_reset_token, token2, sizeof(token2));

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &new_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(2 == conn->dcid.current.seq);
  CU_ASSERT(0 == ngtcp2_ringbuf_len(&conn->dcid.unused));
  CU_ASSERT(NULL == conn->pv);

  frc = conn->pktns.tx.frq;

  CU_ASSERT(NGTCP2_FRAME_RETIRE_CONNECTION_ID == frc->fr.type);
  CU_ASSERT(0 == frc->fr.retire_connection_id.seq);

  frc = frc->next;

  CU_ASSERT(NGTCP2_FRAME_RETIRE_CONNECTION_ID == frc->fr.type);
  CU_ASSERT(1 == frc->fr.retire_connection_id.seq);
  CU_ASSERT(NULL == frc->next);

  ngtcp2_conn_del(conn);

  /* ngtcp2_pv contains DCIDs that should be retired and there is not
     enough connection ID left to continue path validation.  */
  setup_default_server(&conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);

  assert(NULL == conn->pv);

  frs[0].type = NGTCP2_FRAME_PING;
  frs[1].type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  frs[1].new_connection_id.seq = 1;
  frs[1].new_connection_id.retire_prior_to = 0;
  ngtcp2_cid_init(&frs[1].new_connection_id.cid, cid, sizeof(cid));
  memcpy(frs[1].new_connection_id.stateless_reset_token, token, sizeof(token));

  pktlen = write_pkt(conn, buf, sizeof(buf), &conn->oscid, ++pkt_num, frs, 2);
  rv = ngtcp2_conn_read_pkt(conn, &new_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  assert(NULL != conn->pv);

  CU_ASSERT(conn->pv->flags & NGTCP2_PV_FLAG_FALLBACK_ON_FAILURE);
  CU_ASSERT(1 == conn->pv->dcid.seq);
  CU_ASSERT(0 == conn->pv->fallback_dcid.seq);
  CU_ASSERT(0 == ngtcp2_ringbuf_len(&conn->dcid.unused));

  /* Overwrite seq in pv->dcid so that pv->dcid cannot be renewed. */
  conn->pv->dcid.seq = 2;
  /* Internally we assume that if primary dcid and pv->dcid differ,
     then no fallback dcid is present. */
  conn->pv->flags &= (uint8_t)~NGTCP2_PV_FLAG_FALLBACK_ON_FAILURE;

  fr.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = 3;
  fr.new_connection_id.retire_prior_to = 3;
  ngtcp2_cid_init(&fr.new_connection_id.cid, cid3, sizeof(cid3));
  memcpy(fr.new_connection_id.stateless_reset_token, token3, sizeof(token3));

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &new_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(3 == conn->dcid.current.seq);
  CU_ASSERT(0 == ngtcp2_ringbuf_len(&conn->dcid.unused));
  CU_ASSERT(NULL == conn->pv);

  frc = conn->pktns.tx.frq;

  CU_ASSERT(NGTCP2_FRAME_RETIRE_CONNECTION_ID == frc->fr.type);
  CU_ASSERT(2 == frc->fr.retire_connection_id.seq);

  frc = frc->next;

  CU_ASSERT(NGTCP2_FRAME_RETIRE_CONNECTION_ID == frc->fr.type);
  CU_ASSERT(1 == frc->fr.retire_connection_id.seq);
  CU_ASSERT(NULL == frc->next);

  ngtcp2_conn_del(conn);

  /* Receiving more than advertised CID is treated as error */
  setup_default_server(&conn);
  conn->local.settings.transport_params.active_connection_id_limit = 2;

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);

  assert(NULL == conn->pv);

  frs[0].type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  frs[0].new_connection_id.seq = 1;
  frs[0].new_connection_id.retire_prior_to = 0;
  ngtcp2_cid_init(&frs[0].new_connection_id.cid, cid, sizeof(cid));
  memcpy(frs[0].new_connection_id.stateless_reset_token, token, sizeof(token));
  frs[1].type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  frs[1].new_connection_id.seq = 2;
  frs[1].new_connection_id.retire_prior_to = 0;
  ngtcp2_cid_init(&frs[1].new_connection_id.cid, cid2, sizeof(cid2));
  memcpy(frs[1].new_connection_id.stateless_reset_token, token2,
         sizeof(token2));
  frs[2].type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  frs[2].new_connection_id.seq = 3;
  frs[2].new_connection_id.retire_prior_to = 0;
  ngtcp2_cid_init(&frs[2].new_connection_id.cid, cid3, sizeof(cid3));
  memcpy(frs[2].new_connection_id.stateless_reset_token, token3,
         sizeof(token3));

  pktlen = write_pkt(conn, buf, sizeof(buf), &conn->oscid, ++pkt_num, frs, 3);
  rv = ngtcp2_conn_read_pkt(conn, &new_path, buf, pktlen, ++t);

  CU_ASSERT(NGTCP2_ERR_CONNECTION_ID_LIMIT == rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_retire_connection_id(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 1000000009;
  int64_t pkt_num = 0;
  ngtcp2_frame fr;
  int rv;
  ngtcp2_ksl_it it;
  ngtcp2_scid *scid;
  uint64_t seq;

  setup_default_client(&conn);
  conn->remote.transport_params.active_connection_id_limit = 7;

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), t);

  CU_ASSERT(spktlen > 0);

  it = ngtcp2_ksl_begin(&conn->scid.set);
  scid = ngtcp2_ksl_it_get(&it);
  seq = scid->seq;

  CU_ASSERT(NGTCP2_SCID_FLAG_NONE == scid->flags);
  CU_ASSERT(UINT64_MAX == scid->ts_retired);
  CU_ASSERT(0 == ngtcp2_pq_size(&conn->scid.used));

  fr.type = NGTCP2_FRAME_RETIRE_CONNECTION_ID;
  fr.retire_connection_id.seq = seq;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NGTCP2_SCID_FLAG_RETIRED == scid->flags);
  CU_ASSERT(1000000010 == scid->ts_retired);
  CU_ASSERT(2 == ngtcp2_pq_size(&conn->scid.used));
  CU_ASSERT(7 == ngtcp2_ksl_len(&conn->scid.set));
  CU_ASSERT(1 == conn->scid.num_retired);

  /* One NEW_CONNECTION_ID frame is setn as a replacement. */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(8 == ngtcp2_ksl_len(&conn->scid.set));
  CU_ASSERT(1 == conn->scid.num_retired);

  /* No NEW_CONNECTION_ID frames should be sent. */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen == 0);
  CU_ASSERT(8 == ngtcp2_ksl_len(&conn->scid.set));
  CU_ASSERT(1 == conn->scid.num_retired);

  /* Now time passed and still no NEW_CONNECTION_ID frames should be
     sent */
  t += 7 * NGTCP2_DEFAULT_INITIAL_RTT;
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), t);

  CU_ASSERT(spktlen == 0);
  CU_ASSERT(7 == ngtcp2_ksl_len(&conn->scid.set));
  CU_ASSERT(0 == conn->scid.num_retired);

  ngtcp2_conn_del(conn);

  /* Receiving RETIRE_CONNECTION_ID with seq which is greater than the
     sequence number previously sent must be treated as error */
  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_RETIRE_CONNECTION_ID;
  fr.retire_connection_id.seq = 1;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(NGTCP2_ERR_PROTO == rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_server_path_validation(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 900;
  int64_t pkt_num = 0;
  ngtcp2_frame fr;
  int rv;
  const uint8_t raw_cid[] = {0x0f, 0x00, 0x00, 0x00};
  ngtcp2_cid cid, *new_cid;
  const uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN] = {0xff};
  ngtcp2_path another_new_path = {{1, (uint8_t *)"1", NULL},
                                  {1, (uint8_t *)"3", NULL}};
  ngtcp2_ksl_it it;

  ngtcp2_cid_init(&cid, raw_cid, sizeof(raw_cid));

  setup_default_server(&conn);

  /* This will send NEW_CONNECTION_ID frames */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(ngtcp2_ksl_len(&conn->scid.set) > 1);

  fr.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = 1;
  fr.new_connection_id.retire_prior_to = 0;
  fr.new_connection_id.cid = cid;
  memcpy(fr.new_connection_id.stateless_reset_token, token, sizeof(token));

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  fr.type = NGTCP2_FRAME_PING;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &new_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL != conn->pv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(ngtcp2_ringbuf_len(&conn->pv->ents) > 0);

  fr.type = NGTCP2_FRAME_PATH_RESPONSE;
  memset(fr.path_response.data, 0, sizeof(fr.path_response.data));

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &new_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(ngtcp2_path_eq(&new_path, &conn->dcid.current.ps.path));
  /* DCID does not change because the client does not change its
     DCID. */
  CU_ASSERT(!ngtcp2_cid_eq(&cid, &conn->dcid.current.cid));

  /* A remote endpoint changes DCID as well */
  fr.type = NGTCP2_FRAME_PING;

  it = ngtcp2_ksl_begin(&conn->scid.set);

  assert(!ngtcp2_ksl_it_end(&it));

  new_cid = &(((ngtcp2_scid *)ngtcp2_ksl_it_get(&it))->cid);

  pktlen =
      write_single_frame_pkt(conn, buf, sizeof(buf), new_cid, ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &another_new_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL != conn->pv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(ngtcp2_ringbuf_len(&conn->pv->ents) > 0);

  fr.type = NGTCP2_FRAME_PATH_RESPONSE;
  memset(fr.path_response.data, 0, sizeof(fr.path_response.data));

  pktlen =
      write_single_frame_pkt(conn, buf, sizeof(buf), new_cid, ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &another_new_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(ngtcp2_path_eq(&another_new_path, &conn->dcid.current.ps.path));
  CU_ASSERT(ngtcp2_cid_eq(&cid, &conn->dcid.current.cid));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_client_connection_migration(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_tstamp t = 900;
  int64_t pkt_num = 0;
  ngtcp2_frame fr;
  int rv;
  const uint8_t raw_cid[] = {0x0f, 0x00, 0x00, 0x00};
  ngtcp2_cid cid;
  const uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN] = {0xff};

  ngtcp2_cid_init(&cid, raw_cid, sizeof(raw_cid));

  setup_default_client(&conn);

  fr.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = 1;
  fr.new_connection_id.retire_prior_to = 0;
  fr.new_connection_id.cid = cid;
  memcpy(fr.new_connection_id.stateless_reset_token, token, sizeof(token));

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  rv = ngtcp2_conn_initiate_migration(conn, &new_path, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL == conn->pv);
  CU_ASSERT(ngtcp2_path_eq(&new_path, &conn->dcid.current.ps.path));
  CU_ASSERT(ngtcp2_cid_eq(&cid, &conn->dcid.current.cid));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_path_challenge(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 11;
  int64_t pkt_num = 0;
  ngtcp2_frame fr;
  int rv;
  const uint8_t raw_cid[] = {0x0f, 0x00, 0x00, 0x00};
  ngtcp2_cid cid;
  const uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN] = {0xff};
  const uint8_t data[] = {0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8};
  ngtcp2_path_storage ps;

  ngtcp2_cid_init(&cid, raw_cid, sizeof(raw_cid));

  setup_default_server(&conn);

  fr.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = 1;
  fr.new_connection_id.retire_prior_to = 0;
  fr.new_connection_id.cid = cid;
  memcpy(fr.new_connection_id.stateless_reset_token, token, sizeof(token));

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  fr.type = NGTCP2_FRAME_PATH_CHALLENGE;
  memcpy(fr.path_challenge.data, data, sizeof(fr.path_challenge.data));

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &new_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(ngtcp2_ringbuf_len(&conn->rx.path_challenge) > 0);

  ngtcp2_path_storage_zero(&ps);

  spktlen = ngtcp2_conn_write_pkt(conn, &ps.path, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(ngtcp2_path_eq(&conn->dcid.current.ps.path, &ps.path));
  CU_ASSERT(0 == ngtcp2_ringbuf_len(&conn->rx.path_challenge));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_key_update(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_ssize spktlen;
  ngtcp2_tstamp t = 19393;
  int64_t pkt_num = -1;
  ngtcp2_frame fr;
  int rv;
  int64_t stream_id;
  ngtcp2_ssize nwrite;

  setup_default_server(&conn);

  /* The remote endpoint initiates key update */
  fr.type = NGTCP2_FRAME_PING;

  pktlen = write_single_frame_pkt_flags(conn, buf, sizeof(buf),
                                        NGTCP2_PKT_FLAG_KEY_PHASE, &conn->oscid,
                                        ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL != conn->crypto.key_update.old_rx_ckm);
  CU_ASSERT(NULL == conn->crypto.key_update.new_tx_ckm);
  CU_ASSERT(NULL == conn->crypto.key_update.new_rx_ckm);
  CU_ASSERT(UINT64_MAX == conn->crypto.key_update.confirmed_ts);
  CU_ASSERT(conn->flags & NGTCP2_CONN_FLAG_KEY_UPDATE_NOT_CONFIRMED);

  t += NGTCP2_SECONDS;
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), t);

  CU_ASSERT(spktlen > 0);

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = conn->pktns.tx.last_pkt_num;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_blklen = 0;
  fr.ack.num_blks = 0;

  pktlen = write_single_frame_pkt_flags(conn, buf, sizeof(buf),
                                        NGTCP2_PKT_FLAG_KEY_PHASE, &conn->oscid,
                                        ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(t == conn->crypto.key_update.confirmed_ts);
  CU_ASSERT(!(conn->flags & NGTCP2_CONN_FLAG_KEY_UPDATE_NOT_CONFIRMED));

  t += ngtcp2_conn_get_pto(conn) + 1;

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), t);

  CU_ASSERT(0 == spktlen);
  CU_ASSERT(NULL == conn->crypto.key_update.old_rx_ckm);
  CU_ASSERT(NULL != conn->crypto.key_update.new_tx_ckm);
  CU_ASSERT(NULL != conn->crypto.key_update.new_rx_ckm);

  /* The local endpoint initiates key update */
  t += ngtcp2_conn_get_pto(conn) * 2;

  rv = ngtcp2_conn_initiate_key_update(conn, t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(NULL != conn->crypto.key_update.old_rx_ckm);
  CU_ASSERT(NULL == conn->crypto.key_update.new_tx_ckm);
  CU_ASSERT(NULL == conn->crypto.key_update.new_rx_ckm);
  CU_ASSERT(conn->flags & NGTCP2_CONN_FLAG_KEY_UPDATE_NOT_CONFIRMED);

  rv = ngtcp2_conn_open_uni_stream(conn, &stream_id, NULL);

  CU_ASSERT(0 == rv);

  spktlen = ngtcp2_conn_write_stream(conn, NULL, buf, sizeof(buf), &nwrite,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
                                     /* fin = */ 0, null_data, 1024, ++t);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(conn->flags & NGTCP2_CONN_FLAG_KEY_UPDATE_NOT_CONFIRMED);

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = conn->pktns.tx.last_pkt_num;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_blklen = 0;
  fr.ack.num_blks = 0;

  pktlen = write_single_frame_pkt_flags(conn, buf, sizeof(buf),
                                        NGTCP2_PKT_FLAG_KEY_PHASE, &conn->oscid,
                                        ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(t == conn->crypto.key_update.confirmed_ts);
  CU_ASSERT(!(conn->flags & NGTCP2_CONN_FLAG_KEY_UPDATE_NOT_CONFIRMED));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_crypto_buffer_exceeded(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_tstamp t = 11111;
  int64_t pkt_num = -1;
  ngtcp2_frame fr;
  int rv;

  setup_default_client(&conn);

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.crypto.offset = 1000000;
  fr.crypto.datacnt = 1;
  fr.crypto.data[0].base = null_data;
  fr.crypto.data[0].len = 1;

  pktlen = write_single_frame_pkt(conn, buf, sizeof(buf), &conn->oscid,
                                  ++pkt_num, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(NGTCP2_ERR_CRYPTO_BUFFER_EXCEEDED == rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_handshake_probe(void) {
  ngtcp2_conn *conn;
  ngtcp2_tstamp t = 0;
  ngtcp2_ssize spktlen;
  size_t pktlen;
  uint8_t buf[1200];
  ngtcp2_frame fr;
  ngtcp2_rtb_entry *ent;
  ngtcp2_ksl_it it;
  int rv;

  /* Retransmit first Initial on PTO timer */
  setup_handshake_client(&conn);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(1 == ngtcp2_rtb_num_ack_eliciting(&conn->in_pktns->rtb));

  rv = ngtcp2_conn_on_loss_detection_timer(conn, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(1 == conn->in_pktns->rtb.probe_pkt_left);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);
  /* We don't make the first packet lost */
  CU_ASSERT(2 == ngtcp2_rtb_num_ack_eliciting(&conn->in_pktns->rtb));
  CU_ASSERT(0 == conn->in_pktns->rtb.probe_pkt_left);

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = 0;
  fr.ack.ack_delay = 0;
  fr.ack.first_ack_blklen = 0;
  fr.ack.num_blks = 0;

  pktlen = write_single_frame_handshake_pkt(
      conn, buf, sizeof(buf), NGTCP2_PKT_INITIAL, &conn->oscid,
      ngtcp2_conn_get_dcid(conn), 0, NGTCP2_PROTO_VER_MAX, &fr);
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(1 == ngtcp2_rtb_num_ack_eliciting(&conn->in_pktns->rtb));

  rv = ngtcp2_conn_on_loss_detection_timer(conn, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(0 == ngtcp2_rtb_num_ack_eliciting(&conn->in_pktns->rtb));
  CU_ASSERT(1 == conn->in_pktns->rtb.probe_pkt_left);

  /* This sends anti-deadlock padded Initial packet even if we have
     nothing to send. */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(1 == ngtcp2_rtb_num_ack_eliciting(&conn->in_pktns->rtb));
  CU_ASSERT(0 == conn->in_pktns->rtb.probe_pkt_left);

  it = ngtcp2_rtb_head(&conn->in_pktns->rtb);
  ent = ngtcp2_ksl_it_get(&it);

  CU_ASSERT(ent->flags & NGTCP2_RTB_FLAG_PROBE);
  CU_ASSERT(sizeof(buf) == ent->pktlen);

  ngtcp2_conn_install_handshake_key(conn, null_key, null_iv, null_hp_key,
                                    null_key, null_iv, null_hp_key,
                                    sizeof(null_key), sizeof(null_iv));
  ngtcp2_conn_set_aead_overhead(conn, NGTCP2_FAKE_AEAD_OVERHEAD);

  rv = ngtcp2_conn_on_loss_detection_timer(conn, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(1 == ngtcp2_rtb_num_ack_eliciting(&conn->in_pktns->rtb));
  CU_ASSERT(1 == conn->hs_pktns->rtb.probe_pkt_left);

  /* This sends anti-deadlock Handshake packet even if we have nothing
     to send. */
  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);
  CU_ASSERT(1 == ngtcp2_rtb_num_ack_eliciting(&conn->hs_pktns->rtb));
  CU_ASSERT(0 == conn->hs_pktns->rtb.probe_pkt_left);

  it = ngtcp2_rtb_head(&conn->hs_pktns->rtb);
  ent = ngtcp2_ksl_it_get(&it);

  CU_ASSERT(ent->flags & NGTCP2_RTB_FLAG_PROBE);
  CU_ASSERT(sizeof(buf) > ent->pktlen);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_handshake_loss(void) {
  ngtcp2_conn *conn;
  ngtcp2_tstamp t = 0;
  ngtcp2_ssize spktlen;
  size_t i;
  size_t pktlen;
  uint8_t buf[1252];
  ngtcp2_frame fr;
  union {
    ngtcp2_frame fr;
    struct {
      ngtcp2_frame fr;
      ngtcp2_vec data[8];
    } crypto;
  } crypto;
  ngtcp2_frame *cfr;
  ngtcp2_cid rcid;
  int rv;
  int64_t pkt_num = -1;
  ngtcp2_ksl_it it;
  ngtcp2_rtb_entry *ent;

  rcid_init(&rcid);
  setup_handshake_server(&conn);
  conn->callbacks.recv_crypto_data = recv_crypto_data;

  cfr = &crypto.fr;
  cfr->type = NGTCP2_FRAME_CRYPTO;
  cfr->crypto.offset = 0;
  cfr->crypto.datacnt = 1;
  cfr->crypto.data[0].len = 123;
  cfr->crypto.data[0].base = null_data;

  pktlen = write_single_frame_handshake_pkt(
      conn, buf, sizeof(buf), NGTCP2_PKT_INITIAL, &rcid,
      ngtcp2_conn_get_dcid(conn), ++pkt_num, conn->version, cfr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);

  ngtcp2_conn_submit_crypto_data(conn, NGTCP2_CRYPTO_LEVEL_INITIAL, null_data,
                                 123);
  ngtcp2_conn_submit_crypto_data(conn, NGTCP2_CRYPTO_LEVEL_HANDSHAKE, null_data,
                                 163);
  ngtcp2_conn_submit_crypto_data(conn, NGTCP2_CRYPTO_LEVEL_HANDSHAKE, null_data,
                                 2369);
  ngtcp2_conn_submit_crypto_data(conn, NGTCP2_CRYPTO_LEVEL_HANDSHAKE, null_data,
                                 79);
  ngtcp2_conn_submit_crypto_data(conn, NGTCP2_CRYPTO_LEVEL_HANDSHAKE, null_data,
                                 36);

  /* Initial and first Handshake are coalesced into 1 packet. */
  for (i = 0; i < 3; ++i) {
    spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);
    CU_ASSERT(spktlen > 0);
  }

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(0 == spktlen);

  t += 1000;

  ngtcp2_conn_on_loss_detection_timer(conn, t);

  for (i = 0; i < 3; ++i) {
    spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

    CU_ASSERT(spktlen > 0);
  }

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(0 == spktlen);

  it = ngtcp2_ksl_begin(&conn->hs_pktns->rtb.ents);
  ent = ngtcp2_ksl_it_get(&it);

  CU_ASSERT(2181 == ent->frc->fr.crypto.offset);
  CU_ASSERT(5 == ent->hd.pkt_num);

  fr.type = NGTCP2_FRAME_ACK;
  fr.ack.largest_ack = 2;
  fr.ack.ack_delay = 0;
  fr.ack.ack_delay_unscaled = 0;
  fr.ack.first_ack_blklen = 0;
  fr.ack.num_blks = 0;

  pktlen = write_single_frame_handshake_pkt(
      conn, buf, sizeof(buf), NGTCP2_PKT_HANDSHAKE, &conn->oscid,
      ngtcp2_conn_get_dcid(conn), ++pkt_num, conn->version, &fr);

  t += 8;
  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, t);

  CU_ASSERT(0 == rv);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen == 0);

  t += 1000;

  ngtcp2_conn_on_loss_detection_timer(conn, t);

  spktlen = ngtcp2_conn_write_pkt(conn, NULL, buf, sizeof(buf), ++t);

  CU_ASSERT(spktlen > 0);

  it = ngtcp2_ksl_begin(&conn->hs_pktns->rtb.ents);
  ent = ngtcp2_ksl_it_get(&it);

  CU_ASSERT(NGTCP2_FRAME_CRYPTO == ent->frc->fr.type);
  CU_ASSERT(0 == ent->frc->fr.crypto.offset);
  CU_ASSERT(2 == ent->frc->fr.crypto.datacnt);
  CU_ASSERT(1186 == ngtcp2_vec_len(ent->frc->fr.crypto.data,
                                   ent->frc->fr.crypto.datacnt));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_client_initial_retry(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_frame fr;
  int64_t pkt_num = -1;
  ngtcp2_tstamp t = 0;
  ngtcp2_cid rcid;
  int rv;

  rcid_init(&rcid);

  setup_handshake_server(&conn);
  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.crypto.offset = 1;
  fr.crypto.datacnt = 1;
  fr.crypto.data[0].len = 45;
  fr.crypto.data[0].base = null_data;

  pktlen = write_single_frame_handshake_pkt(
      conn, buf, sizeof(buf), NGTCP2_PKT_INITIAL, &rcid,
      ngtcp2_conn_get_dcid(conn), ++pkt_num, conn->version, &fr);

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(NGTCP2_ERR_RETRY == rv);

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_recv_client_initial_token(void) {
  ngtcp2_conn *conn;
  uint8_t buf[2048];
  size_t pktlen;
  ngtcp2_frame fr;
  int64_t pkt_num = -1;
  ngtcp2_tstamp t = 0;
  ngtcp2_cid rcid;
  int rv;
  const uint8_t raw_token[] = {0xff, 0x12, 0x31, 0x04, 0xab};
  ngtcp2_vec token;
  const ngtcp2_mem *mem;

  rcid_init(&rcid);

  setup_handshake_server(&conn);
  mem = conn->mem;

  token.base = ngtcp2_mem_malloc(mem, sizeof(raw_token));
  memcpy(token.base, raw_token, sizeof(raw_token));
  token.len = sizeof(raw_token);

  conn->local.settings.token = token;

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.crypto.offset = 0;
  fr.crypto.datacnt = 1;
  fr.crypto.data[0].len = 45;
  fr.crypto.data[0].base = null_data;

  pktlen = write_single_frame_initial_pkt(
      conn, buf, sizeof(buf), &rcid, ngtcp2_conn_get_dcid(conn), ++pkt_num,
      conn->version, &fr, raw_token, sizeof(raw_token));

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(0 == rv);
  CU_ASSERT(45 ==
            ngtcp2_rob_first_gap_offset(&conn->in_pktns->crypto.strm.rx.rob));

  ngtcp2_conn_del(conn);

  /* Specifying invalid token lets server drop the packet */
  setup_handshake_server(&conn);
  mem = conn->mem;

  token.base = ngtcp2_mem_malloc(mem, sizeof(raw_token));
  memcpy(token.base, raw_token, sizeof(raw_token));
  token.len = sizeof(raw_token) - 1;

  conn->local.settings.token = token;

  fr.type = NGTCP2_FRAME_CRYPTO;
  fr.crypto.offset = 0;
  fr.crypto.datacnt = 1;
  fr.crypto.data[0].len = 45;
  fr.crypto.data[0].base = null_data;

  pktlen = write_single_frame_initial_pkt(
      conn, buf, sizeof(buf), &rcid, ngtcp2_conn_get_dcid(conn), ++pkt_num,
      conn->version, &fr, raw_token, sizeof(raw_token));

  rv = ngtcp2_conn_read_pkt(conn, &null_path, buf, pktlen, ++t);

  CU_ASSERT(NGTCP2_ERR_PROTO == rv);
  CU_ASSERT(0 ==
            ngtcp2_rob_first_gap_offset(&conn->in_pktns->crypto.strm.rx.rob));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_conn_get_active_dcid(void) {
  ngtcp2_conn *conn;
  ngtcp2_cid_token cid_token[2];
  ngtcp2_cid dcid;
  static uint8_t token[] = {0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1,
                            0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1};

  dcid_init(&dcid);
  setup_default_client(&conn);

  CU_ASSERT(1 == ngtcp2_conn_get_num_active_dcid(conn));
  CU_ASSERT(1 == ngtcp2_conn_get_active_dcid(conn, cid_token));
  CU_ASSERT(0 == cid_token[0].seq);
  CU_ASSERT(ngtcp2_cid_eq(&dcid, &cid_token[0].cid));
  CU_ASSERT(ngtcp2_path_eq(&null_path, &cid_token[0].ps.path));
  CU_ASSERT(1 == cid_token[0].token_present);
  CU_ASSERT(0 ==
            memcmp(token, cid_token[0].token, NGTCP2_STATELESS_RESET_TOKENLEN));

  ngtcp2_conn_del(conn);
}

void test_ngtcp2_pkt_write_connection_close(void) {
  ngtcp2_ssize spktlen;
  uint8_t buf[1200];
  ngtcp2_cid dcid, scid;
  ngtcp2_crypto_aead aead = {0};
  ngtcp2_crypto_cipher hp_mask = {0};

  dcid_init(&dcid);
  scid_init(&scid);

  spktlen = ngtcp2_pkt_write_connection_close(
      buf, sizeof(buf), &dcid, &scid, NGTCP2_INVALID_TOKEN, null_encrypt, &aead,
      null_key, null_iv, null_hp_mask, &hp_mask, null_hp_key);

  CU_ASSERT(spktlen > 0);

  spktlen = ngtcp2_pkt_write_connection_close(
      buf, 16, &dcid, &scid, NGTCP2_INVALID_TOKEN, null_encrypt, &aead,
      null_key, null_iv, null_hp_mask, &hp_mask, null_hp_key);

  CU_ASSERT(NGTCP2_ERR_NOBUF == spktlen);
}
