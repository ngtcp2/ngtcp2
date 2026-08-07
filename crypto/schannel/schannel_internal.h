/*
 * ngtcp2
 *
 * Copyright (c) 2026 ngtcp2 contributors
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
#ifndef NGTCP2_SCHANNEL_INTERNAL_H
#define NGTCP2_SCHANNEL_INTERNAL_H

#include <ngtcp2/ngtcp2_crypto_schannel.h>

#include <bcrypt.h>
#include <schannel.h>

#include <stdint.h>

#define NGTCP2_SCHANNEL_TP_EXT_TYPE 0x0039
#define NGTCP2_SCHANNEL_MAX_TRAFFIC_SECRET 64
#define NGTCP2_SCHANNEL_TRAFFIC_SECRET_COUNT 4

typedef enum ngtcp2_schannel_aead_id {
  NGTCP2_SCHANNEL_AEAD_NONE,
  NGTCP2_SCHANNEL_AEAD_AES_128_GCM,
  NGTCP2_SCHANNEL_AEAD_AES_256_GCM,
} ngtcp2_schannel_aead_id;

typedef enum ngtcp2_schannel_md_id {
  NGTCP2_SCHANNEL_MD_NONE,
  NGTCP2_SCHANNEL_MD_SHA256,
  NGTCP2_SCHANNEL_MD_SHA384,
} ngtcp2_schannel_md_id;

typedef struct ngtcp2_schannel_buf {
  uint8_t *base;
  size_t len;
  size_t capacity;
} ngtcp2_schannel_buf;

struct ngtcp2_crypto_schannel {
  CredHandle *cred_handle;
  ngtcp2_crypto_conn_ref *conn_ref;
  CtxtHandle context;
  SECURITY_STATUS last_error;

  wchar_t *server_name;
  SEC_APPLICATION_PROTOCOLS *application_protocols;
  ULONG application_protocolslen;

  uint8_t selected_alpn[255];
  size_t selected_alpnlen;
  char cipher_name[128];

  ngtcp2_schannel_buf input;
  ngtcp2_schannel_buf output;
  ngtcp2_schannel_buf local_tp;
  ngtcp2_schannel_buf peer_tp;

  uint64_t output_offset;
  uint64_t handshake_offset;
  uint64_t app_offset;
  ngtcp2_encryption_level input_level;
  ngtcp2_encryption_level read_level;
  ngtcp2_encryption_level write_level;

  ngtcp2_schannel_aead_id aead_id;
  ngtcp2_schannel_md_id md_id;

  unsigned int server : 1;
  unsigned int context_initialized : 1;
  unsigned int started : 1;
  unsigned int generated_first_payload : 1;
  unsigned int peer_tp_received : 1;
  unsigned int peer_tp_applied : 1;
  unsigned int local_tp_sent : 1;
  unsigned int handshake_completed : 1;
  unsigned int resumed : 1;
  unsigned int handshake_offset_set : 1;
  unsigned int app_offset_set : 1;
  unsigned int tx_handshake_key_installed : 1;
  unsigned int tx_app_key_installed : 1;
  unsigned int rx_handshake_key_installed : 1;
  unsigned int rx_app_key_installed : 1;
};

int ngtcp2_schannel_buf_set(ngtcp2_schannel_buf *buf, const uint8_t *data,
                            size_t datalen);
int ngtcp2_schannel_buf_append(ngtcp2_schannel_buf *buf, const uint8_t *data,
                               size_t datalen);
void ngtcp2_schannel_buf_consume(ngtcp2_schannel_buf *buf, size_t datalen);
void ngtcp2_schannel_buf_free(ngtcp2_schannel_buf *buf);

int ngtcp2_schannel_set_algorithm(
  ngtcp2_crypto_schannel *schannel,
  const SEC_TRAFFIC_SECRETS *traffic_secret);

#endif /* !defined(NGTCP2_SCHANNEL_INTERNAL_H) */
