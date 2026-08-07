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
#ifndef SCHANNEL_COMMON_H
#define SCHANNEL_COMMON_H

#include <winsock2.h>
#include <ws2tcpip.h>

#define SCHANNEL_USE_BLACKLISTS
#include <windows.h>
#include <winternl.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_schannel.h>

#include <schannel.h>
#include <wincrypt.h>

#define SCHANNEL_EXAMPLE_ALPN "\x0bngtcp2-demo"
#define SCHANNEL_EXAMPLE_TIMEOUT (10 * NGTCP2_SECONDS)

typedef struct schannel_example_credential {
  CredHandle handle;
  HCERTSTORE store;
  PCCERT_CONTEXT certificate;
  int initialized;
} schannel_example_credential;

typedef struct schannel_example_endpoint {
  ngtcp2_conn *conn;
  ngtcp2_crypto_schannel *tls;
  ngtcp2_crypto_conn_ref conn_ref;
  ngtcp2_path path;
  struct sockaddr_storage local_addr;
  struct sockaddr_storage remote_addr;
  socklen_t local_addrlen;
  socklen_t remote_addrlen;
  int handshake_completed;
} schannel_example_endpoint;

ngtcp2_tstamp schannel_example_timestamp(void);

int schannel_example_client_credential_new(
  schannel_example_credential *credential, int manual_validation);
int schannel_example_server_credential_new(
  schannel_example_credential *credential, const char *thumbprint);
void schannel_example_credential_del(
  schannel_example_credential *credential);

int schannel_example_client_new(
  schannel_example_endpoint *endpoint,
  schannel_example_credential *credential, const char *server_name,
  const struct sockaddr *local_addr, socklen_t local_addrlen,
  const struct sockaddr *remote_addr, socklen_t remote_addrlen);
int schannel_example_server_new(
  schannel_example_endpoint *endpoint,
  schannel_example_credential *credential, const ngtcp2_pkt_hd *hd,
  const struct sockaddr *local_addr, socklen_t local_addrlen,
  const struct sockaddr *remote_addr, socklen_t remote_addrlen);
void schannel_example_endpoint_del(schannel_example_endpoint *endpoint);

int schannel_example_read(schannel_example_endpoint *endpoint,
                          const uint8_t *data, size_t datalen);
int schannel_example_write(schannel_example_endpoint *endpoint, SOCKET fd);
int schannel_example_handle_expiry(schannel_example_endpoint *endpoint);
void schannel_example_print_result(
  const schannel_example_endpoint *endpoint);

#endif /* !defined(SCHANNEL_COMMON_H) */
