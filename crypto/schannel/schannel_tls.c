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
#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#include "schannel_internal.h"

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define NGTCP2_SCHANNEL_INITIAL_BUFFER_SIZE 4096
#define NGTCP2_SCHANNEL_MAX_PROCESS_ITERATIONS 32

typedef union ngtcp2_schannel_secret_buf {
  SEC_TRAFFIC_SECRETS align;
  uint8_t data[sizeof(SEC_TRAFFIC_SECRETS) +
               NGTCP2_SCHANNEL_MAX_TRAFFIC_SECRET];
} ngtcp2_schannel_secret_buf;

static int buf_reserve(ngtcp2_schannel_buf *buf, size_t capacity) {
  uint8_t *p;
  size_t ncap;

  if (capacity <= buf->capacity) {
    return 0;
  }

  ncap = buf->capacity == 0 ? 4096 : buf->capacity;
  while (ncap < capacity) {
    if (ncap > SIZE_MAX / 2) {
      ncap = capacity;
      break;
    }
    ncap *= 2;
  }

  p = realloc(buf->base, ncap);
  if (p == NULL) {
    return -1;
  }

  buf->base = p;
  buf->capacity = ncap;
  return 0;
}

int ngtcp2_schannel_buf_set(ngtcp2_schannel_buf *buf, const uint8_t *data,
                            size_t datalen) {
  buf->len = 0;
  return ngtcp2_schannel_buf_append(buf, data, datalen);
}

int ngtcp2_schannel_buf_append(ngtcp2_schannel_buf *buf, const uint8_t *data,
                               size_t datalen) {
  if (datalen > SIZE_MAX - buf->len ||
      buf_reserve(buf, buf->len + datalen) != 0) {
    return -1;
  }

  if (datalen != 0) {
    memcpy(buf->base + buf->len, data, datalen);
    buf->len += datalen;
  }
  return 0;
}

void ngtcp2_schannel_buf_consume(ngtcp2_schannel_buf *buf, size_t datalen) {
  assert(datalen <= buf->len);

  if (datalen == buf->len) {
    buf->len = 0;
    return;
  }

  memmove(buf->base, buf->base + datalen, buf->len - datalen);
  buf->len -= datalen;
}

void ngtcp2_schannel_buf_free(ngtcp2_schannel_buf *buf) {
  if (buf->base != NULL) {
    SecureZeroMemory(buf->base, buf->capacity);
    free(buf->base);
  }
  memset(buf, 0, sizeof(*buf));
}

static int validate_alpn(const uint8_t *alpn, size_t alpnlen) {
  size_t offset = 0, n;

  if (alpn == NULL || alpnlen == 0 || alpnlen > UINT16_MAX) {
    return -1;
  }

  while (offset < alpnlen) {
    n = alpn[offset++];
    if (n == 0 || n > alpnlen - offset) {
      return -1;
    }
    offset += n;
  }

  return offset == alpnlen ? 0 : -1;
}

static int parse_client_hello_transport_params(
  ngtcp2_crypto_schannel *schannel) {
  const uint8_t *p = schannel->input.base;
  const uint8_t *end;
  size_t msglen, n;

  if (schannel->input.len < 4) {
    return 0;
  }
  if (p[0] != 1) {
    return -1;
  }
  msglen = (size_t)p[1] << 16 | (size_t)p[2] << 8 | p[3];
  if (msglen > SIZE_MAX - 4) {
    return -1;
  }
  if (schannel->input.len < msglen + 4) {
    return 0;
  }

  p += 4;
  end = p + msglen;
  if ((size_t)(end - p) < 2 + 32 + 1) {
    return -1;
  }
  p += 2 + 32;
  n = *p++;
  if (n > (size_t)(end - p)) {
    return -1;
  }
  p += n;

  if ((size_t)(end - p) < 2) {
    return -1;
  }
  n = (size_t)p[0] << 8 | p[1];
  p += 2;
  if (n > (size_t)(end - p)) {
    return -1;
  }
  p += n;

  if (p == end) {
    return -1;
  }
  n = *p++;
  if (n > (size_t)(end - p)) {
    return -1;
  }
  p += n;

  if ((size_t)(end - p) < 2) {
    return -1;
  }
  n = (size_t)p[0] << 8 | p[1];
  p += 2;
  if (n != (size_t)(end - p)) {
    return -1;
  }

  while (p != end) {
    uint16_t extension_type, extensionlen;

    if ((size_t)(end - p) < 4) {
      return -1;
    }
    extension_type = (uint16_t)((uint16_t)p[0] << 8 | p[1]);
    extensionlen = (uint16_t)((uint16_t)p[2] << 8 | p[3]);
    if ((size_t)(end - p) < (size_t)extensionlen + 4) {
      return -1;
    }
    if (extension_type == NGTCP2_SCHANNEL_TP_EXT_TYPE) {
      if (ngtcp2_schannel_buf_set(&schannel->peer_tp, p,
                                  (size_t)extensionlen + 4) != 0) {
        return -1;
      }
      schannel->peer_tp_received = 1;
      return 1;
    }
    p += (size_t)extensionlen + 4;
  }

  return -1;
}

static wchar_t *utf8_to_wide(const char *s) {
  wchar_t *ws;
  int n;

  if (s == NULL) {
    return NULL;
  }

  n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, NULL, 0);
  if (n == 0) {
    return NULL;
  }

  ws = calloc((size_t)n, sizeof(*ws));
  if (ws == NULL) {
    return NULL;
  }

  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, ws, n) == 0) {
    free(ws);
    return NULL;
  }

  return ws;
}

int ngtcp2_crypto_schannel_new(
  ngtcp2_crypto_schannel **pschannel,
  const ngtcp2_crypto_schannel_config *config) {
  ngtcp2_crypto_schannel *schannel;
  SEC_APPLICATION_PROTOCOL_LIST *protocol_list;
  size_t protocolslen;

  if (pschannel == NULL || config == NULL || config->cred_handle == NULL ||
      config->conn_ref == NULL || config->conn_ref->get_conn == NULL ||
      validate_alpn(config->alpn, config->alpnlen) != 0 ||
      (!config->server && config->server_name == NULL)) {
    return -1;
  }

  schannel = calloc(1, sizeof(*schannel));
  if (schannel == NULL) {
    return -1;
  }

  SecInvalidateHandle(&schannel->context);
  schannel->cred_handle = config->cred_handle;
  schannel->conn_ref = config->conn_ref;
  schannel->server = config->server != 0;
  schannel->input_level = NGTCP2_ENCRYPTION_LEVEL_INITIAL;
  schannel->read_level = NGTCP2_ENCRYPTION_LEVEL_INITIAL;
  schannel->write_level = NGTCP2_ENCRYPTION_LEVEL_INITIAL;

  if (config->server_name != NULL) {
    schannel->server_name = utf8_to_wide(config->server_name);
    if (schannel->server_name == NULL) {
      goto fail;
    }
  }

  protocolslen = FIELD_OFFSET(SEC_APPLICATION_PROTOCOLS, ProtocolLists) +
                 FIELD_OFFSET(SEC_APPLICATION_PROTOCOL_LIST, ProtocolList) +
                 config->alpnlen;
  if (protocolslen > ULONG_MAX) {
    goto fail;
  }

  schannel->application_protocols = calloc(1, protocolslen);
  if (schannel->application_protocols == NULL) {
    goto fail;
  }
  schannel->application_protocolslen = (ULONG)protocolslen;
  schannel->application_protocols->ProtocolListsSize =
    (ULONG)(FIELD_OFFSET(SEC_APPLICATION_PROTOCOL_LIST, ProtocolList) +
            config->alpnlen);
  protocol_list = &schannel->application_protocols->ProtocolLists[0];
  protocol_list->ProtoNegoExt = SecApplicationProtocolNegotiationExt_ALPN;
  protocol_list->ProtocolListSize = (USHORT)config->alpnlen;
  memcpy(protocol_list->ProtocolList, config->alpn, config->alpnlen);

  *pschannel = schannel;
  return 0;

fail:
  ngtcp2_crypto_schannel_del(schannel);
  return -1;
}

void ngtcp2_crypto_schannel_del(ngtcp2_crypto_schannel *schannel) {
  if (schannel == NULL) {
    return;
  }

  if (schannel->context_initialized) {
    DeleteSecurityContext(&schannel->context);
  }
  if (schannel->server_name != NULL) {
    SecureZeroMemory(schannel->server_name,
                     (wcslen(schannel->server_name) + 1) *
                       sizeof(*schannel->server_name));
    free(schannel->server_name);
  }
  if (schannel->application_protocols != NULL) {
    SecureZeroMemory(schannel->application_protocols,
                     schannel->application_protocolslen);
    free(schannel->application_protocols);
  }
  ngtcp2_schannel_buf_free(&schannel->input);
  ngtcp2_schannel_buf_free(&schannel->output);
  ngtcp2_schannel_buf_free(&schannel->local_tp);
  ngtcp2_schannel_buf_free(&schannel->peer_tp);
  SecureZeroMemory(schannel, sizeof(*schannel));
  free(schannel);
}

CtxtHandle *ngtcp2_crypto_schannel_get_context_handle(
  ngtcp2_crypto_schannel *schannel) {
  return schannel != NULL && schannel->context_initialized
           ? &schannel->context
           : NULL;
}

const uint8_t *ngtcp2_crypto_schannel_get_selected_alpn(
  const ngtcp2_crypto_schannel *schannel, size_t *alpnlen) {
  if (alpnlen != NULL) {
    *alpnlen = schannel == NULL ? 0 : schannel->selected_alpnlen;
  }
  return schannel == NULL || schannel->selected_alpnlen == 0
           ? NULL
           : schannel->selected_alpn;
}

const char *ngtcp2_crypto_schannel_get_cipher_name(
  const ngtcp2_crypto_schannel *schannel) {
  return schannel == NULL || schannel->cipher_name[0] == '\0'
           ? NULL
           : schannel->cipher_name;
}

int ngtcp2_crypto_schannel_session_resumed(
  const ngtcp2_crypto_schannel *schannel) {
  return schannel != NULL && schannel->resumed;
}

SECURITY_STATUS ngtcp2_crypto_schannel_get_last_error(
  const ngtcp2_crypto_schannel *schannel) {
  return schannel == NULL ? SEC_E_INVALID_HANDLE : schannel->last_error;
}

static int apply_peer_transport_params(ngtcp2_conn *conn,
                                       ngtcp2_crypto_schannel *schannel) {
  uint16_t extension_type, extensionlen;
  int rv;

  if (schannel->peer_tp_applied) {
    return 0;
  }
  if (!schannel->peer_tp_received || schannel->peer_tp.len < 4) {
    return -1;
  }

  extension_type = (uint16_t)((uint16_t)schannel->peer_tp.base[0] << 8 |
                              schannel->peer_tp.base[1]);
  extensionlen = (uint16_t)((uint16_t)schannel->peer_tp.base[2] << 8 |
                            schannel->peer_tp.base[3]);
  if (extension_type != NGTCP2_SCHANNEL_TP_EXT_TYPE ||
      extensionlen != schannel->peer_tp.len - 4) {
    return -1;
  }

  rv = ngtcp2_conn_decode_and_set_remote_transport_params(
    conn, schannel->peer_tp.base + 4, schannel->peer_tp.len - 4);
  if (rv != 0) {
    ngtcp2_conn_set_tls_error(conn, rv);
    return -1;
  }

  schannel->peer_tp_applied = 1;
  return 0;
}

int ngtcp2_crypto_set_remote_transport_params(ngtcp2_conn *conn, void *tls) {
  return apply_peer_transport_params(conn, tls);
}

int ngtcp2_crypto_set_local_transport_params(void *tls, const uint8_t *buf,
                                             size_t len) {
  ngtcp2_crypto_schannel *schannel = tls;

  if (schannel == NULL || schannel->local_tp_sent || len > UINT16_MAX) {
    return -1;
  }

  return ngtcp2_schannel_buf_set(&schannel->local_tp, buf, len);
}

static int preload_server_transport_params(
  const ngtcp2_conn *conn, ngtcp2_crypto_schannel *schannel) {
  ngtcp2_transport_params params =
    *ngtcp2_conn_get_local_transport_params2(conn);
  ngtcp2_cid *scids = NULL;
  ngtcp2_ssize nwrite;
  size_t nscids;
  int rv = -1;

  if (!params.initial_scid_present) {
    nscids = ngtcp2_conn_get_scid2(conn, NULL);
    if (nscids == 0 || nscids > SIZE_MAX / sizeof(*scids)) {
      return -1;
    }
    scids = malloc(nscids * sizeof(*scids));
    if (scids == NULL) {
      return -1;
    }
    ngtcp2_conn_get_scid2(conn, scids);
    params.initial_scid = scids[0];
    params.initial_scid_present = 1;
  }

  if (params.version_info_present &&
      params.version_info.chosen_version == 0) {
    params.version_info.chosen_version =
      ngtcp2_conn_get_client_chosen_version2(conn);
  }

  nwrite = ngtcp2_transport_params_encode(NULL, 0, &params);
  if (nwrite < 0 || nwrite > UINT16_MAX ||
      buf_reserve(&schannel->local_tp, (size_t)nwrite) != 0) {
    goto cleanup;
  }

  nwrite = ngtcp2_transport_params_encode(
    schannel->local_tp.base, schannel->local_tp.capacity, &params);
  if (nwrite < 0) {
    goto cleanup;
  }

  schannel->local_tp.len = (size_t)nwrite;
  rv = 0;

cleanup:
  free(scids);
  return rv;
}

static int install_secret(ngtcp2_conn *conn, ngtcp2_crypto_schannel *schannel,
                          SEC_TRAFFIC_SECRETS *secret, int own_secret) {
  ngtcp2_encryption_level level;
  uint64_t base_offset = schannel->output_offset;
  int installed;
  int rv;

  if (secret->TrafficSecretSize == 0 ||
      secret->TrafficSecretSize > NGTCP2_SCHANNEL_MAX_TRAFFIC_SECRET ||
      ngtcp2_schannel_set_algorithm(schannel, secret) != 0) {
    return -1;
  }

  if (own_secret) {
    if (secret->MsgSequenceEnd != 0) {
      level = NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE;
      installed = schannel->tx_handshake_key_installed;
    } else {
      if (!schannel->tx_handshake_key_installed) {
        rv = 0;
        goto cleanup;
      }
      level = NGTCP2_ENCRYPTION_LEVEL_1RTT;
      installed = schannel->tx_app_key_installed;
    }
    if (installed) {
      rv = 0;
      goto cleanup;
    }
    rv = ngtcp2_crypto_derive_and_install_tx_key(
      conn, NULL, NULL, NULL, level, secret->TrafficSecret,
      secret->TrafficSecretSize);
    if (rv != 0) {
      goto cleanup;
    }

    if (level == NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE) {
      schannel->tx_handshake_key_installed = 1;
      schannel->handshake_offset = base_offset + secret->MsgSequenceStart;
      schannel->handshake_offset_set = 1;
      if (secret->MsgSequenceEnd != 0) {
        schannel->app_offset = base_offset + secret->MsgSequenceEnd;
        schannel->app_offset_set = 1;
      }
    } else if (!schannel->app_offset_set ||
               schannel->app_offset == schannel->handshake_offset) {
      schannel->tx_app_key_installed = 1;
      schannel->app_offset = base_offset + secret->MsgSequenceStart;
      schannel->app_offset_set = 1;
    } else {
      schannel->tx_app_key_installed = 1;
    }
    schannel->write_level = level;
  } else {
    if (!schannel->rx_handshake_key_installed) {
      level = NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE;
      installed = 0;
    } else {
      level = NGTCP2_ENCRYPTION_LEVEL_1RTT;
      installed = schannel->rx_app_key_installed;
    }
    if (installed) {
      rv = 0;
      goto cleanup;
    }
    rv = ngtcp2_crypto_derive_and_install_rx_key(
      conn, NULL, NULL, NULL, level, secret->TrafficSecret,
      secret->TrafficSecretSize);
    if (rv != 0) {
      goto cleanup;
    }
    if (level == NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE) {
      schannel->rx_handshake_key_installed = 1;
    } else {
      schannel->rx_app_key_installed = 1;
    }
    schannel->read_level = level;
  }

  rv = 0;

cleanup:
  SecureZeroMemory(secret->TrafficSecret, secret->TrafficSecretSize);
  return rv;
}

static int submit_output(ngtcp2_conn *conn, ngtcp2_crypto_schannel *schannel,
                         const uint8_t *data, size_t datalen) {
  ngtcp2_encryption_level level;
  uint64_t offset = schannel->output_offset, boundary;
  size_t nwrite;
  int rv;

  while (datalen != 0) {
    if (schannel->handshake_offset_set &&
        offset >= schannel->handshake_offset) {
      if (schannel->app_offset_set && offset >= schannel->app_offset) {
        level = NGTCP2_ENCRYPTION_LEVEL_1RTT;
        boundary = UINT64_MAX;
      } else {
        level = NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE;
        boundary = schannel->app_offset_set ? schannel->app_offset : UINT64_MAX;
      }
    } else {
      level = NGTCP2_ENCRYPTION_LEVEL_INITIAL;
      boundary = schannel->handshake_offset_set ? schannel->handshake_offset
                                                : UINT64_MAX;
    }

    nwrite = datalen;
    if (boundary != UINT64_MAX && boundary > offset &&
        boundary - offset < nwrite) {
      nwrite = (size_t)(boundary - offset);
    }
    if (nwrite == 0) {
      return -1;
    }

    rv = ngtcp2_conn_submit_crypto_data(conn, level, data, nwrite);
    if (rv != 0) {
      ngtcp2_conn_set_tls_error(conn, rv);
      return -1;
    }

    data += nwrite;
    datalen -= nwrite;
    offset += nwrite;
  }

  schannel->output_offset = offset;
  return 0;
}

static int query_handshake_properties(ngtcp2_crypto_schannel *schannel) {
  SecPkgContext_ApplicationProtocol alpn;
  SecPkgContext_CipherInfo cipher;
  SecPkgContext_ConnectionInfo connection;
  SecPkgContext_SessionInfo session;
  SECURITY_STATUS status;
  DWORD tls13;
  int n;

  status = QueryContextAttributesW(&schannel->context,
                                   SECPKG_ATTR_APPLICATION_PROTOCOL, &alpn);
  if (status != SEC_E_OK ||
      alpn.ProtoNegoStatus != SecApplicationProtocolNegotiationStatus_Success ||
      alpn.ProtocolIdSize == 0) {
    return -1;
  }
  schannel->selected_alpnlen = alpn.ProtocolIdSize;
  memcpy(schannel->selected_alpn, alpn.ProtocolId, alpn.ProtocolIdSize);

  status = QueryContextAttributesW(&schannel->context, SECPKG_ATTR_CIPHER_INFO,
                                   &cipher);
  if (status != SEC_E_OK) {
    return -1;
  }
  n = WideCharToMultiByte(CP_UTF8, 0, cipher.szCipherSuite, -1,
                          schannel->cipher_name,
                          (int)sizeof(schannel->cipher_name), NULL, NULL);
  if (n == 0) {
    return -1;
  }

  status = QueryContextAttributesW(&schannel->context,
                                   SECPKG_ATTR_CONNECTION_INFO, &connection);
  if (status != SEC_E_OK) {
    return -1;
  }
  tls13 = schannel->server ? SP_PROT_TLS1_3_SERVER : SP_PROT_TLS1_3_CLIENT;
  if ((connection.dwProtocol & tls13) == 0) {
    return -1;
  }

  if (QueryContextAttributesW(&schannel->context, SECPKG_ATTR_SESSION_INFO,
                              &session) == SEC_E_OK) {
    schannel->resumed = (session.dwFlags & SSL_SESSION_RECONNECT) != 0;
  }

  return 0;
}

static int process_once(ngtcp2_conn *conn, ngtcp2_crypto_schannel *schannel,
                        SECURITY_STATUS *pstatus) {
  SecBuffer inbufs[7] = {0}, outbufs[7] = {0};
  SecBufferDesc indesc = {SECBUFFER_VERSION, 0, inbufs};
  SecBufferDesc outdesc = {SECBUFFER_VERSION, 0, outbufs};
  SEC_FLAGS secflags = {ISC_REQ_MESSAGES};
  SEND_GENERIC_TLS_EXTENSION *send_extension = NULL;
  SUBSCRIBE_GENERIC_TLS_EXTENSION subscribe_extension = {0};
  ngtcp2_schannel_secret_buf secretbufs[NGTCP2_SCHANNEL_TRAFFIC_SECRET_COUNT];
  uint8_t alertbuf[2] = {0};
  SecBuffer *extra = NULL, *missing = NULL, *output = NULL, *extension = NULL;
  ULONG attrs = 0;
  TimeStamp expiry;
  SECURITY_STATUS status;
  size_t consumed = schannel->input.len;
  size_t send_extensionlen = 0;
  size_t i;
  int own_secret, rv = -1;

  memset(secretbufs, 0, sizeof(secretbufs));
  schannel->output.len = 0;
  if (buf_reserve(&schannel->output, NGTCP2_SCHANNEL_INITIAL_BUFFER_SIZE) != 0 ||
      buf_reserve(&schannel->peer_tp, (size_t)UINT16_MAX + 4) != 0) {
    goto cleanup;
  }

  if (schannel->started || schannel->server) {
    inbufs[indesc.cBuffers].BufferType = SECBUFFER_TOKEN;
    inbufs[indesc.cBuffers].cbBuffer = (ULONG)schannel->input.len;
    inbufs[indesc.cBuffers].pvBuffer = schannel->input.base;
    ++indesc.cBuffers;
  }

  inbufs[indesc.cBuffers++].BufferType = SECBUFFER_EMPTY;
  inbufs[indesc.cBuffers++].BufferType = SECBUFFER_EMPTY;

  inbufs[indesc.cBuffers].BufferType = SECBUFFER_FLAGS;
  inbufs[indesc.cBuffers].cbBuffer = sizeof(secflags);
  inbufs[indesc.cBuffers].pvBuffer = &secflags;
  ++indesc.cBuffers;

  if ((!schannel->started ||
       (schannel->server && !schannel->generated_first_payload)) &&
      schannel->application_protocols != NULL) {
    inbufs[indesc.cBuffers].BufferType = SECBUFFER_APPLICATION_PROTOCOLS;
    inbufs[indesc.cBuffers].cbBuffer = schannel->application_protocolslen;
    inbufs[indesc.cBuffers].pvBuffer = schannel->application_protocols;
    ++indesc.cBuffers;
  }

  if (!schannel->local_tp_sent && schannel->local_tp.len != 0) {
    send_extensionlen = FIELD_OFFSET(SEND_GENERIC_TLS_EXTENSION, Buffer) +
                        schannel->local_tp.len;
    send_extension = malloc(send_extensionlen);
    if (send_extension == NULL) {
      goto cleanup;
    }
    send_extension->ExtensionType = NGTCP2_SCHANNEL_TP_EXT_TYPE;
    send_extension->HandshakeType = schannel->server ? 8 : 1;
    send_extension->Flags = 0;
    send_extension->BufferSize = (USHORT)schannel->local_tp.len;
    memcpy(send_extension->Buffer, schannel->local_tp.base,
           schannel->local_tp.len);
    inbufs[indesc.cBuffers].BufferType = SECBUFFER_SEND_GENERIC_TLS_EXTENSION;
    inbufs[indesc.cBuffers].cbBuffer = (ULONG)send_extensionlen;
    inbufs[indesc.cBuffers].pvBuffer = send_extension;
    ++indesc.cBuffers;
  }

  if (!schannel->server && schannel->input.len != 0 &&
      !schannel->peer_tp_received) {
    subscribe_extension.Flags = 0;
    subscribe_extension.SubscriptionsCount = 1;
    subscribe_extension.Subscriptions[0].ExtensionType =
      NGTCP2_SCHANNEL_TP_EXT_TYPE;
    subscribe_extension.Subscriptions[0].HandshakeType =
      schannel->server ? 1 : 8;
    inbufs[indesc.cBuffers].BufferType =
      SECBUFFER_SUBSCRIBE_GENERIC_TLS_EXTENSION;
    inbufs[indesc.cBuffers].cbBuffer = sizeof(subscribe_extension);
    inbufs[indesc.cBuffers].pvBuffer = &subscribe_extension;
    ++indesc.cBuffers;

    outbufs[outdesc.cBuffers].BufferType =
      SECBUFFER_SUBSCRIBE_GENERIC_TLS_EXTENSION;
    outbufs[outdesc.cBuffers].cbBuffer = (ULONG)schannel->peer_tp.capacity;
    outbufs[outdesc.cBuffers].pvBuffer = schannel->peer_tp.base;
    ++outdesc.cBuffers;
  }

  outbufs[outdesc.cBuffers].BufferType = SECBUFFER_TOKEN;
  outbufs[outdesc.cBuffers].cbBuffer = (ULONG)schannel->output.capacity;
  outbufs[outdesc.cBuffers].pvBuffer = schannel->output.base;
  ++outdesc.cBuffers;

  outbufs[outdesc.cBuffers].BufferType = SECBUFFER_ALERT;
  outbufs[outdesc.cBuffers].cbBuffer = sizeof(alertbuf);
  outbufs[outdesc.cBuffers].pvBuffer = alertbuf;
  ++outdesc.cBuffers;

  for (i = 0; i < NGTCP2_SCHANNEL_TRAFFIC_SECRET_COUNT; ++i) {
    outbufs[outdesc.cBuffers].BufferType = SECBUFFER_TRAFFIC_SECRETS;
    outbufs[outdesc.cBuffers].cbBuffer = sizeof(secretbufs[i]);
    outbufs[outdesc.cBuffers].pvBuffer = secretbufs[i].data;
    ++outdesc.cBuffers;
  }

  if (schannel->server) {
    status = AcceptSecurityContext(
      schannel->cred_handle,
      schannel->context_initialized ? &schannel->context : NULL, &indesc,
      ASC_REQ_SEQUENCE_DETECT | ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR |
        ASC_REQ_STREAM | ASC_REQ_SESSION_TICKET,
      SECURITY_NATIVE_DREP, &schannel->context, &outdesc, &attrs, &expiry);
  } else {
    status = InitializeSecurityContextW(
      schannel->cred_handle,
      schannel->context_initialized ? &schannel->context : NULL,
      schannel->started ? NULL : schannel->server_name,
      ISC_REQ_SEQUENCE_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
        ISC_REQ_STREAM,
      0, SECURITY_NATIVE_DREP, &indesc, 0, &schannel->context, &outdesc, &attrs,
      &expiry);
  }

  schannel->last_error = status;
  *pstatus = status;
  if (SecIsValidHandle(&schannel->context)) {
    schannel->context_initialized = 1;
    schannel->started = 1;
  }

  if (status == SEC_E_BUFFER_TOO_SMALL) {
    size_t capacity = schannel->output.capacity;

    if (capacity > (size_t)ULONG_MAX / 2 ||
        buf_reserve(&schannel->output, capacity * 2) != 0) {
      goto cleanup;
    }
    rv = 1;
    goto cleanup;
  }

  for (i = 0; i < indesc.cBuffers; ++i) {
    if (inbufs[i].BufferType == SECBUFFER_EXTRA) {
      extra = &inbufs[i];
    } else if (inbufs[i].BufferType == SECBUFFER_MISSING) {
      missing = &inbufs[i];
    }
  }
  for (i = 0; i < outdesc.cBuffers; ++i) {
    if (outbufs[i].BufferType == SECBUFFER_TOKEN) {
      output = &outbufs[i];
    } else if (outbufs[i].BufferType ==
               SECBUFFER_SUBSCRIBE_GENERIC_TLS_EXTENSION) {
      extension = &outbufs[i];
    }
  }

  if (status == SEC_E_INCOMPLETE_MESSAGE) {
    (void)missing;
    consumed = 0;
  } else if (extra != NULL) {
    if (extra->cbBuffer > consumed) {
      goto cleanup;
    }
    consumed -= extra->cbBuffer;
  }

  for (i = 0; i < NGTCP2_SCHANNEL_TRAFFIC_SECRET_COUNT; ++i) {
    SEC_TRAFFIC_SECRETS *secret = (SEC_TRAFFIC_SECRETS *)secretbufs[i].data;
    if (secret->TrafficSecretType == SecTrafficSecret_None) {
      continue;
    }
    own_secret = schannel->server
                   ? secret->TrafficSecretType == SecTrafficSecret_Server
                   : secret->TrafficSecretType == SecTrafficSecret_Client;
    if (install_secret(conn, schannel, secret, own_secret) != 0) {
      goto cleanup;
    }
  }

  if (output != NULL && output->cbBuffer != 0) {
    if (output->pvBuffer == NULL ||
        output->cbBuffer > schannel->output.capacity ||
        submit_output(conn, schannel, output->pvBuffer, output->cbBuffer) !=
          0) {
      goto cleanup;
    }
    schannel->generated_first_payload = 1;
    schannel->local_tp_sent = 1;
  }

  if (status == SEC_I_GENERIC_EXTENSION_RECEIVED) {
    if (extension == NULL || extension->cbBuffer < 4 ||
        extension->cbBuffer > schannel->peer_tp.capacity) {
      goto cleanup;
    }
    schannel->peer_tp.len = extension->cbBuffer;
    schannel->peer_tp_received = 1;
    if (apply_peer_transport_params(conn, schannel) != 0) {
      goto cleanup;
    }
  } else if (schannel->server && schannel->peer_tp_received &&
             !schannel->peer_tp_applied &&
             apply_peer_transport_params(conn, schannel) != 0) {
    goto cleanup;
  }

  ngtcp2_schannel_buf_consume(&schannel->input, consumed);

  switch (status) {
  case SEC_E_OK:
    if (!schannel->peer_tp_received) {
      goto cleanup;
    }
    if (!schannel->handshake_completed) {
      if (query_handshake_properties(schannel) != 0) {
        goto cleanup;
      }
      ngtcp2_conn_tls_handshake_completed(conn);
      schannel->handshake_completed = 1;
    }
    break;
  case SEC_I_CONTINUE_NEEDED:
#ifdef SEC_I_CONTINUE_NEEDED_MESSAGE_OK
  case SEC_I_CONTINUE_NEEDED_MESSAGE_OK:
#endif /* defined(SEC_I_CONTINUE_NEEDED_MESSAGE_OK) */
  case SEC_I_GENERIC_EXTENSION_RECEIVED:
  case SEC_E_INCOMPLETE_MESSAGE:
    break;
  default:
    for (i = 0; i < outdesc.cBuffers; ++i) {
      if (outbufs[i].BufferType == SECBUFFER_ALERT &&
          outbufs[i].cbBuffer >= 2) {
        ngtcp2_conn_set_tls_alert(conn, ((uint8_t *)outbufs[i].pvBuffer)[1]);
        break;
      }
    }
    goto cleanup;
  }

  rv = 0;

cleanup:
  if (send_extension != NULL) {
    SecureZeroMemory(send_extension, send_extensionlen);
    free(send_extension);
  }
  SecureZeroMemory(secretbufs, sizeof(secretbufs));
  return rv;
}

int ngtcp2_crypto_read_write_crypto_data(
  ngtcp2_conn *conn, ngtcp2_encryption_level encryption_level,
  const uint8_t *data, size_t datalen) {
  ngtcp2_crypto_schannel *schannel =
    ngtcp2_conn_get_tls_native_handle2(conn);
  SECURITY_STATUS status = SEC_I_CONTINUE_NEEDED;
  size_t previous_inputlen;
  unsigned int i;
  int process_result;

  if (schannel == NULL || (datalen != 0 && data == NULL)) {
    return -1;
  }

  if (datalen != 0) {
    if (schannel->input.len != 0 &&
        schannel->input_level != encryption_level) {
      return -1;
    }
    if (datalen > ULONG_MAX ||
        schannel->input.len > (size_t)ULONG_MAX - datalen) {
      return -1;
    }
    schannel->input_level = encryption_level;
    if (ngtcp2_schannel_buf_append(&schannel->input, data, datalen) != 0) {
      return -1;
    }
  }

  if (schannel->server && !schannel->peer_tp_received) {
    int parse_result = parse_client_hello_transport_params(schannel);
    if (parse_result < 0) {
      return -1;
    }
    if (parse_result == 0) {
      return 0;
    }
    if (apply_peer_transport_params(conn, schannel) != 0) {
      return -1;
    }
  }

  if (schannel->server && !schannel->started && schannel->local_tp.len == 0) {
    if (preload_server_transport_params(conn, schannel) != 0) {
      return -1;
    }
  }

  for (i = 0; i < NGTCP2_SCHANNEL_MAX_PROCESS_ITERATIONS; ++i) {
    previous_inputlen = schannel->input.len;
    process_result = process_once(conn, schannel, &status);
    if (process_result < 0) {
      return -1;
    }
    if (process_result > 0) {
      continue;
    }

    if (status == SEC_E_INCOMPLETE_MESSAGE || status == SEC_E_OK ||
        (status != SEC_I_GENERIC_EXTENSION_RECEIVED &&
         schannel->input.len == 0) ||
        (status != SEC_I_GENERIC_EXTENSION_RECEIVED &&
         schannel->input.len == previous_inputlen)) {
      return 0;
    }
  }

  return -1;
}
