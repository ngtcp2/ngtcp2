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
#include "schannel_common.h"

#include <bcrypt.h>

#include <stdio.h>
#include <string.h>

ngtcp2_tstamp schannel_example_timestamp(void) {
  return GetTickCount64() * NGTCP2_MILLISECONDS;
}

static void unicode_string_init(UNICODE_STRING *dest, wchar_t *value,
                                size_t valuelen) {
  dest->Length = (USHORT)valuelen;
  dest->MaximumLength = (USHORT)valuelen;
  dest->Buffer = value;
}

static SECURITY_STATUS acquire_credential(
  schannel_example_credential *credential, int server,
  PCCERT_CONTEXT certificate, int manual_validation) {
  CRYPTO_SETTINGS disabled_crypto[2] = {0};
  UNICODE_STRING blocked_mode = {0};
  TLS_PARAMETERS tls_parameters = {0};
  SCH_CREDENTIALS credentials = {0};
  TimeStamp expiry;
  SECURITY_STATUS status;

  unicode_string_init(&disabled_crypto[0].strCngAlgId,
                      (wchar_t *)BCRYPT_CHACHA20_POLY1305_ALGORITHM,
                      sizeof(BCRYPT_CHACHA20_POLY1305_ALGORITHM));
  disabled_crypto[0].eAlgorithmUsage = TlsParametersCngAlgUsageCipher;
  unicode_string_init(&blocked_mode, (wchar_t *)BCRYPT_CHAIN_MODE_CCM,
                      sizeof(BCRYPT_CHAIN_MODE_CCM));
  unicode_string_init(&disabled_crypto[1].strCngAlgId,
                      (wchar_t *)BCRYPT_AES_ALGORITHM,
                      sizeof(BCRYPT_AES_ALGORITHM));
  disabled_crypto[1].eAlgorithmUsage = TlsParametersCngAlgUsageCipher;
  disabled_crypto[1].cChainingModes = 1;
  disabled_crypto[1].rgstrChainingModes = &blocked_mode;

  tls_parameters.grbitDisabledProtocols =
    ~(server ? SP_PROT_TLS1_3_SERVER : SP_PROT_TLS1_3_CLIENT);
  tls_parameters.cDisabledCrypto = _countof(disabled_crypto);
  tls_parameters.pDisabledCrypto = disabled_crypto;

  credentials.dwVersion = SCH_CREDENTIALS_VERSION;
  credentials.dwFlags = SCH_USE_STRONG_CRYPTO;
  credentials.cTlsParameters = 1;
  credentials.pTlsParameters = &tls_parameters;
  if (server) {
    credentials.cCreds = 1;
    credentials.paCred = &certificate;
    credentials.dwFlags |= SCH_CRED_NO_SYSTEM_MAPPER;
  } else {
    credentials.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS |
                           (manual_validation ? SCH_CRED_MANUAL_CRED_VALIDATION
                                              : SCH_CRED_AUTO_CRED_VALIDATION);
  }

  SecInvalidateHandle(&credential->handle);
  status = AcquireCredentialsHandleW(
    NULL, UNISP_NAME_W,
    server ? SECPKG_CRED_INBOUND : SECPKG_CRED_OUTBOUND, NULL, &credentials,
    NULL, NULL, &credential->handle, &expiry);
  credential->initialized = status == SEC_E_OK;
  return status;
}

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

int schannel_example_client_credential_new(
  schannel_example_credential *credential, int manual_validation) {
  memset(credential, 0, sizeof(*credential));
  return acquire_credential(credential, 0, NULL, manual_validation) == SEC_E_OK
           ? 0
           : -1;
}

int schannel_example_server_credential_new(
  schannel_example_credential *credential, const char *thumbprint) {
  uint8_t hashdata[20];
  CRYPT_HASH_BLOB hash;
  size_t i;

  memset(credential, 0, sizeof(*credential));
  if (thumbprint == NULL || strlen(thumbprint) != sizeof(hashdata) * 2) {
    return -1;
  }
  for (i = 0; i < sizeof(hashdata); ++i) {
    int high = hex_nibble(thumbprint[i * 2]);
    int low = hex_nibble(thumbprint[i * 2 + 1]);
    if (high < 0 || low < 0) {
      return -1;
    }
    hashdata[i] = (uint8_t)(high << 4 | low);
  }

  credential->store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                                    CERT_SYSTEM_STORE_CURRENT_USER, L"MY");
  if (credential->store == NULL) {
    return -1;
  }
  hash.cbData = sizeof(hashdata);
  hash.pbData = hashdata;
  credential->certificate = CertFindCertificateInStore(
    credential->store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
    CERT_FIND_HASH, &hash, NULL);
  if (credential->certificate == NULL ||
      acquire_credential(credential, 1, credential->certificate, 0) !=
        SEC_E_OK) {
    schannel_example_credential_del(credential);
    return -1;
  }
  return 0;
}

void schannel_example_credential_del(
  schannel_example_credential *credential) {
  if (credential->initialized) {
    FreeCredentialsHandle(&credential->handle);
  }
  if (credential->certificate != NULL) {
    CertFreeCertificateContext(credential->certificate);
  }
  if (credential->store != NULL) {
    CertCloseStore(credential->store, 0);
  }
  SecureZeroMemory(credential, sizeof(*credential));
}

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref) {
  schannel_example_endpoint *endpoint = conn_ref->user_data;
  return endpoint->conn;
}

static int secure_random(uint8_t *dest, size_t destlen) {
  while (destlen != 0) {
    ULONG nwrite = destlen > ULONG_MAX ? ULONG_MAX : (ULONG)destlen;
    if (BCryptGenRandom(NULL, dest, nwrite,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
      return -1;
    }
    dest += nwrite;
    destlen -= nwrite;
  }
  return 0;
}

static void rand_cb(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx) {
  (void)rand_ctx;
  if (secure_random(dest, destlen) != 0) {
    SecureZeroMemory(dest, destlen);
  }
}

static int get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                 ngtcp2_stateless_reset_token *token,
                                 size_t cidlen, void *user_data) {
  (void)conn;
  (void)user_data;
  if (secure_random(cid->data, cidlen) != 0 ||
      secure_random(token->data, sizeof(token->data)) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  cid->datalen = cidlen;
  return 0;
}

static int handshake_completed(ngtcp2_conn *conn, void *user_data) {
  schannel_example_endpoint *endpoint = user_data;
  (void)conn;
  endpoint->handshake_completed = 1;
  return 0;
}

static void callbacks_init(ngtcp2_callbacks *callbacks, int server) {
  memset(callbacks, 0, sizeof(*callbacks));
  if (server) {
    callbacks->recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
  } else {
    callbacks->client_initial = ngtcp2_crypto_client_initial_cb;
    callbacks->recv_retry = ngtcp2_crypto_recv_retry_cb;
  }
  callbacks->recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
  callbacks->encrypt = ngtcp2_crypto_encrypt_cb;
  callbacks->decrypt = ngtcp2_crypto_decrypt_cb;
  callbacks->hp_mask = ngtcp2_crypto_hp_mask_cb;
  callbacks->rand = rand_cb;
  callbacks->update_key = ngtcp2_crypto_update_key_cb;
  callbacks->delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
  callbacks->delete_crypto_cipher_ctx =
    ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
  callbacks->version_negotiation = ngtcp2_crypto_version_negotiation_cb;
  callbacks->get_new_connection_id2 = get_new_connection_id;
  callbacks->get_path_challenge_data2 =
    ngtcp2_crypto_get_path_challenge_data2_cb;
  callbacks->handshake_completed = handshake_completed;
}

static void endpoint_init(schannel_example_endpoint *endpoint,
                          const struct sockaddr *local_addr,
                          socklen_t local_addrlen,
                          const struct sockaddr *remote_addr,
                          socklen_t remote_addrlen) {
  memset(endpoint, 0, sizeof(*endpoint));
  memcpy(&endpoint->local_addr, local_addr, local_addrlen);
  memcpy(&endpoint->remote_addr, remote_addr, remote_addrlen);
  endpoint->local_addrlen = local_addrlen;
  endpoint->remote_addrlen = remote_addrlen;
  endpoint->path.local.addr = (ngtcp2_sockaddr *)&endpoint->local_addr;
  endpoint->path.local.addrlen = local_addrlen;
  endpoint->path.remote.addr = (ngtcp2_sockaddr *)&endpoint->remote_addr;
  endpoint->path.remote.addrlen = remote_addrlen;
  endpoint->conn_ref.get_conn = get_conn;
  endpoint->conn_ref.user_data = endpoint;
}

int schannel_example_client_new(
  schannel_example_endpoint *endpoint,
  schannel_example_credential *credential, const char *server_name,
  const struct sockaddr *local_addr, socklen_t local_addrlen,
  const struct sockaddr *remote_addr, socklen_t remote_addrlen) {
  static const uint8_t alpn[] = SCHANNEL_EXAMPLE_ALPN;
  ngtcp2_callbacks callbacks;
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  ngtcp2_crypto_schannel_config tls_config;
  ngtcp2_cid dcid = {.datalen = NGTCP2_MIN_INITIAL_DCIDLEN};
  ngtcp2_cid scid = {.datalen = 8};
  int rv;

  endpoint_init(endpoint, local_addr, local_addrlen, remote_addr,
                remote_addrlen);
  callbacks_init(&callbacks, 0);
  ngtcp2_settings_default(&settings);
  settings.initial_ts = schannel_example_timestamp();
  ngtcp2_transport_params_default(&params);
  if (secure_random(dcid.data, dcid.datalen) != 0 ||
      secure_random(scid.data, scid.datalen) != 0) {
    return -1;
  }

  rv = ngtcp2_conn_client_new(&endpoint->conn, &dcid, &scid, &endpoint->path,
                              NGTCP2_PROTO_VER_V1, &callbacks, &settings,
                              &params, NULL, endpoint);
  if (rv != 0) {
    return -1;
  }
  tls_config = (ngtcp2_crypto_schannel_config){
    .cred_handle = &credential->handle,
    .conn_ref = &endpoint->conn_ref,
    .server_name = server_name,
    .alpn = alpn,
    .alpnlen = sizeof(alpn) - 1,
  };
  if (ngtcp2_crypto_schannel_new(&endpoint->tls, &tls_config) != 0) {
    schannel_example_endpoint_del(endpoint);
    return -1;
  }
  ngtcp2_conn_set_tls_native_handle(endpoint->conn, endpoint->tls);
  return 0;
}

int schannel_example_server_new(
  schannel_example_endpoint *endpoint,
  schannel_example_credential *credential, const ngtcp2_pkt_hd *hd,
  const struct sockaddr *local_addr, socklen_t local_addrlen,
  const struct sockaddr *remote_addr, socklen_t remote_addrlen) {
  static const uint8_t alpn[] = SCHANNEL_EXAMPLE_ALPN;
  ngtcp2_callbacks callbacks;
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  ngtcp2_crypto_schannel_config tls_config;
  ngtcp2_cid scid = {.datalen = 8};
  int rv;

  endpoint_init(endpoint, local_addr, local_addrlen, remote_addr,
                remote_addrlen);
  callbacks_init(&callbacks, 1);
  ngtcp2_settings_default(&settings);
  settings.initial_ts = schannel_example_timestamp();
  ngtcp2_transport_params_default(&params);
  params.original_dcid = hd->dcid;
  params.original_dcid_present = 1;
  if (secure_random(scid.data, scid.datalen) != 0) {
    return -1;
  }

  rv = ngtcp2_conn_server_new(&endpoint->conn, &hd->scid, &scid,
                              &endpoint->path, hd->version, &callbacks,
                              &settings, &params, NULL, endpoint);
  if (rv != 0) {
    return -1;
  }
  tls_config = (ngtcp2_crypto_schannel_config){
    .cred_handle = &credential->handle,
    .conn_ref = &endpoint->conn_ref,
    .alpn = alpn,
    .alpnlen = sizeof(alpn) - 1,
    .server = 1,
  };
  if (ngtcp2_crypto_schannel_new(&endpoint->tls, &tls_config) != 0) {
    schannel_example_endpoint_del(endpoint);
    return -1;
  }
  ngtcp2_conn_set_tls_native_handle(endpoint->conn, endpoint->tls);
  return 0;
}

void schannel_example_endpoint_del(schannel_example_endpoint *endpoint) {
  ngtcp2_conn_del(endpoint->conn);
  ngtcp2_crypto_schannel_del(endpoint->tls);
  memset(endpoint, 0, sizeof(*endpoint));
}

int schannel_example_read(schannel_example_endpoint *endpoint,
                          const uint8_t *data, size_t datalen) {
  int rv = ngtcp2_conn_read_pkt(endpoint->conn, &endpoint->path, NULL, data,
                                datalen, schannel_example_timestamp());
  if (rv != 0) {
    fprintf(stderr, "ngtcp2_conn_read_pkt: %s\n", ngtcp2_strerror(rv));
    return -1;
  }
  return 0;
}

int schannel_example_write(schannel_example_endpoint *endpoint, SOCKET fd) {
  uint8_t packet[65536];
  unsigned int i;

  for (i = 0; i < 32; ++i) {
    ngtcp2_path path = endpoint->path;
    ngtcp2_ssize nwrite = ngtcp2_conn_write_pkt(
      endpoint->conn, &path, NULL, packet, sizeof(packet),
      schannel_example_timestamp());
    if (nwrite < 0) {
      fprintf(stderr, "ngtcp2_conn_write_pkt: %s\n",
              ngtcp2_strerror((int)nwrite));
      return -1;
    }
    if (nwrite == 0) {
      return 0;
    }
    if (sendto(fd, (const char *)packet, (int)nwrite, 0,
               (const struct sockaddr *)&endpoint->remote_addr,
               endpoint->remote_addrlen) == SOCKET_ERROR) {
      fprintf(stderr, "sendto: %d\n", WSAGetLastError());
      return -1;
    }
  }
  return 0;
}

int schannel_example_handle_expiry(schannel_example_endpoint *endpoint) {
  int rv = ngtcp2_conn_handle_expiry(endpoint->conn,
                                     schannel_example_timestamp());
  if (rv != 0) {
    fprintf(stderr, "ngtcp2_conn_handle_expiry: %s\n", ngtcp2_strerror(rv));
    return -1;
  }
  return 0;
}

void schannel_example_print_result(
  const schannel_example_endpoint *endpoint) {
  size_t alpnlen;
  const uint8_t *alpn =
    ngtcp2_crypto_schannel_get_selected_alpn(endpoint->tls, &alpnlen);
  const char *cipher = ngtcp2_crypto_schannel_get_cipher_name(endpoint->tls);

  printf("Handshake complete: cipher=%s ALPN=%.*s resumed=%s\n",
         cipher == NULL ? "unknown" : cipher, (int)alpnlen,
         alpn == NULL ? "" : (const char *)alpn,
         ngtcp2_crypto_schannel_session_resumed(endpoint->tls) ? "yes" : "no");
}
