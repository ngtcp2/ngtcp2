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
#include "schannel_test.h"

#include <winsock2.h>
#define SCHANNEL_USE_BLACKLISTS
#include <windows.h>
#include <winternl.h>

#include "schannel_internal.h"

#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_schannel.h>

#include <bcrypt.h>
#ifdef _MSC_VER
#include <crtdbg.h>
#endif /* defined(_MSC_VER) */
#include <schannel.h>
#include <wincrypt.h>

#include <stdio.h>
#include <string.h>

static MunitResult
wrap_test_schannel_handshake(const MunitParameter params[], void *fixture);

static const MunitTest tests[] = {
  munit_void_test(test_schannel_hkdf),
  munit_void_test(test_schannel_aes_gcm),
  munit_void_test(test_schannel_aes_256_gcm),
  munit_void_test(test_schannel_hp_mask),
  munit_void_test(test_schannel_api),
  {"/test_schannel_handshake", wrap_test_schannel_handshake, NULL, NULL,
   MUNIT_TEST_OPTION_NONE, NULL},
  munit_test_end(),
};

const MunitSuite schannel_suite = {
  .prefix = "/schannel",
  .tests = tests,
};

void test_schannel_hkdf(void) {
  static const uint8_t ikm[22] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
  };
  static const uint8_t salt[13] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
  };
  static const uint8_t info[10] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
  };
  static const uint8_t expected_prk[32] = {
    0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
    0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
    0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
    0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5,
  };
  static const uint8_t expected_okm[42] = {
    0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
    0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
    0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
    0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
    0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
    0x58, 0x65,
  };
  ngtcp2_crypto_md md;
  uint8_t prk[32], okm[42];

  ngtcp2_crypto_md_sha256(&md);
  assert_int(0, ==, ngtcp2_crypto_hkdf_extract(prk, &md, ikm, sizeof(ikm),
                                               salt, sizeof(salt)));
  assert_memory_equal(sizeof(expected_prk), expected_prk, prk);
  assert_int(0, ==, ngtcp2_crypto_hkdf_expand(okm, sizeof(okm), &md, prk,
                                              sizeof(prk), info,
                                              sizeof(info)));
  assert_memory_equal(sizeof(expected_okm), expected_okm, okm);
}

void test_schannel_aes_gcm(void) {
  static const uint8_t expected[32] = {
    0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
    0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
    0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
    0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf,
  };
  const uint8_t key[16] = {0};
  const uint8_t nonce[12] = {0};
  const uint8_t plaintext[16] = {0};
  ngtcp2_crypto_aead aead;
  ngtcp2_crypto_aead_ctx encrypt_ctx = {0}, decrypt_ctx = {0};
  uint8_t buf[sizeof(expected)], bad[sizeof(expected)];

  ngtcp2_crypto_aead_aes_128_gcm(&aead);
  assert_size(16, ==, ngtcp2_crypto_aead_keylen(&aead));
  assert_size(12, ==, ngtcp2_crypto_aead_noncelen(&aead));
  assert_int(0, ==, ngtcp2_crypto_aead_ctx_encrypt_init(
                       &encrypt_ctx, &aead, key, sizeof(nonce)));
  assert_int(0, ==, ngtcp2_crypto_aead_ctx_decrypt_init(
                       &decrypt_ctx, &aead, key, sizeof(nonce)));

  assert_int(0, ==, ngtcp2_crypto_encrypt(buf, &aead, &encrypt_ctx, plaintext,
                                         sizeof(plaintext), nonce,
                                         sizeof(nonce), NULL, 0));
  assert_memory_equal(sizeof(expected), expected, buf);
  assert_int(0, ==, ngtcp2_crypto_decrypt(buf, &aead, &decrypt_ctx, buf,
                                         sizeof(buf), nonce, sizeof(nonce),
                                         NULL, 0));
  assert_memory_equal(sizeof(plaintext), plaintext, buf);

  memcpy(bad, expected, sizeof(bad));
  bad[sizeof(bad) - 1] ^= 1;
  assert_int(-1, ==, ngtcp2_crypto_decrypt(buf, &aead, &decrypt_ctx, bad,
                                          sizeof(bad), nonce, sizeof(nonce),
                                          NULL, 0));

  ngtcp2_crypto_aead_ctx_free(&decrypt_ctx);
  ngtcp2_crypto_aead_ctx_free(&encrypt_ctx);
  assert_null(decrypt_ctx.native_handle);
  assert_null(encrypt_ctx.native_handle);
}

void test_schannel_aes_256_gcm(void) {
  static const uint8_t expected[32] = {
    0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
    0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18,
    0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
    0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19,
  };
  const uint8_t key[32] = {0};
  const uint8_t nonce[12] = {0};
  const uint8_t plaintext[16] = {0};
  ngtcp2_crypto_aead aead;
  ngtcp2_crypto_aead_ctx encrypt_ctx = {0}, decrypt_ctx = {0};
  uint8_t buf[sizeof(expected)];

  ngtcp2_crypto_aead_init(
    &aead, (void *)(intptr_t)NGTCP2_SCHANNEL_AEAD_AES_256_GCM);
  assert_size(32, ==, ngtcp2_crypto_aead_keylen(&aead));
  assert_int(0, ==, ngtcp2_crypto_aead_ctx_encrypt_init(
                       &encrypt_ctx, &aead, key, sizeof(nonce)));
  assert_int(0, ==, ngtcp2_crypto_aead_ctx_decrypt_init(
                       &decrypt_ctx, &aead, key, sizeof(nonce)));
  assert_int(0, ==, ngtcp2_crypto_encrypt(buf, &aead, &encrypt_ctx, plaintext,
                                         sizeof(plaintext), nonce,
                                         sizeof(nonce), NULL, 0));
  assert_memory_equal(sizeof(expected), expected, buf);
  assert_int(0, ==, ngtcp2_crypto_decrypt(buf, &aead, &decrypt_ctx, buf,
                                         sizeof(buf), nonce, sizeof(nonce),
                                         NULL, 0));
  assert_memory_equal(sizeof(plaintext), plaintext, buf);

  ngtcp2_crypto_aead_ctx_free(&decrypt_ctx);
  ngtcp2_crypto_aead_ctx_free(&encrypt_ctx);
}

void test_schannel_hp_mask(void) {
  static const uint8_t hp_key[16] = {
    0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
    0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2,
  };
  static const uint8_t sample[16] = {
    0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68, 0x9f, 0xb8,
    0xec, 0x11, 0xd2, 0x42, 0xb1, 0x23, 0xdc, 0x9b,
  };
  static const uint8_t expected[5] = {0x43, 0x7b, 0x9a, 0xec, 0x36};
  ngtcp2_crypto_ctx crypto_ctx;
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  uint8_t mask[5];

  ngtcp2_crypto_ctx_initial(&crypto_ctx);
  assert_int(0, ==, ngtcp2_crypto_cipher_ctx_encrypt_init(
                       &hp_ctx, &crypto_ctx.hp, hp_key));
  assert_int(0, ==, ngtcp2_crypto_hp_mask(mask, &crypto_ctx.hp, &hp_ctx,
                                         sample));
  assert_memory_equal(sizeof(expected), expected, mask);

  ngtcp2_crypto_cipher_ctx_free(&hp_ctx);
  assert_null(hp_ctx.native_handle);
}

static ngtcp2_conn *schannel_test_null_conn(ngtcp2_crypto_conn_ref *conn_ref) {
  (void)conn_ref;
  return NULL;
}

void test_schannel_api(void) {
  static const uint8_t alpn[] = {2, 'h', '3'};
  static const uint8_t zero_alpn[] = {0};
  static const uint8_t truncated_alpn[] = {3, 'h', '3'};
  ngtcp2_crypto_conn_ref conn_ref = {
    .get_conn = schannel_test_null_conn,
  };
  CredHandle credential;
  ngtcp2_crypto_schannel_config config = {
    .cred_handle = &credential,
    .conn_ref = &conn_ref,
    .server_name = "localhost",
    .alpn = alpn,
    .alpnlen = sizeof(alpn),
  };
  ngtcp2_crypto_schannel *schannel = NULL;
  uint8_t random_bytes[32] = {0};
  size_t alpnlen = 99;
  size_t i;
  int all_zero = 1;

  SecInvalidateHandle(&credential);
  assert_int(-1, ==, ngtcp2_crypto_schannel_new(NULL, &config));
  assert_int(-1, ==, ngtcp2_crypto_schannel_new(&schannel, NULL));

  config.server_name = NULL;
  assert_int(-1, ==, ngtcp2_crypto_schannel_new(&schannel, &config));
  config.server_name = "localhost";
  config.alpn = zero_alpn;
  config.alpnlen = sizeof(zero_alpn);
  assert_int(-1, ==, ngtcp2_crypto_schannel_new(&schannel, &config));
  config.alpn = truncated_alpn;
  config.alpnlen = sizeof(truncated_alpn);
  assert_int(-1, ==, ngtcp2_crypto_schannel_new(&schannel, &config));

  config.alpn = alpn;
  config.alpnlen = sizeof(alpn);
  assert_int(0, ==, ngtcp2_crypto_schannel_new(&schannel, &config));
  assert_null(ngtcp2_crypto_schannel_get_context_handle(schannel));
  assert_null(ngtcp2_crypto_schannel_get_selected_alpn(schannel, &alpnlen));
  assert_size(0, ==, alpnlen);
  assert_null(ngtcp2_crypto_schannel_get_cipher_name(schannel));
  assert_false(ngtcp2_crypto_schannel_session_resumed(schannel));
  ngtcp2_crypto_schannel_del(schannel);

  assert_uint32(SEC_E_INVALID_HANDLE, ==,
                ngtcp2_crypto_schannel_get_last_error(NULL));
  assert_int(0, ==, ngtcp2_crypto_random(random_bytes, sizeof(random_bytes)));
  for (i = 0; i < sizeof(random_bytes); ++i) {
    all_zero &= random_bytes[i] == 0;
  }
  assert_false(all_zero);
}

typedef struct schannel_test_credential {
  CredHandle handle;
  int initialized;
} schannel_test_credential;

typedef struct schannel_test_certificate {
  HCERTSTORE store;
  PCCERT_CONTEXT context;
} schannel_test_certificate;

static MunitResult
wrap_test_schannel_handshake(const MunitParameter params[], void *fixture) {
  (void)params;
  (void)fixture;

  if (getenv("NGTCP2_SCHANNEL_TEST_CERT_HASH") == NULL) {
    return MUNIT_SKIP;
  }

  test_schannel_handshake();
  return MUNIT_OK;
}

typedef struct schannel_test_endpoint {
  ngtcp2_conn *conn;
  ngtcp2_crypto_schannel *schannel;
  ngtcp2_crypto_conn_ref conn_ref;
  ngtcp2_path path;
  uint8_t stream_data[64];
  size_t stream_datalen;
  int handshake_completed;
} schannel_test_endpoint;

static ngtcp2_conn *schannel_test_get_conn(ngtcp2_crypto_conn_ref *conn_ref) {
  schannel_test_endpoint *endpoint = conn_ref->user_data;
  return endpoint->conn;
}

static void schannel_test_rand(uint8_t *dest, size_t destlen,
                               const ngtcp2_rand_ctx *rand_ctx) {
  (void)rand_ctx;
  if (ngtcp2_crypto_random(dest, destlen) != 0) {
    memset(dest, 0, destlen);
  }
}

static int schannel_test_get_new_connection_id(
  ngtcp2_conn *conn, ngtcp2_cid *cid, ngtcp2_stateless_reset_token *token,
  size_t cidlen, void *user_data) {
  (void)conn;
  (void)user_data;

  if (ngtcp2_crypto_random(cid->data, cidlen) != 0 ||
      ngtcp2_crypto_random(token->data, sizeof(token->data)) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  cid->datalen = cidlen;
  return 0;
}

static int schannel_test_handshake_completed(ngtcp2_conn *conn,
                                              void *user_data) {
  schannel_test_endpoint *endpoint = user_data;
  (void)conn;
  endpoint->handshake_completed = 1;
  return 0;
}

static int schannel_test_recv_stream_data(
  ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t offset,
  const uint8_t *data, size_t datalen, void *user_data,
  void *stream_user_data) {
  schannel_test_endpoint *endpoint = user_data;
  (void)conn;
  (void)flags;
  (void)stream_id;
  (void)stream_user_data;

  if (offset > sizeof(endpoint->stream_data) ||
      datalen > sizeof(endpoint->stream_data) - (size_t)offset) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  memcpy(endpoint->stream_data + offset, data, datalen);
  if (endpoint->stream_datalen < offset + datalen) {
    endpoint->stream_datalen = (size_t)offset + datalen;
  }
  return 0;
}

static void schannel_test_callbacks(ngtcp2_callbacks *callbacks, int server) {
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
  callbacks->rand = schannel_test_rand;
  callbacks->update_key = ngtcp2_crypto_update_key_cb;
  callbacks->delete_crypto_aead_ctx =
    ngtcp2_crypto_delete_crypto_aead_ctx_cb;
  callbacks->delete_crypto_cipher_ctx =
    ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
  callbacks->version_negotiation = ngtcp2_crypto_version_negotiation_cb;
  callbacks->get_new_connection_id2 = schannel_test_get_new_connection_id;
  callbacks->get_path_challenge_data2 =
    ngtcp2_crypto_get_path_challenge_data2_cb;
  callbacks->handshake_completed = schannel_test_handshake_completed;
  callbacks->recv_stream_data = schannel_test_recv_stream_data;
}

static int schannel_test_hex_nibble(char c) {
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

static int schannel_test_certificate_new(schannel_test_certificate *cert) {
  const char *thumbprint = getenv("NGTCP2_SCHANNEL_TEST_CERT_HASH");
  CRYPT_HASH_BLOB hash;
  uint8_t hashdata[20];
  size_t i;

  memset(cert, 0, sizeof(*cert));
  if (thumbprint == NULL || strlen(thumbprint) != sizeof(hashdata) * 2) {
    return -1;
  }
  for (i = 0; i < sizeof(hashdata); ++i) {
    int high = schannel_test_hex_nibble(thumbprint[i * 2]);
    int low = schannel_test_hex_nibble(thumbprint[i * 2 + 1]);

    if (high == -1 || low == -1) {
      return -1;
    }
    hashdata[i] = (uint8_t)((high << 4) | low);
  }
  cert->store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                              CERT_SYSTEM_STORE_CURRENT_USER, L"MY");
  if (cert->store == NULL) {
    return -1;
  }
  hash.cbData = sizeof(hashdata);
  hash.pbData = hashdata;
  cert->context = CertFindCertificateInStore(
    cert->store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_HASH,
    &hash, NULL);
  if (cert->context == NULL) {
    CertCloseStore(cert->store, 0);
    cert->store = NULL;
    return -1;
  }
  return 0;
}

static void
schannel_test_certificate_del(schannel_test_certificate *certificate) {
  if (certificate->context != NULL) {
    CertFreeCertificateContext(certificate->context);
  }
  if (certificate->store != NULL) {
    CertCloseStore(certificate->store, 0);
  }
  SecureZeroMemory(certificate, sizeof(*certificate));
}

static void schannel_test_unicode_string(UNICODE_STRING *dest, wchar_t *s,
                                         size_t bytelen) {
  dest->Length = (USHORT)bytelen;
  dest->MaximumLength = (USHORT)bytelen;
  dest->Buffer = s;
}

static SECURITY_STATUS schannel_test_acquire_credential(
  schannel_test_credential *credential, int server,
  PCCERT_CONTEXT certificate) {
  CRYPTO_SETTINGS disabled_crypto[2] = {0};
  UNICODE_STRING blocked_mode = {0};
  TLS_PARAMETERS tls_parameters = {0};
  SCH_CREDENTIALS credentials = {0};
  TimeStamp expiry;
  SECURITY_STATUS status;

  schannel_test_unicode_string(
    &disabled_crypto[0].strCngAlgId,
    (wchar_t *)BCRYPT_CHACHA20_POLY1305_ALGORITHM,
    sizeof(BCRYPT_CHACHA20_POLY1305_ALGORITHM));
  disabled_crypto[0].eAlgorithmUsage = TlsParametersCngAlgUsageCipher;
  schannel_test_unicode_string(&blocked_mode, (wchar_t *)BCRYPT_CHAIN_MODE_CCM,
                               sizeof(BCRYPT_CHAIN_MODE_CCM));
  schannel_test_unicode_string(&disabled_crypto[1].strCngAlgId,
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
    credentials.dwFlags |=
      SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION;
  }

  SecInvalidateHandle(&credential->handle);
  credential->initialized = 0;
  status = AcquireCredentialsHandleW(
    NULL, UNISP_NAME_W,
    server ? SECPKG_CRED_INBOUND : SECPKG_CRED_OUTBOUND, NULL, &credentials,
    NULL, NULL, &credential->handle, &expiry);
  credential->initialized = status == SEC_E_OK;
  return status;
}

static void
schannel_test_credential_del(schannel_test_credential *credential) {
  if (credential->initialized) {
    FreeCredentialsHandle(&credential->handle);
  }
  memset(credential, 0, sizeof(*credential));
}

static int schannel_test_transfer(schannel_test_endpoint *source,
                                  schannel_test_endpoint *dest,
                                  ngtcp2_tstamp ts) {
  uint8_t packet[65536];
  ngtcp2_path path = source->path;
  ngtcp2_ssize nwrite;
  int rv;

  nwrite = ngtcp2_conn_write_pkt(source->conn, &path, NULL, packet,
                                 sizeof(packet), ts);
  if (nwrite < 0) {
    return (int)nwrite;
  }
  if (nwrite == 0) {
    return 0;
  }

  path = dest->path;
  rv = ngtcp2_conn_read_pkt(dest->conn, &path, NULL, packet, (size_t)nwrite,
                            ts);
  return rv == 0 ? 1 : rv;
}

void test_schannel_handshake(void) {
  static const uint8_t alpn[] = {11, 'n', 'g', 't', 'c', 'p', '2', '-',
                                 't', 'e', 's', 't'};
  schannel_test_certificate certificate;
  schannel_test_credential client_credential = {0}, server_credential = {0};
  schannel_test_endpoint client = {0}, server = {0};
  ngtcp2_crypto_schannel_config tls_config;
  ngtcp2_callbacks client_callbacks, server_callbacks;
  ngtcp2_settings client_settings, server_settings;
  ngtcp2_transport_params client_params, server_params;
  ngtcp2_cid client_dcid = {.datalen = 8,
                            .data = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                     0x16, 0x17}};
  ngtcp2_cid client_scid = {.datalen = 8,
                            .data = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
                                     0x26, 0x27}};
  ngtcp2_cid server_scid = {.datalen = 8,
                            .data = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
                                     0x36, 0x37}};
  struct sockaddr_in client_addr = {0}, server_addr = {0};
  size_t selected_alpnlen;
  const uint8_t *selected_alpn;
  const char *cipher_name;
  int rv = -1, client_result, server_result;
  unsigned int i;

#ifdef _MSC_VER
  _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
  _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
  _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
  _CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);
  _CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);
  _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
#endif /* defined(_MSC_VER) */

  assert_int(0, ==, schannel_test_certificate_new(&certificate));
  assert_uint32(SEC_E_OK, ==,
                schannel_test_acquire_credential(&client_credential, 0,
                                                  NULL));
  assert_uint32(SEC_E_OK, ==,
                schannel_test_acquire_credential(
                  &server_credential, 1, certificate.context));

  client_addr.sin_family = AF_INET;
  client_addr.sin_port = htons(44300);
  client_addr.sin_addr.s_addr = htonl(0x7f000001);
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(44301);
  server_addr.sin_addr.s_addr = htonl(0x7f000001);

  client.path.local.addr = (ngtcp2_sockaddr *)&client_addr;
  client.path.local.addrlen = sizeof(client_addr);
  client.path.remote.addr = (ngtcp2_sockaddr *)&server_addr;
  client.path.remote.addrlen = sizeof(server_addr);
  server.path.local.addr = (ngtcp2_sockaddr *)&server_addr;
  server.path.local.addrlen = sizeof(server_addr);
  server.path.remote.addr = (ngtcp2_sockaddr *)&client_addr;
  server.path.remote.addrlen = sizeof(client_addr);

  schannel_test_callbacks(&client_callbacks, 0);
  schannel_test_callbacks(&server_callbacks, 1);
  ngtcp2_settings_default(&client_settings);
  ngtcp2_settings_default(&server_settings);
  ngtcp2_transport_params_default(&client_params);
  ngtcp2_transport_params_default(&server_params);
  server_params.initial_max_data = 1024;
  server_params.initial_max_stream_data_bidi_remote = 1024;
  server_params.initial_max_streams_bidi = 1;
  server_params.original_dcid = client_dcid;
  server_params.original_dcid_present = 1;

  client.conn_ref.get_conn = schannel_test_get_conn;
  client.conn_ref.user_data = &client;
  server.conn_ref.get_conn = schannel_test_get_conn;
  server.conn_ref.user_data = &server;

  assert_int(0, ==,
             ngtcp2_conn_client_new(&client.conn, &client_dcid, &client_scid,
                                    &client.path, NGTCP2_PROTO_VER_V1,
                                    &client_callbacks, &client_settings,
                                    &client_params, NULL, &client));
  assert_int(0, ==,
             ngtcp2_conn_server_new(&server.conn, &client_scid, &server_scid,
                                    &server.path, NGTCP2_PROTO_VER_V1,
                                    &server_callbacks, &server_settings,
                                    &server_params, NULL, &server));

  tls_config = (ngtcp2_crypto_schannel_config){
    .cred_handle = &client_credential.handle,
    .conn_ref = &client.conn_ref,
    .server_name = "localhost",
    .alpn = alpn,
    .alpnlen = sizeof(alpn),
  };
  assert_int(0, ==, ngtcp2_crypto_schannel_new(&client.schannel, &tls_config));
  ngtcp2_conn_set_tls_native_handle(client.conn, client.schannel);

  tls_config = (ngtcp2_crypto_schannel_config){
    .cred_handle = &server_credential.handle,
    .conn_ref = &server.conn_ref,
    .alpn = alpn,
    .alpnlen = sizeof(alpn),
    .server = 1,
  };
  assert_int(0, ==, ngtcp2_crypto_schannel_new(&server.schannel, &tls_config));
  ngtcp2_conn_set_tls_native_handle(server.conn, server.schannel);

  for (i = 0; i < 1000; ++i) {
    client_result = schannel_test_transfer(
      &client, &server, (ngtcp2_tstamp)i * NGTCP2_MILLISECONDS);
    server_result = schannel_test_transfer(
      &server, &client, (ngtcp2_tstamp)i * NGTCP2_MILLISECONDS);
    if (client_result < 0 || server_result < 0) {
      fprintf(stderr,
              "Schannel handshake failed: client=%d server=%d "
              "client_tls=0x%08lx server_tls=0x%08lx\n",
              client_result, server_result,
              (unsigned long)ngtcp2_crypto_schannel_get_last_error(
                client.schannel),
              (unsigned long)ngtcp2_crypto_schannel_get_last_error(
                server.schannel));
      goto cleanup;
    }
    if (client.handshake_completed && server.handshake_completed) {
      rv = 0;
      break;
    }
  }

cleanup:
  assert_int(0, ==, rv);
  assert_true(ngtcp2_conn_get_handshake_completed2(client.conn));
  assert_true(ngtcp2_conn_get_handshake_completed2(server.conn));

  selected_alpn = ngtcp2_crypto_schannel_get_selected_alpn(
    client.schannel, &selected_alpnlen);
  assert_size(sizeof(alpn) - 1, ==, selected_alpnlen);
  assert_memory_equal(selected_alpnlen, alpn + 1, selected_alpn);
  selected_alpn = ngtcp2_crypto_schannel_get_selected_alpn(
    server.schannel, &selected_alpnlen);
  assert_size(sizeof(alpn) - 1, ==, selected_alpnlen);
  assert_memory_equal(selected_alpnlen, alpn + 1, selected_alpn);
  cipher_name =
    ngtcp2_crypto_schannel_get_cipher_name(client.schannel);
  assert_not_null(cipher_name);
  assert_not_null(strstr(cipher_name, "AES"));
  assert_false(ngtcp2_crypto_schannel_session_resumed(client.schannel));

  {
    static const uint8_t payload[] = "Schannel QUIC 1-RTT";
    uint8_t packet[65536];
    ngtcp2_vec datav;
    ngtcp2_ssize ndatalen, nwrite;
    ngtcp2_path path;
    size_t payload_offset = 0;
    int64_t stream_id;
    unsigned int j;

    assert_int(0, ==,
               ngtcp2_conn_open_bidi_stream(client.conn, &stream_id, NULL));
    for (j = 0; j < 1000 && payload_offset < sizeof(payload) - 1; ++j) {
      ngtcp2_tstamp ts =
        (ngtcp2_tstamp)(i + j + 1) * NGTCP2_MILLISECONDS;

      datav.base = (uint8_t *)payload + payload_offset;
      datav.len = sizeof(payload) - 1 - payload_offset;
      ndatalen = -1;
      path = client.path;
      nwrite = ngtcp2_conn_writev_stream(
        client.conn, &path, NULL, packet, sizeof(packet), &ndatalen,
        NGTCP2_WRITE_STREAM_FLAG_FIN, stream_id, &datav, 1, ts);
      assert_ptrdiff(0, <=, nwrite);
      if (ndatalen > 0) {
        payload_offset += (size_t)ndatalen;
      }
      if (nwrite > 0) {
        path = server.path;
        assert_int(0, ==,
                   ngtcp2_conn_read_pkt(server.conn, &path, NULL, packet,
                                        (size_t)nwrite, ts));
      }
      assert_int(0, <=,
                 schannel_test_transfer(&server, &client, ts));
    }
    assert_size(sizeof(payload) - 1, ==, payload_offset);
    assert_size(sizeof(payload) - 1, ==, server.stream_datalen);
    assert_memory_equal(sizeof(payload) - 1, payload, server.stream_data);
  }

  ngtcp2_conn_del(client.conn);
  ngtcp2_conn_del(server.conn);
  ngtcp2_crypto_schannel_del(client.schannel);
  ngtcp2_crypto_schannel_del(server.schannel);
  schannel_test_credential_del(&client_credential);
  schannel_test_credential_del(&server_credential);
  schannel_test_certificate_del(&certificate);
}
