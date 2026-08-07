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
#ifndef NGTCP2_CRYPTO_SCHANNEL_H
#define NGTCP2_CRYPTO_SCHANNEL_H

#include <ngtcp2/ngtcp2_crypto.h>

#ifdef _WIN32
#  ifndef SECURITY_WIN32
#    define SECURITY_WIN32
#  endif /* !defined(SECURITY_WIN32) */
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif /* !defined(WIN32_LEAN_AND_MEAN) */
#  include <windows.h>
#  include <security.h>
#else /* !defined(_WIN32) */
#  error "ngtcp2 Schannel support is only available on Windows"
#endif /* !defined(_WIN32) */

#ifdef __cplusplus
extern "C" {
#endif /* defined(__cplusplus) */

typedef struct ngtcp2_crypto_schannel ngtcp2_crypto_schannel;

/**
 * @struct
 *
 * :type:`ngtcp2_crypto_schannel_config` contains the settings for one
 * Schannel TLS session.  The caller retains ownership of |cred_handle|,
 * |conn_ref|, |server_name|, and |alpn|.  The strings and ALPN bytes are
 * copied by `ngtcp2_crypto_schannel_new`.  |cred_handle| and |conn_ref|
 * must remain valid until the session is deleted.
 *
 * The credential must be created for TLS 1.3 with ``SCH_CREDENTIALS``.
 * It must restrict cipher negotiation to AES-128-GCM or AES-256-GCM.
 * Certificate selection and validation policy are properties of the
 * supplied Schannel credential and are controlled by the application.
 */
typedef struct ngtcp2_crypto_schannel_config {
  CredHandle *cred_handle;
  ngtcp2_crypto_conn_ref *conn_ref;
  const char *server_name;
  const uint8_t *alpn;
  size_t alpnlen;
  int server;
} ngtcp2_crypto_schannel_config;

/**
 * @function
 *
 * `ngtcp2_crypto_schannel_new` creates a per-connection Schannel TLS
 * session.  |config->alpn| uses the TLS wire format: one or more
 * 8-bit-length-prefixed protocol identifiers.  A client must provide a
 * non-NULL UTF-8 |config->server_name|.  A server ignores that member.
 */
NGTCP2_EXTERN int ngtcp2_crypto_schannel_new(
  ngtcp2_crypto_schannel **pschannel,
  const ngtcp2_crypto_schannel_config *config);

/**
 * @function
 *
 * `ngtcp2_crypto_schannel_del` deletes |schannel| and securely clears
 * buffered TLS data and traffic secrets.
 */
NGTCP2_EXTERN void
ngtcp2_crypto_schannel_del(ngtcp2_crypto_schannel *schannel);

/**
 * @function
 *
 * `ngtcp2_crypto_schannel_get_context_handle` returns the native
 * Schannel security context, or NULL before it has been initialized.
 */
NGTCP2_EXTERN CtxtHandle *ngtcp2_crypto_schannel_get_context_handle(
  ngtcp2_crypto_schannel *schannel);

/**
 * @function
 *
 * `ngtcp2_crypto_schannel_get_selected_alpn` returns the selected ALPN.
 * The returned storage is owned by |schannel|.
 */
NGTCP2_EXTERN const uint8_t *ngtcp2_crypto_schannel_get_selected_alpn(
  const ngtcp2_crypto_schannel *schannel, size_t *alpnlen);

/**
 * @function
 *
 * `ngtcp2_crypto_schannel_get_cipher_name` returns the negotiated TLS
 * cipher suite name.  The returned storage is owned by |schannel|.
 */
NGTCP2_EXTERN const char *ngtcp2_crypto_schannel_get_cipher_name(
  const ngtcp2_crypto_schannel *schannel);

/**
 * @function
 *
 * `ngtcp2_crypto_schannel_session_resumed` returns nonzero if Schannel
 * resumed a previous TLS session.
 */
NGTCP2_EXTERN int ngtcp2_crypto_schannel_session_resumed(
  const ngtcp2_crypto_schannel *schannel);

/**
 * @function
 *
 * `ngtcp2_crypto_schannel_get_last_error` returns the last Schannel
 * SECURITY_STATUS observed by the session.
 */
NGTCP2_EXTERN SECURITY_STATUS ngtcp2_crypto_schannel_get_last_error(
  const ngtcp2_crypto_schannel *schannel);

#ifdef __cplusplus
}
#endif /* defined(__cplusplus) */

#endif /* !defined(NGTCP2_CRYPTO_SCHANNEL_H) */
