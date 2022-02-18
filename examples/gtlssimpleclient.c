/*
 * ngtcp2
 *
 * Copyright (c) 2021-2022 ngtcp2 contributors
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
#endif /* HAVE_CONFIG_H */

#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>

#include <ev.h>

#define REMOTE_HOST "127.0.0.1"
#define REMOTE_PORT "4433"
#define ALPN "hq-interop"
#define MESSAGE "GET /\r\n"

/*
 * Example 1: Handshake with www.google.com
 *
 * #define REMOTE_HOST "www.google.com"
 * #define REMOTE_PORT "443"
 * #define ALPN "h3"
 *
 * and undefine MESSAGE macro.
 */

static uint64_t timestamp(void) {
  struct timespec tp;

  if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
    fprintf(stderr, "clock_gettime: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

static int create_sock(struct sockaddr *addr, socklen_t *paddrlen,
                       const char *host, const char *port) {
  struct addrinfo hints = {0};
  struct addrinfo *res, *rp;
  int rv;
  int fd = -1;

  hints.ai_flags = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  rv = getaddrinfo(host, port, &hints, &res);
  if (rv != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return -1;
  }

  for (rp = res; rp; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd == -1) {
      continue;
    }

    break;
  }

  if (fd == -1) {
    goto end;
  }

  *paddrlen = rp->ai_addrlen;
  memcpy(addr, rp->ai_addr, rp->ai_addrlen);

end:
  freeaddrinfo(res);

  return fd;
}

static int connect_sock(struct sockaddr *local_addr, socklen_t *plocal_addrlen,
                        int fd, const struct sockaddr *remote_addr,
                        size_t remote_addrlen) {
  socklen_t len;

  if (connect(fd, remote_addr, (socklen_t)remote_addrlen) != 0) {
    fprintf(stderr, "connect: %s\n", strerror(errno));
    return -1;
  }

  len = *plocal_addrlen;

  if (getsockname(fd, local_addr, &len) == -1) {
    fprintf(stderr, "getsockname: %s\n", strerror(errno));
    return -1;
  }

  *plocal_addrlen = len;

  return 0;
}

struct client {
  int fd;
  struct sockaddr_storage local_addr;
  socklen_t local_addrlen;
  gnutls_certificate_credentials_t cred;
  gnutls_session_t session;
  ngtcp2_conn *conn;

  struct {
    int64_t stream_id;
    const uint8_t *data;
    size_t datalen;
    size_t nwrite;
  } stream;

  uint64_t last_error;

  ev_io rev;
  ev_timer timer;
  ev_timer idle_timer;
};

static int hook_func(gnutls_session_t session, unsigned int htype,
                     unsigned when, unsigned int incoming,
                     const gnutls_datum_t *msg) {
  (void)session;
  (void)htype;
  (void)when;
  (void)incoming;
  (void)msg;
  /* we could save session data here */

  return 0;
}

static int secret_func(gnutls_session_t session,
                       gnutls_record_encryption_level_t gtls_level,
                       const void *rx_secret, const void *tx_secret,
                       size_t secret_size) {
  struct client *c = gnutls_session_get_ptr(session);
  ngtcp2_crypto_level level =
      ngtcp2_crypto_gnutls_from_gnutls_record_encryption_level(gtls_level);

  if (rx_secret &&
      ngtcp2_crypto_derive_and_install_rx_key(c->conn, NULL, NULL, NULL, level,
                                              rx_secret, secret_size) != 0) {
    fprintf(stderr, "ngtcp2_crypto_derive_and_install_rx_key failed\n");
    return -1;
  }

  if (tx_secret &&
      ngtcp2_crypto_derive_and_install_tx_key(c->conn, NULL, NULL, NULL, level,
                                              tx_secret, secret_size) != 0) {
    fprintf(stderr, "ngtcp2_crypto_derive_and_install_tx_key failed\n");
    return -1;
  }

  return 0;
}

static int read_func(gnutls_session_t session,
                     gnutls_record_encryption_level_t level,
                     gnutls_handshake_description_t htype, const void *data,
                     size_t data_size) {
  struct client *c = gnutls_session_get_ptr(session);
  int rv;

  if (htype == GNUTLS_HANDSHAKE_CHANGE_CIPHER_SPEC) {
    return 0;
  }

  if ((rv = ngtcp2_conn_submit_crypto_data(
           c->conn,
           ngtcp2_crypto_gnutls_from_gnutls_record_encryption_level(level),
           data, data_size)) != 0) {
    fprintf(stderr, "ngtcp2_conn_submit_crypto_data: %s\n",
            ngtcp2_strerror(rv));
    return -1;
  }

  return 0;
}

static int alert_read_func(gnutls_session_t session,
                           gnutls_record_encryption_level_t level,
                           gnutls_alert_level_t alert_level,
                           gnutls_alert_description_t alert_desc) {
  struct client *c = gnutls_session_get_ptr(session);
  (void)level;
  (void)alert_level;

  c->last_error = NGTCP2_CRYPTO_ERROR | alert_desc;

  return 0;
}

static int numeric_host_family(const char *hostname, int family) {
  uint8_t dst[sizeof(struct in6_addr)];
  return inet_pton(family, hostname, dst) == 1;
}

static int numeric_host(const char *hostname) {
  return numeric_host_family(hostname, AF_INET) ||
         numeric_host_family(hostname, AF_INET6);
}

static int tp_recv_func(gnutls_session_t session, const uint8_t *data,
                        size_t data_size) {
  struct client *c = gnutls_session_get_ptr(session);
  ngtcp2_transport_params params;
  int rv;

  rv = ngtcp2_decode_transport_params(
      &params, NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, data,
      data_size);
  if (rv != 0) {
    fprintf(stderr, "ngtcp2_decode_transport_params: %s\n",
            ngtcp2_strerror(rv));
    return -1;
  }

  rv = ngtcp2_conn_set_remote_transport_params(c->conn, &params);
  if (rv != 0) {
    fprintf(stderr, "ngtcp2_conn_set_remote_transport_params: %s\n",
            ngtcp2_strerror(rv));
    return -1;
  }

  return 0;
}

static int tp_send_func(gnutls_session_t session, gnutls_buffer_t extdata) {
  struct client *c = gnutls_session_get_ptr(session);
  ngtcp2_transport_params params;
  unsigned char buf[64];
  ngtcp2_ssize nwrite;
  int rv;

  ngtcp2_conn_get_local_transport_params(c->conn, &params);

  nwrite = ngtcp2_encode_transport_params(
      buf, sizeof(buf), NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, &params);
  if (nwrite < 0) {
    fprintf(stderr, "ngtcp2_encode_transport_params: %s\n",
            ngtcp2_strerror((int)nwrite));
    return -1;
  }

  rv = gnutls_buffer_append_data(extdata, buf, (size_t)nwrite);
  if (rv != 0) {
    fprintf(stderr, "gnutls_buffer_append_data failed: %s\n",
            gnutls_strerror(rv));
    return -1;
  }

  return 0;
}

static const char priority[] =
    "NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:"
    "+CHACHA20-POLY1305:+AES-128-CCM:-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519:"
    "+GROUP-SECP384R1:"
    "+GROUP-SECP521R1:%DISABLE_TLS13_COMPAT_MODE";

static const gnutls_datum_t alpn = {(uint8_t *)ALPN, sizeof(ALPN) - 1};

static int client_gnutls_init(struct client *c) {
  int rv = gnutls_certificate_allocate_credentials(&c->cred);

  if (rv == 0)
    rv = gnutls_certificate_set_x509_system_trust(c->cred);
  if (rv < 0) {
    fprintf(stderr, "cred init failed: %d: %s\n", rv, gnutls_strerror(rv));
    return -1;
  }

  rv = gnutls_init(&c->session, GNUTLS_CLIENT | GNUTLS_ENABLE_EARLY_DATA |
                                    GNUTLS_NO_END_OF_EARLY_DATA);
  if (rv != 0) {
    fprintf(stderr, "gnutls_init: %s\n", gnutls_strerror(rv));
    return -1;
  }

  rv = gnutls_priority_set_direct(c->session, priority, NULL);
  if (rv != 0) {
    fprintf(stderr, "gnutls_priority_set_direct: %s\n", gnutls_strerror(rv));
    return -1;
  }

  gnutls_handshake_set_hook_function(c->session, GNUTLS_HANDSHAKE_ANY,
                                     GNUTLS_HOOK_POST, hook_func);
  gnutls_handshake_set_secret_function(c->session, secret_func);
  gnutls_handshake_set_read_function(c->session, read_func);
  gnutls_alert_set_read_function(c->session, alert_read_func);

  rv = gnutls_session_ext_register(
      c->session, "QUIC Transport Parameters",
      NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS_V1, GNUTLS_EXT_TLS, tp_recv_func,
      tp_send_func, NULL, NULL, NULL,
      GNUTLS_EXT_FLAG_TLS | GNUTLS_EXT_FLAG_CLIENT_HELLO | GNUTLS_EXT_FLAG_EE);

  if (rv != 0) {
    fprintf(stderr, "gnutls_session_ext_register: %s\n", gnutls_strerror(rv));
    return -1;
  }

  gnutls_session_set_ptr(c->session, c);

  rv = gnutls_credentials_set(c->session, GNUTLS_CRD_CERTIFICATE, c->cred);

  if (rv != 0) {
    fprintf(stderr, "gnutls_credentials_set: %s\n", gnutls_strerror(rv));
    return -1;
  }

  gnutls_alpn_set_protocols(c->session, &alpn, 1, GNUTLS_ALPN_MANDATORY);

  if (!numeric_host(REMOTE_HOST)) {
    gnutls_server_name_set(c->session, GNUTLS_NAME_DNS, REMOTE_HOST,
                           strlen(REMOTE_HOST));
  } else {
    gnutls_server_name_set(c->session, GNUTLS_NAME_DNS, "localhost",
                           strlen("localhost"));
  }

  return 0;
}

static void rand_cb(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx) {
  (void)rand_ctx;

  (void)gnutls_rnd(GNUTLS_RND_RANDOM, dest, destlen);
}

static int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                    uint8_t *token, size_t cidlen,
                                    void *user_data) {
  (void)conn;
  (void)user_data;

  if (gnutls_rnd(GNUTLS_RND_RANDOM, cid->data, cidlen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  cid->datalen = cidlen;

  if (gnutls_rnd(GNUTLS_RND_RANDOM, token, NGTCP2_STATELESS_RESET_TOKENLEN) !=
      0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int extend_max_local_streams_bidi(ngtcp2_conn *conn,
                                         uint64_t max_streams,
                                         void *user_data) {
#ifdef MESSAGE
  struct client *c = user_data;
  int rv;
  int64_t stream_id;
  (void)max_streams;

  if (c->stream.stream_id != -1) {
    return 0;
  }

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  if (rv != 0) {
    return 0;
  }

  c->stream.stream_id = stream_id;
  c->stream.data = (const uint8_t *)MESSAGE;
  c->stream.datalen = sizeof(MESSAGE) - 1;

  return 0;
#else  /* !MESSAGE */
  (void)conn;
  (void)max_streams;
  (void)user_data;

  return 0;
#endif /* !MESSAGE */
}

static void log_printf(void *user_data, const char *fmt, ...) {
  va_list ap;
  (void)user_data;

  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);

  fprintf(stderr, "\n");
}

static int client_quic_init(struct client *c,
                            const struct sockaddr *remote_addr,
                            socklen_t remote_addrlen,
                            const struct sockaddr *local_addr,
                            socklen_t local_addrlen) {
  ngtcp2_path path = {
      {
          (struct sockaddr *)local_addr,
          local_addrlen,
      },
      {
          (struct sockaddr *)remote_addr,
          remote_addrlen,
      },
      NULL,
  };
  ngtcp2_callbacks callbacks = {
      ngtcp2_crypto_client_initial_cb,
      NULL, /* recv_client_initial */
      ngtcp2_crypto_recv_crypto_data_cb,
      NULL, /* handshake_completed */
      NULL, /* recv_version_negotiation */
      ngtcp2_crypto_encrypt_cb,
      ngtcp2_crypto_decrypt_cb,
      ngtcp2_crypto_hp_mask_cb,
      NULL, /* recv_stream_data */
      NULL, /* acked_stream_data_offset */
      NULL, /* stream_open */
      NULL, /* stream_close */
      NULL, /* recv_stateless_reset */
      ngtcp2_crypto_recv_retry_cb,
      extend_max_local_streams_bidi,
      NULL, /* extend_max_local_streams_uni */
      rand_cb,
      get_new_connection_id_cb,
      NULL, /* remove_connection_id */
      ngtcp2_crypto_update_key_cb,
      NULL, /* path_validation */
      NULL, /* select_preferred_address */
      NULL, /* stream_reset */
      NULL, /* extend_max_remote_streams_bidi */
      NULL, /* extend_max_remote_streams_uni */
      NULL, /* extend_max_stream_data */
      NULL, /* dcid_status */
      NULL, /* handshake_confirmed */
      NULL, /* recv_new_token */
      ngtcp2_crypto_delete_crypto_aead_ctx_cb,
      ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
      NULL, /* recv_datagram */
      NULL, /* ack_datagram */
      NULL, /* lost_datagram */
      ngtcp2_crypto_get_path_challenge_data_cb,
      NULL, /* stream_stop_sending */
  };
  ngtcp2_cid dcid, scid;
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  int rv;

  dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
  if (gnutls_rnd(GNUTLS_RND_RANDOM, dcid.data, dcid.datalen) != 0) {
    fprintf(stderr, "gnutls_rnd failed\n");
    return -1;
  }

  scid.datalen = 8;
  if (gnutls_rnd(GNUTLS_RND_RANDOM, scid.data, scid.datalen) != 0) {
    fprintf(stderr, "gnutls_rnd failed\n");
    return -1;
  }

  ngtcp2_settings_default(&settings);

  settings.initial_ts = timestamp();
  settings.log_printf = log_printf;

  ngtcp2_transport_params_default(&params);

  params.initial_max_streams_uni = 3;
  params.initial_max_stream_data_bidi_local = 128 * 1024;
  params.initial_max_data = 1024 * 1024;

  rv =
      ngtcp2_conn_client_new(&c->conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1,
                             &callbacks, &settings, &params, NULL, c);
  if (rv != 0) {
    fprintf(stderr, "ngtcp2_conn_client_new: %s\n", ngtcp2_strerror(rv));
    return -1;
  }

  ngtcp2_conn_set_tls_native_handle(c->conn, c->session);

  return 0;
}

static void client_reset_idle_timer(struct client *c) {
  ngtcp2_tstamp expiry = ngtcp2_conn_get_idle_expiry(c->conn);
  ngtcp2_tstamp now = timestamp();

  c->idle_timer.repeat =
      expiry < now ? 1e-9 : (ev_tstamp)(expiry - now) / NGTCP2_SECONDS;

  ev_timer_again(EV_DEFAULT, &c->idle_timer);
}

static int client_read(struct client *c) {
  uint8_t buf[65536];
  struct sockaddr_storage addr;
  struct iovec iov = {buf, sizeof(buf)};
  struct msghdr msg = {0};
  ssize_t nread;
  ngtcp2_path path;
  ngtcp2_pkt_info pi = {0};
  int rv;

  msg.msg_name = &addr;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  for (;;) {
    msg.msg_namelen = sizeof(addr);

    nread = recvmsg(c->fd, &msg, MSG_DONTWAIT);

    if (nread == -1) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        fprintf(stderr, "recvmsg: %s\n", strerror(errno));
      }

      break;
    }

    path.local.addrlen = c->local_addrlen;
    path.local.addr = (struct sockaddr *)&c->local_addr;
    path.remote.addrlen = msg.msg_namelen;
    path.remote.addr = msg.msg_name;

    rv = ngtcp2_conn_read_pkt(c->conn, &path, &pi, buf, (size_t)nread,
                              timestamp());
    if (rv != 0) {
      fprintf(stderr, "ngtcp2_conn_read_pkt: %s\n", ngtcp2_strerror(rv));
      switch (rv) {
      case NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM:
      case NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM:
      case NGTCP2_ERR_TRANSPORT_PARAM:
      case NGTCP2_ERR_PROTO:
        c->last_error = ngtcp2_err_infer_quic_transport_error_code(rv);
        break;
      default:
        if (!c->last_error) {
          c->last_error = ngtcp2_err_infer_quic_transport_error_code(rv);
        }
        break;
      }
      return -1;
    }
  }

  client_reset_idle_timer(c);

  return 0;
}

static int client_send_packet(struct client *c, const uint8_t *data,
                              size_t datalen) {
  struct iovec iov = {(uint8_t *)data, datalen};
  struct msghdr msg = {0};
  ssize_t nwrite;

  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  do {
    nwrite = sendmsg(c->fd, &msg, 0);
  } while (nwrite == -1 && errno == EINTR);

  if (nwrite == -1) {
    fprintf(stderr, "sendmsg: %s\n", strerror(errno));

    return -1;
  }

  return 0;
}

static size_t client_get_message(struct client *c, int64_t *pstream_id,
                                 int *pfin, ngtcp2_vec *datav,
                                 size_t datavcnt) {
  if (datavcnt == 0) {
    return 0;
  }

  if (c->stream.stream_id != -1 && c->stream.nwrite < c->stream.datalen) {
    *pstream_id = c->stream.stream_id;
    *pfin = 1;
    datav->base = (uint8_t *)c->stream.data + c->stream.nwrite;
    datav->len = c->stream.datalen - c->stream.nwrite;
    return 1;
  }

  *pstream_id = -1;
  *pfin = 0;
  datav->base = NULL;
  datav->len = 0;

  return 0;
}

static int client_write_streams(struct client *c) {
  ngtcp2_tstamp ts = timestamp();
  ngtcp2_pkt_info pi;
  ngtcp2_ssize nwrite;
  uint8_t buf[1280];
  ngtcp2_path_storage ps;
  ngtcp2_vec datav;
  size_t datavcnt;
  int64_t stream_id;
  ngtcp2_ssize wdatalen;
  uint32_t flags;
  int fin;

  ngtcp2_path_storage_zero(&ps);

  for (;;) {
    datavcnt = client_get_message(c, &stream_id, &fin, &datav, 1);

    flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
    if (fin) {
      flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
    }

    nwrite = ngtcp2_conn_writev_stream(c->conn, &ps.path, &pi, buf, sizeof(buf),
                                       &wdatalen, flags, stream_id, &datav,
                                       datavcnt, ts);
    if (nwrite < 0) {
      switch (nwrite) {
      case NGTCP2_ERR_WRITE_MORE:
        c->stream.nwrite += (size_t)wdatalen;
        continue;
      default:
        fprintf(stderr, "ngtcp2_conn_writev_stream: %s\n",
                ngtcp2_strerror((int)nwrite));
        c->last_error = ngtcp2_err_infer_quic_transport_error_code((int)nwrite);
        return -1;
      }
    }

    if (nwrite == 0) {
      return 0;
    }

    if (wdatalen > 0) {
      c->stream.nwrite += (size_t)wdatalen;
    }

    if (client_send_packet(c, buf, (size_t)nwrite) != 0) {
      break;
    }
  }

  client_reset_idle_timer(c);

  return 0;
}

static int client_write(struct client *c) {
  ngtcp2_tstamp expiry, now;
  ev_tstamp t;

  if (client_write_streams(c) != 0) {
    return -1;
  }

  expiry = ngtcp2_conn_get_expiry(c->conn);
  now = timestamp();

  t = expiry < now ? 1e-9 : (ev_tstamp)(expiry - now) / NGTCP2_SECONDS;

  c->timer.repeat = t;
  ev_timer_again(EV_DEFAULT, &c->timer);

  return 0;
}

static int client_handle_expiry(struct client *c) {
  int rv = ngtcp2_conn_handle_expiry(c->conn, timestamp());
  if (rv != 0) {
    fprintf(stderr, "ngtcp2_conn_handle_expiry: %s\n", ngtcp2_strerror(rv));
    return -1;
  }

  return 0;
}

static void client_close(struct client *c) {
  ngtcp2_ssize nwrite;
  ngtcp2_pkt_info pi;
  ngtcp2_path_storage ps;
  uint8_t buf[1280];

  if (ngtcp2_conn_is_in_closing_period(c->conn) || !c->last_error) {
    goto fin;
  }

  ngtcp2_path_storage_zero(&ps);

  nwrite = ngtcp2_conn_write_connection_close(c->conn, &ps.path, &pi, buf,
                                              sizeof(buf), c->last_error, NULL,
                                              0, timestamp());
  if (nwrite < 0) {
    fprintf(stderr, "ngtcp2_conn_write_connection_close: %s\n",
            ngtcp2_strerror((int)nwrite));
    goto fin;
  }

  client_send_packet(c, buf, (size_t)nwrite);

fin:
  ev_break(EV_DEFAULT, EVBREAK_ALL);
}

static void read_cb(struct ev_loop *loop, ev_io *w, int revents) {
  struct client *c = w->data;
  (void)loop;
  (void)revents;

  if (client_read(c) != 0) {
    client_close(c);
    return;
  }

  if (client_write(c) != 0) {
    client_close(c);
  }
}

static void timer_cb(struct ev_loop *loop, ev_timer *w, int revents) {
  struct client *c = w->data;
  (void)loop;
  (void)revents;

  if (client_handle_expiry(c) != 0) {
    client_close(c);
    return;
  }

  if (client_write(c) != 0) {
    client_close(c);
  }
}

static void idle_timer_cb(struct ev_loop *loop, ev_timer *w, int revents) {
  (void)loop;
  (void)w;
  (void)revents;

  fprintf(stderr, "idle timeout\n");

  ev_break(EV_DEFAULT, EVBREAK_ALL);
}

static int client_init(struct client *c) {
  struct sockaddr_storage remote_addr, local_addr;
  socklen_t remote_addrlen, local_addrlen = sizeof(local_addr);

  memset(c, 0, sizeof(*c));

  c->fd = create_sock((struct sockaddr *)&remote_addr, &remote_addrlen,
                      REMOTE_HOST, REMOTE_PORT);
  if (c->fd == -1) {
    return -1;
  }

  if (connect_sock((struct sockaddr *)&local_addr, &local_addrlen, c->fd,
                   (struct sockaddr *)&remote_addr, remote_addrlen) != 0) {
    return -1;
  }

  memcpy(&c->local_addr, &local_addr, sizeof(c->local_addr));
  c->local_addrlen = local_addrlen;

  if (client_gnutls_init(c) != 0) {
    return -1;
  }

  if (client_quic_init(c, (struct sockaddr *)&remote_addr, remote_addrlen,
                       (struct sockaddr *)&local_addr, local_addrlen) != 0) {
    return -1;
  }

  c->stream.stream_id = -1;

  ev_io_init(&c->rev, read_cb, c->fd, EV_READ);
  c->rev.data = c;
  ev_io_start(EV_DEFAULT, &c->rev);

  ev_timer_init(&c->timer, timer_cb, 0., 0.);
  c->timer.data = c;

  ev_timer_init(&c->idle_timer, idle_timer_cb, 0., 30.);
  c->idle_timer.data = c;
  ev_timer_again(EV_DEFAULT, &c->timer);

  return 0;
}

static void client_free(struct client *c) {
  ngtcp2_conn_del(c->conn);
  gnutls_deinit(c->session);
  gnutls_certificate_free_credentials(c->cred);
}

int main(void) {
  struct client c;

  if (client_init(&c) != 0) {
    exit(EXIT_FAILURE);
  }

  if (client_write(&c) != 0) {
    exit(EXIT_FAILURE);
  }

  ev_run(EV_DEFAULT, 0);

  client_free(&c);

  return 0;
}
