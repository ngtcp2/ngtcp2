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
#include <cstdlib>
#include <cassert>
#include <cerrno>
#include <iostream>
#include <algorithm>
#include <memory>

#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <openssl/bio.h>
#include <openssl/err.h>

#include "client.h"
#include "network.h"
#include "debug.h"
#include "util.h"
#include "crypto.h"

using namespace ngtcp2;

namespace {
auto randgen = util::make_mt19937();
} // namespace

namespace {
Config config{};
} // namespace

namespace {
int bio_write(BIO *b, const char *buf, int len) {
  int rv;

  BIO_clear_retry_flags(b);

  auto c = static_cast<Client *>(BIO_get_data(b));

  rv = c->write_client_handshake(reinterpret_cast<const uint8_t *>(buf), len);
  if (rv != 0) {
    return -1;
  }

  return len;
}
} // namespace

namespace {
int bio_read(BIO *b, char *buf, int len) {
  BIO_clear_retry_flags(b);

  auto c = static_cast<Client *>(BIO_get_data(b));

  len = c->read_server_handshake(reinterpret_cast<uint8_t *>(buf), len);
  if (len == 0) {
    BIO_set_retry_read(b);
    return -1;
  }

  return len;
}
} // namespace

namespace {
int bio_puts(BIO *b, const char *str) { return bio_write(b, str, strlen(str)); }
} // namespace

namespace {
int bio_gets(BIO *b, char *buf, int len) { return -1; }
} // namespace

namespace {
long bio_ctrl(BIO *b, int cmd, long num, void *ptr) {
  switch (cmd) {
  case BIO_CTRL_FLUSH:
    return 1;
  }

  return 0;
}
} // namespace

namespace {
int bio_create(BIO *b) {
  BIO_set_init(b, 1);
  return 1;
}
} // namespace

namespace {
int bio_destroy(BIO *b) {
  if (b == nullptr) {
    return 0;
  }

  return 1;
}
} // namespace

namespace {
BIO_METHOD *create_bio_method() {
  static auto meth = BIO_meth_new(BIO_TYPE_FD, "bio");
  BIO_meth_set_write(meth, bio_write);
  BIO_meth_set_read(meth, bio_read);
  BIO_meth_set_puts(meth, bio_puts);
  BIO_meth_set_gets(meth, bio_gets);
  BIO_meth_set_ctrl(meth, bio_ctrl);
  BIO_meth_set_create(meth, bio_create);
  BIO_meth_set_destroy(meth, bio_destroy);
  return meth;
}
} // namespace

namespace {
void writecb(struct ev_loop *loop, ev_io *w, int revents) {}
} // namespace

namespace {
void readcb(struct ev_loop *loop, ev_io *w, int revents) {
  auto c = static_cast<Client *>(w->data);

  if (c->on_read() != 0) {
    c->disconnect();
  }
}
} // namespace

namespace {
void stdin_readcb(struct ev_loop *loop, ev_io *w, int revents) {
  auto c = static_cast<Client *>(w->data);

  if (c->send_interactive_input()) {
    c->disconnect();
  }
}
} // namespace

namespace {
void timeoutcb(struct ev_loop *loop, ev_timer *w, int revents) {
  auto c = static_cast<Client *>(w->data);

  debug::print_timestamp();
  std::cerr << "Timeout" << std::endl;

  c->disconnect();
}
} // namespace

namespace {
void retransmitcb(struct ev_loop *loop, ev_timer *w, int revents) {
  auto c = static_cast<Client *>(w->data);

  if (c->on_write() != 0) {
    c->disconnect();
  }
}
} // namespace

Client::Client(struct ev_loop *loop, SSL_CTX *ssl_ctx)
    : remote_addr_{},
      max_pktlen_(0),
      loop_(loop),
      ssl_ctx_(ssl_ctx),
      ssl_(nullptr),
      fd_(-1),
      stdinfd_(-1),
      stream_id_(0),
      ncread_(0),
      nsread_(0),
      conn_(nullptr),
      crypto_ctx_{},
      stream_offset_(0) {
  chandshake_.reserve(128_k);

  ev_io_init(&wev_, writecb, 0, EV_WRITE);
  ev_io_init(&rev_, readcb, 0, EV_READ);
  ev_io_init(&stdinrev_, stdin_readcb, 0, EV_READ);
  wev_.data = this;
  rev_.data = this;
  stdinrev_.data = this;
  ev_timer_init(&timer_, timeoutcb, 0., 30.);
  timer_.data = this;
  ev_timer_init(&rttimer_, retransmitcb, 0., 0.);
  rttimer_.data = this;
}

Client::~Client() { disconnect(); }

void Client::disconnect() {
  ev_timer_stop(loop_, &rttimer_);
  ev_timer_stop(loop_, &timer_);

  ev_io_stop(loop_, &stdinrev_);
  ev_io_stop(loop_, &rev_);
  ev_io_stop(loop_, &wev_);

  if (conn_) {
    ngtcp2_conn_del(conn_);
    conn_ = nullptr;
  }

  if (ssl_) {
    SSL_free(ssl_);
    ssl_ = nullptr;
  }

  if (fd_ != -1) {
    close(fd_);
    fd_ = -1;
  }
}

namespace {
ssize_t send_client_initial(ngtcp2_conn *conn, uint32_t flags,
                            uint64_t *ppkt_num, const uint8_t **pdest,
                            void *user_data) {
  auto c = static_cast<Client *>(user_data);

  if (c->tls_handshake() != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  *ppkt_num = std::uniform_int_distribution<uint64_t>(
      0, std::numeric_limits<int32_t>::max())(randgen);

  auto len = c->read_client_handshake(pdest);

  return len;
}
} // namespace

namespace {
ssize_t send_client_cleartext(ngtcp2_conn *conn, uint32_t flags,
                              const uint8_t **pdest, void *user_data) {
  auto c = static_cast<Client *>(user_data);

  auto len = c->read_client_handshake(pdest);

  return len;
}
} // namespace

namespace {
int recv_handshake_data(ngtcp2_conn *conn, const uint8_t *data, size_t datalen,
                        void *user_data) {
  int rv;

  auto c = static_cast<Client *>(user_data);

  c->write_server_handshake(data, datalen);

  if (c->tls_handshake() != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

namespace {
int recv_stream_data(ngtcp2_conn *conn, uint32_t stream_id, uint8_t fin,
                     const uint8_t *data, size_t datalen, void *user_data,
                     void *stream_user_data) {
  debug::print_stream_data(stream_id, data, datalen);

  return 0;
}
} // namespace

namespace {
int handshake_completed(ngtcp2_conn *conn, void *user_data) {
  auto c = static_cast<Client *>(user_data);

  debug::handshake_completed(conn, user_data);

  if (c->setup_crypto_context() != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  if (c->start_interactive_input() != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

namespace {
ssize_t do_encrypt(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                   const uint8_t *plaintext, size_t plaintextlen,
                   const uint8_t *key, size_t keylen, const uint8_t *nonce,
                   size_t noncelen, const uint8_t *ad, size_t adlen,
                   void *user_data) {
  auto c = static_cast<Client *>(user_data);

  auto nwrite = c->encrypt_data(dest, destlen, plaintext, plaintextlen, key,
                                keylen, nonce, noncelen, ad, adlen);
  if (nwrite < 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return nwrite;
}
} // namespace

namespace {
ssize_t do_decrypt(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                   const uint8_t *ciphertext, size_t ciphertextlen,
                   const uint8_t *key, size_t keylen, const uint8_t *nonce,
                   size_t noncelen, const uint8_t *ad, size_t adlen,
                   void *user_data) {
  auto c = static_cast<Client *>(user_data);

  auto nwrite = c->decrypt_data(dest, destlen, ciphertext, ciphertextlen, key,
                                keylen, nonce, noncelen, ad, adlen);
  if (nwrite < 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return nwrite;
}
} // namespace

int Client::init(int fd, const Address &remote_addr, const char *addr,
                 int stdinfd) {
  int rv;

  remote_addr_ = remote_addr;

  switch (remote_addr_.su.storage.ss_family) {
  case AF_INET:
    max_pktlen_ = NGTCP2_MAX_PKTLEN_IPV4;
    break;
  case AF_INET6:
    max_pktlen_ = NGTCP2_MAX_PKTLEN_IPV6;
    break;
  default:
    return -1;
  }

  fd_ = fd;
  stdinfd_ = stdinfd;
  ssl_ = SSL_new(ssl_ctx_);
  auto bio = BIO_new(create_bio_method());
  BIO_set_data(bio, this);
  SSL_set_bio(ssl_, bio, bio);
  SSL_set_app_data(ssl_, this);
  SSL_set_connect_state(ssl_);

  if (util::numeric_host(addr)) {
    // If remote host is numeric address, just send "localhost" as SNI
    // for now.
    SSL_set_tlsext_host_name(ssl_, "localhost");
  } else {
    SSL_set_tlsext_host_name(ssl_, addr);
  }

  auto callbacks = ngtcp2_conn_callbacks{
      send_client_initial,
      send_client_cleartext,
      nullptr,
      recv_handshake_data,
      debug::send_pkt,
      debug::send_frame,
      debug::recv_pkt,
      debug::recv_frame,
      handshake_completed,
      debug::recv_version_negotiation,
      do_encrypt,
      do_decrypt,
      recv_stream_data,
  };

  auto conn_id = std::uniform_int_distribution<uint64_t>(
      0, std::numeric_limits<uint64_t>::max())(randgen);

  ngtcp2_settings settings;
  settings.max_stream_data = 128_k;
  settings.max_data = 128;
  settings.max_stream_id = 0;
  settings.idle_timeout = 5;
  settings.omit_connection_id = 0;
  settings.max_packet_size = NGTCP2_MAX_PKT_SIZE;

  rv = ngtcp2_conn_client_new(&conn_, conn_id, NGTCP2_PROTO_VERSION, &callbacks,
                              &settings, this);
  if (rv != 0) {
    std::cerr << "ngtcp2_conn_client_new: " << ngtcp2_strerror(rv) << std::endl;
    return -1;
  }

  ev_io_set(&wev_, fd_, EV_WRITE);
  ev_io_set(&rev_, fd_, EV_READ);

  ev_io_start(loop_, &rev_);
  ev_timer_again(loop_, &timer_);

  return 0;
}

int Client::tls_handshake() {
  ERR_clear_error();

  auto rv = SSL_do_handshake(ssl_);
  if (rv <= 0) {
    auto err = SSL_get_error(ssl_, rv);
    switch (err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      return 0;
    case SSL_ERROR_SSL:
      std::cerr << "TLS handshake error: "
                << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
      return -1;
    default:
      std::cerr << "TLS handshake error: " << err << std::endl;
      return -1;
    }
  }

  ngtcp2_conn_handshake_completed(conn_);

  const unsigned char *alpn = nullptr;
  unsigned int alpnlen;

  SSL_get0_alpn_selected(ssl_, &alpn, &alpnlen);
  if (alpn) {
    debug::print_timestamp();
    std::cerr << "Negotiated ALPN ";
    std::cerr.write(reinterpret_cast<const char *>(alpn), alpnlen);
    std::cerr << std::endl;
  }

  return 0;
}

int Client::feed_data(uint8_t *data, size_t datalen) {
  int rv;

  rv = ngtcp2_conn_recv(conn_, data, datalen, util::timestamp());
  if (rv != 0) {
    std::cerr << "ngtcp2_conn_recv: " << ngtcp2_strerror(rv) << std::endl;
    return -1;
  }

  return 0;
}

int Client::on_read() {
  std::array<uint8_t, 65536> buf;

  for (;;) {
    auto nread =
        recvfrom(fd_, buf.data(), buf.size(), MSG_DONTWAIT, nullptr, nullptr);

    if (nread == -1) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        std::cerr << "recvfrom: " << strerror(errno) << std::endl;
      }
      break;
    }

    if (debug::packet_lost(config.rx_loss_prob)) {
      std::cerr << "** Simulated incoming packet loss **" << std::endl;
      break;
    }

    if (feed_data(buf.data(), nread) != 0) {
      return -1;
    }
  }

  ev_timer_again(loop_, &timer_);

  return on_write();
}

int Client::on_write() {
  std::array<uint8_t, NGTCP2_MAX_PKTLEN_IPV4> buf;
  assert(buf.size() >= max_pktlen_);

  for (;;) {
    auto n =
        ngtcp2_conn_send(conn_, buf.data(), max_pktlen_, util::timestamp());
    if (n < 0) {
      std::cerr << "ngtcp2_conn_send: " << ngtcp2_strerror(n) << std::endl;
      return -1;
    }
    if (n == 0) {
      schedule_retransmit();
      return 0;
    }

    if (debug::packet_lost(config.tx_loss_prob)) {
      std::cerr << "** Simulated outgoing packet loss **" << std::endl;
      continue;
    }

    auto nwrite = write(fd_, buf.data(), n);
    if (nwrite == -1) {
      std::cerr << "write: " << strerror(errno) << std::endl;
      return -1;
    }
  }
}

int Client::on_write_stream(uint32_t stream_id, uint8_t fin,
                            const uint8_t *data, size_t datalen) {
  std::array<uint8_t, NGTCP2_MAX_PKTLEN_IPV4> buf;
  assert(buf.size() >= max_pktlen_);
  size_t ndatalen;

  for (;;) {
    auto n = ngtcp2_conn_write_stream(conn_, buf.data(), max_pktlen_, &ndatalen,
                                      stream_id, fin, data, datalen,
                                      util::timestamp());
    if (n < 0) {
      std::cerr << "ngtcp2_conn_write_stream: " << ngtcp2_strerror(n)
                << std::endl;
      return -1;
    }

    data += ndatalen;
    datalen -= ndatalen;

    if (debug::packet_lost(config.tx_loss_prob)) {
      std::cerr << "** Simulated outgoing packet loss **" << std::endl;
      if (datalen == 0) {
        break;
      }
      continue;
    }

    auto nwrite = write(fd_, buf.data(), n);
    if (nwrite == -1) {
      std::cerr << "write: " << strerror(errno) << std::endl;
      return -1;
    }

    if (datalen == 0) {
      break;
    }
  }

  if (datalen == 0) {
    schedule_retransmit();
    return 0;
  }
}

void Client::schedule_retransmit() {
  auto expiry = ngtcp2_conn_earliest_expiry(conn_);
  if (expiry == 0) {
    return;
  }

  ev_tstamp t;
  auto now = util::timestamp();
  if (now >= expiry) {
    t = 0.;
  } else {
    t = static_cast<ev_tstamp>(expiry - now) / 1000000;
  }
  ev_timer_stop(loop_, &rttimer_);
  ev_timer_set(&rttimer_, t, 0.);
  ev_timer_start(loop_, &rttimer_);
}

int Client::write_client_handshake(const uint8_t *data, size_t datalen) {
  if (chandshake_.capacity() <= chandshake_.size() + datalen) {
    return -1;
  }
  std::copy_n(data, datalen, std::back_inserter(chandshake_));
  return 0;
}

size_t Client::read_client_handshake(const uint8_t **pdest) {
  auto n = chandshake_.size() - ncread_;
  *pdest = chandshake_.data() + ncread_;
  ncread_ = chandshake_.size();
  return n;
}

size_t Client::read_server_handshake(uint8_t *buf, size_t buflen) {
  auto n = std::min(buflen, shandshake_.size() - nsread_);
  std::copy_n(std::begin(shandshake_) + nsread_, n, buf);
  nsread_ += n;
  return n;
}

void Client::write_server_handshake(const uint8_t *data, size_t datalen) {
  std::copy_n(data, datalen, std::back_inserter(shandshake_));
}

int Client::setup_crypto_context() {
  int rv;

  rv = crypto::negotiated_prf(crypto_ctx_, ssl_);
  if (rv != 0) {
    return -1;
  }
  rv = crypto::negotiated_aead(crypto_ctx_, ssl_);
  if (rv != 0) {
    return -1;
  }

  auto length = EVP_MD_size(crypto_ctx_.prf);

  crypto_ctx_.secretlen = length;

  rv = crypto::export_client_secret(crypto_ctx_.tx_secret.data(),
                                    crypto_ctx_.secretlen, ssl_);
  if (rv != 0) {
    return -1;
  }

  std::array<uint8_t, 64> key{}, iv{};

  auto keylen = crypto::derive_packet_protection_key(
      key.data(), key.size(), crypto_ctx_.tx_secret.data(),
      crypto_ctx_.secretlen, crypto_ctx_);
  if (rv != 0) {
    return -1;
  }

  auto ivlen = crypto::derive_packet_protection_iv(
      iv.data(), iv.size(), crypto_ctx_.tx_secret.data(), crypto_ctx_.secretlen,
      crypto_ctx_);
  if (rv != 0) {
    return -1;
  }

  ngtcp2_conn_update_tx_keys(conn_, key.data(), keylen, iv.data(), ivlen);

  rv = crypto::export_server_secret(crypto_ctx_.rx_secret.data(),
                                    crypto_ctx_.secretlen, ssl_);
  if (rv != 0) {
    return -1;
  }

  keylen = crypto::derive_packet_protection_key(
      key.data(), key.size(), crypto_ctx_.rx_secret.data(),
      crypto_ctx_.secretlen, crypto_ctx_);
  if (rv != 0) {
    return -1;
  }

  ivlen = crypto::derive_packet_protection_iv(
      iv.data(), iv.size(), crypto_ctx_.rx_secret.data(), crypto_ctx_.secretlen,
      crypto_ctx_);
  if (rv != 0) {
    return -1;
  }

  ngtcp2_conn_update_rx_keys(conn_, key.data(), keylen, iv.data(), ivlen);

  ngtcp2_conn_set_aead_overhead(conn_, crypto::aead_max_overhead(crypto_ctx_));

  return 0;
}

ssize_t Client::encrypt_data(uint8_t *dest, size_t destlen,
                             const uint8_t *plaintext, size_t plaintextlen,
                             const uint8_t *key, size_t keylen,
                             const uint8_t *nonce, size_t noncelen,
                             const uint8_t *ad, size_t adlen) {
  return crypto::encrypt(dest, destlen, plaintext, plaintextlen, crypto_ctx_,
                         key, keylen, nonce, noncelen, ad, adlen);
}

ssize_t Client::decrypt_data(uint8_t *dest, size_t destlen,
                             const uint8_t *ciphertext, size_t ciphertextlen,
                             const uint8_t *key, size_t keylen,
                             const uint8_t *nonce, size_t noncelen,
                             const uint8_t *ad, size_t adlen) {
  return crypto::decrypt(dest, destlen, ciphertext, ciphertextlen, crypto_ctx_,
                         key, keylen, nonce, noncelen, ad, adlen);
}

ngtcp2_conn *Client::conn() const { return conn_; }

int Client::start_interactive_input() {
  int rv;
  if (stdinfd_ == -1) {
    return 0;
  }

  std::cerr << "Interactive session started.  Hit Ctrl-D to end the session."
            << std::endl;

  ev_io_set(&stdinrev_, stdinfd_, EV_READ);
  ev_io_start(loop_, &stdinrev_);

  uint32_t stream_id;
  rv = ngtcp2_conn_open_stream(conn_, &stream_id, nullptr);
  if (rv != 0) {
    std::cerr << "ngtcp2_conn_open_stream: " << ngtcp2_strerror(rv)
              << std::endl;
    return -1;
  }

  stream_id_ = stream_id;

  std::cerr << "The stream " << stream_id_ << " has opened." << std::endl;

  return 0;
}

int Client::send_interactive_input() {
  int rv;
  ssize_t nread;

  auto p = streambuf_.data() + stream_offset_;
  auto plen = streambuf_.size() - stream_offset_;

  while ((nread = read(stdinfd_, p, plen)) == -1 && errno == EINTR)
    ;
  if (nread == -1) {
    return stop_interactive_input();
  }
  if (nread == 0) {
    return stop_interactive_input();
  }

  stream_offset_ += nread;

  rv = on_write_stream(stream_id_, 0, p, nread);
  if (rv != 0) {
    return -1;
  }

  return on_write();
}

int Client::stop_interactive_input() {
  int rv;
  rv = on_write_stream(stream_id_, 1, nullptr, 0);
  if (rv != 0) {
    return -1;
  }

  ev_io_stop(loop_, &stdinrev_);

  std::cerr << "Interactive session has ended." << std::endl;

  return on_write();
}

namespace {
int transport_params_add_cb(SSL *ssl, unsigned int ext_type,
                            unsigned int content, const unsigned char **out,
                            size_t *outlen, X509 *x, size_t chainidx, int *al,
                            void *add_arg) {
  int rv;
  auto c = static_cast<Client *>(SSL_get_app_data(ssl));
  auto conn = c->conn();

  ngtcp2_transport_params params;

  rv = ngtcp2_conn_get_local_transport_params(
      conn, &params, NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO);
  if (rv != 0) {
    return -1;
  }

  constexpr size_t bufsize = 64;
  auto buf = std::make_unique<uint8_t[]>(bufsize);

  auto nwrite = ngtcp2_encode_transport_params(
      buf.get(), bufsize, NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, &params);
  if (nwrite < 0) {
    std::cerr << "ngtcp2_encode_transport_params: " << ngtcp2_strerror(nwrite)
              << std::endl;
    // TODO Set *al
    return -1;
  }

  *out = buf.release();
  *outlen = static_cast<size_t>(nwrite);

  return 1;
}
} // namespace

namespace {
void transport_params_free_cb(SSL *ssl, unsigned int ext_type,
                              unsigned int context, const unsigned char *out,
                              void *add_arg) {
  delete[] const_cast<unsigned char *>(out);
}
} // namespace

namespace {
int transport_params_parse_cb(SSL *ssl, unsigned int ext_type,
                              unsigned int context, const unsigned char *in,
                              size_t inlen, X509 *x, size_t chainidx, int *al,
                              void *parse_arg) {
  if (context != SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS) {
    // TODO Handle transport parameter in NewSessionTicket.
    return 1;
  }

  auto c = static_cast<Client *>(SSL_get_app_data(ssl));
  auto conn = c->conn();

  int rv;

  ngtcp2_transport_params params;

  rv = ngtcp2_decode_transport_params(
      &params, NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, in, inlen);
  if (rv != 0) {
    std::cerr << "ngtcp2_decode_transport_params: " << ngtcp2_strerror(rv)
              << std::endl;
    // TODO Just continue for now
    return 1;
  }

  debug::print_timestamp();
  std::cerr << "TransportParameter received in EncryptedExtensions"
            << std::endl;
  debug::print_transport_params(
      &params, NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS);

  rv = ngtcp2_conn_set_remote_transport_params(
      conn, NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, &params);
  if (rv != 0) {
    // TODO Set *al
    return -1;
  }

  return 1;
}
} // namespace

namespace {
SSL_CTX *create_ssl_ctx() {
  auto ssl_ctx = SSL_CTX_new(TLS_method());

  SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);

  SSL_CTX_set_default_verify_paths(ssl_ctx);

  SSL_CTX_set1_curves_list(ssl_ctx, "P-256");

  SSL_CTX_set_alpn_protos(ssl_ctx,
                          reinterpret_cast<const uint8_t *>(NGTCP2_ALPN),
                          str_size(NGTCP2_ALPN));

  if (SSL_CTX_add_custom_ext(
          ssl_ctx, NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS,
          SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS |
              SSL_EXT_TLS1_3_NEW_SESSION_TICKET | SSL_EXT_IGNORE_ON_RESUMPTION,
          transport_params_add_cb, transport_params_free_cb, nullptr,
          transport_params_parse_cb, nullptr) != 1) {
    std::cerr << "SSL_CTX_add_custom_ext(NGTCP2_TLSEXT_QUIC_TRANSPORT_"
                 "PARAMETERS) failed: "
              << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
    exit(EXIT_FAILURE);
  }

  return ssl_ctx;
}
} // namespace

namespace {
int create_sock(Address &remote_addr, const char *addr, const char *port) {
  addrinfo hints{};
  addrinfo *res, *rp;
  int rv;

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  rv = getaddrinfo(addr, port, &hints, &res);
  if (rv != 0) {
    std::cerr << "getaddrinfo: " << gai_strerror(rv) << std::endl;
    return -1;
  }

  auto res_d = defer(freeaddrinfo, res);

  int fd = -1;

  for (rp = res; rp; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd == -1) {
      continue;
    }

    if (connect(fd, rp->ai_addr, rp->ai_addrlen) == -1) {
      goto next;
    }

    break;

  next:
    close(fd);
  }

  if (!rp) {
    std::cerr << "Could not connect" << std::endl;
    return -1;
  }

  auto val = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val,
                 static_cast<socklen_t>(sizeof(val))) == -1) {
    return -1;
  }

  remote_addr.len = rp->ai_addrlen;
  memcpy(&remote_addr.su, rp->ai_addr, rp->ai_addrlen);

  return fd;
}

} // namespace

namespace {
int run(Client &c, const char *addr, const char *port) {
  int rv;
  Address remote_addr;

  auto fd = create_sock(remote_addr, addr, port);
  if (fd == -1) {
    return -1;
  }

  if (c.init(fd, remote_addr, addr, config.fd) != 0) {
    return -1;
  }

  c.on_write();

  ev_run(EV_DEFAULT, 0);

  return 0;
}
} // namespace

namespace {
void print_usage() {
  std::cerr << "Usage: client [OPTIONS] <ADDR> <PORT>" << std::endl;
}
} // namespace

namespace {
void print_help() {
  print_usage();

  std::cout << R"(
  <ADDR>      Remote server address
  <PORT>      Remote server port
Options:
  -t, --tx-loss=<P>
              The probability of losing outgoing packets.  <P> must be
              [0.0, 1.0],  inclusive.  0.0 means no  packet loss.  1.0
              means 100% packet loss.
  -r, --rx-loss=<P>
              The probability of losing incoming packets.  <P> must be
              [0.0, 1.0],  inclusive.  0.0 means no  packet loss.  1.0
              means 100% packet loss.
  -i, --interactive
              Read input from stdin, and send them as STREAM data.
  -h, --help  Display this help and exit.
)";
}
} // namespace

int main(int argc, char **argv) {
  config.tx_loss_prob = 0.;
  config.rx_loss_prob = 0.;
  config.fd = -1;

  for (;;) {
    static int flag = 0;
    constexpr static option long_opts[] = {
        {"help", no_argument, nullptr, 'h'},
        {"tx-loss", required_argument, nullptr, 't'},
        {"rx-loss", required_argument, nullptr, 'r'},
        {"interactive", no_argument, nullptr, 'i'},
        {nullptr, 0, nullptr, 0},
    };

    auto optidx = 0;
    auto c = getopt_long(argc, argv, "hir:t:", long_opts, &optidx);
    if (c == -1) {
      break;
    }
    switch (c) {
    case 'h':
      // --help
      print_help();
      exit(EXIT_SUCCESS);
    case 'r':
      // --rx-loss
      config.rx_loss_prob = strtod(optarg, nullptr);
      break;
    case 't':
      // --tx-loss
      config.tx_loss_prob = strtod(optarg, nullptr);
      break;
    case 'i':
      // --interactive
      config.fd = fileno(stdin);
      break;
    case '?':
      print_usage();
      exit(EXIT_FAILURE);
    default:
      break;
    };
  }

  if (argc - optind < 2) {
    std::cerr << "Too few arguments" << std::endl;
    print_usage();
    exit(EXIT_FAILURE);
  }

  auto addr = argv[optind++];
  auto port = argv[optind++];

  auto ssl_ctx = create_ssl_ctx();
  auto ssl_ctx_d = defer(SSL_CTX_free, ssl_ctx);

  debug::reset_timestamp();

  if (isatty(STDOUT_FILENO)) {
    debug::set_color_output(true);
  }

  Client c(EV_DEFAULT, ssl_ctx);

  if (run(c, addr, port) != 0) {
    exit(EXIT_FAILURE);
  }
}
