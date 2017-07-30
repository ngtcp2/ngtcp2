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

#include "server.h"
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

  auto h = static_cast<Handler *>(BIO_get_data(b));

  rv = h->write_server_handshake(reinterpret_cast<const uint8_t *>(buf), len);
  if (rv != 0) {
    return -1;
  }

  return len;
}
} // namespace

namespace {
int bio_read(BIO *b, char *buf, int len) {
  BIO_clear_retry_flags(b);

  auto h = static_cast<Handler *>(BIO_get_data(b));

  len = h->read_client_handshake(reinterpret_cast<uint8_t *>(buf), len);
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

Stream::Stream(uint32_t stream_id)
    : stream_id(stream_id), streambuf_idx(0), should_send_fin(false) {}

namespace {
void timeoutcb(struct ev_loop *loop, ev_timer *w, int revents) {
  auto h = static_cast<Handler *>(w->data);

  debug::print_timestamp();
  std::cerr << "Timeout" << std::endl;

  auto server = h->server();
  server->remove(h);
}
} // namespace

namespace {
void retransmitcb(struct ev_loop *loop, ev_timer *w, int revents) {
  auto h = static_cast<Handler *>(w->data);

  if (h->on_write() != 0) {
    auto server = h->server();
    server->remove(h);
  }
}
} // namespace

Handler::Handler(struct ev_loop *loop, SSL_CTX *ssl_ctx, Server *server)
    : remote_addr_{},
      max_pktlen_(0),
      loop_(loop),
      ssl_ctx_(ssl_ctx),
      ssl_(nullptr),
      server_(server),
      fd_(-1),
      ncread_(0),
      shandshake_idx_(0),
      conn_(nullptr),
      crypto_ctx_{},
      conn_id_(std::uniform_int_distribution<uint64_t>(
          0, std::numeric_limits<uint64_t>::max())(randgen)) {
  ev_timer_init(&timer_, timeoutcb, 0., 30.);
  timer_.data = this;
  ev_timer_init(&rttimer_, retransmitcb, 0., 0.);
  rttimer_.data = this;
}

Handler::~Handler() {
  debug::print_timestamp();
  std::cerr << "Closing QUIC connection" << std::endl;

  ev_timer_stop(loop_, &rttimer_);
  ev_timer_stop(loop_, &timer_);

  if (conn_) {
    ngtcp2_conn_del(conn_);
  }

  if (ssl_) {
    SSL_free(ssl_);
  }
}

namespace {
ssize_t send_server_cleartext(ngtcp2_conn *conn, uint32_t flags,
                              uint64_t *ppkt_num, const uint8_t **pdest,
                              void *user_data) {
  auto h = static_cast<Handler *>(user_data);

  if (ppkt_num) {
    *ppkt_num = std::uniform_int_distribution<uint64_t>(
        0, std::numeric_limits<int32_t>::max())(randgen);
  }

  auto len = h->read_server_handshake(pdest);

  // If Client Initial does not have complete ClientHello, then drop
  // connection.
  if (ppkt_num && len == 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return len;
}
} // namespace

namespace {
int handshake_completed(ngtcp2_conn *conn, void *user_data) {
  auto h = static_cast<Handler *>(user_data);

  debug::handshake_completed(conn, user_data);

  if (h->setup_crypto_context() != 0) {
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
  auto h = static_cast<Handler *>(user_data);

  auto nwrite = h->encrypt_data(dest, destlen, plaintext, plaintextlen, key,
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
  auto h = static_cast<Handler *>(user_data);

  auto nwrite = h->decrypt_data(dest, destlen, ciphertext, ciphertextlen, key,
                                keylen, nonce, noncelen, ad, adlen);
  if (nwrite < 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return nwrite;
}
} // namespace

namespace {
int recv_handshake_data(ngtcp2_conn *conn, const uint8_t *data, size_t datalen,
                        void *user_data) {
  auto h = static_cast<Handler *>(user_data);

  h->write_client_handshake(data, datalen);

  if (h->tls_handshake() != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

namespace {
int recv_stream_data(ngtcp2_conn *conn, uint32_t stream_id, uint8_t fin,
                     const uint8_t *data, size_t datalen, void *user_data,
                     void *stream_user_data) {
  auto h = static_cast<Handler *>(user_data);

  if (h->recv_stream_data(stream_id, fin, data, datalen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

namespace {
int acked_stream_data_offset(ngtcp2_conn *conn, uint32_t stream_id,
                             uint64_t offset, size_t datalen, void *user_data,
                             void *stream_user_data) {
  auto h = static_cast<Handler *>(user_data);
  h->remove_tx_stream_data(stream_id, offset, datalen);
  return 0;
}
} // namespace

int Handler::init(int fd, const sockaddr *sa, socklen_t salen) {
  int rv;

  remote_addr_.len = salen;
  memcpy(&remote_addr_.su.sa, sa, salen);

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
  ssl_ = SSL_new(ssl_ctx_);
  auto bio = BIO_new(create_bio_method());
  BIO_set_data(bio, this);
  SSL_set_bio(ssl_, bio, bio);
  SSL_set_app_data(ssl_, this);
  SSL_set_accept_state(ssl_);

  auto callbacks = ngtcp2_conn_callbacks{
      nullptr,
      nullptr,
      send_server_cleartext,
      recv_handshake_data,
      debug::send_pkt,
      debug::send_frame,
      debug::recv_pkt,
      debug::recv_frame,
      handshake_completed,
      nullptr,
      do_encrypt,
      do_decrypt,
      ::recv_stream_data,
      acked_stream_data_offset,
  };

  ngtcp2_settings settings;

  settings.max_stream_data = 128_k;
  settings.max_data = 128;
  // TODO Just allow stream ID = 1 to exchange encrypted data for now.
  settings.max_stream_id = 1;
  settings.idle_timeout = 5;
  settings.omit_connection_id = 0;
  settings.max_packet_size = NGTCP2_MAX_PKT_SIZE;

  rv = ngtcp2_conn_server_new(&conn_, conn_id_, NGTCP2_PROTO_VERSION,
                              &callbacks, &settings, this);
  if (rv != 0) {
    std::cerr << "ngtcp2_conn_server_new: " << ngtcp2_strerror(rv) << std::endl;
    return -1;
  }

  ev_timer_again(loop_, &timer_);

  return 0;
}

int Handler::tls_handshake() {
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

  // SSL_do_handshake returns 1 if TLS handshake has completed.  With
  // boringSSL, it may return 1 if we have 0-RTT early data.  This is
  // a problem, but for First Implementation draft, 0-RTT early data
  // is out of interest.
  ngtcp2_conn_handshake_completed(conn_);

  return 0;
}

int Handler::write_server_handshake(const uint8_t *data, size_t datalen) {
  shandshake_.emplace_back(data, data + datalen);
  return 0;
}

size_t Handler::read_server_handshake(const uint8_t **pdest) {
  if (shandshake_idx_ == shandshake_.size()) {
    return 0;
  }
  const auto &v = shandshake_[shandshake_idx_++];
  *pdest = v.data();
  return v.size();
}

size_t Handler::read_client_handshake(uint8_t *buf, size_t buflen) {
  auto n = std::min(buflen, chandshake_.size() - ncread_);
  std::copy_n(std::begin(chandshake_) + ncread_, n, buf);
  ncread_ += n;
  return n;
}

void Handler::write_client_handshake(const uint8_t *data, size_t datalen) {
  std::copy_n(data, datalen, std::back_inserter(chandshake_));
}

int Handler::setup_crypto_context() {
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

  rv = crypto::export_server_secret(crypto_ctx_.tx_secret.data(),
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

  rv = crypto::export_client_secret(crypto_ctx_.rx_secret.data(),
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

ssize_t Handler::encrypt_data(uint8_t *dest, size_t destlen,
                              const uint8_t *plaintext, size_t plaintextlen,
                              const uint8_t *key, size_t keylen,
                              const uint8_t *nonce, size_t noncelen,
                              const uint8_t *ad, size_t adlen) {
  return crypto::encrypt(dest, destlen, plaintext, plaintextlen, crypto_ctx_,
                         key, keylen, nonce, noncelen, ad, adlen);
}

ssize_t Handler::decrypt_data(uint8_t *dest, size_t destlen,
                              const uint8_t *ciphertext, size_t ciphertextlen,
                              const uint8_t *key, size_t keylen,
                              const uint8_t *nonce, size_t noncelen,
                              const uint8_t *ad, size_t adlen) {
  return crypto::decrypt(dest, destlen, ciphertext, ciphertextlen, crypto_ctx_,
                         key, keylen, nonce, noncelen, ad, adlen);
}

int Handler::feed_data(uint8_t *data, size_t datalen) {
  int rv;

  rv = ngtcp2_conn_recv(conn_, data, datalen, util::timestamp());
  if (rv != 0) {
    std::cerr << "ngtcp2_conn_recv: " << ngtcp2_strerror(rv) << std::endl;
    return -1;
  }

  return 0;
}

int Handler::on_read(uint8_t *data, size_t datalen) {
  int rv;

  if (feed_data(data, datalen) != 0) {
    return -1;
  }

  ev_timer_again(loop_, &timer_);

  for (auto &p : streams_) {
    auto &stream = p.second;
    rv = on_write_stream(stream);
    if (rv != 0) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
  }

  return on_write();
}

int Handler::on_write() {
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

    auto nwrite =
        sendto(fd_, buf.data(), n, 0, &remote_addr_.su.sa, remote_addr_.len);
    if (nwrite == -1) {
      std::cerr << "sendto: " << strerror(errno) << std::endl;
      return -1;
    }
  }
}

int Handler::on_write_stream(Stream &stream) {
  std::array<uint8_t, NGTCP2_MAX_PKTLEN_IPV4> buf;
  size_t ndatalen;

  assert(buf.size() >= max_pktlen_);

  if (stream.streambuf_idx == stream.streambuf.size()) {
    if (stream.should_send_fin) {
      stream.should_send_fin = false;
      if (write_stream_data(stream, 1, nullptr, 0) != 0) {
        return -1;
      }
    }
    return 0;
  }

  for (auto it = std::begin(stream.streambuf) + stream.streambuf_idx;
       it != std::end(stream.streambuf); ++it) {
    const auto &v = *it;
    auto fin = stream.should_send_fin &&
               stream.streambuf_idx == stream.streambuf.size() - 1;
    if (fin) {
      stream.should_send_fin = false;
    }
    if (write_stream_data(stream, fin, v.data(), v.size()) != 0) {
      return -1;
    }
    ++stream.streambuf_idx;
  }

  schedule_retransmit();

  return 0;
}

int Handler::write_stream_data(Stream &stream, int fin, const uint8_t *data,
                               size_t datalen) {
  std::array<uint8_t, NGTCP2_MAX_PKTLEN_IPV4> buf;
  size_t ndatalen;

  assert(buf.size() >= max_pktlen_);

  for (; datalen || fin;) {
    auto n = ngtcp2_conn_write_stream(conn_, buf.data(), max_pktlen_, &ndatalen,
                                      stream.stream_id, fin && datalen == 0,
                                      data, datalen, util::timestamp());
    if (n < 0) {
      std::cerr << "ngtcp2_conn_write_stream: " << ngtcp2_strerror(n)
                << std::endl;
      return -1;
    }

    data += ndatalen;
    datalen -= ndatalen;

    if (debug::packet_lost(config.tx_loss_prob)) {
      std::cerr << "** Simulated outgoing packet loss **" << std::endl;
      if (fin && ndatalen == 0) {
        return 0;
      }
      continue;
    }

    auto nwrite =
        sendto(fd_, buf.data(), n, 0, &remote_addr_.su.sa, remote_addr_.len);
    if (nwrite == -1) {
      std::cerr << "sendto: " << strerror(errno) << std::endl;
      return -1;
    }
    if (fin && ndatalen == 0) {
      return 0;
    }
  }

  return 0;
}

void Handler::schedule_retransmit() {
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

int Handler::recv_stream_data(uint32_t stream_id, uint8_t fin,
                              const uint8_t *data, size_t datalen) {
  int rv;

  debug::print_stream_data(stream_id, data, datalen);

  auto it = streams_.find(stream_id);
  if (it == std::end(streams_)) {
    it = streams_.emplace(stream_id, Stream{stream_id}).first;
  }

  auto &stream = (*it).second;

  size_t len = 0;
  if (datalen > 0) {
    static constexpr uint8_t start_tag[] = "<blink>";
    static constexpr uint8_t end_tag[] = "</blink>";

    auto v = std::vector<uint8_t>();
    v.resize(str_size(start_tag) + datalen + str_size(end_tag));

    auto p = v.data();

    p = std::copy_n(start_tag, str_size(start_tag), p);
    p = std::copy_n(data, datalen, p);
    p = std::copy_n(end_tag, str_size(end_tag), p);

    stream.streambuf.emplace_back(std::move(v));
  }

  stream.should_send_fin = fin != 0;

  return 0;
}

uint64_t Handler::conn_id() const { return conn_id_; }

Server *Handler::server() const { return server_; }

const Address &Handler::remote_addr() const { return remote_addr_; }

ngtcp2_conn *Handler::conn() const { return conn_; }

namespace {
void remove_tx_stream_data(std::deque<std::vector<uint8_t>> &d, size_t &idx,
                           size_t datalen) {
  for (; !d.empty() && d.front().size() <= datalen;) {
    --idx;
    datalen -= d.front().size();
    d.pop_front();
  }
}
} // namespace

void Handler::remove_tx_stream_data(uint32_t stream_id, uint64_t offset,
                                    size_t datalen) {
  if (stream_id == 0) {
    ::remove_tx_stream_data(shandshake_, shandshake_idx_, datalen);
    return;
  }
  auto it = streams_.find(stream_id);
  assert(it != std::end(streams_));
  auto &stream = (*it).second;
  ::remove_tx_stream_data(stream.streambuf, stream.streambuf_idx, datalen);
}

namespace {
void swritecb(struct ev_loop *loop, ev_io *w, int revents) {}
} // namespace

namespace {
void sreadcb(struct ev_loop *loop, ev_io *w, int revents) {
  auto s = static_cast<Server *>(w->data);

  s->on_read();
}
} // namespace

Server::Server(struct ev_loop *loop, SSL_CTX *ssl_ctx)
    : loop_(loop), ssl_ctx_(ssl_ctx), fd_(-1) {
  ev_io_init(&wev_, swritecb, 0, EV_WRITE);
  ev_io_init(&rev_, sreadcb, 0, EV_READ);
  wev_.data = this;
  rev_.data = this;
}

Server::~Server() {
  ev_io_stop(loop_, &rev_);
  ev_io_stop(loop_, &wev_);

  if (fd_ != -1) {
    close(fd_);
  }
}

int Server::init(int fd) {
  fd_ = fd;

  ev_io_set(&wev_, fd_, EV_WRITE);
  ev_io_set(&rev_, fd_, EV_READ);

  ev_io_start(loop_, &rev_);

  return 0;
}

int Server::on_read() {
  sockaddr_union su;
  socklen_t addrlen = sizeof(su);
  std::array<uint8_t, 64_k> buf;
  int rv;
  ngtcp2_pkt_hd hd;

  auto nread =
      recvfrom(fd_, buf.data(), buf.size(), MSG_DONTWAIT, &su.sa, &addrlen);
  if (nread == -1) {
    std::cerr << "recvfrom: " << strerror(errno) << std::endl;
    // TODO Handle running out of fd
    return 0;
  }

  if (debug::packet_lost(config.rx_loss_prob)) {
    std::cerr << "** Simulated incoming packet loss **" << std::endl;
    return 0;
  }

  rv = ngtcp2_pkt_decode_hd(&hd, buf.data(), nread);
  if (rv < 0) {
    std::cerr << "Could not decode QUIC packet header: " << ngtcp2_strerror(rv)
              << std::endl;
    return 0;
  }

  auto conn_id = hd.conn_id;

  auto handler_it = handlers_.find(conn_id);
  if (handler_it == std::end(handlers_)) {
    switch (su.storage.ss_family) {
    case AF_INET:
      if (nread < NGTCP2_MAX_PKTLEN_IPV4) {
        std::cerr << "IPv4 packet is too short: " << nread << " < "
                  << NGTCP2_MAX_PKTLEN_IPV4 << std::endl;
        return 0;
      }
      break;
    case AF_INET6:
      if (nread < NGTCP2_MAX_PKTLEN_IPV6) {
        std::cerr << "IPv6 packet is too short: " << nread << " < "
                  << NGTCP2_MAX_PKTLEN_IPV6 << std::endl;
        return 0;
      }
      break;
    }

    rv = ngtcp2_accept(&hd, buf.data(), nread);
    if (rv == -1) {
      std::cerr << "Unexpected packet received" << std::endl;
      return 0;
    }
    if (rv == 1) {
      std::cerr << "Unsupported version: Send Version Negotiation" << std::endl;
      send_version_negotiation(&hd, &su.sa, addrlen);
      return 0;
    }

    if ((buf[0] & 0x7f) != NGTCP2_PKT_CLIENT_INITIAL) {
      return 0;
    }

    auto h = std::make_unique<Handler>(loop_, ssl_ctx_, this);
    h->init(fd_, &su.sa, addrlen);

    if (h->on_read(buf.data(), nread) != 0) {
      return 0;
    }

    conn_id = h->conn_id();
    handlers_.emplace(conn_id, std::move(h));
    return 0;
  }

  auto h = (*handler_it).second.get();
  if (h->on_read(buf.data(), nread) != 0) {
    handlers_.erase(conn_id);
  }

  return 0;
}

namespace {
uint32_t generate_reserved_vesrion(const sockaddr *sa, socklen_t salen,
                                   uint32_t version) {
  uint32_t h = 0x811C9DC5u;
  const uint8_t *p = (const uint8_t *)sa;
  const uint8_t *ep = p + salen;
  for (; p != ep; ++p) {
    h ^= *p;
    h *= 0x01000193u;
  }
  version = htonl(version);
  p = (const uint8_t *)&version;
  ep = p + sizeof(version);
  for (; p != ep; ++p) {
    h ^= *p;
    h *= 0x01000193u;
  }
  h &= 0xf0f0f0f0u;
  h |= 0x0a0a0a0au;
  return h;
}
} // namespace

int Server::send_version_negotiation(const ngtcp2_pkt_hd *chd,
                                     const sockaddr *sa, socklen_t salen) {
  std::array<uint8_t, 256> buf;
  ngtcp2_upe *upe;
  ngtcp2_pkt_hd hd;
  uint32_t reserved_ver;
  uint32_t sv[2];
  size_t pktlen;
  ssize_t nwrite;
  int rv;

  hd.type = NGTCP2_PKT_VERSION_NEGOTIATION;
  hd.flags = NGTCP2_PKT_FLAG_LONG_FORM;
  hd.conn_id = chd->conn_id;
  hd.pkt_num = chd->pkt_num;
  hd.version = chd->version;

  reserved_ver = generate_reserved_vesrion(sa, salen, hd.version);

  sv[0] = reserved_ver;
  sv[1] = NGTCP2_PROTO_VERSION;

  rv = ngtcp2_upe_new(&upe, buf.data(), buf.size());
  if (rv != 0) {
    std::cerr << "ngtcp2_upe_new: " << ngtcp2_strerror(rv) << std::endl;
    return -1;
  }

  auto upe_d = defer(ngtcp2_upe_del, upe);

  rv = ngtcp2_upe_encode_hd(upe, &hd);
  if (rv != 0) {
    return -1;
  }

  rv = ngtcp2_upe_encode_version_negotiation(upe, sv, array_size(sv));
  if (rv != 0) {
    std::cerr << "ngtcp2_upe_encode_version_negotiation: "
              << ngtcp2_strerror(rv) << std::endl;
    return -1;
  }

  pktlen = ngtcp2_upe_final(upe, NULL);

  nwrite = sendto(fd_, buf.data(), pktlen, 0, sa, salen);
  if (nwrite == -1) {
    std::cerr << "sendto: " << strerror(errno) << std::endl;
    return -1;
  }

  return 0;
}

void Server::remove(const Handler *h) { handlers_.erase(h->conn_id()); }

namespace {
int alpn_select_proto_cb(SSL *ssl, const unsigned char **out,
                         unsigned char *outlen, const unsigned char *in,
                         unsigned int inlen, void *arg) {
  for (auto p = in, end = in + inlen; p + str_size(NGTCP2_ALPN) <= end;
       p += *p + 1) {
    if (std::equal(std::begin(NGTCP2_ALPN), std::end(NGTCP2_ALPN) - 1, p)) {
      *out = p + 1;
      *outlen = *p;
      debug::print_timestamp();
      std::cerr << "Negotiated ALPN ";
      std::cerr.write(reinterpret_cast<const char *>(*out), *outlen);
      std::cerr << std::endl;
      return SSL_TLSEXT_ERR_OK;
    }
  }
  // Just select NGTCP2_ALPN for now.
  *out = reinterpret_cast<const uint8_t *>(NGTCP2_ALPN + 1);
  *outlen = NGTCP2_ALPN[0];
  return SSL_TLSEXT_ERR_OK;
}
} // namespace

namespace {
int transport_params_add_cb(SSL *ssl, unsigned int ext_type,
                            unsigned int content, const unsigned char **out,
                            size_t *outlen, X509 *x, size_t chainidx, int *al,
                            void *add_arg) {
  int rv;
  auto h = static_cast<Handler *>(SSL_get_app_data(ssl));
  auto conn = h->conn();

  ngtcp2_transport_params params;

  rv = ngtcp2_conn_get_local_transport_params(
      conn, &params, NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS);
  if (rv != 0) {
    // TODO Set *al
    return -1;
  }

  constexpr size_t bufsize = 64;
  auto buf = std::make_unique<uint8_t[]>(bufsize);

  auto nwrite = ngtcp2_encode_transport_params(
      buf.get(), bufsize, NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS,
      &params);
  if (nwrite < 0) {
    std::cerr << "ngtcp2_encode_transport_params: "
              << ngtcp2_strerror(static_cast<int>(nwrite)) << std::endl;
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
  if (context != SSL_EXT_CLIENT_HELLO) {
    // TODO Set *al
    return -1;
  }

  auto h = static_cast<Handler *>(SSL_get_app_data(ssl));
  auto conn = h->conn();

  int rv;

  ngtcp2_transport_params params;

  rv = ngtcp2_decode_transport_params(
      &params, NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, in, inlen);
  if (rv != 0) {
    std::cerr << "ngtcp2_decode_transport_params: " << ngtcp2_strerror(rv)
              << std::endl;
    // TODO Just continue for now
    return 1;
  }

  debug::print_timestamp();
  std::cerr << "TransportParameter received in ClientHello" << std::endl;
  debug::print_transport_params(&params,
                                NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO);

  rv = ngtcp2_conn_set_remote_transport_params(
      conn, NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, &params);
  if (rv != 0) {
    // TODO Set *al
    return -1;
  }

  return 1;
}
} // namespace

namespace {
SSL_CTX *create_ssl_ctx(const char *private_key_file, const char *cert_file) {
  auto ssl_ctx = SSL_CTX_new(TLS_method());

  constexpr auto ssl_opts = (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) |
                            SSL_OP_SINGLE_ECDH_USE |
                            SSL_OP_CIPHER_SERVER_PREFERENCE;

  SSL_CTX_set_options(ssl_ctx, ssl_opts);
  SSL_CTX_set1_curves_list(ssl_ctx, "p-256");
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);

  SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);

  SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_select_proto_cb, nullptr);

  SSL_CTX_set_default_verify_paths(ssl_ctx);

  if (SSL_CTX_use_PrivateKey_file(ssl_ctx, private_key_file,
                                  SSL_FILETYPE_PEM) != 1) {
    std::cerr << "SSL_CTX_use_PrivateKey_file: "
              << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
    goto fail;
  }

  if (SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_file) != 1) {
    std::cerr << "SSL_CTX_use_certificate_file: "
              << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
    goto fail;
  }

  if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
    std::cerr << "SSL_CTX_check_private_key: "
              << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
    goto fail;
  }

  if (SSL_CTX_add_custom_ext(
          ssl_ctx, NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS,
          SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS |
              SSL_EXT_IGNORE_ON_RESUMPTION,
          transport_params_add_cb, transport_params_free_cb, nullptr,
          transport_params_parse_cb, nullptr) != 1) {
    std::cerr << "SSL_CTX_add_custom_ext(NGTCP2_TLSEXT_QUIC_TRANSPORT_"
                 "PARAMETERS) failed: "
              << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
    goto fail;
  }

  return ssl_ctx;

fail:
  SSL_CTX_free(ssl_ctx);
  return nullptr;
}
} // namespace

namespace {
int create_sock(const char *addr, const char *port) {
  addrinfo hints{};
  addrinfo *res, *rp;
  int rv;

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;

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

    if (bind(fd, rp->ai_addr, rp->ai_addrlen) != -1) {
      break;
    }

    close(fd);
  }

  if (!rp) {
    std::cerr << "Could not bind" << std::endl;
    return -1;
  }

  auto val = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val,
                 static_cast<socklen_t>(sizeof(val))) == -1) {
    return -1;
  }

  return fd;
}

} // namespace

namespace {
int serve(Server &s, const char *addr, const char *port) {
  int rv;

  auto fd = create_sock(addr, port);
  if (fd == -1) {
    return -1;
  }

  if (s.init(fd) != 0) {
    return -1;
  }

  ev_run(EV_DEFAULT, 0);

  return 0;
}
} // namespace

namespace {
void print_usage() {
  std::cerr << "Usage: server [OPTIONS] <ADDR> <PORT> <PRIVATE_KEY_FILE> "
               "<CERTIFICATE_FILE>"
            << std::endl;
}
} // namespace

namespace {
void print_help() {
  print_usage();

  std::cout << R"(
  <ADDR>      Remote server address
  <PORT>      Remote server port
  <PRIVATE_KEY_FILE>
              Path to private key file
  <CERTIFICATE_FILE>
              Path to certificate file
Options:
  -t, --tx-loss=<P>
              The probability of losing outgoing packets.  <P> must be
              [0.0, 1.0],  inclusive.  0.0 means no  packet loss.  1.0
              means 100% packet loss.
  -r, --rx-loss=<P>
              The probability of losing incoming packets.  <P> must be
              [0.0, 1.0],  inclusive.  0.0 means no  packet loss.  1.0
              means 100% packet loss.
  -h, --help  Display this help and exit.
)";
}
} // namespace

int main(int argc, char **argv) {
  config.tx_loss_prob = 0.;
  config.rx_loss_prob = 0.;

  for (;;) {
    static int flag = 0;
    constexpr static option long_opts[] = {
        {"help", no_argument, nullptr, 'h'},
        {"tx-loss", required_argument, nullptr, 't'},
        {"rx-loss", required_argument, nullptr, 'r'},
        {nullptr, 0, nullptr, 0}};

    auto optidx = 0;
    auto c = getopt_long(argc, argv, "hr:t:", long_opts, &optidx);
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
    case '?':
      print_usage();
      exit(EXIT_FAILURE);
    default:
      break;
    };
  }

  if (argc - optind < 4) {
    std::cerr << "Too few arguments" << std::endl;
    print_usage();
    exit(EXIT_FAILURE);
  }

  auto addr = argv[optind++];
  auto port = argv[optind++];
  auto private_key_file = argv[optind++];
  auto cert_file = argv[optind++];

  auto ssl_ctx = create_ssl_ctx(private_key_file, cert_file);
  if (ssl_ctx == nullptr) {
    exit(EXIT_FAILURE);
  }

  auto ssl_ctx_d = defer(SSL_CTX_free, ssl_ctx);

  debug::reset_timestamp();

  if (isatty(STDOUT_FILENO)) {
    debug::set_color_output(true);
  }

  Server s(EV_DEFAULT, ssl_ctx);

  if (serve(s, addr, port) != 0) {
    exit(EXIT_FAILURE);
  }
}
