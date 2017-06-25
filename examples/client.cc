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

#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <openssl/bio.h>

#include "client.h"
#include "template.h"
#include "network.h"
#include "debug.h"
#include "util.h"

using namespace ngtcp2;

namespace {
auto randgen = util::make_mt19937();
} // namespace

namespace {
void *BIO_get_data(BIO *bio) { return bio->ptr; }
void BIO_set_data(BIO *bio, void *ptr) { bio->ptr = ptr; }
void BIO_set_init(BIO *bio, int init) { bio->init = init; }
} // namespace

namespace {
int bio_write(BIO *b, const char *buf, int len) {
  BIO_clear_retry_flags(b);

  auto c = static_cast<Client *>(BIO_get_data(b));

  c->write_client_handshake(reinterpret_cast<const uint8_t *>(buf), len);

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
  static auto meth = new BIO_METHOD{
      BIO_TYPE_FD, "bio",    bio_write,  bio_read,    bio_puts,
      bio_gets,    bio_ctrl, bio_create, bio_destroy,
  };

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

Client::Client(struct ev_loop *loop, SSL_CTX *ssl_ctx)
    : loop_(loop),
      ssl_ctx_(ssl_ctx),
      ssl_(nullptr),
      fd_(-1),
      ncread_(0),
      nsread_(0),
      conn_(nullptr) {
  ev_io_init(&wev_, writecb, 0, EV_WRITE);
  ev_io_init(&rev_, readcb, 0, EV_READ);
  wev_.data = this;
  rev_.data = this;
}

Client::~Client() { disconnect(); }

void Client::disconnect() {
  std::cerr << "disconnecting" << std::endl;

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

  if (c->tls_handshake() != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  auto len = c->read_client_handshake(pdest);

  return len;
}
} // namespace

namespace {
int recv_handshake_data(ngtcp2_conn *conn, const uint8_t *data, size_t datalen,
                        void *user_data) {
  auto c = static_cast<Client *>(user_data);

  c->write_server_handshake(data, datalen);

  if (c->tls_handshake() != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

int Client::init(int fd) {
  int rv;

  fd_ = fd;
  ssl_ = SSL_new(ssl_ctx_);
  auto bio = BIO_new(create_bio_method());
  BIO_set_data(bio, this);
  SSL_set_bio(ssl_, bio, bio);
  SSL_set_app_data(ssl_, this);
  SSL_set_connect_state(ssl_);

  auto callbacks = ngtcp2_conn_callbacks{
      send_client_initial,
      send_client_cleartext,
      nullptr,
      recv_handshake_data,
      debug::send_pkt,
      debug::send_frame,
      debug::recv_pkt,
      debug::recv_frame,
      debug::handshake_completed,
      debug::recv_version_negotiation,
  };

  auto conn_id = std::uniform_int_distribution<uint64_t>(
      0, std::numeric_limits<uint64_t>::max())(randgen);

  rv = ngtcp2_conn_client_new(&conn_, conn_id, 1, &callbacks, this);
  if (rv != 0) {
    std::cerr << "ngtcp2_conn_client_new: " << rv << std::endl;
    return -1;
  }

  ev_io_set(&wev_, fd_, EV_WRITE);
  ev_io_set(&rev_, fd_, EV_READ);

  ev_io_start(loop_, &rev_);

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

  rv = ngtcp2_conn_handshake_completed(conn_);
  if (rv != 0) {
    std::cerr << "ngtcp2_conn_handshake_completed: " << rv << std::endl;
    return -1;
  }

  return 0;
}

int Client::feed_data(const uint8_t *data, size_t datalen) {
  int rv;

  rv = ngtcp2_conn_recv(conn_, data, datalen, util::timestamp());
  if (rv != 0) {
    std::cerr << "ngtcp2_conn_recv: " << rv << std::endl;
    return -1;
  }

  return 0;
}

int Client::on_read() {
  std::array<uint8_t, 65536> buf;

  auto nread =
      recvfrom(fd_, buf.data(), buf.size(), MSG_DONTWAIT, nullptr, nullptr);

  if (nread == -1) {
    std::cerr << "recvfrom: " << strerror(errno) << std::endl;
    return 0;
  }

  if (feed_data(buf.data(), nread) != 0) {
    return -1;
  }

  return on_write();
}

int Client::on_write() {
  std::array<uint8_t, 1280> buf;
  auto n = ngtcp2_conn_send(conn_, buf.data(), buf.size(), util::timestamp());
  if (n < 0) {
    return -1;
  }
  if (n == 0) {
    return 0;
  }

  auto nwrite = write(fd_, buf.data(), n);
  if (nwrite == -1) {
    std::cerr << "write: " << strerror(errno) << std::endl;
    return -1;
  }

  return 0;
}

void Client::write_client_handshake(const uint8_t *data, size_t datalen) {
  std::copy_n(data, datalen, std::back_inserter(chandshake_));
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

namespace {
SSL_CTX *create_ssl_ctx() {
  auto ssl_ctx = SSL_CTX_new(TLS_method());

  SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);

  SSL_CTX_set_default_verify_paths(ssl_ctx);

  return ssl_ctx;
}
} // namespace

namespace {
int create_sock(const char *addr, const char *port) {
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

  return fd;
}

} // namespace

namespace {
int run(Client &c, const char *addr, const char *port) {
  int rv;

  auto fd = create_sock(addr, port);
  if (fd == -1) {
    return -1;
  }

  if (c.init(fd) != 0) {
    return -1;
  }

  c.on_write();

  ev_run(EV_DEFAULT, 0);

  return 0;
}
} // namespace

namespace {
void print_usage() { std::cerr << "Usage: client ADDR PORT" << std::endl; }
} // namespace

int main(int argc, char **argv) {
  for (;;) {
    static int flag = 0;
    constexpr static option long_opts[] = {{nullptr, 0, nullptr, 0}};

    auto optidx = 0;
    auto c = getopt_long(argc, argv, "", long_opts, &optidx);
    if (c == -1) {
      break;
    }
    switch (c) {
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
