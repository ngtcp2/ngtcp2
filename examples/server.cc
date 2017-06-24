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

#include "server.h"
#include "template.h"
#include "network.h"

using namespace ngtcp2;

namespace {
void *BIO_get_data(BIO *bio) { return bio->ptr; }
void BIO_set_data(BIO *bio, void *ptr) { bio->ptr = ptr; }
void BIO_set_init(BIO *bio, int init) { bio->init = init; }
} // namespace

namespace {
int bio_write(BIO *b, const char *buf, int len) {
  BIO_clear_retry_flags(b);

  auto h = static_cast<Handler *>(BIO_get_data(b));

  h->write_server_handshake(reinterpret_cast<const uint8_t *>(buf), len);

  std::cerr << "ServerHello: " << len << " bytes" << std::endl;
  ;
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

  std::cerr << "ClientHello: " << len << " bytes" << std::endl;
  ;

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
void hwritecb(struct ev_loop *loop, ev_io *w, int revents) {
  auto h = static_cast<Handler *>(w->data);

  if (h->on_write() != 0) {
    delete h;
  }
}
} // namespace

namespace {
void hreadcb(struct ev_loop *loop, ev_io *w, int revents) {
  auto h = static_cast<Handler *>(w->data);

  if (h->on_read() != 0) {
    delete h;
  }
}
} // namespace

Handler::Handler(struct ev_loop *loop, SSL_CTX *ssl_ctx)
    : loop_(loop),
      ssl_ctx_(ssl_ctx),
      ssl_(nullptr),
      fd_(-1),
      ncread_(0),
      nsread_(0),
      conn_(nullptr) {
  ev_io_init(&wev_, hwritecb, 0, EV_WRITE);
  ev_io_init(&rev_, hreadcb, 0, EV_READ);
  wev_.data = this;
  rev_.data = this;
}

Handler::~Handler() {
  ev_io_stop(loop_, &rev_);
  ev_io_stop(loop_, &wev_);

  if (conn_) {
    ngtcp2_conn_del(conn_);
  }

  if (ssl_) {
    SSL_free(ssl_);
  }

  if (fd_ != -1) {
    close(fd_);
  }
  assert(0);
}

namespace {
ssize_t send_server_cleartext(ngtcp2_conn *conn, uint32_t flags,
                              uint64_t *ppkt_num, const uint8_t **pdest,
                              size_t maxdestlen, void *user_data) {
  auto h = static_cast<Handler *>(user_data);

  if (h->tls_handshake() != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  if (ppkt_num) {
    *ppkt_num = 1;
  }

  auto len = h->read_server_handshake(pdest, maxdestlen);

  std::cerr << "Server Cleartext: " << len << " bytes" << std::endl;

  return len;
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

int Handler::init(int fd) {
  int rv;

  fd_ = fd;
  ssl_ = SSL_new(ssl_ctx_);
  auto bio = BIO_new(create_bio_method());
  BIO_set_data(bio, this);
  SSL_set_bio(ssl_, bio, bio);
  SSL_set_app_data(ssl_, this);
  SSL_set_accept_state(ssl_);

  auto callbacks = ngtcp2_conn_callbacks{
      nullptr, nullptr, send_server_cleartext, recv_handshake_data,
  };

  rv = ngtcp2_conn_server_new(&conn_, 2, 1, &callbacks, this);
  if (rv != 0) {
    std::cerr << "ngtcp2_conn_server_new: " << rv << std::endl;
    return -1;
  }

  ev_io_set(&wev_, fd_, EV_WRITE);
  ev_io_set(&rev_, fd_, EV_READ);

  ev_io_start(loop_, &rev_);

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
      break;
    case SSL_ERROR_SSL:
      std::cerr << "TLS handshake error: "
                << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
      return -1;
    default:
      std::cerr << "TLS handshake error: " << err << std::endl;
      return -1;
    }
  }

  return 0;
}

void Handler::write_server_handshake(const uint8_t *data, size_t datalen) {
  std::copy_n(data, datalen, std::back_inserter(chandshake_));
}

size_t Handler::read_server_handshake(const uint8_t **pdest,
                                      size_t maxdestlen) {
  auto n = std::min(maxdestlen, chandshake_.size() - ncread_);
  *pdest = chandshake_.data() + ncread_;
  ncread_ += n;
  return n;
}

size_t Handler::read_client_handshake(uint8_t *buf, size_t buflen) {
  auto n = std::min(buflen, shandshake_.size() - nsread_);
  std::copy_n(std::begin(shandshake_) + nsread_, n, buf);
  nsread_ += n;
  return n;
}

void Handler::write_client_handshake(const uint8_t *data, size_t datalen) {
  std::copy_n(data, datalen, std::back_inserter(shandshake_));
}

int Handler::feed_data(const uint8_t *data, size_t datalen) {
  int rv;

  rv = ngtcp2_conn_recv(conn_, data, datalen);
  if (rv != 0) {
    std::cerr << "ngtcp2_conn_recv: " << rv << std::endl;
    return -1;
  }

  return 0;
}

int Handler::on_read() {
  sockaddr_union su;
  socklen_t addrlen = sizeof(su);
  std::array<uint8_t, 1280> buf;

  auto nread =
      recvfrom(fd_, buf.data(), buf.size(), MSG_DONTWAIT, &su.sa, &addrlen);
  if (nread == -1) {
    std::cerr << "recvfrom: " << strerror(errno) << std::endl;
    return 0;
  }

  std::cerr << "Read " << nread << " from socket " << fd_ << std::endl;

  if (feed_data(buf.data(), nread) != 0) {
    return -1;
  }

  return on_write();
}

int Handler::on_write() {
  std::array<uint8_t, 1280> buf;
  std::cerr << "on_write" << std::endl;

  for (;;) {
    auto n = ngtcp2_conn_send(conn_, buf.data(), buf.size());
    if (n < 0) {
      return -1;
    }
    if (n == 0) {
      return 0;
    }

    std::cerr << "Write " << n << " bytes of UDP payload" << std::endl;

    auto nwrite = write(fd_, buf.data(), n);
    if (nwrite == -1) {
      std::cerr << "write: " << strerror(errno) << std::endl;
      return -1;
    }

    std::cerr << "Wrote " << nwrite << " bytes" << std::endl;
  }
}

void Handler::signal_write() { ev_feed_event(loop_, &wev_, EV_WRITE); }

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
  std::array<uint8_t, 1280> buf;

  auto nread =
      recvfrom(fd_, buf.data(), buf.size(), MSG_DONTWAIT, &su.sa, &addrlen);
  if (nread == -1) {
    std::cerr << "recvfrom: " << strerror(errno) << std::endl;
    // TODO Handle running out of fd
    return 0;
  }

  auto fd = socket(su.storage.ss_family, SOCK_DGRAM, 0);
  if (fd == -1) {
    std::cerr << "socket: " << strerror(errno) << std::endl;
    return 0;
  }

  auto val = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val,
                 static_cast<socklen_t>(sizeof(val))) == -1) {
    close(fd);
    return 0;
  }

  {
    sockaddr_union su;
    socklen_t addrlen = sizeof(su);

    if (getsockname(fd_, &su.sa, &addrlen) == -1) {
      std::cerr << "getsockname: " << strerror(errno) << std::endl;
    }

    if (bind(fd, &su.sa, addrlen) == -1) {
      std::cerr << "bind: " << strerror(errno) << std::endl;
    }
  }

  if (connect(fd, &su.sa, addrlen) == -1) {
    std::cerr << "connect: " << strerror(errno) << std::endl;
    close(fd);
    return 0;
  }

  auto h = std::make_unique<Handler>(loop_, ssl_ctx_);
  h->init(fd);
  if (h->feed_data(buf.data(), nread) != 0) {
    return 0;
  }
  h->signal_write();
  h.release();

  return 0;
}

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
  std::cerr << "Usage: server ADDR PORT PRIVATE_KEY_FILE CERTIFICATE_FILE"
            << std::endl;
}
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

  Server s(EV_DEFAULT, ssl_ctx);

  if (serve(s, addr, port) != 0) {
    exit(EXIT_FAILURE);
  }
}
