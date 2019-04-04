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
#include <fstream>

#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <openssl/bio.h>
#include <openssl/err.h>

#include <http-parser/http_parser.h>

#include "server.h"
#include "network.h"
#include "debug.h"
#include "util.h"
#include "crypto.h"
#include "shared.h"
#include "http.h"
#include "keylog.h"

using namespace ngtcp2;

namespace {
constexpr size_t NGTCP2_SV_SCIDLEN = 18;
} // namespace

namespace {
constexpr size_t TOKEN_RAND_DATALEN = 16;
} // namespace

namespace {
auto randgen = util::make_mt19937();
} // namespace

namespace {
Config config{};
} // namespace

Buffer::Buffer(const uint8_t *data, size_t datalen)
    : buf{data, data + datalen},
      begin(buf.data()),
      head(begin),
      tail(begin + datalen) {}
Buffer::Buffer(uint8_t *begin, uint8_t *end)
    : begin(begin), head(begin), tail(end) {}
Buffer::Buffer(size_t datalen)
    : buf(datalen), begin(buf.data()), head(begin), tail(begin) {}
Buffer::Buffer() : begin(buf.data()), head(begin), tail(begin) {}

namespace {
int key_cb(SSL *ssl, int name, const unsigned char *secret, size_t secretlen,
           void *arg) {
  auto h = static_cast<Handler *>(arg);

  if (h->on_key(name, secret, secretlen) != 0) {
    return 0;
  }

  keylog::log_secret(ssl, name, secret, secretlen);

  return 1;
}
} // namespace

int Handler::on_key(int name, const uint8_t *secret, size_t secretlen) {
  int rv;

  switch (name) {
  case SSL_KEY_CLIENT_EARLY_TRAFFIC:
  case SSL_KEY_CLIENT_HANDSHAKE_TRAFFIC:
  case SSL_KEY_SERVER_HANDSHAKE_TRAFFIC:
    break;
  case SSL_KEY_CLIENT_APPLICATION_TRAFFIC:
    rx_secret_.assign(secret, secret + secretlen);
    break;
  case SSL_KEY_SERVER_APPLICATION_TRAFFIC:
    tx_secret_.assign(secret, secret + secretlen);
    break;
  default:
    return 0;
  }

  // TODO We don't have to call this everytime we get key generated.
  rv = crypto::negotiated_prf(crypto_ctx_, ssl_);
  if (rv != 0) {
    return -1;
  }
  rv = crypto::negotiated_aead(crypto_ctx_, ssl_);
  if (rv != 0) {
    return -1;
  }

  std::array<uint8_t, 64> key, iv, hp;
  auto keylen = crypto::derive_packet_protection_key(
      key.data(), key.size(), secret, secretlen, crypto_ctx_);
  if (keylen < 0) {
    return -1;
  }

  auto ivlen = crypto::derive_packet_protection_iv(iv.data(), iv.size(), secret,
                                                   secretlen, crypto_ctx_);
  if (ivlen < 0) {
    return -1;
  }

  auto hplen = crypto::derive_header_protection_key(
      hp.data(), hp.size(), secret, secretlen, crypto_ctx_);
  if (hplen < 0) {
    return -1;
  }

  // TODO Just call this once.
  ngtcp2_conn_set_aead_overhead(conn_, crypto::aead_max_overhead(crypto_ctx_));

  switch (name) {
  case SSL_KEY_CLIENT_EARLY_TRAFFIC: {
    if (!config.quiet) {
      std::cerr << "client_early_traffic" << std::endl;
    }
    ngtcp2_conn_install_early_keys(conn_, key.data(), keylen, iv.data(), ivlen,
                                   hp.data(), hplen);
    if (setup_httpconn() != 0) {
      return -1;
    }
    break;
  }
  case SSL_KEY_CLIENT_HANDSHAKE_TRAFFIC:
    if (!config.quiet) {
      std::cerr << "client_handshake_traffic" << std::endl;
    }
    ngtcp2_conn_install_handshake_rx_keys(conn_, key.data(), keylen, iv.data(),
                                          ivlen, hp.data(), hplen);
    break;
  case SSL_KEY_CLIENT_APPLICATION_TRAFFIC:
    if (!config.quiet) {
      std::cerr << "client_application_traffic" << std::endl;
    }
    ngtcp2_conn_install_rx_keys(conn_, key.data(), keylen, iv.data(), ivlen,
                                hp.data(), hplen);
    break;
  case SSL_KEY_SERVER_HANDSHAKE_TRAFFIC:
    if (!config.quiet) {
      std::cerr << "server_handshake_traffic" << std::endl;
    }
    ngtcp2_conn_install_handshake_tx_keys(conn_, key.data(), keylen, iv.data(),
                                          ivlen, hp.data(), hplen);
    tx_crypto_level_ = NGTCP2_CRYPTO_LEVEL_HANDSHAKE;
    break;
  case SSL_KEY_SERVER_APPLICATION_TRAFFIC:
    if (!config.quiet) {
      std::cerr << "server_application_traffic" << std::endl;
    }
    ngtcp2_conn_install_tx_keys(conn_, key.data(), keylen, iv.data(), ivlen,
                                hp.data(), hplen);
    break;
  }

  if (!config.quiet) {
    debug::print_secrets(secret, secretlen, key.data(), keylen, iv.data(),
                         ivlen, hp.data(), hplen);
  }

  return 0;
}

namespace {
void msg_cb(int write_p, int version, int content_type, const void *buf,
            size_t len, SSL *ssl, void *arg) {
  int rv;

  if (!config.quiet) {
    std::cerr << "msg_cb: write_p=" << write_p << " version=" << version
              << " content_type=" << content_type << " len=" << len
              << std::endl;
  }

  if (!write_p) {
    return;
  }

  auto h = static_cast<Handler *>(arg);
  auto msg = reinterpret_cast<const uint8_t *>(buf);

  switch (content_type) {
  case SSL3_RT_HANDSHAKE:
    break;
  case SSL3_RT_ALERT:
    assert(len == 2);
    if (msg[0] != 2 /* FATAL */) {
      return;
    }
    h->set_tls_alert(msg[1]);
    return;
  default:
    return;
  }

  rv = h->write_server_handshake(reinterpret_cast<const uint8_t *>(buf), len);

  assert(0 == rv);
}
} // namespace

namespace {
int bio_write(BIO *b, const char *buf, int len) {
  assert(0);
  return -1;
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

Stream::Stream(int64_t stream_id, Handler *handler)
    : stream_id(stream_id),
      handler(handler),
      fd(-1),
      data(nullptr),
      datalen(0),
      dynresp(false),
      dyndataleft(0),
      dynackedoffset(0),
      dynbuflen(0),
      md_ctx(nullptr) {}

Stream::~Stream() {
  if (md_ctx) {
    EVP_MD_CTX_free(md_ctx);
  }

  munmap(data, datalen);
  if (fd != -1) {
    close(fd);
  }
}

int Stream::recv_data(uint8_t fin, const uint8_t *data, size_t datalen) {
  return 0;
}

namespace {
constexpr char NGTCP2_SERVER[] = "nghttp3/ngtcp2 server";
} // namespace

namespace {
std::string make_status_body(unsigned int status_code) {
  auto status_string = std::to_string(status_code);
  auto reason_phrase = http::get_reason_phrase(status_code);

  std::string body;
  body = "<html><head><title>";
  body += status_string;
  body += ' ';
  body += reason_phrase;
  body += "</title></head><body><h1>";
  body += status_string;
  body += ' ';
  body += reason_phrase;
  body += "</h1><hr><address>";
  body += NGTCP2_SERVER;
  body += " at port ";
  body += std::to_string(config.port);
  body += "</address>";
  body += "</body></html>";
  return body;
}
} // namespace

namespace {
std::string request_path(const std::string &uri, bool is_connect) {
  http_parser_url u;

  http_parser_url_init(&u);

  auto rv = http_parser_parse_url(uri.c_str(), uri.size(), is_connect, &u);
  if (rv != 0) {
    return "";
  }

  if (u.field_set & (1 << UF_PATH)) {
    // TODO path could be empty?
    auto req_path = std::string(uri.c_str() + u.field_data[UF_PATH].off,
                                u.field_data[UF_PATH].len);
    if (!req_path.empty() && req_path.back() == '/') {
      req_path += "index.html";
    }
    return req_path;
  }

  return "/index.html";
}
} // namespace

namespace {
std::string resolve_path(const std::string &req_path) {
  auto raw_path = config.htdocs + req_path;
  auto malloced_path = realpath(raw_path.c_str(), nullptr);
  if (malloced_path == nullptr) {
    return "";
  }
  auto path = std::string(malloced_path);
  free(malloced_path);

  if (path.size() < config.htdocs.size() ||
      !std::equal(std::begin(config.htdocs), std::end(config.htdocs),
                  std::begin(path))) {
    return "";
  }
  return path;
}
} // namespace

int Stream::open_file(const std::string &path) {
  fd = open(path.c_str(), O_RDONLY);
  if (fd == -1) {
    return -1;
  }

  return 0;
}

int Stream::map_file(size_t len) {
  if (len == 0) {
    return 0;
  }
  data =
      static_cast<uint8_t *>(mmap(nullptr, len, PROT_READ, MAP_SHARED, fd, 0));
  if (data == MAP_FAILED) {
    std::cerr << "mmap: " << strerror(errno) << std::endl;
    return -1;
  }
  datalen = len;
  return 0;
}

int64_t Stream::find_dyn_length(const std::string &path) {
  assert(path[0] == '/');

  int64_t n = 0;

  for (auto it = std::begin(path) + 1; it != std::end(path); ++it) {
    if (*it < '0' || '9' < *it) {
      return -1;
    }
    n = n * 10 + (*it - '0');
    if (n > 1000000) {
      return -1;
    }
  }

  return n;
}

namespace {
int read_data(nghttp3_conn *conn, int64_t stream_id, const uint8_t **pdata,
              size_t *pdatalen, uint32_t *pflags, void *user_data,
              void *stream_user_data) {
  auto stream = static_cast<Stream *>(stream_user_data);

  *pdata = stream->data;
  *pdatalen = stream->datalen;
  *pflags |= NGHTTP3_DATA_FLAG_EOF;

  return 0;
}
} // namespace

struct DynDataIterator
    : public std::iterator<std::input_iterator_tag, uint8_t, std::ptrdiff_t,
                           const uint8_t *, const uint8_t> {
  DynDataIterator(std::uniform_int_distribution<uint8_t> &dis, size_t left)
      : dis(dis), c(dis(randgen)), left(left) {}

  DynDataIterator(std::uniform_int_distribution<uint8_t> &dis, uint8_t c,
                  size_t left)
      : dis(dis), c(c), left(left) {}

  DynDataIterator &operator++() {
    assert(left);
    --left;
    c = dis(randgen);
    return *this;
  }

  DynDataIterator operator++(int) {
    assert(left);
    return DynDataIterator(dis, c, left--);
  }

  pointer operator->() const { return &c; }

  reference operator*() const { return c; }

  bool operator==(const DynDataIterator &other) const {
    return left == other.left;
  }

  bool operator!=(const DynDataIterator &other) const {
    return left != other.left;
  }

  std::uniform_int_distribution<uint8_t> &dis;
  uint8_t c;
  size_t left;
};

struct DynDataGenerator {
  using const_iterator = DynDataIterator;

  DynDataGenerator(size_t len) : len(len), dis(0, 255) {}

  const_iterator begin() { return DynDataIterator(dis, len); }

  const_iterator end() { return DynDataIterator(dis, 0); }

  size_t len;
  std::uniform_int_distribution<uint8_t> dis;
};

namespace {
int dyn_read_data(nghttp3_conn *conn, int64_t stream_id, const uint8_t **pdata,
                  size_t *pdatalen, uint32_t *pflags, void *user_data,
                  void *stream_user_data) {
  auto stream = static_cast<Stream *>(stream_user_data);

  auto len = std::min(static_cast<size_t>(16384),
                      static_cast<size_t>(stream->dyndataleft));
  auto g = DynDataGenerator(len);
  auto buf = std::make_unique<std::vector<uint8_t>>(std::begin(g), std::end(g));

  *pdata = buf->data();
  *pdatalen = len;

  auto rv = EVP_DigestUpdate(stream->md_ctx, buf->data(), len);
  assert(rv == 1);

  stream->dynbuflen += len;
  stream->dynbufs.emplace_back(std::move(buf));

  stream->dyndataleft -= len;

  if (stream->dyndataleft == 0) {
    *pflags |= NGHTTP3_DATA_FLAG_EOF;

    std::array<uint8_t, 32> md;
    unsigned int mdlen = md.size();

    rv = EVP_DigestFinal_ex(stream->md_ctx, md.data(), &mdlen);
    assert(rv == 1);
    assert(mdlen == md.size());

    auto digest_hdr = std::string("SHA-256=");
    digest_hdr += util::b64encode(std::begin(md), std::end(md));

    auto stream_id_str = std::to_string(stream_id);
    std::array<nghttp3_nv, 2> trailers{
        util::make_nv("x-ngtcp2-stream-id", stream_id_str),
        util::make_nv("digest", digest_hdr),
    };

    rv = nghttp3_conn_submit_trailers(conn, stream_id, trailers.data(),
                                      trailers.size());
    if (rv != 0) {
      std::cerr << "nghttp3_conn_submit_trailers: " << nghttp3_strerror(rv)
                << std::endl;
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    }

    rv = nghttp3_conn_end_stream(conn, stream_id);
    assert(0 == rv);
  }

  return 0;
}
} // namespace

void Stream::http_acked_stream_data(size_t datalen) {
  if (!dynresp) {
    return;
  }

  datalen += dynackedoffset;

  assert(dynbuflen >= datalen);
  assert(!dynbufs.empty());

  for (; !dynbufs.empty() && datalen;) {
    auto &buf = dynbufs[0];
    if (datalen < buf->size()) {
      dynackedoffset = datalen;
      return;
    }

    datalen -= buf->size();
    dynbufs.pop_front();
  }

  dynackedoffset = 0;
}

int Stream::send_status_response(nghttp3_conn *httpconn,
                                 unsigned int status_code,
                                 const std::vector<HTTPHeader> &extra_headers) {
  status_resp_body = make_status_body(status_code);

  auto status_code_str = std::to_string(status_code);
  auto content_length_str = std::to_string(status_resp_body.size());

  std::vector<nghttp3_nv> nva(4 + extra_headers.size());
  nva[0] = util::make_nv(":status", status_code_str);
  nva[1] = util::make_nv("server", NGTCP2_SERVER);
  nva[2] = util::make_nv("content-type", "text/html; charset=utf-8");
  nva[3] = util::make_nv("content-length", content_length_str);
  for (size_t i = 0; i < extra_headers.size(); ++i) {
    auto &hdr = extra_headers[i];
    auto &nv = nva[4 + i];
    nv = util::make_nv(hdr.name, hdr.value);
  }

  data = (uint8_t *)status_resp_body.data();
  datalen = status_resp_body.size();

  nghttp3_data_reader dr{};
  dr.read_data = read_data;

  auto rv = nghttp3_conn_submit_response(httpconn, stream_id, nva.data(),
                                         nva.size(), &dr);
  if (rv != 0) {
    std::cerr << "nghttp3_conn_submit_response: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }

  auto stream_id_str = std::to_string(stream_id);
  std::array<nghttp3_nv, 1> trailers{
      util::make_nv("x-ngtcp2-stream-id", stream_id_str),
  };

  rv = nghttp3_conn_submit_trailers(httpconn, stream_id, trailers.data(),
                                    trailers.size());
  if (rv != 0) {
    std::cerr << "nghttp3_conn_submit_trailers: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }

  rv = nghttp3_conn_end_stream(httpconn, stream_id);
  assert(0 == rv);

  handler->shutdown_read(stream_id, NGHTTP3_HTTP_EARLY_RESPONSE);

  return 0;
}

int Stream::send_redirect_response(nghttp3_conn *httpconn,
                                   unsigned int status_code,
                                   const std::string &path) {
  return send_status_response(httpconn, status_code, {{"location", path}});
}

int Stream::start_response(nghttp3_conn *httpconn) {
  // TODO This should be handled by nghttp3
  if (uri.empty() || method.empty()) {
    return send_status_response(httpconn, 400);
  }

  auto req_path = request_path(uri, method == "CONNECT");
  auto dyn_len = find_dyn_length(req_path);

  int64_t content_length = -1;
  nghttp3_data_reader dr{};

  if (dyn_len == -1) {
    auto path = resolve_path(req_path);
    if (path.empty() || open_file(path) != 0) {
      send_status_response(httpconn, 404);
      return 0;
    }

    struct stat st {};

    if (fstat(fd, &st) == 0) {
      if (st.st_mode & S_IFDIR) {
        send_redirect_response(httpconn, 308,
                               path.substr(config.htdocs.size() - 1) + '/');
        return 0;
      }
      content_length = st.st_size;
    } else {
      send_status_response(httpconn, 404);
      return 0;
    }

    if (method == "HEAD") {
      close(fd);
      fd = -1;
    } else if (map_file(content_length) != 0) {
      send_status_response(httpconn, 500);
      return 0;
    }

    dr.read_data = read_data;
  } else {
    content_length = dyn_len;
    datalen = dyn_len;
    dynresp = true;
    dyndataleft = dyn_len;

    dr.read_data = dyn_read_data;

    md_ctx = EVP_MD_CTX_new();
    auto rv = EVP_DigestInit_ex(md_ctx, EVP_sha256(), nullptr);
    assert(rv == 1);
  }

  auto content_length_str = std::to_string(content_length);

  std::array<nghttp3_nv, 4> nva{
      util::make_nv(":status", "200"),
      util::make_nv("server", NGTCP2_SERVER),
      util::make_nv("content-type", "text/html; charset=utf-8"),
      util::make_nv("content-length", content_length_str),
  };

  auto rv = nghttp3_conn_submit_response(httpconn, stream_id, nva.data(),
                                         nva.size(), &dr);
  if (rv != 0) {
    std::cerr << "nghttp3_conn_submit_response: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }

  if (dyn_len == -1) {
    auto stream_id_str = std::to_string(stream_id);
    std::array<nghttp3_nv, 1> trailers{
        util::make_nv("x-ngtcp2-stream-id", stream_id_str),
    };

    rv = nghttp3_conn_submit_trailers(httpconn, stream_id, trailers.data(),
                                      trailers.size());
    if (rv != 0) {
      std::cerr << "nghttp3_conn_submit_trailers: " << nghttp3_strerror(rv)
                << std::endl;
      return -1;
    }

    rv = nghttp3_conn_end_stream(httpconn, stream_id);
    assert(0 == rv);

    handler->shutdown_read(stream_id, NGHTTP3_HTTP_EARLY_RESPONSE);
  }

  return 0;
}

namespace {
void timeoutcb(struct ev_loop *loop, ev_timer *w, int revents) {
  auto h = static_cast<Handler *>(w->data);
  auto s = h->server();

  if (ngtcp2_conn_is_in_closing_period(h->conn())) {
    if (!config.quiet) {
      std::cerr << "Closing Period is over" << std::endl;
    }

    s->remove(h);
    return;
  }
  if (h->draining()) {
    if (!config.quiet) {
      std::cerr << "Draining Period is over" << std::endl;
    }

    s->remove(h);
    return;
  }

  if (!config.quiet) {
    std::cerr << "Timeout" << std::endl;
  }

  h->start_draining_period();
}
} // namespace

namespace {
void retransmitcb(struct ev_loop *loop, ev_timer *w, int revents) {
  int rv;

  auto h = static_cast<Handler *>(w->data);
  auto s = h->server();
  auto conn = h->conn();
  auto now = util::timestamp(loop);

  if (!config.quiet) {
    std::cerr << "Timer expired" << std::endl;
  }
  if (ngtcp2_conn_loss_detection_expiry(conn) <= now) {
    if (!config.quiet) {
      std::cerr << "Loss detection timer expired" << std::endl;
    }
    rv = ngtcp2_conn_on_loss_detection_timer(conn, util::timestamp(loop));
    if (rv != 0) {
      std::cerr << "ngtcp2_conn_on_loss_detection_timer: "
                << ngtcp2_strerror(rv) << std::endl;
      s->remove(h);
      return;
    }
    rv = h->on_write();
    switch (rv) {
    case 0:
    case NETWORK_ERR_CLOSE_WAIT:
      return;
    case NETWORK_ERR_SEND_NON_FATAL:
      return;
    default:
      s->remove(h);
      return;
    }
  }

  if (ngtcp2_conn_ack_delay_expiry(conn) <= now) {
    if (!config.quiet) {
      std::cerr << "Delayed ACK timer expired" << std::endl;
    }
    rv = h->on_write();
    switch (rv) {
    case 0:
    case NETWORK_ERR_CLOSE_WAIT:
      return;
    case NETWORK_ERR_SEND_NON_FATAL:
      return;
    default:
      s->remove(h);
      return;
    }
  }
}
} // namespace

Handler::Handler(struct ev_loop *loop, SSL_CTX *ssl_ctx, Server *server,
                 const ngtcp2_cid *rcid)
    : endpoint_{nullptr},
      remote_addr_{},
      max_pktlen_(0),
      loop_(loop),
      ssl_ctx_(ssl_ctx),
      ssl_(nullptr),
      server_(server),
      ncread_(0),
      shandshake_idx_(0),
      tx_crypto_level_(NGTCP2_CRYPTO_LEVEL_INITIAL),
      conn_(nullptr),
      scid_{},
      pscid_{},
      rcid_(*rcid),
      hs_crypto_ctx_{},
      crypto_ctx_{},
      httpconn_{nullptr},
      sendbuf_{NGTCP2_MAX_PKTLEN_IPV4},
      tx_crypto_offset_(0),
      last_error_{QUICErrorType::Transport, 0},
      nkey_update_(0),
      initial_(true),
      draining_(false) {
  ev_timer_init(&timer_, timeoutcb, 0., config.timeout / 1000.);
  timer_.data = this;
  ev_timer_init(&rttimer_, retransmitcb, 0., 0.);
  rttimer_.data = this;
}

Handler::~Handler() {
  if (!config.quiet) {
    std::cerr << "Closing QUIC connection" << std::endl;
  }

  ev_timer_stop(loop_, &rttimer_);
  ev_timer_stop(loop_, &timer_);

  if (httpconn_) {
    nghttp3_conn_del(httpconn_);
  }

  if (conn_) {
    ngtcp2_conn_del(conn_);
  }

  if (ssl_) {
    SSL_free(ssl_);
  }
}

namespace {
int recv_client_initial(ngtcp2_conn *conn, const ngtcp2_cid *dcid,
                        void *user_data) {
  auto h = static_cast<Handler *>(user_data);

  if (h->recv_client_initial(dcid) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

namespace {
int handshake_completed(ngtcp2_conn *conn, void *user_data) {
  auto h = static_cast<Handler *>(user_data);

  if (!config.quiet) {
    debug::handshake_completed(conn, user_data);
  }

  if (h->handshake_completed() != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

int Handler::handshake_completed() {
  tx_crypto_level_ = NGTCP2_CRYPTO_LEVEL_APP;
  return setup_httpconn() != 0;
}

namespace {
ssize_t do_hs_encrypt(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                      const uint8_t *plaintext, size_t plaintextlen,
                      const uint8_t *key, size_t keylen, const uint8_t *nonce,
                      size_t noncelen, const uint8_t *ad, size_t adlen,
                      void *user_data) {
  auto h = static_cast<Handler *>(user_data);

  auto nwrite = h->hs_encrypt_data(dest, destlen, plaintext, plaintextlen, key,
                                   keylen, nonce, noncelen, ad, adlen);
  if (nwrite < 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return nwrite;
}
} // namespace

namespace {
ssize_t do_hs_decrypt(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                      const uint8_t *ciphertext, size_t ciphertextlen,
                      const uint8_t *key, size_t keylen, const uint8_t *nonce,
                      size_t noncelen, const uint8_t *ad, size_t adlen,
                      void *user_data) {
  auto h = static_cast<Handler *>(user_data);

  auto nwrite = h->hs_decrypt_data(dest, destlen, ciphertext, ciphertextlen,
                                   key, keylen, nonce, noncelen, ad, adlen);
  if (nwrite < 0) {
    return NGTCP2_ERR_TLS_DECRYPT;
  }

  return nwrite;
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
    return NGTCP2_ERR_TLS_DECRYPT;
  }

  return nwrite;
}
} // namespace

namespace {
ssize_t do_in_hp_mask(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                      const uint8_t *key, size_t keylen, const uint8_t *sample,
                      size_t samplelen, void *user_data) {
  auto h = static_cast<Handler *>(user_data);

  auto nwrite = h->in_hp_mask(dest, destlen, key, keylen, sample, samplelen);
  if (nwrite < 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  if (!config.quiet && config.show_secret) {
    debug::print_hp_mask(dest, destlen, sample, samplelen);
  }

  return nwrite;
}
} // namespace

namespace {
ssize_t do_hp_mask(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                   const uint8_t *key, size_t keylen, const uint8_t *sample,
                   size_t samplelen, void *user_data) {
  auto h = static_cast<Handler *>(user_data);

  auto nwrite = h->hp_mask(dest, destlen, key, keylen, sample, samplelen);
  if (nwrite < 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  if (!config.quiet && config.show_secret) {
    debug::print_hp_mask(dest, destlen, sample, samplelen);
  }

  return nwrite;
}
} // namespace

namespace {
int recv_crypto_data(ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data) {
  int rv;

  if (!config.quiet) {
    debug::print_crypto_data(crypto_level, data, datalen);
  }

  auto h = static_cast<Handler *>(user_data);

  h->write_client_handshake(data, datalen);

  if (!ngtcp2_conn_get_handshake_completed(h->conn())) {
    rv = h->tls_handshake();
    if (rv != 0) {
      return rv;
    }
    return 0;
  }

  // SSL_do_handshake() might not consume all data (e.g.,
  // NewSessionTicket).
  return h->read_tls();
}
} // namespace

namespace {
int recv_stream_data(ngtcp2_conn *conn, int64_t stream_id, int fin,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data, void *stream_user_data) {
  auto h = static_cast<Handler *>(user_data);

  if (h->recv_stream_data(stream_id, fin, data, datalen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

namespace {
int acked_crypto_offset(ngtcp2_conn *conn, uint64_t offset, size_t datalen,
                        void *user_data) {
  auto h = static_cast<Handler *>(user_data);
  h->remove_tx_crypto_data(offset, datalen);
  return 0;
}
} // namespace

namespace {
int acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id,
                             uint64_t offset, size_t datalen, void *user_data,
                             void *stream_user_data) {
  auto h = static_cast<Handler *>(user_data);
  if (h->acked_stream_data_offset(stream_id, datalen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
} // namespace

int Handler::acked_stream_data_offset(int64_t stream_id, size_t datalen) {
  if (!httpconn_) {
    return 0;
  }

  auto rv = nghttp3_conn_add_ack_offset(httpconn_, stream_id, datalen);
  if (rv != 0) {
    std::cerr << "nghttp3_conn_add_ack_offset: " << nghttp3_error(rv)
              << std::endl;
    return -1;
  }

  return 0;
}

namespace {
int stream_open(ngtcp2_conn *conn, int64_t stream_id, void *user_data) {
  auto h = static_cast<Handler *>(user_data);
  h->on_stream_open(stream_id);
  return 0;
}
} // namespace

void Handler::on_stream_open(int64_t stream_id) {
  auto it = streams_.find(stream_id);
  assert(it == std::end(streams_));
  streams_.emplace(stream_id, std::make_unique<Stream>(stream_id, this));
}

namespace {
int stream_close(ngtcp2_conn *conn, int64_t stream_id, uint16_t app_error_code,
                 void *user_data, void *stream_user_data) {
  auto h = static_cast<Handler *>(user_data);
  if (h->on_stream_close(stream_id) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
} // namespace

namespace {
int stream_reset(ngtcp2_conn *conn, int64_t stream_id, uint64_t final_size,
                 uint16_t app_error_code, void *user_data,
                 void *stream_user_data) {
  auto h = static_cast<Handler *>(user_data);
  if (h->on_stream_reset(stream_id) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
} // namespace

int Handler::on_stream_reset(int64_t stream_id) {
  if (httpconn_) {
    auto rv = nghttp3_conn_reset_stream(httpconn_, stream_id);
    if (rv != 0) {
      std::cerr << "nghttp3_conn_reset_stream: " << nghttp3_strerror(rv)
                << std::endl;
      return -1;
    }
  }
  return 0;
}

namespace {
int rand(ngtcp2_conn *conn, uint8_t *dest, size_t destlen, ngtcp2_rand_ctx ctx,
         void *user_data) {
  auto dis = std::uniform_int_distribution<uint8_t>(0, 255);
  std::generate(dest, dest + destlen, [&dis]() { return dis(randgen); });
  return 0;
}
} // namespace

namespace {
int get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
                          size_t cidlen, void *user_data) {
  auto dis = std::uniform_int_distribution<uint8_t>(0, 255);
  auto f = [&dis]() { return dis(randgen); };

  std::generate_n(cid->data, cidlen, f);
  cid->datalen = cidlen;
  std::generate_n(token, NGTCP2_STATELESS_RESET_TOKENLEN, f);

  auto h = static_cast<Handler *>(user_data);
  h->server()->associate_cid(cid, h);

  return 0;
}
} // namespace

namespace {
int remove_connection_id(ngtcp2_conn *conn, const ngtcp2_cid *cid,
                         void *user_data) {
  auto h = static_cast<Handler *>(user_data);
  h->server()->dissociate_cid(cid);
  return 0;
}
} // namespace

namespace {
int update_key(ngtcp2_conn *conn, void *user_data) {
  auto h = static_cast<Handler *>(user_data);
  if (h->update_key() != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
} // namespace

namespace {
int path_validation(ngtcp2_conn *conn, const ngtcp2_path *path,
                    ngtcp2_path_validation_result res, void *user_data) {
  if (!config.quiet) {
    debug::path_validation(path, res);
  }
  return 0;
}
} // namespace

namespace {
int extend_max_remote_streams_bidi(ngtcp2_conn *conn, uint64_t max_streams,
                                   void *user_data) {
  auto h = static_cast<Handler *>(user_data);
  h->extend_max_remote_streams_bidi(max_streams);
  return 0;
}
} // namespace

void Handler::extend_max_remote_streams_bidi(uint64_t max_streams) {
  if (!httpconn_) {
    return;
  }

  nghttp3_conn_set_max_client_streams_bidi(httpconn_, max_streams);
}

namespace {
int http_recv_data(nghttp3_conn *conn, int64_t stream_id, const uint8_t *data,
                   size_t datalen, void *user_data, void *stream_user_data) {
  if (!config.quiet) {
    debug::print_http_data(stream_id, data, datalen);
  }
  auto h = static_cast<Handler *>(user_data);
  h->http_consume(stream_id, datalen);
  return 0;
}
} // namespace

namespace {
int http_deferred_consume(nghttp3_conn *conn, int64_t stream_id,
                          size_t nconsumed, void *user_data,
                          void *stream_user_data) {
  auto h = static_cast<Handler *>(user_data);
  h->http_consume(stream_id, nconsumed);
  return 0;
}
} // namespace

void Handler::http_consume(int64_t stream_id, size_t nconsumed) {
  ngtcp2_conn_extend_max_stream_offset(conn_, stream_id, nconsumed);
  ngtcp2_conn_extend_max_offset(conn_, nconsumed);
}

namespace {
int http_begin_request_headers(nghttp3_conn *conn, int64_t stream_id,
                               void *user_data, void *stream_user_data) {
  if (!config.quiet) {
    debug::print_http_begin_request_headers(stream_id);
  }

  auto h = static_cast<Handler *>(user_data);
  h->http_begin_request_headers(stream_id);
  return 0;
}
} // namespace

void Handler::http_begin_request_headers(int64_t stream_id) {
  auto it = streams_.find(stream_id);
  assert(it != std::end(streams_));
  auto &stream = (*it).second;

  nghttp3_conn_set_stream_user_data(httpconn_, stream_id, stream.get());
}

namespace {
int http_recv_request_header(nghttp3_conn *conn, int64_t stream_id,
                             int32_t token, nghttp3_rcbuf *name,
                             nghttp3_rcbuf *value, uint8_t flags,
                             void *user_data, void *stream_user_data) {
  if (!config.quiet) {
    debug::print_http_header(stream_id, name, value, flags);
  }

  auto h = static_cast<Handler *>(user_data);
  h->http_recv_request_header(stream_id, token, name, value);
  return 0;
}
} // namespace

void Handler::http_recv_request_header(int64_t stream_id, int32_t token,
                                       nghttp3_rcbuf *name,
                                       nghttp3_rcbuf *value) {
  auto it = streams_.find(stream_id);
  assert(it != std::end(streams_));
  auto &stream = (*it).second;
  auto v = nghttp3_rcbuf_get_buf(value);

  switch (token) {
  case NGHTTP3_QPACK_TOKEN__PATH:
    stream->uri = std::string{v.base, v.base + v.len};
    break;
  case NGHTTP3_QPACK_TOKEN__METHOD:
    stream->method = std::string{v.base, v.base + v.len};
    break;
  }
}

namespace {
int http_end_request_headers(nghttp3_conn *conn, int64_t stream_id,
                             void *user_data, void *stream_user_data) {
  if (!config.quiet) {
    debug::print_http_end_headers(stream_id);
  }

  auto h = static_cast<Handler *>(user_data);
  if (h->http_end_request_headers(stream_id) != 0) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
} // namespace

int Handler::http_end_request_headers(int64_t stream_id) {
  auto it = streams_.find(stream_id);
  assert(it != std::end(streams_));
  auto &stream = (*it).second;

  return stream->start_response(httpconn_);
}

namespace {
int http_acked_stream_data(nghttp3_conn *conn, int64_t stream_id,
                           size_t datalen, void *user_data,
                           void *stream_user_data) {
  auto h = static_cast<Handler *>(user_data);
  h->http_acked_stream_data(stream_id, datalen);
  return 0;
}
} // namespace

void Handler::http_acked_stream_data(int64_t stream_id, size_t datalen) {
  auto it = streams_.find(stream_id);
  assert(it != std::end(streams_));
  auto &stream = (*it).second;

  stream->http_acked_stream_data(datalen);
}

int Handler::setup_httpconn() {
  int rv;

  if (httpconn_) {
    return 0;
  }

  if (ngtcp2_conn_get_max_local_streams_uni(conn_) < 3) {
    std::cerr << "peer does not allow at least 3 unidirectional streams."
              << std::endl;
    return -1;
  }

  nghttp3_conn_callbacks callbacks{
      ::http_acked_stream_data, // acked_stream_data
      nullptr,                  // stream_close
      ::http_recv_data,
      ::http_deferred_consume,
      ::http_begin_request_headers,
      ::http_recv_request_header,
      ::http_end_request_headers,
      nullptr, // begin_trailers
      nullptr, // recv_trailer
      nullptr, // end_trailers
      nullptr, // begin_push_promise
      nullptr, // recv_push_promise
      nullptr, // end_push_promise
  };
  nghttp3_conn_settings settings;
  nghttp3_conn_settings_default(&settings);
  settings.qpack_max_table_capacity = 4096;
  settings.qpack_blocked_streams = 100;
  settings.num_placeholders = 10;

  auto mem = nghttp3_mem_default();

  rv = nghttp3_conn_server_new(&httpconn_, &callbacks, &settings, mem, this);
  if (rv != 0) {
    std::cerr << "nghttp3_conn_server_new: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }

  int64_t ctrl_stream_id;

  rv = ngtcp2_conn_open_uni_stream(conn_, &ctrl_stream_id, NULL);
  if (rv != 0) {
    std::cerr << "ngtcp2_conn_open_uni_stream: " << ngtcp2_strerror(rv)
              << std::endl;
    return -1;
  }

  rv = nghttp3_conn_bind_control_stream(httpconn_, ctrl_stream_id);
  if (rv != 0) {
    std::cerr << "nghttp3_conn_bind_control_stream: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }

  if (!config.quiet) {
    fprintf(stderr, "http: control stream=%" PRIx64 "\n", ctrl_stream_id);
  }

  int64_t qpack_enc_stream_id, qpack_dec_stream_id;

  rv = ngtcp2_conn_open_uni_stream(conn_, &qpack_enc_stream_id, NULL);
  if (rv != 0) {
    std::cerr << "ngtcp2_conn_open_uni_stream: " << ngtcp2_strerror(rv)
              << std::endl;
    return -1;
  }

  rv = ngtcp2_conn_open_uni_stream(conn_, &qpack_dec_stream_id, NULL);
  if (rv != 0) {
    std::cerr << "ngtcp2_conn_open_uni_stream: " << ngtcp2_strerror(rv)
              << std::endl;
    return -1;
  }

  rv = nghttp3_conn_bind_qpack_streams(httpconn_, qpack_enc_stream_id,
                                       qpack_dec_stream_id);
  if (rv != 0) {
    std::cerr << "nghttp3_conn_bind_qpack_streams: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }

  if (!config.quiet) {
    fprintf(stderr,
            "http: QPACK streams encoder=%" PRIx64 " decoder=%" PRIx64 "\n",
            qpack_enc_stream_id, qpack_dec_stream_id);
  }

  return 0;
}

namespace {
int extend_max_stream_data(ngtcp2_conn *conn, int64_t stream_id,
                           uint64_t max_data, void *user_data,
                           void *stream_user_data) {
  auto h = static_cast<Handler *>(user_data);
  if (h->extend_max_stream_data(stream_id, max_data) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
} // namespace

int Handler::extend_max_stream_data(int64_t stream_id, uint64_t max_data) {
  auto rv = nghttp3_conn_unblock_stream(httpconn_, stream_id);
  if (rv != 0) {
    std::cerr << "nghttp3_conn_unblock_stream: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }
  return 0;
}

int Handler::init(const Endpoint &ep, const sockaddr *sa, socklen_t salen,
                  const ngtcp2_cid *dcid, const ngtcp2_cid *ocid,
                  uint32_t version) {
  int rv;

  endpoint_ = const_cast<Endpoint *>(&ep);

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

  ssl_ = SSL_new(ssl_ctx_);
  auto bio = BIO_new(create_bio_method());
  BIO_set_data(bio, this);
  SSL_set_bio(ssl_, bio, bio);
  SSL_set_app_data(ssl_, this);
  SSL_set_accept_state(ssl_);
  SSL_set_msg_callback(ssl_, msg_cb);
  SSL_set_msg_callback_arg(ssl_, this);
  SSL_set_key_callback(ssl_, key_cb, this);

  auto callbacks = ngtcp2_conn_callbacks{
      nullptr, // client_initial
      ::recv_client_initial,
      recv_crypto_data,
      ::handshake_completed,
      nullptr, // recv_version_negotiation
      do_hs_encrypt,
      do_hs_decrypt,
      do_encrypt,
      do_decrypt,
      do_in_hp_mask,
      do_hp_mask,
      ::recv_stream_data,
      acked_crypto_offset,
      ::acked_stream_data_offset,
      stream_open,
      stream_close,
      nullptr, // recv_stateless_reset
      nullptr, // recv_retry
      nullptr, // extend_max_streams_bidi
      nullptr, // extend_max_streams_uni
      rand,
      get_new_connection_id,
      remove_connection_id,
      ::update_key,
      path_validation,
      nullptr, // select_preferred_addr
      ::stream_reset,
      ::extend_max_remote_streams_bidi, // extend_max_remote_streams_bidi,
      nullptr,                          // extend_max_remote_streams_uni,
      ::extend_max_stream_data,
  };

  ngtcp2_settings settings;
  ngtcp2_settings_default(&settings);
  settings.log_printf = config.quiet ? nullptr : debug::log_printf;
  settings.initial_ts = util::timestamp(loop_);
  settings.max_stream_data_bidi_local = 256_k;
  settings.max_stream_data_bidi_remote = 256_k;
  settings.max_stream_data_uni = 256_k;
  settings.max_data = 1_m;
  settings.max_streams_bidi = 100;
  settings.max_streams_uni = 3;
  settings.idle_timeout = config.timeout;
  settings.stateless_reset_token_present = 1;

  auto dis = std::uniform_int_distribution<uint8_t>(0, 255);
  std::generate(std::begin(settings.stateless_reset_token),
                std::end(settings.stateless_reset_token),
                [&dis]() { return dis(randgen); });

  scid_.datalen = NGTCP2_SV_SCIDLEN;
  std::generate(scid_.data, scid_.data + scid_.datalen,
                [&dis]() { return dis(randgen); });

  if (config.preferred_ipv4_addr.len || config.preferred_ipv6_addr.len) {
    settings.preferred_address_present = 1;
    if (config.preferred_ipv4_addr.len) {
      auto &dest = settings.preferred_address.ipv4_addr;
      const auto &addr = config.preferred_ipv4_addr;
      assert(sizeof(dest) == sizeof(addr.su.in.sin_addr));
      memcpy(&dest, &addr.su.in.sin_addr, sizeof(dest));
      settings.preferred_address.ipv4_port = htons(addr.su.in.sin_port);
    }
    if (config.preferred_ipv6_addr.len) {
      auto &dest = settings.preferred_address.ipv6_addr;
      const auto &addr = config.preferred_ipv6_addr;
      assert(sizeof(dest) == sizeof(addr.su.in6.sin6_addr));
      memcpy(&dest, &addr.su.in6.sin6_addr, sizeof(dest));
      settings.preferred_address.ipv6_port = htons(addr.su.in6.sin6_port);
    }

    auto &token = settings.preferred_address.stateless_reset_token;
    std::generate(std::begin(token), std::end(token),
                  [&dis]() { return dis(randgen); });

    pscid_.datalen = NGTCP2_SV_SCIDLEN;
    std::generate(pscid_.data, pscid_.data + pscid_.datalen,
                  [&dis]() { return dis(randgen); });
    settings.preferred_address.cid = pscid_;
  }

  auto path = ngtcp2_path{
      {ep.addr.len,
       const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(&ep.addr.su)),
       const_cast<Endpoint *>(&ep)},
      {salen, const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(sa))}};
  rv = ngtcp2_conn_server_new(&conn_, dcid, &scid_, &path, version, &callbacks,
                              &settings, this);
  if (rv != 0) {
    std::cerr << "ngtcp2_conn_server_new: " << ngtcp2_strerror(rv) << std::endl;
    return -1;
  }

  if (ocid) {
    ngtcp2_conn_set_retry_ocid(conn_, ocid);
  }

  ev_timer_again(loop_, &timer_);

  return 0;
}

int Handler::tls_handshake() {
  ERR_clear_error();

  int rv;

  if (initial_) {
    std::array<uint8_t, 8> buf;
    size_t nread;
    rv = SSL_read_early_data(ssl_, buf.data(), buf.size(), &nread);
    initial_ = false;
    switch (rv) {
    case SSL_READ_EARLY_DATA_ERROR: {
      if (!config.quiet) {
        std::cerr << "SSL_READ_EARLY_DATA_ERROR" << std::endl;
      }
      auto err = SSL_get_error(ssl_, rv);
      switch (err) {
      case SSL_ERROR_WANT_READ:
      case SSL_ERROR_WANT_WRITE: {
        return 0;
      }
      case SSL_ERROR_SSL:
        std::cerr << "TLS handshake error: "
                  << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        return NGTCP2_ERR_CRYPTO;
      default:
        std::cerr << "TLS handshake error: " << err << std::endl;
        return NGTCP2_ERR_CRYPTO;
      }
      break;
    }
    case SSL_READ_EARLY_DATA_SUCCESS:
      if (!config.quiet) {
        std::cerr << "SSL_READ_EARLY_DATA_SUCCESS" << std::endl;
      }
      // Reading 0-RTT data in TLS stream is a protocol violation.
      if (nread > 0) {
        return NGTCP2_ERR_PROTO;
      }
      break;
    case SSL_READ_EARLY_DATA_FINISH:
      if (!config.quiet) {
        std::cerr << "SSL_READ_EARLY_DATA_FINISH" << std::endl;
      }
      break;
    }
  }

  rv = SSL_do_handshake(ssl_);
  if (rv <= 0) {
    auto err = SSL_get_error(ssl_, rv);
    switch (err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      return 0;
    case SSL_ERROR_SSL:
      std::cerr << "TLS handshake error: "
                << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
      return NGTCP2_ERR_CRYPTO;
    default:
      std::cerr << "TLS handshake error: " << err << std::endl;
      return NGTCP2_ERR_CRYPTO;
    }
  }

  // SSL_do_handshake returns 1 if TLS handshake has completed.  With
  // boringSSL, it may return 1 if we have 0-RTT early data.  This is
  // a problem, but for First Implementation draft, 0-RTT early data
  // is out of interest.
  ngtcp2_conn_handshake_completed(conn_);

  if (!config.quiet) {
    std::cerr << "Negotiated cipher suite is " << SSL_get_cipher_name(ssl_)
              << std::endl;

    const unsigned char *alpn = nullptr;
    unsigned int alpnlen;

    SSL_get0_alpn_selected(ssl_, &alpn, &alpnlen);
    if (alpn) {
      std::cerr << "Negotiated ALPN is ";
      std::cerr.write(reinterpret_cast<const char *>(alpn), alpnlen);
      std::cerr << std::endl;
    }
  }

  return 0;
}

int Handler::read_tls() {
  ERR_clear_error();

  std::array<uint8_t, 4096> buf;
  size_t nread;

  for (;;) {
    auto rv = SSL_read_ex(ssl_, buf.data(), buf.size(), &nread);
    if (rv == 1) {
      std::cerr << "Read " << nread << " bytes from TLS crypto stream"
                << std::endl;
      return NGTCP2_ERR_PROTO;
    }
    auto err = SSL_get_error(ssl_, 0);
    switch (err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      return 0;
    case SSL_ERROR_SSL:
    case SSL_ERROR_ZERO_RETURN:
      std::cerr << "TLS read error: "
                << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
      return NGTCP2_ERR_CRYPTO;
    default:
      std::cerr << "TLS read error: " << err << std::endl;
      return NGTCP2_ERR_CRYPTO;
    }
  }
}

int Handler::write_server_handshake(const uint8_t *data, size_t datalen) {
  write_server_handshake(shandshake_, shandshake_idx_, data, datalen);

  return 0;
}

void Handler::write_server_handshake(std::deque<Buffer> &dest, size_t &idx,
                                     const uint8_t *data, size_t datalen) {
  dest.emplace_back(data, datalen);
  ++idx;

  auto &buf = dest.back();

  ngtcp2_conn_submit_crypto_data(conn_, tx_crypto_level_, buf.rpos(),
                                 buf.size());
}

size_t Handler::read_server_handshake(const uint8_t **pdest) {
  if (shandshake_idx_ == shandshake_.size()) {
    return 0;
  }
  auto &v = shandshake_[shandshake_idx_++];
  *pdest = v.rpos();
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

int Handler::recv_client_initial(const ngtcp2_cid *dcid) {
  int rv;
  std::array<uint8_t, 32> initial_secret, secret;

  rv = crypto::derive_initial_secret(
      initial_secret.data(), initial_secret.size(), dcid,
      reinterpret_cast<const uint8_t *>(NGTCP2_INITIAL_SALT),
      str_size(NGTCP2_INITIAL_SALT));
  if (rv != 0) {
    std::cerr << "crypto::derive_initial_secret() failed" << std::endl;
    return -1;
  }

  if (!config.quiet && config.show_secret) {
    debug::print_initial_secret(initial_secret.data(), initial_secret.size());
  }

  crypto::prf_sha256(hs_crypto_ctx_);
  crypto::aead_aes_128_gcm(hs_crypto_ctx_);

  rv = crypto::derive_server_initial_secret(secret.data(), secret.size(),
                                            initial_secret.data(),
                                            initial_secret.size());
  if (rv != 0) {
    std::cerr << "crypto::derive_server_initial_secret() failed" << std::endl;
    return -1;
  }

  std::array<uint8_t, 16> key, iv, hp;
  auto keylen = crypto::derive_packet_protection_key(
      key.data(), key.size(), secret.data(), secret.size(), hs_crypto_ctx_);
  if (keylen < 0) {
    return -1;
  }

  auto ivlen = crypto::derive_packet_protection_iv(
      iv.data(), iv.size(), secret.data(), secret.size(), hs_crypto_ctx_);
  if (ivlen < 0) {
    return -1;
  }

  auto hplen = crypto::derive_header_protection_key(
      hp.data(), hp.size(), secret.data(), secret.size(), hs_crypto_ctx_);
  if (hplen < 0) {
    return -1;
  }

  if (!config.quiet && config.show_secret) {
    debug::print_server_in_secret(secret.data(), secret.size());
    debug::print_server_pp_key(key.data(), keylen);
    debug::print_server_pp_iv(iv.data(), ivlen);
    debug::print_server_pp_hp(hp.data(), hplen);
  }

  ngtcp2_conn_install_initial_tx_keys(conn_, key.data(), keylen, iv.data(),
                                      ivlen, hp.data(), hplen);

  rv = crypto::derive_client_initial_secret(secret.data(), secret.size(),
                                            initial_secret.data(),
                                            initial_secret.size());
  if (rv != 0) {
    std::cerr << "crypto::derive_client_initial_secret() failed" << std::endl;
    return -1;
  }

  keylen = crypto::derive_packet_protection_key(
      key.data(), key.size(), secret.data(), secret.size(), hs_crypto_ctx_);
  if (keylen < 0) {
    return -1;
  }

  ivlen = crypto::derive_packet_protection_iv(
      iv.data(), iv.size(), secret.data(), secret.size(), hs_crypto_ctx_);
  if (ivlen < 0) {
    return -1;
  }

  hplen = crypto::derive_header_protection_key(
      hp.data(), hp.size(), secret.data(), secret.size(), hs_crypto_ctx_);
  if (hplen < 0) {
    return -1;
  }

  if (!config.quiet && config.show_secret) {
    debug::print_client_in_secret(secret.data(), secret.size());
    debug::print_client_pp_key(key.data(), keylen);
    debug::print_client_pp_iv(iv.data(), ivlen);
    debug::print_client_pp_hp(hp.data(), hplen);
  }

  ngtcp2_conn_install_initial_rx_keys(conn_, key.data(), keylen, iv.data(),
                                      ivlen, hp.data(), hplen);

  return 0;
}

ssize_t Handler::hs_encrypt_data(uint8_t *dest, size_t destlen,
                                 const uint8_t *plaintext, size_t plaintextlen,
                                 const uint8_t *key, size_t keylen,
                                 const uint8_t *nonce, size_t noncelen,
                                 const uint8_t *ad, size_t adlen) {
  return crypto::encrypt(dest, destlen, plaintext, plaintextlen, hs_crypto_ctx_,
                         key, keylen, nonce, noncelen, ad, adlen);
}

ssize_t Handler::hs_decrypt_data(uint8_t *dest, size_t destlen,
                                 const uint8_t *ciphertext,
                                 size_t ciphertextlen, const uint8_t *key,
                                 size_t keylen, const uint8_t *nonce,
                                 size_t noncelen, const uint8_t *ad,
                                 size_t adlen) {
  return crypto::decrypt(dest, destlen, ciphertext, ciphertextlen,
                         hs_crypto_ctx_, key, keylen, nonce, noncelen, ad,
                         adlen);
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

ssize_t Handler::in_hp_mask(uint8_t *dest, size_t destlen, const uint8_t *key,
                            size_t keylen, const uint8_t *sample,
                            size_t samplelen) {
  return crypto::hp_mask(dest, destlen, hs_crypto_ctx_, key, keylen, sample,
                         samplelen);
}

ssize_t Handler::hp_mask(uint8_t *dest, size_t destlen, const uint8_t *key,
                         size_t keylen, const uint8_t *sample,
                         size_t samplelen) {
  return crypto::hp_mask(dest, destlen, crypto_ctx_, key, keylen, sample,
                         samplelen);
}

int Handler::do_handshake_read_once(const ngtcp2_path *path,
                                    const uint8_t *data, size_t datalen) {
  auto rv = ngtcp2_conn_read_handshake(conn_, path, data, datalen,
                                       util::timestamp(loop_));
  if (rv != 0) {
    std::cerr << "ngtcp2_conn_read_handshake: " << ngtcp2_strerror(rv)
              << std::endl;
    if (!last_error_.code) {
      last_error_ = quicErrorTransport(rv);
    }
    return -1;
  }
  return 0;
}

ssize_t Handler::do_handshake_write_once() {
  auto nwrite = ngtcp2_conn_write_handshake(conn_, sendbuf_.wpos(), max_pktlen_,
                                            util::timestamp(loop_));
  if (nwrite < 0) {
    std::cerr << "ngtcp2_conn_write_handshake: " << ngtcp2_strerror(nwrite)
              << std::endl;
    last_error_ = quicErrorTransport(nwrite);
    return -1;
  }

  if (nwrite == 0) {
    return 0;
  }

  sendbuf_.push(nwrite);

  auto rv = server_->send_packet(*endpoint_, remote_addr_, sendbuf_);
  if (rv == NETWORK_ERR_SEND_NON_FATAL) {
    schedule_retransmit();
    return rv;
  }
  if (rv != NETWORK_ERR_OK) {
    return rv;
  }

  return nwrite;
}

int Handler::do_handshake(const ngtcp2_path *path, const uint8_t *data,
                          size_t datalen) {
  if (datalen) {
    auto rv = do_handshake_read_once(path, data, datalen);
    if (rv != 0) {
      return rv;
    }
  }

  if (sendbuf_.size() > 0) {
    auto rv = server_->send_packet(*endpoint_, remote_addr_, sendbuf_);
    if (rv != NETWORK_ERR_OK) {
      return rv;
    }
  }

  for (;;) {
    auto nwrite = do_handshake_write_once();
    if (nwrite < 0) {
      return nwrite;
    }
    if (nwrite == 0) {
      return 0;
    }
  }
}

void Handler::update_endpoint(const ngtcp2_addr *addr) {
  endpoint_ = static_cast<Endpoint *>(addr->user_data);
  assert(endpoint_);
}

void Handler::update_remote_addr(const ngtcp2_addr *addr) {
  remote_addr_.len = addr->addrlen;
  memcpy(&remote_addr_.su, addr->addr, addr->addrlen);
}

int Handler::feed_data(const Endpoint &ep, const sockaddr *sa, socklen_t salen,
                       uint8_t *data, size_t datalen) {
  int rv;

  auto path = ngtcp2_path{
      {ep.addr.len,
       const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(&ep.addr.su)),
       const_cast<Endpoint *>(&ep)},
      {salen, const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(sa))}};

  if (ngtcp2_conn_get_handshake_completed(conn_)) {
    rv = ngtcp2_conn_read_pkt(conn_, &path, data, datalen,
                              util::timestamp(loop_));
    if (rv != 0) {
      std::cerr << "ngtcp2_conn_read_pkt: " << ngtcp2_strerror(rv) << std::endl;
      if (rv == NGTCP2_ERR_DRAINING) {
        start_draining_period();
        return NETWORK_ERR_CLOSE_WAIT;
      }
      if (!last_error_.code) {
        last_error_ = quicErrorTransport(rv);
      }
      return handle_error();
    }

    return 0;
  }

  rv = do_handshake(&path, data, datalen);
  if (rv != 0) {
    return handle_error();
  }

  return 0;
}

int Handler::on_read(const Endpoint &ep, const sockaddr *sa, socklen_t salen,
                     uint8_t *data, size_t datalen) {
  int rv;

  rv = feed_data(ep, sa, salen, data, datalen);
  if (rv != 0) {
    return rv;
  }

  timer_.repeat = static_cast<ev_tstamp>(ngtcp2_conn_get_idle_timeout(conn_)) /
                  NGTCP2_SECONDS;
  ev_timer_again(loop_, &timer_);

  return 0;
}

int Handler::on_write() {
  int rv;

  if (ngtcp2_conn_is_in_closing_period(conn_)) {
    return 0;
  }

  if (sendbuf_.size() > 0) {
    auto rv = server_->send_packet(*endpoint_, remote_addr_, sendbuf_);
    if (rv != NETWORK_ERR_OK) {
      return rv;
    }
  }

  assert(sendbuf_.left() >= max_pktlen_);

  if (!ngtcp2_conn_get_handshake_completed(conn_)) {
    rv = do_handshake(nullptr, nullptr, 0);
    if (rv == NETWORK_ERR_SEND_NON_FATAL) {
      schedule_retransmit();
    }
    if (rv != NETWORK_ERR_OK) {
      return rv;
    }
  }

  rv = write_streams();
  if (rv != 0) {
    if (rv == NETWORK_ERR_SEND_NON_FATAL) {
      schedule_retransmit();
    }
    return rv;
  }

  if (!ngtcp2_conn_get_handshake_completed(conn_)) {
    schedule_retransmit();
    return 0;
  }

  PathStorage path;

  for (;;) {
    auto n = ngtcp2_conn_write_pkt(conn_, &path.path, sendbuf_.wpos(),
                                   max_pktlen_, util::timestamp(loop_));
    if (n < 0) {
      std::cerr << "ngtcp2_conn_write_pkt: " << ngtcp2_strerror(n) << std::endl;
      last_error_ = quicErrorTransport(n);
      return handle_error();
    }
    if (n == 0) {
      break;
    }

    sendbuf_.push(n);

    update_endpoint(&path.path.local);
    update_remote_addr(&path.path.remote);

    auto rv = server_->send_packet(*endpoint_, remote_addr_, sendbuf_);
    if (rv == NETWORK_ERR_SEND_NON_FATAL) {
      schedule_retransmit();
      return rv;
    }
    if (rv != NETWORK_ERR_OK) {
      return rv;
    }
  }

  schedule_retransmit();
  return 0;
}

int Handler::write_streams() {
  if (!httpconn_) {
    return 0;
  }

  std::array<nghttp3_vec, 16> vec;
  int rv;

  if (ngtcp2_conn_get_max_data_left(conn_) == 0) {
    return 0;
  }

  for (;;) {
    int64_t stream_id;
    int fin;

    auto sveccnt = nghttp3_conn_writev_stream(httpconn_, &stream_id, &fin,
                                              vec.data(), vec.size());
    if (sveccnt < 0) {
      std::cerr << "nghttp3_conn_writev_stream: " << nghttp3_strerror(sveccnt)
                << std::endl;
      last_error_ = quicErrorApplication(sveccnt);
      return handle_error();
    }

    if (sveccnt == 0) {
      break;
    }

    ssize_t ndatalen;
    PathStorage path;
    auto v = vec.data();
    auto vcnt = static_cast<size_t>(sveccnt);
    for (;;) {
      auto nwrite = ngtcp2_conn_writev_stream(
          conn_, &path.path, sendbuf_.wpos(), max_pktlen_, &ndatalen, stream_id,
          fin, reinterpret_cast<const ngtcp2_vec *>(v), vcnt,
          util::timestamp(loop_));
      if (nwrite < 0) {
        auto should_break = false;
        switch (nwrite) {
        case NGTCP2_ERR_STREAM_DATA_BLOCKED:
          if (ngtcp2_conn_get_max_data_left(conn_) == 0) {
            return 0;
          }

          rv = nghttp3_conn_block_stream(httpconn_, stream_id);
          if (rv != 0) {
            std::cerr << "nghttp3_conn_block_stream: " << nghttp3_strerror(rv)
                      << std::endl;
            last_error_ = quicErrorApplication(rv);
            return handle_error();
          }
          should_break = true;
          break;
        case NGTCP2_ERR_STREAM_SHUT_WR:
          should_break = true;
          break;
        }

        if (should_break) {
          break;
        }

        std::cerr << "ngtcp2_conn_write_stream: " << ngtcp2_strerror(nwrite)
                  << std::endl;
        last_error_ = quicErrorTransport(nwrite);
        return handle_error();
      }

      if (nwrite == 0) {
        // We are congestion limited.
        return 0;
      }

      sendbuf_.push(nwrite);

      if (ndatalen > 0) {
        rv = nghttp3_conn_add_write_offset(httpconn_, stream_id, ndatalen);
        if (rv != 0) {
          std::cerr << "nghttp3_conn_add_write_offset: " << nghttp3_strerror(rv)
                    << std::endl;
          last_error_ = quicErrorApplication(rv);
          return handle_error();
        }
      }

      update_endpoint(&path.path.local);
      update_remote_addr(&path.path.remote);

      auto rv = server_->send_packet(*endpoint_, remote_addr_, sendbuf_);
      if (rv != NETWORK_ERR_OK) {
        return rv;
      }

      if (ndatalen > 0) {
        break;
      }
    }
  }

  return 0;
}

bool Handler::draining() const { return draining_; }

void Handler::start_draining_period() {
  draining_ = true;

  ev_timer_stop(loop_, &rttimer_);

  timer_.repeat = 15.;
  ev_timer_again(loop_, &timer_);

  if (!config.quiet) {
    std::cerr << "Draining period has started" << std::endl;
  }
}

int Handler::start_closing_period() {
  if (!conn_ || ngtcp2_conn_is_in_closing_period(conn_)) {
    return 0;
  }

  ev_timer_stop(loop_, &rttimer_);

  timer_.repeat = 15.;
  ev_timer_again(loop_, &timer_);

  if (!config.quiet) {
    std::cerr << "Closing period has started" << std::endl;
  }

  sendbuf_.reset();
  assert(sendbuf_.left() >= max_pktlen_);

  conn_closebuf_ = std::make_unique<Buffer>(NGTCP2_MAX_PKTLEN_IPV4);

  PathStorage path;
  if (last_error_.type == QUICErrorType::Transport) {
    auto n = ngtcp2_conn_write_connection_close(
        conn_, &path.path, conn_closebuf_->wpos(), max_pktlen_,
        last_error_.code, util::timestamp(loop_));
    if (n < 0) {
      std::cerr << "ngtcp2_conn_write_connection_close: " << ngtcp2_strerror(n)
                << std::endl;
      return -1;
    }
    conn_closebuf_->push(n);
  } else {
    auto n = ngtcp2_conn_write_application_close(
        conn_, &path.path, conn_closebuf_->wpos(), max_pktlen_,
        last_error_.code, util::timestamp(loop_));
    if (n < 0) {
      std::cerr << "ngtcp2_conn_write_application_close: " << ngtcp2_strerror(n)
                << std::endl;
      return -1;
    }
    conn_closebuf_->push(n);
  }

  update_endpoint(&path.path.local);
  update_remote_addr(&path.path.remote);

  return 0;
}

int Handler::handle_error() {
  int rv;

  rv = start_closing_period();
  if (rv != 0) {
    return -1;
  }

  rv = send_conn_close();
  if (rv != NETWORK_ERR_OK) {
    return rv;
  }

  return NETWORK_ERR_CLOSE_WAIT;
}

int Handler::send_conn_close() {
  if (!config.quiet) {
    std::cerr << "Closing Period: TX CONNECTION_CLOSE" << std::endl;
  }

  assert(conn_closebuf_ && conn_closebuf_->size());

  if (sendbuf_.size() == 0) {
    std::copy_n(conn_closebuf_->rpos(), conn_closebuf_->size(),
                sendbuf_.wpos());
    sendbuf_.push(conn_closebuf_->size());
  }

  return server_->send_packet(*endpoint_, remote_addr_, sendbuf_);
}

void Handler::schedule_retransmit() {
  auto expiry = ngtcp2_conn_get_expiry(conn_);
  auto now = util::timestamp(loop_);
  auto t = expiry < now ? 1e-9
                        : static_cast<ev_tstamp>(expiry - now) / NGTCP2_SECONDS;
  if (!config.quiet) {
    std::cerr << "Set timer=" << std::fixed << t << "s" << std::endl;
  }
  rttimer_.repeat = t;
  ev_timer_again(loop_, &rttimer_);
}

int Handler::recv_stream_data(int64_t stream_id, uint8_t fin,
                              const uint8_t *data, size_t datalen) {
  if (!config.quiet) {
    debug::print_stream_data(stream_id, data, datalen);
  }

  if (!httpconn_) {
    return 0;
  }

  auto nconsumed =
      nghttp3_conn_read_stream(httpconn_, stream_id, data, datalen, fin);
  if (nconsumed < 0) {
    std::cerr << "nghttp3_conn_read_stream: " << nghttp3_strerror(nconsumed)
              << std::endl;
    last_error_ = quicErrorApplication(nconsumed);
    return -1;
  }

  ngtcp2_conn_extend_max_stream_offset(conn_, stream_id, nconsumed);
  ngtcp2_conn_extend_max_offset(conn_, nconsumed);

  return 0;
}

int Handler::update_key() {
  int rv;
  std::array<uint8_t, 64> secret, key, iv;

  ++nkey_update_;

  auto secretlen = crypto::update_traffic_secret(
      secret.data(), secret.size(), tx_secret_.data(), tx_secret_.size(),
      crypto_ctx_);
  if (secretlen < 0) {
    return -1;
  }

  tx_secret_.assign(std::begin(secret), std::end(secret));

  auto keylen = crypto::derive_packet_protection_key(
      key.data(), key.size(), secret.data(), secretlen, crypto_ctx_);
  if (keylen < 0) {
    return -1;
  }

  auto ivlen = crypto::derive_packet_protection_iv(
      iv.data(), iv.size(), secret.data(), secretlen, crypto_ctx_);
  if (ivlen < 0) {
    return -1;
  }

  rv = ngtcp2_conn_update_tx_key(conn_, key.data(), keylen, iv.data(), ivlen);
  if (rv != 0) {
    std::cerr << "ngtcp2_conn_update_tx_key: " << ngtcp2_strerror(rv)
              << std::endl;
    return -1;
  }

  if (!config.quiet) {
    std::cerr << "server_application_traffic " << nkey_update_ << std::endl;
    debug::print_secrets(secret.data(), secretlen, key.data(), keylen,
                         iv.data(), ivlen);
  }

  secretlen = crypto::update_traffic_secret(secret.data(), secret.size(),
                                            rx_secret_.data(),
                                            rx_secret_.size(), crypto_ctx_);
  if (secretlen < 0) {
    return -1;
  }

  rx_secret_.assign(std::begin(secret), std::end(secret));

  keylen = crypto::derive_packet_protection_key(
      key.data(), key.size(), secret.data(), secretlen, crypto_ctx_);
  if (keylen < 0) {
    return -1;
  }

  ivlen = crypto::derive_packet_protection_iv(
      iv.data(), iv.size(), secret.data(), secretlen, crypto_ctx_);
  if (ivlen < 0) {
    return -1;
  }

  rv = ngtcp2_conn_update_rx_key(conn_, key.data(), keylen, iv.data(), ivlen);
  if (rv != 0) {
    std::cerr << "ngtcp2_conn_update_rx_key: " << ngtcp2_strerror(rv)
              << std::endl;
    return -1;
  }

  if (!config.quiet) {
    std::cerr << "client_application_traffic " << nkey_update_ << std::endl;
    debug::print_secrets(secret.data(), secretlen, key.data(), keylen,
                         iv.data(), ivlen);
  }

  return 0;
}

const ngtcp2_cid *Handler::scid() const { return &scid_; }

const ngtcp2_cid *Handler::pscid() const { return &pscid_; }

const ngtcp2_cid *Handler::rcid() const { return &rcid_; }

Server *Handler::server() const { return server_; }

const Address &Handler::remote_addr() const { return remote_addr_; }

ngtcp2_conn *Handler::conn() const { return conn_; }

namespace {
size_t remove_tx_stream_data(std::deque<Buffer> &d, size_t &idx,
                             uint64_t &tx_offset, uint64_t offset) {
  size_t len = 0;
  for (; !d.empty() && tx_offset + d.front().bufsize() <= offset;) {
    --idx;
    auto &v = d.front();
    len += v.bufsize();
    tx_offset += v.bufsize();
    d.pop_front();
  }
  return len;
}
} // namespace

void Handler::remove_tx_crypto_data(uint64_t offset, size_t datalen) {
  ::remove_tx_stream_data(shandshake_, shandshake_idx_, tx_crypto_offset_,
                          offset + datalen);
}

int Handler::on_stream_close(int64_t stream_id) {
  if (!config.quiet) {
    std::cerr << "QUIC stream " << stream_id << " closed" << std::endl;
  }

  auto it = streams_.find(stream_id);
  assert(it != std::end(streams_));

  if (httpconn_) {
    auto rv = nghttp3_conn_close_stream(httpconn_, stream_id);
    if (rv != 0) {
      std::cerr << "nghttp3_conn_close_stream: " << nghttp3_strerror(rv)
                << std::endl;
      last_error_ = quicErrorApplication(rv);
      return -1;
    }
  }

  streams_.erase(it);

  return 0;
}

void Handler::shutdown_read(int64_t stream_id, int app_error_code) {
  ngtcp2_conn_shutdown_stream_read(conn_, stream_id, app_error_code);
}

void Handler::set_tls_alert(uint8_t alert) {
  last_error_ = quicErrorTransportTLS(alert);
}

namespace {
void swritecb(struct ev_loop *loop, ev_io *w, int revents) {
  ev_io_stop(loop, w);

  auto ep = static_cast<Endpoint *>(w->data);
  // TODO At the moment, this triggers writes to the all endpoints,
  // which is not ideal.
  ep->server->on_write();
}
} // namespace

namespace {
void sreadcb(struct ev_loop *loop, ev_io *w, int revents) {
  auto ep = static_cast<Endpoint *>(w->data);

  ep->server->on_read(*ep);
}
} // namespace

namespace {
void siginthandler(struct ev_loop *loop, ev_signal *watcher, int revents) {
  ev_break(loop, EVBREAK_ALL);
}
} // namespace

Server::Server(struct ev_loop *loop, SSL_CTX *ssl_ctx)
    : loop_(loop), ssl_ctx_(ssl_ctx), token_crypto_ctx_{} {
  ev_signal_init(&sigintev_, siginthandler, SIGINT);

  crypto::aead_aes_128_gcm(token_crypto_ctx_);
  crypto::prf_sha256(token_crypto_ctx_);

  auto dis = std::uniform_int_distribution<uint8_t>(0, 255);
  std::generate(std::begin(token_secret_), std::end(token_secret_),
                [&dis]() { return dis(randgen); });
}

Server::~Server() {
  disconnect();
  close();
}

void Server::disconnect() {
  config.tx_loss_prob = 0;

  for (auto &ep : endpoints_) {
    ev_io_stop(loop_, &ep.rev);
  }

  ev_signal_stop(loop_, &sigintev_);

  while (!handlers_.empty()) {
    auto it = std::begin(handlers_);
    auto &h = (*it).second;

    h->handle_error();

    remove(it);
  }
}

void Server::close() {
  for (auto &ep : endpoints_) {
    ev_io_stop(loop_, &ep.wev);
    ::close(ep.fd);
  }

  endpoints_.clear();
}

namespace {
int create_sock(Address &local_addr, const char *addr, const char *port,
                int family) {
  addrinfo hints{};
  addrinfo *res, *rp;
  int rv;
  int val = 1;

  hints.ai_family = family;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;

  if (strcmp("addr", "*") == 0) {
    addr = nullptr;
  }

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

    if (rp->ai_family == AF_INET6) {
      if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val,
                     static_cast<socklen_t>(sizeof(val))) == -1) {
        close(fd);
        continue;
      }
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

  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val,
                 static_cast<socklen_t>(sizeof(val))) == -1) {
    return -1;
  }

  socklen_t len = sizeof(local_addr.su.storage);
  rv = getsockname(fd, &local_addr.su.sa, &len);
  if (rv == -1) {
    std::cerr << "getsockname: " << strerror(errno) << std::endl;
    return -1;
  }
  local_addr.len = len;

  return fd;
}

} // namespace

namespace {
int add_endpoint(std::vector<Endpoint> &endpoints, const char *addr,
                 const char *port, int af) {
  Address dest;
  auto fd = create_sock(dest, addr, port, af);
  if (fd == -1) {
    return -1;
  }

  endpoints.emplace_back();
  auto &ep = endpoints.back();
  ep.addr = dest;
  ep.fd = fd;
  ev_io_init(&ep.wev, swritecb, 0, EV_WRITE);
  ev_io_init(&ep.rev, sreadcb, 0, EV_READ);

  return 0;
}
} // namespace

namespace {
int add_endpoint(std::vector<Endpoint> &endpoints, const Address &addr) {
  auto fd = socket(addr.su.sa.sa_family, SOCK_DGRAM, 0);
  if (fd == -1) {
    std::cerr << "socket: " << strerror(errno) << std::endl;
    return -1;
  }

  int val = 1;
  if (addr.su.sa.sa_family == AF_INET6 &&
      setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val,
                 static_cast<socklen_t>(sizeof(val)))) {
    std::cerr << "setsockopt: " << strerror(errno) << std::endl;
    close(fd);
    return -1;
  }

  if (bind(fd, &addr.su.sa, addr.len) == -1) {
    std::cerr << "bind: " << strerror(errno) << std::endl;
    close(fd);
    return -1;
  }

  endpoints.emplace_back(Endpoint{});
  auto &ep = endpoints.back();
  ep.addr = addr;
  ep.fd = fd;
  ev_io_init(&ep.wev, swritecb, 0, EV_WRITE);
  ev_io_init(&ep.rev, sreadcb, 0, EV_READ);

  return 0;
}
} // namespace

int Server::init(const char *addr, const char *port) {
  endpoints_.reserve(4);

  auto ready = false;
  if (!util::numeric_host(addr, AF_INET6) &&
      add_endpoint(endpoints_, addr, port, AF_INET) == 0) {
    ready = true;
  }
  if (!util::numeric_host(addr, AF_INET) &&
      add_endpoint(endpoints_, addr, port, AF_INET6) == 0) {
    ready = true;
  }
  if (!ready) {
    return -1;
  }

  if (config.preferred_ipv4_addr.len &&
      add_endpoint(endpoints_, config.preferred_ipv4_addr) != 0) {
    return -1;
  }
  if (config.preferred_ipv6_addr.len &&
      add_endpoint(endpoints_, config.preferred_ipv6_addr) != 0) {
    return -1;
  }

  for (auto &ep : endpoints_) {
    ep.server = this;
    ep.wev.data = &ep;
    ep.rev.data = &ep;

    ev_io_set(&ep.wev, ep.fd, EV_WRITE);
    ev_io_set(&ep.rev, ep.fd, EV_READ);

    ev_io_start(loop_, &ep.rev);
  }

  ev_signal_start(loop_, &sigintev_);

  return 0;
}

int Server::on_write() {
  for (auto it = std::cbegin(handlers_); it != std::cend(handlers_);) {
    auto h = it->second.get();
    auto rv = h->on_write();
    switch (rv) {
    case 0:
    case NETWORK_ERR_CLOSE_WAIT:
      ++it;
      continue;
    case NETWORK_ERR_SEND_NON_FATAL:
      return NETWORK_ERR_SEND_NON_FATAL;
    }
    it = remove(it);
  }

  return NETWORK_ERR_OK;
}

int Server::on_read(Endpoint &ep) {
  sockaddr_union su;
  socklen_t addrlen;
  std::array<uint8_t, 64_k> buf;
  int rv;
  ngtcp2_pkt_hd hd;

  while (true) {
    addrlen = sizeof(su);
    auto nread =
        recvfrom(ep.fd, buf.data(), buf.size(), MSG_DONTWAIT, &su.sa, &addrlen);
    if (nread == -1) {
      if (!(errno == EAGAIN || errno == ENOTCONN)) {
        std::cerr << "recvfrom: " << strerror(errno) << std::endl;
      }
      return 0;
    }

    if (!config.quiet) {
      std::cerr << "Received packet: local="
                << util::straddr(&ep.addr.su.sa, ep.addr.len)
                << " remote=" << util::straddr(&su.sa, addrlen) << " " << nread
                << " bytes" << std::endl;
    }

    if (debug::packet_lost(config.rx_loss_prob)) {
      if (!config.quiet) {
        std::cerr << "** Simulated incoming packet loss **" << std::endl;
      }
      return 0;
    }

    if (nread == 0) {
      continue;
    }

    if (buf[0] & 0x80) {
      rv = ngtcp2_pkt_decode_hd_long(&hd, buf.data(), nread);
    } else {
      // TODO For Short packet, we just need DCID.
      rv =
          ngtcp2_pkt_decode_hd_short(&hd, buf.data(), nread, NGTCP2_SV_SCIDLEN);
    }
    if (rv < 0) {
      std::cerr << "Could not decode QUIC packet header: "
                << ngtcp2_strerror(rv) << std::endl;
      return 0;
    }

    auto dcid_key = util::make_cid_key(&hd.dcid);

    auto handler_it = handlers_.find(dcid_key);
    if (handler_it == std::end(handlers_)) {
      auto ctos_it = ctos_.find(dcid_key);
      if (ctos_it == std::end(ctos_)) {
        rv = ngtcp2_accept(&hd, buf.data(), nread);
        if (rv == -1) {
          if (!config.quiet) {
            std::cerr << "Unexpected packet received: length=" << nread
                      << std::endl;
          }
          return 0;
        }

        if (rv == 1) {
          if (!config.quiet) {
            std::cerr << "Unsupported version: Send Version Negotiation"
                      << std::endl;
          }
          send_version_negotiation(&hd, ep, &su.sa, addrlen);
          return 0;
        }

        ngtcp2_cid ocid;
        ngtcp2_cid *pocid = nullptr;
        if (config.validate_addr && hd.type == NGTCP2_PKT_INITIAL) {
          std::cerr << "Perform stateless address validation" << std::endl;
          if (hd.tokenlen == 0 ||
              verify_token(&ocid, &hd, &su.sa, addrlen) != 0) {
            send_retry(&hd, ep, &su.sa, addrlen);
            return 0;
          }
          pocid = &ocid;
        }

        auto h = std::make_unique<Handler>(loop_, ssl_ctx_, this, &hd.dcid);
        h->init(ep, &su.sa, addrlen, &hd.scid, pocid, hd.version);

        if (h->on_read(ep, &su.sa, addrlen, buf.data(), nread) != 0) {
          return 0;
        }
        rv = h->on_write();
        switch (rv) {
        case 0:
          break;
        case NETWORK_ERR_SEND_NON_FATAL:
          break;
        default:
          return 0;
        }

        auto scid = h->scid();
        auto scid_key = util::make_cid_key(scid);
        ctos_.emplace(dcid_key, scid_key);

        auto pscid = h->pscid();
        if (pscid->datalen) {
          auto pscid_key = util::make_cid_key(pscid);
          ctos_.emplace(pscid_key, scid_key);
        }

        handlers_.emplace(scid_key, std::move(h));
        return 0;
      }
      if (!config.quiet) {
        std::cerr << "Forward CID=" << util::format_hex((*ctos_it).first)
                  << " to CID=" << util::format_hex((*ctos_it).second)
                  << std::endl;
      }
      handler_it = handlers_.find((*ctos_it).second);
      assert(handler_it != std::end(handlers_));
    }

    auto h = (*handler_it).second.get();
    if (ngtcp2_conn_is_in_closing_period(h->conn())) {
      // TODO do exponential backoff.
      rv = h->send_conn_close();
      switch (rv) {
      case 0:
      case NETWORK_ERR_SEND_NON_FATAL:
        break;
      default:
        remove(handler_it);
      }
      return 0;
    }
    if (h->draining()) {
      return 0;
    }

    rv = h->on_read(ep, &su.sa, addrlen, buf.data(), nread);
    if (rv != 0) {
      if (rv != NETWORK_ERR_CLOSE_WAIT) {
        remove(handler_it);
      }
      return 0;
    }

    rv = h->on_write();
    switch (rv) {
    case 0:
    case NETWORK_ERR_CLOSE_WAIT:
      break;
    case NETWORK_ERR_SEND_NON_FATAL:
      break;
    default:
      remove(handler_it);
    }
  }
  return 0;
}

namespace {
uint32_t generate_reserved_version(const sockaddr *sa, socklen_t salen,
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

int Server::send_version_negotiation(const ngtcp2_pkt_hd *chd, Endpoint &ep,
                                     const sockaddr *sa, socklen_t salen) {
  Buffer buf{NGTCP2_MAX_PKTLEN_IPV4};
  std::array<uint32_t, 2> sv;

  sv[0] = generate_reserved_version(sa, salen, chd->version);
  sv[1] = NGTCP2_PROTO_VER_D19;

  auto nwrite = ngtcp2_pkt_write_version_negotiation(
      buf.wpos(), buf.left(),
      std::uniform_int_distribution<uint8_t>(
          0, std::numeric_limits<uint8_t>::max())(randgen),
      &chd->scid, &chd->dcid, sv.data(), sv.size());
  if (nwrite < 0) {
    std::cerr << "ngtcp2_pkt_write_version_negotiation: "
              << ngtcp2_strerror(nwrite) << std::endl;
    return -1;
  }

  buf.push(nwrite);

  Address remote_addr;
  remote_addr.len = salen;
  memcpy(&remote_addr.su.sa, sa, salen);

  if (send_packet(ep, remote_addr, buf) != NETWORK_ERR_OK) {
    return -1;
  }

  return 0;
}

int Server::send_retry(const ngtcp2_pkt_hd *chd, Endpoint &ep,
                       const sockaddr *sa, socklen_t salen) {
  std::array<char, NI_MAXHOST> host;
  std::array<char, NI_MAXSERV> port;
  int rv;

  rv = getnameinfo(sa, salen, host.data(), host.size(), port.data(),
                   port.size(), NI_NUMERICHOST | NI_NUMERICSERV);
  if (rv != 0) {
    std::cerr << "getnameinfo: " << gai_strerror(rv) << std::endl;
    return -1;
  }

  if (!config.quiet) {
    std::cerr << "Sending Retry packet to [" << host.data()
              << "]:" << port.data() << std::endl;
  }

  std::array<uint8_t, 256> token;
  size_t tokenlen = token.size();

  if (generate_token(token.data(), tokenlen, sa, salen, &chd->dcid) != 0) {
    return -1;
  }

  if (!config.quiet) {
    std::cerr << "Generated address validation token:" << std::endl;
    util::hexdump(stderr, token.data(), tokenlen);
  }

  Buffer buf{NGTCP2_MAX_PKTLEN_IPV4};
  ngtcp2_pkt_hd hd;

  hd.version = chd->version;
  hd.flags = NGTCP2_PKT_FLAG_LONG_FORM;
  hd.type = NGTCP2_PKT_RETRY;
  hd.pkt_num = 0;
  hd.token = NULL;
  hd.tokenlen = 0;
  hd.len = 0;
  hd.dcid = chd->scid;
  hd.scid.datalen = NGTCP2_SV_SCIDLEN;
  auto dis = std::uniform_int_distribution<uint8_t>(0, 255);
  std::generate(hd.scid.data, hd.scid.data + hd.scid.datalen,
                [&dis]() { return dis(randgen); });

  auto nwrite = ngtcp2_pkt_write_retry(buf.wpos(), buf.left(), &hd, &chd->dcid,
                                       token.data(), tokenlen);
  if (nwrite < 0) {
    std::cerr << "ngtcp2_pkt_write_retry: " << ngtcp2_strerror(nwrite)
              << std::endl;
    return -1;
  }

  buf.push(nwrite);

  Address remote_addr;
  remote_addr.len = salen;
  memcpy(&remote_addr.su.sa, sa, salen);

  if (send_packet(ep, remote_addr, buf) != NETWORK_ERR_OK) {
    return -1;
  }

  return 0;
}

int Server::derive_token_key(uint8_t *key, size_t &keylen, uint8_t *iv,
                             size_t &ivlen, const uint8_t *rand_data,
                             size_t rand_datalen) {
  std::array<uint8_t, 32> secret;

  if (crypto::hkdf_extract(secret.data(), secret.size(), token_secret_.data(),
                           token_secret_.size(), rand_data, rand_datalen,
                           token_crypto_ctx_) != 0) {
    return -1;
  }

  auto slen = crypto::derive_packet_protection_key(
      key, keylen, secret.data(), secret.size(), token_crypto_ctx_);
  if (slen < 0) {
    return -1;
  }
  keylen = slen;

  slen = crypto::derive_packet_protection_iv(iv, ivlen, secret.data(),
                                             secret.size(), token_crypto_ctx_);
  if (slen < 0) {
    return -1;
  }
  ivlen = slen;

  return 0;
}

int Server::generate_rand_data(uint8_t *buf, size_t len) {
  std::array<uint8_t, 16> rand;
  std::array<uint8_t, 32> md;
  auto dis = std::uniform_int_distribution<uint8_t>(0, 255);
  std::generate_n(rand.data(), rand.size(), [&dis]() { return dis(randgen); });
  if (crypto::message_digest(md.data(), EVP_sha256(), rand.data(),
                             rand.size()) != 0) {
    return -1;
  }
  assert(len <= md.size());
  std::copy_n(std::begin(md), len, buf);
  return 0;
}

int Server::generate_token(uint8_t *token, size_t &tokenlen, const sockaddr *sa,
                           socklen_t salen, const ngtcp2_cid *ocid) {
  std::array<uint8_t, 4096> plaintext;

  uint64_t t = std::chrono::duration_cast<std::chrono::nanoseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

  auto p = std::begin(plaintext);
  p = std::copy_n(reinterpret_cast<const uint8_t *>(sa), salen, p);
  // Host byte order
  p = std::copy_n(reinterpret_cast<uint8_t *>(&t), sizeof(t), p);
  p = std::copy_n(ocid->data, ocid->datalen, p);

  std::array<uint8_t, TOKEN_RAND_DATALEN> rand_data;
  std::array<uint8_t, 32> key, iv;
  auto keylen = key.size();
  auto ivlen = iv.size();

  if (generate_rand_data(rand_data.data(), rand_data.size()) != 0) {
    return -1;
  }
  if (derive_token_key(key.data(), keylen, iv.data(), ivlen, rand_data.data(),
                       rand_data.size()) != 0) {
    return -1;
  }

  auto n = crypto::encrypt(token, tokenlen, plaintext.data(),
                           std::distance(std::begin(plaintext), p),
                           token_crypto_ctx_, key.data(), keylen, iv.data(),
                           ivlen, reinterpret_cast<const uint8_t *>(sa), salen);

  if (n < 0) {
    return -1;
  }

  memcpy(token + n, rand_data.data(), rand_data.size());

  tokenlen = n + rand_data.size();

  return 0;
}

int Server::verify_token(ngtcp2_cid *ocid, const ngtcp2_pkt_hd *hd,
                         const sockaddr *sa, socklen_t salen) {
  std::array<char, NI_MAXHOST> host;
  std::array<char, NI_MAXSERV> port;
  int rv;

  rv = getnameinfo(sa, salen, host.data(), host.size(), port.data(),
                   port.size(), NI_NUMERICHOST | NI_NUMERICSERV);
  if (rv != 0) {
    std::cerr << "getnameinfo: " << gai_strerror(rv) << std::endl;
    return -1;
  }

  if (!config.quiet) {
    std::cerr << "Verifying token from [" << host.data() << "]:" << port.data()
              << std::endl;
  }

  if (!config.quiet) {
    std::cerr << "Received address validation token:" << std::endl;
    util::hexdump(stderr, hd->token, hd->tokenlen);
  }

  if (hd->tokenlen < TOKEN_RAND_DATALEN) {
    if (!config.quiet) {
      std::cerr << "Token is too short" << std::endl;
    }
    return -1;
  }

  auto rand_data = hd->token + hd->tokenlen - TOKEN_RAND_DATALEN;
  auto ciphertext = hd->token;
  auto ciphertextlen = hd->tokenlen - TOKEN_RAND_DATALEN;

  std::array<uint8_t, 32> key, iv;
  auto keylen = key.size();
  auto ivlen = iv.size();

  if (derive_token_key(key.data(), keylen, iv.data(), ivlen, rand_data,
                       TOKEN_RAND_DATALEN) != 0) {
    return -1;
  }

  std::array<uint8_t, 4096> plaintext;

  auto n = crypto::decrypt(plaintext.data(), plaintext.size(), ciphertext,
                           ciphertextlen, token_crypto_ctx_, key.data(), keylen,
                           iv.data(), ivlen,
                           reinterpret_cast<const uint8_t *>(sa), salen);
  if (n < 0) {
    if (!config.quiet) {
      std::cerr << "Could not decrypt token" << std::endl;
    }
    return -1;
  }

  if (static_cast<size_t>(n) < salen + sizeof(uint64_t)) {
    if (!config.quiet) {
      std::cerr << "Bad token construction" << std::endl;
    }
    return -1;
  }

  auto cil = static_cast<size_t>(n) - salen - sizeof(uint64_t);
  if (cil != 0 && (cil < NGTCP2_MIN_CIDLEN || cil > NGTCP2_MAX_CIDLEN)) {
    if (!config.quiet) {
      std::cerr << "Bad token construction" << std::endl;
    }
    return -1;
  }

  if (memcmp(plaintext.data(), sa, salen) != 0) {
    if (!config.quiet) {
      std::cerr << "Client address does not match" << std::endl;
    }
    return -1;
  }

  uint64_t t;
  memcpy(&t, plaintext.data() + salen, sizeof(uint64_t));

  uint64_t now = std::chrono::duration_cast<std::chrono::nanoseconds>(
                     std::chrono::system_clock::now().time_since_epoch())
                     .count();

  // Allow 10 seconds window
  if (t + 10ULL * NGTCP2_SECONDS < now) {
    if (!config.quiet) {
      std::cerr << "Token has been expired" << std::endl;
    }
    return -1;
  }

  ngtcp2_cid_init(ocid, plaintext.data() + salen + sizeof(uint64_t), cil);

  return 0;
}

int Server::send_packet(Endpoint &ep, const Address &remote_addr, Buffer &buf) {
  if (debug::packet_lost(config.tx_loss_prob)) {
    if (!config.quiet) {
      std::cerr << "** Simulated outgoing packet loss **" << std::endl;
    }
    buf.reset();
    return NETWORK_ERR_OK;
  }

  int eintr_retries = 5;
  ssize_t nwrite = 0;

  do {
    nwrite = sendto(ep.fd, buf.rpos(), buf.size(), 0, &remote_addr.su.sa,
                    remote_addr.len);
  } while ((nwrite == -1) && (errno == EINTR) && (eintr_retries-- > 0));

  if (nwrite == -1) {
    switch (errno) {
    case EAGAIN:
    case EINTR:
    case 0:
      ev_io_start(loop_, &ep.wev);
      return NETWORK_ERR_SEND_NON_FATAL;
    default:
      std::cerr << "sendto: " << strerror(errno) << std::endl;
      // TODO We have packet which is expected to fail to send (e.g.,
      // path validation to old path).
      buf.reset();
      return NETWORK_ERR_OK;
    }
  }

  assert(static_cast<size_t>(nwrite) == buf.size());
  buf.reset();

  if (!config.quiet) {
    std::cerr << "Sent packet: local="
              << util::straddr(&ep.addr.su.sa, ep.addr.len) << " remote="
              << util::straddr(&remote_addr.su.sa, remote_addr.len) << " "
              << nwrite << " bytes" << std::endl;
  }

  return NETWORK_ERR_OK;
}

void Server::associate_cid(const ngtcp2_cid *cid, Handler *h) {
  ctos_.emplace(util::make_cid_key(cid), util::make_cid_key(h->scid()));
}

void Server::dissociate_cid(const ngtcp2_cid *cid) {
  ctos_.erase(util::make_cid_key(cid));
}

void Server::remove(const Handler *h) {
  ctos_.erase(util::make_cid_key(h->rcid()));
  ctos_.erase(util::make_cid_key(h->pscid()));

  auto conn = h->conn();
  std::vector<ngtcp2_cid> cids(ngtcp2_conn_get_num_scid(conn));
  ngtcp2_conn_get_scid(conn, cids.data());

  for (auto &cid : cids) {
    ctos_.erase(util::make_cid_key(&cid));
  }

  handlers_.erase(util::make_cid_key(h->scid()));
}

std::map<std::string, std::unique_ptr<Handler>>::const_iterator Server::remove(
    std::map<std::string, std::unique_ptr<Handler>>::const_iterator it) {
  ctos_.erase(util::make_cid_key((*it).second->rcid()));
  return handlers_.erase(it);
}

namespace {
int alpn_select_proto_cb(SSL *ssl, const unsigned char **out,
                         unsigned char *outlen, const unsigned char *in,
                         unsigned int inlen, void *arg) {
  auto h = static_cast<Handler *>(SSL_get_app_data(ssl));
  const uint8_t *alpn;
  size_t alpnlen;
  auto version = ngtcp2_conn_get_negotiated_version(h->conn());

  switch (version) {
  case NGTCP2_PROTO_VER_D19:
    alpn = reinterpret_cast<const uint8_t *>(NGTCP2_ALPN_D19);
    alpnlen = str_size(NGTCP2_ALPN_D19);
    break;
  default:
    if (!config.quiet) {
      std::cerr << "Unexpected quic protocol version: " << std::hex << "0x"
                << version << std::endl;
    }
    return SSL_TLSEXT_ERR_NOACK;
  }

  for (auto p = in, end = in + inlen; p + alpnlen <= end; p += *p + 1) {
    if (std::equal(alpn, alpn + alpnlen, p)) {
      *out = p + 1;
      *outlen = *p;
      return SSL_TLSEXT_ERR_OK;
    }
  }
  // Just select alpn for now.
  *out = reinterpret_cast<const uint8_t *>(alpn + 1);
  *outlen = alpn[0];

  if (!config.quiet) {
    std::cerr << "Client did not present ALPN " << NGTCP2_ALPN_D19 + 1
              << std::endl;
  }

  return SSL_TLSEXT_ERR_OK;
}
} // namespace

namespace {
int transport_params_add_cb(SSL *ssl, unsigned int ext_type,
                            unsigned int context, const unsigned char **out,
                            size_t *outlen, X509 *x, size_t chainidx, int *al,
                            void *add_arg) {
  auto h = static_cast<Handler *>(SSL_get_app_data(ssl));
  auto conn = h->conn();

  ngtcp2_transport_params params;

  ngtcp2_conn_get_local_transport_params(conn, &params);

  constexpr size_t bufsize = 512;
  auto buf = std::make_unique<uint8_t[]>(bufsize);

  auto nwrite = ngtcp2_encode_transport_params(
      buf.get(), bufsize, NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS,
      &params);
  if (nwrite < 0) {
    std::cerr << "ngtcp2_encode_transport_params: "
              << ngtcp2_strerror(static_cast<int>(nwrite)) << std::endl;
    *al = SSL_AD_INTERNAL_ERROR;
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
    *al = SSL_AD_ILLEGAL_PARAMETER;
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
    *al = SSL_AD_ILLEGAL_PARAMETER;
    return -1;
  }

  rv = ngtcp2_conn_set_remote_transport_params(conn, &params);
  if (rv != 0) {
    std::cerr << "ngtcp2_conn_set_remote_transport_params: "
              << ngtcp2_strerror(rv) << std::endl;
    *al = SSL_AD_ILLEGAL_PARAMETER;
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
                            SSL_OP_CIPHER_SERVER_PREFERENCE |
                            SSL_OP_NO_ANTI_REPLAY;

  SSL_CTX_set_options(ssl_ctx, ssl_opts);
  SSL_CTX_clear_options(ssl_ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);

  if (SSL_CTX_set_ciphersuites(ssl_ctx, config.ciphers) != 1) {
    std::cerr << "SSL_CTX_set_ciphersuites: "
              << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
    goto fail;
  }

  if (SSL_CTX_set1_groups_list(ssl_ctx, config.groups) != 1) {
    std::cerr << "SSL_CTX_set1_groups_list failed" << std::endl;
    goto fail;
  }

  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS | SSL_MODE_QUIC_HACK);

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
          SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
          transport_params_add_cb, transport_params_free_cb, nullptr,
          transport_params_parse_cb, nullptr) != 1) {
    std::cerr << "SSL_CTX_add_custom_ext(NGTCP2_TLSEXT_QUIC_TRANSPORT_"
                 "PARAMETERS) failed: "
              << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
    goto fail;
  }

  SSL_CTX_set_max_early_data(ssl_ctx, std::numeric_limits<uint32_t>::max());

  return ssl_ctx;

fail:
  SSL_CTX_free(ssl_ctx);
  return nullptr;
}
} // namespace

namespace {
std::ofstream keylog_file;
void keylog_callback(const SSL *ssl, const char *line) {
  keylog_file.write(line, strlen(line));
  keylog_file.put('\n');
  keylog_file.flush();
}
} // namespace

namespace {
int parse_host_port(Address &dest, int af, const char *first,
                    const char *last) {
  if (std::distance(first, last) == 0) {
    return -1;
  }

  const char *host_begin, *host_end, *it;
  if (*first == '[') {
    host_begin = first + 1;
    it = std::find(host_begin, last, ']');
    if (it == last) {
      return -1;
    }
    host_end = it;
    ++it;
    if (it == last || *it != ':') {
      return -1;
    }
  } else {
    host_begin = first;
    it = std::find(host_begin, last, ':');
    if (it == last) {
      return -1;
    }
    host_end = it;
  }

  if (++it == last) {
    return -1;
  }
  auto svc_begin = it;

  std::array<char, NI_MAXHOST> host;
  *std::copy(host_begin, host_end, std::begin(host)) = '\0';

  addrinfo hints{}, *res;
  hints.ai_family = af;
  hints.ai_socktype = SOCK_DGRAM;

  auto rv = getaddrinfo(host.data(), svc_begin, &hints, &res);
  if (rv != 0) {
    std::cerr << "getaddrinfo: [" << host.data() << "]:" << svc_begin << ": "
              << gai_strerror(rv) << std::endl;
    return -1;
  }

  dest.len = res->ai_addrlen;
  memcpy(&dest.su, res->ai_addr, res->ai_addrlen);

  freeaddrinfo(res);

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
void config_set_default(Config &config) {
  config = Config{};
  config.tx_loss_prob = 0.;
  config.rx_loss_prob = 0.;
  config.ciphers = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_"
                   "POLY1305_SHA256";
  config.groups = "P-256:X25519:P-384:P-521";
  config.timeout = 30000;
  {
    auto path = realpath(".", nullptr);
    config.htdocs = path;
    free(path);
  }
}
} // namespace

namespace {
void print_help() {
  print_usage();

  config_set_default(config);

  std::cout << R"(
  <ADDR>      Address to listen to.  '*' binds to any address.
  <PORT>      Port
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
  --ciphers=<CIPHERS>
              Specify the cipher suite list to enable.
              Default: )"
            << config.ciphers << R"(
  --groups=<GROUPS>
              Specify the supported groups.
              Default: )"
            << config.groups << R"(
  -d, --htdocs=<PATH>
              Specify document root.  If this option is not specified,
              the document root is the current working directory.
  -q, --quiet Suppress debug output.
  -s, --show-secret
              Print out secrets unless --quiet is used.
  --timeout=<T>
              Specify idle timeout in milliseconds.
              Default: )"
            << config.timeout << R"(
  -V, --validate-addr
              Perform address validation.
  --preferred-ipv4-addr=<ADDR>:<PORT>
              Specify preferred IPv4 address and port.
  --preferred-ipv6-addr=<ADDR>:<PORT>
              Specify preferred IPv6 address and port.  A numeric IPv6
              address  must   be  enclosed  by  '['   and  ']'  (e.g.,
              [::1]:8443)
  -h, --help  Display this help and exit.
)";
}
} // namespace

int main(int argc, char **argv) {
  config_set_default(config);

  for (;;) {
    static int flag = 0;
    constexpr static option long_opts[] = {
        {"help", no_argument, nullptr, 'h'},
        {"tx-loss", required_argument, nullptr, 't'},
        {"rx-loss", required_argument, nullptr, 'r'},
        {"htdocs", required_argument, nullptr, 'd'},
        {"quiet", no_argument, nullptr, 'q'},
        {"show-secret", no_argument, nullptr, 's'},
        {"validate-addr", no_argument, nullptr, 'V'},
        {"ciphers", required_argument, &flag, 1},
        {"groups", required_argument, &flag, 2},
        {"timeout", required_argument, &flag, 3},
        {"preferred-ipv4-addr", required_argument, &flag, 4},
        {"preferred-ipv6-addr", required_argument, &flag, 5},
        {nullptr, 0, nullptr, 0}};

    auto optidx = 0;
    auto c = getopt_long(argc, argv, "d:hqr:st:V", long_opts, &optidx);
    if (c == -1) {
      break;
    }
    switch (c) {
    case 'd': {
      // --htdocs
      auto path = realpath(optarg, nullptr);
      if (path == nullptr) {
        std::cerr << "path: invalid path " << optarg << std::endl;
        exit(EXIT_FAILURE);
      }
      config.htdocs = path;
      free(path);
      break;
    }
    case 'h':
      // --help
      print_help();
      exit(EXIT_SUCCESS);
    case 'q':
      // -quiet
      config.quiet = true;
      break;
    case 'r':
      // --rx-loss
      config.rx_loss_prob = strtod(optarg, nullptr);
      break;
    case 's':
      // --show-secret
      config.show_secret = true;
      break;
    case 't':
      // --tx-loss
      config.tx_loss_prob = strtod(optarg, nullptr);
      break;
    case 'V':
      // --validate-addr
      config.validate_addr = true;
      break;
    case '?':
      print_usage();
      exit(EXIT_FAILURE);
    case 0:
      switch (flag) {
      case 1:
        // --ciphers
        config.ciphers = optarg;
        break;
      case 2:
        // --groups
        config.groups = optarg;
        break;
      case 3:
        // --timeout
        config.timeout = strtol(optarg, nullptr, 10);
        break;
      case 4:
        // --preferred-ipv4-addr
        if (parse_host_port(config.preferred_ipv4_addr, AF_INET, optarg,
                            optarg + strlen(optarg)) != 0) {
          std::cerr << "preferred-ipv4-addr: could not use '" << optarg << "'"
                    << std::endl;
          exit(EXIT_FAILURE);
        }
        break;
      case 5:
        // --preferred-ipv6-addr
        if (parse_host_port(config.preferred_ipv6_addr, AF_INET6, optarg,
                            optarg + strlen(optarg)) != 0) {
          std::cerr << "preferred-ipv6-addr: could not use '" << optarg << "'"
                    << std::endl;
          exit(EXIT_FAILURE);
        }
        break;
      }
      break;
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

  errno = 0;
  config.port = strtoul(port, nullptr, 10);
  if (errno != 0) {
    std::cerr << "port: invalid port number" << std::endl;
    exit(EXIT_FAILURE);
  }

  auto ssl_ctx = create_ssl_ctx(private_key_file, cert_file);
  if (ssl_ctx == nullptr) {
    exit(EXIT_FAILURE);
  }

  if (config.htdocs.back() != '/') {
    config.htdocs += '/';
  }

  std::cerr << "Using document root " << config.htdocs << std::endl;

  auto ssl_ctx_d = defer(SSL_CTX_free, ssl_ctx);

  auto ev_loop_d = defer(ev_loop_destroy, EV_DEFAULT);

  if (isatty(STDOUT_FILENO)) {
    debug::set_color_output(true);
  }

  auto keylog_filename = getenv("SSLKEYLOGFILE");
  if (keylog_filename) {
    keylog_file.open(keylog_filename, std::ios_base::app);
    if (keylog_file) {
      SSL_CTX_set_keylog_callback(ssl_ctx, keylog_callback);
    }
  }

  Server s(EV_DEFAULT, ssl_ctx);
  if (s.init(addr, port) != 0) {
    exit(EXIT_FAILURE);
  }

  ev_run(EV_DEFAULT, 0);

  s.disconnect();
  s.close();

  return EXIT_SUCCESS;
}
