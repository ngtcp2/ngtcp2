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
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <openssl/bio.h>
#include <openssl/err.h>

#include "server.h"
#include "network.h"
#include "debug.h"
#include "util.h"
#include "crypto.h"
#include "shared.h"
#include "http.h"

using namespace ngtcp2;

namespace {
auto randgen = util::make_mt19937();
} // namespace

namespace {
Config config{};
} // namespace

namespace {
constexpr size_t MAX_BYTES_IN_FLIGHT = 1460 * 10;
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

namespace {
int on_msg_begin(http_parser *htp) {
  auto s = static_cast<Stream *>(htp->data);
  if (s->resp_state != RESP_IDLE) {
    return -1;
  }
  return 0;
}
} // namespace

namespace {
int on_url_cb(http_parser *htp, const char *data, size_t datalen) {
  auto s = static_cast<Stream *>(htp->data);
  s->uri.append(data, datalen);
  return 0;
}
} // namespace

namespace {
int on_header_field(http_parser *htp, const char *data, size_t datalen) {
  auto s = static_cast<Stream *>(htp->data);
  if (s->prev_hdr_key) {
    s->hdrs.back().first.append(data, datalen);
  } else {
    s->prev_hdr_key = true;
    s->hdrs.emplace_back(std::string(data, datalen), "");
  }
  return 0;
}
} // namespace

namespace {
int on_header_value(http_parser *htp, const char *data, size_t datalen) {
  auto s = static_cast<Stream *>(htp->data);
  s->prev_hdr_key = false;
  s->hdrs.back().second.append(data, datalen);
  return 0;
}
} // namespace

namespace {
int on_headers_complete(http_parser *htp) {
  auto s = static_cast<Stream *>(htp->data);
  if (s->start_response() != 0) {
    return -1;
  }
  return 0;
}
} // namespace

auto htp_settings = http_parser_settings{
    on_msg_begin,        // on_message_begin
    on_url_cb,           // on_url
    nullptr,             // on_status
    on_header_field,     // on_header_field
    on_header_value,     // on_header_value
    on_headers_complete, // on_headers_complete
    nullptr,             // on_body
    nullptr,             // on_message_complete
    nullptr,             // on_chunk_header,
    nullptr,             // on_chunk_complete
};

Stream::Stream(uint32_t stream_id)
    : stream_id(stream_id),
      streambuf_idx(0),
      tx_stream_offset(0),
      should_send_fin(false),
      http_major(0),
      http_minor(0),
      resp_state(RESP_IDLE),
      prev_hdr_key(false),
      fd(-1),
      data(nullptr),
      datalen(0) {
  http_parser_init(&htp, HTTP_REQUEST);
  htp.data = this;
}

Stream::~Stream() {
  munmap(data, datalen);
  if (fd != -1) {
    close(fd);
  }
}

int Stream::recv_data(uint8_t fin, const uint8_t *data, size_t datalen) {
  auto nread = http_parser_execute(
      &htp, &htp_settings, reinterpret_cast<const char *>(data), datalen);
  if (nread != datalen) {
    return -1;
  }

  return 0;
}

namespace {
constexpr char NGTCP2_SERVER[] = "ngtcp2";
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

void Stream::buffer_file() {
  streambuf.emplace_back(data, data + datalen);
  should_send_fin = true;
}

void Stream::send_status_response(unsigned int status_code,
                                  const std::string &extra_headers) {
  auto body = make_status_body(status_code);
  std::string hdr;
  if (http_major >= 1) {
    hdr += "HTTP/";
    hdr += std::to_string(http_major);
    hdr += '.';
    hdr += std::to_string(http_minor);
    hdr += ' ';
    hdr += std::to_string(status_code);
    hdr += " ";
    hdr += http::get_reason_phrase(status_code);
    hdr += "\r\n";
    hdr += "Server: ";
    hdr += NGTCP2_SERVER;
    hdr += "\r\n";
    hdr += "Content-Type: text/html; charset=UTF-8\r\n";
    hdr += "Content-Length: ";
    hdr += std::to_string(body.size());
    hdr += "\r\n";
    hdr += extra_headers;
    hdr += "\r\n";
  }

  auto v = Buffer{hdr.size() + ((htp.method == HTTP_HEAD) ? 0 : body.size())};
  auto p = std::begin(v.buf);
  p = std::copy(std::begin(hdr), std::end(hdr), p);
  if (htp.method != HTTP_HEAD) {
    p = std::copy(std::begin(body), std::end(body), p);
  }
  v.push(std::distance(std::begin(v.buf), p));
  streambuf.emplace_back(std::move(v));
  should_send_fin = true;
  resp_state = RESP_COMPLETED;
}

void Stream::send_redirect_response(unsigned int status_code,
                                    const std::string &path) {
  std::string hdrs = "Location: ";
  hdrs += path;
  hdrs += "\r\n";
  send_status_response(status_code, hdrs);
}

int Stream::start_response() {
  http_major = htp.http_major;
  http_minor = htp.http_minor;

  auto req_path = request_path(uri, htp.method == HTTP_CONNECT);
  auto path = resolve_path(req_path);
  if (path.empty() || open_file(path) != 0) {
    send_status_response(404);
    return 0;
  }

  struct stat st {};

  int64_t content_length = -1;

  if (fstat(fd, &st) == 0) {
    if (st.st_mode & S_IFDIR) {
      send_redirect_response(308, path.substr(config.htdocs.size() - 1) + '/');
      return 0;
    }
    content_length = st.st_size;
  } else {
    send_status_response(404);
    return 0;
  }

  if (map_file(content_length) != 0) {
    send_status_response(500);
    return 0;
  }

  if (http_major >= 1) {
    std::string hdr;
    hdr += "HTTP/";
    hdr += std::to_string(http_major);
    hdr += '.';
    hdr += std::to_string(http_minor);
    hdr += " 200 OK\r\n";
    hdr += "Server: ";
    hdr += NGTCP2_SERVER;
    hdr += "\r\n";
    if (content_length != -1) {
      hdr += "Content-Length: ";
      hdr += std::to_string(content_length);
      hdr += "\r\n";
    }
    hdr += "\r\n";

    auto v = Buffer{hdr.size()};
    auto p = std::begin(v.buf);
    p = std::copy(std::begin(hdr), std::end(hdr), p);
    v.push(std::distance(std::begin(v.buf), p));
    streambuf.emplace_back(std::move(v));
  }

  resp_state = RESP_COMPLETED;

  switch (htp.method) {
  case HTTP_HEAD:
    should_send_fin = true;
    close(fd);
    fd = -1;
    break;
  default:
    buffer_file();
  }

  return 0;
}

namespace {
void timeoutcb(struct ev_loop *loop, ev_timer *w, int revents) {
  int rv;

  auto h = static_cast<Handler *>(w->data);
  auto s = h->server();

  if (ngtcp2_conn_closed(h->conn())) {
    if (!config.quiet) {
      debug::print_timestamp();
      std::cerr << "Draining Period is over" << std::endl;
    }

    s->remove(h);
    return;
  }

  if (!config.quiet) {
    debug::print_timestamp();
    std::cerr << "Timeout" << std::endl;
  }

  rv = h->start_drain_period(0);
  if (rv != 0) {
    s->remove(h);
  }
}
} // namespace

namespace {
void retransmitcb(struct ev_loop *loop, ev_timer *w, int revents) {
  int rv;

  auto h = static_cast<Handler *>(w->data);
  auto s = h->server();

  rv = h->on_write();
  switch (rv) {
  case 0:
  case NETWORK_ERR_CLOSE_WAIT:
    break;
  case NETWORK_ERR_SEND_NON_FATAL:
    s->start_wev();
    break;
  default:
    s->remove(h);
  }
}
} // namespace

Handler::Handler(struct ev_loop *loop, SSL_CTX *ssl_ctx, Server *server,
                 uint64_t client_conn_id)
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
      sendbuf_{NGTCP2_MAX_PKTLEN_IPV4},
      conn_id_(std::uniform_int_distribution<uint64_t>(
          0, std::numeric_limits<uint64_t>::max())(randgen)),
      client_conn_id_(client_conn_id),
      tx_stream0_offset_(0) {
  ev_timer_init(&timer_, timeoutcb, 0., 30.);
  timer_.data = this;
  ev_timer_init(&rttimer_, retransmitcb, 0., 0.);
  rttimer_.data = this;
}

Handler::~Handler() {
  if (!config.quiet) {
    debug::print_timestamp();
    std::cerr << "Closing QUIC connection" << std::endl;
  }

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

  if (!config.quiet) {
    debug::handshake_completed(conn, user_data);
  }

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
    return NGTCP2_ERR_TLS_HANDSHAKE;
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
  if (h->remove_tx_stream_data(stream_id, offset, datalen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
} // namespace

namespace {
int stream_close(ngtcp2_conn *conn, uint32_t stream_id, uint32_t error_code,
                 void *user_data, void *stream_user_data) {
  auto h = static_cast<Handler *>(user_data);
  h->on_stream_close(stream_id);
  return 0;
}
} // namespace

int Handler::init(int fd, const sockaddr *sa, socklen_t salen,
                  uint32_t version) {
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
      config.quiet ? nullptr : debug::send_pkt,
      config.quiet ? nullptr : debug::send_frame,
      config.quiet ? nullptr : debug::recv_pkt,
      config.quiet ? nullptr : debug::recv_frame,
      handshake_completed,
      nullptr,
      do_encrypt,
      do_decrypt,
      ::recv_stream_data,
      acked_stream_data_offset,
      stream_close,
  };

  ngtcp2_settings settings;

  settings.max_stream_data = 256_k;
  settings.max_data = 1_k;
  settings.max_stream_id = 199;
  settings.idle_timeout = 30;
  settings.omit_connection_id = 0;
  settings.max_packet_size = NGTCP2_MAX_PKT_SIZE;

  auto dis = std::uniform_int_distribution<uint8_t>(0, 255);
  std::generate(std::begin(settings.stateless_reset_token),
                std::end(settings.stateless_reset_token),
                [&dis]() { return dis(randgen); });

  rv = ngtcp2_conn_server_new(&conn_, conn_id_, version, &callbacks, &settings,
                              this);
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

  if (!config.quiet) {
    debug::print_indent();
    std::cerr << "; Negotiated cipher suite is " << SSL_get_cipher_name(ssl_)
              << std::endl;

    const unsigned char *alpn = nullptr;
    unsigned int alpnlen;

    SSL_get0_alpn_selected(ssl_, &alpn, &alpnlen);
    if (alpn) {
      debug::print_indent();
      std::cerr << "; Negotiated ALPN is ";
      std::cerr.write(reinterpret_cast<const char *>(alpn), alpnlen);
      std::cerr << std::endl;
    }
  }

  return 0;
}

int Handler::write_server_handshake(const uint8_t *data, size_t datalen) {
  shandshake_.emplace_back(data, datalen);
  return 0;
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
    return handle_error(rv);
  }
  if (ngtcp2_conn_closed(conn_)) {
    if (!config.quiet) {
      debug::print_timestamp();
      std::cerr << "QUIC connection has been closed by peer" << std::endl;
    }
    return -1;
  }

  return 0;
}

int Handler::on_read(uint8_t *data, size_t datalen) {
  int rv;

  rv = feed_data(data, datalen);
  if (rv != 0) {
    return rv;
  }

  ev_timer_again(loop_, &timer_);

  return 0;
}

int Handler::on_write() {
  int rv;

  if (ngtcp2_conn_closed(conn_)) {
    return 0;
  }

  if (sendbuf_.size() > 0) {
    auto rv = server_->send_packet(remote_addr_, sendbuf_);
    if (rv != NETWORK_ERR_OK) {
      return rv;
    }
  }

  assert(sendbuf_.left() >= max_pktlen_);

  for (;;) {
    ssize_t n;
    if (ngtcp2_conn_bytes_in_flight(conn_) < MAX_BYTES_IN_FLIGHT) {
      n = ngtcp2_conn_write_pkt(conn_, sendbuf_.wpos(), max_pktlen_,
                                util::timestamp());
    } else {
      n = ngtcp2_conn_write_ack_pkt(conn_, sendbuf_.wpos(), max_pktlen_,
                                    util::timestamp());
    }
    if (n < 0) {
      std::cerr << "ngtcp2_conn_write_pkt: " << ngtcp2_strerror(n) << std::endl;
      return handle_error(n);
    }
    if (n == 0) {
      break;
    }

    sendbuf_.push(n);

    auto rv = server_->send_packet(remote_addr_, sendbuf_);
    if (rv == NETWORK_ERR_SEND_NON_FATAL) {
      break;
    }
    if (rv != NETWORK_ERR_OK) {
      return rv;
    }
  }

  for (auto &p : streams_) {
    auto &stream = p.second;
    rv = on_write_stream(*stream);
    if (rv != 0) {
      return rv;
    }
  }

  schedule_retransmit();
  return 0;
}

int Handler::on_write_stream(Stream &stream) {
  if (stream.streambuf_idx == stream.streambuf.size()) {
    if (stream.should_send_fin) {
      if (ngtcp2_conn_bytes_in_flight(conn_) >= MAX_BYTES_IN_FLIGHT) {
        return 0;
      }

      stream.should_send_fin = false;
      auto v = Buffer{};
      if (write_stream_data(stream, 1, v) != 0) {
        return -1;
      }
    }
    return 0;
  }

  for (auto it = std::begin(stream.streambuf) + stream.streambuf_idx;
       it != std::end(stream.streambuf); ++it) {
    auto &v = *it;
    auto fin = stream.should_send_fin &&
               stream.streambuf_idx == stream.streambuf.size() - 1;
    auto rv = write_stream_data(stream, fin, v);
    if (rv != 0) {
      return rv;
    }
    if (v.size() > 0) {
      break;
    }
    ++stream.streambuf_idx;
    if (fin) {
      stream.should_send_fin = false;
    }
  }

  return 0;
}

int Handler::write_stream_data(Stream &stream, int fin, Buffer &data) {
  size_t ndatalen;

  for (;;) {
    if (ngtcp2_conn_bytes_in_flight(conn_) >= MAX_BYTES_IN_FLIGHT) {
      break;
    }

    auto n = ngtcp2_conn_write_stream(
        conn_, sendbuf_.wpos(), max_pktlen_, &ndatalen, stream.stream_id, fin,
        data.rpos(), data.size(), util::timestamp());
    if (n < 0) {
      switch (n) {
      case NGTCP2_ERR_STREAM_DATA_BLOCKED:
      case NGTCP2_ERR_STREAM_SHUT_WR:
        return 0;
      }
      std::cerr << "ngtcp2_conn_write_stream: " << ngtcp2_strerror(n)
                << std::endl;
      return handle_error(n);
    }

    data.seek(ndatalen);

    sendbuf_.push(n);

    auto rv = server_->send_packet(remote_addr_, sendbuf_);
    if (rv != NETWORK_ERR_OK) {
      return rv;
    }

    if (data.size() == 0) {
      break;
    }
  }

  return 0;
}

int Handler::start_drain_period(int liberr) {
  int rv;

  if (!conn_ || ngtcp2_conn_closed(conn_)) {
    return 0;
  }

  ev_timer_stop(loop_, &rttimer_);

  timer_.repeat = 15.;
  ev_timer_again(loop_, &timer_);

  sendbuf_.reset();
  assert(sendbuf_.left() >= max_pktlen_);

  conn_closebuf_ = std::make_unique<Buffer>(NGTCP2_MAX_PKTLEN_IPV4);

  auto n = ngtcp2_conn_write_connection_close(conn_, conn_closebuf_->wpos(),
                                              max_pktlen_,
                                              infer_quic_error_code(liberr));
  if (n < 0) {
    std::cerr << "ngtcp2_conn_write_connection_close: " << ngtcp2_strerror(n)
              << std::endl;
    return -1;
  }

  conn_closebuf_->push(n);

  return 0;
}

int Handler::handle_error(int liberr) {
  int rv;

  rv = start_drain_period(liberr);
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
  int rv;

  if (!config.quiet) {
    debug::print_timestamp();
    std::cerr << "Draining Period: TX CONNECTION_CLOSE" << std::endl;
  }

  assert(conn_closebuf_ && conn_closebuf_->size());

  if (sendbuf_.size() == 0) {
    std::copy_n(conn_closebuf_->rpos(), conn_closebuf_->size(),
                sendbuf_.wpos());
    sendbuf_.push(conn_closebuf_->size());
  }

  return server_->send_packet(remote_addr_, sendbuf_);
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

  if (!config.quiet) {
    debug::print_stream_data(stream_id, data, datalen);
  }

  auto it = streams_.find(stream_id);
  if (it == std::end(streams_)) {
    it = streams_.emplace(stream_id, std::make_unique<Stream>(stream_id)).first;
  }

  auto &stream = (*it).second;

  ngtcp2_conn_extend_max_stream_offset(conn_, stream_id, datalen);
  ngtcp2_conn_extend_max_offset(conn_, datalen);

  if (stream->recv_data(fin, data, datalen) != 0) {
    if (stream->resp_state == RESP_IDLE) {
      stream->send_status_response(400);
      return 0;
    }
    rv = ngtcp2_conn_shutdown_stream(conn_, stream_id, NGTCP2_INTERNAL_ERROR);
    if (rv != 0) {
      std::cerr << "ngtcp2_conn_shutdown_stream: " << ngtcp2_strerror(rv)
                << std::endl;
      return -1;
    }
  }

  return 0;
}

uint64_t Handler::conn_id() const { return conn_id_; }

uint64_t Handler::client_conn_id() const { return client_conn_id_; }

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

int Handler::remove_tx_stream_data(uint32_t stream_id, uint64_t offset,
                                   size_t datalen) {
  int rv;

  if (stream_id == 0) {
    ::remove_tx_stream_data(shandshake_, shandshake_idx_, tx_stream0_offset_,
                            offset + datalen);
    return 0;
  }
  auto it = streams_.find(stream_id);
  assert(it != std::end(streams_));
  auto &stream = (*it).second;
  ::remove_tx_stream_data(stream->streambuf, stream->streambuf_idx,
                          stream->tx_stream_offset, offset + datalen);

  if (stream->streambuf.empty() && stream->resp_state == RESP_COMPLETED) {
    rv = ngtcp2_conn_shutdown_stream_read(conn_, stream_id, NGTCP2_NO_ERROR);
    if (rv != 0 && rv != NGTCP2_ERR_STREAM_NOT_FOUND) {
      std::cerr << "ngtcp2_conn_shutdown_stream_read: " << ngtcp2_strerror(rv)
                << std::endl;
      return -1;
    }
  }

  return 0;
}

void Handler::on_stream_close(uint32_t stream_id) {
  if (stream_id == 0) {
    return;
  }
  auto it = streams_.find(stream_id);
  assert(it != std::end(streams_));
  streams_.erase(it);
}

namespace {
void swritecb(struct ev_loop *loop, ev_io *w, int revents) {
  ev_io_stop(loop, w);

  auto s = static_cast<Server *>(w->data);

  auto rv = s->on_write();
  if (rv != 0) {
    if (rv == NETWORK_ERR_SEND_NON_FATAL) {
      s->start_wev();
    }
  }
}
} // namespace

namespace {
void sreadcb(struct ev_loop *loop, ev_io *w, int revents) {
  auto s = static_cast<Server *>(w->data);

  s->on_read();
}
} // namespace

namespace {
void siginthandler(struct ev_loop *loop, ev_signal *watcher, int revents) {
  ev_break(loop, EVBREAK_ALL);
}
} // namespace

Server::Server(struct ev_loop *loop, SSL_CTX *ssl_ctx)
    : loop_(loop), ssl_ctx_(ssl_ctx), fd_(-1) {
  ev_io_init(&wev_, swritecb, 0, EV_WRITE);
  ev_io_init(&rev_, sreadcb, 0, EV_READ);
  wev_.data = this;
  rev_.data = this;
  ev_signal_init(&sigintev_, siginthandler, SIGINT);
}

Server::~Server() {
  disconnect();
  close();
}

void Server::disconnect() { disconnect(0); }

void Server::disconnect(int liberr) {
  config.tx_loss_prob = 0;

  ev_io_stop(loop_, &rev_);

  ev_signal_stop(loop_, &sigintev_);

  while (!handlers_.empty()) {
    auto it = std::begin(handlers_);
    auto &h = (*it).second;

    h->handle_error(0);

    remove(it);
  }
}

void Server::close() {
  ev_io_stop(loop_, &wev_);

  if (fd_ != -1) {
    ::close(fd_);
    fd_ = -1;
  }
}

int Server::init(int fd) {
  fd_ = fd;

  ev_io_set(&wev_, fd_, EV_WRITE);
  ev_io_set(&rev_, fd_, EV_READ);

  ev_io_start(loop_, &rev_);

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
    if (!config.quiet) {
      std::cerr << "** Simulated incoming packet loss **" << std::endl;
    }
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
    auto ctos_it = ctos_.find(conn_id);
    if (ctos_it == std::end(ctos_)) {
      auto client_conn_id = conn_id;
      constexpr size_t MIN_PKT_SIZE = 1200;
      if (static_cast<size_t>(nread) < MIN_PKT_SIZE) {
        if (!config.quiet) {
          std::cerr << "Client Initial packet is too short: " << nread << " < "
                    << MIN_PKT_SIZE << std::endl;
        }
        return 0;
      }

      rv = ngtcp2_accept(&hd, buf.data(), nread);
      if (rv == -1) {
        if (!config.quiet) {
          std::cerr << "Unexpected packet received" << std::endl;
        }
        return 0;
      }
      if (rv == 1) {
        if (!config.quiet) {
          std::cerr << "Unsupported version: Send Version Negotiation"
                    << std::endl;
        }
        send_version_negotiation(&hd, &su.sa, addrlen);
        return 0;
      }

      if ((buf[0] & 0x7f) != NGTCP2_PKT_CLIENT_INITIAL) {
        return 0;
      }

      auto h = std::make_unique<Handler>(loop_, ssl_ctx_, this, client_conn_id);
      h->init(fd_, &su.sa, addrlen, hd.version);

      if (h->on_read(buf.data(), nread) != 0) {
        return 0;
      }
      rv = h->on_write();
      switch (rv) {
      case 0:
        break;
      case NETWORK_ERR_SEND_NON_FATAL:
        start_wev();
        break;
      default:
        return 0;
      }

      conn_id = h->conn_id();
      handlers_.emplace(conn_id, std::move(h));
      ctos_.emplace(client_conn_id, conn_id);
      return 0;
    }
    if (!config.quiet) {
      debug::print_timestamp();
      fprintf(stderr, "Forward CID=%016" PRIx64 " to CID=%016" PRIx64 "\n",
              (*ctos_it).first, (*ctos_it).second);
    }
    handler_it = handlers_.find((*ctos_it).second);
    assert(handler_it != std::end(handlers_));
  }

  auto h = (*handler_it).second.get();
  if (ngtcp2_conn_closed(h->conn())) {
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

  rv = h->on_read(buf.data(), nread);
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
    start_wev();
    break;
  default:
    remove(handler_it);
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
  Buffer buf{NGTCP2_MAX_PKTLEN_IPV4};
  ngtcp2_upe *upe;
  ngtcp2_pkt_hd hd;
  uint32_t reserved_ver;
  uint32_t sv[3];
  int rv;

  hd.type = NGTCP2_PKT_VERSION_NEGOTIATION;
  hd.flags = NGTCP2_PKT_FLAG_LONG_FORM;
  hd.conn_id = chd->conn_id;
  hd.pkt_num = chd->pkt_num;
  hd.version = chd->version;

  reserved_ver = generate_reserved_vesrion(sa, salen, hd.version);

  sv[0] = reserved_ver;
  sv[1] = NGTCP2_PROTO_VER_D5;
  sv[2] = NGTCP2_PROTO_VER_D6;

  rv = ngtcp2_upe_new(&upe, buf.wpos(), buf.left());
  if (rv != 0) {
    std::cerr << "ngtcp2_upe_new: " << ngtcp2_strerror(rv) << std::endl;
    return -1;
  }

  auto upe_d = defer(ngtcp2_upe_del, upe);

  rv = ngtcp2_upe_encode_hd(upe, &hd);
  if (rv != 0) {
    return -1;
  }

  auto sn =
      ngtcp2_upe_encode_version_negotiation(upe, nullptr, sv, array_size(sv));
  if (sn < 0) {
    std::cerr << "ngtcp2_upe_encode_version_negotiation: "
              << ngtcp2_strerror(rv) << std::endl;
    return -1;
  }

  buf.push(sn);

  Address remote_addr;
  remote_addr.len = salen;
  memcpy(&remote_addr.su.sa, sa, salen);

  if (send_packet(remote_addr, buf) != NETWORK_ERR_OK) {
    return -1;
  }

  return 0;
}

int Server::send_packet(Address &remote_addr, Buffer &buf) {
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
    nwrite = sendto(fd_, buf.rpos(), buf.size(), 0, &remote_addr.su.sa,
                    remote_addr.len);
  } while ((nwrite == -1) && (errno == EINTR) && (eintr_retries-- > 0));

  if (nwrite == -1) {
    switch (errno) {
    case EAGAIN:
    case EINTR:
    case 0:
      return NETWORK_ERR_SEND_NON_FATAL;
    default:
      std::cerr << "sendto: " << strerror(errno) << std::endl;
      return NETWORK_ERR_SEND_FATAL;
    }
  }

  assert(nwrite == buf.size());
  buf.reset();

  return NETWORK_ERR_OK;
}

void Server::remove(const Handler *h) {
  ctos_.erase(h->client_conn_id());
  handlers_.erase(h->conn_id());
}

std::map<uint64_t, std::unique_ptr<Handler>>::const_iterator Server::remove(
    std::map<uint64_t, std::unique_ptr<Handler>>::const_iterator it) {
  ctos_.erase((*it).second->client_conn_id());
  return handlers_.erase(it);
}

void Server::start_wev() { ev_io_start(loop_, &wev_); }

namespace {
int alpn_select_proto_cb(SSL *ssl, const unsigned char **out,
                         unsigned char *outlen, const unsigned char *in,
                         unsigned int inlen, void *arg) {
  auto h = static_cast<Handler *>(SSL_get_app_data(ssl));
  const uint8_t *alpn;
  size_t alpnlen;
  auto version = ngtcp2_conn_negotiated_version(h->conn());

  switch (version) {
  case NGTCP2_PROTO_VER_D5:
    alpn = reinterpret_cast<const uint8_t *>(NGTCP2_ALPN_D5);
    alpnlen = str_size(NGTCP2_ALPN_D5);
    break;
  case NGTCP2_PROTO_VER_D6:
    alpn = reinterpret_cast<const uint8_t *>(NGTCP2_ALPN_D6);
    alpnlen = str_size(NGTCP2_ALPN_D6);
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
    debug::print_indent();
    std::cerr << "; Client did not present ALPN " << NGTCP2_ALPN_D5 + 1
              << " or " << NGTCP2_ALPN_D6 + 1 << std::endl;
  }

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

  params.v.ee.len = 2;
  params.v.ee.supported_versions[0] = NGTCP2_PROTO_VER_D5;
  params.v.ee.supported_versions[1] = NGTCP2_PROTO_VER_D6;

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
    // TODO Set *al
    return -1;
  }

  if (!config.quiet) {
    debug::print_indent();
    std::cerr << "; TransportParameter received in ClientHello" << std::endl;
    debug::print_transport_params(&params,
                                  NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO);
  }

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

  if (SSL_CTX_set_cipher_list(ssl_ctx, config.ciphers) != 1) {
    std::cerr << "SSL_CTX_set_cipher_list: "
              << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
    goto fail;
  }

  if (SSL_CTX_set1_groups_list(ssl_ctx, config.groups) != 1) {
    std::cerr << "SSL_CTX_set1_groups_list failed" << std::endl;
    goto fail;
  }

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
int create_sock(const char *addr, const char *port, int family) {
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

  return fd;
}

} // namespace

namespace {
int serve(Server &s, const char *addr, const char *port, int family) {
  auto fd = create_sock(addr, port, family);
  if (fd == -1) {
    return -1;
  }

  if (s.init(fd) != 0) {
    return -1;
  }

  return 0;
}
} // namespace

namespace {
void close(Server &s) {
  s.disconnect();

  s.close();
}
}

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
  -h, --help  Display this help and exit.
)";
}
} // namespace

int main(int argc, char **argv) {
  config.tx_loss_prob = 0.;
  config.rx_loss_prob = 0.;
  config.ciphers = "TLS13-AES-128-GCM-SHA256:TLS13-AES-256-GCM-SHA384:TLS13-"
                   "CHACHA20-POLY1305-SHA256";
  config.groups = "P-256:X25519:P-384:P-521";
  {
    auto path = realpath(".", nullptr);
    config.htdocs = path;
    free(path);
  }
  for (;;) {
    static int flag = 0;
    constexpr static option long_opts[] = {
        {"help", no_argument, nullptr, 'h'},
        {"tx-loss", required_argument, nullptr, 't'},
        {"rx-loss", required_argument, nullptr, 'r'},
        {"htdocs", required_argument, nullptr, 'd'},
        {"quiet", no_argument, nullptr, 'q'},
        {"ciphers", required_argument, &flag, 1},
        {"groups", required_argument, &flag, 2},
        {nullptr, 0, nullptr, 0}};

    auto optidx = 0;
    auto c = getopt_long(argc, argv, "d:hqr:t:", long_opts, &optidx);
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
    case 't':
      // --tx-loss
      config.tx_loss_prob = strtod(optarg, nullptr);
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

  debug::reset_timestamp();

  if (isatty(STDOUT_FILENO)) {
    debug::set_color_output(true);
  }

  auto ready = false;

  Server s4(EV_DEFAULT, ssl_ctx);
  if (!util::numeric_host(addr, AF_INET6)) {
    if (serve(s4, addr, port, AF_INET) == 0) {
      ready = true;
    }
  }

  Server s6(EV_DEFAULT, ssl_ctx);
  if (!util::numeric_host(addr, AF_INET)) {
    if (serve(s6, addr, port, AF_INET6) == 0) {
      ready = true;
    }
  }

  if (!ready) {
    exit(EXIT_FAILURE);
  }

  ev_run(EV_DEFAULT, 0);

  close(s6);
  close(s4);

  return EXIT_SUCCESS;
}
