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
#include <chrono>
#include <cstdlib>
#include <cassert>
#include <cstring>
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
#include <netinet/udp.h>

#include <openssl/bio.h>
#include <openssl/err.h>

#include <http-parser/http_parser.h>

#include "server.h"
#include "network.h"
#include "debug.h"
#include "util.h"
#include "shared.h"
#include "http.h"
#include "keylog.h"
#include "template.h"

using namespace ngtcp2;
using namespace std::literals;

#ifndef NGTCP2_ENABLE_UDP_GSO
#  ifdef UDP_SEGMENT
#    define NGTCP2_ENABLE_UDP_GSO 1
#  else // !UDP_SEGMENT
#    define NGTCP2_ENABLE_UDP_GSO 0
#  endif // !UDP_SEGMENT
#endif   // NGTCP2_ENABLE_UDP_GSO

namespace {
constexpr size_t NGTCP2_SV_SCIDLEN = 18;
} // namespace

namespace {
constexpr size_t TOKEN_RAND_DATALEN = 16;
} // namespace

namespace {
constexpr size_t MAX_DYNBUFLEN = 1024 * 1024;
} // namespace

namespace {
auto randgen = util::make_mt19937();
} // namespace

namespace {
// RETRY_TOKEN_MAGIC is the magic byte of Retry token.  Sent in
// plaintext.
constexpr uint8_t RETRY_TOKEN_MAGIC = 0xb6;
constexpr size_t MAX_RETRY_TOKENLEN =
    /* magic */ 1 + sizeof(uint64_t) + NGTCP2_MAX_CIDLEN +
    /* aead tag */ 16 + TOKEN_RAND_DATALEN;

// TOKEN_MAGIC is the magic byte of token which is sent in NEW_TOKEN
// frame.  Sent in plaintext.
constexpr uint8_t TOKEN_MAGIC = 0x36;
constexpr size_t MAX_TOKENLEN =
    /* magic */ 1 + sizeof(uint64_t) + /* aead tag */ 16 + TOKEN_RAND_DATALEN;
} // namespace

namespace {
Config config{};
} // namespace

Buffer::Buffer(const uint8_t *data, size_t datalen)
    : buf{data, data + datalen}, begin(buf.data()), tail(begin + datalen) {}
Buffer::Buffer(size_t datalen) : buf(datalen), begin(buf.data()), tail(begin) {}

int Handler::on_key(ngtcp2_crypto_level level, const uint8_t *rx_secret,
                    const uint8_t *tx_secret, size_t secretlen) {
  std::array<uint8_t, 64> rx_key, rx_iv, rx_hp_key, tx_key, tx_iv, tx_hp_key;

  if (ngtcp2_crypto_derive_and_install_rx_key(
          conn_, rx_key.data(), rx_iv.data(), rx_hp_key.data(), level,
          rx_secret, secretlen) != 0) {
    return -1;
  }
  if (ngtcp2_crypto_derive_and_install_tx_key(
          conn_, tx_key.data(), tx_iv.data(), tx_hp_key.data(), level,
          tx_secret, secretlen) != 0) {
    return -1;
  }

  auto crypto_ctx = ngtcp2_conn_get_crypto_ctx(conn_);
  auto aead = &crypto_ctx->aead;
  auto keylen = ngtcp2_crypto_aead_keylen(aead);
  auto ivlen = ngtcp2_crypto_packet_protection_ivlen(aead);

  const char *title = nullptr;
  switch (level) {
  case NGTCP2_CRYPTO_LEVEL_EARLY:
    title = "early_traffic";
    keylog::log_secret(ssl_, keylog::QUIC_CLIENT_EARLY_TRAFFIC_SECRET,
                       rx_secret, secretlen);
    break;
  case NGTCP2_CRYPTO_LEVEL_HANDSHAKE:
    title = "handshake_traffic";
    keylog::log_secret(ssl_, keylog::QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET,
                       rx_secret, secretlen);
    keylog::log_secret(ssl_, keylog::QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET,
                       tx_secret, secretlen);
    break;
  case NGTCP2_CRYPTO_LEVEL_APP:
    title = "application_traffic";
    keylog::log_secret(ssl_, keylog::QUIC_CLIENT_TRAFFIC_SECRET_0, rx_secret,
                       secretlen);
    keylog::log_secret(ssl_, keylog::QUIC_SERVER_TRAFFIC_SECRET_0, tx_secret,
                       secretlen);
    break;
  default:
    assert(0);
  }

  if (!config.quiet && config.show_secret) {
    std::cerr << title << " rx secret" << std::endl;
    debug::print_secrets(rx_secret, secretlen, rx_key.data(), keylen,
                         rx_iv.data(), ivlen, rx_hp_key.data(), keylen);
    if (tx_secret) {
      std::cerr << title << " tx secret" << std::endl;
      debug::print_secrets(tx_secret, secretlen, tx_key.data(), keylen,
                           tx_iv.data(), ivlen, tx_hp_key.data(), keylen);
    }
  }

  if (level == NGTCP2_CRYPTO_LEVEL_APP && setup_httpconn() != 0) {
    return -1;
  }

  return 0;
}

Stream::Stream(int64_t stream_id, Handler *handler)
    : stream_id(stream_id),
      handler(handler),
      data(nullptr),
      datalen(0),
      dynresp(false),
      dyndataleft(0),
      dynbuflen(0) {}

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

struct Request {
  std::string path;
  std::vector<std::string> pushes;
  struct {
    int32_t urgency;
    int inc;
  } pri;
};

namespace {
Request request_path(const std::string_view &uri, bool is_connect) {
  http_parser_url u;
  Request req;

  req.pri.urgency = -1;
  req.pri.inc = -1;

  http_parser_url_init(&u);

  if (auto rv = http_parser_parse_url(uri.data(), uri.size(), is_connect, &u);
      rv != 0) {
    return req;
  }

  if (u.field_set & (1 << UF_PATH)) {
    req.path = std::string(uri.data() + u.field_data[UF_PATH].off,
                           u.field_data[UF_PATH].len);
    if (req.path.find('%') != std::string::npos) {
      req.path = util::percent_decode(std::begin(req.path), std::end(req.path));
    }
    if (!req.path.empty() && req.path.back() == '/') {
      req.path += "index.html";
    }
  } else {
    req.path = "/index.html";
  }

  req.path = util::normalize_path(req.path);
  if (req.path == "/") {
    req.path = "/index.html";
  }

  if (u.field_set & (1 << UF_QUERY)) {
    static constexpr char push_prefix[] = "push=";
    static constexpr char urgency_prefix[] = "u=";
    static constexpr char inc_prefix[] = "i=";
    auto q = std::string(uri.data() + u.field_data[UF_QUERY].off,
                         u.field_data[UF_QUERY].len);
    for (auto p = std::begin(q); p != std::end(q);) {
      if (util::istarts_with(p, std::end(q), std::begin(push_prefix),
                             std::end(push_prefix) - 1)) {
        auto path_start = p + sizeof(push_prefix) - 1;
        auto path_end = std::find(path_start, std::end(q), '&');
        if (path_start != path_end && *path_start == '/') {
          req.pushes.emplace_back(path_start, path_end);
        }
        if (path_end == std::end(q)) {
          break;
        }
        p = path_end + 1;
        continue;
      }
      if (util::istarts_with(p, std::end(q), std::begin(urgency_prefix),
                             std::end(urgency_prefix) - 1)) {
        auto urgency_start = p + sizeof(urgency_prefix) - 1;
        auto urgency_end = std::find(urgency_start, std::end(q), '&');
        if (urgency_start + 1 == urgency_end && '0' <= *urgency_start &&
            *urgency_start <= '7') {
          req.pri.urgency = *urgency_start - '0';
        }
        if (urgency_end == std::end(q)) {
          break;
        }
        p = urgency_end + 1;
        continue;
      }
      if (util::istarts_with(p, std::end(q), std::begin(inc_prefix),
                             std::end(inc_prefix) - 1)) {
        auto inc_start = p + sizeof(inc_prefix) - 1;
        auto inc_end = std::find(inc_start, std::end(q), '&');
        if (inc_start + 1 == inc_end &&
            (*inc_start == '0' || *inc_start == '1')) {
          req.pri.inc = *inc_start - '0';
        }
        if (inc_end == std::end(q)) {
          break;
        }
        p = inc_end + 1;
        continue;
      }

      p = std::find(p, std::end(q), '&');
      if (p == std::end(q)) {
        break;
      }
      ++p;
    }
  }
  return req;
}
} // namespace

enum FileEntryFlag {
  FILE_ENTRY_TYPE_DIR = 0x1,
};

struct FileEntry {
  uint64_t len;
  void *map;
  int fd;
  uint8_t flags;
};

namespace {
std::unordered_map<std::string, FileEntry> file_cache;
} // namespace

std::pair<FileEntry, int> Stream::open_file(const std::string &path) {
  auto it = file_cache.find(path);
  if (it != std::end(file_cache)) {
    return {(*it).second, 0};
  }

  auto fd = open(path.c_str(), O_RDONLY);
  if (fd == -1) {
    return {{}, -1};
  }

  struct stat st {};
  if (fstat(fd, &st) != 0) {
    close(fd);
    return {{}, -1};
  }

  FileEntry fe{};
  if (st.st_mode & S_IFDIR) {
    fe.flags |= FILE_ENTRY_TYPE_DIR;
    fe.fd = -1;
    close(fd);
  } else {
    fe.fd = fd;
    fe.len = st.st_size;
    fe.map = mmap(nullptr, fe.len, PROT_READ, MAP_SHARED, fd, 0);
    if (fe.map == MAP_FAILED) {
      std::cerr << "mmap: " << strerror(errno) << std::endl;
      close(fd);
      return {{}, -1};
    }
  }

  file_cache.emplace(path, fe);

  return {std::move(fe), 0};
}

void Stream::map_file(const FileEntry &fe) {
  data = static_cast<uint8_t *>(fe.map);
  datalen = fe.len;
}

int64_t Stream::find_dyn_length(const std::string_view &path) {
  assert(path[0] == '/');

  if (path.size() == 1) {
    return -1;
  }

  uint64_t n = 0;

  for (auto it = std::begin(path) + 1; it != std::end(path); ++it) {
    if (*it < '0' || '9' < *it) {
      return -1;
    }
    auto d = *it - '0';
    if (n > (((1ull << 62) - 1) - d) / 10) {
      return -1;
    }
    n = n * 10 + d;
    if (n > config.max_dyn_length) {
      return -1;
    }
  }

  return static_cast<int64_t>(n);
}

namespace {
nghttp3_ssize read_data(nghttp3_conn *conn, int64_t stream_id, nghttp3_vec *vec,
                        size_t veccnt, uint32_t *pflags, void *user_data,
                        void *stream_user_data) {
  auto stream = static_cast<Stream *>(stream_user_data);

  vec[0].base = stream->data;
  vec[0].len = stream->datalen;
  *pflags |= NGHTTP3_DATA_FLAG_EOF;
  if (config.send_trailers) {
    *pflags |= NGHTTP3_DATA_FLAG_NO_END_STREAM;
  }

  return 1;
}
} // namespace

auto dyn_buf = std::make_unique<std::array<uint8_t, 16_k>>();

namespace {
nghttp3_ssize dyn_read_data(nghttp3_conn *conn, int64_t stream_id,
                            nghttp3_vec *vec, size_t veccnt, uint32_t *pflags,
                            void *user_data, void *stream_user_data) {
  auto stream = static_cast<Stream *>(stream_user_data);

  if (stream->dynbuflen > MAX_DYNBUFLEN) {
    return NGHTTP3_ERR_WOULDBLOCK;
  }

  auto len =
      std::min(dyn_buf->size(), static_cast<size_t>(stream->dyndataleft));

  vec[0].base = dyn_buf->data();
  vec[0].len = len;

  stream->dynbuflen += len;
  stream->dyndataleft -= len;

  if (stream->dyndataleft == 0) {
    *pflags |= NGHTTP3_DATA_FLAG_EOF;
    if (config.send_trailers) {
      *pflags |= NGHTTP3_DATA_FLAG_NO_END_STREAM;
      auto stream_id_str = std::to_string(stream_id);
      std::array<nghttp3_nv, 1> trailers{
          util::make_nv("x-ngtcp2-stream-id", stream_id_str),
      };

      if (auto rv = nghttp3_conn_submit_trailers(
              conn, stream_id, trailers.data(), trailers.size());
          rv != 0) {
        std::cerr << "nghttp3_conn_submit_trailers: " << nghttp3_strerror(rv)
                  << std::endl;
        return NGHTTP3_ERR_CALLBACK_FAILURE;
      }
    }
  }

  return 1;
}
} // namespace

void Stream::http_acked_stream_data(size_t datalen) {
  if (!dynresp) {
    return;
  }

  assert(dynbuflen >= datalen);

  dynbuflen -= datalen;
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

  if (auto rv = nghttp3_conn_submit_response(httpconn, stream_id, nva.data(),
                                             nva.size(), &dr);
      rv != 0) {
    std::cerr << "nghttp3_conn_submit_response: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }

  if (config.send_trailers) {
    auto stream_id_str = std::to_string(stream_id);
    std::array<nghttp3_nv, 1> trailers{
        util::make_nv("x-ngtcp2-stream-id", stream_id_str),
    };

    if (auto rv = nghttp3_conn_submit_trailers(
            httpconn, stream_id, trailers.data(), trailers.size());
        rv != 0) {
      std::cerr << "nghttp3_conn_submit_trailers: " << nghttp3_strerror(rv)
                << std::endl;
      return -1;
    }
  }

  handler->shutdown_read(stream_id, NGHTTP3_H3_NO_ERROR);

  return 0;
}

int Stream::send_redirect_response(nghttp3_conn *httpconn,
                                   unsigned int status_code,
                                   const std::string_view &path) {
  return send_status_response(httpconn, status_code, {{"location", path}});
}

int Stream::start_response(nghttp3_conn *httpconn) {
  // TODO This should be handled by nghttp3
  if (uri.empty() || method.empty()) {
    return send_status_response(httpconn, 400);
  }

  auto req = request_path(uri, method == "CONNECT");
  if (req.path.empty()) {
    return send_status_response(httpconn, 400);
  }

  auto dyn_len = find_dyn_length(req.path);

  int64_t content_length = -1;
  nghttp3_data_reader dr{};
  std::string content_type = "text/plain";

  if (dyn_len == -1) {
    auto path = config.htdocs + req.path;
    auto [fe, rv] = open_file(path);
    if (rv != 0) {
      send_status_response(httpconn, 404);
      return 0;
    }

    if (fe.flags & FILE_ENTRY_TYPE_DIR) {
      send_redirect_response(httpconn, 308,
                             path.substr(config.htdocs.size() - 1) + '/');
      return 0;
    }

    content_length = fe.len;

    if (method != "HEAD") {
      map_file(fe);
    }

    dr.read_data = read_data;

    auto ext = std::end(req.path) - 1;
    for (; ext != std::begin(req.path) && *ext != '.' && *ext != '/'; --ext)
      ;
    if (*ext == '.') {
      ++ext;
      auto it = config.mime_types.find(std::string{ext, std::end(req.path)});
      if (it != std::end(config.mime_types)) {
        content_type = (*it).second;
      }
    }

  } else {
    content_length = dyn_len;
    datalen = dyn_len;
    dynresp = true;
    dyndataleft = dyn_len;

    dr.read_data = dyn_read_data;

    content_type = "application/octet-stream";
  }

  if ((stream_id & 0x3) == 0 && !authority.empty()) {
    for (const auto &push : req.pushes) {
      if (handler->push_content(stream_id, authority, push) != 0) {
        return -1;
      }
    }
  }

  auto content_length_str = std::to_string(content_length);

  std::array<nghttp3_nv, 5> nva{
      util::make_nv(":status", "200"),
      util::make_nv("server", NGTCP2_SERVER),
      util::make_nv("content-type", content_type),
      util::make_nv("content-length", content_length_str),
  };

  size_t nvlen = 4;

  std::string prival;

  if (req.pri.urgency != -1 || req.pri.inc != -1) {
    nghttp3_pri pri;

    if (auto rv = nghttp3_conn_get_stream_priority(httpconn, &pri, stream_id);
        rv != 0) {
      std::cerr << "nghttp3_conn_get_stream_priority: " << nghttp3_strerror(rv)
                << std::endl;
      return -1;
    }

    if (req.pri.urgency != -1) {
      pri.urgency = req.pri.urgency;
    }
    if (req.pri.inc != -1) {
      pri.inc = req.pri.inc;
    }

    if (auto rv = nghttp3_conn_set_stream_priority(httpconn, stream_id, &pri);
        rv != 0) {
      std::cerr << "nghttp3_conn_set_stream_priority: " << nghttp3_strerror(rv)
                << std::endl;
      return -1;
    }

    prival = "u=";
    prival += pri.urgency + '0';
    prival += ",i";
    if (!pri.inc) {
      prival += "=?0";
    }

    nva[nvlen++] = util::make_nv("priority", prival);
  }

  if (!config.quiet) {
    debug::print_http_response_headers(stream_id, nva.data(), nvlen);
  }

  if (auto rv = nghttp3_conn_submit_response(httpconn, stream_id, nva.data(),
                                             nvlen, &dr);
      rv != 0) {
    std::cerr << "nghttp3_conn_submit_response: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }

  if (config.send_trailers && dyn_len == -1) {
    auto stream_id_str = std::to_string(stream_id);
    std::array<nghttp3_nv, 1> trailers{
        util::make_nv("x-ngtcp2-stream-id", stream_id_str),
    };

    if (auto rv = nghttp3_conn_submit_trailers(
            httpconn, stream_id, trailers.data(), trailers.size());
        rv != 0) {
      std::cerr << "nghttp3_conn_submit_trailers: " << nghttp3_strerror(rv)
                << std::endl;
      return -1;
    }

    handler->shutdown_read(stream_id, NGHTTP3_H3_NO_ERROR);
  }

  return 0;
}

namespace {
void writecb(struct ev_loop *loop, ev_io *w, int revents) {
  ev_io_stop(loop, w);

  auto h = static_cast<Handler *>(w->data);
  auto s = h->server();

  switch (h->on_write()) {
  case 0:
  case NETWORK_ERR_CLOSE_WAIT:
    return;
  default:
    s->remove(h);
  }
}
} // namespace

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

  if (!config.quiet) {
    std::cerr << "Timer expired" << std::endl;
  }

  rv = h->handle_expiry();
  if (rv != 0) {
    goto fail;
  }

  rv = h->on_write();
  if (rv != 0) {
    goto fail;
  }

  return;

fail:
  switch (rv) {
  case NETWORK_ERR_CLOSE_WAIT:
    ev_timer_stop(loop, w);
    return;
  default:
    s->remove(h);
    return;
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
      qlog_(nullptr),
      crypto_{},
      conn_(nullptr),
      scid_{},
      pscid_{},
      rcid_(*rcid),
      httpconn_{nullptr},
      last_error_{QUICErrorType::Transport, 0},
      nkey_update_(0),
      draining_(false) {
  ev_io_init(&wev_, writecb, 0, EV_WRITE);
  wev_.data = this;
  ev_timer_init(&timer_, timeoutcb, 0.,
                static_cast<double>(config.timeout) / NGTCP2_SECONDS);
  timer_.data = this;
  ev_timer_init(&rttimer_, retransmitcb, 0., 0.);
  rttimer_.data = this;
}

Handler::~Handler() {
  if (!config.quiet) {
    std::cerr << scid_ << " Closing QUIC connection " << std::endl;
  }

  ev_timer_stop(loop_, &rttimer_);
  ev_timer_stop(loop_, &timer_);
  ev_io_stop(loop_, &wev_);

  if (httpconn_) {
    nghttp3_conn_del(httpconn_);
  }

  if (conn_) {
    ngtcp2_conn_del(conn_);
  }

  if (ssl_) {
    SSL_free(ssl_);
  }

  if (qlog_) {
    fclose(qlog_);
  }
}

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

  std::array<uint8_t, MAX_TOKENLEN> token;
  size_t tokenlen = token.size();

  if (server_->generate_token(token.data(), tokenlen, &remote_addr_.su.sa) !=
      0) {
    if (!config.quiet) {
      std::cerr << "Unable to generate token" << std::endl;
    }
    return 0;
  }

  if (auto rv = ngtcp2_conn_submit_new_token(conn_, token.data(), tokenlen);
      rv != 0) {
    if (!config.quiet) {
      std::cerr << "ngtcp2_conn_submit_new_token: " << ngtcp2_strerror(rv)
                << std::endl;
    }
    return -1;
  }

  return 0;
}

namespace {
int do_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
               const ngtcp2_crypto_cipher_ctx *hp_ctx, const uint8_t *sample) {
  if (ngtcp2_crypto_hp_mask(dest, hp, hp_ctx, sample) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  if (!config.quiet && config.show_secret) {
    debug::print_hp_mask(dest, NGTCP2_HP_MASKLEN, sample, NGTCP2_HP_SAMPLELEN);
  }

  return 0;
}
} // namespace

namespace {
int recv_crypto_data(ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data) {
  if (!config.quiet && !config.no_quic_dump) {
    debug::print_crypto_data(crypto_level, data, datalen);
  }

  auto h = static_cast<Handler *>(user_data);

  if (h->recv_crypto_data(crypto_level, data, datalen) != 0) {
    if (auto err = ngtcp2_conn_get_tls_error(conn); err) {
      return err;
    }
    return NGTCP2_ERR_CRYPTO;
  }

  return 0;
}
} // namespace

namespace {
int recv_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data, void *stream_user_data) {
  auto h = static_cast<Handler *>(user_data);

  if (h->recv_stream_data(flags, stream_id, data, datalen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

namespace {
int acked_crypto_offset(ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level,
                        uint64_t offset, uint64_t datalen, void *user_data) {
  auto h = static_cast<Handler *>(user_data);
  h->remove_tx_crypto_data(crypto_level, offset, datalen);
  return 0;
}
} // namespace

namespace {
int acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id,
                             uint64_t offset, uint64_t datalen, void *user_data,
                             void *stream_user_data) {
  auto h = static_cast<Handler *>(user_data);
  if (h->acked_stream_data_offset(stream_id, datalen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
} // namespace

int Handler::acked_stream_data_offset(int64_t stream_id, uint64_t datalen) {
  if (!httpconn_) {
    return 0;
  }

  if (auto rv = nghttp3_conn_add_ack_offset(httpconn_, stream_id, datalen);
      rv != 0) {
    std::cerr << "nghttp3_conn_add_ack_offset: " << nghttp3_strerror(rv)
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
  if (!ngtcp2_is_bidi_stream(stream_id)) {
    return;
  }
  auto it = streams_.find(stream_id);
  assert(it == std::end(streams_));
  streams_.emplace(stream_id, std::make_unique<Stream>(stream_id, this));
}

int Handler::push_content(int64_t stream_id, const std::string_view &authority,
                          const std::string_view &path) {
  auto nva = std::array<nghttp3_nv, 4>{
      util::make_nv(":method", "GET"),
      util::make_nv(":scheme", "https"),
      util::make_nv(":authority", authority),
      util::make_nv(":path", path),
  };

  int64_t push_id;
  if (auto rv = nghttp3_conn_submit_push_promise(httpconn_, &push_id, stream_id,
                                                 nva.data(), nva.size());
      rv != 0) {
    std::cerr << "nghttp3_conn_submit_push_promise: " << nghttp3_strerror(rv)
              << std::endl;
    if (rv != NGHTTP3_ERR_PUSH_ID_BLOCKED) {
      return -1;
    }
    return 0;
  }

  if (!config.quiet) {
    debug::print_http_push_promise(stream_id, push_id, nva.data(), nva.size());
  }

  int64_t push_stream_id;
  if (auto rv = ngtcp2_conn_open_uni_stream(conn_, &push_stream_id, nullptr);
      rv != 0) {
    std::cerr << "ngtcp2_conn_open_uni_stream: " << ngtcp2_strerror(rv)
              << std::endl;
    if (rv != NGTCP2_ERR_STREAM_ID_BLOCKED) {
      return -1;
    }
    return 0;
  }

  if (!config.quiet) {
    debug::push_stream(push_id, push_stream_id);
  }

  Stream *stream;
  {
    auto p = std::make_unique<Stream>(push_stream_id, this);
    stream = p.get();
    streams_.emplace(push_stream_id, std::move(p));
  }

  if (auto rv =
          nghttp3_conn_bind_push_stream(httpconn_, push_id, push_stream_id);
      rv != 0) {
    std::cerr << "nghttp3_conn_bind_push_stream: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }

  stream->uri = path;
  stream->method = "GET";
  stream->authority = authority;

  nghttp3_conn_set_stream_user_data(httpconn_, push_stream_id, stream);

  stream->start_response(httpconn_);

  return 0;
}

namespace {
int stream_close(ngtcp2_conn *conn, int64_t stream_id, uint64_t app_error_code,
                 void *user_data, void *stream_user_data) {
  auto h = static_cast<Handler *>(user_data);
  if (h->on_stream_close(stream_id, app_error_code) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
} // namespace

namespace {
int stream_reset(ngtcp2_conn *conn, int64_t stream_id, uint64_t final_size,
                 uint64_t app_error_code, void *user_data,
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
    if (auto rv = nghttp3_conn_reset_stream(httpconn_, stream_id); rv != 0) {
      std::cerr << "nghttp3_conn_reset_stream: " << nghttp3_strerror(rv)
                << std::endl;
      return -1;
    }
  }
  return 0;
}

namespace {
int rand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx,
         ngtcp2_rand_usage usage) {
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
  auto md = ngtcp2_crypto_md{const_cast<EVP_MD *>(EVP_sha256())};
  if (ngtcp2_crypto_generate_stateless_reset_token(
          token, &md, config.static_secret.data(), config.static_secret.size(),
          cid) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

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
int update_key(ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
               ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
               ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
               const uint8_t *current_rx_secret,
               const uint8_t *current_tx_secret, size_t secretlen,
               void *user_data) {
  auto h = static_cast<Handler *>(user_data);
  if (h->update_key(rx_secret, tx_secret, rx_aead_ctx, rx_iv, tx_aead_ctx,
                    tx_iv, current_rx_secret, current_tx_secret,
                    secretlen) != 0) {
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
  if (!config.quiet && !config.no_http_dump) {
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
  auto stream = static_cast<Stream *>(stream_user_data);
  h->http_recv_request_header(stream, token, name, value);
  return 0;
}
} // namespace

void Handler::http_recv_request_header(Stream *stream, int32_t token,
                                       nghttp3_rcbuf *name,
                                       nghttp3_rcbuf *value) {
  auto v = nghttp3_rcbuf_get_buf(value);

  switch (token) {
  case NGHTTP3_QPACK_TOKEN__PATH:
    stream->uri = std::string{v.base, v.base + v.len};
    break;
  case NGHTTP3_QPACK_TOKEN__METHOD:
    stream->method = std::string{v.base, v.base + v.len};
    break;
  case NGHTTP3_QPACK_TOKEN__AUTHORITY:
    stream->authority = std::string{v.base, v.base + v.len};
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
  auto stream = static_cast<Stream *>(stream_user_data);
  if (h->http_end_request_headers(stream) != 0) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
} // namespace

int Handler::http_end_request_headers(Stream *stream) {
  if (config.early_response) {
    return start_response(stream);
  }
  return 0;
}

namespace {
int http_end_stream(nghttp3_conn *conn, int64_t stream_id, void *user_data,
                    void *stream_user_data) {
  auto h = static_cast<Handler *>(user_data);
  auto stream = static_cast<Stream *>(stream_user_data);
  if (h->http_end_stream(stream) != 0) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
} // namespace

int Handler::http_end_stream(Stream *stream) {
  if (!config.early_response) {
    return start_response(stream);
  }
  return 0;
}

int Handler::start_response(Stream *stream) {
  return stream->start_response(httpconn_);
}

namespace {
int http_acked_stream_data(nghttp3_conn *conn, int64_t stream_id,
                           size_t datalen, void *user_data,
                           void *stream_user_data) {
  auto h = static_cast<Handler *>(user_data);
  auto stream = static_cast<Stream *>(stream_user_data);
  h->http_acked_stream_data(stream, datalen);
  return 0;
}
} // namespace

void Handler::http_acked_stream_data(Stream *stream, size_t datalen) {
  stream->http_acked_stream_data(datalen);

  if (stream->dynresp && stream->dynbuflen < MAX_DYNBUFLEN - 16384) {
    if (auto rv = nghttp3_conn_resume_stream(httpconn_, stream->stream_id);
        rv != 0) {
      // TODO Handle error
      std::cerr << "nghttp3_conn_resume_stream: " << nghttp3_strerror(rv)
                << std::endl;
    }
  }
}

namespace {
int http_stream_close(nghttp3_conn *conn, int64_t stream_id,
                      uint64_t app_error_code, void *conn_user_data,
                      void *stream_user_data) {
  auto h = static_cast<Handler *>(conn_user_data);
  h->http_stream_close(stream_id, app_error_code);
  return 0;
}
} // namespace

void Handler::http_stream_close(int64_t stream_id, uint64_t app_error_code) {
  auto it = streams_.find(stream_id);
  if (it == std::end(streams_)) {
    return;
  }

  if (!config.quiet) {
    std::cerr << "HTTP stream " << stream_id << " closed with error code "
              << app_error_code << std::endl;
  }

  streams_.erase(it);

  if (ngtcp2_is_bidi_stream(stream_id)) {
    assert(!ngtcp2_conn_is_local_stream(conn_, stream_id));
    ngtcp2_conn_extend_max_streams_bidi(conn_, 1);
  }
}

int Handler::setup_httpconn() {
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
      ::http_stream_close,
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
      nullptr, // cancel_push
      nullptr, // send_stop_sending
      nullptr, // push_stream
      ::http_end_stream,
  };
  nghttp3_conn_settings settings;
  nghttp3_conn_settings_default(&settings);
  settings.qpack_max_table_capacity = 4096;
  settings.qpack_blocked_streams = 100;

  auto mem = nghttp3_mem_default();

  if (auto rv =
          nghttp3_conn_server_new(&httpconn_, &callbacks, &settings, mem, this);
      rv != 0) {
    std::cerr << "nghttp3_conn_server_new: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }

  ngtcp2_transport_params params;
  ngtcp2_conn_get_local_transport_params(conn_, &params);

  nghttp3_conn_set_max_client_streams_bidi(httpconn_,
                                           params.initial_max_streams_bidi);

  int64_t ctrl_stream_id;

  if (auto rv = ngtcp2_conn_open_uni_stream(conn_, &ctrl_stream_id, nullptr);
      rv != 0) {
    std::cerr << "ngtcp2_conn_open_uni_stream: " << ngtcp2_strerror(rv)
              << std::endl;
    return -1;
  }

  if (auto rv = nghttp3_conn_bind_control_stream(httpconn_, ctrl_stream_id);
      rv != 0) {
    std::cerr << "nghttp3_conn_bind_control_stream: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }

  if (!config.quiet) {
    fprintf(stderr, "http: control stream=%" PRIx64 "\n", ctrl_stream_id);
  }

  int64_t qpack_enc_stream_id, qpack_dec_stream_id;

  if (auto rv =
          ngtcp2_conn_open_uni_stream(conn_, &qpack_enc_stream_id, nullptr);
      rv != 0) {
    std::cerr << "ngtcp2_conn_open_uni_stream: " << ngtcp2_strerror(rv)
              << std::endl;
    return -1;
  }

  if (auto rv =
          ngtcp2_conn_open_uni_stream(conn_, &qpack_dec_stream_id, nullptr);
      rv != 0) {
    std::cerr << "ngtcp2_conn_open_uni_stream: " << ngtcp2_strerror(rv)
              << std::endl;
    return -1;
  }

  if (auto rv = nghttp3_conn_bind_qpack_streams(httpconn_, qpack_enc_stream_id,
                                                qpack_dec_stream_id);
      rv != 0) {
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
  if (auto rv = nghttp3_conn_unblock_stream(httpconn_, stream_id); rv != 0) {
    std::cerr << "nghttp3_conn_unblock_stream: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }
  return 0;
}

namespace {
void write_qlog(void *user_data, uint32_t flags, const void *data,
                size_t datalen) {
  auto h = static_cast<Handler *>(user_data);
  h->write_qlog(data, datalen);
}
} // namespace

void Handler::write_qlog(const void *data, size_t datalen) {
  assert(qlog_);
  fwrite(data, 1, datalen, qlog_);
}

int Handler::init(const Endpoint &ep, const sockaddr *sa, socklen_t salen,
                  const ngtcp2_cid *dcid, const ngtcp2_cid *scid,
                  const ngtcp2_cid *ocid, const uint8_t *token, size_t tokenlen,
                  uint32_t version) {
  endpoint_ = const_cast<Endpoint *>(&ep);

  remote_addr_.len = salen;
  memcpy(&remote_addr_.su.sa, sa, salen);

  if (config.max_udp_payload_size) {
    max_pktlen_ = config.max_udp_payload_size;
  } else {
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
  }

  ssl_ = SSL_new(ssl_ctx_);
  SSL_set_app_data(ssl_, this);
  SSL_set_accept_state(ssl_);
  SSL_set_quic_early_data_enabled(ssl_, 1);

  auto callbacks = ngtcp2_conn_callbacks{
      nullptr, // client_initial
      ngtcp2_crypto_recv_client_initial_cb,
      ::recv_crypto_data,
      ::handshake_completed,
      nullptr, // recv_version_negotiation
      ngtcp2_crypto_encrypt_cb,
      ngtcp2_crypto_decrypt_cb,
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
      ::extend_max_remote_streams_bidi,
      nullptr, // extend_max_remote_streams_uni
      ::extend_max_stream_data,
      nullptr, // dcid_status
      nullptr, // handshake_confirmed
      nullptr, // recv_new_token
      ngtcp2_crypto_delete_crypto_aead_ctx_cb,
      ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
  };

  auto dis = std::uniform_int_distribution<uint8_t>(0, 255);

  scid_.datalen = NGTCP2_SV_SCIDLEN;
  std::generate(scid_.data, scid_.data + scid_.datalen,
                [&dis]() { return dis(randgen); });

  ngtcp2_settings settings;
  ngtcp2_settings_default(&settings);
  settings.log_printf = config.quiet ? nullptr : debug::log_printf;
  settings.initial_ts = util::timestamp(loop_);
  settings.token = ngtcp2_vec{const_cast<uint8_t *>(token), tokenlen};
  settings.max_udp_payload_size = max_pktlen_;
  settings.cc_algo =
      config.cc == "cubic" ? NGTCP2_CC_ALGO_CUBIC : NGTCP2_CC_ALGO_RENO;
  settings.initial_rtt = config.initial_rtt;
  if (!config.qlog_dir.empty()) {
    auto path = std::string{config.qlog_dir};
    path += '/';
    path += util::format_hex(scid_.data, scid_.datalen);
    path += ".qlog";
    qlog_ = fopen(path.c_str(), "w");
    if (qlog_ == nullptr) {
      std::cerr << "Could not open qlog file " << path << ": "
                << strerror(errno) << std::endl;
      return -1;
    }
    settings.qlog.write = ::write_qlog;
    settings.qlog.odcid = *scid;
  }
  auto &params = settings.transport_params;
  params.initial_max_stream_data_bidi_local = config.max_stream_data_bidi_local;
  params.initial_max_stream_data_bidi_remote =
      config.max_stream_data_bidi_remote;
  params.initial_max_stream_data_uni = config.max_stream_data_uni;
  params.initial_max_data = config.max_data;
  params.initial_max_streams_bidi = config.max_streams_bidi;
  params.initial_max_streams_uni = config.max_streams_uni;
  params.max_idle_timeout = config.timeout;
  params.stateless_reset_token_present = 1;
  params.active_connection_id_limit = 7;

  if (ocid) {
    params.original_dcid = *ocid;
    params.retry_scid = *scid;
    params.retry_scid_present = 1;
  } else {
    params.original_dcid = *scid;
  }

  std::generate(std::begin(params.stateless_reset_token),
                std::end(params.stateless_reset_token),
                [&dis]() { return dis(randgen); });

  if (config.preferred_ipv4_addr.len || config.preferred_ipv6_addr.len) {
    params.preferred_address_present = 1;
    if (config.preferred_ipv4_addr.len) {
      auto &dest = params.preferred_address.ipv4_addr;
      const auto &addr = config.preferred_ipv4_addr;
      assert(sizeof(dest) == sizeof(addr.su.in.sin_addr));
      memcpy(&dest, &addr.su.in.sin_addr, sizeof(dest));
      params.preferred_address.ipv4_port = htons(addr.su.in.sin_port);
    }
    if (config.preferred_ipv6_addr.len) {
      auto &dest = params.preferred_address.ipv6_addr;
      const auto &addr = config.preferred_ipv6_addr;
      assert(sizeof(dest) == sizeof(addr.su.in6.sin6_addr));
      memcpy(&dest, &addr.su.in6.sin6_addr, sizeof(dest));
      params.preferred_address.ipv6_port = htons(addr.su.in6.sin6_port);
    }

    auto &token = params.preferred_address.stateless_reset_token;
    std::generate(std::begin(token), std::end(token),
                  [&dis]() { return dis(randgen); });

    pscid_.datalen = NGTCP2_SV_SCIDLEN;
    std::generate(pscid_.data, pscid_.data + pscid_.datalen,
                  [&dis]() { return dis(randgen); });
    params.preferred_address.cid = pscid_;
  }

  auto path = ngtcp2_path{{ep.addr.len, const_cast<sockaddr *>(&ep.addr.su.sa),
                           const_cast<Endpoint *>(&ep)},
                          {salen, const_cast<sockaddr *>(sa)}};
  if (auto rv = ngtcp2_conn_server_new(&conn_, dcid, &scid_, &path, version,
                                       &callbacks, &settings, nullptr, this);
      rv != 0) {
    std::cerr << "ngtcp2_conn_server_new: " << ngtcp2_strerror(rv) << std::endl;
    return -1;
  }

  ngtcp2_conn_set_tls_native_handle(conn_, ssl_);

  ev_io_set(&wev_, endpoint_->fd, EV_WRITE);
  ev_timer_again(loop_, &timer_);

  return 0;
}

void Handler::write_server_handshake(ngtcp2_crypto_level level,
                                     const uint8_t *data, size_t datalen) {
  auto &crypto = crypto_[level];
  crypto.data.emplace_back(data, datalen);

  auto &buf = crypto.data.back();

  ngtcp2_conn_submit_crypto_data(conn_, level, buf.rpos(), buf.size());
}

int Handler::recv_crypto_data(ngtcp2_crypto_level crypto_level,
                              const uint8_t *data, size_t datalen) {
  return ngtcp2_crypto_read_write_crypto_data(conn_, crypto_level, data,
                                              datalen);
}

void Handler::update_endpoint(const ngtcp2_addr *addr) {
  endpoint_ = static_cast<Endpoint *>(addr->user_data);
  assert(endpoint_);
}

void Handler::update_remote_addr(const ngtcp2_addr *addr,
                                 const ngtcp2_pkt_info *pi) {
  remote_addr_.len = addr->addrlen;
  memcpy(&remote_addr_.su, addr->addr, addr->addrlen);

  if (pi) {
    ecn_ = pi->ecn;
  } else {
    ecn_ = 0;
  }
}

int Handler::feed_data(const Endpoint &ep, const sockaddr *sa, socklen_t salen,
                       const ngtcp2_pkt_info *pi, uint8_t *data,
                       size_t datalen) {
  auto path = ngtcp2_path{{ep.addr.len, const_cast<sockaddr *>(&ep.addr.su.sa),
                           const_cast<Endpoint *>(&ep)},
                          {salen, const_cast<sockaddr *>(sa)}};

  if (auto rv = ngtcp2_conn_read_pkt(conn_, &path, pi, data, datalen,
                                     util::timestamp(loop_));
      rv != 0) {
    std::cerr << "ngtcp2_conn_read_pkt: " << ngtcp2_strerror(rv) << std::endl;
    switch (rv) {
    case NGTCP2_ERR_DRAINING:
      start_draining_period();
      return NETWORK_ERR_CLOSE_WAIT;
    case NGTCP2_ERR_RETRY:
      return NETWORK_ERR_RETRY;
    case NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM:
    case NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM:
    case NGTCP2_ERR_TRANSPORT_PARAM:
      // If rv indicates transport_parameters related error, we should
      // send TRANSPORT_PARAMETER_ERROR even if last_error_.code is
      // already set.  This is because OpenSSL might set Alert.
      last_error_ = quic_err_transport(rv);
      break;
    case NGTCP2_ERR_DROP_CONN:
      return NETWORK_ERR_DROP_CONN;
    default:
      if (!last_error_.code) {
        last_error_ = quic_err_transport(rv);
      }
    }
    return handle_error();
  }

  return 0;
}

int Handler::on_read(const Endpoint &ep, const sockaddr *sa, socklen_t salen,
                     const ngtcp2_pkt_info *pi, uint8_t *data, size_t datalen) {
  if (auto rv = feed_data(ep, sa, salen, pi, data, datalen); rv != 0) {
    return rv;
  }

  reset_idle_timer();

  return 0;
}

void Handler::reset_idle_timer() {
  auto now = util::timestamp(loop_);
  auto idle_expiry = ngtcp2_conn_get_idle_expiry(conn_);
  timer_.repeat =
      idle_expiry > now
          ? static_cast<ev_tstamp>(idle_expiry - now) / NGTCP2_SECONDS
          : 1e-9;

  if (!config.quiet) {
    std::cerr << "Set idle timer=" << std::fixed << timer_.repeat << "s"
              << std::defaultfloat << std::endl;
  }

  ev_timer_again(loop_, &timer_);
}

int Handler::handle_expiry() {
  auto now = util::timestamp(loop_);
  if (ngtcp2_conn_loss_detection_expiry(conn_) <= now) {
    if (!config.quiet) {
      std::cerr << "Loss detection timer expired" << std::endl;
    }
  }

  if (ngtcp2_conn_ack_delay_expiry(conn_) <= now) {
    if (!config.quiet) {
      std::cerr << "Delayed ACK timer expired" << std::endl;
    }
  }

  if (auto rv = ngtcp2_conn_handle_expiry(conn_, now); rv != 0) {
    std::cerr << "ngtcp2_conn_handle_expiry: " << ngtcp2_strerror(rv)
              << std::endl;
    last_error_ = quic_err_transport(rv);
    return handle_error();
  }

  return 0;
}

int Handler::on_write() {
  if (ngtcp2_conn_is_in_closing_period(conn_) ||
      ngtcp2_conn_is_in_draining_period(conn_)) {
    return 0;
  }

  if (auto rv = write_streams(); rv != 0) {
    return rv;
  }

  schedule_retransmit();

  return 0;
}

int Handler::write_streams() {
  std::array<nghttp3_vec, 16> vec;
  PathStorage path;
  size_t pktcnt = 0;
  size_t max_pktcnt = std::min(static_cast<size_t>(10),
                               static_cast<size_t>(64_k / max_pktlen_));
  std::array<uint8_t, 64_k> buf;
  uint8_t *bufpos = buf.data();
  ngtcp2_pkt_info pi;

  for (;;) {
    int64_t stream_id = -1;
    int fin = 0;
    nghttp3_ssize sveccnt = 0;

    if (httpconn_ && ngtcp2_conn_get_max_data_left(conn_)) {
      sveccnt = nghttp3_conn_writev_stream(httpconn_, &stream_id, &fin,
                                           vec.data(), vec.size());
      if (sveccnt < 0) {
        std::cerr << "nghttp3_conn_writev_stream: " << nghttp3_strerror(sveccnt)
                  << std::endl;
        last_error_ = quic_err_app(sveccnt);
        return handle_error();
      }
    }

    ngtcp2_ssize ndatalen;
    auto v = vec.data();
    auto vcnt = static_cast<size_t>(sveccnt);

    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
    if (fin) {
      flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
    }

    auto nwrite = ngtcp2_conn_writev_stream(
        conn_, &path.path, &pi, bufpos, max_pktlen_, &ndatalen, flags,
        stream_id, reinterpret_cast<const ngtcp2_vec *>(v), vcnt,
        util::timestamp(loop_));
    if (nwrite < 0) {
      switch (nwrite) {
      case NGTCP2_ERR_STREAM_DATA_BLOCKED:
      case NGTCP2_ERR_STREAM_SHUT_WR:
        assert(ndatalen == -1);
        if (auto rv = nghttp3_conn_block_stream(httpconn_, stream_id);
            rv != 0) {
          std::cerr << "nghttp3_conn_block_stream: " << nghttp3_strerror(rv)
                    << std::endl;
          last_error_ = quic_err_app(rv);
          return handle_error();
        }
        continue;
      case NGTCP2_ERR_WRITE_MORE:
        assert(ndatalen > 0);
        if (auto rv =
                nghttp3_conn_add_write_offset(httpconn_, stream_id, ndatalen);
            rv != 0) {
          std::cerr << "nghttp3_conn_add_write_offset: " << nghttp3_strerror(rv)
                    << std::endl;
          last_error_ = quic_err_app(rv);
          return handle_error();
        }
        continue;
      }

      assert(ndatalen == -1);

      std::cerr << "ngtcp2_conn_writev_stream: " << ngtcp2_strerror(nwrite)
                << std::endl;
      last_error_ = quic_err_transport(nwrite);
      return handle_error();
    }

    assert(ndatalen == -1);

    if (nwrite == 0) {
      if (bufpos - buf.data()) {
        server_->send_packet(*endpoint_, remote_addr_, ecn_, buf.data(),
                             bufpos - buf.data(), max_pktlen_);
        reset_idle_timer();
      }
      // We are congestion limited.
      return 0;
    }

    bufpos += nwrite;

#if NGTCP2_ENABLE_UDP_GSO
    if (pktcnt == 0) {
      update_endpoint(&path.path.local);
      update_remote_addr(&path.path.remote, &pi);
    } else if (remote_addr_.len != path.path.remote.addrlen ||
               0 != memcmp(&remote_addr_.su, path.path.remote.addr,
                           path.path.remote.addrlen) ||
               endpoint_ != path.path.local.user_data || ecn_ != pi.ecn) {
      server_->send_packet(*endpoint_, remote_addr_, ecn_, buf.data(),
                           bufpos - buf.data() - nwrite, max_pktlen_);

      update_endpoint(&path.path.local);
      update_remote_addr(&path.path.remote, &pi);

      server_->send_packet(*endpoint_, remote_addr_, ecn_, bufpos - nwrite,
                           nwrite, max_pktlen_);
      reset_idle_timer();
      ev_io_start(loop_, &wev_);
      return 0;
    }

    if (++pktcnt == max_pktcnt || static_cast<size_t>(nwrite) < max_pktlen_) {
      server_->send_packet(*endpoint_, remote_addr_, ecn_, buf.data(),
                           bufpos - buf.data(), max_pktlen_);
      reset_idle_timer();
      ev_io_start(loop_, &wev_);
      return 0;
    }
#else  // !NGTCP2_ENABLE_UDP_GSO
    update_endpoint(&path.path.local);
    update_remote_addr(&path.path.remote, &pi);
    reset_idle_timer();

    server_->send_packet(*endpoint_, remote_addr_, ecn_, buf.data(),
                         bufpos - buf.data(), 0);
    if (++pktcnt == max_pktcnt) {
      ev_io_start(loop_, &wev_);
      return 0;
    }

    bufpos = buf.data();
#endif // !NGTCP2_ENABLE_UDP_GSO
  }
}

void Handler::signal_write() { ev_io_start(loop_, &wev_); }

bool Handler::draining() const { return draining_; }

void Handler::start_draining_period() {
  draining_ = true;

  ev_timer_stop(loop_, &rttimer_);

  timer_.repeat =
      static_cast<ev_tstamp>(ngtcp2_conn_get_pto(conn_)) / NGTCP2_SECONDS * 3;
  ev_timer_again(loop_, &timer_);

  if (!config.quiet) {
    std::cerr << "Draining period has started (" << timer_.repeat << " seconds)"
              << std::endl;
  }
}

int Handler::start_closing_period() {
  if (!conn_ || ngtcp2_conn_is_in_closing_period(conn_)) {
    return 0;
  }

  ev_timer_stop(loop_, &rttimer_);

  timer_.repeat =
      static_cast<ev_tstamp>(ngtcp2_conn_get_pto(conn_)) / NGTCP2_SECONDS * 3;
  ev_timer_again(loop_, &timer_);

  if (!config.quiet) {
    std::cerr << "Closing period has started (" << timer_.repeat << " seconds)"
              << std::endl;
  }

  conn_closebuf_ = std::make_unique<Buffer>(max_pktlen_);

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
  update_remote_addr(&path.path.remote, nullptr);

  return 0;
}

int Handler::handle_error() {
  if (start_closing_period() != 0) {
    return -1;
  }

  if (auto rv = send_conn_close(); rv != NETWORK_ERR_OK) {
    return rv;
  }

  return NETWORK_ERR_CLOSE_WAIT;
}

int Handler::send_conn_close() {
  if (!config.quiet) {
    std::cerr << "Closing Period: TX CONNECTION_CLOSE" << std::endl;
  }

  assert(conn_closebuf_ && conn_closebuf_->size());

  return server_->send_packet(*endpoint_, remote_addr_, 0,
                              conn_closebuf_->rpos(), conn_closebuf_->size(),
                              0);
}

void Handler::schedule_retransmit() {
  auto expiry = ngtcp2_conn_get_expiry(conn_);
  auto now = util::timestamp(loop_);
  auto t = expiry < now ? 1e-9
                        : static_cast<ev_tstamp>(expiry - now) / NGTCP2_SECONDS;
  if (!config.quiet) {
    std::cerr << "Set timer=" << std::fixed << t << "s" << std::defaultfloat
              << std::endl;
  }
  rttimer_.repeat = t;
  ev_timer_again(loop_, &rttimer_);
}

int Handler::recv_stream_data(uint32_t flags, int64_t stream_id,
                              const uint8_t *data, size_t datalen) {
  if (!config.quiet && !config.no_quic_dump) {
    debug::print_stream_data(stream_id, data, datalen);
  }

  if (!httpconn_) {
    return 0;
  }

  auto nconsumed = nghttp3_conn_read_stream(
      httpconn_, stream_id, data, datalen, flags & NGTCP2_STREAM_DATA_FLAG_FIN);
  if (nconsumed < 0) {
    std::cerr << "nghttp3_conn_read_stream: " << nghttp3_strerror(nconsumed)
              << std::endl;
    last_error_ = quic_err_app(nconsumed);
    return -1;
  }

  ngtcp2_conn_extend_max_stream_offset(conn_, stream_id, nconsumed);
  ngtcp2_conn_extend_max_offset(conn_, nconsumed);

  return 0;
}

int Handler::update_key(uint8_t *rx_secret, uint8_t *tx_secret,
                        ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
                        ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
                        const uint8_t *current_rx_secret,
                        const uint8_t *current_tx_secret, size_t secretlen) {
  auto crypto_ctx = ngtcp2_conn_get_crypto_ctx(conn_);
  auto aead = &crypto_ctx->aead;
  auto keylen = ngtcp2_crypto_aead_keylen(aead);
  auto ivlen = ngtcp2_crypto_packet_protection_ivlen(aead);

  ++nkey_update_;

  std::array<uint8_t, 64> rx_key, tx_key;

  if (ngtcp2_crypto_update_key(conn_, rx_secret, tx_secret, rx_aead_ctx,
                               rx_key.data(), rx_iv, tx_aead_ctx, tx_key.data(),
                               tx_iv, current_rx_secret, current_tx_secret,
                               secretlen) != 0) {
    return -1;
  }

  if (!config.quiet && config.show_secret) {
    std::cerr << "application_traffic rx secret " << nkey_update_ << std::endl;
    debug::print_secrets(rx_secret, secretlen, rx_key.data(), keylen, rx_iv,
                         ivlen);
    std::cerr << "application_traffic tx secret " << nkey_update_ << std::endl;
    debug::print_secrets(tx_secret, secretlen, tx_key.data(), keylen, tx_iv,
                         ivlen);
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
void remove_tx_stream_data(std::deque<Buffer> &d, uint64_t &tx_offset,
                           uint64_t offset) {
  for (; !d.empty() && tx_offset + d.front().size() <= offset;) {
    auto &v = d.front();
    tx_offset += v.size();
    d.pop_front();
  }
}
} // namespace

void Handler::remove_tx_crypto_data(ngtcp2_crypto_level crypto_level,
                                    uint64_t offset, uint64_t datalen) {
  auto &crypto = crypto_[crypto_level];
  ::remove_tx_stream_data(crypto.data, crypto.acked_offset, offset + datalen);
}

int Handler::on_stream_close(int64_t stream_id, uint64_t app_error_code) {
  if (!config.quiet) {
    std::cerr << "QUIC stream " << stream_id << " closed" << std::endl;
  }

  if (httpconn_) {
    if (app_error_code == 0) {
      app_error_code = NGHTTP3_H3_NO_ERROR;
    }
    auto rv = nghttp3_conn_close_stream(httpconn_, stream_id, app_error_code);
    switch (rv) {
    case 0:
      break;
    case NGHTTP3_ERR_STREAM_NOT_FOUND:
      if (ngtcp2_is_bidi_stream(stream_id)) {
        assert(!ngtcp2_conn_is_local_stream(conn_, stream_id));
        ngtcp2_conn_extend_max_streams_bidi(conn_, 1);
      }
      break;
    default:
      std::cerr << "nghttp3_conn_close_stream: " << nghttp3_strerror(rv)
                << std::endl;
      last_error_ = quic_err_app(rv);
      return -1;
    }
  }

  return 0;
}

void Handler::shutdown_read(int64_t stream_id, int app_error_code) {
  ngtcp2_conn_shutdown_stream_read(conn_, stream_id, app_error_code);
}

void Handler::set_tls_alert(uint8_t alert) {
  last_error_ = quic_err_tls(alert);
}

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
    : loop_(loop), ssl_ctx_(ssl_ctx) {
  ev_signal_init(&sigintev_, siginthandler, SIGINT);

  token_aead_.native_handle = const_cast<EVP_CIPHER *>(EVP_aes_128_gcm());
  token_md_.native_handle = const_cast<EVP_MD *>(EVP_sha256());
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

    remove(h.get());
  }
}

void Server::close() {
  for (auto &ep : endpoints_) {
    ::close(ep.fd);
  }

  endpoints_.clear();
}

namespace {
int create_sock(Address &local_addr, const char *addr, const char *port,
                int family) {
  addrinfo hints{};
  addrinfo *res, *rp;
  int val = 1;

  hints.ai_family = family;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;

  if (strcmp(addr, "*") == 0) {
    addr = nullptr;
  }

  if (auto rv = getaddrinfo(addr, port, &hints, &res); rv != 0) {
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
    close(fd);
    return -1;
  }

  fd_set_recv_ecn(fd, rp->ai_family);

  socklen_t len = sizeof(local_addr.su.storage);
  if (getsockname(fd, &local_addr.su.sa, &len) == -1) {
    std::cerr << "getsockname: " << strerror(errno) << std::endl;
    close(fd);
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

  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val,
                 static_cast<socklen_t>(sizeof(val))) == -1) {
    close(fd);
    return -1;
  }

  fd_set_recv_ecn(fd, addr.su.sa.sa_family);

  endpoints.emplace_back(Endpoint{});
  auto &ep = endpoints.back();
  ep.addr = addr;
  ep.fd = fd;
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
    ep.rev.data = &ep;

    ev_io_set(&ep.rev, ep.fd, EV_READ);

    ev_io_start(loop_, &ep.rev);
  }

  ev_signal_start(loop_, &sigintev_);

  return 0;
}

int Server::on_read(Endpoint &ep) {
  sockaddr_union su;
  std::array<uint8_t, 64_k> buf;
  ngtcp2_pkt_hd hd;
  size_t pktcnt = 0;
  ngtcp2_pkt_info pi;

  iovec msg_iov;
  msg_iov.iov_base = buf.data();
  msg_iov.iov_len = buf.size();

  msghdr msg{};
  msg.msg_name = &su;
  msg.msg_iov = &msg_iov;
  msg.msg_iovlen = 1;

  uint8_t msg_ctrl[CMSG_SPACE(sizeof(uint8_t))];
  msg.msg_control = msg_ctrl;

  for (; pktcnt < 10;) {
    msg.msg_namelen = sizeof(su);
    msg.msg_controllen = sizeof(msg_ctrl);

    auto nread = recvmsg(ep.fd, &msg, MSG_DONTWAIT);
    if (nread == -1) {
      if (!(errno == EAGAIN || errno == ENOTCONN)) {
        std::cerr << "recvfrom: " << strerror(errno) << std::endl;
      }
      return 0;
    }

    ++pktcnt;

    pi.ecn = msghdr_get_ecn(&msg, su.storage.ss_family);

    if (!config.quiet) {
      std::cerr << "Received packet: local="
                << util::straddr(&ep.addr.su.sa, ep.addr.len)
                << " remote=" << util::straddr(&su.sa, msg.msg_namelen)
                << " ecn=0x" << std::hex << pi.ecn << std::dec << " " << nread
                << " bytes" << std::endl;
    }

    if (debug::packet_lost(config.rx_loss_prob)) {
      if (!config.quiet) {
        std::cerr << "** Simulated incoming packet loss **" << std::endl;
      }
      continue;
    }

    if (nread == 0) {
      continue;
    }

    uint32_t version;
    const uint8_t *dcid, *scid;
    size_t dcidlen, scidlen;

    if (auto rv = ngtcp2_pkt_decode_version_cid(&version, &dcid, &dcidlen,
                                                &scid, &scidlen, buf.data(),
                                                nread, NGTCP2_SV_SCIDLEN);
        rv != 0) {
      if (rv == 1) {
        send_version_negotiation(version, scid, scidlen, dcid, dcidlen, ep,
                                 &su.sa, msg.msg_namelen);
        continue;
      }
      std::cerr << "Could not decode version and CID from QUIC packet header: "
                << ngtcp2_strerror(rv) << std::endl;
      continue;
    }

    auto dcid_key = util::make_cid_key(dcid, dcidlen);

    auto handler_it = handlers_.find(dcid_key);
    if (handler_it == std::end(handlers_)) {
      auto ctos_it = ctos_.find(dcid_key);
      if (ctos_it == std::end(ctos_)) {
        if (auto rv = ngtcp2_accept(&hd, buf.data(), nread); rv == -1) {
          if (!config.quiet) {
            std::cerr << "Unexpected packet received: length=" << nread
                      << std::endl;
          }
          continue;
        } else if (rv == 1) {
          if (!config.quiet) {
            std::cerr << "Unsupported version: Send Version Negotiation"
                      << std::endl;
          }
          send_version_negotiation(hd.version, hd.scid.data, hd.scid.datalen,
                                   hd.dcid.data, hd.dcid.datalen, ep, &su.sa,
                                   msg.msg_namelen);
          continue;
        }

        ngtcp2_cid ocid;
        ngtcp2_cid *pocid = nullptr;
        switch (hd.type) {
        case NGTCP2_PKT_INITIAL:
          if (config.validate_addr || hd.token.len) {
            std::cerr << "Perform stateless address validation" << std::endl;
            if (hd.token.len == 0) {
              send_retry(&hd, ep, &su.sa, msg.msg_namelen);
              continue;
            }

            if (hd.token.base[0] != RETRY_TOKEN_MAGIC &&
                hd.dcid.datalen < NGTCP2_MIN_INITIAL_DCIDLEN) {
              send_stateless_connection_close(&hd, ep, &su.sa, msg.msg_namelen);
              continue;
            }

            switch (hd.token.base[0]) {
            case RETRY_TOKEN_MAGIC:
              if (verify_retry_token(&ocid, &hd, &su.sa, msg.msg_namelen) !=
                  0) {
                send_stateless_connection_close(&hd, ep, &su.sa,
                                                msg.msg_namelen);
                continue;
              }
              pocid = &ocid;
              break;
            case TOKEN_MAGIC:
              if (verify_token(&hd, &su.sa, msg.msg_namelen) != 0) {
                if (config.validate_addr) {
                  send_retry(&hd, ep, &su.sa, msg.msg_namelen);
                  continue;
                }

                hd.token.base = nullptr;
                hd.token.len = 0;
              }
              break;
            default:
              if (!config.quiet) {
                std::cerr << "Ignore unrecognized token" << std::endl;
              }
              if (config.validate_addr) {
                send_retry(&hd, ep, &su.sa, msg.msg_namelen);
                continue;
              }

              hd.token.base = nullptr;
              hd.token.len = 0;
              break;
            }
          }
          break;
        case NGTCP2_PKT_0RTT:
          send_retry(&hd, ep, &su.sa, msg.msg_namelen);
          continue;
        }

        auto h = std::make_unique<Handler>(loop_, ssl_ctx_, this, &hd.dcid);
        if (h->init(ep, &su.sa, msg.msg_namelen, &hd.scid, &hd.dcid, pocid,
                    hd.token.base, hd.token.len, hd.version) != 0) {
          continue;
        }

        switch (
            h->on_read(ep, &su.sa, msg.msg_namelen, &pi, buf.data(), nread)) {
        case 0:
          break;
        case NETWORK_ERR_RETRY:
          send_retry(&hd, ep, &su.sa, msg.msg_namelen);
          continue;
        default:
          continue;
        }

        switch (h->on_write()) {
        case 0:
          break;
        default:
          continue;
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
        continue;
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
      switch (h->send_conn_close()) {
      case 0:
        break;
      default:
        remove(h);
      }
      continue;
    }
    if (h->draining()) {
      continue;
    }

    if (auto rv =
            h->on_read(ep, &su.sa, msg.msg_namelen, &pi, buf.data(), nread);
        rv != 0) {
      if (rv != NETWORK_ERR_CLOSE_WAIT) {
        remove(h);
      }
      continue;
    }

    h->signal_write();
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

int Server::send_version_negotiation(uint32_t version, const uint8_t *dcid,
                                     size_t dcidlen, const uint8_t *scid,
                                     size_t scidlen, Endpoint &ep,
                                     const sockaddr *sa, socklen_t salen) {
  Buffer buf{NGTCP2_MAX_PKTLEN_IPV4};
  std::array<uint32_t, 2> sv;

  sv[0] = generate_reserved_version(sa, salen, version);
  sv[1] = NGTCP2_PROTO_VER;

  auto nwrite = ngtcp2_pkt_write_version_negotiation(
      buf.wpos(), buf.left(),
      std::uniform_int_distribution<uint8_t>(
          0, std::numeric_limits<uint8_t>::max())(randgen),
      dcid, dcidlen, scid, scidlen, sv.data(), sv.size());
  if (nwrite < 0) {
    std::cerr << "ngtcp2_pkt_write_version_negotiation: "
              << ngtcp2_strerror(nwrite) << std::endl;
    return -1;
  }

  buf.push(nwrite);

  Address remote_addr;
  remote_addr.len = salen;
  memcpy(&remote_addr.su.sa, sa, salen);

  if (send_packet(ep, remote_addr, 0, buf.rpos(), buf.size(), 0) !=
      NETWORK_ERR_OK) {
    return -1;
  }

  return 0;
}

int Server::send_retry(const ngtcp2_pkt_hd *chd, Endpoint &ep,
                       const sockaddr *sa, socklen_t salen) {
  std::array<char, NI_MAXHOST> host;
  std::array<char, NI_MAXSERV> port;

  if (auto rv = getnameinfo(sa, salen, host.data(), host.size(), port.data(),
                            port.size(), NI_NUMERICHOST | NI_NUMERICSERV);
      rv != 0) {
    std::cerr << "getnameinfo: " << gai_strerror(rv) << std::endl;
    return -1;
  }

  if (!config.quiet) {
    std::cerr << "Sending Retry packet to [" << host.data()
              << "]:" << port.data() << std::endl;
  }

  ngtcp2_cid scid;

  scid.datalen = NGTCP2_SV_SCIDLEN;
  auto dis = std::uniform_int_distribution<uint8_t>(0, 255);
  std::generate(scid.data, scid.data + scid.datalen,
                [&dis]() { return dis(randgen); });

  std::array<uint8_t, MAX_RETRY_TOKENLEN> token;
  size_t tokenlen = token.size();

  if (generate_retry_token(token.data(), tokenlen, sa, salen, &scid,
                           &chd->dcid) != 0) {
    return -1;
  }

  if (!config.quiet) {
    std::cerr << "Generated address validation token:" << std::endl;
    util::hexdump(stderr, token.data(), tokenlen);
  }

  Buffer buf{NGTCP2_MAX_PKTLEN_IPV4};

  auto nwrite =
      ngtcp2_crypto_write_retry(buf.wpos(), buf.left(), &chd->scid, &scid,
                                &chd->dcid, token.data(), tokenlen);
  if (nwrite < 0) {
    std::cerr << "ngtcp2_crypto_write_retry failed" << std::endl;
    return -1;
  }

  buf.push(nwrite);

  Address remote_addr;
  remote_addr.len = salen;
  memcpy(&remote_addr.su.sa, sa, salen);

  if (send_packet(ep, remote_addr, 0, buf.rpos(), buf.size(), 0) !=
      NETWORK_ERR_OK) {
    return -1;
  }

  return 0;
}

int Server::send_stateless_connection_close(const ngtcp2_pkt_hd *chd,
                                            Endpoint &ep, const sockaddr *sa,
                                            socklen_t salen) {
  Buffer buf{NGTCP2_MAX_PKTLEN_IPV4};

  auto nwrite = ngtcp2_crypto_write_connection_close(
      buf.wpos(), buf.left(), &chd->scid, &chd->dcid, NGTCP2_INVALID_TOKEN);
  if (nwrite < 0) {
    std::cerr << "ngtcp2_crypto_write_connection_close failed" << std::endl;
    return -1;
  }

  buf.push(nwrite);

  Address remote_addr;
  remote_addr.len = salen;
  memcpy(&remote_addr.su.sa, sa, salen);

  if (send_packet(ep, remote_addr, 0, buf.rpos(), buf.size(), 0) !=
      NETWORK_ERR_OK) {
    return -1;
  }

  return 0;
}

int Server::derive_token_key(uint8_t *key, size_t &keylen, uint8_t *iv,
                             size_t &ivlen, const uint8_t *rand_data,
                             size_t rand_datalen) {
  std::array<uint8_t, 32> secret;

  if (ngtcp2_crypto_hkdf_extract(
          secret.data(), &token_md_, config.static_secret.data(),
          config.static_secret.size(), rand_data, rand_datalen) != 0) {
    return -1;
  }

  keylen = ngtcp2_crypto_aead_keylen(&token_aead_);
  ivlen = ngtcp2_crypto_packet_protection_ivlen(&token_aead_);

  if (ngtcp2_crypto_derive_packet_protection_key(key, iv, nullptr, &token_aead_,
                                                 &token_md_, secret.data(),
                                                 secret.size()) != 0) {
    return -1;
  }

  return 0;
}

void Server::generate_rand_data(uint8_t *buf, size_t len) {
  auto dis = std::uniform_int_distribution<uint8_t>(0, 255);
  std::generate_n(buf, len, [&dis]() { return dis(randgen); });
}

namespace {
size_t generate_retry_token_aad(uint8_t *dest, size_t destlen,
                                const sockaddr *sa, socklen_t salen,
                                const ngtcp2_cid *retry_scid) {
  assert(destlen >= salen + retry_scid->datalen);

  auto p = std::copy_n(reinterpret_cast<const uint8_t *>(sa), salen, dest);
  p = std::copy_n(retry_scid->data, retry_scid->datalen, p);

  return p - dest;
}
} // namespace

int Server::generate_retry_token(uint8_t *token, size_t &tokenlen,
                                 const sockaddr *sa, socklen_t salen,
                                 const ngtcp2_cid *retry_scid,
                                 const ngtcp2_cid *ocid) {
  std::array<uint8_t, 4096> plaintext;

  uint64_t t = std::chrono::duration_cast<std::chrono::nanoseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

  auto p = std::begin(plaintext);
  // Host byte order
  p = std::copy_n(reinterpret_cast<uint8_t *>(&t), sizeof(t), p);
  p = std::copy_n(ocid->data, ocid->datalen, p);

  std::array<uint8_t, TOKEN_RAND_DATALEN> rand_data;
  std::array<uint8_t, 32> key, iv;
  auto keylen = key.size();
  auto ivlen = iv.size();

  generate_rand_data(rand_data.data(), rand_data.size());
  if (derive_token_key(key.data(), keylen, iv.data(), ivlen, rand_data.data(),
                       rand_data.size()) != 0) {
    return -1;
  }

  auto plaintextlen = std::distance(std::begin(plaintext), p);

  std::array<uint8_t, 256> aad;
  auto aadlen =
      generate_retry_token_aad(aad.data(), aad.size(), sa, salen, retry_scid);

  token[0] = RETRY_TOKEN_MAGIC;

  ngtcp2_crypto_aead_ctx aead_ctx;
  if (ngtcp2_crypto_aead_ctx_encrypt_init(&aead_ctx, &token_aead_, key.data(),
                                          ivlen) != 0) {
    return -1;
  }

  auto rv = ngtcp2_crypto_encrypt(token + 1, &token_aead_, &aead_ctx,
                                  plaintext.data(), plaintextlen, iv.data(),
                                  ivlen, aad.data(), aadlen);

  ngtcp2_crypto_aead_ctx_free(&aead_ctx);

  if (rv != 0) {
    return -1;
  }

  /* 1 for magic byte */
  tokenlen = 1 + plaintextlen + ngtcp2_crypto_aead_taglen(&token_aead_);
  memcpy(token + tokenlen, rand_data.data(), rand_data.size());
  tokenlen += rand_data.size();

  return 0;
}

int Server::verify_retry_token(ngtcp2_cid *ocid, const ngtcp2_pkt_hd *hd,
                               const sockaddr *sa, socklen_t salen) {
  std::array<char, NI_MAXHOST> host;
  std::array<char, NI_MAXSERV> port;

  if (auto rv = getnameinfo(sa, salen, host.data(), host.size(), port.data(),
                            port.size(), NI_NUMERICHOST | NI_NUMERICSERV);
      rv != 0) {
    std::cerr << "getnameinfo: " << gai_strerror(rv) << std::endl;
    return -1;
  }

  if (!config.quiet) {
    std::cerr << "Verifying Retry token from [" << host.data()
              << "]:" << port.data() << std::endl;
    util::hexdump(stderr, hd->token.base, hd->token.len);
  }

  /* 1 for RETRY_TOKEN_MAGIC */
  if (hd->token.len < TOKEN_RAND_DATALEN + 1) {
    if (!config.quiet) {
      std::cerr << "Token is too short" << std::endl;
    }
    return -1;
  }
  if (hd->token.len > MAX_RETRY_TOKENLEN) {
    if (!config.quiet) {
      std::cerr << "Token is too long" << std::endl;
    }
    return -1;
  }

  assert(hd->token.base[0] == RETRY_TOKEN_MAGIC);

  auto rand_data = hd->token.base + hd->token.len - TOKEN_RAND_DATALEN;
  auto ciphertext = hd->token.base + 1;
  auto ciphertextlen = hd->token.len - TOKEN_RAND_DATALEN - 1;

  std::array<uint8_t, 32> key, iv;
  auto keylen = key.size();
  auto ivlen = iv.size();

  if (derive_token_key(key.data(), keylen, iv.data(), ivlen, rand_data,
                       TOKEN_RAND_DATALEN) != 0) {
    return -1;
  }

  std::array<uint8_t, 256> aad;
  auto aadlen =
      generate_retry_token_aad(aad.data(), aad.size(), sa, salen, &hd->dcid);

  ngtcp2_crypto_aead_ctx aead_ctx;
  if (ngtcp2_crypto_aead_ctx_decrypt_init(&aead_ctx, &token_aead_, key.data(),
                                          ivlen) != 0) {
    return -1;
  }

  std::array<uint8_t, MAX_RETRY_TOKENLEN> plaintext;

  auto rv = ngtcp2_crypto_decrypt(plaintext.data(), &token_aead_, &aead_ctx,
                                  ciphertext, ciphertextlen, iv.data(), ivlen,
                                  aad.data(), aadlen);

  ngtcp2_crypto_aead_ctx_free(&aead_ctx);

  if (rv != 0) {
    if (!config.quiet) {
      std::cerr << "Could not decrypt token" << std::endl;
    }
    return -1;
  }

  assert(ciphertextlen >= ngtcp2_crypto_aead_taglen(&token_aead_));

  auto plaintextlen = ciphertextlen - ngtcp2_crypto_aead_taglen(&token_aead_);
  if (plaintextlen < sizeof(uint64_t)) {
    if (!config.quiet) {
      std::cerr << "Bad token construction" << std::endl;
    }
    return -1;
  }

  auto cil = plaintextlen - sizeof(uint64_t);
  if (cil != 0 && (cil < NGTCP2_MIN_CIDLEN || cil > NGTCP2_MAX_CIDLEN)) {
    if (!config.quiet) {
      std::cerr << "Bad token construction" << std::endl;
    }
    return -1;
  }

  uint64_t t;
  memcpy(&t, plaintext.data(), sizeof(uint64_t));

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

  ngtcp2_cid_init(ocid, plaintext.data() + sizeof(uint64_t), cil);

  if (!config.quiet) {
    std::cerr << "Token was successfully validated" << std::endl;
  }

  return 0;
}

namespace {
size_t generate_token_aad(uint8_t *dest, size_t destlen, const sockaddr *sa) {
  const uint8_t *addr;
  size_t addrlen;

  switch (sa->sa_family) {
  case AF_INET:
    addr = reinterpret_cast<const uint8_t *>(
        &reinterpret_cast<const sockaddr_in *>(sa)->sin_addr);
    addrlen = sizeof(reinterpret_cast<const sockaddr_in *>(sa)->sin_addr);
    break;
  case AF_INET6:
    addr = reinterpret_cast<const uint8_t *>(
        &reinterpret_cast<const sockaddr_in6 *>(sa)->sin6_addr);
    addrlen = sizeof(reinterpret_cast<const sockaddr_in6 *>(sa)->sin6_addr);
    break;
  default:
    if (!config.quiet) {
      std::cerr << "Unknown address family 0x" << std::hex << sa->sa_family
                << std::dec << std::endl;
    }
    return -1;
  }

  assert(destlen >= addrlen);

  return std::copy_n(addr, addrlen, dest) - dest;
}
} // namespace

int Server::generate_token(uint8_t *token, size_t &tokenlen,
                           const sockaddr *sa) {
  std::array<uint8_t, 8> plaintext;

  uint64_t t = std::chrono::duration_cast<std::chrono::nanoseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

  std::array<uint8_t, 256> aad;
  auto aadlen = generate_token_aad(aad.data(), aad.size(), sa);

  auto p = std::begin(plaintext);
  // Host byte order
  p = std::copy_n(reinterpret_cast<uint8_t *>(&t), sizeof(t), p);

  std::array<uint8_t, TOKEN_RAND_DATALEN> rand_data;
  std::array<uint8_t, 32> key, iv;
  auto keylen = key.size();
  auto ivlen = iv.size();

  generate_rand_data(rand_data.data(), rand_data.size());
  if (derive_token_key(key.data(), keylen, iv.data(), ivlen, rand_data.data(),
                       rand_data.size()) != 0) {
    return -1;
  }

  auto plaintextlen = std::distance(std::begin(plaintext), p);

  ngtcp2_crypto_aead_ctx aead_ctx;
  if (ngtcp2_crypto_aead_ctx_encrypt_init(&aead_ctx, &token_aead_, key.data(),
                                          ivlen) != 0) {
    return -1;
  }

  token[0] = TOKEN_MAGIC;
  auto rv = ngtcp2_crypto_encrypt(token + 1, &token_aead_, &aead_ctx,
                                  plaintext.data(), plaintextlen, iv.data(),
                                  ivlen, aad.data(), aadlen);

  ngtcp2_crypto_aead_ctx_free(&aead_ctx);

  if (rv != 0) {
    return -1;
  }

  /* 1 for magic byte */
  tokenlen = 1 + plaintextlen + ngtcp2_crypto_aead_taglen(&token_aead_);
  memcpy(token + tokenlen, rand_data.data(), rand_data.size());
  tokenlen += rand_data.size();

  return 0;
}

int Server::verify_token(const ngtcp2_pkt_hd *hd, const sockaddr *sa,
                         socklen_t salen) {
  std::array<char, NI_MAXHOST> host;
  std::array<char, NI_MAXSERV> port;

  if (auto rv = getnameinfo(sa, salen, host.data(), host.size(), port.data(),
                            port.size(), NI_NUMERICHOST | NI_NUMERICSERV);
      rv != 0) {
    std::cerr << "getnameinfo: " << gai_strerror(rv) << std::endl;
    return -1;
  }

  if (!config.quiet) {
    std::cerr << "Verifying token from [" << host.data() << "]:" << port.data()
              << std::endl;
    util::hexdump(stderr, hd->token.base, hd->token.len);
  }

  /* 1 for TOKEN_MAGIC */
  if (hd->token.len < TOKEN_RAND_DATALEN + 1) {
    if (!config.quiet) {
      std::cerr << "Token is too short" << std::endl;
    }
    return -1;
  }
  if (hd->token.len > MAX_TOKENLEN) {
    if (!config.quiet) {
      std::cerr << "Token is too long" << std::endl;
    }
    return -1;
  }

  assert(hd->token.base[0] == TOKEN_MAGIC);

  std::array<uint8_t, 256> aad;
  auto aadlen = generate_token_aad(aad.data(), aad.size(), sa);

  auto rand_data = hd->token.base + hd->token.len - TOKEN_RAND_DATALEN;
  auto ciphertext = hd->token.base + 1;
  auto ciphertextlen = hd->token.len - TOKEN_RAND_DATALEN - 1;

  std::array<uint8_t, 32> key, iv;
  auto keylen = key.size();
  auto ivlen = iv.size();

  if (derive_token_key(key.data(), keylen, iv.data(), ivlen, rand_data,
                       TOKEN_RAND_DATALEN) != 0) {
    return -1;
  }

  ngtcp2_crypto_aead_ctx aead_ctx;
  if (ngtcp2_crypto_aead_ctx_decrypt_init(&aead_ctx, &token_aead_, key.data(),
                                          ivlen) != 0) {
    return -1;
  }

  std::array<uint8_t, MAX_TOKENLEN> plaintext;

  auto rv = ngtcp2_crypto_decrypt(plaintext.data(), &token_aead_, &aead_ctx,
                                  ciphertext, ciphertextlen, iv.data(), ivlen,
                                  aad.data(), aadlen);

  ngtcp2_crypto_aead_ctx_free(&aead_ctx);

  if (rv != 0) {
    if (!config.quiet) {
      std::cerr << "Could not decrypt token" << std::endl;
    }
    return -1;
  }

  assert(ciphertextlen >= ngtcp2_crypto_aead_taglen(&token_aead_));

  auto plaintextlen = ciphertextlen - ngtcp2_crypto_aead_taglen(&token_aead_);
  if (plaintextlen != sizeof(uint64_t)) {
    if (!config.quiet) {
      std::cerr << "Bad token construction" << std::endl;
    }
    return -1;
  }

  uint64_t t;
  memcpy(&t, plaintext.data(), sizeof(uint64_t));

  uint64_t now = std::chrono::duration_cast<std::chrono::nanoseconds>(
                     std::chrono::system_clock::now().time_since_epoch())
                     .count();

  // Allow 1 hour window
  if (t + 3600ULL * NGTCP2_SECONDS < now) {
    if (!config.quiet) {
      std::cerr << "Token has been expired" << std::endl;
    }
    return -1;
  }

  if (!config.quiet) {
    std::cerr << "Token was successfully validated" << std::endl;
  }

  return 0;
}

int Server::send_packet(Endpoint &ep, const Address &remote_addr,
                        unsigned int ecn, const uint8_t *data, size_t datalen,
                        size_t gso_size) {
  if (debug::packet_lost(config.tx_loss_prob)) {
    if (!config.quiet) {
      std::cerr << "** Simulated outgoing packet loss **" << std::endl;
    }
    return NETWORK_ERR_OK;
  }

  iovec msg_iov;
  msg_iov.iov_base = const_cast<uint8_t *>(data);
  msg_iov.iov_len = datalen;

  msghdr msg{};
  msg.msg_name = const_cast<sockaddr *>(&remote_addr.su.sa);
  msg.msg_namelen = remote_addr.len;
  msg.msg_iov = &msg_iov;
  msg.msg_iovlen = 1;

#if NGTCP2_ENABLE_UDP_GSO
  std::array<uint8_t, CMSG_SPACE(sizeof(uint16_t))> msg_ctrl{};
  if (gso_size && datalen > gso_size) {
    msg.msg_control = msg_ctrl.data();
    msg.msg_controllen = msg_ctrl.size();

    auto cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = SOL_UDP;
    cm->cmsg_type = UDP_SEGMENT;
    cm->cmsg_len = CMSG_LEN(sizeof(uint16_t));
    *(reinterpret_cast<uint16_t *>(CMSG_DATA(cm))) = gso_size;
  }
#endif // NGTCP2_ENABLE_UDP_GSO

  if (ep.ecn != ecn) {
    ep.ecn = ecn;
    fd_set_ecn(ep.fd, ep.addr.su.storage.ss_family, ecn);
  }

  ssize_t nwrite = 0;

  do {
    nwrite = sendmsg(ep.fd, &msg, 0);
  } while (nwrite == -1 && errno == EINTR);

  if (nwrite == -1) {
    std::cerr << "sendmsg: " << strerror(errno) << std::endl;
    // TODO We have packet which is expected to fail to send (e.g.,
    // path validation to old path).
    return NETWORK_ERR_OK;
  }

  if (!config.quiet) {
    std::cerr << "Sent packet: local="
              << util::straddr(&ep.addr.su.sa, ep.addr.len) << " remote="
              << util::straddr(&remote_addr.su.sa, remote_addr.len) << " ecn=0x"
              << std::hex << ecn << std::dec << " " << nwrite << " bytes"
              << std::endl;
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

namespace {
int alpn_select_proto_cb(SSL *ssl, const unsigned char **out,
                         unsigned char *outlen, const unsigned char *in,
                         unsigned int inlen, void *arg) {
  auto h = static_cast<Handler *>(SSL_get_app_data(ssl));
  const uint8_t *alpn;
  size_t alpnlen;
  auto version = ngtcp2_conn_get_negotiated_version(h->conn());

  switch (version) {
  case NGTCP2_PROTO_VER:
    alpn = reinterpret_cast<const uint8_t *>(NGHTTP3_ALPN_H3);
    alpnlen = str_size(NGHTTP3_ALPN_H3);
    break;
  default:
    if (!config.quiet) {
      std::cerr << "Unexpected quic protocol version: " << std::hex << "0x"
                << version << std::dec << std::endl;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }

  for (auto p = in, end = in + inlen; p + alpnlen <= end; p += *p + 1) {
    if (std::equal(alpn, alpn + alpnlen, p)) {
      *out = p + 1;
      *outlen = *p;
      return SSL_TLSEXT_ERR_OK;
    }
  }

  if (!config.quiet) {
    std::cerr << "Client did not present ALPN " << &NGHTTP3_ALPN_H3[1]
              << std::endl;
  }

  return SSL_TLSEXT_ERR_ALERT_FATAL;
}
} // namespace

namespace {
int set_encryption_secrets(SSL *ssl, OSSL_ENCRYPTION_LEVEL ossl_level,
                           const uint8_t *read_secret,
                           const uint8_t *write_secret, size_t secret_len) {
  auto h = static_cast<Handler *>(SSL_get_app_data(ssl));

  if (auto rv = h->on_key(util::from_ossl_level(ossl_level), read_secret,
                          write_secret, secret_len);
      rv != 0) {
    return 0;
  }

  return 1;
}
} // namespace

namespace {
int add_handshake_data(SSL *ssl, OSSL_ENCRYPTION_LEVEL ossl_level,
                       const uint8_t *data, size_t len) {
  auto h = static_cast<Handler *>(SSL_get_app_data(ssl));
  h->write_server_handshake(util::from_ossl_level(ossl_level), data, len);
  return 1;
}
} // namespace

namespace {
int flush_flight(SSL *ssl) { return 1; }
} // namespace

namespace {
int send_alert(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert) {
  auto h = static_cast<Handler *>(SSL_get_app_data(ssl));
  h->set_tls_alert(alert);
  return 1;
}
} // namespace

namespace {
auto quic_method = SSL_QUIC_METHOD{
    set_encryption_secrets,
    add_handshake_data,
    flush_flight,
    send_alert,
};
} // namespace

namespace {
int client_hello_cb(SSL *ssl, int *al, void *arg) {
  const uint8_t *tp;
  size_t tplen;

  if (!SSL_client_hello_get0_ext(ssl, NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS,
                                 &tp, &tplen)) {
    *al = SSL_AD_INTERNAL_ERROR;
    return SSL_CLIENT_HELLO_ERROR;
  }

  return SSL_CLIENT_HELLO_SUCCESS;
}
} // namespace

namespace {
int verify_cb(int preverify_ok, X509_STORE_CTX *ctx) {
  // We don't verify the client certificate.  Just request it for the
  // testing purpose.
  return 1;
}
} // namespace

namespace {
SSL_CTX *create_ssl_ctx(const char *private_key_file, const char *cert_file) {
  constexpr static unsigned char sid_ctx[] = "ngtcp2 server";

  auto ssl_ctx = SSL_CTX_new(TLS_server_method());

  constexpr auto ssl_opts = (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) |
                            SSL_OP_SINGLE_ECDH_USE |
                            SSL_OP_CIPHER_SERVER_PREFERENCE |
                            SSL_OP_NO_ANTI_REPLAY;

  SSL_CTX_set_options(ssl_ctx, ssl_opts);

  if (SSL_CTX_set_ciphersuites(ssl_ctx, config.ciphers) != 1) {
    std::cerr << "SSL_CTX_set_ciphersuites: "
              << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_set1_groups_list(ssl_ctx, config.groups) != 1) {
    std::cerr << "SSL_CTX_set1_groups_list failed" << std::endl;
    exit(EXIT_FAILURE);
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
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_file) != 1) {
    std::cerr << "SSL_CTX_use_certificate_file: "
              << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
    std::cerr << "SSL_CTX_check_private_key: "
              << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
    exit(EXIT_FAILURE);
  }

  SSL_CTX_set_session_id_context(ssl_ctx, sid_ctx, sizeof(sid_ctx) - 1);

  if (config.verify_client) {
    SSL_CTX_set_verify(ssl_ctx,
                       SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE |
                           SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       verify_cb);
  }

  SSL_CTX_set_max_early_data(ssl_ctx, std::numeric_limits<uint32_t>::max());
  SSL_CTX_set_quic_method(ssl_ctx, &quic_method);
  SSL_CTX_set_client_hello_cb(ssl_ctx, client_hello_cb, nullptr);

  return ssl_ctx;
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

  if (auto rv = getaddrinfo(host.data(), svc_begin, &hints, &res); rv != 0) {
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
                   "POLY1305_SHA256:TLS_AES_128_CCM_SHA256";
  config.groups = "P-256:X25519:P-384:P-521";
  config.timeout = 30 * NGTCP2_SECONDS;
  {
    auto path = realpath(".", nullptr);
    assert(path);
    config.htdocs = path;
    free(path);
  }
  config.mime_types_file = "/etc/mime.types";
  config.max_data = 1_m;
  config.max_stream_data_bidi_local = 256_k;
  config.max_stream_data_bidi_remote = 256_k;
  config.max_stream_data_uni = 256_k;
  config.max_streams_bidi = 100;
  config.max_streams_uni = 3;
  config.max_dyn_length = 20_m;
  config.cc = "cubic"sv;
  config.initial_rtt = NGTCP2_DEFAULT_INITIAL_RTT;
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
  --timeout=<DURATION>
              Specify idle timeout.
              Default: )"
            << util::format_duration(config.timeout) << R"(
  -V, --validate-addr
              Perform address validation.
  --preferred-ipv4-addr=<ADDR>:<PORT>
              Specify preferred IPv4 address and port.
  --preferred-ipv6-addr=<ADDR>:<PORT>
              Specify preferred IPv6 address and port.  A numeric IPv6
              address  must   be  enclosed  by  '['   and  ']'  (e.g.,
              [::1]:8443)
  --mime-types-file=<PATH>
              Path  to file  that contains  MIME media  types and  the
              extensions.
              Default: )"
            << config.mime_types_file << R"(
  --early-response
              Start  sending response  when  it  receives HTTP  header
              fields  without  waiting  for  request  body.   If  HTTP
              response data is written  before receiving request body,
              STOP_SENDING is sent.
  --verify-client
              Request a  client certificate.   At the moment,  we just
              request a certificate and no verification is done.
  --qlog-dir=<PATH>
              Path to  the directory where  qlog file is  stored.  The
              file name  of each qlog  is the Source Connection  ID of
              server.
  --no-quic-dump
              Disables printing QUIC STREAM and CRYPTO frame data out.
  --no-http-dump
              Disables printing HTTP response body out.
  --max-data=<SIZE>
              The initial connection-level flow control window.
              Default: )"
            << util::format_uint_iec(config.max_data) << R"(
  --max-stream-data-bidi-local=<SIZE>
              The  initial  stream-level  flow control  window  for  a
              bidirectional stream that the local endpoint initiates.
              Default: )"
            << util::format_uint_iec(config.max_stream_data_bidi_local) << R"(
  --max-stream-data-bidi-remote=<SIZE>
              The  initial  stream-level  flow control  window  for  a
              bidirectional stream that the remote endpoint initiates.
              Default: )"
            << util::format_uint_iec(config.max_stream_data_bidi_remote) << R"(
  --max-stream-data-uni=<SIZE>
              The  initial  stream-level  flow control  window  for  a
              unidirectional stream.
              Default: )"
            << util::format_uint_iec(config.max_stream_data_uni) << R"(
  --max-streams-bidi=<N>
              The number of the concurrent bidirectional streams.
              Default: )"
            << config.max_streams_bidi << R"(
  --max-streams-uni=<N>
              The number of the concurrent unidirectional streams.
              Default: )"
            << config.max_streams_uni << R"(
  --max-dyn-length=<SIZE>
              The maximum length of a dynamically generated content.
              Default: )"
            << util::format_uint_iec(config.max_dyn_length) << R"(
  --cc=(<cubic>|<reno>)
              The name of congestion controller algorithm.
  --initial-rtt=<DURATION>
              Set an initial RTT.
              Default: )"
            << util::format_duration(config.initial_rtt) << R"(
  --max-udp-payload-size=<SIZE>
              Override maximum UDP payload size that server transmits.
              Default: )"
            << NGTCP2_MAX_PKTLEN_IPV4 << R"( for IPv4, )"
            << NGTCP2_MAX_PKTLEN_IPV6 << R"( for IPv6
  --send-trailers
              Send trailer fields.
  -h, --help  Display this help and exit.

---

  The <SIZE> argument is an integer and an optional unit (e.g., 10K is
  10 * 1024).  Units are K, M and G (powers of 1024).

  The <DURATION> argument is an integer and an optional unit (e.g., 1s
  is 1 second and 500ms is 500  milliseconds).  Units are h, m, s, ms,
  us, or ns (hours,  minutes, seconds, milliseconds, microseconds, and
  nanoseconds respectively).  If  a unit is omitted, a  second is used
  as unit.)" << std::endl;
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
        {"mime-types-file", required_argument, &flag, 6},
        {"early-response", no_argument, &flag, 7},
        {"verify-client", no_argument, &flag, 8},
        {"qlog-dir", required_argument, &flag, 9},
        {"no-quic-dump", no_argument, &flag, 10},
        {"no-http-dump", no_argument, &flag, 11},
        {"max-data", required_argument, &flag, 12},
        {"max-stream-data-bidi-local", required_argument, &flag, 13},
        {"max-stream-data-bidi-remote", required_argument, &flag, 14},
        {"max-stream-data-uni", required_argument, &flag, 15},
        {"max-streams-bidi", required_argument, &flag, 16},
        {"max-streams-uni", required_argument, &flag, 17},
        {"max-dyn-length", required_argument, &flag, 18},
        {"cc", required_argument, &flag, 19},
        {"initial-rtt", required_argument, &flag, 20},
        {"max-udp-payload-size", required_argument, &flag, 21},
        {"send-trailers", no_argument, &flag, 22},
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
      // --quiet
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
        if (auto [t, rv] = util::parse_duration(optarg); rv != 0) {
          std::cerr << "timeout: invalid argument" << std::endl;
          exit(EXIT_FAILURE);
        } else {
          config.timeout = t;
        }
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
      case 6:
        // --mime-types-file
        config.mime_types_file = optarg;
        break;
      case 7:
        // --early-response
        config.early_response = optarg;
        break;
      case 8:
        // --verify-client
        config.verify_client = true;
        break;
      case 9:
        // --qlog-dir
        config.qlog_dir = optarg;
        break;
      case 10:
        // --no-quic-dump
        config.no_quic_dump = true;
        break;
      case 11:
        // --no-http-dump
        config.no_http_dump = true;
        break;
      case 12:
        // --max-data
        if (auto [n, rv] = util::parse_uint_iec(optarg); rv != 0) {
          std::cerr << "max-data: invalid argument" << std::endl;
          exit(EXIT_FAILURE);
        } else {
          config.max_data = n;
        }
        break;
      case 13:
        // --max-stream-data-bidi-local
        if (auto [n, rv] = util::parse_uint_iec(optarg); rv != 0) {
          std::cerr << "max-stream-data-bidi-local: invalid argument"
                    << std::endl;
          exit(EXIT_FAILURE);
        } else {
          config.max_stream_data_bidi_local = n;
        }
        break;
      case 14:
        // --max-stream-data-bidi-remote
        if (auto [n, rv] = util::parse_uint_iec(optarg); rv != 0) {
          std::cerr << "max-stream-data-bidi-remote: invalid argument"
                    << std::endl;
          exit(EXIT_FAILURE);
        } else {
          config.max_stream_data_bidi_remote = n;
        }
        break;
      case 15:
        // --max-stream-data-uni
        if (auto [n, rv] = util::parse_uint_iec(optarg); rv != 0) {
          std::cerr << "max-stream-data-uni: invalid argument" << std::endl;
          exit(EXIT_FAILURE);
        } else {
          config.max_stream_data_uni = n;
        }
        break;
      case 16:
        // --max-streams-bidi
        config.max_streams_bidi = strtoull(optarg, nullptr, 10);
        break;
      case 17:
        // --max-streams-uni
        config.max_streams_uni = strtoull(optarg, nullptr, 10);
        break;
      case 18:
        // --max-dyn-length
        if (auto [n, rv] = util::parse_uint_iec(optarg); rv != 0) {
          std::cerr << "max-dyn-length: invalid argument" << std::endl;
          exit(EXIT_FAILURE);
        } else {
          config.max_dyn_length = n;
        }
        break;
      case 19:
        // --cc
        if (strcmp("cubic", optarg) == 0 || strcmp("reno", optarg) == 0) {
          config.cc = optarg;
          break;
        }
        std::cerr << "cc: specify cubic or reno" << std::endl;
        exit(EXIT_FAILURE);
      case 20:
        // --initial-rtt
        if (auto [t, rv] = util::parse_duration(optarg); rv != 0) {
          std::cerr << "initial-rtt: invalid argument" << std::endl;
          exit(EXIT_FAILURE);
        } else {
          config.initial_rtt = t;
        }
        break;
      case 21:
        // --max-udp-payload-size
        if (auto [n, rv] = util::parse_uint_iec(optarg); rv != 0) {
          std::cerr << "max-udp-payload-size: invalid argument" << std::endl;
          exit(EXIT_FAILURE);
        } else if (n > 64_k) {
          std::cerr << "max-udp-payload-size: must not exceed 65536"
                    << std::endl;
          exit(EXIT_FAILURE);
        } else {
          config.max_udp_payload_size = n;
        }
        break;
      case 22:
        // --send-trailers
        config.send_trailers = true;
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

  if (util::read_mime_types(config.mime_types, config.mime_types_file) != 0) {
    std::cerr << "mime-types-file: Could not read MIME media types file "
              << config.mime_types_file << std::endl;
  }

  auto ssl_ctx = create_ssl_ctx(private_key_file, cert_file);

  if (config.htdocs.back() != '/') {
    config.htdocs += '/';
  }

  std::cerr << "Using document root " << config.htdocs << std::endl;

  auto ssl_ctx_d = defer(SSL_CTX_free, ssl_ctx);

  auto ev_loop_d = defer(ev_loop_destroy, EV_DEFAULT);

  auto keylog_filename = getenv("SSLKEYLOGFILE");
  if (keylog_filename) {
    keylog_file.open(keylog_filename, std::ios_base::app);
    if (keylog_file) {
      SSL_CTX_set_keylog_callback(ssl_ctx, keylog_callback);
    }
  }

  if (util::generate_secret(config.static_secret.data(),
                            config.static_secret.size()) != 0) {
    std::cerr << "Unable to generate static secret" << std::endl;
    exit(EXIT_FAILURE);
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
