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
#include "baton_wt_app.h"

#include <urlparse.h>

#include "util.h"
#include "debug.h"

namespace ngtcp2 {
namespace webtransport {
namespace baton {

Config config;

namespace {
auto randgen = util::make_mt19937();
} // namespace

App::App(ngtcp2_conn *conn, nghttp3_conn *httpconn, int64_t session_id,
         Side side)
  : conn_{conn}, httpconn_{httpconn}, session_id_{session_id}, side_{side} {}

std::expected<void, Error>
App::submit_session_request(std::string_view scheme, std::string_view authority,
                            std::string_view path) {
  assert(side_ == Side::CLIENT);

  std::string content_length_str;

  urlparse_url u;

  if (auto rv = urlparse_parse_url(path.data(), path.size(),
                                   /* is_connect = */ 0, &u);
      rv != 0) {
    return std::unexpected{Error::INVALID_ARGUMENT};
  }

  if (u.field_set & (1 << URLPARSE_QUERY)) {
    auto maybe_baton =
      parse_baton_parameters(util::get_string(path, u, URLPARSE_QUERY));
    if (!maybe_baton) {
      return std::unexpected{maybe_baton.error()};
    }

    auto &baton = *maybe_baton;
    count_ = baton.count;
  } else {
    count_ = 1;
  }

  auto nva = std::to_array<nghttp3_nv>({
    util::make_nv_nn(":method", "CONNECT"),
    util::make_nv_nn(":scheme", scheme),
    util::make_nv_nn(":authority", authority),
    util::make_nv_nn(":path", path),
    util::make_nv_nn(":protocol", "webtransport-h3"),
    util::make_nv_nn("user-agent", "nghttp3/ngtcp2 baton client"),
  });

  if (!config.quiet) {
    debug::print_http_request_headers(session_id_, nva.data(), nva.size());
  }

  if (auto rv = nghttp3_conn_submit_wt_request(httpconn_, session_id_,
                                               nva.data(), nva.size(), nullptr);
      rv != 0) {
    std::println(stderr, "nghttp3_conn_submit_wt_request: {}",
                 nghttp3_strerror(rv));
    return std::unexpected{Error::HTTP3};
  }

  return {};
}

struct Request {
  std::string path;
  BatonParams baton;
  struct {
    int32_t urgency;
    int inc;
  } pri{};
};

namespace {
std::expected<Request, Error> request_path(const std::string_view &uri) {
  urlparse_url u;
  Request req{
    .pri{
      .urgency = -1,
      .inc = -1,
    },
  };

  if (auto rv =
        urlparse_parse_url(uri.data(), uri.size(), /* is_connect = */ 0, &u);
      rv != 0) {
    return std::unexpected{Error::INVALID_ARGUMENT};
  }

  if (u.field_set & (1 << URLPARSE_PATH)) {
    req.path = util::get_string(uri, u, URLPARSE_PATH);
    if (req.path.find('%') != std::string::npos) {
      req.path = util::percent_decode(req.path);
    }

    assert(!req.path.empty());

    if (req.path[0] != '/') {
      return std::unexpected{Error::INVALID_ARGUMENT};
    }

    if (req.path.back() == '/') {
      req.path += "index.html";
    }

    auto maybe_norm_path = util::normalize_path(req.path);
    if (!maybe_norm_path) {
      return std::unexpected{maybe_norm_path.error()};
    }

    req.path = std::move(*maybe_norm_path);
  } else {
    req.path = "/index.html";
  }

  if (u.field_set & (1 << URLPARSE_QUERY)) {
    auto maybe_baton =
      parse_baton_parameters(util::get_string(uri, u, URLPARSE_QUERY));
    if (!maybe_baton) {
      return {};
    }

    req.baton = *maybe_baton;
  } else {
    req.baton = {
      .count = 1,
      .baton = 1,
    };
  }

  return req;
}
} // namespace

std::expected<void, Error>
App::accept_session_request(std::string_view path,
                            std::span<const std::string> avail_protos) {
  if (path != "/webtransport/devious-baton"sv &&
      !util::istarts_with(path, "/webtransport/devious-baton?"sv)) {
    return std::unexpected{Error::INVALID_ARGUMENT};
  }

  auto maybe_req = request_path(path);
  if (!maybe_req) {
    return std::unexpected{Error::INVALID_ARGUMENT};
  }

  const auto &req = *maybe_req;

  count_ = req.baton.count;

  auto nva = std::to_array<nghttp3_nv>({
    util::make_nv_nn(":status"sv, "200"sv),
    util::make_nv_nn("server"sv, "ngtcp2/nghttp3 baton server"sv),
  });

  if (!config.quiet) {
    debug::print_http_response_headers(session_id_, nva.data(), nva.size());
  }

  if (auto rv = nghttp3_conn_submit_wt_response(httpconn_, session_id_,
                                                nva.data(), nva.size());
      rv != 0) {
    std::println(stderr, "nghttp3_conn_submit_wt_response: {}",
                 nghttp3_strerror(rv));
    return std::unexpected{Error::HTTP3};
  }

  return start_baton_session(req.baton.baton);
}

namespace {
std::array<uint8_t, 4096> null_data;
} // namespace

namespace {
uint32_t rand_padlen() {
  return std::uniform_int_distribution<uint32_t>(0, null_data.size())(randgen);
}
} // namespace

namespace {
nghttp3_ssize baton_read_data(nghttp3_conn *conn, int64_t stream_id,
                              nghttp3_vec *vec, size_t veccnt, uint32_t *pflags,
                              void *user_data, void *stream_user_data) {
  auto stream = static_cast<Stream *>(stream_user_data);
  auto &baton = stream->baton;

  assert(veccnt > 2);

  int64_t padlen;

  nghttp3_get_varint(&padlen,
                     reinterpret_cast<uint8_t *>(&baton.tx.padding_be));

  auto varintlen =
    nghttp3_get_varintlen(reinterpret_cast<uint8_t *>(&baton.tx.padding_be));

  vec[0] = (nghttp3_vec){
    .base = reinterpret_cast<uint8_t *>(&baton.tx.padding_be),
    .len = varintlen,
  };
  vec[1] = (nghttp3_vec){
    .base = null_data.data(),
    .len = static_cast<size_t>(padlen),
  };
  vec[2] = (nghttp3_vec){
    .base = &baton.tx.value,
    .len = sizeof(baton.tx.value),
  };

  *pflags |= NGHTTP3_DATA_FLAG_EOF;

  return 3;
}
} // namespace

std::expected<void, Error> App::start_baton_session(uint8_t baton) {
  for (size_t i = 0; i < count_; ++i) {
    int64_t stream_id;

    auto rv = ngtcp2_conn_open_uni_stream(conn_, &stream_id, nullptr);
    if (rv != 0) {
      std::println(stderr, "ngtcp2_conn_open_uni_stream: {}",
                   ngtcp2_strerror(rv));
      return std::unexpected{Error::QUIC};
    }

    auto stream = std::make_unique<Stream>(stream_id);

    stream->baton.set_baton_msg(rand_padlen(), baton);

    auto dr = nghttp3_data_reader{
      .read_data = baton_read_data,
    };

    rv = nghttp3_conn_open_wt_data_stream(httpconn_, session_id_, stream_id,
                                          &dr, stream.get());
    if (rv != 0) {
      std::println(stderr, "nghttp3_conn_open_wt_data_stream: {}",
                   nghttp3_strerror(rv));
      return std::unexpected{Error::HTTP3};
    }

    if (auto [_, rv] = streams_.try_emplace(stream_id, std::move(stream));
        !rv) {
      assert(0);
    }
  }

  return {};
}

namespace {
Datagram make_baton_datagram(int64_t session_id, size_t padlen, uint8_t baton) {
  // TODO padlen = 0 for now
  return Datagram{
    .session_id = session_id,
    .data = {static_cast<uint8_t>(padlen), baton},
  };
}
} // namespace

std::expected<void, Error> App::on_data(int64_t stream_id,
                                        std::span<const uint8_t> data) {
  Stream *stream;

  auto it = streams_.find(stream_id);
  if (it == std::ranges::end(streams_)) {
    auto s = std::make_unique<Stream>(stream_id);

    stream = s.get();
    if (auto [_, rv] = streams_.try_emplace(stream_id, std::move(s)); !rv) {
      assert(rv);
    }
  } else {
    stream = (*it).second.get();
  }

  auto [baton, rest] = stream->baton.recv_data(data);
  if (baton == -1) {
    return {};
  }

  if (!rest.empty()) {
    return std::unexpected{Error::INTERNAL};
  }

  if (baton % 7 == (side_ == Side::SERVER ? 0 : 1)) {
    if (max_baton_count <= batons_.size()) {
      batons_.pop_front();
    }

    batons_.emplace_back(make_baton_datagram(
      session_id_, static_cast<size_t>(stream->baton.rx.padlen),
      static_cast<uint8_t>(baton)));
  }

  if (baton == 0) {
    if (count_ == 0) {
      return {};
    }

    if (--count_ == 0) {
      static constexpr uint8_t error_msg[] = "bye";

      if (auto rv = nghttp3_conn_close_wt_session(
            httpconn_, session_id_, 0, error_msg, sizeof(error_msg) - 1);
          rv != 0) {
        std::println(stderr, "nghttp3_conn_close_wt_session: {}",
                     nghttp3_strerror(rv));

        return std::unexpected{Error::HTTP3};
      }
    }

    return {};
  }

  baton = (baton + 1) & 0xFF;

  if (stream_id & 0x2) {
    return open_baton_bidi(static_cast<uint8_t>(baton));
  }

  if (side_ == Side::CLIENT) {
    if (stream_id & 0x1) {
      return send_baton(stream, static_cast<uint8_t>(baton));
    }

    return open_baton_uni(static_cast<uint8_t>(baton));
  }

  if (stream_id & 0x1) {
    return open_baton_uni(static_cast<uint8_t>(baton));
  }

  return send_baton(stream, static_cast<uint8_t>(baton));
}

std::vector<Datagram> App::pull_datagram() {
  auto q = std::vector<Datagram>{};
  std::ranges::move(batons_, std::back_inserter(q));
  batons_.clear();

  return q;
}

std::expected<void, Error> App::open_baton_bidi(uint8_t baton) {
  int64_t stream_id;

  if (auto rv = ngtcp2_conn_open_bidi_stream(conn_, &stream_id, nullptr);
      rv != 0) {
    std::println(stderr, "ngtcp2_conn_open_bidi_stream: {}",
                 ngtcp2_strerror(rv));

    return std::unexpected{Error::QUIC};
  }

  auto s = std::make_unique<Stream>(stream_id);
  auto stream = s.get();
  if (auto [_, rv] = streams_.try_emplace(stream_id, std::move(s)); !rv) {
    assert(0);
  }

  return send_baton(stream, baton);
}

std::expected<void, Error> App::open_baton_uni(uint8_t baton) {
  int64_t stream_id;

  if (auto rv = ngtcp2_conn_open_uni_stream(conn_, &stream_id, nullptr);
      rv != 0) {
    std::println(stderr, "ngtcp2_conn_open_uni_stream: {}",
                 ngtcp2_strerror(rv));

    return std::unexpected{Error::QUIC};
  }

  auto s = std::make_unique<Stream>(stream_id);
  auto stream = s.get();
  if (auto [_, rv] = streams_.try_emplace(stream_id, std::move(s)); !rv) {
    assert(0);
  }

  return send_baton(stream, baton);
}

std::expected<void, Error> App::send_baton(Stream *stream, uint8_t baton) {
  stream->baton.set_baton_msg(rand_padlen(), baton);

  auto dr = nghttp3_data_reader{
    .read_data = baton_read_data,
  };

  if (auto rv = nghttp3_conn_open_wt_data_stream(
        httpconn_, session_id_, stream->stream_id, &dr, stream);
      rv != 0) {
    std::println(stderr, "nghttp3_conn_open_wt_data_stream: {}",
                 nghttp3_strerror(rv));

    return std::unexpected{Error::HTTP3};
  }

  return {};
}

void App::on_stream_close(int64_t stream_id, uint64_t app_error_code) {
  if (streams_.erase(stream_id) && !config.quiet) {
    std::println(stderr,
                 "WebTransport stream {:#x} closed with error code {:#x}",
                 stream_id, app_error_code);
  }
}

} // namespace baton
} // namespace webtransport
} // namespace ngtcp2
