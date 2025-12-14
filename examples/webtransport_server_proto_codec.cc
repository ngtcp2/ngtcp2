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
#include "webtransport_server_proto_codec.h"

#include <sfparse.h>

#include "server.h"
#include "debug.h"
#include "baton_wt_app.h"
#include "interop_wt_app.h"

extern Config config;

namespace ngtcp2 {

ProtoCodec::ProtoCodec(Handler *h, ngtcp2_ccerr &last_error)
  : handler_{h}, conn_{handler_->conn()}, last_error_{last_error} {}

ProtoCodec::~ProtoCodec() {
  if (httpconn_) {
    nghttp3_conn_del(httpconn_);
  }
}

std::expected<void, Error>
ProtoCodec::acked_stream_data_offset(int64_t stream_id, uint64_t datalen) {
  if (!httpconn_) {
    return {};
  }

  if (auto rv = nghttp3_conn_add_ack_offset(httpconn_, stream_id, datalen);
      rv != 0) {
    std::println(stderr, "nghttp3_conn_add_ack_offset: {}",
                 nghttp3_strerror(rv));
    return std::unexpected{Error::HTTP3};
  }

  return {};
}

std::expected<void, Error> ProtoCodec::on_stream_reset(int64_t stream_id) {
  if (!httpconn_) {
    return {};
  }

  if (auto rv = nghttp3_conn_shutdown_stream_read(httpconn_, stream_id);
      rv != 0) {
    std::println(stderr, "nghttp3_conn_shutdown_stream_read: {}",
                 nghttp3_strerror(rv));
    return std::unexpected{Error::HTTP3};
  }

  return {};
}

std::expected<void, Error>
ProtoCodec::on_stream_stop_sending(int64_t stream_id) {
  if (!httpconn_) {
    return {};
  }

  if (auto rv = nghttp3_conn_shutdown_stream_read(httpconn_, stream_id);
      rv != 0) {
    std::println(stderr, "nghttp3_conn_shutdown_stream_read: {}",
                 nghttp3_strerror(rv));
    return std::unexpected{Error::HTTP3};
  }

  return {};
}

void ProtoCodec::extend_max_remote_streams_bidi(uint64_t max_streams) {
  if (!httpconn_) {
    return;
  }

  nghttp3_conn_set_max_client_streams_bidi(httpconn_, max_streams);
}

std::expected<void, Error>
ProtoCodec::extend_max_stream_data(int64_t stream_id, uint64_t max_data) {
  if (auto rv = nghttp3_conn_unblock_stream(httpconn_, stream_id); rv != 0) {
    std::println(stderr, "nghttp3_conn_unblock_stream: {}",
                 nghttp3_strerror(rv));
    return std::unexpected{Error::HTTP3};
  }
  return {};
}

std::expected<void, Error> ProtoCodec::on_app_tx_ready() {
  return setup_httpconn();
}

ngtcp2_ssize ProtoCodec::write_pkt(ngtcp2_path *path, ngtcp2_pkt_info *pi,
                                   uint8_t *dest, size_t destlen,
                                   ngtcp2_tstamp ts) {
  std::array<nghttp3_vec, 16> vec;

  for (;;) {
    int64_t stream_id = -1;
    int fin = 0;
    nghttp3_ssize sveccnt = 0;

    if (httpconn_ && ngtcp2_conn_get_max_data_left2(conn_)) {
      sveccnt = nghttp3_conn_writev_stream(httpconn_, &stream_id, &fin,
                                           vec.data(), vec.size());
      if (sveccnt < 0) {
        std::println(stderr, "nghttp3_conn_writev_stream: {}",
                     nghttp3_strerror(static_cast<int>(sveccnt)));
        ngtcp2_ccerr_set_application_error(
          &last_error_,
          nghttp3_err_infer_quic_app_error_code(static_cast<int>(sveccnt)),
          nullptr, 0);
        return NGTCP2_ERR_CALLBACK_FAILURE;
      }
    }

    if (sveccnt || datagrams_.empty()) {
      ngtcp2_ssize ndatalen;
      auto v = vec.data();
      auto vcnt = static_cast<size_t>(sveccnt);

      uint32_t flags =
        NGTCP2_WRITE_STREAM_FLAG_MORE | NGTCP2_WRITE_STREAM_FLAG_PADDING;
      if (fin) {
        flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
      }

      auto nwrite = ngtcp2_conn_writev_stream(
        conn_, path, pi, dest, destlen, &ndatalen, flags, stream_id,
        reinterpret_cast<const ngtcp2_vec *>(v), vcnt, ts);
      if (nwrite < 0) {
        switch (nwrite) {
        case NGTCP2_ERR_STREAM_DATA_BLOCKED:
          assert(ndatalen == -1);
          nghttp3_conn_block_stream(httpconn_, stream_id);
          continue;
        case NGTCP2_ERR_STREAM_SHUT_WR:
          assert(ndatalen == -1);
          nghttp3_conn_shutdown_stream_write(httpconn_, stream_id);
          continue;
        case NGTCP2_ERR_WRITE_MORE:
          assert(ndatalen >= 0);
          if (auto rv = nghttp3_conn_add_write_offset(httpconn_, stream_id,
                                                      as_unsigned(ndatalen));
              rv != 0) {
            std::println(stderr, "nghttp3_conn_add_write_offset: {}",
                         nghttp3_strerror(rv));
            ngtcp2_ccerr_set_application_error(
              &last_error_, nghttp3_err_infer_quic_app_error_code(rv), nullptr,
              0);
            return NGTCP2_ERR_CALLBACK_FAILURE;
          }
          continue;
        }

        assert(ndatalen == -1);

        std::println(stderr, "ngtcp2_conn_writev_stream: {}",
                     ngtcp2_strerror(static_cast<int>(nwrite)));
        ngtcp2_ccerr_set_liberr(&last_error_, static_cast<int>(nwrite), nullptr,
                                0);
        return NGTCP2_ERR_CALLBACK_FAILURE;
      }

      if (ndatalen >= 0) {
        if (auto rv = nghttp3_conn_add_write_offset(httpconn_, stream_id,
                                                    as_unsigned(ndatalen));
            rv != 0) {
          std::println(stderr, "nghttp3_conn_add_write_offset: {}",
                       nghttp3_strerror(rv));
          ngtcp2_ccerr_set_application_error(
            &last_error_, nghttp3_err_infer_quic_app_error_code(rv), nullptr,
            0);
          return NGTCP2_ERR_CALLBACK_FAILURE;
        }
      }

      return nwrite;
    } else {
      uint32_t flags =
        NGTCP2_WRITE_DATAGRAM_FLAG_MORE | NGTCP2_WRITE_DATAGRAM_FLAG_PADDING;

      const auto &dgram = datagrams_.front();

      int64_t qstream_id;
      nghttp3_put_varint(reinterpret_cast<uint8_t *>(&qstream_id),
                         dgram.session_id / 4);

      auto v = std::span{vec}.first(2);

      v[0] = {
        .base = reinterpret_cast<uint8_t *>(&qstream_id),
        .len = nghttp3_put_varintlen(dgram.session_id / 4),
      };
      v[1] = {
        .base = const_cast<uint8_t *>(dgram.data.data()),
        .len = dgram.data.size(),
      };

      int accepted;

      auto nwrite = ngtcp2_conn_writev_datagram(
        conn_, path, pi, dest, destlen, &accepted, flags, 0,
        reinterpret_cast<const ngtcp2_vec *>(v.data()), v.size(), ts);

      if (nwrite < 0) {
        switch (nwrite) {
        case NGTCP2_ERR_WRITE_MORE:
          assert(accepted);

          datagrams_.pop_front();

          continue;
        case NGTCP2_ERR_INVALID_ARGUMENT:
          // DATAGRAM is too large
          datagrams_.pop_front();

          continue;
        }

        assert(!accepted);

        std::println(stderr, "ngtcp2_conn_writev_datagram: {}",
                     ngtcp2_strerror(static_cast<int>(nwrite)));
        ngtcp2_ccerr_set_liberr(&last_error_, static_cast<int>(nwrite), nullptr,
                                0);
        return NGTCP2_ERR_CALLBACK_FAILURE;
      }

      if (accepted) {
        datagrams_.pop_front();
      }

      return nwrite;
    }
  }
}

std::expected<void, Error>
ProtoCodec::recv_stream_data(uint32_t flags, int64_t stream_id,
                             std::span<const uint8_t> data) {
  if (!config.quiet && !config.no_quic_dump) {
    debug::print_stream_data(stream_id, data);
  }

  if (!httpconn_) {
    return {};
  }

  auto nconsumed = nghttp3_conn_read_stream2(
    httpconn_, stream_id, data.data(), data.size(),
    flags & NGTCP2_STREAM_DATA_FLAG_FIN, ngtcp2_conn_get_timestamp(conn_));
  if (nconsumed < 0) {
    std::println(stderr, "nghttp3_conn_read_stream2: {}",
                 nghttp3_strerror(static_cast<int>(nconsumed)));
    ngtcp2_ccerr_set_application_error(
      &last_error_,
      nghttp3_err_infer_quic_app_error_code(static_cast<int>(nconsumed)),
      nullptr, 0);
    return std::unexpected{Error::HTTP3};
  }

  ngtcp2_conn_extend_max_stream_offset(conn_, stream_id,
                                       static_cast<uint64_t>(nconsumed));
  ngtcp2_conn_extend_max_offset(conn_, static_cast<uint64_t>(nconsumed));

  return {};
}

std::expected<void, Error>
ProtoCodec::recv_datagram(std::span<const uint8_t> data) {
  if (data.empty()) {
    return {};
  }

  auto qidlen = nghttp3_get_varintlen(data.data());
  if (qidlen > data.size()) {
    return {};
  }

  int64_t session_id;
  nghttp3_get_varint(&session_id, data.data());

  data = data.subspan(qidlen);

  session_id <<= 2;

  auto wt_session_stream = handler_->find_stream(session_id);
  if (!wt_session_stream) {
    return {};
  }

  auto &wt_app = wt_session_stream->wt_app;

  auto rv = wt_app->on_datagram(data);
  if (!rv) {
    return rv;
  }

  handle_pending_transmission(wt_session_stream, *wt_app);

  if (wt_app->finished()) {
    handler_->break_loop();
  }

  return {};
}

std::expected<void, Error>
ProtoCodec::on_stream_close(int64_t stream_id, uint64_t app_error_code) {
  if (!httpconn_) {
    return {};
  }

  if (app_error_code == 0) {
    app_error_code = NGHTTP3_H3_NO_ERROR;
  }

  if (auto rv = nghttp3_conn_close_stream(httpconn_, stream_id, app_error_code);
      rv != 0) {
    if (rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
      std::println(stderr, "nghttp3_conn_close_stream: {}",
                   nghttp3_strerror(rv));
      ngtcp2_ccerr_set_application_error(
        &last_error_, nghttp3_err_infer_quic_app_error_code(rv), nullptr, 0);
      return std::unexpected{Error::HTTP3};
    }

    return {};
  }

  return {};
}

std::expected<void, Error> ProtoCodec::extend_max_local_streams_bidi() {
  for (; !bidi_streams_.empty();) {
    auto session_id = *std::ranges::begin(bidi_streams_);

    auto wt_session_stream = handler_->find_stream(session_id);
    if (!wt_session_stream) {
      bidi_streams_.erase(session_id);

      continue;
    }

    const auto &wt_app = wt_session_stream->wt_app;

    if (auto rv = wt_app->handle_pending_bidi_stream(); !rv) {
      return rv;
    }

    if (wt_app->has_pending_bidi_stream()) {
      break;
    }

    bidi_streams_.erase(session_id);
  }

  return {};
}

std::expected<void, Error> ProtoCodec::extend_max_local_streams_uni() {
  for (; !uni_streams_.empty();) {
    auto session_id = *std::ranges::begin(uni_streams_);

    auto wt_session_stream = handler_->find_stream(session_id);
    if (!wt_session_stream) {
      uni_streams_.erase(session_id);

      continue;
    }

    const auto &wt_app = wt_session_stream->wt_app;

    if (auto rv = wt_app->handle_pending_uni_stream(); !rv) {
      return rv;
    }

    if (wt_app->has_pending_uni_stream()) {
      break;
    }

    uni_streams_.erase(session_id);
  }

  return {};
}

namespace {
int http_recv_data(nghttp3_conn *conn, int64_t stream_id, const uint8_t *data,
                   size_t datalen, void *user_data, void *stream_user_data) {
  if (!config.quiet && !config.no_http_dump) {
    debug::print_http_data(stream_id, {data, datalen});
  }
  auto pc = static_cast<ProtoCodec *>(user_data);
  pc->http_consume(stream_id, datalen);
  return 0;
}
} // namespace

namespace {
int http_deferred_consume(nghttp3_conn *conn, int64_t stream_id,
                          size_t nconsumed, void *user_data,
                          void *stream_user_data) {
  auto pc = static_cast<ProtoCodec *>(user_data);
  pc->http_consume(stream_id, nconsumed);
  return 0;
}
} // namespace

void ProtoCodec::http_consume(int64_t stream_id, size_t nconsumed) {
  ngtcp2_conn_extend_max_stream_offset(conn_, stream_id, nconsumed);
  ngtcp2_conn_extend_max_offset(conn_, nconsumed);
}

namespace {
int http_begin_request_headers(nghttp3_conn *conn, int64_t stream_id,
                               void *user_data, void *stream_user_data) {
  if (!config.quiet) {
    debug::print_http_begin_request_headers(stream_id);
  }

  auto pc = static_cast<ProtoCodec *>(user_data);
  pc->http_begin_request_headers(stream_id);

  return 0;
}
} // namespace

void ProtoCodec::http_begin_request_headers(int64_t stream_id) {
  auto stream = handler_->find_stream(stream_id);

  assert(stream);

  nghttp3_conn_set_stream_user_data(httpconn_, stream_id, stream);
}

namespace {
int http_recv_request_header(nghttp3_conn *conn, int64_t stream_id,
                             int32_t token, nghttp3_rcbuf *name,
                             nghttp3_rcbuf *value, uint8_t flags,
                             void *user_data, void *stream_user_data) {
  if (!config.quiet) {
    debug::print_http_header(stream_id, name, value, flags);
  }

  auto pc = static_cast<ProtoCodec *>(user_data);
  auto stream = static_cast<Stream *>(stream_user_data);
  pc->http_recv_request_header(stream, token, name, value);

  return 0;
}
} // namespace

void ProtoCodec::http_recv_request_header(Stream *stream, int32_t token,
                                          nghttp3_rcbuf *name,
                                          nghttp3_rcbuf *value) {
  auto v = nghttp3_rcbuf_get_buf(value);
  static constexpr auto proto_wt = "webtransport-h3"sv;
  static constexpr auto proto_wt_pre15 = "webtransport"sv;

  switch (token) {
  case NGHTTP3_QPACK_TOKEN__PATH:
    stream->uri = {v.base, v.base + v.len};
    break;
  case NGHTTP3_QPACK_TOKEN__METHOD:
    stream->method = {v.base, v.base + v.len};
    break;
  case NGHTTP3_QPACK_TOKEN__AUTHORITY:
    stream->authority = {v.base, v.base + v.len};
    break;
  case NGHTTP3_QPACK_TOKEN__PROTOCOL:
    stream->webtransport =
      std::ranges::equal(proto_wt, std::span{v.base, v.len}) ||
      std::ranges::equal(proto_wt_pre15, std::span{v.base, v.len});

    break;
  case -1: {
    auto k = nghttp3_rcbuf_get_buf(name);

    if (std::ranges::equal("wt-available-protocols"sv,
                           std::span{k.base, k.len})) {
      if (!stream->wt_available_protos.empty()) {
        stream->wt_available_protos += ", ";
      }

      stream->wt_available_protos +=
        as_string_view(std::span{v.base, v.base + v.len});
    }

    break;
  }
  }
}

namespace {
int http_end_request_headers(nghttp3_conn *conn, int64_t stream_id, int fin,
                             void *user_data, void *stream_user_data) {
  if (!config.quiet) {
    debug::print_http_end_headers(stream_id);
  }

  auto pc = static_cast<ProtoCodec *>(user_data);
  auto stream = static_cast<Stream *>(stream_user_data);
  if (!pc->http_end_request_headers(stream)) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
} // namespace

std::expected<void, Error>
ProtoCodec::http_end_request_headers(Stream *stream) {
  return start_response(stream);
}

namespace {
int http_stop_sending(nghttp3_conn *conn, int64_t stream_id,
                      uint64_t app_error_code, void *user_data,
                      void *stream_user_data) {
  auto pc = static_cast<ProtoCodec *>(user_data);
  if (!pc->http_stop_sending(stream_id, app_error_code)) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
} // namespace

std::expected<void, Error>
ProtoCodec::http_stop_sending(int64_t stream_id, uint64_t app_error_code) {
  if (auto rv =
        ngtcp2_conn_shutdown_stream_read(conn_, 0, stream_id, app_error_code);
      rv != 0) {
    std::println(stderr, "ngtcp2_conn_shutdown_stream_read: {}",
                 ngtcp2_strerror(rv));
    return std::unexpected{Error::QUIC};
  }
  return {};
}

namespace {
int http_end_stream(nghttp3_conn *conn, int64_t stream_id, void *user_data,
                    void *stream_user_data) {
  auto pc = static_cast<ProtoCodec *>(user_data);
  if (!pc->http_end_stream(stream_id)) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
} // namespace

std::expected<void, Error> ProtoCodec::http_end_stream(int64_t stream_id) {
  auto session_id = nghttp3_conn_get_stream_wt_session_id(httpconn_, stream_id);
  if (session_id == -1) {
    return {};
  }

  auto wt_session_stream = handler_->find_stream(session_id);
  if (!wt_session_stream) {
    return {};
  }

  return wt_session_stream->wt_app->on_end_stream(stream_id);
}

namespace {
int http_reset_stream(nghttp3_conn *conn, int64_t stream_id,
                      uint64_t app_error_code, void *user_data,
                      void *stream_user_data) {
  auto pc = static_cast<ProtoCodec *>(user_data);
  if (!pc->http_reset_stream(stream_id, app_error_code)) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
} // namespace

std::expected<void, Error>
ProtoCodec::http_reset_stream(int64_t stream_id, uint64_t app_error_code) {
  // Use NGTCP2_SHUT_STREAM_FLAG_FLUSH to use RESET_STREAM_AT frame.
  if (auto rv = ngtcp2_conn_shutdown_stream_write(
        conn_, NGTCP2_SHUT_STREAM_FLAG_FLUSH, stream_id, app_error_code);
      rv != 0) {
    std::println(stderr, "ngtcp2_conn_shutdown_stream_write: {}",
                 ngtcp2_strerror(rv));
    return std::unexpected{Error::QUIC};
  }
  return {};
}

namespace {
void rand_bytes(uint8_t *dest, size_t destlen) {
  if (!util::generate_secure_random({dest, destlen})) {
    assert(0);
    abort();
  }
}
} // namespace

namespace {
int http_recv_settings(nghttp3_conn *conn,
                       const nghttp3_proto_settings *settings,
                       void *user_data) {
  if (!config.quiet) {
    debug::print_http_settings(settings);
  }

  auto pc = static_cast<ProtoCodec *>(user_data);
  pc->http_recv_settings(settings);

  return 0;
}
} // namespace

void ProtoCodec::http_recv_settings(const nghttp3_proto_settings *settings) {
  // TODO Only draft version client sends SETTINGS_WT_ENABLED.
  wt_settings_enabled_ = settings->wt_enabled && settings->h3_datagram;
}

namespace {
int http_recv_wt_data(nghttp3_conn *conn, int64_t session_id, int64_t stream_id,
                      const uint8_t *data, size_t datalen, void *user_data,
                      void *stream_user_data) {
  auto pc = static_cast<ProtoCodec *>(user_data);

  if (!pc->http_recv_wt_data(session_id, stream_id, {data, datalen})) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

std::expected<void, Error>
ProtoCodec::http_recv_wt_data(int64_t session_id, int64_t stream_id,
                              std::span<const uint8_t> data) {
  auto wt_session_stream = handler_->find_stream(session_id);
  if (!wt_session_stream) {
    return std::unexpected{Error::INTERNAL};
  }

  const auto &wt_app = wt_session_stream->wt_app;

  if (auto rv = wt_app->on_data(stream_id, data); !rv) {
    return rv;
  }

  http_consume(stream_id, data.size());

  handle_pending_transmission(wt_session_stream, *wt_app);

  return {};
}

namespace {
int http_stream_close(nghttp3_conn *conn, int64_t stream_id,
                      uint64_t app_error_code, void *conn_user_data,
                      void *stream_user_data) {
  auto pc = static_cast<ProtoCodec *>(conn_user_data);

  pc->http_stream_close(stream_id, app_error_code);

  return 0;
}
} // namespace

void ProtoCodec::http_stream_close(int64_t stream_id, uint64_t app_error_code) {
  if (!config.quiet) {
    std::println(stderr, "HTTP stream {:#x} closed with error code {:#x}",
                 stream_id, app_error_code);
  }

  auto session_id = nghttp3_conn_get_stream_wt_session_id(httpconn_, stream_id);
  if (session_id == -1) {
    return;
  }

  auto wt_session_stream = handler_->find_stream(session_id);
  if (wt_session_stream && wt_session_stream->wt_app) {
    wt_session_stream->wt_app->on_stream_close(stream_id, app_error_code);

    if (wt_session_stream->wt_app->finished()) {
      handler_->break_loop();
    }
  }
}

void ProtoCodec::handle_pending_transmission(Stream *stream,
                                             webtransport::AppBase &wt_app) {
  auto q = wt_app.pull_datagram();
  std::ranges::move(q, std::back_inserter(datagrams_));

  if (wt_app.has_pending_bidi_stream()) {
    bidi_streams_.emplace(stream->stream_id);
  }

  if (wt_app.has_pending_uni_stream()) {
    uni_streams_.emplace(stream->stream_id);
  }
}

namespace {
std::expected<std::vector<std::string>, Error>
parse_wt_avail_protos(std::string_view avail_protos) {
  sfparse_parser sfp;

  sfparse_parser_init(&sfp,
                      reinterpret_cast<const uint8_t *>(avail_protos.data()),
                      avail_protos.size());

  std::vector<std::string> protos;

  sfparse_value item;

  for (;;) {
    auto rv = sfparse_parser_list(&sfp, &item);
    if (rv != 0) {
      switch (rv) {
      case SFPARSE_ERR_EOF:
        return protos;
      case SFPARSE_ERR_PARSE:
        return std::unexpected{Error::INVALID_ARGUMENT};
      default:
        std::unreachable();
      }
    }

    if (item.type != SFPARSE_TYPE_STRING) {
      return std::unexpected{Error::INVALID_ARGUMENT};
    }

    if (item.flags & SFPARSE_VALUE_FLAG_ESCAPED_STRING) {
      std::string s;
      s.resize_and_overwrite(item.vec.len, [&vec = item.vec](auto p, auto len) {
        sfparse_vec dest{
          .base = reinterpret_cast<uint8_t *>(p),
        };

        sfparse_unescape(&dest, &vec);

        return dest.len;
      });

      protos.emplace_back(s);
    } else {
      protos.emplace_back(item.vec.base, item.vec.base + item.vec.len);
    }
  }
}
} // namespace

bool ProtoCodec::wt_capable(Stream *stream) const {
  if (!stream->webtransport) {
    return false;
  }

  auto remote_params = ngtcp2_conn_get_remote_transport_params2(conn_);

  // TODO Exclude reset_stream_at requirement to allow chrome to
  // connect.
  return remote_params->max_datagram_frame_size;
}

std::expected<void, Error> ProtoCodec::start_response(Stream *stream) {
  if (!wt_capable(stream)) {
    return send_status_response(stream, 404);
  }

  auto maybe_avail_protos = parse_wt_avail_protos(stream->wt_available_protos);
  if (!maybe_avail_protos) {
    return send_status_response(stream, 400);
  }

  if (config.webtransport_interop) {
    stream->wt_app = std::make_unique<webtransport::interop::App>(
      conn_, httpconn_, stream->stream_id, webtransport::Side::SERVER,
      webtransport::interop::config.protos);
  } else {
    stream->wt_app = std::make_unique<webtransport::baton::App>(
      conn_, httpconn_, stream->stream_id, webtransport::Side::SERVER);
  }

  if (auto rv = stream->wt_app->accept_session_request(stream->uri,
                                                       *maybe_avail_protos);
      !rv) {
    return send_status_response(stream, 400);
  }

  handle_pending_transmission(stream, *stream->wt_app);

  return {};
}

namespace {
nghttp3_ssize read_data(nghttp3_conn *conn, int64_t stream_id, nghttp3_vec *vec,
                        size_t veccnt, uint32_t *pflags, void *user_data,
                        void *stream_user_data) {
  auto stream = static_cast<Stream *>(stream_user_data);

  vec[0].base = const_cast<uint8_t *>(stream->resp_data.data());
  vec[0].len = stream->resp_data.size();
  *pflags |= NGHTTP3_DATA_FLAG_EOF;
  if (config.send_trailers) {
    *pflags |= NGHTTP3_DATA_FLAG_NO_END_STREAM;
  }

  return 1;
}
} // namespace

std::expected<void, Error>
ProtoCodec::send_status_response(Stream *stream, uint32_t status_code) {
  stream->status_resp_body = make_status_body(status_code);

  auto status_code_str = util::format_uint(status_code);
  auto content_length_str = util::format_uint(stream->status_resp_body.size());

  auto nva = std::to_array({
    util::make_nv_nc(":status", status_code_str),
    util::make_nv_nn("server", NGTCP2_SERVER),
    util::make_nv_nn("content-type", "text/html; charset=utf-8"),
    util::make_nv_nc("content-length", content_length_str),
  });

  stream->resp_data = as_uint8_span(std::span{stream->status_resp_body});

  static constexpr nghttp3_data_reader dr{
    .read_data = read_data,
  };

  if (auto rv = nghttp3_conn_submit_response(httpconn_, stream->stream_id,
                                             nva.data(), nva.size(), &dr);
      rv != 0) {
    std::println(stderr, "nghttp3_conn_submit_response: {}",
                 nghttp3_strerror(rv));
    return std::unexpected{Error::HTTP3};
  }

  if (config.send_trailers) {
    auto stream_id_str = util::format_uint(as_unsigned(stream->stream_id));
    auto trailers = std::to_array({
      util::make_nv_nc("x-ngtcp2-stream-id"sv, stream_id_str),
    });

    if (auto rv = nghttp3_conn_submit_trailers(
          httpconn_, stream->stream_id, trailers.data(), trailers.size());
        rv != 0) {
      std::println(stderr, "nghttp3_conn_submit_trailers: {}",
                   nghttp3_strerror(rv));
      return std::unexpected{Error::HTTP3};
    }
  }

  handler_->shutdown_read(stream->stream_id, NGHTTP3_H3_NO_ERROR);

  return {};
}

std::expected<void, Error> ProtoCodec::setup_httpconn() {
  if (httpconn_) {
    return {};
  }

  if (ngtcp2_conn_get_streams_uni_left2(conn_) < 3) {
    std::println(stderr,
                 "peer does not allow at least 3 unidirectional streams.");
    return std::unexpected{Error::QUIC};
  }

  static constexpr auto callbacks = nghttp3_callbacks{
    .stream_close = ::http_stream_close,
    .recv_data = ::http_recv_data,
    .deferred_consume = ::http_deferred_consume,
    .begin_headers = ::http_begin_request_headers,
    .recv_header = ::http_recv_request_header,
    .end_headers = ::http_end_request_headers,
    .stop_sending = ::http_stop_sending,
    .end_stream = ::http_end_stream,
    .reset_stream = ::http_reset_stream,
    .rand = rand_bytes,
    .recv_settings2 = ::http_recv_settings,
    .recv_wt_data = ::http_recv_wt_data,
  };

  nghttp3_settings settings;
  nghttp3_settings_default(&settings);
  settings.qpack_max_dtable_capacity = 4096;
  settings.qpack_blocked_streams = 100;
  settings.wt_enabled = 1;
  settings.enable_connect_protocol = 1;
  settings.h3_datagram = 1;

  nghttp3_vec origin_list;

  if (config.origin_list) {
    origin_list.base = config.origin_list->data();
    origin_list.len = config.origin_list->size();

    settings.origin_list = &origin_list;
  }

  auto mem = nghttp3_mem_default();

  if (auto rv =
        nghttp3_conn_server_new(&httpconn_, &callbacks, &settings, mem, this);
      rv != 0) {
    std::println(stderr, "nghttp3_conn_server_new: {}", nghttp3_strerror(rv));
    return std::unexpected{Error::HTTP3};
  }

  auto params = ngtcp2_conn_get_local_transport_params2(conn_);

  nghttp3_conn_set_max_client_streams_bidi(httpconn_,
                                           params->initial_max_streams_bidi);

  int64_t ctrl_stream_id;

  if (auto rv = ngtcp2_conn_open_uni_stream(conn_, &ctrl_stream_id, nullptr);
      rv != 0) {
    std::println(stderr, "ngtcp2_conn_open_uni_stream: {}",
                 ngtcp2_strerror(rv));
    return std::unexpected{Error::QUIC};
  }

  if (auto rv = nghttp3_conn_bind_control_stream(httpconn_, ctrl_stream_id);
      rv != 0) {
    std::println(stderr, "nghttp3_conn_bind_control_stream: {}",
                 nghttp3_strerror(rv));
    return std::unexpected{Error::HTTP3};
  }

  if (!config.quiet) {
    std::println(stderr, "http: control stream={:#x}", ctrl_stream_id);
  }

  int64_t qpack_enc_stream_id, qpack_dec_stream_id;

  if (auto rv =
        ngtcp2_conn_open_uni_stream(conn_, &qpack_enc_stream_id, nullptr);
      rv != 0) {
    std::println(stderr, "ngtcp2_conn_open_uni_stream: {}",
                 ngtcp2_strerror(rv));
    return std::unexpected{Error::QUIC};
  }

  if (auto rv =
        ngtcp2_conn_open_uni_stream(conn_, &qpack_dec_stream_id, nullptr);
      rv != 0) {
    std::println(stderr, "ngtcp2_conn_open_uni_stream: {}",
                 ngtcp2_strerror(rv));
    return std::unexpected{Error::QUIC};
  }

  if (auto rv = nghttp3_conn_bind_qpack_streams(httpconn_, qpack_enc_stream_id,
                                                qpack_dec_stream_id);
      rv != 0) {
    std::println(stderr, "nghttp3_conn_bind_qpack_streams: {}",
                 nghttp3_strerror(rv));
    return std::unexpected{Error::HTTP3};
  }

  if (!config.quiet) {
    std::println(stderr, "http: QPACK streams encoder={:#x} decoder={:#x}",
                 qpack_enc_stream_id, qpack_dec_stream_id);
  }

  return {};
}

Config ProtoCodec::config_default() {
  Config config;

  config.max_stream_data_bidi_local = config.max_stream_data_bidi_remote;
  config.max_streams_uni += config.max_streams_bidi;
  config.download = "downloads"sv;

  return config;
}

void ProtoCodec::configure_transport_params(ngtcp2_transport_params &params) {
  params.max_datagram_frame_size = 65535;
  params.reset_stream_at = 1;
}

void ProtoCodec::init() {
  if (config.webtransport_interop) {
    webtransport::interop::config.quiet = config.quiet;
    webtransport::interop::config.www_root = config.htdocs;

    if (auto tc = getenv("TESTCASE"); tc) {
      std::println(stderr, "TESTCASE {}", tc);

      if ("handshake"sv == tc) {
        webtransport::interop::config.testcase =
          webtransport::interop::Testcase::HANDSHAKE;
      } else if ("transfer"sv == tc) {
        webtransport::interop::config.testcase =
          webtransport::interop::Testcase::TRANSFER;
      } else if ("transfer-bidirectional-send"sv == tc) {
        webtransport::interop::config.testcase =
          webtransport::interop::Testcase::TRANSFER_BIDIRECTIONAL_SEND;
      } else if ("transfer-unidirectional-send"sv == tc) {
        webtransport::interop::config.testcase =
          webtransport::interop::Testcase::TRANSFER_UNIDIRECTIONAL_SEND;
      } else if ("transfer-datagram-send"sv == tc) {
        webtransport::interop::config.testcase =
          webtransport::interop::Testcase::TRANSFER_DATAGRAM_SEND;
      } else {
        std::println(stderr, "Unexpected TESTCASE: {}", tc);
        exit(127);
      }
    } else {
      std::println(stderr, "TESTCASE not defined");
      exit(127);
    }

    if (auto protos_env = getenv("PROTOCOLS"); protos_env) {
      webtransport::interop::config.protos =
        util::split_str(protos_env, ' ') |
        std::ranges::to<std::vector<std::string>>();
    }

    if (auto reqs_env = getenv("REQUESTS"); reqs_env) {
      auto maybe_reqs = webtransport::interop::parse_server_requests(reqs_env);
      if (!maybe_reqs) {
        std::println(stderr, "Invalid REQUESTS");
        exit(127);
      }

      webtransport::interop::config.server_requests = std::move(*maybe_reqs);
    }

    std::error_code ec;

    auto download_root = std::filesystem::canonical(config.download, ec);
    if (ec) {
      std::println(stderr, "Download directory {} not found",
                   config.download.native());
      exit(127);
    }

    std::println(stderr, "Using download root {}", download_root.native());

    webtransport::interop::config.download_root = download_root;
  } else {
    webtransport::baton::config.quiet = config.quiet;
  }
}

} // namespace ngtcp2
