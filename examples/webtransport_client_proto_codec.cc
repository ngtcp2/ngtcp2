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
#include "webtransport_client_proto_codec.h"

#include <unistd.h>

#include <sfparse.h>

#include "client.h"
#include "debug.h"
#include "baton_wt_app.h"
#include "interop_wt_app.h"

extern Config config;

namespace ngtcp2 {

ProtoCodec::ProtoCodec(Client *c, ngtcp2_ccerr &last_error)
  : client_{c}, conn_{client_->conn()}, last_error_{last_error} {}

ProtoCodec::~ProtoCodec() {
  if (httpconn_) {
    nghttp3_conn_del(httpconn_);
  }
}

std::expected<void, Error>
ProtoCodec::recv_stream_data(uint32_t flags, int64_t stream_id,
                             std::span<const uint8_t> data) {
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

  auto wt_session_stream = client_->find_stream(session_id);
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
    client_->break_loop();
  }

  return {};
}

std::expected<void, Error>
ProtoCodec::acked_stream_data_offset(int64_t stream_id, uint64_t datalen) {
  if (auto rv = nghttp3_conn_add_ack_offset(httpconn_, stream_id, datalen);
      rv != 0) {
    std::println(stderr, "nghttp3_conn_add_ack_offset: {}",
                 nghttp3_strerror(rv));
    return std::unexpected{Error::HTTP3};
  }

  return {};
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

std::expected<void, Error> ProtoCodec::extend_max_local_streams_bidi() {
  for (; !bidi_streams_.empty();) {
    auto session_id = *std::ranges::begin(bidi_streams_);

    auto wt_session_stream = client_->find_stream(session_id);
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

    auto wt_session_stream = client_->find_stream(session_id);
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

void ProtoCodec::early_data_rejected() {
  nghttp3_conn_del(httpconn_);
  httpconn_ = nullptr;
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

  http_stream_close(stream_id, app_error_code);

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

ngtcp2_ssize ProtoCodec::write_pkt(ngtcp2_path *path, ngtcp2_pkt_info *pi,
                                   uint8_t *dest, size_t destlen,
                                   ngtcp2_tstamp ts) {
  std::array<nghttp3_vec, 16> vec;

  for (;;) {
    if (datagrams_.empty()) {
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

      ngtcp2_ssize ndatalen;
      auto v = vec.data();
      auto vcnt = static_cast<size_t>(sveccnt);

      uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
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

namespace {
int http_recv_data(nghttp3_conn *conn, int64_t stream_id, const uint8_t *data,
                   size_t datalen, void *user_data, void *stream_user_data) {
  if (!config.quiet && !config.no_http_dump) {
    debug::print_http_data(stream_id, {data, datalen});
  }
  auto pc = static_cast<ProtoCodec *>(user_data);
  pc->http_consume(stream_id, datalen);
  pc->http_write_data(stream_id, {data, datalen});
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

void ProtoCodec::http_write_data(int64_t stream_id,
                                 std::span<const uint8_t> data) {
  auto stream = client_->find_stream(stream_id);
  if (!stream) {
    return;
  }

  if (stream->fd == -1) {
    return;
  }

  ssize_t nwrite;

  for (; !data.empty();) {
    do {
      nwrite = write(stream->fd, data.data(), data.size());
    } while (nwrite == -1 && errno == EINTR);

    if (nwrite < 0) {
      std::println(stderr, "Could not write data to file: {}", strerror(errno));

      return;
    }

    data = data.subspan(static_cast<size_t>(nwrite));
  }
}

namespace {
int http_begin_headers(nghttp3_conn *conn, int64_t stream_id, void *user_data,
                       void *stream_user_data) {
  if (!config.quiet) {
    debug::print_http_begin_response_headers(stream_id);
  }
  return 0;
}
} // namespace

namespace {
std::expected<std::string, Error>
parse_wt_proto(std::span<const uint8_t> data) {
  sfparse_parser sfp;

  sfparse_parser_init(&sfp, data.data(), data.size());

  sfparse_value item;

  auto rv = sfparse_parser_item(&sfp, &item);
  if (rv != 0 || item.type != SFPARSE_TYPE_STRING) {
    return std::unexpected{Error::INVALID_ARGUMENT};
  }

  if (sfparse_parser_item(&sfp, nullptr) != SFPARSE_ERR_EOF) {
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

    return s;
  }

  return std::string{item.vec.base, item.vec.base + item.vec.len};
}
} // namespace

namespace {
int http_recv_header(nghttp3_conn *conn, int64_t stream_id, int32_t token,
                     nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
                     void *user_data, void *stream_user_data) {
  if (!config.quiet) {
    debug::print_http_header(stream_id, name, value, flags);
  }

  auto stream = static_cast<Stream *>(stream_user_data);
  if (!stream) {
    return 0;
  }

  auto v = nghttp3_rcbuf_get_buf(value);

  if (token == NGHTTP3_QPACK_TOKEN__STATUS) {
    auto maybe_status_code =
      util::parse_uint(as_string_view(std::span{v.base, v.len}));
    assert(maybe_status_code);
    stream->status_code = static_cast<uint32_t>(*maybe_status_code);

    return 0;
  }

  if (token != -1) {
    return 0;
  }

  auto k = nghttp3_rcbuf_get_buf(name);
  if (std::ranges::equal("wt-protocol"sv, std::span{k.base, k.len})) {
    auto maybe_proto = parse_wt_proto(std::span{v.base, v.len});
    if (!maybe_proto) {
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    }

    stream->negotiated_proto = *maybe_proto;
  }

  return 0;
}
} // namespace

namespace {
int http_end_headers(nghttp3_conn *conn, int64_t stream_id, int fin,
                     void *user_data, void *stream_user_data) {
  if (!config.quiet) {
    debug::print_http_end_headers(stream_id);
  }

  auto stream = static_cast<Stream *>(stream_user_data);
  if (!stream) {
    return 0;
  }

  auto pc = static_cast<ProtoCodec *>(user_data);

  if (!pc->http_end_headers(stream)) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

std::expected<void, Error> ProtoCodec::http_end_headers(Stream *stream) {
  if (stream->status_code / 100 != 2) {
    return {};
  }

  const auto &wt_app = stream->wt_app;

  wt_app->on_proto_negotiated(stream->negotiated_proto);

  if (auto rv = wt_app->on_session_started(); !rv) {
    return rv;
  }

  handle_pending_transmission(stream, *wt_app);

  return {};
}

namespace {
int http_begin_trailers(nghttp3_conn *conn, int64_t stream_id, void *user_data,
                        void *stream_user_data) {
  if (!config.quiet) {
    debug::print_http_begin_trailers(stream_id);
  }
  return 0;
}
} // namespace

namespace {
int http_recv_trailer(nghttp3_conn *conn, int64_t stream_id, int32_t token,
                      nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
                      void *user_data, void *stream_user_data) {
  if (!config.quiet) {
    debug::print_http_header(stream_id, name, value, flags);
  }
  return 0;
}
} // namespace

namespace {
int http_end_trailers(nghttp3_conn *conn, int64_t stream_id, int fin,
                      void *user_data, void *stream_user_data) {
  if (!config.quiet) {
    debug::print_http_end_trailers(stream_id);
  }
  return 0;
}
} // namespace

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

  auto wt_session_stream = client_->find_stream(session_id);
  if (!wt_session_stream) {
    return {};
  }

  return wt_session_stream->wt_app->on_end_stream(stream_id);
}

namespace {
int http_stop_sending(nghttp3_conn *conn, int64_t stream_id,
                      uint64_t app_error_code, void *user_data,
                      void *stream_user_data) {
  auto pc = static_cast<ProtoCodec *>(user_data);
  if (!pc->stop_sending(stream_id, app_error_code)) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
} // namespace

std::expected<void, Error> ProtoCodec::stop_sending(int64_t stream_id,
                                                    uint64_t app_error_code) {
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
int http_reset_stream(nghttp3_conn *conn, int64_t stream_id,
                      uint64_t app_error_code, void *user_data,
                      void *stream_user_data) {
  auto pc = static_cast<ProtoCodec *>(user_data);
  if (!pc->reset_stream(stream_id, app_error_code)) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
} // namespace

std::expected<void, Error> ProtoCodec::reset_stream(int64_t stream_id,
                                                    uint64_t app_error_code) {
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
                       void *conn_user_data) {
  if (!config.quiet) {
    debug::print_http_settings(settings);
  }

  auto pc = static_cast<ProtoCodec *>(conn_user_data);

  if (!pc->http_recv_settings(settings)) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

std::expected<void, Error>
ProtoCodec::http_recv_settings(const nghttp3_proto_settings *settings) {
  if ((config.requests.empty() && !config.webtransport_interop) ||
      !settings->wt_enabled || !settings->enable_connect_protocol ||
      !settings->h3_datagram) {
    return {};
  }

  if (!wt_capable()) {
    return std::unexpected{Error::INTERNAL};
  }

  return submit_webtransport_request();
}

std::expected<void, Error> ProtoCodec::submit_webtransport_request() {
  int64_t stream_id;

  if (auto rv = ngtcp2_conn_open_bidi_stream(conn_, &stream_id, nullptr);
      rv != 0) {
    if (NGTCP2_ERR_STREAM_ID_BLOCKED != rv) {
      return std::unexpected{Error::INTERNAL};
    }

    return std::unexpected{Error::STREAM_ID_BLOCKED};
  }

  if (!config.webtransport_interop) {
    assert(!config.requests.empty());

    auto stream = std::make_unique<Stream>(config.requests[0], stream_id);

    stream->wt_app = std::make_unique<webtransport::baton::App>(
      conn_, httpconn_, stream_id, webtransport::Side::CLIENT);

    if (auto rv = stream->wt_app->submit_session_request(
          stream->req.scheme, stream->req.authority, stream->req.path);
        !rv) {
      return rv;
    }

    client_->add_stream(std::move(stream));

    return {};
  }

  // TODO We currently only use single endpoint.
  const auto &creq = webtransport::interop::config.client_request;
  const auto &session_req = creq.session_requests[0];
  std::string authority;

  if (util::numeric_host(creq.host.c_str(), AF_INET6)) {
    authority = '[';
    authority += creq.host;
    authority += ']';
  } else {
    authority = creq.host;
  }

  if (!creq.port.empty() && creq.port != "443"sv) {
    authority += ':';
    authority += creq.port;
  }

  auto req = Request{
    .scheme = creq.scheme,
    .authority = authority,
    .path = "/" + session_req.endpoint,
  };

  auto stream = std::make_unique<Stream>(std::move(req), stream_id);

  stream->wt_app = std::make_unique<webtransport::interop::App>(
    conn_, httpconn_, stream_id, webtransport::Side::CLIENT);

  if (auto rv = stream->wt_app->submit_session_request(
        stream->req.scheme, stream->req.authority, stream->req.path);
      !rv) {
    return rv;
  }

  nghttp3_conn_set_stream_user_data(httpconn_, stream_id, stream.get());

  client_->add_stream(std::move(stream));

  return {};
}

bool ProtoCodec::wt_capable() const {
  auto remote_params = ngtcp2_conn_get_remote_transport_params2(conn_);

  return remote_params->max_datagram_frame_size &&
         remote_params->reset_stream_at;
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

  auto wt_session_stream = client_->find_stream(session_id);
  if (wt_session_stream && wt_session_stream->wt_app) {
    wt_session_stream->wt_app->on_stream_close(stream_id, app_error_code);

    if (wt_session_stream->wt_app->finished()) {
      client_->break_loop();
    }
  }
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
  auto wt_session_stream = client_->find_stream(session_id);
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
int http_recv_origin(nghttp3_conn *conn, const uint8_t *origin,
                     size_t originlen, void *conn_user_data) {
  if (!config.quiet) {
    debug::print_http_origin(origin, originlen);
  }

  return 0;
}
} // namespace

namespace {
int http_end_origin(nghttp3_conn *conn, void *conn_user_data) {
  if (!config.quiet) {
    debug::print_http_end_origin();
  }

  return 0;
}
} // namespace

std::expected<void, Error> ProtoCodec::setup_codec() {
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
    .begin_headers = ::http_begin_headers,
    .recv_header = ::http_recv_header,
    .end_headers = ::http_end_headers,
    .begin_trailers = ::http_begin_trailers,
    .recv_trailer = ::http_recv_trailer,
    .end_trailers = ::http_end_trailers,
    .stop_sending = ::http_stop_sending,
    .end_stream = ::http_end_stream,
    .reset_stream = ::http_reset_stream,
    .recv_origin = ::http_recv_origin,
    .end_origin = ::http_end_origin,
    .rand = rand_bytes,
    .recv_settings2 = ::http_recv_settings,
    .recv_wt_data = ::http_recv_wt_data,
  };
  nghttp3_settings settings;
  nghttp3_settings_default(&settings);
  settings.qpack_max_dtable_capacity = 4_k;
  settings.qpack_blocked_streams = 100;
  settings.wt_enabled = 1;
  settings.h3_datagram = 1;

  auto mem = nghttp3_mem_default();

  if (auto rv =
        nghttp3_conn_client_new(&httpconn_, &callbacks, &settings, mem, this);
      rv != 0) {
    std::println(stderr, "nghttp3_conn_client_new: {}", nghttp3_strerror(rv));
    return std::unexpected{Error::HTTP3};
  }

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

  config.max_stream_data_bidi_remote = config.max_stream_data_bidi_local;
  config.max_streams_bidi = 100;
  config.max_streams_uni += 3;
  config.download = "downloads";

  return config;
}

void ProtoCodec::configure_transport_params(ngtcp2_transport_params &params) {
  params.max_datagram_frame_size = 65535;
  params.reset_stream_at = 1;
}

void ProtoCodec::init() {
  if (!config.webtransport_interop) {
    webtransport::baton::config.quiet = config.quiet;
    return;
  }

  webtransport::interop::config.quiet = config.quiet;

  if (auto tc = getenv("TESTCASE"); tc) {
    std::println(stderr, "TESTCASE {}", tc);

    if ("handshake"sv == tc) {
      webtransport::interop::config.testcase =
        webtransport::interop::Testcase::HANDSHAKE;
    } else if ("transfer"sv == tc) {
      webtransport::interop::config.testcase =
        webtransport::interop::Testcase::TRANSFER;
    } else if ("transfer-bidirectional-receive"sv == tc) {
      webtransport::interop::config.testcase =
        webtransport::interop::Testcase::TRANSFER_BIDIRECTIONAL_RECEIVE;
    } else if ("transfer-unidirectional-receive"sv == tc) {
      webtransport::interop::config.testcase =
        webtransport::interop::Testcase::TRANSFER_UNIDIRECTIONAL_RECEIVE;
    } else if ("transfer-datagram-receive"sv == tc) {
      webtransport::interop::config.testcase =
        webtransport::interop::Testcase::TRANSFER_DATAGRAM_RECEIVE;
    } else {
      std::println(stderr, "Unexpected TESTCASE: {}", tc);
      exit(127);
    }
  } else {
    std::println(stderr, "TESTCASE not defined");
    exit(127);
  }

  if (auto protos_env = getenv("PROTOCOLS"); protos_env) {
    auto raw_protos = util::split_str(protos_env, ' ');

    std::vector<std::string> protos{std::ranges::begin(raw_protos),
                                    std::ranges::end(raw_protos)};

    webtransport::interop::config.protos = std::move(protos);
  }

  if (auto reqs_env = getenv("REQUESTS"); reqs_env) {
    auto maybe_req = webtransport::interop::parse_client_requests(reqs_env);
    if (!maybe_req) {
      std::println(stderr, "Invalid REQUESTS");
      exit(127);
    }

    config.addr = maybe_req->host;
    config.port = maybe_req->port;

    webtransport::interop::config.client_request = std::move(*maybe_req);
  }

  if (webtransport::interop::config.client_request.session_requests.empty()) {
    std::println(stderr, "No REQUESTS given");

    exit(EXIT_SUCCESS);
  }

  std::error_code ec;

  auto www_root = std::filesystem::canonical(config.htdocs, ec);
  if (ec) {
    std::println(stderr, "Document root directory {} not found",
                 config.htdocs.native());
    exit(127);
  }

  std::println(stderr, "Using document root {}", www_root.native());

  webtransport::interop::config.www_root = www_root;

  auto download_root = std::filesystem::canonical(config.download, ec);
  if (ec) {
    std::println(stderr, "Download directory {} not found",
                 config.download.native());
    exit(127);
  }

  std::println(stderr, "Using download root {}", download_root.native());

  webtransport::interop::config.download_root = download_root;
}

} // namespace ngtcp2
