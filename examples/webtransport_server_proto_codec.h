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
#ifndef WEBTRANSPORT_SERVER_PROTO_CODEC_H
#define WEBTRANSPORT_SERVER_PROTO_CODEC_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif // defined(HAVE_CONFIG_H)

#include <vector>
#include <expected>
#include <unordered_set>

#include <ngtcp2/ngtcp2.h>
#include <nghttp3/nghttp3.h>

#include "shared.h"
#include "server_base.h"
#include "wt_app.h"

struct Stream;
class Handler;

namespace ngtcp2 {

class ProtoCodec {
public:
  ProtoCodec(Handler *handler, ngtcp2_ccerr &last_error);
  ~ProtoCodec();

  std::expected<void, Error> acked_stream_data_offset(int64_t stream_id,
                                                      uint64_t datalen);

  std::expected<void, Error> on_stream_reset(int64_t stream_id);

  std::expected<void, Error> on_stream_stop_sending(int64_t stream_id);

  void extend_max_remote_streams_bidi(uint64_t max_streams);

  std::expected<void, Error> extend_max_stream_data(int64_t stream_id,
                                                    uint64_t max_data);

  std::expected<void, Error> extend_max_local_streams_bidi();

  std::expected<void, Error> extend_max_local_streams_uni();

  std::expected<void, Error> on_app_tx_ready();

  ngtcp2_ssize write_pkt(ngtcp2_path *path, ngtcp2_pkt_info *pi, uint8_t *dest,
                         size_t destlen, ngtcp2_tstamp ts);

  std::expected<void, Error> recv_stream_data(uint32_t flags, int64_t stream_id,
                                              std::span<const uint8_t> data);

  std::expected<void, Error> recv_datagram(std::span<const uint8_t> data);

  std::expected<void, Error> on_stream_close(int64_t stream_id,
                                             uint64_t app_error_code);

  std::expected<void, Error> start_response(Stream *stream);

  // The following functions are made public so that they can be
  // called from nghttp3 callback functions.
  void http_acked_stream_data(Stream *stream, uint64_t datalen);

  void http_consume(int64_t stream_id, size_t nconsumed);

  void http_begin_request_headers(int64_t stream_id);

  void http_recv_request_header(Stream *stream, int32_t token,
                                nghttp3_rcbuf *name, nghttp3_rcbuf *value);

  std::expected<void, Error> http_end_request_headers(Stream *stream);

  std::expected<void, Error> http_stop_sending(int64_t stream_id,
                                               uint64_t app_error_code);

  std::expected<void, Error> http_end_stream(int64_t stream_id);

  std::expected<void, Error> http_reset_stream(int64_t stream_id,
                                               uint64_t app_error_code);

  void http_stream_close(int64_t stream_id, uint64_t app_error_code);

  void http_recv_settings(const nghttp3_proto_settings *settings);

  std::expected<void, Error> http_recv_wt_data(int64_t session_id,
                                               int64_t stream_id,
                                               std::span<const uint8_t> data);

  static constexpr auto protocol = AppProtocol::H3;

  static Config config_default();

  static void configure_transport_params(ngtcp2_transport_params &params);

  static void init();

private:
  std::expected<void, Error> send_status_response(Stream *stream,
                                                  uint32_t status_code);

  std::expected<void, Error> setup_httpconn();

  void handle_pending_transmission(Stream *stream,
                                   webtransport::AppBase &wt_app);

  bool wt_capable(Stream *stream) const;

  Handler *handler_;
  ngtcp2_conn *conn_;
  ngtcp2_ccerr &last_error_;
  nghttp3_conn *httpconn_{};
  bool wt_settings_enabled_{};
  std::deque<webtransport::Datagram> datagrams_;
  std::unordered_set<int64_t> bidi_streams_;
  std::unordered_set<int64_t> uni_streams_;
};

} // namespace ngtcp2

#endif // WEBTRANSPORT_SERVER_PROTO_CODEC_H
