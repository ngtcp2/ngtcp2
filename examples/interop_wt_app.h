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
#ifndef INTEROP_WT_APP_H
#define INTEROP_WT_APP_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif // defined(HAVE_CONFIG_H)

#include <deque>
#include <unordered_map>
#include <memory>
#include <filesystem>

#include <ngtcp2/ngtcp2.h>
#include <nghttp3/nghttp3.h>

#include "wt_app.h"
#include "shared.h"

namespace ngtcp2 {
namespace webtransport {
namespace interop {

enum class Testcase {
  HANDSHAKE,
  TRANSFER,
  // for server
  TRANSFER_BIDIRECTIONAL_SEND,
  TRANSFER_UNIDIRECTIONAL_SEND,
  TRANSFER_DATAGRAM_SEND,
  // for client
  TRANSFER_BIDIRECTIONAL_RECEIVE = TRANSFER_BIDIRECTIONAL_SEND,
  TRANSFER_UNIDIRECTIONAL_RECEIVE = TRANSFER_UNIDIRECTIONAL_SEND,
  TRANSFER_DATAGRAM_RECEIVE = TRANSFER_DATAGRAM_SEND,
};

struct SessionRequest {
  std::string endpoint;
  std::vector<std::string> requests;
};

struct ClientRequest {
  std::string_view scheme;
  std::string host;
  std::string port;
  std::vector<SessionRequest> session_requests;
};

struct Config {
  bool quiet{};
  Testcase testcase{};
  std::filesystem::path www_root;
  std::filesystem::path download_root;
  std::vector<std::string> protos;
  std::unordered_map<std::string, std::vector<std::string>> server_requests;
  ClientRequest client_request;
};

extern Config config;

struct Stream {
  Stream(int64_t stream_id) : stream_id{stream_id} {}
  ~Stream();

  std::expected<void, Error> map_file();
  std::expected<void, Error> open_download_file();
  std::expected<void, Error> write_file(std::span<const uint8_t> data);

  int64_t stream_id;
  std::vector<uint8_t> input;
  std::filesystem::path path;
  std::filesystem::path req_path;
  int fd{-1};
  size_t map_len{};
  void *map_addr{};
  bool download{};
};

enum class Action {
  SEND_FILE,
  SEND_REQUEST,
};

struct PendingAction {
  Action action{};
  std::filesystem::path path;
};

class App : public AppBase {
public:
  App(ngtcp2_conn *conn, nghttp3_conn *httpconn, int64_t session_id, Side side,
      std::span<const std::string> protos = {});

  std::expected<void, Error>
  submit_session_request(std::string_view scheme, std::string_view authority,
                         std::string_view path) override;

  std::expected<void, Error>
  accept_session_request(std::string_view path,
                         std::span<const std::string> avail_protos) override;

  std::expected<void, Error> on_data(int64_t stream_id,
                                     std::span<const uint8_t> data) override;

  std::expected<void, Error> on_end_stream(int64_t stream_id) override;

  std::expected<void, Error>
  on_datagram(std::span<const uint8_t> data) override;

  std::vector<Datagram> pull_datagram() override;

  bool has_pending_bidi_stream() const override {
    return !pending_bidi_streams_.empty();
  }

  bool has_pending_uni_stream() const override {
    return !pending_uni_streams_.empty();
  }

  void on_stream_close(int64_t stream_id, uint64_t app_error_code) override;

  std::expected<void, Error> handle_pending_bidi_stream() override;

  std::expected<void, Error> handle_pending_uni_stream() override;

  bool finished() const override;

  void on_proto_negotiated(std::string_view proto) override;

  std::expected<void, Error> on_session_started() override;

private:
  std::expected<void, Error> transfer_on_data(int64_t stream_id,
                                              std::span<const uint8_t> data);

  std::expected<void, Error> transfer_on_end_stream(Stream *stream);

  std::expected<void, Error> send_file(Stream *stream);

  std::expected<void, Error>
  open_uni_stream_and_send_file(const std::filesystem::path &path);

  std::expected<void, Error>
  transfer_on_datagram(std::span<const uint8_t> data);

  std::expected<void, Error>
  send_file_datagram(const std::filesystem::path &path);

  std::expected<std::filesystem::path, Error>
  extract_filename(const std::filesystem::path &root,
                   std::string_view expected_method,
                   std::span<const uint8_t> data);

  std::expected<std::filesystem::path, Error>
  extract_filename_for_reading(std::string_view expected_method,
                               std::span<const uint8_t> data);

  std::expected<std::filesystem::path, Error>
  extract_filename_for_writing(std::string_view expected_method,
                               std::span<const uint8_t> data);

  std::expected<void, Error>
  transfer_bidi_on_session_open(std::span<const std::filesystem::path> paths);

  std::expected<void, Error>
  open_bidi_stream_and_send_request(const std::filesystem::path &path);

  std::expected<void, Error>
  transfer_uni_on_session_open(std::span<const std::filesystem::path> paths);

  void transfer_datagram_on_session_open(
    std::span<const std::filesystem::path> paths);

  std::expected<void, Error>
  open_uni_stream_and_send_request(const std::filesystem::path &path);

  std::expected<void, Error> send_request(Stream *stream);

  void datagram_send_request(const std::filesystem::path &path);

  std::expected<void, Error>
  transfer_bidi_on_data(int64_t stream_id, std::span<const uint8_t> data);

  std::expected<void, Error>
  transfer_uni_on_data(int64_t stream_id, std::span<const uint8_t> data);

  std::expected<void, Error>
  transfer_datagram_on_datagram(std::span<const uint8_t> data);

  std::expected<std::vector<std::filesystem::path>, Error>
  make_filenames_absolute(std::span<const std::string> filenames);

  std::expected<void, Error> write_proto(std::string_view proto);

  std::filesystem::path fixup_download_path(const std::filesystem::path &path);

  const std::vector<std::string> &get_endpoint_paths() const;

  std::expected<void, Error> setup_root_dirs();

  ngtcp2_conn *conn_{};
  nghttp3_conn *httpconn_{};
  int64_t session_id_{};
  Side side_{};
  std::span<const std::string> protos_;
  std::string endpoint_;
  std::filesystem::path www_root_;
  std::filesystem::path download_root_;
  std::unordered_map<int64_t, std::unique_ptr<Stream>> streams_;
  std::deque<PendingAction> pending_bidi_streams_;
  std::deque<PendingAction> pending_uni_streams_;
  std::deque<Datagram> pending_datagrams_;
  size_t datagrams_inflight_{};
  size_t downloads_left_{std::numeric_limits<size_t>::max()};
  std::string negotiated_proto_;
};

std::expected<std::unordered_map<std::string, std::vector<std::string>>, Error>
parse_server_requests(std::string_view data);

std::expected<ClientRequest, Error>
parse_client_requests(std::string_view data);

} // namespace interop
} // namespace webtransport
} // namespace ngtcp2

#endif // INTEROP_WT_APP_H
