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
#include "interop_wt_app.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <ranges>

#include <urlparse.h>

#include "util.h"
#include "debug.h"

namespace ngtcp2 {
namespace webtransport {
namespace interop {

Config config;

constexpr auto MAX_STREAM_INPUT = 256UZ;

constexpr auto PUSH_PREFIX = "PUSH "sv;
constexpr auto GET_PREFIX = "GET "sv;

namespace {
auto randgen = util::make_mt19937();
} // namespace

App::App(ngtcp2_conn *conn, nghttp3_conn *httpconn, int64_t session_id,
         Side side, std::span<const std::string> protos)
  : conn_{conn},
    httpconn_{httpconn},
    session_id_{session_id},
    side_{side},
    protos_{protos} {}

std::expected<void, Error>
App::submit_session_request(std::string_view scheme, std::string_view authority,
                            std::string_view path) {
  auto nva = std::to_array<nghttp3_nv>({
    util::make_nv_nn(":method", "CONNECT"),
    util::make_nv_nn(":scheme", scheme),
    util::make_nv_nn(":authority", authority),
    util::make_nv_nn(":path", path),
    // TODO This should be webtransport-h3, but we need to deal with
    // the older servers.
    util::make_nv_nn(":protocol", "webtransport"),
    util::make_nv_nn("user-agent", "nghttp3/ngtcp2 interop client"),
    {},
  });

  size_t nvlen = 6;
  std::string avail_protos;

  if (!config.protos.empty()) {
    avail_protos = util::encode_sflist(config.protos);

    nva[nvlen++] = util::make_nv_nc("wt-available-protocols"sv, avail_protos);
  }

  if (!config.quiet) {
    debug::print_http_request_headers(session_id_, nva.data(), nvlen);
  }

  if (auto rv = nghttp3_conn_submit_wt_request(httpconn_, session_id_,
                                               nva.data(), nvlen, nullptr);
      rv != 0) {
    std::println(stderr, "nghttp3_conn_submit_wt_request: {}",
                 nghttp3_strerror(rv));
    return std::unexpected{Error::HTTP3};
  }

  endpoint_ = std::filesystem::path{path}.relative_path().native();

  return setup_root_dirs();
}

struct Request {
  std::string path;
};

namespace {
std::expected<Request, Error> request_path(const std::string_view &uri) {
  urlparse_url u;
  Request req;

  if (auto rv =
        urlparse_parse_url(uri.data(), uri.size(), /* is_connect = */ 0, &u);
      rv != 0) {
    std::println(stderr, "Could not parse URL {}", uri);

    return std::unexpected{Error::INVALID_ARGUMENT};
  }

  if (u.field_set & (1 << URLPARSE_PATH)) {
    req.path = util::get_string(uri, u, URLPARSE_PATH);
    if (req.path.find('%') != std::string::npos) {
      req.path = util::percent_decode(req.path);
    }

    assert(!req.path.empty());

    if (req.path[0] != '/') {
      std::println(stderr, "The path {} does not start with '/'", req.path);

      return std::unexpected{Error::INVALID_ARGUMENT};
    }

    if (req.path.back() == '/') {
      req.path += "index.html";
    }

    auto maybe_norm_path = util::normalize_path(req.path);
    if (!maybe_norm_path) {
      std::println(stderr, "Could not normalize path {}", req.path);

      return std::unexpected{maybe_norm_path.error()};
    }

    req.path = std::move(*maybe_norm_path);
  } else {
    req.path = "/index.html";
  }

  return req;
}
} // namespace

namespace {
bool check_safe_path(const std::filesystem::path &path,
                     const std::filesystem::path &root) {
  return std::string_view{path.native()}.starts_with(
    std::string_view{root.native()});
}
} // namespace

std::expected<std::vector<std::filesystem::path>, Error>
App::make_filenames_absolute(std::span<const std::string> filenames) {
  std::vector<std::filesystem::path> res;

  for (auto &fn : filenames) {
    auto path = (download_root_ / fn).lexically_normal();
    if (!check_safe_path(path, download_root_)) {
      std::println(stderr, "The path {} is unsafe", path.native());

      return std::unexpected{Error::INVALID_ARGUMENT};
    }

    res.emplace_back(std::move(path));
  }

  return res;
}

std::expected<void, Error>
App::accept_session_request(std::string_view path,
                            std::span<const std::string> avail_protos) {
  auto maybe_req = request_path(path);
  if (!maybe_req) {
    return std::unexpected{Error::INVALID_ARGUMENT};
  }

  for (auto &k : avail_protos) {
    if (std::ranges::contains(protos_, k)) {
      negotiated_proto_ = k;
      break;
    }
  }

  const auto &req = *maybe_req;

  auto relpath = std::filesystem::path{req.path}.relative_path();
  // Some implementations (chrome only?) send filename as a part of
  // endpoint.  Strip the filename part.
  if (relpath.has_parent_path()) {
    relpath = relpath.parent_path();
  }

  endpoint_ = relpath.native();

  if (auto rv = setup_root_dirs(); !rv) {
    return rv;
  }

  auto nva = std::to_array<nghttp3_nv>({
    util::make_nv_nn(":status"sv, "200"sv),
    util::make_nv_nn("server"sv, "ngtcp2/nghttp3 interop server"sv),
    {},
  });

  auto nvlen = 2UZ;

  std::string encoded_proto;

  // negotiated_proto_ can be empty because some implementations
  // (chrome only?) do not send wt-available-protocols header field in
  // test cases other than HANDSHAKE.
  if (!negotiated_proto_.empty()) {
    encoded_proto = util::encode_sfstring(negotiated_proto_);

    nva[nvlen++] = util::make_nv_nc("wt-protocol"sv, encoded_proto);
  }

  if (!config.quiet) {
    debug::print_http_response_headers(session_id_, nva.data(), nvlen);
  }

  if (auto rv = nghttp3_conn_submit_wt_response(httpconn_, session_id_,
                                                nva.data(), nvlen);
      rv != 0) {
    std::println(stderr, "nghttp3_conn_submit_wt_response: {}",
                 nghttp3_strerror(rv));
    return std::unexpected{Error::HTTP3};
  }

  return on_session_started();
}

std::expected<void, Error> App::setup_root_dirs() {
  auto www_root = (config.www_root / endpoint_).lexically_normal();
  if (!check_safe_path(www_root, config.www_root)) {
    std::println(stderr, "The path {} is unsafe", www_root.native());

    return std::unexpected{Error::INVALID_ARGUMENT};
  }

  www_root_ = www_root;

  auto download_root = (config.download_root / endpoint_).lexically_normal();
  if (!check_safe_path(download_root, config.download_root)) {
    std::println(stderr, "The path {} is unsafe", download_root.native());

    return std::unexpected{Error::INVALID_ARGUMENT};
  }

  download_root_ = download_root;

  return {};
}

std::expected<void, Error> App::write_proto(std::string_view proto) {
  auto path = config.download_root / "negotiated_protocol.txt"sv;

  std::println(stderr, "Writing negotiated protocol {} to {}", proto,
               path.native());

  auto f = fopen(path.c_str(), "w");
  if (!f) {
    std::println(stderr, "Could not open file {}: {}", path.native(),
                 strerror(errno));

    return std::unexpected{Error::IO};
  }

  auto nwrite = fwrite(proto.data(), 1, proto.size(), f);
  if (nwrite < proto.size()) {
    std::println(stderr, "Could not write protocol {}, only written {} bytes",
                 proto, nwrite);

    return std::unexpected{Error::IO};
  }

  if (fclose(f) != 0) {
    std::println(stderr, "Could not close file {}: {}", path.native(),
                 strerror(errno));

    return std::unexpected{Error::IO};
  }

  return {};
}

std::expected<void, Error> App::transfer_bidi_on_session_open(
  std::span<const std::filesystem::path> paths) {
  for (auto &path : paths) {
    if (auto rv = open_bidi_stream_and_send_request(path); !rv) {
      if (rv.error() != Error::STREAM_ID_BLOCKED) {
        return rv;
      }

      pending_bidi_streams_.emplace_back(PendingAction{
        .action = Action::SEND_REQUEST,
        .path = path,
      });
    }
  }

  return {};
}

std::expected<void, Error> App::transfer_uni_on_session_open(
  std::span<const std::filesystem::path> paths) {
  for (auto &path : paths) {
    if (auto rv = open_uni_stream_and_send_request(path); !rv) {
      if (rv.error() != Error::STREAM_ID_BLOCKED) {
        return rv;
      }

      pending_uni_streams_.emplace_back(PendingAction{
        .action = Action::SEND_REQUEST,
        .path = path,
      });
    }
  }

  return {};
}

void App::transfer_datagram_on_session_open(
  std::span<const std::filesystem::path> paths) {
  for (auto &path : paths) {
    datagram_send_request(path);
  }
}

std::expected<void, Error> App::on_data(int64_t stream_id,
                                        std::span<const uint8_t> data) {
  auto n = std::min(data.size(), 16UZ);
  util::hexdump(stderr, data.first(n));
  switch (config.testcase) {
  case Testcase::TRANSFER:
    return transfer_on_data(stream_id, data);
  case Testcase::TRANSFER_BIDIRECTIONAL_SEND:
    return transfer_bidi_on_data(stream_id, data);
  case Testcase::TRANSFER_UNIDIRECTIONAL_SEND:
    return transfer_uni_on_data(stream_id, data);
  default:
    break;
  };

  return {};
}

std::expected<void, Error>
App::transfer_on_data(int64_t stream_id, std::span<const uint8_t> data) {
  Stream *stream;

  auto it = streams_.find(stream_id);
  if (it == std::ranges::end(streams_)) {
    auto s = std::make_unique<Stream>(stream_id);
    stream = s.get();
    if (auto [_, rv] = streams_.try_emplace(stream_id, std::move(s)); !rv) {
      assert(0);
    }
  } else {
    stream = (*it).second.get();
  }

  if (stream->input.size() + data.size() > MAX_STREAM_INPUT) {
    std::println(
      stderr, "Could not find filename for stream {:#x}: buffer limit exceeded",
      stream_id);

    return std::unexpected{Error::INTERNAL};
  }

  std::ranges::copy(data, std::back_inserter(stream->input));

  return {};
}

std::expected<void, Error>
App::transfer_bidi_on_data(int64_t stream_id, std::span<const uint8_t> data) {
  auto it = streams_.find(stream_id);
  if (it == std::ranges::end(streams_)) {
    return {};
  }

  const auto &stream = (*it).second;

  return stream->write_file(data);
}

// For some reason (or simply a bug?), interop runner requires that we
// have to collapse directory structure when writing files.
std::filesystem::path
App::fixup_download_path(const std::filesystem::path &path) {
  auto p = path.lexically_relative(download_root_);
  return download_root_ / p.filename();
}

std::expected<void, Error>
App::transfer_uni_on_data(int64_t stream_id, std::span<const uint8_t> data) {
  Stream *stream;

  auto it = streams_.find(stream_id);
  if (it == std::ranges::end(streams_)) {
    auto s = std::make_unique<Stream>(stream_id);
    stream = s.get();
    if (auto [_, rv] = streams_.try_emplace(stream_id, std::move(s)); !rv) {
      assert(0);
    }
  } else {
    stream = (*it).second.get();
  }

  if (stream->fd == -1) {
    constexpr auto MAX_SNIFFLEN = 1024;

    auto end = std::ranges::find(data, '\n');
    if (end == std::ranges::end(data)) {
      if (stream->input.size() + data.size() >= MAX_SNIFFLEN) {
        std::println(
          stderr,
          "Could not find filename for stream {:#x}: buffer limit exceeded",
          stream_id);

        return std::unexpected{Error::INTERNAL};
      }

      std::ranges::copy(data, std::back_inserter(stream->input));

      return {};
    }

    auto n = as_unsigned(std::ranges::distance(std::ranges::begin(data), end));

    std::span<const uint8_t> name;

    if (stream->input.empty()) {
      name = data.first(n);
    } else {
      std::ranges::copy(data.first(n), std::back_inserter(stream->input));
      name = stream->input;
    }

    data = data.subspan(n + 1);

    auto maybe_path = extract_filename_for_writing("PUSH"sv, name);
    if (!maybe_path) {
      return std::unexpected{maybe_path.error()};
    }

    stream->path = fixup_download_path(*maybe_path);
    stream->req_path = maybe_path->lexically_relative(download_root_);

    if (auto rv = stream->open_download_file(); !rv) {
      return rv;
    }
  }

  return stream->write_file(data);
}

std::expected<void, Error> App::on_end_stream(int64_t stream_id) {
  auto it = streams_.find(stream_id);
  if (it == std::ranges::end(streams_)) {
    return {};
  }

  const auto &stream = (*it).second;

  switch (config.testcase) {
  case Testcase::TRANSFER:
    return transfer_on_end_stream(stream.get());
  default:
    break;
  };

  return {};
}

std::expected<void, Error> App::on_datagram(std::span<const uint8_t> data) {
  auto n = std::min(data.size(), 16UZ);
  util::hexdump(stderr, data.first(n));

  if (data.empty()) {
    std::println(stderr, "DATAGRAM is empty");

    return std::unexpected{Error::INVALID_ARGUMENT};
  }

  switch (config.testcase) {
  case Testcase::TRANSFER:
    return transfer_on_datagram(data);
  case Testcase::TRANSFER_DATAGRAM_SEND:
    return transfer_datagram_on_datagram(data);
  default:
    break;
  };

  return {};
}

struct FileRequest {
  std::string_view method;
  std::string_view filename;
};

namespace {
std::expected<FileRequest, Error> parse_request(std::span<const uint8_t> data) {
  static constexpr auto isspace = [](auto c) { return c == ' ' || c == '\t'; };

  auto start = std::ranges::find_if(data, std::not_fn(isspace));
  data = std::span{start, std::ranges::end(data)};

  auto method_end = std::ranges::find_if(data, isspace);
  if (method_end == std::ranges::end(data)) {
    std::println(stderr, "Could not find method from {}", as_string_view(data));

    return std::unexpected{Error::INVALID_ARGUMENT};
  }

  auto filename_start = std::ranges::find_if(method_end, std::ranges::end(data),
                                             std::not_fn(isspace));
  if (filename_start == std::ranges::end(data)) {
    std::println(stderr, "Could not find filename from {}",
                 as_string_view(data));

    return std::unexpected{Error::INVALID_ARGUMENT};
  }

  auto filename_end =
    std::ranges::find_if(std::views::reverse(data), std::not_fn(isspace))
      .base();

  return FileRequest{
    .method = as_string_view(std::span{start, method_end}),
    .filename = as_string_view(std::span{filename_start, filename_end}),
  };
}
} // namespace

std::expected<std::filesystem::path, Error>
App::extract_filename(const std::filesystem::path &root,
                      std::string_view expected_method,
                      std::span<const uint8_t> data) {
  auto maybe_freq = parse_request(data);
  if (!maybe_freq) {
    return std::unexpected{maybe_freq.error()};
  }

  const auto &freq = *maybe_freq;
  if (freq.method != expected_method) {
    std::println(stderr, "Unexpected method {}, want {}", freq.method,
                 expected_method);

    return std::unexpected{Error::INVALID_ARGUMENT};
  }

  auto path = (root / freq.filename).lexically_normal();
  if (!check_safe_path(path, root)) {
    std::println(stderr, "The path {} is unsafe", path.native());

    return std::unexpected{Error::INVALID_ARGUMENT};
  }

  std::println(stderr, "method={} filename={} path={}", freq.method,
               freq.filename, path.native());

  return path;
}

std::expected<std::filesystem::path, Error>
App::extract_filename_for_reading(std::string_view expected_method,
                                  std::span<const uint8_t> data) {
  return extract_filename(www_root_, expected_method, data);
}

std::expected<std::filesystem::path, Error>
App::extract_filename_for_writing(std::string_view expected_method,
                                  std::span<const uint8_t> data) {
  return extract_filename(download_root_, expected_method, data);
}

std::expected<void, Error> App::transfer_on_end_stream(Stream *stream) {
  auto maybe_path = extract_filename_for_reading("GET"sv, stream->input);
  if (!maybe_path) {
    return std::unexpected{maybe_path.error()};
  }

  const auto &path = *maybe_path;

  stream->path = path;
  stream->req_path = path.lexically_relative(www_root_);

  if (!(stream->stream_id & 0x2)) {
    return send_file(stream);
  }

  if (auto rv = open_uni_stream_and_send_file(stream->path); !rv) {
    if (rv.error() != Error::STREAM_ID_BLOCKED) {
      return rv;
    }

    pending_uni_streams_.emplace_back(PendingAction{
      .action = Action::SEND_FILE,
      .path = path,
    });
  }

  return {};
}

std::expected<void, Error>
App::transfer_on_datagram(std::span<const uint8_t> data) {
  auto maybe_path = extract_filename_for_reading("GET"sv, data);
  if (!maybe_path) {
    return std::unexpected{maybe_path.error()};
  }

  return send_file_datagram(*maybe_path);
}

std::expected<void, Error>
App::transfer_datagram_on_datagram(std::span<const uint8_t> data) {
  if (datagrams_inflight_ > 0) {
    --datagrams_inflight_;
  }

  auto stream = Stream{0};

  auto end = std::ranges::find(data, '\n');
  if (end == std::ranges::end(data)) {
    std::println(stderr, "Could not find request delimiter in DATAGRAM");

    return std::unexpected{Error::INVALID_ARGUMENT};
  }

  auto maybe_path =
    extract_filename_for_writing("PUSH"sv, {std::ranges::begin(data), end});
  if (!maybe_path) {
    return std::unexpected{maybe_path.error()};
  }

  stream.path = fixup_download_path(*maybe_path);
  stream.req_path = maybe_path->lexically_relative(download_root_);

  if (auto rv = stream.open_download_file(); !rv) {
    return rv;
  }

  if (downloads_left_) {
    --downloads_left_;
  }

  return stream.write_file({end + 1, std::ranges::end(data)});
}

namespace {
nghttp3_ssize file_read_data(nghttp3_conn *conn, int64_t stream_id,
                             nghttp3_vec *vec, size_t veccnt, uint32_t *pflags,
                             void *user_data, void *stream_user_data) {
  auto stream = static_cast<Stream *>(stream_user_data);

  auto rv = stream->map_file();
  if (!rv) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }

  size_t vidx = 0;

  if (stream_id & 0x2) {
    vec[vidx++] = (nghttp3_vec){
      .base = const_cast<uint8_t *>(
        reinterpret_cast<const uint8_t *>(PUSH_PREFIX.data())),
      .len = PUSH_PREFIX.size(),
    };

    vec[vidx++] = (nghttp3_vec){
      .base = const_cast<uint8_t *>(
        reinterpret_cast<const uint8_t *>(stream->req_path.c_str())),
      .len = stream->req_path.native().size(),
    };

    vec[vidx++] = (nghttp3_vec){
      .base = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>("\n")),
      .len = 1,
    };
  }

  if (stream->map_len) {
    vec[vidx++] = (nghttp3_vec){
      .base = reinterpret_cast<uint8_t *>(stream->map_addr),
      .len = stream->map_len,
    };
  }

  *pflags = NGHTTP3_DATA_FLAG_EOF;

  return static_cast<nghttp3_ssize>(vidx);
}
} // namespace

std::expected<void, Error> App::send_file(Stream *stream) {
  std::println(stderr, "sending file for {}", stream->req_path.native());

  auto dr = nghttp3_data_reader{
    .read_data = file_read_data,
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

std::expected<void, Error>
App::open_uni_stream_and_send_file(const std::filesystem::path &path) {
  int64_t stream_id;

  if (auto rv = ngtcp2_conn_open_uni_stream(conn_, &stream_id, nullptr);
      rv != 0) {
    if (rv == NGTCP2_ERR_STREAM_ID_BLOCKED) {
      return std::unexpected{Error::STREAM_ID_BLOCKED};
    }

    std::println(stderr, "ngtcp2_conn_open_uni_stream: {}",
                 ngtcp2_strerror(rv));

    return std::unexpected{Error::QUIC};
  }

  auto s = std::make_unique<Stream>(stream_id);
  s->path = path;
  s->req_path = path.lexically_relative(www_root_);

  auto stream = s.get();
  if (auto [_, rv] = streams_.try_emplace(stream_id, std::move(s)); !rv) {
    assert(0);
  }

  return send_file(stream);
}

std::expected<void, Error>
App::send_file_datagram(const std::filesystem::path &path) {
  auto s = Stream{0};
  s.path = path;

  if (auto rv = s.map_file(); !rv) {
    return rv;
  }

  auto req_path = path.lexically_relative(www_root_);

  std::println(stderr, "sending file for {} in datagram", req_path.native());

  std::vector<uint8_t> data;
  std::ranges::copy(PUSH_PREFIX, std::back_inserter(data));
  std::ranges::copy(req_path.native(), std::back_inserter(data));
  data.emplace_back('\n');
  std::ranges::copy_n(static_cast<const uint8_t *>(s.map_addr),
                      as_signed(s.map_len), std::back_inserter(data));

  pending_datagrams_.emplace_back(Datagram{
    .session_id = session_id_,
    .data = std::move(data),
  });

  return {};
}

std::expected<void, Error>
App::open_bidi_stream_and_send_request(const std::filesystem::path &path) {
  int64_t stream_id;

  if (auto rv = ngtcp2_conn_open_bidi_stream(conn_, &stream_id, nullptr);
      rv != 0) {
    if (rv == NGTCP2_ERR_STREAM_ID_BLOCKED) {
      return std::unexpected{Error::STREAM_ID_BLOCKED};
    }
    std::println(stderr, "ngtcp2_conn_open_bidi_stream: {}",
                 ngtcp2_strerror(rv));

    return std::unexpected{Error::QUIC};
  }

  auto s = std::make_unique<Stream>(stream_id);
  s->path = fixup_download_path(path);
  s->req_path = path.lexically_relative(download_root_);

  auto stream = s.get();
  if (auto [_, rv] = streams_.try_emplace(stream_id, std::move(s)); !rv) {
    assert(0);
  }

  if (auto rv = send_request(stream); !rv) {
    return rv;
  }

  return stream->open_download_file();
}

std::expected<void, Error>
App::open_uni_stream_and_send_request(const std::filesystem::path &path) {
  int64_t stream_id;

  if (auto rv = ngtcp2_conn_open_uni_stream(conn_, &stream_id, nullptr);
      rv != 0) {
    if (rv == NGTCP2_ERR_STREAM_ID_BLOCKED) {
      return std::unexpected{Error::STREAM_ID_BLOCKED};
    }
    std::println(stderr, "ngtcp2_conn_open_uni_stream: {}",
                 ngtcp2_strerror(rv));

    return std::unexpected{Error::QUIC};
  }

  auto s = std::make_unique<Stream>(stream_id);
  s->path = path;
  s->req_path = path.lexically_relative(download_root_);

  auto stream = s.get();
  if (auto [_, rv] = streams_.try_emplace(stream_id, std::move(s)); !rv) {
    assert(0);
  }

  return send_request(stream);
}

void App::datagram_send_request(const std::filesystem::path &path) {
  std::vector<uint8_t> data;
  std::ranges::copy(GET_PREFIX, std::back_inserter(data));

  auto req_path = path.lexically_relative(download_root_);

  std::println(stderr, "request for {} in datagram", req_path.native());

  std::ranges::copy(req_path.native(), std::back_inserter(data));

  pending_datagrams_.emplace_back(Datagram{
    .session_id = session_id_,
    .data = std::move(data),
  });
}

namespace {
nghttp3_ssize request_read_data(nghttp3_conn *conn, int64_t stream_id,
                                nghttp3_vec *vec, size_t veccnt,
                                uint32_t *pflags, void *user_data,
                                void *stream_user_data) {
  auto stream = static_cast<Stream *>(stream_user_data);

  vec[0] = (nghttp3_vec){
    .base = const_cast<uint8_t *>(
      reinterpret_cast<const uint8_t *>(GET_PREFIX.data())),
    .len = GET_PREFIX.size(),
  };

  vec[1] = (nghttp3_vec){
    .base = const_cast<uint8_t *>(
      reinterpret_cast<const uint8_t *>(stream->req_path.c_str())),
    .len = stream->req_path.native().size(),
  };

  *pflags = NGHTTP3_DATA_FLAG_EOF;

  return 2Z;
}
} // namespace

std::expected<void, Error> App::send_request(Stream *stream) {
  auto dr = nghttp3_data_reader{
    .read_data = request_read_data,
  };

  if (auto rv = nghttp3_conn_open_wt_data_stream(
        httpconn_, session_id_, stream->stream_id, &dr, stream);
      rv != 0) {
    std::println(stderr, "nghttp3_conn_open_wt_data_stream: {}",
                 nghttp3_strerror(rv));

    return std::unexpected{Error::HTTP3};
  }

  std::println(stderr, "request for {}", stream->req_path.native());

  return {};
}

std::vector<Datagram> App::pull_datagram() {
  if (config.testcase != Testcase::TRANSFER_DATAGRAM_SEND) {
    auto q = pending_datagrams_ | std::views::as_rvalue |
             std::ranges::to<std::vector<Datagram>>();
    pending_datagrams_.clear();

    return q;
  }

  // Rate limit in-flight DATAGRAM frames in transfer testcase
  // otherwise some implementations drop them for some reason.
  constexpr auto MAX_DATAGRAM_INFLIGHT = 1UZ;

  if (datagrams_inflight_ >= MAX_DATAGRAM_INFLIGHT) {
    return {};
  }

  auto n = std::min(pending_datagrams_.size(),
                    MAX_DATAGRAM_INFLIGHT - datagrams_inflight_);
  if (n == 0) {
    return {};
  }

  auto q = pending_datagrams_ | std::views::take(as_signed(n)) |
           std::views::as_rvalue | std::ranges::to<std::vector<Datagram>>();

  pending_datagrams_.erase(std::ranges::begin(pending_datagrams_),
                           std::ranges::begin(pending_datagrams_) +
                             as_signed(n));

  datagrams_inflight_ += n;

  return q;
}

std::expected<void, Error> App::handle_pending_bidi_stream() {
  for (; !pending_bidi_streams_.empty();) {
    const auto &act = pending_bidi_streams_[0];

    switch (act.action) {
    case Action::SEND_REQUEST:
      if (auto rv = open_bidi_stream_and_send_request(act.path); !rv) {
        if (rv.error() == Error::STREAM_ID_BLOCKED) {
          return {};
        }

        return rv;
      }

      break;
    default:
      break;
    }

    pending_bidi_streams_.pop_front();
  }

  return {};
}

std::expected<void, Error> App::handle_pending_uni_stream() {
  for (; !pending_uni_streams_.empty();) {
    const auto &act = pending_uni_streams_[0];

    switch (act.action) {
    case Action::SEND_FILE:
      if (auto rv = open_uni_stream_and_send_file(act.path); !rv) {
        if (rv.error() == Error::STREAM_ID_BLOCKED) {
          return {};
        }

        return rv;
      }

      break;
    case Action::SEND_REQUEST:
      if (auto rv = open_uni_stream_and_send_request(act.path); !rv) {
        if (rv.error() == Error::STREAM_ID_BLOCKED) {
          return {};
        }

        return rv;
      }

      break;
    }

    pending_uni_streams_.pop_front();
  }

  return {};
}

void App::on_stream_close(int64_t stream_id, uint64_t app_error_code) {
  auto it = streams_.find(stream_id);
  if (it == std::ranges::end(streams_)) {
    return;
  }

  if (!config.quiet) {
    std::println(stderr,
                 "WebTransport stream {:#x} closed with error code {:#x}",
                 stream_id, app_error_code);
  }

  const auto &stream = (*it).second;

  if (stream->download && downloads_left_) {
    --downloads_left_;
  }

  streams_.erase(stream_id);
}

bool App::finished() const {
  switch (config.testcase) {
  case Testcase::HANDSHAKE:
  case Testcase::TRANSFER:
    return false;
  default:
    return downloads_left_ == 0;
  }
}

void App::on_proto_negotiated(std::string_view proto) {
  negotiated_proto_ = proto;
}

const std::vector<std::string> &App::get_endpoint_paths() const {
  static std::vector<std::string> empty;

  switch (side_) {
  case Side::CLIENT:
    if (config.client_request.session_requests.empty()) {
      return empty;
    }

    return config.client_request.session_requests[0].requests;
  case Side::SERVER: {
    auto it = config.server_requests.find(endpoint_);
    if (it == std::ranges::end(config.server_requests)) {
      return empty;
    }

    return (*it).second;
  }
  }

  std::unreachable();
}

std::expected<void, Error> App::on_session_started() {
  if (config.testcase == Testcase::HANDSHAKE) {
    std::println(stderr, "testcase handshake");
    return write_proto(negotiated_proto_);
  }

  auto maybe_paths = make_filenames_absolute(get_endpoint_paths());
  if (!maybe_paths) {
    return std::unexpected{maybe_paths.error()};
  }

  const auto &paths = *maybe_paths;

  downloads_left_ = paths.size();

  switch (config.testcase) {
  case Testcase::TRANSFER_BIDIRECTIONAL_SEND:
    std::println(stderr, "testcase transfer-bidirectional-send");
    return transfer_bidi_on_session_open(paths);
  case Testcase::TRANSFER_UNIDIRECTIONAL_SEND:
    std::println(stderr, "testcase transfer-unidirectional-send");
    return transfer_uni_on_session_open(paths);
  case Testcase::TRANSFER_DATAGRAM_SEND:
    std::println(stderr, "testcase transfer-datagram-send");
    transfer_datagram_on_session_open(paths);
    return {};
  default:
    std::println(stderr, "testcase, probably transfer");
    break;
  }

  return {};
}

Stream::~Stream() {
  if (map_addr) {
    munmap(map_addr, map_len);
  }

  if (fd != -1) {
    close(fd);
  }
}

std::expected<void, Error> Stream::map_file() {
  fd = open(path.c_str(), O_RDONLY);
  if (fd == -1) {
    std::println(stderr, "Could not open file {}: {}", path.native(),
                 strerror(errno));

    return std::unexpected{Error::IO};
  }

  struct stat st;
  if (fstat(fd, &st) != 0) {
    std::println(stderr, "Could not stat file {}: {}", path.native(),
                 strerror(errno));

    return std::unexpected{Error::IO};
  }

  if (st.st_size) {
    auto len = static_cast<size_t>(st.st_size);
    auto addr = mmap(nullptr, len, PROT_READ, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
      std::println(stderr, "Could not map file {}: {}", path.native(),
                   strerror(errno));

      return std::unexpected{Error::IO};
    }

    map_len = len;
    map_addr = addr;
  }

  return {};
}

std::expected<void, Error> Stream::open_download_file() {
  std::error_code ec;

  std::filesystem::create_directories(path.parent_path(), ec);
  if (ec) {
    std::println(stderr, "Could not make directories {}: {}",
                 path.parent_path().native(), ec.message());

    return std::unexpected{Error::IO};
  }

  fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC,
            S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  if (fd == -1) {
    std::println(stderr, "Could not open file {}: {}", path.native(),
                 strerror(errno));

    return std::unexpected{Error::IO};
  }

  std::println(stderr, "fd {} was opened for file {}", fd, path.native());

  download = true;

  return {};
}

std::expected<void, Error> Stream::write_file(std::span<const uint8_t> data) {
  assert(fd != -1);

  ssize_t nwrite;

  for (; !data.empty();) {
    while ((nwrite = write(fd, data.data(), data.size())) == -1 &&
           errno == EINTR)
      ;
    if (nwrite == -1) {
      std::println(stderr, "Could not write data to file {}: {}", path.native(),
                   strerror(errno));

      return std::unexpected{Error::IO};
    }

    data = data.subspan(as_unsigned(nwrite));
  }

  return {};
}

std::expected<std::unordered_map<std::string, std::vector<std::string>>, Error>
parse_server_requests(std::string_view data) {
  std::unordered_map<std::string, std::vector<std::string>> reqs;

  for (auto v : std::ranges::views::split(data, ' ')) {
    if (v.empty()) {
      continue;
    }

    auto ep_end = std::ranges::find(v, '/');
    if (ep_end == std::ranges::end(v)) {
      std::println(stderr, "Could not find '/' in {}", as_string_view(v));

      return std::unexpected{Error::INVALID_ARGUMENT};
    }

    auto endpoint = as_string_view(std::span{std::ranges::begin(v), ep_end});
    if (endpoint.empty()) {
      std::println(stderr, "Endpoint must not be empty");

      return std::unexpected{Error::INVALID_ARGUMENT};
    }

    auto path = as_string_view(std::span{ep_end + 1, std::ranges::end(v)});
    if (path.empty()) {
      std::println(stderr, "Path must not be empty");

      return std::unexpected{Error::INVALID_ARGUMENT};
    }

    reqs[std::string{endpoint}].emplace_back(path);
  }

  return reqs;
}

std::expected<ClientRequest, Error>
parse_client_requests(std::string_view data) {
  ClientRequest creq;

  for (auto v : std::ranges::views::split(data, ' ')) {
    if (v.empty()) {
      continue;
    }

    auto s = as_string_view(v);

    urlparse_url u;

    if (urlparse_parse_url(s.data(), s.size(), /* is _connect = */ 0, &u) !=
        0) {
      std::println(stderr, "Could parse {} as URL", s);

      return std::unexpected{Error::INVALID_ARGUMENT};
    }

    if (!(u.field_set & (1 << URLPARSE_SCHEMA)) ||
        !(u.field_set & (1 << URLPARSE_HOST)) ||
        !(u.field_set & (1 << URLPARSE_PATH))) {
      std::println(stderr, "Could not find schema, host, and path in {}", s);

      return std::unexpected{Error::INVALID_ARGUMENT};
    }

    if (creq.scheme.empty()) {
      creq.scheme = util::get_string(s, u, URLPARSE_SCHEMA);
      creq.host = util::get_string(s, u, URLPARSE_HOST);
      if (u.field_set & (1 << URLPARSE_PORT)) {
        creq.port = util::get_string(s, u, URLPARSE_PORT);
      }
    }

    auto ep_path = util::get_string(s, u, URLPARSE_PATH);
    assert(ep_path[0] == '/');
    ep_path.remove_prefix(1);

    auto ep_end = std::ranges::find(ep_path, '/');
    auto endpoint =
      as_string_view(std::span{std::ranges::begin(ep_path), ep_end});
    if (endpoint.empty()) {
      std::println(stderr, "Endpoint must not be empty");

      return std::unexpected{Error::INVALID_ARGUMENT};
    }

    std::string_view path;

    if (ep_end != std::ranges::end(ep_path)) {
      path = as_string_view(std::span{ep_end + 1, std::ranges::end(ep_path)});
    }

    auto it =
      std::ranges::find_if(creq.session_requests, [endpoint](const auto &sr) {
        return sr.endpoint == endpoint;
      });
    if (it == std::ranges::end(creq.session_requests)) {
      auto sreq = SessionRequest{
        .endpoint = std::string{endpoint},
      };

      if (!path.empty()) {
        sreq.requests.emplace_back(path);
      }

      creq.session_requests.emplace_back(std::move(sreq));
    } else if (!path.empty()) {
      auto &sreq = *it;
      sreq.requests.emplace_back(path);
    }
  }

  return creq;
}

} // namespace interop
} // namespace webtransport
} // namespace ngtcp2
