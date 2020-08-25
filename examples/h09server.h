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
#ifndef SERVER_H
#define SERVER_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif // HAVE_CONFIG_H

#include <vector>
#include <unordered_map>
#include <string>
#include <deque>
#include <string_view>
#include <set>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <nghttp3/nghttp3.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <ev.h>

#include "network.h"
#include "shared.h"

using namespace ngtcp2;

struct Config {
  Address preferred_ipv4_addr;
  Address preferred_ipv6_addr;
  // tx_loss_prob is probability of losing outgoing packet.
  double tx_loss_prob;
  // rx_loss_prob is probability of losing incoming packet.
  double rx_loss_prob;
  // ciphers is the list of enabled ciphers.
  const char *ciphers;
  // groups is the list of supported groups.
  const char *groups;
  // htdocs is a root directory to serve documents.
  std::string htdocs;
  // mime_types_file is a path to "MIME media types and the
  // extensions" file.  Ubuntu mime-support package includes it in
  // /etc/mime/types.
  const char *mime_types_file;
  // mime_types maps file extension to MIME media type.
  std::unordered_map<std::string, std::string> mime_types;
  // port is the port number which server listens on for incoming
  // connections.
  uint16_t port;
  // quiet suppresses the output normally shown except for the error
  // messages.
  bool quiet;
  // timeout is an idle timeout for QUIC connection.
  ngtcp2_duration timeout;
  // show_secret is true if transport secrets should be printed out.
  bool show_secret;
  // validate_addr is true if server requires address validation.
  bool validate_addr;
  // early_response is true if server starts sending response when it
  // receives HTTP header fields without waiting for request body.  If
  // HTTP response data is written before receiving request body,
  // STOP_SENDING is sent.
  bool early_response;
  // verify_client is true if server verifies client with X.509
  // certificate based authentication.
  bool verify_client;
  // qlog_dir is the path to directory where qlog is stored.
  std::string_view qlog_dir;
  // no_quic_dump is true if hexdump of QUIC STREAM and CRYPTO data
  // should be disabled.
  bool no_quic_dump;
  // no_http_dump is true if hexdump of HTTP response body should be
  // disabled.
  bool no_http_dump;
  // max_data is the initial connection-level flow control window.
  uint64_t max_data;
  // max_stream_data_bidi_local is the initial stream-level flow
  // control window for a bidirectional stream that the local endpoint
  // initiates.
  uint64_t max_stream_data_bidi_local;
  // max_stream_data_bidi_remote is the initial stream-level flow
  // control window for a bidirectional stream that the remote
  // endpoint initiates.
  uint64_t max_stream_data_bidi_remote;
  // max_stream_data_uni is the initial stream-level flow control
  // window for a unidirectional stream.
  uint64_t max_stream_data_uni;
  // max_streams_bidi is the number of the concurrent bidirectional
  // streams.
  uint64_t max_streams_bidi;
  // max_streams_uni is the number of the concurrent unidirectional
  // streams.
  uint64_t max_streams_uni;
  // max_dyn_length is the maximum length of dynamically generated
  // response.
  uint64_t max_dyn_length;
  // static_secret is used to derive keying materials for Retry and
  // Stateless Retry token.
  std::array<uint8_t, 32> static_secret;
  // cc is the congestion controller algorithm.
  std::string_view cc;
  // initial_rtt is an initial RTT.
  ngtcp2_duration initial_rtt;
  // max_udp_payload_size is the maximum UDP payload size that server
  // transmits.  If it is 0, the default value is chosen.
  size_t max_udp_payload_size;
  // send_trailers controls whether server sends trailer fields or
  // not.
  bool send_trailers;
};

struct Buffer {
  Buffer(const uint8_t *data, size_t datalen);
  explicit Buffer(size_t datalen);

  size_t size() const { return tail - begin; }
  size_t left() const { return buf.data() + buf.size() - tail; }
  uint8_t *const wpos() { return tail; }
  const uint8_t *rpos() const { return begin; }
  void push(size_t len) { tail += len; }
  void reset() { tail = begin; }

  std::vector<uint8_t> buf;
  // begin points to the beginning of the buffer.  This might point to
  // buf.data() if a buffer space is allocated by this object.  It is
  // also allowed to point to the external shared buffer.
  uint8_t *begin;
  // tail points to the position of the buffer where write should
  // occur.
  uint8_t *tail;
};

struct HTTPHeader {
  HTTPHeader(const std::string_view &name, const std::string_view &value)
      : name(name), value(value) {}

  std::string_view name;
  std::string_view value;
};

class Handler;
struct FileEntry;

struct Stream {
  Stream(int64_t stream_id, Handler *handler);

  int start_response();
  std::pair<FileEntry, int> open_file(const std::string &path);
  void map_file(const FileEntry &fe);
  int send_status_response(unsigned int status_code);

  int64_t stream_id;
  Handler *handler;
  // uri is request uri/path.
  std::string uri;
  std::string status_resp_body;
  nghttp3_buf respbuf;
  http_parser htp;
  // eos gets true when one HTTP request message is seen.
  bool eos;
};

struct StreamIDLess {
  constexpr bool operator()(const Stream *lhs, const Stream *rhs) const {
    return lhs->stream_id < rhs->stream_id;
  }
};

class Server;

// Endpoint is a local endpoint.
struct Endpoint {
  Address addr;
  ev_io rev;
  Server *server;
  int fd;
  // ecn is the last ECN bits set to fd.
  unsigned int ecn;
};

struct Crypto {
  /* data is unacknowledged data. */
  std::deque<Buffer> data;
  /* acked_offset is the size of acknowledged crypto data removed from
     |data| so far */
  uint64_t acked_offset;
};

class Handler {
public:
  Handler(struct ev_loop *loop, SSL_CTX *ssl_ctx, Server *server,
          const ngtcp2_cid *rcid);
  ~Handler();

  int init(const Endpoint &ep, const sockaddr *sa, socklen_t salen,
           const ngtcp2_cid *dcid, const ngtcp2_cid *scid,
           const ngtcp2_cid *ocid, const uint8_t *token, size_t tokenlen,
           uint32_t version);

  int on_read(const Endpoint &ep, const sockaddr *sa, socklen_t salen,
              const ngtcp2_pkt_info *pi, uint8_t *data, size_t datalen);
  int on_write();
  int write_streams();
  int feed_data(const Endpoint &ep, const sockaddr *sa, socklen_t salen,
                const ngtcp2_pkt_info *pi, uint8_t *data, size_t datalen);
  void schedule_retransmit();
  int handle_expiry();
  void signal_write();
  int handshake_completed();

  void write_server_handshake(ngtcp2_crypto_level crypto_level,
                              const uint8_t *data, size_t datalen);

  int recv_crypto_data(ngtcp2_crypto_level crypto_level, const uint8_t *data,
                       size_t datalen);

  Server *server() const;
  const Address &remote_addr() const;
  ngtcp2_conn *conn() const;
  int recv_stream_data(uint32_t flags, int64_t stream_id, const uint8_t *data,
                       size_t datalen);
  int acked_stream_data_offset(int64_t stream_id, uint64_t offset,
                               uint64_t datalen);
  const ngtcp2_cid *scid() const;
  const ngtcp2_cid *pscid() const;
  const ngtcp2_cid *rcid() const;
  uint32_t version() const;
  void remove_tx_crypto_data(ngtcp2_crypto_level crypto_level, uint64_t offset,
                             uint64_t datalen);
  void on_stream_open(int64_t stream_id);
  int on_stream_close(int64_t stream_id, uint64_t app_error_code);
  void start_draining_period();
  int start_closing_period();
  bool draining() const;
  int handle_error();
  int send_conn_close();
  void update_endpoint(const ngtcp2_addr *addr);
  void update_remote_addr(const ngtcp2_addr *addr, const ngtcp2_pkt_info *pi);

  int on_key(ngtcp2_crypto_level level, const uint8_t *rsecret,
             const uint8_t *wsecret, size_t secretlen);

  void set_tls_alert(uint8_t alert);

  int update_key(uint8_t *rx_secret, uint8_t *tx_secret,
                 ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
                 ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
                 const uint8_t *current_rx_secret,
                 const uint8_t *current_tx_secret, size_t secretlen);

  Stream *find_stream(int64_t stream_id);
  int extend_max_stream_data(int64_t stream_id, uint64_t max_data);
  void shutdown_read(int64_t stream_id, int app_error_code);

  void reset_idle_timer();

  void write_qlog(const void *data, size_t datalen);
  void singal_write();
  void add_sendq(Stream *stream);

private:
  Endpoint *endpoint_;
  Address remote_addr_;
  unsigned int ecn_;
  size_t max_pktlen_;
  struct ev_loop *loop_;
  SSL_CTX *ssl_ctx_;
  SSL *ssl_;
  Server *server_;
  ev_io wev_;
  ev_timer timer_;
  ev_timer rttimer_;
  FILE *qlog_;
  Crypto crypto_[3];
  ngtcp2_conn *conn_;
  ngtcp2_cid scid_;
  ngtcp2_cid pscid_;
  ngtcp2_cid rcid_;
  std::unordered_map<int64_t, std::unique_ptr<Stream>> streams_;
  std::set<Stream *, StreamIDLess> sendq_;
  // conn_closebuf_ contains a packet which contains CONNECTION_CLOSE.
  // This packet is repeatedly sent as a response to the incoming
  // packet in draining period.
  std::unique_ptr<Buffer> conn_closebuf_;
  QUICError last_error_;
  // nkey_update_ is the number of key update occurred.
  size_t nkey_update_;
  // draining_ becomes true when draining period starts.
  bool draining_;
};

class Server {
public:
  Server(struct ev_loop *loop, SSL_CTX *ssl_ctx);
  ~Server();

  int init(const char *addr, const char *port);
  void disconnect();
  void close();

  int on_read(Endpoint &ep);
  int send_version_negotiation(uint32_t version, const uint8_t *dcid,
                               size_t dcidlen, const uint8_t *scid,
                               size_t scidlen, Endpoint &ep, const sockaddr *sa,
                               socklen_t salen);
  int send_retry(const ngtcp2_pkt_hd *chd, Endpoint &ep, const sockaddr *sa,
                 socklen_t salen);
  int send_stateless_connection_close(const ngtcp2_pkt_hd *chd, Endpoint &ep,
                                      const sockaddr *sa, socklen_t salen);
  int generate_retry_token(uint8_t *token, size_t &tokenlen, const sockaddr *sa,
                           socklen_t salen, const ngtcp2_cid *scid,
                           const ngtcp2_cid *ocid);
  int verify_retry_token(ngtcp2_cid *ocid, const ngtcp2_pkt_hd *hd,
                         const sockaddr *sa, socklen_t salen);
  int generate_token(uint8_t *token, size_t &tokenlen, const sockaddr *sa);
  int verify_token(const ngtcp2_pkt_hd *hd, const sockaddr *sa,
                   socklen_t salen);
  int send_packet(Endpoint &ep, const Address &remote_addr, unsigned int ecn,
                  const uint8_t *data, size_t datalen, size_t gso_size);
  void remove(const Handler *h);

  int derive_token_key(uint8_t *key, size_t &keylen, uint8_t *iv, size_t &ivlen,
                       const uint8_t *rand_data, size_t rand_datalen);
  void generate_rand_data(uint8_t *buf, size_t len);
  void associate_cid(const ngtcp2_cid *cid, Handler *h);
  void dissociate_cid(const ngtcp2_cid *cid);

private:
  std::unordered_map<std::string, std::unique_ptr<Handler>> handlers_;
  // ctos_ is a mapping between client's initial destination
  // connection ID, and server source connection ID.
  std::unordered_map<std::string, std::string> ctos_;
  struct ev_loop *loop_;
  std::vector<Endpoint> endpoints_;
  SSL_CTX *ssl_ctx_;
  ngtcp2_crypto_aead token_aead_;
  ngtcp2_crypto_md token_md_;
  ev_signal sigintev_;
};

#endif // SERVER_H
