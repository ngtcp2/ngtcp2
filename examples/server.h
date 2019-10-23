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
#include <map>
#include <string>
#include <deque>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <nghttp3/nghttp3.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <ev.h>

#include "network.h"
#include "template.h"
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
  std::map<std::string, std::string> mime_types;
  // port is the port number which server listens on for incoming
  // connections.
  uint16_t port;
  // quiet suppresses the output normally shown except for the error
  // messages.
  bool quiet;
  // timeout is an idle timeout for QUIC connection.
  uint32_t timeout;
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
  std::string qlog_dir;
};

struct Buffer {
  Buffer(const uint8_t *data, size_t datalen);
  Buffer(uint8_t *begin, uint8_t *end);
  explicit Buffer(size_t datalen);
  Buffer();

  size_t size() const { return tail - head; }
  size_t left() const { return buf.data() + buf.size() - tail; }
  uint8_t *const wpos() { return tail; }
  const uint8_t *rpos() const { return head; }
  void seek(size_t len) { head += len; }
  void push(size_t len) { tail += len; }
  void reset() { head = tail = begin; }
  size_t bufsize() const { return tail - begin; }

  std::vector<uint8_t> buf;
  // begin points to the beginning of the buffer.  This might point to
  // buf.data() if a buffer space is allocated by this object.  It is
  // also allowed to point to the external shared buffer.
  uint8_t *begin;
  // head points to the position of the buffer where read should
  // occur.
  uint8_t *head;
  // tail points to the position of the buffer where write should
  // occur.
  uint8_t *tail;
};

struct HTTPHeader {
  HTTPHeader(const std::string &name, const std::string &value)
      : name(name), value(value) {}

  std::string name;
  std::string value;
};

class Handler;

struct Stream {
  Stream(int64_t stream_id, Handler *handler);
  ~Stream();

  int recv_data(uint8_t fin, const uint8_t *data, size_t datalen);
  int start_response(nghttp3_conn *conn);
  int open_file(const std::string &path);
  int map_file(size_t len);
  int send_status_response(nghttp3_conn *conn, unsigned int status_code,
                           const std::vector<HTTPHeader> &extra_headers = {});
  int send_redirect_response(nghttp3_conn *conn, unsigned int status_code,
                             const std::string &path);
  int64_t find_dyn_length(const std::string &path);
  void http_acked_stream_data(size_t datalen);

  int64_t stream_id;
  Handler *handler;
  // uri is request uri/path.
  std::string uri;
  std::string method;
  std::string authority;
  // fd is a file descriptor to read file to send its content to a
  // client.
  int fd;
  std::string status_resp_body;
  // data is a pointer to the memory which maps file denoted by fd.
  uint8_t *data;
  // datalen is the length of mapped file by data.
  uint64_t datalen;
  // dynresp is true if dynamic data response is enabled.
  bool dynresp;
  // dyndataleft is the number of dynamic data left to send.
  uint64_t dyndataleft;
  // dynackedoffset is the offset of acked data in the first element
  // of dynbufs.
  size_t dynackedoffset;
  // dynbuflen is the number of bytes buffered in dybufs.
  size_t dynbuflen;
  // dynbufs stores the buffers for dynamic data response.
  std::deque<std::unique_ptr<std::vector<uint8_t>>> dynbufs;
  // mmapped is true if data points to the memory assigned by mmap.
  bool mmapped;
};

class Server;

// Endpoint is a local endpoint.
struct Endpoint {
  Address addr;
  ev_io rev;
  Server *server;
  int fd;
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
           const ngtcp2_cid *ocid, uint32_t version);

  int on_read(const Endpoint &ep, const sockaddr *sa, socklen_t salen,
              uint8_t *data, size_t datalen);
  int on_write();
  int write_streams();
  int feed_data(const Endpoint &ep, const sockaddr *sa, socklen_t salen,
                uint8_t *data, size_t datalen);
  void schedule_retransmit();
  int handle_expiry();
  void signal_write();
  int handshake_completed();

  void write_server_handshake(ngtcp2_crypto_level crypto_level,
                              const uint8_t *data, size_t datalen);

  int recv_crypto_data(ngtcp2_crypto_level crypto_level, const uint8_t *data,
                       size_t datalen);

  int recv_client_initial(const ngtcp2_cid *dcid);
  Server *server() const;
  const Address &remote_addr() const;
  ngtcp2_conn *conn() const;
  int recv_stream_data(int64_t stream_id, uint8_t fin, const uint8_t *data,
                       size_t datalen);
  int acked_stream_data_offset(int64_t stream_id, size_t datalen);
  const ngtcp2_cid *scid() const;
  const ngtcp2_cid *pscid() const;
  const ngtcp2_cid *rcid() const;
  uint32_t version() const;
  void remove_tx_crypto_data(ngtcp2_crypto_level crypto_level, uint64_t offset,
                             size_t datalen);
  void on_stream_open(int64_t stream_id);
  int on_stream_close(int64_t stream_id, uint64_t app_error_code);
  void start_draining_period();
  int start_closing_period();
  bool draining() const;
  int handle_error();
  int send_conn_close();
  void update_endpoint(const ngtcp2_addr *addr);
  void update_remote_addr(const ngtcp2_addr *addr);

  int on_key(ngtcp2_crypto_level level, const uint8_t *rsecret,
             const uint8_t *wsecret, size_t secretlen);

  void set_tls_alert(uint8_t alert);

  int update_key();

  int setup_httpconn();
  void http_consume(int64_t stream_id, size_t nconsumed);
  void extend_max_remote_streams_bidi(uint64_t max_streams);
  Stream *find_stream(int64_t stream_id);
  void http_begin_request_headers(int64_t stream_id);
  void http_recv_request_header(int64_t stream_id, int32_t token,
                                nghttp3_rcbuf *name, nghttp3_rcbuf *value);
  int http_end_request_headers(int64_t stream_id);
  int http_end_stream(int64_t stream_id);
  int start_response(int64_t stream_id);
  int on_stream_reset(int64_t stream_id);
  int extend_max_stream_data(int64_t stream_id, uint64_t max_data);
  void shutdown_read(int64_t stream_id, int app_error_code);
  void http_acked_stream_data(int64_t stream_id, size_t datalen);
  int push_content(int64_t stream_id, const std::string &authority,
                   const std::string &path);

  void reset_idle_timer();

  void write_qlog(const void *data, size_t datalen);

private:
  Endpoint *endpoint_;
  Address remote_addr_;
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
  nghttp3_conn *httpconn_;
  std::map<int64_t, std::unique_ptr<Stream>> streams_;
  // common buffer used to store packet data before sending
  Buffer sendbuf_;
  // conn_closebuf_ contains a packet which contains CONNECTION_CLOSE.
  // This packet is repeatedly sent as a response to the incoming
  // packet in draining period.
  std::unique_ptr<Buffer> conn_closebuf_;
  std::vector<uint8_t> tx_secret_;
  std::vector<uint8_t> rx_secret_;
  QUICError last_error_;
  // nkey_update_ is the number of key update occurred.
  size_t nkey_update_;
  // draining_ becomes true when draining period starts.
  bool draining_;
};

constexpr size_t TOKEN_SECRETLEN = 16;

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
  int generate_token(uint8_t *token, size_t &tokenlen, const sockaddr *sa,
                     socklen_t salen, const ngtcp2_cid *ocid);
  int verify_token(ngtcp2_cid *ocid, const ngtcp2_pkt_hd *hd,
                   const sockaddr *sa, socklen_t salen);
  int send_packet(Endpoint &ep, const Address &remote_addr, Buffer &buf,
                  ev_io *wev = nullptr);
  void remove(const Handler *h);

  int derive_token_key(uint8_t *key, size_t &keylen, uint8_t *iv, size_t &ivlen,
                       const uint8_t *rand_data, size_t rand_datalen);
  int generate_rand_data(uint8_t *buf, size_t len);
  void associate_cid(const ngtcp2_cid *cid, Handler *h);
  void dissociate_cid(const ngtcp2_cid *cid);

private:
  std::map<std::string, std::unique_ptr<Handler>> handlers_;
  // ctos_ is a mapping between client's initial destination
  // connection ID, and server source connection ID.
  std::map<std::string, std::string> ctos_;
  struct ev_loop *loop_;
  std::vector<Endpoint> endpoints_;
  SSL_CTX *ssl_ctx_;
  ngtcp2_crypto_aead token_aead_;
  ngtcp2_crypto_md token_md_;
  std::array<uint8_t, TOKEN_SECRETLEN> token_secret_;
  ev_signal sigintev_;
};

#endif // SERVER_H
