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
#include <deque>
#include <map>
#include <string>

#include <ngtcp2/ngtcp2.h>

#include <openssl/ssl.h>
#include <ev.h>
#include <http-parser/http_parser.h>

#include "network.h"
#include "crypto.h"
#include "template.h"

using namespace ngtcp2;

struct Config {
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

enum {
  RESP_IDLE,
  RESP_STARTED,
  RESP_COMPLETED,
};

struct Stream {
  Stream(uint64_t stream_id);
  ~Stream();

  int recv_data(uint8_t fin, const uint8_t *data, size_t datalen);
  int start_response();
  int open_file(const std::string &path);
  int map_file(size_t len);
  void buffer_file();
  void send_status_response(unsigned int status_code,
                            const std::string &extra_headers = "");
  void send_redirect_response(unsigned int status_code,
                              const std::string &path);

  uint64_t stream_id;
  std::deque<Buffer> streambuf;
  // streambuf_idx is the index in streambuf, which points to the
  // buffer to send next.
  size_t streambuf_idx;
  // tx_stream_offset is the offset where all data before offset is
  // acked by the remote endpoint.
  uint64_t tx_stream_offset;
  // should_send_fin tells that fin should be sent after currently
  // buffered data is sent.  After sending fin, it is set to false.
  bool should_send_fin;
  // resp_state is the state of response.
  int resp_state;
  http_parser htp;
  unsigned int http_major;
  unsigned int http_minor;
  // uri is request uri/path.
  std::string uri;
  // hdrs contains request HTTP header fields.
  std::vector<std::pair<std::string, std::string>> hdrs;
  // prev_hdr_key is true if the previous modification to hdrs is
  // adding key (header field name).
  bool prev_hdr_key;
  // fd is a file descriptor to read file to send its content to a
  // client.
  int fd;
  // data is a pointer to the memory which maps file denoted by fd.
  uint8_t *data;
  // datalen is the length of mapped file by data.
  uint64_t datalen;
};

class Server;

class Handler {
public:
  Handler(struct ev_loop *loop, SSL_CTX *ssl_ctx, Server *server,
          const ngtcp2_cid *rcid);
  ~Handler();

  int init(int fd, const sockaddr *sa, socklen_t salen, const ngtcp2_cid *dcid,
           const ngtcp2_cid *ocid, uint32_t version);

  int tls_handshake();
  int read_tls();
  int on_read(uint8_t *data, size_t datalen);
  int on_write(bool retransmit = false);
  int on_write_stream(Stream &stream);
  int write_stream_data(Stream &stream, int fin, Buffer &data);
  int feed_data(uint8_t *data, size_t datalen);
  int do_handshake_read_once(const uint8_t *data, size_t datalen);
  ssize_t do_handshake_write_once();
  int do_handshake(const uint8_t *data, size_t datalen);
  void schedule_retransmit();
  void signal_write();

  int write_server_handshake(const uint8_t *data, size_t datalen);
  void write_server_handshake(std::deque<Buffer> &dest, size_t &idx,
                              const uint8_t *data, size_t datalen);
  size_t read_server_handshake(const uint8_t **pdest);

  size_t read_client_handshake(uint8_t *buf, size_t buflen);
  void write_client_handshake(const uint8_t *data, size_t datalen);

  int recv_client_initial(const ngtcp2_cid *dcid);
  ssize_t hs_encrypt_data(uint8_t *dest, size_t destlen,
                          const uint8_t *plaintext, size_t plaintextlen,
                          const uint8_t *key, size_t keylen,
                          const uint8_t *nonce, size_t noncelen,
                          const uint8_t *ad, size_t adlen);
  ssize_t hs_decrypt_data(uint8_t *dest, size_t destlen,
                          const uint8_t *ciphertext, size_t ciphertextlen,
                          const uint8_t *key, size_t keylen,
                          const uint8_t *nonce, size_t noncelen,
                          const uint8_t *ad, size_t adlen);
  ssize_t encrypt_data(uint8_t *dest, size_t destlen, const uint8_t *plaintext,
                       size_t plaintextlen, const uint8_t *key, size_t keylen,
                       const uint8_t *nonce, size_t noncelen, const uint8_t *ad,
                       size_t adlen);
  ssize_t decrypt_data(uint8_t *dest, size_t destlen, const uint8_t *ciphertext,
                       size_t ciphertextlen, const uint8_t *key, size_t keylen,
                       const uint8_t *nonce, size_t noncelen, const uint8_t *ad,
                       size_t adlen);
  ssize_t in_hp_mask(uint8_t *dest, size_t destlen, const uint8_t *key,
                     size_t keylen, const uint8_t *sample, size_t samplelen);
  ssize_t hp_mask(uint8_t *dest, size_t destlen, const uint8_t *key,
                  size_t keylen, const uint8_t *sample, size_t samplelen);
  Server *server() const;
  const Address &remote_addr() const;
  ngtcp2_conn *conn() const;
  int recv_stream_data(uint64_t stream_id, uint8_t fin, const uint8_t *data,
                       size_t datalen);
  const ngtcp2_cid *scid() const;
  const ngtcp2_cid *rcid() const;
  uint32_t version() const;
  void remove_tx_crypto_data(uint64_t offset, size_t datalen);
  int remove_tx_stream_data(uint64_t stream_id, uint64_t offset,
                            size_t datalen);
  void on_stream_close(uint64_t stream_id);
  void start_draining_period();
  int start_closing_period(int liberror);
  bool draining() const;
  int handle_error(int liberror);
  int send_conn_close();

  int send_greeting();

  int on_key(int name, const uint8_t *secret, size_t secretlen);

  void set_tls_alert(uint8_t alert);

private:
  Address remote_addr_;
  size_t max_pktlen_;
  struct ev_loop *loop_;
  SSL_CTX *ssl_ctx_;
  SSL *ssl_;
  Server *server_;
  int fd_;
  ev_timer timer_;
  ev_timer rttimer_;
  std::vector<uint8_t> chandshake_;
  size_t ncread_;
  std::deque<Buffer> shandshake_;
  // shandshake_idx_ is the index in shandshake_, which points to the
  // buffer to read next.
  size_t shandshake_idx_;
  ngtcp2_conn *conn_;
  ngtcp2_cid rcid_;
  crypto::Context hs_crypto_ctx_;
  crypto::Context crypto_ctx_;
  std::map<uint32_t, std::unique_ptr<Stream>> streams_;
  // common buffer used to store packet data before sending
  Buffer sendbuf_;
  // conn_closebuf_ contains a packet which contains CONNECTION_CLOSE.
  // This packet is repeatedly sent as a response to the incoming
  // packet in draining period.
  std::unique_ptr<Buffer> conn_closebuf_;
  // tx_crypto_offset_ is the offset where all data before offset is
  // acked by the remote endpoint.
  uint64_t tx_crypto_offset_;
  // tls_alert_ is the last TLS alert description generated by the
  // local endpoint.
  uint8_t tls_alert_;
  // initial_ is initially true, and used to process first packet from
  // client specially.  After first packet, it becomes false.
  bool initial_;
  // draining_ becomes true when draining period starts.
  bool draining_;
};

constexpr size_t TOKEN_SECRETLEN = 16;

class Server {
public:
  Server(struct ev_loop *loop, SSL_CTX *ssl_ctx);
  ~Server();

  int init(int fd);
  void disconnect();
  void disconnect(int liberr);
  void close();

  int on_write();
  int on_read();
  int send_version_negotiation(const ngtcp2_pkt_hd *hd, const sockaddr *sa,
                               socklen_t salen);
  int send_retry(const ngtcp2_pkt_hd *chd, const sockaddr *sa, socklen_t salen);
  int generate_token(uint8_t *token, size_t &tokenlen, const sockaddr *sa,
                     socklen_t salen, const ngtcp2_cid *ocid);
  int verify_token(ngtcp2_cid *ocid, const ngtcp2_pkt_hd *hd,
                   const sockaddr *sa, socklen_t salen);
  int send_packet(Address &remote_addr, Buffer &buf);
  void remove(const Handler *h);
  std::map<std::string, std::unique_ptr<Handler>>::const_iterator
  remove(std::map<std::string, std::unique_ptr<Handler>>::const_iterator it);
  void start_wev();

  int derive_token_key(uint8_t *key, size_t &keylen, uint8_t *iv, size_t &ivlen,
                       const uint8_t *rand_data, size_t rand_datalen);
  int generate_rand_data(uint8_t *buf, size_t len);

private:
  std::map<std::string, std::unique_ptr<Handler>> handlers_;
  // ctos_ is a mapping between client's initial destination
  // connection ID, and server source connection ID.
  std::map<std::string, std::string> ctos_;
  struct ev_loop *loop_;
  SSL_CTX *ssl_ctx_;
  crypto::Context token_crypto_ctx_;
  std::array<uint8_t, TOKEN_SECRETLEN> token_secret_;
  int fd_;
  ev_io wev_;
  ev_io rev_;
  ev_signal sigintev_;
};

#endif // SERVER_H
