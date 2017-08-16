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
#include <config.h>
#endif // HAVE_CONFIG_H

#include <vector>
#include <deque>
#include <map>

#include <ngtcp2/ngtcp2.h>

#include <openssl/ssl.h>
#include <ev.h>

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
};

struct Buffer {
  Buffer(const uint8_t *data, size_t datalen);
  Buffer();
  size_t left() const { return std::end(buf) - pos; }
  const uint8_t *rpos() const {
    return buf.data() + std::distance(std::begin(buf), pos);
  }

  std::vector<uint8_t> buf;
  std::vector<uint8_t>::const_iterator pos;
};

struct BIOMethod {
  BIOMethod();
  ~BIOMethod();
  BIO_METHOD *meth;
};

struct Stream {
  Stream(uint32_t stream_id);

  uint32_t stream_id;
  std::deque<Buffer> streambuf;
  // streambuf_idx is the index in streambuf, which points to the
  // buffer to send next.
  size_t streambuf_idx;
  // tx_stream_offset is the offset where all data before offset is
  // acked by the remote endpoint.
  uint64_t tx_stream_offset;
  bool should_send_fin;
};

class Server;

class Handler {
public:
  Handler(struct ev_loop *loop, SSL_CTX *ssl_ctx, Server *server);
  ~Handler();

  int init(int fd, const sockaddr *sa, socklen_t salen);
  int tls_handshake();
  int on_read(uint8_t *data, size_t datalen);
  int on_write();
  int on_write_stream(Stream &stream);
  int write_stream_data(Stream &stream, int fin, Buffer &data);
  int feed_data(uint8_t *data, size_t datalen);
  void schedule_retransmit();
  void signal_write();

  int write_server_handshake(const uint8_t *data, size_t datalen);
  size_t read_server_handshake(const uint8_t **pdest);

  size_t read_client_handshake(uint8_t *buf, size_t buflen);
  void write_client_handshake(const uint8_t *data, size_t datalen);

  int setup_crypto_context();
  ssize_t encrypt_data(uint8_t *dest, size_t destlen, const uint8_t *plaintext,
                       size_t plaintextlen, const uint8_t *key, size_t keylen,
                       const uint8_t *nonce, size_t noncelen, const uint8_t *ad,
                       size_t adlen);
  ssize_t decrypt_data(uint8_t *dest, size_t destlen, const uint8_t *ciphertext,
                       size_t ciphertextlen, const uint8_t *key, size_t keylen,
                       const uint8_t *nonce, size_t noncelen, const uint8_t *ad,
                       size_t adlen);
  Server *server() const;
  const Address &remote_addr() const;
  ngtcp2_conn *conn() const;
  int recv_stream_data(uint32_t stream_id, uint8_t fin, const uint8_t *data,
                       size_t datalen);
  uint64_t conn_id() const;
  void remove_tx_stream_data(uint32_t stream_id, uint64_t offset,
                             size_t datalen);
  void on_stream_close(uint32_t stream_id);
  void handle_error(int liberror);

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
  crypto::Context crypto_ctx_;
  std::map<uint32_t, Stream> streams_;
  uint64_t conn_id_;
  // tx_stream0_offset_ is the offset where all data before offset is
  // acked by the remote endpoint.
  uint64_t tx_stream0_offset_;
};

class Server {
public:
  Server(struct ev_loop *loop, SSL_CTX *ssl_ctx);
  ~Server();

  int init(int fd);
  int on_read();
  int send_version_negotiation(const ngtcp2_pkt_hd *hd, const sockaddr *sa,
                               socklen_t salen);
  void remove(const Handler *h);

private:
  std::map<uint64_t, std::unique_ptr<Handler>> handlers_;
  struct ev_loop *loop_;
  SSL_CTX *ssl_ctx_;
  int fd_;
  ev_io wev_;
  ev_io rev_;
};

#endif // SERVER_H
