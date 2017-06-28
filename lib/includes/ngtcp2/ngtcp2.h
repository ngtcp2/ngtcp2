/*
 * ngtcp2
 *
 * Copyright (c) 2017 ngtcp2 contributors
 * Copyright (c) 2017 nghttp2 contributors
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
#ifndef NGTCP2_H
#define NGTCP2_H

/* Define WIN32 when build target is Win32 API (borrowed from
   libcurl) */
#if (defined(_WIN32) || defined(__WIN32__)) && !defined(WIN32)
#define WIN32
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#if defined(_MSC_VER) && (_MSC_VER < 1800)
/* MSVC < 2013 does not have inttypes.h because it is not C99
   compliant.  See compiler macros and version number in
   https://sourceforge.net/p/predef/wiki/Compilers/ */
#include <stdint.h>
#else /* !defined(_MSC_VER) || (_MSC_VER >= 1800) */
#include <inttypes.h>
#endif /* !defined(_MSC_VER) || (_MSC_VER >= 1800) */
#include <sys/types.h>
#include <stdarg.h>

#include <ngtcp2/version.h>

#ifdef NGTCP2_STATICLIB
#define NGTCP2_EXTERN
#elif defined(WIN32)
#ifdef BUILDING_NGTCP2
#define NGTCP2_EXTERN __declspec(dllexport)
#else /* !BUILDING_NGTCP2 */
#define NGTCP2_EXTERN __declspec(dllimport)
#endif /* !BUILDING_NGTCP2 */
#else  /* !defined(WIN32) */
#ifdef BUILDING_NGTCP2
#define NGTCP2_EXTERN __attribute__((visibility("default")))
#else /* !BUILDING_NGTCP2 */
#define NGTCP2_EXTERN
#endif /* !BUILDING_NGTCP2 */
#endif /* !defined(WIN32) */

/**
 * @functypedef
 *
 * Custom memory allocator to replace malloc().  The |mem_user_data|
 * is the mem_user_data member of :type:`ngtcp2_mem` structure.
 */
typedef void *(*ngtcp2_malloc)(size_t size, void *mem_user_data);

/**
 * @functypedef
 *
 * Custom memory allocator to replace free().  The |mem_user_data| is
 * the mem_user_data member of :type:`ngtcp2_mem` structure.
 */
typedef void (*ngtcp2_free)(void *ptr, void *mem_user_data);

/**
 * @functypedef
 *
 * Custom memory allocator to replace calloc().  The |mem_user_data|
 * is the mem_user_data member of :type:`ngtcp2_mem` structure.
 */
typedef void *(*ngtcp2_calloc)(size_t nmemb, size_t size, void *mem_user_data);

/**
 * @functypedef
 *
 * Custom memory allocator to replace realloc().  The |mem_user_data|
 * is the mem_user_data member of :type:`ngtcp2_mem` structure.
 */
typedef void *(*ngtcp2_realloc)(void *ptr, size_t size, void *mem_user_data);

/**
 * @struct
 *
 * Custom memory allocator functions and user defined pointer.  The
 * |mem_user_data| member is passed to each allocator function.  This
 * can be used, for example, to achieve per-session memory pool.
 *
 * In the following example code, ``my_malloc``, ``my_free``,
 * ``my_calloc`` and ``my_realloc`` are the replacement of the
 * standard allocators ``malloc``, ``free``, ``calloc`` and
 * ``realloc`` respectively::
 *
 *     void *my_malloc_cb(size_t size, void *mem_user_data) {
 *       return my_malloc(size);
 *     }
 *
 *     void my_free_cb(void *ptr, void *mem_user_data) { my_free(ptr); }
 *
 *     void *my_calloc_cb(size_t nmemb, size_t size, void *mem_user_data) {
 *       return my_calloc(nmemb, size);
 *     }
 *
 *     void *my_realloc_cb(void *ptr, size_t size, void *mem_user_data) {
 *       return my_realloc(ptr, size);
 *     }
 *
 *     void conn_new() {
 *       nghttp2_mem mem = {NULL, my_malloc_cb, my_free_cb, my_calloc_cb,
 *                          my_realloc_cb};
 *
 *       ...
 *     }
 */
typedef struct {
  /**
   * An arbitrary user supplied data.  This is passed to each
   * allocator function.
   */
  void *mem_user_data;
  /**
   * Custom allocator function to replace malloc().
   */
  ngtcp2_malloc malloc;
  /**
   * Custom allocator function to replace free().
   */
  ngtcp2_free free;
  /**
   * Custom allocator function to replace calloc().
   */
  ngtcp2_calloc calloc;
  /**
   * Custom allocator function to replace realloc().
   */
  ngtcp2_realloc realloc;
} ngtcp2_mem;

/* NGTCP2_PROTO_VERSION is the supported QUIC protocol version */
#define NGTCP2_PROTO_VERSION 0xff000004u

#define NGTCP2_MAX_PKTLEN_IPV4 1252
#define NGTCP2_MAX_PKTLEN_IPV6 1232

typedef enum {
  NGTCP2_ERR_INVALID_ARGUMENT = -201,
  NGTCP2_ERR_UNKNOWN_PKT_TYPE = -202,
  NGTCP2_ERR_NOBUF = -203,
  NGTCP2_ERR_BAD_PKT_HASH = -204,
  NGTCP2_ERR_PROTO = -205,
  NGTCP2_ERR_INVALID_STATE = -206,
  /* Fatal error >= 500 */
  NGTCP2_ERR_NOMEM = -501,
  NGTCP2_ERR_CALLBACK_FAILURE = -502,
  NGTCP2_ERR_INTERNAL = -503
} ngtcp2_lib_error;

typedef enum {
  NGTCP2_PKT_FLAG_NONE = 0,
  NGTCP2_PKT_FLAG_LONG_FORM = 0x01,
  NGTCP2_PKT_FLAG_CONN_ID = 0x02,
  NGTCP2_PKT_FLAG_KEY_PHASE = 0x04
} ngtcp2_pkt_flag;

typedef enum {
  NGTCP2_PKT_VERSION_NEGOTIATION = 0x01,
  NGTCP2_PKT_CLIENT_INITIAL = 0x02,
  NGTCP2_PKT_SERVER_STATELESS_RETRY = 0x03,
  NGTCP2_PKT_SERVER_CLEARTEXT = 0x04,
  NGTCP2_PKT_CLIENT_CLEARTEXT = 0x05,
  NGTCP2_PKT_0RTT_PROTECTED = 0x06,
  NGTCP2_PKT_1RTT_PROTECTED_K0 = 0x07,
  NGTCP2_PKT_1RTT_PROTECTED_K1 = 0x08,
  NGTCP2_PKT_PUBLIC_RESET = 0x09,
  NGTCP2_PKT_01 = 0x01,
  NGTCP2_PKT_02 = 0x02,
  NGTCP2_PKT_03 = 0x03,
} ngtcp2_pkt_type;

typedef enum {
  NGTCP2_FRAME_PADDING = 0x00,
  NGTCP2_FRAME_RST_STREAM = 0x01,
  NGTCP2_FRAME_CONNECTION_CLOSE = 0x02,
  NGTCP2_FRAME_GOAWAY = 0x03,
  NGTCP2_FRAME_MAX_DATA = 0x04,
  NGTCP2_FRAME_MAX_STREAM_DATA = 0x05,
  NGTCP2_FRAME_MAX_STREAM_ID = 0x06,
  NGTCP2_FRAME_PING = 0x07,
  NGTCP2_FRAME_BLOCKED = 0x08,
  NGTCP2_FRAME_STREAM_BLOCKED = 0x09,
  NGTCP2_FRAME_STREAM_ID_NEEDED = 0x0a,
  NGTCP2_FRAME_NEW_CONNECTION_ID = 0x0b,
  NGTCP2_FRAME_ACK = 0xa0,
  NGTCP2_FRAME_STREAM = 0xc0
} ngtcp2_frame_type;

typedef enum { NGTCP2_QUIC_INTERNAL_ERROR = 0x80000001u } ngtcp2_error;

/*
 * ngtcp2_tstamp is a timestamp with microsecond resolution.
 */
typedef uint64_t ngtcp2_tstamp;

typedef struct {
  uint8_t flags;
  uint8_t type;
  uint64_t conn_id;
  uint64_t pkt_num;
  uint32_t version;
} ngtcp2_pkt_hd;

typedef struct {
  uint8_t type;
  /**
   * flags of decoded STREAM frame.  This gets ignored when encoding
   * STREAM frame.
   */
  uint8_t flags;
  uint8_t fin;
  uint32_t stream_id;
  uint64_t offset;
  size_t datalen;
  const uint8_t *data;
} ngtcp2_stream;

typedef struct {
  uint64_t blklen;
  uint8_t gap;
} ngtcp2_ack_blk;

typedef struct {
  uint8_t type;
  /**
   * flags of decoded ACK frame.  This gets ignored when encoding ACK
   * frame.
   */
  uint8_t flags;
  uint64_t largest_ack;
  uint16_t ack_delay;
  uint64_t first_ack_blklen;
  size_t num_blks;
  ngtcp2_ack_blk blks[255];
  size_t num_ts;
} ngtcp2_ack;

typedef struct {
  uint8_t type;
  /**
   * The length of contiguous PADDING frames.
   */
  size_t len;
} ngtcp2_padding;

typedef struct { uint8_t type; } ngtcp2_rst_stream;

typedef struct {
  uint8_t type;
  uint32_t error_code;
  size_t reasonlen;
  uint8_t *reason;
} ngtcp2_connection_close;

typedef struct { uint8_t type; } ngtcp2_goaway;

typedef struct { uint8_t type; } ngtcp2_max_data;

typedef struct { uint8_t type; } ngtcp2_max_stream_data;

typedef struct { uint8_t type; } ngtcp2_max_stream_id;

typedef struct { uint8_t type; } ngtcp2_ping;

typedef struct { uint8_t type; } ngtcp2_blocked;

typedef struct { uint8_t type; } ngtcp2_stream_blocked;

typedef struct { uint8_t type; } ngtcp2_stream_id_needed;

typedef struct { uint8_t type; } ngtcp2_new_connection_id;

typedef union {
  uint8_t type;
  ngtcp2_stream stream;
  ngtcp2_ack ack;
  ngtcp2_padding padding;
  ngtcp2_rst_stream rst_stream;
  ngtcp2_connection_close connection_close;
  ngtcp2_goaway goaway;
  ngtcp2_max_data max_data;
  ngtcp2_max_stream_data max_stream_data;
  ngtcp2_max_stream_id max_stream_id;
  ngtcp2_ping ping;
  ngtcp2_blocked blocked;
  ngtcp2_stream_blocked stream_blocked;
  ngtcp2_stream_id_needed stream_id_needed;
  ngtcp2_new_connection_id new_connection_id;
} ngtcp2_frame;

/**
 * @function
 *
 * `ngtcp2_pkt_decode_hd` decodes QUIC packet header included in |pkt|
 * of length |pktlen|, and sotres the result in the object pointed by
 * |dest|.  This function can decode both long and short packet
 * header.  On success, if ``dest->flags & NGTCP2_PKT_FLAG_LONG_FORM``
 * is nonzero, the packet header has long form.
 *
 * This function returns the exact number of bytes to be read in order
 * to decode packet header, or one of the following negative error
 * codes:
 *
 * :enum:`NGTCP2_ERR_INVALID_ARGUMENT`
 *     Packet is too short
 * :enum:`NGTCP2_ERR_UNKNOWN_PKT_TYPE`
 *     Packet type is unknown
 */
NGTCP2_EXTERN ssize_t ngtcp2_pkt_decode_hd(ngtcp2_pkt_hd *dest,
                                           const uint8_t *pkt, size_t pktlen);

NGTCP2_EXTERN ssize_t ngtcp2_pkt_decode_frame(ngtcp2_frame *dest,
                                              const uint8_t *payload,
                                              size_t payloadlen,
                                              uint64_t max_rx_pkt_num);

/**
 * @function
 *
 * `ngtcp2_pkt_encode_frame` encodes a frame |fm| into the buffer
 * pointed by |out| of length |outlen|.
 *
 * This function returns the number of bytes written to the buffer, or
 * one of the following negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOBUF`
 *     Buffer does not have enough capacity to write a frame.
 */
NGTCP2_EXTERN ssize_t ngtcp2_pkt_encode_frame(uint8_t *out, size_t outlen,
                                              const ngtcp2_frame *fr);

/* Unprotected Packet Encoder: upe */
struct ngtcp2_upe;
typedef struct ngtcp2_upe ngtcp2_upe;

/**
 * @function
 *
 * `ngtcp2_upe_new` creates new ngtcp2_upe, and initializes it with
 * the given buffer.
 *
 * It returns 0, and stores the pointer to the created object to
 * |*pupe|, otherwise it returns one of the following negative error
 * codes:
 *
 * :enum:`NGTCP2_ERR_NOMEM`
 *     Out of memory
 */
NGTCP2_EXTERN int ngtcp2_upe_new(ngtcp2_upe **pupe, uint8_t *out,
                                 size_t outlen);

/**
 * @function
 *
 * `ngtcp2_upe_del` deletes |upe|.
 */
NGTCP2_EXTERN void ngtcp2_upe_del(ngtcp2_upe *upe);

/**
 * @function
 *
 * `ngtcp2_upe_encode_hd` encodes QUIC packet header |hd| in the
 * buffer.  |hd| is encoded as long header.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOBUF`
 *     Buffer does not have enough capacity to write a header.
 */
NGTCP2_EXTERN int ngtcp2_upe_encode_hd(ngtcp2_upe *upe,
                                       const ngtcp2_pkt_hd *hd);

/**
 * @function
 *
 * `ngtcp2_upe_encode_frame` encodes the frame |fm| in the buffer.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOBUF`
 *     Buffer does not have enough capacity to write a header.
 */
NGTCP2_EXTERN int ngtcp2_upe_encode_frame(ngtcp2_upe *upe,
                                          const ngtcp2_frame *fr);

/**
 * @function
 *
 * `ngtcp2_upe_padding` encodes PADDING frames to the end of the
 * buffer.
 */
NGTCP2_EXTERN void ngtcp2_upe_padding(ngtcp2_upe *upe);

/**
 * @function
 *
 * `ngtcp2_upe_encode_version_negotiation` encodes payload of Version
 * Negotiation packet.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOBUF`
 *     Buffer does not have enough capacity to write a payload.
 */
NGTCP2_EXTERN int ngtcp2_upe_encode_version_negotiation(ngtcp2_upe *upe,
                                                        const uint32_t *sv,
                                                        size_t nsv);

/**
 * @function
 *
 * `ngtcp2_upe_final` calculates checksum of the content in the
 * buffer, and appends it to the end of the buffer.  The pointer to
 * the packet is stored into |*pkt| if |*pkt| is not ``NULL``, and the
 * length of packet is returned.
 */
NGTCP2_EXTERN size_t ngtcp2_upe_final(ngtcp2_upe *upe, const uint8_t **ppkt);

/**
 * @function
 *
 * `ngtcp2_upe_left` returns the number of bytes left to write
 * additional frames.  It does not include the checksum bytes.
 */
NGTCP2_EXTERN size_t ngtcp2_upe_left(ngtcp2_upe *upe);

/**
 * @function
 *
 * `ngtcp2_pkt_verify` verifies the integrity of QUIC unprotected
 * packet included in |pkt| of length |pktlen|.
 *
 * This function returns 0 if it succeeds, or -1.
 */
NGTCP2_EXTERN int ngtcp2_pkt_verify(const uint8_t *pkt, size_t pktlen);

typedef enum { NGTCP2_CONN_FLAG_NONE } ngtcp2_conn_flag;

struct ngtcp2_conn;

typedef struct ngtcp2_conn ngtcp2_conn;

typedef ssize_t (*ngtcp2_send_client_initial)(ngtcp2_conn *conn, uint32_t flags,
                                              uint64_t *ppkt_num,
                                              const uint8_t **pdest,
                                              void *user_data);

typedef ssize_t (*ngtcp2_send_client_cleartext)(ngtcp2_conn *conn,
                                                uint32_t flags,
                                                const uint8_t **pdest,
                                                void *user_data);

typedef ssize_t (*ngtcp2_send_server_cleartext)(ngtcp2_conn *conn,
                                                uint32_t flags,
                                                uint64_t *ppkt_num,
                                                const uint8_t **pdest,
                                                void *user_data);

typedef int (*ngtcp2_recv_handshake_data)(ngtcp2_conn *conn,
                                          const uint8_t *data, size_t datalen,
                                          void *user_data);

typedef int (*ngtcp2_send_pkt)(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                               void *user_data);

typedef int (*ngtcp2_send_frame)(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                                 const ngtcp2_frame *fr, void *user_data);

typedef int (*ngtcp2_recv_pkt)(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                               void *user_data);

typedef int (*ngtcp2_recv_frame)(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                                 const ngtcp2_frame *fr, void *user_data);

typedef int (*ngtcp2_handshake_completed)(ngtcp2_conn *conn, void *user_data);

typedef int (*ngtcp2_recv_version_negotiation)(ngtcp2_conn *conn,
                                               const ngtcp2_pkt_hd *hd,
                                               const uint32_t *sv, size_t nsv,
                                               void *user_data);

typedef ssize_t (*ngtcp2_encrypt)(ngtcp2_conn *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *plaintext,
                                  size_t plaintextlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *nonce,
                                  size_t noncelen, const uint8_t *ad,
                                  size_t adlen, void *user_data);

typedef ssize_t (*ngtcp2_decrypt)(ngtcp2_conn *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *ciphertext,
                                  size_t ciphertextlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *nonce,
                                  size_t noncelen, const uint8_t *ad,
                                  size_t adlen, void *user_data);

typedef struct {
  ngtcp2_send_client_initial send_client_initial;
  ngtcp2_send_client_cleartext send_client_cleartext;
  ngtcp2_send_server_cleartext send_server_cleartext;
  ngtcp2_recv_handshake_data recv_handshake_data;
  ngtcp2_send_pkt send_pkt;
  ngtcp2_send_frame send_frame;
  ngtcp2_recv_pkt recv_pkt;
  ngtcp2_recv_frame recv_frame;
  ngtcp2_handshake_completed handshake_completed;
  ngtcp2_recv_version_negotiation recv_version_negotiation;
  ngtcp2_encrypt encrypt;
  ngtcp2_decrypt decrypt;
} ngtcp2_conn_callbacks;

/*
 * `ngtcp2_accept` is used by server implementation, and decides
 * whether packet |pkt| of length |pktlen| is acceptable for initial
 * packet from client.
 *
 * If it is acceptable, it returns 0.  If it is not acceptable, and
 * Version Negotiation packet is required to send, it returns 1.
 * Otherwise, it returns -1.
 *
 * If |dest| is not NULL, and the return value is 0 or 1, the decoded
 * packet header is stored to the object pointed by |dest|.
 */
NGTCP2_EXTERN int ngtcp2_accept(ngtcp2_pkt_hd *dest, const uint8_t *pkt,
                                size_t pktlen);

NGTCP2_EXTERN int ngtcp2_conn_client_new(ngtcp2_conn **pconn, uint64_t conn_id,
                                         uint32_t version,
                                         const ngtcp2_conn_callbacks *callbacks,
                                         void *user_data);

NGTCP2_EXTERN int ngtcp2_conn_server_new(ngtcp2_conn **pconn, uint64_t conn_id,
                                         uint32_t version,
                                         const ngtcp2_conn_callbacks *callbacks,
                                         void *user_data);

NGTCP2_EXTERN void ngtcp2_conn_del(ngtcp2_conn *conn);

/*
 * |pkt| is intentionally non-const so that we can decrypt packet
 * payload in-place.  We may reconsider this strategy later.
 */
NGTCP2_EXTERN int ngtcp2_conn_recv(ngtcp2_conn *conn, uint8_t *pkt,
                                   size_t pktlen, ngtcp2_tstamp ts);

NGTCP2_EXTERN ssize_t ngtcp2_conn_send(ngtcp2_conn *conn, uint8_t *dest,
                                       size_t destlen, ngtcp2_tstamp ts);

/**
 * @function
 *
 * `ngtcp2_conn_handshake_completed` tells |conn| that the QUIC
 * handshake has completed.
 */
NGTCP2_EXTERN void ngtcp2_conn_handshake_completed(ngtcp2_conn *conn);

NGTCP2_EXTERN void ngtcp2_conn_set_aead_overhead(ngtcp2_conn *conn,
                                                 size_t aead_overhead);

NGTCP2_EXTERN int ngtcp2_conn_update_tx_keys(ngtcp2_conn *conn,
                                             const uint8_t *key, size_t keylen,
                                             const uint8_t *iv, size_t ivlen);

NGTCP2_EXTERN int ngtcp2_conn_update_rx_keys(ngtcp2_conn *conn,
                                             const uint8_t *key, size_t keylen,
                                             const uint8_t *iv, size_t ivlen);

/**
 * @function
 *
 * `ngtcp2_strerror` returns the text representation of |liberr|.
 */
NGTCP2_EXTERN const char *ngtcp2_strerror(int liberr);

#ifdef __cplusplus
}
#endif

#endif /* NGTCP2_H */
