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
 *       ngtcp2_mem mem = {NULL, my_malloc_cb, my_free_cb, my_calloc_cb,
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

/* NGTCP2_PROTO_VER_D7 is the supported QUIC protocol version
   draft-7. */
#define NGTCP2_PROTO_VER_D7 0xff000007u
/* NGTCP2_PROTO_VER_MAX is the highest QUIC version the library
   supports. */
#define NGTCP2_PROTO_VER_MAX NGTCP2_PROTO_VER_D7

/* NGTCP2_ALPN_* is a serialized form of ALPN protocol identifier this
   library supports.  Notice that the first byte is the length of the
   following protocol identifier. */
#define NGTCP2_ALPN_D7 "\x5hq-07"

#define NGTCP2_MAX_PKTLEN_IPV4 1252
#define NGTCP2_MAX_PKTLEN_IPV6 1232

/* NGTCP2_STATELESS_RESET_TOKENLEN is the length of Stateless Reset
   Token. */
#define NGTCP2_STATELESS_RESET_TOKENLEN 16

/* NGTCP2_QUIC_V1_SALT is a salt value which is used to derive
   cleartext secret. */
#define NGTCP2_QUIC_V1_SALT                                                    \
  "\xaf\xc8\x24\xec\x5f\xc7\x7e\xca\x1e\x9d\x36\xf3\x7f\xb2\xd4\x65\x18\xc3"   \
  "\x66\x39"

typedef enum {
  NGTCP2_ERR_INVALID_ARGUMENT = -201,
  NGTCP2_ERR_UNKNOWN_PKT_TYPE = -202,
  NGTCP2_ERR_NOBUF = -203,
  NGTCP2_ERR_BAD_PKT_HASH = -204,
  NGTCP2_ERR_PROTO = -205,
  NGTCP2_ERR_INVALID_STATE = -206,
  NGTCP2_ERR_ACK_FRAME = -207,
  NGTCP2_ERR_STREAM_ID_BLOCKED = -208,
  NGTCP2_ERR_STREAM_IN_USE = -209,
  NGTCP2_ERR_STREAM_DATA_BLOCKED = -210,
  NGTCP2_ERR_FLOW_CONTROL = -211,
  NGTCP2_ERR_PKT_TIMEOUT = -212,
  NGTCP2_ERR_STREAM_ID = -213,
  NGTCP2_ERR_FINAL_OFFSET = -214,
  NGTCP2_ERR_TLS_ALERT = -215,
  NGTCP2_ERR_PKT_NUM_EXHAUSTED = -216,
  NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM = -217,
  NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM = -218,
  NGTCP2_ERR_FRAME_FORMAT = -219,
  NGTCP2_ERR_TLS_DECRYPT = -220,
  NGTCP2_ERR_STREAM_SHUT_WR = -221,
  NGTCP2_ERR_STREAM_NOT_FOUND = -222,
  NGTCP2_ERR_VERSION_NEGOTIATION = -223,
  NGTCP2_ERR_FATAL = -500,
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
  NGTCP2_PKT_PUBLIC_RESET = 0x09,
  NGTCP2_PKT_01 = 0x01,
  NGTCP2_PKT_02 = 0x02,
  NGTCP2_PKT_03 = 0x03,
} ngtcp2_pkt_type;

typedef enum {
  NGTCP2_FRAME_PADDING = 0x00,
  NGTCP2_FRAME_RST_STREAM = 0x01,
  NGTCP2_FRAME_CONNECTION_CLOSE = 0x02,
  NGTCP2_FRAME_APPLICATION_CLOSE = 0x03,
  NGTCP2_FRAME_MAX_DATA = 0x04,
  NGTCP2_FRAME_MAX_STREAM_DATA = 0x05,
  NGTCP2_FRAME_MAX_STREAM_ID = 0x06,
  NGTCP2_FRAME_PING = 0x07,
  NGTCP2_FRAME_BLOCKED = 0x08,
  NGTCP2_FRAME_STREAM_BLOCKED = 0x09,
  NGTCP2_FRAME_STREAM_ID_BLOCKED = 0x0a,
  NGTCP2_FRAME_NEW_CONNECTION_ID = 0x0b,
  NGTCP2_FRAME_STOP_SENDING = 0x0c,
  NGTCP2_FRAME_ACK = 0xa0,
  NGTCP2_FRAME_STREAM = 0x10
} ngtcp2_frame_type;

typedef enum {
  NGTCP2_NO_ERROR = 0x0u,
  NGTCP2_INTERNAL_ERROR = 0x1u,
  NGTCP2_FLOW_CONTROL_ERROR = 0x3u,
  NGTCP2_STREAM_ID_ERROR = 0x4u,
  NGTCP2_STREAM_STATE_ERROR = 0x5u,
  NGTCP2_FINAL_OFFSET_ERROR = 0x6u,
  NGTCP2_FRAME_FORMAT_ERROR = 0x7u,
  NGTCP2_TRANSPORT_PARAMETER_ERROR = 0x8u,
  NGTCP2_VERSION_NEGOTIATION_ERROR = 0x9u,
  NGTCP2_PROTOCOL_VIOLATION = 0xau
} ngtcp2_transport_error;

typedef enum { NGTCP2_STOPPING = 0x0u } ngtcp2_app_error;

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
  const uint8_t *stateless_reset_token;
  const uint8_t *rand;
  size_t randlen;
} ngtcp2_pkt_stateless_reset;

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
  ngtcp2_ack_blk blks[1];
} ngtcp2_ack;

typedef struct {
  uint8_t type;
  /**
   * The length of contiguous PADDING frames.
   */
  size_t len;
} ngtcp2_padding;

typedef struct {
  uint8_t type;
  uint32_t stream_id;
  uint16_t app_error_code;
  uint64_t final_offset;
} ngtcp2_rst_stream;

typedef struct {
  uint8_t type;
  uint16_t error_code;
  size_t reasonlen;
  uint8_t *reason;
} ngtcp2_connection_close;

typedef struct {
  uint8_t type;
  uint16_t app_error_code;
  size_t reasonlen;
  uint8_t *reason;
} ngtcp2_application_close;

typedef struct {
  uint8_t type;
  /**
   * max_data is Maximum Data.
   */
  uint64_t max_data;
} ngtcp2_max_data;

typedef struct {
  uint8_t type;
  uint32_t stream_id;
  uint64_t max_stream_data;
} ngtcp2_max_stream_data;

typedef struct {
  uint8_t type;
  uint32_t max_stream_id;
} ngtcp2_max_stream_id;

typedef struct { uint8_t type; } ngtcp2_ping;

typedef struct { uint8_t type; } ngtcp2_blocked;

typedef struct {
  uint8_t type;
  uint32_t stream_id;
} ngtcp2_stream_blocked;

typedef struct { uint8_t type; } ngtcp2_stream_id_blocked;

typedef struct {
  uint8_t type;
  uint16_t seq;
  uint64_t conn_id;
  uint8_t stateless_reset_token[NGTCP2_STATELESS_RESET_TOKENLEN];
} ngtcp2_new_connection_id;

typedef struct {
  uint8_t type;
  uint32_t stream_id;
  uint16_t app_error_code;
} ngtcp2_stop_sending;

typedef union {
  uint8_t type;
  ngtcp2_stream stream;
  ngtcp2_ack ack;
  ngtcp2_padding padding;
  ngtcp2_rst_stream rst_stream;
  ngtcp2_connection_close connection_close;
  ngtcp2_application_close application_close;
  ngtcp2_max_data max_data;
  ngtcp2_max_stream_data max_stream_data;
  ngtcp2_max_stream_id max_stream_id;
  ngtcp2_ping ping;
  ngtcp2_blocked blocked;
  ngtcp2_stream_blocked stream_blocked;
  ngtcp2_stream_id_blocked stream_id_blocked;
  ngtcp2_new_connection_id new_connection_id;
  ngtcp2_stop_sending stop_sending;
} ngtcp2_frame;

typedef enum {
  NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA = 0,
  NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_DATA = 1,
  NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_STREAM_ID = 2,
  NGTCP2_TRANSPORT_PARAM_IDLE_TIMEOUT = 3,
  NGTCP2_TRANSPORT_PARAM_OMIT_CONNECTION_ID = 4,
  NGTCP2_TRANSPORT_PARAM_MAX_PACKET_SIZE = 5,
  NGTCP2_TRANSPORT_PARAM_STATELESS_RESET_TOKEN = 6
} ngtcp2_transport_param_id;

typedef enum {
  NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO,
  NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS,
  NGTCP2_TRANSPORT_PARAMS_TYPE_NEW_SESSION_TICKET,
} ngtcp2_transport_params_type;

#define NGTCP2_MAX_PKT_SIZE 65527

/**
 * @macro
 *
 * NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS is TLS extension type of
 * quic_transport_parameters.
 */
#define NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS 26

typedef struct {
  union {
    struct {
      uint32_t negotiated_version;
      uint32_t initial_version;
    } ch;
    struct {
      uint32_t supported_versions[63];
      size_t len;
    } ee;
  } v;
  uint32_t initial_max_stream_data;
  uint32_t initial_max_data;
  uint32_t initial_max_stream_id;
  uint16_t idle_timeout;
  uint8_t omit_connection_id;
  uint16_t max_packet_size;
  uint8_t stateless_reset_token[NGTCP2_STATELESS_RESET_TOKENLEN];
} ngtcp2_transport_params;

typedef struct {
  uint32_t max_stream_data;
  uint32_t max_data;
  uint32_t max_stream_id;
  uint16_t idle_timeout;
  uint8_t omit_connection_id;
  uint16_t max_packet_size;
  uint8_t stateless_reset_token[NGTCP2_STATELESS_RESET_TOKENLEN];
} ngtcp2_settings;

/**
 * @function
 *
 * `ngtcp2_encode_transport_params` encodes |params| in |dest| of
 * length |destlen|.
 *
 * This function returns the number of written, or one of the
 * following negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOBUF`
 *     Buffer is too small.
 */
NGTCP2_EXTERN ssize_t
ngtcp2_encode_transport_params(uint8_t *dest, size_t destlen, uint8_t exttype,
                               const ngtcp2_transport_params *params);

/**
 * @function
 *
 * `ngtcp2_decode_transport_params` decodes transport parameters in
 * |data| of length |datalen|, and stores the result in the object
 * pointed by |params|.
 *
 * If the optional parameters are missing, the default value is
 * assigned.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM`
 *     The required parameter is missing.
 * :enum:`NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM`
 *     The input is malformed.
 */
NGTCP2_EXTERN int
ngtcp2_decode_transport_params(ngtcp2_transport_params *params, uint8_t exttype,
                               const uint8_t *data, size_t datalen);

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

/**
 * @function
 *
 * `ngtcp2_pkt_decode_frame` decodes a QUIC frame from the buffer
 * pointed by |payload| whose length is |payloadlen|.
 *
 * This function returns the number of bytes read to decode a single
 * frame if it succeeds, or one of the following negative error codes:
 *
 * :enum:`NGTCP2_ERR_FRAME_FORMAT`
 *     Frame is badly formatted; or frame type is unknown.
 */
NGTCP2_EXTERN ssize_t ngtcp2_pkt_decode_frame(ngtcp2_frame *dest,
                                              const uint8_t *payload,
                                              size_t payloadlen);

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
                                              ngtcp2_frame *fr);

/**
 * @function
 *
 * `ngtcp2_pkt_write_stateless_reset` writes Stateless Reset packet in
 * the buffer pointed by |dest| whose length is |destlen|.  |hd| is a
 * short packet header.  This function assumes that
 * :enum:`NGTCP2_PKT_FLAG_LONG_FORM` is not set in hd->type.
 * |stateless_reset_token| is a pointer to the Stateless Reset Token,
 * and its length must be :macro:`NGTCP2_STATELESS_RESET_TOKENLEN`
 * bytes long.  |rand| specifies the random octets following Stateless
 * Reset Token.  The length of |rand| is specified by |randlen|.
 *
 * If |randlen| is too long to write them all in the buffer, |rand| is
 * written to the buffer as much as possible, and is truncated.
 *
 * This function returns the number of bytes written to the buffer, or
 * one of the following negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOBUF`
 *     Buffer is too small.
 */
NGTCP2_EXTERN ssize_t ngtcp2_pkt_write_stateless_reset(
    uint8_t *dest, size_t destlen, const ngtcp2_pkt_hd *hd,
    uint8_t *stateless_reset_token, uint8_t *rand, size_t randlen);

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
NGTCP2_EXTERN int ngtcp2_upe_encode_frame(ngtcp2_upe *upe, ngtcp2_frame *fr);

/**
 * @function
 *
 * `ngtcp2_upe_padding` encodes PADDING frames to the end of the
 * buffer.  This function returns the number of bytes padded.
 */
NGTCP2_EXTERN size_t ngtcp2_upe_padding(ngtcp2_upe *upe);

/**
 * @function
 *
 * `ngtcp2_upe_encode_version_negotiation` encodes payload of Version
 * Negotiation packet.  Unlike the other functions to encode a frame,
 * this function returns the packet size just like `ngtcp2_upe_final`.
 * You should not call `ngtcp2_upe_final` since Version Negotiation
 * packet does not have an integrity check.
 *
 * This function returns the length of a packet, and assigns the
 * pointer to the packet to |*pkt| if |pkt| is not ``NULL``.  If it
 * fails, one of the following negative error codes is returned:
 *
 * :enum:`NGTCP2_ERR_NOBUF`
 *     Buffer does not have enough capacity to write a payload.
 */
NGTCP2_EXTERN ssize_t
ngtcp2_upe_encode_version_negotiation(ngtcp2_upe *upe, const uint8_t **ppkt,

                                      const uint32_t *sv, size_t nsv);

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

/**
 * @function
 *
 * :type:`ngtcp2_recv_client_initial` is invoked when Client Initial
 * packet is received.  An server application must implement this
 * callback, and generate handshake key, and iv.  Then call
 * `ngtcp2_conn_set_handshake_tx_keys` and
 * `ngtcp2_conn_set_handshake_rx_keys` to inform |conn| of the packet
 * protection keys and ivs.
 *
 * The callback function must return 0 if it succeeds.  If an error
 * occurs, return :enum:`NGTCP2_ERR_CALLBACK_FAILURE` which makes the
 * library call return immediately.
 *
 */
typedef int (*ngtcp2_recv_client_initial)(ngtcp2_conn *conn, uint64_t conn_id,
                                          void *user_data);

typedef ssize_t (*ngtcp2_send_server_cleartext)(ngtcp2_conn *conn,
                                                uint32_t flags,
                                                uint64_t *ppkt_num,
                                                const uint8_t **pdest,
                                                void *user_data);

/**
 * @functypedef
 *
 * ngtcp2_recv_stream0_data is invoked when stream 0 data are
 * received.  The received data are pointed by |data|, and its length
 * is |datalen|.  |user_data| is the arbitrary pointer passed to
 * `ngtcp2_conn_client_new` or `ngtcp2_conn_server_new`.
 *
 * The callback function must return 0 if it succeeds.  Depending on
 * the TLS backend, TLS connection in stream 0 is aborted with TLS
 * alert when reading this data.  In this case, return
 * :enum:`NGTCP2_ERR_TLS_ALERT`.  This will ensure that pending data,
 * especially TLS alert, is sent at least for TLS handshake.  If
 * application encounters fatal error, return
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE` which makes the library call
 * return immediately.  It is undefined when the other value is
 * returned.
 */
typedef int (*ngtcp2_recv_stream0_data)(ngtcp2_conn *conn, const uint8_t *data,
                                        size_t datalen, void *user_data);

/**
 * @functypedef
 *
 * :type:`ngtcp2_send_pkt` is invoked when outgoing packet header |hd|
 * is being encoded.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*ngtcp2_send_pkt)(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                               void *user_data);

/**
 * @functypedef
 *
 * :type:`ngtcp2_send_frame` is invoked when outgoing frame |fr| is
 * being encoded.  The packet header is the object pointed by |hd|.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*ngtcp2_send_frame)(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                                 const ngtcp2_frame *fr, void *user_data);

/**
 * @functypedef
 *
 * :type:`ngtcp2_revc_pkt` is invoked when incoming packet header |hd|
 * is successfully decoded.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*ngtcp2_recv_pkt)(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                               void *user_data);

/**
 * @functypedef
 *
 * :type:`ngtcp2_recv_frame` is invoked when incoming frame |fr| is
 * successfully decoded.  The packet header is the object pointed by
 * |hd|.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*ngtcp2_recv_frame)(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                                 const ngtcp2_frame *fr, void *user_data);

/**
 * @functypedef
 *
 * :type:`ngtcp2_handshake_completed` is invoked when QUIC
 * cryptographic handshake has completed.
 *
 * Application should prepare cryptographic context (e.g., exporting
 * keys from TLS backend, and deriving packet protection key, and iv,
 * etc).  See also `ngtcp2_conn_set_aead_overhead`,
 * `ngtcp2_conn_update_tx_keys`, and `ngtcp2_conn_update_rx_keys`.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*ngtcp2_handshake_completed)(ngtcp2_conn *conn, void *user_data);

typedef int (*ngtcp2_recv_version_negotiation)(ngtcp2_conn *conn,
                                               const ngtcp2_pkt_hd *hd,
                                               const uint32_t *sv, size_t nsv,
                                               void *user_data);

typedef int (*ngtcp2_recv_server_stateless_retry)(ngtcp2_conn *conn,
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

typedef int (*ngtcp2_recv_stream_data)(ngtcp2_conn *conn, uint32_t stream_id,
                                       uint8_t fin, const uint8_t *data,
                                       size_t datalen, void *user_data,
                                       void *stream_user_data);

typedef int (*ngtcp2_stream_close)(ngtcp2_conn *conn, uint32_t stream_id,
                                   uint16_t app_error_code, void *user_data,
                                   void *stream_user_data);
/*
 * @functypedef
 *
 * :type:`ngtcp2_acked_stream_data_offset` is a callback function
 * which is called when stream data is acked, and application can free
 * the data.  The acked range of data is [offset, offset + datalen).
 * For a given stream_id, this callback is called sequentially in
 * increasing order of |offset|.  |datalen| is normally strictly
 * greater than 0.  One exception is that when a packet which includes
 * STREAM frame which has fin flag set, and 0 length data, this
 * callback is invoked with 0 passed as |datalen|.
 */
typedef int (*ngtcp2_acked_stream_data_offset)(ngtcp2_conn *conn,
                                               uint32_t stream_id,
                                               uint64_t offset, size_t datalen,
                                               void *user_data,
                                               void *stream_user_data);

typedef int (*ngtcp2_recv_stateless_reset)(ngtcp2_conn *conn,
                                           const ngtcp2_pkt_hd *hd,
                                           const ngtcp2_pkt_stateless_reset *sr,
                                           void *user_data);

/*
 * @functypedef
 *
 * :type:`ngtcp2_extend_max_stream_id` is a callback function which is
 * called every time max stream ID is strictly extended.
 * |max_stream_id| is the maximum stream ID which a local endpoint can
 * open.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*ngtcp2_extend_max_stream_id)(ngtcp2_conn *conn,
                                           uint32_t max_stream_id,
                                           void *user_data);

typedef struct {
  ngtcp2_send_client_initial send_client_initial;
  ngtcp2_send_client_cleartext send_client_cleartext;
  ngtcp2_recv_client_initial recv_client_initial;
  ngtcp2_send_server_cleartext send_server_cleartext;
  ngtcp2_recv_stream0_data recv_stream0_data;
  ngtcp2_send_pkt send_pkt;
  ngtcp2_send_frame send_frame;
  ngtcp2_recv_pkt recv_pkt;
  ngtcp2_recv_frame recv_frame;
  ngtcp2_handshake_completed handshake_completed;
  ngtcp2_recv_version_negotiation recv_version_negotiation;
  /* hs_encrypt is a callback function which is invoked to encrypt
     handshake cleartext packets. */
  ngtcp2_encrypt hs_encrypt;
  /* hs_decrypt is a callback function which is invoked to encrypt
     handshake cleartext packets. */
  ngtcp2_decrypt hs_decrypt;
  ngtcp2_encrypt encrypt;
  ngtcp2_decrypt decrypt;
  ngtcp2_recv_stream_data recv_stream_data;
  ngtcp2_acked_stream_data_offset acked_stream_data_offset;
  ngtcp2_stream_close stream_close;
  ngtcp2_recv_stateless_reset recv_stateless_reset;
  ngtcp2_recv_server_stateless_retry recv_server_stateless_retry;
  ngtcp2_extend_max_stream_id extend_max_stream_id;
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

/*
 * @function
 *
 * `ngtcp2_conn_client_new` creates new :type:`ngtcp2_conn`, and
 * initializes it as client.  |conn_id| is client-chosen connection
 * ID.  |version| is a QUIC version to use.  |callbacks|, and
 * |settings| must not be NULL, and the function make a copy of each
 * of them.  |user_data| is the arbitrary pointer which is passed to
 * the user-defined callback functions.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOMEM`
 *     Out of memory.
 */
NGTCP2_EXTERN int ngtcp2_conn_client_new(ngtcp2_conn **pconn, uint64_t conn_id,
                                         uint32_t version,
                                         const ngtcp2_conn_callbacks *callbacks,
                                         const ngtcp2_settings *settings,
                                         void *user_data);

/*
 * @function
 *
 * `ngtcp2_conn_server_new` creates new :type:`ngtcp2_conn`, and
 * initializes it as client.  |conn_id| is server-chosen connection
 * ID.  |version| is a QUIC version to use.  |callbacks|, and
 * |settings| must not be NULL, and the function make a copy of each
 * of them.  |user_data| is the arbitrary pointer which is passed to
 * the user-defined callback functions.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOMEM`
 *     Out of memory.
 */
NGTCP2_EXTERN int ngtcp2_conn_server_new(ngtcp2_conn **pconn, uint64_t conn_id,
                                         uint32_t version,
                                         const ngtcp2_conn_callbacks *callbacks,
                                         const ngtcp2_settings *settings,
                                         void *user_data);

/*
 * @function
 *
 * `ngtcp2_conn_del` frees resources allocated for |conn|.  It also
 * frees memory pointed by |conn|.
 */
NGTCP2_EXTERN void ngtcp2_conn_del(ngtcp2_conn *conn);

NGTCP2_EXTERN int ngtcp2_conn_recv(ngtcp2_conn *conn, const uint8_t *pkt,
                                   size_t pktlen, ngtcp2_tstamp ts);

/*
 * @function
 *
 * `ngtcp2_conn_write_pkt` writes a QUIC packet in the buffer pointed
 * by |dest| whose length is |destlen|.  |ts| is the timestamp of the
 * current time.
 *
 * If there is no packet to send, this function returns 0.
 *
 * This function returns the number of bytes written in |dest| if it
 * succeeds, or one of the following negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE`
 *     User-defined callback function failed.
 * :enum:`NGTCP2_ERR_NOBUF`
 *     Buffer is too small.
 * :enum:`NGTCP2_ERR_PKT_TIMEOUT`
 *     Give up the retransmission of lost packet because of timeout.
 * :enum:`NGTCP2_ERR_INVALID_ARGUMENT`
 *     Packet type is unexpected.  TODO: This will be removed in the
 *     future.
 * :enum:`NGTCP2_ERR_PKT_NUM_EXHAUSTED`
 *     The packet number has reached at the maximum value, therefore
 *     the function cannot make new packet on this connection.
 * :enum:`NGTCP2_ERR_TLS_HANDSHAKE`
 *     QUIC cryptographic handshake failed.  Application should just
 *     discard state, and delete |conn|.
 */
NGTCP2_EXTERN ssize_t ngtcp2_conn_write_pkt(ngtcp2_conn *conn, uint8_t *dest,
                                            size_t destlen, ngtcp2_tstamp ts);

/*
 * @function
 *
 * `ngtcp2_conn_write_ack_pkt` is just like `ngtcp2_conn_write_pkt`,
 * but only sends ACK only packet, or lost packet.
 */
NGTCP2_EXTERN ssize_t ngtcp2_conn_write_ack_pkt(ngtcp2_conn *conn,
                                                uint8_t *dest, size_t destlen,
                                                ngtcp2_tstamp ts);

/**
 * @function
 *
 * `ngtcp2_conn_handshake_completed` tells |conn| that the QUIC
 * handshake has completed.
 */
NGTCP2_EXTERN void ngtcp2_conn_handshake_completed(ngtcp2_conn *conn);

/**
 * @function
 *
 * `ngtcp2_conn_set_handshake_tx_keys` sets key and iv to
 *  encrypt handshake cleartext packets.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_INVALID_STATE`
 *     A packet protection key and iv are already set.
 */
NGTCP2_EXTERN int ngtcp2_conn_set_handshake_tx_keys(ngtcp2_conn *conn,
                                                    const uint8_t *key,
                                                    size_t keylen,
                                                    const uint8_t *iv,
                                                    size_t ivlen);

/**
 * @function
 *
 * `ngtcp2_conn_set_handshake_rx_keys` sets key and iv to decrypt
 * handshake cleartext packets.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_INVALID_STATE`
 *     A packet protection key and iv are already set.
 */
NGTCP2_EXTERN int ngtcp2_conn_set_handshake_rx_keys(ngtcp2_conn *conn,
                                                    const uint8_t *key,
                                                    size_t keylen,
                                                    const uint8_t *iv,
                                                    size_t ivlen);

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
 * `ngtcp2_conn_earliest_expiry` returns the earliest expiry time
 * point that application should call `ngtcp2_conn_write_pkt` before
 * that expires.  It returns 0 if there is no expiry.
 */
NGTCP2_EXTERN ngtcp2_tstamp ngtcp2_conn_earliest_expiry(ngtcp2_conn *conn);

/**
 * @function
 *
 * `ngtcp2_conn_set_remote_transport_params` sets transport parameter
 * |params| to |conn|.  |exttype| is the type of message it is
 * carried, and it should be one of
 * :type:`ngtcp2_transport_params_type`.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_PROTO`
 *     If |conn| is server, and negotiated_version field is not the
 *     same as the used version.
 * :enum:`NGTCP2_ERR_INVALID_ARGUMENT`
 *     If |conn| is client, and |exttype| is
 *     :enum:`NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO`; or, if
 *     |conn| is server, and |exttype| is either
 *     :enum:`NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS`, or
 *     :enum:`NGTCP2_TRANSPORT_PARAMS_TYPE_NEW_SESSION_TICKET`
 */
NGTCP2_EXTERN int
ngtcp2_conn_set_remote_transport_params(ngtcp2_conn *conn, uint8_t exttype,
                                        const ngtcp2_transport_params *params);

/**
 * @function
 *
 * `ngtcp2_conn_get_local_transport_params` fills settings values in
 * |params|.  |exttype| is the type of message it is carried, and it
 * should be one of :type:`ngtcp2_transport_params_type`.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_INVALID_ARGUMENT`
 *     If |conn| is server, and |exttype| is
 *     :enum:`NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO`; or, if
 *     |conn| is client, and |exttype| is either
 *     :enum:`NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS`, or
 *     :enum:`NGTCP2_TRANSPORT_PARAMS_TYPE_NEW_SESSION_TICKET`
 */
NGTCP2_EXTERN int ngtcp2_conn_get_local_transport_params(
    ngtcp2_conn *conn, ngtcp2_transport_params *params, uint8_t exttype);

/**
 * @function
 *
 * `ngtcp2_conn_open_stream` opens new stream denoted by |stream_id|..
 * The |stream_user_data| is the user data specific to the stream.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOMEM`
 *     Out of memory
 * :enum:`NGTCP2_ERR_STREAM_ID_BLOCKED`
 *     The remote peer does not allow |stream_id| yet.
 * :enum:`NGTCP2_ERR_STREAM_IN_USE`
 *     The stream has already been opened.

 */
NGTCP2_EXTERN int ngtcp2_conn_open_stream(ngtcp2_conn *conn, uint32_t stream_id,
                                          void *stream_user_data);

/**
 * @function
 *
 * `ngtcp2_conn_shutdown_stream` closes stream denoted by |stream_id|
 * abruptly.  |app_error_code| is one of application error codes, and
 * indicates the reason of shutdown.  Successful call of this function
 * does not immediately erase the state of the stream.  The actual
 * deletion is done when the remote endpoint sends acknowledgement.
 * Calling this function is equivalent to call
 * `ngtcp2_conn_shutdown_stream_read`, and
 * `ngtcp2_conn_shutdown_stream_write` sequentially.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOMEM`
 *     Out of memory
 * :enum:`NGTCP2_ERR_INVALID_ARGUMENT`
 *     |stream_id| is 0; or |app_error_code| ==
 *     :enum:`NGTCP2_STOPPING`.
 * :enum:`NGTCP2_ERR_STREAM_NOT_FOUND`
 *     Stream does not exist
 */
NGTCP2_EXTERN int ngtcp2_conn_shutdown_stream(ngtcp2_conn *conn,
                                              uint32_t stream_id,
                                              uint16_t app_error_code);

/**
 * @function
 *
 * `ngtcp2_conn_shutdown_stream_write` closes write-side of stream
 * denoted by |stream_id| abruptly.  |app_error_code| is one of
 * application error codes, and indicates the reason of shutdown.  If
 * this function succeeds, no application data is sent to the remote
 * endpoint.  It discards all data which has not been acknowledged
 * yet.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOMEM`
 *     Out of memory
 * :enum:`NGTCP2_ERR_INVALID_ARGUMENT`
 *     |stream_id| is 0; or |app_error_code| ==
 *     :enum:`NGTCP2_STOPPING`.
 * :enum:`NGTCP2_ERR_STREAM_NOT_FOUND`
 *     Stream does not exist
 */
NGTCP2_EXTERN int ngtcp2_conn_shutdown_stream_write(ngtcp2_conn *conn,
                                                    uint32_t stream_id,
                                                    uint16_t app_error_code);

/**
 * @function
 *
 * `ngtcp2_conn_shutdown_stream_read` closes read-side of stream
 * denoted by |stream_id| abruptly.  |app_error_code| is one of
 * application error codes, and indicates the reason of shutdown.  If
 * this function succeeds, no application data is forwarded to an
 * application layer.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOMEM`
 *     Out of memory
 * :enum:`NGTCP2_ERR_INVALID_ARGUMENT`
 *     |stream_id| is 0; or |app_error_code| ==
 *     :enum:`NGTCP2_STOPPING`.
 * :enum:`NGTCP2_ERR_STREAM_NOT_FOUND`
 *     Stream does not exist
 */
NGTCP2_EXTERN int ngtcp2_conn_shutdown_stream_read(ngtcp2_conn *conn,
                                                   uint32_t stream_id,
                                                   uint16_t app_error_code);

/**
 * @function
 *
 * `ngtcp2_conn_write_stream` writes a packet containing stream data
 * of stream denoted by |stream_id|.  The buffer of the packet is
 * pointed by |dest| of length |destlen|.
 *
 * If the all given data is encoded as STREAM frame in|dest|, and if
 * |fin| is nonzero, fin flag is set in outgoing STREAM frame.
 * Otherwise, fin flag in STREAM frame is not set.
 *
 * The number of data encoded in STREAM frame is stored in |*pdatalen|
 * if it is not NULL.
 *
 * This function returns the number of bytes written in |dest| if it
 * succeeds, or one of the following negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOMEM`
 *     Out of memory
 * :enum:`NGTCP2_ERR_NOBUF`
 *     Buffer is too small
 * :enum:`NGTCP2_ERR_STREAM_NOT_FOUND`
 *     Stream does not exist
 * :enum:`NGTCP2_ERR_STREAM_SHUT_WR`
 *     Stream is half closed (local); or stream is being reset.
 * :enum:`NGTCP2_ERR_PKT_NUM_EXHAUSTED`
 *     Packet number is exhausted, and cannot send any more packet.
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE`
 *     User callback failed
 */
NGTCP2_EXTERN ssize_t ngtcp2_conn_write_stream(ngtcp2_conn *conn, uint8_t *dest,
                                               size_t destlen, size_t *pdatalen,
                                               uint32_t stream_id, uint8_t fin,
                                               const uint8_t *data,
                                               size_t datalen,
                                               ngtcp2_tstamp ts);

/**
 * @function
 *
 * `ngtcp2_conn_write_connection_close` writes a packet which contains
 * a CONNECTION_CLOSE frame in the buffer pointed by |dest| whose
 * capacity is |datalen|.
 *
 * At the moment, successful call to this function makes connection
 * close.  We may change this behaviour in the future to allow
 * graceful shutdown.
 *
 * :enum:`NGTCP2_ERR_NOMEM`
 *     Out of memory
 * :enum:`NGTCP2_ERR_NOBUF`
 *     Buffer is too small
 * :enum:`NGTCP2_ERR_INVALID_STATE`
 *     The current state does not allow sending CONNECTION_CLOSE.
 * :enum:`NGTCP2_ERR_PKT_NUM_EXHAUSTED`
 *     Packet number is exhausted, and cannot send any more packet.
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE`
 *     User callback failed
 */
NGTCP2_EXTERN ssize_t ngtcp2_conn_write_connection_close(ngtcp2_conn *conn,
                                                         uint8_t *dest,
                                                         size_t destlen,
                                                         uint16_t error_code);

/**
 * @function
 *
 * `ngtcp2_conn_write_application_close` writes a packet which
 * contains a APPLICATION_CLOSE frame in the buffer pointed by |dest|
 * whose capacity is |datalen|.
 *
 * At the moment, successful call to this function makes connection
 * close.  We may change this behaviour in the future to allow
 * graceful shutdown.
 *
 * :enum:`NGTCP2_ERR_NOMEM`
 *     Out of memory
 * :enum:`NGTCP2_ERR_NOBUF`
 *     Buffer is too small
 * :enum:`NGTCP2_ERR_INVALID_STATE`
 *     The current state does not allow sending APPLICATION_CLOSE.
 * :enum:`NGTCP2_ERR_PKT_NUM_EXHAUSTED`
 *     Packet number is exhausted, and cannot send any more packet.
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE`
 *     User callback failed
 * :enum:`NGTCP2_ERR_INVALID_ARGUMENT`
 *     |app_error_code| == :enum:`NGTCP2_STOPPING`.
 */
NGTCP2_EXTERN ssize_t ngtcp2_conn_write_application_close(
    ngtcp2_conn *conn, uint8_t *dest, size_t destlen, uint16_t app_error_code);

/**
 * @function
 *
 * `ngtcp2_conn_closed` returns nonzero if QUIC connection has been
 * closed.
 */
NGTCP2_EXTERN int ngtcp2_conn_closed(ngtcp2_conn *conn);

/**
 * @function
 *
 * `ngtcp2_conn_extend_max_stream_offset` extends stream's max stream
 * data value by |datalen|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_STREAM_NOT_FOUND`
 *     Stream was not found
 */
NGTCP2_EXTERN int ngtcp2_conn_extend_max_stream_offset(ngtcp2_conn *conn,
                                                       uint32_t stream_id,
                                                       size_t datalen);

/**
 * @function
 *
 * `ngtcp2_conn_extend_max_offset` extends max data offset by
 * |datalen|.
 */
NGTCP2_EXTERN void ngtcp2_conn_extend_max_offset(ngtcp2_conn *conn,
                                                 size_t datalen);

/**
 * @function
 *
 * `ngtcp2_conn_bytes_in_flight` returns the number of bytes which is
 * the sum of outgoing QUIC packet length in flight.  This does not
 * include a packet which only includes ACK frames.
 */
NGTCP2_EXTERN size_t ngtcp2_conn_bytes_in_flight(ngtcp2_conn *conn);

/**
 * @function
 *
 * `ngtcp2_conn_negotiated_conn_id` returns the negotiated connection
 * ID.
 */
NGTCP2_EXTERN uint64_t ngtcp2_conn_negotiated_conn_id(ngtcp2_conn *conn);

/**
 * @function
 *
 * `ngtcp2_conn_negotiated_version` returns the negotiated version.
 */
NGTCP2_EXTERN uint32_t ngtcp2_conn_negotiated_version(ngtcp2_conn *conn);

/**
 * @function
 *
 * `ngtcp2_strerror` returns the text representation of |liberr|.
 */
NGTCP2_EXTERN const char *ngtcp2_strerror(int liberr);

/**
 * @function
 *
 * `ngtcp2_err_fatal` returns nonzero if |liberr| is a fatal error.
 */
NGTCP2_EXTERN int ngtcp2_err_fatal(int liberr);

#ifdef __cplusplus
}
#endif

#endif /* NGTCP2_H */
