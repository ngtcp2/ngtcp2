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
#  define WIN32
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#if defined(_MSC_VER) && (_MSC_VER < 1800)
/* MSVC < 2013 does not have inttypes.h because it is not C99
   compliant.  See compiler macros and version number in
   https://sourceforge.net/p/predef/wiki/Compilers/ */
#  include <stdint.h>
#else /* !defined(_MSC_VER) || (_MSC_VER >= 1800) */
#  include <inttypes.h>
#endif /* !defined(_MSC_VER) || (_MSC_VER >= 1800) */
#include <sys/types.h>
#include <stdarg.h>

#include <ngtcp2/version.h>

#ifdef NGTCP2_STATICLIB
#  define NGTCP2_EXTERN
#elif defined(WIN32)
#  ifdef BUILDING_NGTCP2
#    define NGTCP2_EXTERN __declspec(dllexport)
#  else /* !BUILDING_NGTCP2 */
#    define NGTCP2_EXTERN __declspec(dllimport)
#  endif /* !BUILDING_NGTCP2 */
#else    /* !defined(WIN32) */
#  ifdef BUILDING_NGTCP2
#    define NGTCP2_EXTERN __attribute__((visibility("default")))
#  else /* !BUILDING_NGTCP2 */
#    define NGTCP2_EXTERN
#  endif /* !BUILDING_NGTCP2 */
#endif   /* !defined(WIN32) */

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

/* NGTCP2_PROTO_VER_D19 is the supported QUIC protocol version. */
#define NGTCP2_PROTO_VER_D19 0xff000013u
/* NGTCP2_PROTO_VER_MAX is the highest QUIC version the library
   supports. */
#define NGTCP2_PROTO_VER_MAX NGTCP2_PROTO_VER_D19

/* NGTCP2_ALPN_* is a serialized form of ALPN protocol identifier this
   library supports.  Notice that the first byte is the length of the
   following protocol identifier. */
#define NGTCP2_ALPN_D19 "\x5h3-19"

#define NGTCP2_MAX_PKTLEN_IPV4 1252
#define NGTCP2_MAX_PKTLEN_IPV6 1232

/* NGTCP2_MIN_INITIAL_PKTLEN is the minimum UDP packet size for a
   packet sent by client which contains its first Initial packet. */
#define NGTCP2_MIN_INITIAL_PKTLEN 1200

/* NGTCP2_STATELESS_RESET_TOKENLEN is the length of Stateless Reset
   Token. */
#define NGTCP2_STATELESS_RESET_TOKENLEN 16

/* NGTCP2_MIN_STATELESS_RESET_RANDLEN is the minimum length of random
   bytes in Stateless Retry packet */
#define NGTCP2_MIN_STATELESS_RESET_RANDLEN 23

/* NGTCP2_INITIAL_SALT is a salt value which is used to derive initial
   secret. */
#define NGTCP2_INITIAL_SALT                                                    \
  "\xef\x4f\xb0\xab\xb4\x74\x70\xc4\x1b\xef\xcf\x80\x31\x33\x4f\xae\x48\x5e"   \
  "\x09\xa0"

/* NGTCP2_HP_MASKLEN is the length of header protection mask. */
#define NGTCP2_HP_MASKLEN 5

/* NGTCP2_DURATION_TICK is a count of tick per second. */
#define NGTCP2_DURATION_TICK 1000000000

/* NGTCP2_SECONDS is a count of tick which corresponds to 1 second. */
#define NGTCP2_SECONDS 1000000000

/* NGTCP2_MILLISECONDS is a count of tick which corresponds to 1
   millisecond. */
#define NGTCP2_MILLISECONDS 1000000

/* NGTCP2_MICROSECONDS is a count of tick which corresponds to 1
   microsecond. */
#define NGTCP2_MICROSECONDS 1000

/* NGTCP2_NANOSECONDS is a count of tick which corresponds to 1
   nanosecond. */
#define NGTCP2_NANOSECONDS 1

typedef enum {
  NGTCP2_ERR_INVALID_ARGUMENT = -201,
  NGTCP2_ERR_UNKNOWN_PKT_TYPE = -202,
  NGTCP2_ERR_NOBUF = -203,
  NGTCP2_ERR_PROTO = -205,
  NGTCP2_ERR_INVALID_STATE = -206,
  NGTCP2_ERR_ACK_FRAME = -207,
  NGTCP2_ERR_STREAM_ID_BLOCKED = -208,
  NGTCP2_ERR_STREAM_IN_USE = -209,
  NGTCP2_ERR_STREAM_DATA_BLOCKED = -210,
  NGTCP2_ERR_FLOW_CONTROL = -211,
  NGTCP2_ERR_STREAM_LIMIT = -213,
  NGTCP2_ERR_FINAL_SIZE = -214,
  NGTCP2_ERR_CRYPTO = -215,
  NGTCP2_ERR_PKT_NUM_EXHAUSTED = -216,
  NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM = -217,
  NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM = -218,
  NGTCP2_ERR_FRAME_ENCODING = -219,
  NGTCP2_ERR_TLS_DECRYPT = -220,
  NGTCP2_ERR_STREAM_SHUT_WR = -221,
  NGTCP2_ERR_STREAM_NOT_FOUND = -222,
  NGTCP2_ERR_STREAM_STATE = -226,
  NGTCP2_ERR_NOKEY = -227,
  NGTCP2_ERR_EARLY_DATA_REJECTED = -228,
  NGTCP2_ERR_RECV_VERSION_NEGOTIATION = -229,
  NGTCP2_ERR_CLOSING = -230,
  NGTCP2_ERR_DRAINING = -231,
  NGTCP2_ERR_TRANSPORT_PARAM = -234,
  NGTCP2_ERR_DISCARD_PKT = -235,
  NGTCP2_ERR_PATH_VALIDATION_FAILED = -236,
  NGTCP2_ERR_FATAL = -500,
  NGTCP2_ERR_NOMEM = -501,
  NGTCP2_ERR_CALLBACK_FAILURE = -502,
  NGTCP2_ERR_INTERNAL = -503
} ngtcp2_lib_error;

typedef enum {
  NGTCP2_PKT_FLAG_NONE = 0,
  NGTCP2_PKT_FLAG_LONG_FORM = 0x01,
  NGTCP2_PKT_FLAG_KEY_PHASE = 0x04
} ngtcp2_pkt_flag;

typedef enum {
  /* NGTCP2_PKT_VERSION_NEGOTIATION is defined by libngtcp2 for
     convenience. */
  NGTCP2_PKT_VERSION_NEGOTIATION = 0xf0,
  NGTCP2_PKT_INITIAL = 0x0,
  NGTCP2_PKT_0RTT = 0x1,
  NGTCP2_PKT_HANDSHAKE = 0x2,
  NGTCP2_PKT_RETRY = 0x3,
  /* NGTCP2_PKT_SHORT is defined by libngtcp2 for convenience. */
  NGTCP2_PKT_SHORT = 0x70
} ngtcp2_pkt_type;

typedef enum {
  NGTCP2_FRAME_PADDING = 0x00,
  NGTCP2_FRAME_PING = 0x01,
  NGTCP2_FRAME_ACK = 0x02,
  NGTCP2_FRAME_ACK_ECN = 0x03,
  NGTCP2_FRAME_RESET_STREAM = 0x04,
  NGTCP2_FRAME_STOP_SENDING = 0x05,
  NGTCP2_FRAME_CRYPTO = 0x06,
  NGTCP2_FRAME_NEW_TOKEN = 0x07,
  NGTCP2_FRAME_STREAM = 0x08,
  NGTCP2_FRAME_MAX_DATA = 0x10,
  NGTCP2_FRAME_MAX_STREAM_DATA = 0x11,
  NGTCP2_FRAME_MAX_STREAMS_BIDI = 0x12,
  NGTCP2_FRAME_MAX_STREAMS_UNI = 0x13,
  NGTCP2_FRAME_DATA_BLOCKED = 0x14,
  NGTCP2_FRAME_STREAM_DATA_BLOCKED = 0x15,
  NGTCP2_FRAME_STREAMS_BLOCKED_BIDI = 0x16,
  NGTCP2_FRAME_STREAMS_BLOCKED_UNI = 0x17,
  NGTCP2_FRAME_NEW_CONNECTION_ID = 0x18,
  NGTCP2_FRAME_RETIRE_CONNECTION_ID = 0x19,
  NGTCP2_FRAME_PATH_CHALLENGE = 0x1a,
  NGTCP2_FRAME_PATH_RESPONSE = 0x1b,
  NGTCP2_FRAME_CONNECTION_CLOSE = 0x1c,
  NGTCP2_FRAME_CONNECTION_CLOSE_APP = 0x1d
} ngtcp2_frame_type;

typedef enum {
  NGTCP2_NO_ERROR = 0x0u,
  NGTCP2_INTERNAL_ERROR = 0x1u,
  NGTCP2_SERVER_BUSY = 0x2u,
  NGTCP2_FLOW_CONTROL_ERROR = 0x3u,
  NGTCP2_STREAM_LIMIT_ERROR = 0x4u,
  NGTCP2_STREAM_STATE_ERROR = 0x5u,
  NGTCP2_FINAL_SIZE_ERROR = 0x6u,
  NGTCP2_FRAME_ENCODING_ERROR = 0x7u,
  NGTCP2_TRANSPORT_PARAMETER_ERROR = 0x8u,
  NGTCP2_VERSION_NEGOTIATION_ERROR = 0x9u,
  NGTCP2_PROTOCOL_VIOLATION = 0xau,
  NGTCP2_INVALID_MIGRATION = 0xcu,
  NGTCP2_CRYPTO_ERROR = 0x100
} ngtcp2_transport_error;

typedef enum {
  NGTCP2_PATH_VALIDATION_RESULT_SUCCESS,
  NGTCP2_PATH_VALIDATION_RESULT_FAILURE,
} ngtcp2_path_validation_result;

/*
 * ngtcp2_tstamp is a timestamp with NGTCP2_DURATION_TICK resolution.
 */
typedef uint64_t ngtcp2_tstamp;

/*
 * ngtcp2_duration is a period of time in NGTCP2_DURATION_TICK
 * resolution.
 */
typedef uint64_t ngtcp2_duration;

/* NGTCP2_MAX_CIDLEN is the maximum length of Connection ID. */
#define NGTCP2_MAX_CIDLEN 18
/* NGTCP2_MIN_CIDLEN is the minimum length of Connection ID. */
#define NGTCP2_MIN_CIDLEN 4

/**
 * @struct
 *
 * ngtcp2_cid holds a Connection ID.
 */
typedef struct {
  size_t datalen;
  uint8_t data[NGTCP2_MAX_CIDLEN];
} ngtcp2_cid;

/**
 * @struct
 *
 * ngtcp2_vec is struct iovec compatible structure to reference
 * arbitrary array of bytes.
 */
typedef struct {
  /* base points to the data. */
  uint8_t *base;
  /* len is the number of bytes which the buffer pointed by base
     contains. */
  size_t len;
} ngtcp2_vec;

/**
 * @function
 *
 * `ngtcp2_cid_init` initializes Connection ID |cid| with the byte
 * string pointed by |data| and its length is |datalen|.  |datalen|
 * must be at least :enum:`NGTCP2_MIN_CDLEN`, and at most
 * :enum:`NGTCP2_MAX_CDLEN`.
 */
NGTCP2_EXTERN void ngtcp2_cid_init(ngtcp2_cid *cid, const uint8_t *data,
                                   size_t datalen);

typedef struct {
  ngtcp2_cid dcid;
  ngtcp2_cid scid;
  int64_t pkt_num;
  uint8_t *token;
  size_t tokenlen;
  /**
   * pkt_numlen is the number of bytes spent to encode pkt_num.
   */
  size_t pkt_numlen;
  /**
   * len is the sum of pkt_numlen and the length of QUIC packet
   * payload.
   */
  size_t len;
  uint32_t version;
  uint8_t type;
  uint8_t flags;
} ngtcp2_pkt_hd;

typedef struct {
  const uint8_t *stateless_reset_token;
  const uint8_t *rand;
  size_t randlen;
} ngtcp2_pkt_stateless_reset;

typedef struct {
  ngtcp2_cid odcid;
  const uint8_t *token;
  size_t tokenlen;
} ngtcp2_pkt_retry;

typedef struct {
  uint8_t type;
  /**
   * flags of decoded STREAM frame.  This gets ignored when encoding
   * STREAM frame.
   */
  uint8_t flags;
  uint8_t fin;
  int64_t stream_id;
  uint64_t offset;
  /* datacnt is the number of elements that data contains.  Although
     the length of data is 1 in this definition, the library may
     allocate extra bytes to hold more elements. */
  size_t datacnt;
  /* data is the array of ngtcp2_vec which references data. */
  ngtcp2_vec data[1];
} ngtcp2_stream;

typedef struct {
  uint64_t gap;
  uint64_t blklen;
} ngtcp2_ack_blk;

typedef struct {
  uint8_t type;
  int64_t largest_ack;
  uint64_t ack_delay;
  /**
   * ack_delay_unscaled is an ack_delay multiplied by
   * 2**ack_delay_component * NGTCP2_DURATION_TICK /
   * NGTCP2_MICROSECONDS.
   */
  ngtcp2_duration ack_delay_unscaled;
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
  int64_t stream_id;
  uint16_t app_error_code;
  uint64_t final_size;
} ngtcp2_reset_stream;

typedef struct {
  uint8_t type;
  uint16_t error_code;
  uint8_t frame_type;
  size_t reasonlen;
  uint8_t *reason;
} ngtcp2_connection_close;

typedef struct {
  uint8_t type;
  /**
   * max_data is Maximum Data.
   */
  uint64_t max_data;
} ngtcp2_max_data;

typedef struct {
  uint8_t type;
  int64_t stream_id;
  uint64_t max_stream_data;
} ngtcp2_max_stream_data;

typedef struct {
  uint8_t type;
  uint64_t max_streams;
} ngtcp2_max_streams;

typedef struct {
  uint8_t type;
} ngtcp2_ping;

typedef struct {
  uint8_t type;
  uint64_t offset;
} ngtcp2_data_blocked;

typedef struct {
  uint8_t type;
  int64_t stream_id;
  uint64_t offset;
} ngtcp2_stream_data_blocked;

typedef struct {
  uint8_t type;
  uint64_t stream_limit;
} ngtcp2_streams_blocked;

typedef struct {
  uint8_t type;
  uint64_t seq;
  ngtcp2_cid cid;
  uint8_t stateless_reset_token[NGTCP2_STATELESS_RESET_TOKENLEN];
} ngtcp2_new_connection_id;

typedef struct {
  uint8_t type;
  int64_t stream_id;
  uint16_t app_error_code;
} ngtcp2_stop_sending;

typedef struct {
  uint8_t type;
  uint8_t data[8];
} ngtcp2_path_challenge;

typedef struct {
  uint8_t type;
  uint8_t data[8];
} ngtcp2_path_response;

typedef struct {
  uint8_t type;
  /* ordered_offset is an offset in global TLS stream which combines
     Initial, Handshake, 0/1-RTT packet number space.  Although
     packets can be acknowledged in the random order, they must be fed
     into TLS stack as they are generated, so their offset in TLS
     stream must be ordered and distinct.  This field is not sent on
     wire, and currently used for outgoing frame only. */
  uint64_t ordered_offset;
  uint64_t offset;
  /* datacnt is the number of elements that data contains.  Although
     the length of data is 1 in this definition, the library may
     allocate extra bytes to hold more elements. */
  size_t datacnt;
  /* data is the array of ngtcp2_vec which references data. */
  ngtcp2_vec data[1];
} ngtcp2_crypto;

typedef struct {
  uint8_t type;
  size_t tokenlen;
  const uint8_t *token;
} ngtcp2_new_token;

typedef struct {
  uint8_t type;
  uint64_t seq;
} ngtcp2_retire_connection_id;

typedef union {
  uint8_t type;
  ngtcp2_stream stream;
  ngtcp2_ack ack;
  ngtcp2_padding padding;
  ngtcp2_reset_stream reset_stream;
  ngtcp2_connection_close connection_close;
  ngtcp2_max_data max_data;
  ngtcp2_max_stream_data max_stream_data;
  ngtcp2_max_streams max_streams;
  ngtcp2_ping ping;
  ngtcp2_data_blocked data_blocked;
  ngtcp2_stream_data_blocked stream_data_blocked;
  ngtcp2_streams_blocked streams_blocked;
  ngtcp2_new_connection_id new_connection_id;
  ngtcp2_stop_sending stop_sending;
  ngtcp2_path_challenge path_challenge;
  ngtcp2_path_response path_response;
  ngtcp2_crypto crypto;
  ngtcp2_new_token new_token;
  ngtcp2_retire_connection_id retire_connection_id;
} ngtcp2_frame;

typedef enum {
  NGTCP2_TRANSPORT_PARAM_ORIGINAL_CONNECTION_ID = 0x0000,
  NGTCP2_TRANSPORT_PARAM_IDLE_TIMEOUT = 0x0001,
  NGTCP2_TRANSPORT_PARAM_STATELESS_RESET_TOKEN = 0x0002,
  NGTCP2_TRANSPORT_PARAM_MAX_PACKET_SIZE = 0x0003,
  NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_DATA = 0x0004,
  NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL = 0x0005,
  NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 0x0006,
  NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI = 0x0007,
  NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI = 0x0008,
  NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI = 0x0009,
  NGTCP2_TRANSPORT_PARAM_ACK_DELAY_EXPONENT = 0x000a,
  NGTCP2_TRANSPORT_PARAM_MAX_ACK_DELAY = 0x000b,
  NGTCP2_TRANSPORT_PARAM_DISABLE_MIGRATION = 0x000c,
  NGTCP2_TRANSPORT_PARAM_PREFERRED_ADDRESS = 0x000d
} ngtcp2_transport_param_id;

typedef enum {
  NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO,
  NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS
} ngtcp2_transport_params_type;

/**
 * @enum
 *
 * ngtcp2_rand_ctx is a context where generated random value is used.
 */
typedef enum {
  NGTCP2_RAND_CTX_NONE,
  /**
   * NGTCP2_RAND_CTX_PATH_CHALLENGE indicates that random value is
   * used for PATH_CHALLENGE.
   */
  NGTCP2_RAND_CTX_PATH_CHALLENGE
} ngtcp2_rand_ctx;

#define NGTCP2_MAX_PKT_SIZE 65527

/**
 * @macro
 *
 * NGTCP2_DEFAULT_ACK_DELAY_EXPONENT is a default value of scaling
 * factor of ACK Delay field in ACK frame.
 */
#define NGTCP2_DEFAULT_ACK_DELAY_EXPONENT 3

/**
 * @macro
 *
 * NGTCP2_DEFAULT_MAX_ACK_DELAY is a default value of the maximum
 * amount of time in milliseconds by which endpoint delays sending
 * acknowledgement.
 */
#define NGTCP2_DEFAULT_MAX_ACK_DELAY 25

/**
 * @macro
 *
 * NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS is TLS extension type of
 * quic_transport_parameters.
 */
#define NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS 0xffa5u

typedef struct {
  ngtcp2_cid cid;
  uint16_t ipv4_port;
  uint16_t ipv6_port;
  uint8_t ipv4_addr[4];
  uint8_t ipv6_addr[16];
  uint8_t stateless_reset_token[NGTCP2_STATELESS_RESET_TOKENLEN];
} ngtcp2_preferred_addr;

typedef struct {
  ngtcp2_preferred_addr preferred_address;
  ngtcp2_cid original_connection_id;
  uint64_t initial_max_stream_data_bidi_local;
  uint64_t initial_max_stream_data_bidi_remote;
  uint64_t initial_max_stream_data_uni;
  uint64_t initial_max_data;
  uint64_t initial_max_streams_bidi;
  uint64_t initial_max_streams_uni;
  uint64_t idle_timeout;
  uint64_t max_packet_size;
  uint8_t stateless_reset_token[NGTCP2_STATELESS_RESET_TOKENLEN];
  uint8_t stateless_reset_token_present;
  uint64_t ack_delay_exponent;
  uint8_t disable_migration;
  uint8_t original_connection_id_present;
  uint64_t max_ack_delay;
  uint8_t preferred_address_present;
} ngtcp2_transport_params;

/* user_data is the same object passed to ngtcp2_conn_client_new or
   ngtcp2_conn_server_new. */
typedef void (*ngtcp2_printf)(void *user_data, const char *format, ...);

typedef struct {
  ngtcp2_preferred_addr preferred_address;
  ngtcp2_tstamp initial_ts;
  /* log_printf is a function that the library uses to write logs.
     NULL means no logging output. */
  ngtcp2_printf log_printf;
  uint64_t max_stream_data_bidi_local;
  uint64_t max_stream_data_bidi_remote;
  uint64_t max_stream_data_uni;
  uint64_t max_data;
  uint64_t max_streams_bidi;
  uint64_t max_streams_uni;
  uint64_t idle_timeout;
  uint64_t max_packet_size;
  uint8_t stateless_reset_token[NGTCP2_STATELESS_RESET_TOKENLEN];
  uint8_t stateless_reset_token_present;
  uint64_t ack_delay_exponent;
  uint8_t disable_migration;
  uint64_t max_ack_delay;
  uint8_t preferred_address_present;
} ngtcp2_settings;

/**
 * @struct
 *
 * ngtcp2_rcvry_stat holds various statistics, and computed data for
 * recovery from packet loss.
 *
 * Everything is NGTCP2_DURATION_TICK resolution.
 */
typedef struct {
  ngtcp2_duration latest_rtt;
  ngtcp2_duration min_rtt;
  ngtcp2_duration max_ack_delay;
  double smoothed_rtt;
  double rttvar;
  ngtcp2_tstamp loss_time;
  size_t pto_count;
  size_t crypto_count;
  /* probe_pkt_left is the number of probe packet to sent */
  size_t probe_pkt_left;
  ngtcp2_tstamp loss_detection_timer;
  /* last_tx_pkt_ts corresponds to
     time_of_last_sent_ack_eliciting_packet in
     draft-ietf-quic-recovery-17. */
  ngtcp2_tstamp last_tx_pkt_ts;
  /* last_hs_tx_pkt_ts corresponds to
     time_of_last_sent_handshake_packet. */
  ngtcp2_tstamp last_hs_tx_pkt_ts;
} ngtcp2_rcvry_stat;

/**
 * @struct
 *
 * ngtcp2_addr is the endpoint address.
 */
typedef struct {
  /* len is the length of addr. */
  size_t addrlen;
  /* addr points to the buffer which contains endpoint address.  It is
     opaque to the ngtcp2 library. */
  uint8_t *addr;
  /* user_data is an arbitrary data and opaque to the library. */
  void *user_data;
} ngtcp2_addr;

/**
 * @struct
 *
 * ngtcp2_path is the network endpoints where a packet is sent and
 * received.
 */
typedef struct {
  /* local is the address of local endpoint. */
  ngtcp2_addr local;
  /* remote is the address of remote endpoint. */
  ngtcp2_addr remote;
} ngtcp2_path;

/**
 * @struct
 *
 * ngtcp2_path_storage is a convenient struct to have buffers to store
 * the longest addresses.
 */
typedef struct {
  uint8_t local_addrbuf[128];
  uint8_t remote_addrbuf[128];
  ngtcp2_path path;
} ngtcp2_path_storage;

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
 * :enum:`NGTCP2_ERR_INVALID_ARGUMENT`:
 *     |exttype| is invalid.
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
 * :enum:`NGTCP2_ERR_INVALID_ARGUMENT`:
 *     |exttype| is invalid.
 */
NGTCP2_EXTERN int
ngtcp2_decode_transport_params(ngtcp2_transport_params *params, uint8_t exttype,
                               const uint8_t *data, size_t datalen);

/**
 * @function
 *
 * `ngtcp2_pkt_decode_hd_long` decodes QUIC long packet header in
 * |pkt| of length |pktlen|.  This function only parses the input just
 * before packet number field.
 *
 * This function does not verify that length field is correct.  In
 * other words, this function succeeds even if length > |pktlen|.
 *
 * This function handles Version Negotiation specially.  If version
 * field is 0, |pkt| must contain Version Negotiation packet.  Version
 * Negotiation packet has random type in wire format.  For
 * convenience, this function sets
 * :enum:`NGTCP2_PKT_VERSION_NEGOTIATION` to dest->type, and set
 * dest->payloadlen and dest->pkt_num to 0.  Version Negotiation
 * packet occupies a single packet.
 *
 * It stores the result in the object pointed by |dest|, and returns
 * the number of bytes decoded to read the packet header if it
 * succeeds, or one of the following error codes:
 *
 * :enum:`NGTCP2_ERR_INVALID_ARGUMENT`
 *     Packet is too short; or it is not a long header
 * :enum:`NGTCP2_ERR_UNKNOWN_PKT_TYPE`
 *     Packet type is unknown
 */
NGTCP2_EXTERN ssize_t ngtcp2_pkt_decode_hd_long(ngtcp2_pkt_hd *dest,
                                                const uint8_t *pkt,
                                                size_t pktlen);

/**
 * @function
 *
 * `ngtcp2_pkt_decode_hd_short` decodes QUIC short packet header in
 * |pkt| of length |pktlen|.  |dcidlen| is the length of DCID in
 * packet header.  Short packet does not encode the length of
 * connection ID, thus we need the input from the outside.  This
 * function only parses the input just before packet number field.  It
 * stores the result in the object pointed by |dest|, and returns the
 * number of bytes decoded to read the packet header if it succeeds,
 * or one of the following error codes:
 *
 * :enum:`NGTCP2_ERR_INVALID_ARGUMENT`
 *     Packet is too short; or it is not a short header
 * :enum:`NGTCP2_ERR_UNKNOWN_PKT_TYPE`
 *     Packet type is unknown
 */
NGTCP2_EXTERN ssize_t ngtcp2_pkt_decode_hd_short(ngtcp2_pkt_hd *dest,
                                                 const uint8_t *pkt,
                                                 size_t pktlen, size_t dcidlen);

/**
 * @function
 *
 * `ngtcp2_pkt_decode_frame` decodes a QUIC frame from the buffer
 * pointed by |payload| whose length is |payloadlen|.
 *
 * This function returns the number of bytes read to decode a single
 * frame if it succeeds, or one of the following negative error codes:
 *
 * :enum:`NGTCP2_ERR_FRAME_ENCODING`
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
 * the buffer pointed by |dest| whose length is |destlen|.
 * |stateless_reset_token| is a pointer to the Stateless Reset Token,
 * and its length must be :macro:`NGTCP2_STATELESS_RESET_TOKENLEN`
 * bytes long.  |rand| specifies the random octets preceding Stateless
 * Reset Token.  The length of |rand| is specified by |randlen| which
 * must be at least :macro:`NGTCP2_MIN_STATELESS_RETRY_RANDLEN` bytes
 * long.
 *
 * If |randlen| is too long to write them all in the buffer, |rand| is
 * written to the buffer as much as possible, and is truncated.
 *
 * This function returns the number of bytes written to the buffer, or
 * one of the following negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOBUF`
 *     Buffer is too small.
 * :enum:`NGTCP2_ERR_INVALID_ARGUMENT`
 *     |randlen| is strictly less than
 *     :macro:`NGTCP2_MIN_STATELESS_RETRY_RANDLEN`.
 */
NGTCP2_EXTERN ssize_t ngtcp2_pkt_write_stateless_reset(
    uint8_t *dest, size_t destlen, uint8_t *stateless_reset_token,
    uint8_t *rand, size_t randlen);

/**
 * @function
 *
 * `ngtcp2_pkt_write_retry` writes Retry packet in the buffer pointed
 * by |dest| whose length is |destlen|.  |hd| must be long packet
 * header, and its type must be :enum:`NGTCP2_PKT_RETRY`.  |odcid|
 * specifies Original Destination Connection ID.  |token| specifies
 * Retry Token, and |tokenlen| specifies its length.
 *
 * This function returns the number of bytes written to the buffer, or
 * one of the following negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOBUF`
 *     Buffer is too small.
 */
NGTCP2_EXTERN ssize_t ngtcp2_pkt_write_retry(uint8_t *dest, size_t destlen,
                                             const ngtcp2_pkt_hd *hd,
                                             const ngtcp2_cid *odcid,
                                             const uint8_t *token,
                                             size_t tokenlen);

/**
 * @function
 *
 * `ngtcp2_pkt_write_version_negotiation` writes Version Negotiation
 * packet in the buffer pointed by |dest| whose length is |destlen|.
 * |unused_random| should be generated randomly.  |dcid| is the
 * destination connection ID which appears in a packet as a source
 * connection ID sent by client which caused version negotiation.
 * Similarly, |scid| is the source connection ID which appears in a
 * packet as a destination connection ID sent by client.  |sv| is a
 * list of supported versions, and |nsv| specifies the number of
 * supported versions included in |sv|.
 *
 * This function returns the number of bytes written to the buffer, or
 * one of the following negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOBUF`
 *     Buffer is too small.
 */
NGTCP2_EXTERN ssize_t ngtcp2_pkt_write_version_negotiation(
    uint8_t *dest, size_t destlen, uint8_t unused_random,
    const ngtcp2_cid *dcid, const ngtcp2_cid *scid, const uint32_t *sv,
    size_t nsv);

/**
 * @function
 *
 * `ngtcp2_pkt_get_type_long` returns the long packet type.  |c| is
 * the first byte of Long packet header.
 */
NGTCP2_EXTERN uint8_t ngtcp2_pkt_get_type_long(uint8_t c);

struct ngtcp2_conn;

typedef struct ngtcp2_conn ngtcp2_conn;

/**
 * @functypedef
 *
 * :type:`ngtcp2_client_initial` is invoked when client application
 * asks TLS stack to produce first TLS cryptographic handshake data.
 *
 * This implementation of this callback must get the first handshake
 * data from TLS stack and pass it to ngtcp2 library using
 * `ngtcp2_conn_submit_crypto_data` function.  Make sure that before
 * calling `ngtcp2_conn_submit_crypto_data` function, client
 * application must create initial packet protection keys and IVs, and
 * provide them to ngtcp2 library using
 * `ngtcp2_conn_set_initial_tx_keys` and
 * `ngtcp2_conn_set_initial_rx_keys`.
 *
 * This callback function must return 0 if it succeeds, or
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE` which makes the library call
 * return immediately.
 *
 * TODO: Define error code for TLS stack failure.  Suggestion:
 * NGTCP2_ERR_CRYPTO.
 */
typedef int (*ngtcp2_client_initial)(ngtcp2_conn *conn, void *user_data);

/**
 * @functypedef
 *
 * :type:`ngtcp2_recv_client_initial` is invoked when server receives
 * Initial packet from client.  An server application must implement
 * this callback, and generate initial keys and IVs for both
 * transmission and reception.  Install them using
 * `ngtcp2_conn_set_initial_tx_keys` and
 * `ngtcp2_conn_set_initial_rx_keys.  |dcid| is the destination
 * connection ID which client generated randomly.  It is used to
 * derive initial packet protection keys.
 *
 * The callback function must return 0 if it succeeds.  If an error
 * occurs, return :enum:`NGTCP2_ERR_CALLBACK_FAILURE` which makes the
 * library call return immediately.
 *
 * TODO: Define error code for TLS stack failure.  Suggestion:
 * NGTCP2_ERR_CRYPTO.
 */
typedef int (*ngtcp2_recv_client_initial)(ngtcp2_conn *conn,
                                          const ngtcp2_cid *dcid,
                                          void *user_data);

/**
 * @enum
 *
 * ngtcp2_crypto_level is encryption level.
 */
typedef enum {
  /**
   * NGTCP2_CRYPTO_LEVEL_INITIAL is Initial Keys encryption level.
   */
  NGTCP2_CRYPTO_LEVEL_INITIAL,
  /**
   * NGTCP2_CRYPTO_LEVEL_EARLY is Early Data (0-RTT) Keys encryption
   * level.
   */
  NGTCP2_CRYPTO_LEVEL_EARLY,
  /**
   * NGTCP2_CRYPTO_LEVEL_HANDSHAKE is Handshake Keys encryption level.
   */
  NGTCP2_CRYPTO_LEVEL_HANDSHAKE,
  /**
   * NGTCP2_CRYPTO_LEVEL_APP is Application Data (1-RTT) Keys
   * encryption level.
   */
  NGTCP2_CRYPTO_LEVEL_APP
} ngtcp2_crypto_level;

/**
 * @functypedef
 *
 * :type`ngtcp2_recv_crypto_data` is invoked when crypto data are
 * received.  The received data are pointed by |data|, and its length
 * is |datalen|.  The |offset| specifies the offset where |data| is
 * positioned.  |user_data| is the arbitrary pointer passed to
 * `ngtcp2_conn_client_new` or `ngtcp2_conn_server_new`.  The ngtcp2
 * library ensures that the crypto data is passed to the application
 * in the increasing order of |offset|.  |datalen| is always strictly
 * greater than 0.  |crypto_level| indicates the encryption level
 * where this data is received.  Crypto data never be received in
 * :enum:`NGTCP2_CRYPTO_LEVEL_EARLY`.
 *
 * The application should provide the given data to TLS stack.
 *
 * The callback function must return 0 if it succeeds.  If TLS stack
 * reported error, return :enum:`NGTCP2_ERR_CRYPTO`.  If application
 * encounters fatal error, return :enum:`NGTCP2_ERR_CALLBACK_FAILURE`
 * which makes the library call return immediately.  If the other
 * value is returned, it is treated as
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*ngtcp2_recv_crypto_data)(ngtcp2_conn *conn,
                                       ngtcp2_crypto_level crypto_level,
                                       uint64_t offset, const uint8_t *data,
                                       size_t datalen, void *user_data);

/**
 * @functypedef
 *
 * :type:`ngtcp2_handshake_completed` is invoked when QUIC
 * cryptographic handshake has completed.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*ngtcp2_handshake_completed)(ngtcp2_conn *conn, void *user_data);

/**
 * @functypedef
 *
 * :type:`ngtcp2_recv_version_negotiation` is invoked when Version
 * Negotiation packet is received.  |hd| is the pointer to the QUIC
 * packet header object.  The vector |sv| of |nsv| elements contains
 * the QUIC version the server supports.  Since Version Negotiation is
 * only sent by server, this callback function is used by client only.
 *
 * The callback function must return 0 if it succeeds, or
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE` which makes the library call
 * return immediately.
 */
typedef int (*ngtcp2_recv_version_negotiation)(ngtcp2_conn *conn,
                                               const ngtcp2_pkt_hd *hd,
                                               const uint32_t *sv, size_t nsv,
                                               void *user_data);

/**
 * @functypedef
 *
 * :type:`ngtcp2_recv_retry` is invoked when Retry packet is received.
 * This callback is client only.
 *
 * Application must regenerate packet protection key, IV, and header
 * protection key for Initial packets using the destination connection
 * ID obtained by `ngtcp2_conn_get_dcid()` and install them by calling
 * `ngtcp2_conn_install_initial_tx_keys()` and
 * `ngtcp2_conn_install_initial_rx_keys()`.
 *
 * 0-RTT data accepted by the ngtcp2 library will be retransmitted by
 * the library automatically.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*ngtcp2_recv_retry)(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                                 const ngtcp2_pkt_retry *retry,
                                 void *user_data);

/**
 * @functypedef
 *
 * :type:`ngtcp2_encrypt` is invoked when the ngtcp2 library asks the
 * application to encrypt packet payload.  The packet payload to
 * encrypt is passed as |plaintext| of length |plaintextlen|.  The
 * encryption key is passed as |key| of length |keylen|.  The nonce is
 * passed as |nonce| of length |noncelen|.  The ad, Additional Data to
 * AEAD, is passed as |ad| of length |adlen|.
 *
 * The implementation of this callback must encrypt |plaintext| using
 * the negotiated cipher suite and write the ciphertext into the
 * buffer pointed by |dest| of length |destlen|.
 *
 * |dest| and |plaintext| may point to the same buffer.
 *
 * The callback function must return the number of bytes written to
 * |dest|, or :enum:`NGTCP2_ERR_CALLBACK_FAILURE` which makes the
 * library call return immediately.
 */
typedef ssize_t (*ngtcp2_encrypt)(ngtcp2_conn *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *plaintext,
                                  size_t plaintextlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *nonce,
                                  size_t noncelen, const uint8_t *ad,
                                  size_t adlen, void *user_data);

/**
 * @functypedef
 *
 * :type:`ngtcp2_decrypt` is invoked when the ngtcp2 library asks the
 * application to decrypt packet payload.  The packet payload to
 * decrypt is passed as |ciphertext| of length |ciphertextlen|.  The
 * decryption key is passed as |key| of length |keylen|.  The nonce is
 * passed as |nonce| of length |noncelen|.  The ad, Additional Data to
 * AEAD, is passed as |ad| of length |adlen|.
 *
 * The implementation of this callback must decrypt |ciphertext| using
 * the negotiated cipher suite and write the ciphertext into the
 * buffer pointed by |dest| of length |destlen|.
 *
 * |dest| and |ciphertext| may point to the same buffer.
 *
 * The callback function must return the number of bytes written to
 * |dest|.  If TLS stack fails to decrypt data, return
 * :enum:`NGTCP2_ERR_TLS_DECRYPT`.  For any other errors, return
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE` which makes the library call
 * return immediately.
 */
typedef ssize_t (*ngtcp2_decrypt)(ngtcp2_conn *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *ciphertext,
                                  size_t ciphertextlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *nonce,
                                  size_t noncelen, const uint8_t *ad,
                                  size_t adlen, void *user_data);

/**
 * @functypedef
 *
 * :type:`ngtcp2_hp_mask` is invoked when the ngtcp2 library asks the
 * application to produce mask to encrypt or decrypt packet header.
 * The key is passed as |key| of length |keylen|.  The sample is
 * passed as |sample| of length |samplelen|.
 *
 * The implementation of this callback must produce a mask using the
 * header protection cipher suite specified by QUIC specification and
 * write the result into the buffer pointed by |dest| of length
 * |destlen|.  The length of mask must be at least
 * :macro:`NGTCP2_HP_MASKLEN`.  The library ensures that |destlen| is
 * at least :macro:`NGTCP2_HP_MASKLEN`.
 *
 * The callback function must return the number of bytes written to
 * |dest|, or :enum:`NGTCP2_ERR_CALLBACK_FAILURE` which makes the
 * library call return immediately.
 */
typedef ssize_t (*ngtcp2_hp_mask)(ngtcp2_conn *conn, uint8_t *dest,
                                  size_t destlen, const uint8_t *key,
                                  size_t keylen, const uint8_t *sample,
                                  size_t samplelen, void *user_data);

/**
 * @functypedef
 *
 * :type:`ngtcp2_recv_stream_data` is invoked when stream data is
 * received.  The stream is specified by |stream_id|.  If |fin| is
 * nonzero, this portion of the data is the last data in this stream.
 * |offset| is the offset where this data begins.  The library ensures
 * that data is passed to the application in the non-decreasing order
 * of |offset|.  The data is passed as |data| of length |datalen|.
 * |datalen| may be 0 if and only if |fin| is nonzero.
 *
 * The callback function must return 0 if it succeeds, or
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE` which makes the library return
 * immediately.
 */
typedef int (*ngtcp2_recv_stream_data)(ngtcp2_conn *conn, int64_t stream_id,
                                       int fin, uint64_t offset,
                                       const uint8_t *data, size_t datalen,
                                       void *user_data, void *stream_user_data);

/**
 * @functypedef
 *
 * :type:`ngtcp2_stream_open` is a callback function which is called
 * when remote stream is opened by peer.  This function is not called
 * if stream is opened by implicitly (we might reconsider this
 * behaviour).
 *
 * The implementation of this callback should return 0 if it succeeds.
 * Returning :enum:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library
 * call return immediately.
 */
typedef int (*ngtcp2_stream_open)(ngtcp2_conn *conn, int64_t stream_id,
                                  void *user_data);

/**
 * @functypedef
 *
 * :type:`ngtcp2_stream_close` is invoked when a stream is closed.
 * This callback is not called when QUIC connection is closed before
 * existing streams are closed.  |app_error_code| indicates the error
 * code of this closure.
 *
 * The implementation of this callback should return 0 if it succeeds.
 * Returning :enum:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library
 * call return immediately.
 */
typedef int (*ngtcp2_stream_close)(ngtcp2_conn *conn, int64_t stream_id,
                                   uint16_t app_error_code, void *user_data,
                                   void *stream_user_data);

/**
 * @functypedef
 *
 * :type:`ngtcp2_stream_reset` is invoked when a stream identified by
 * |stream_id| is reset by a remote endpoint.
 *
 * The implementation of this callback should return 0 if it succeeds.
 * Returning :enum:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library
 * call return immediately.
 */
typedef int (*ngtcp2_stream_reset)(ngtcp2_conn *conn, int64_t stream_id,
                                   uint64_t final_size, uint16_t app_error_code,
                                   void *user_data, void *stream_user_data);

/**
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
 *
 * If a stream is closed prematurely and stream data is still
 * in-flight, this callback function is not called for those data.
 *
 * The implementation of this callback should return 0 if it succeeds.
 * Returning :enum:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library
 * call return immediately.
 */
typedef int (*ngtcp2_acked_stream_data_offset)(ngtcp2_conn *conn,
                                               int64_t stream_id,
                                               uint64_t offset, size_t datalen,
                                               void *user_data,
                                               void *stream_user_data);

/**
 * @functypedef
 *
 * :type:`ngtcp2_acked_crypto_offset` is a callback function which is
 * called when crypto stream data is acknowledged, and application can
 * free the data.  This works like
 * :type:`ngtcp2_acked_stream_data_offset` but crypto stream has no
 * stream_id and stream_user_data, and |datalen| never become 0.
 *
 * The implementation of this callback should return 0 if it succeeds.
 * Returning :enum:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library
 * call return immediately.
 */
typedef int (*ngtcp2_acked_crypto_offset)(ngtcp2_conn *conn, uint64_t offset,
                                          size_t datalen, void *user_data);

/**
 * @functypedef
 *
 * :type:`ngtcp2_recv_stateless_reset` is a callback function which is
 * called when Stateless Reset packet is received.  The |hd| is the
 * packet header, and the stateless reset details are given in |sr|.
 *
 * The implementation of this callback should return 0 if it succeeds.
 * Returning :enum:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library
 * call return immediately.
 */
typedef int (*ngtcp2_recv_stateless_reset)(ngtcp2_conn *conn,
                                           const ngtcp2_pkt_hd *hd,
                                           const ngtcp2_pkt_stateless_reset *sr,
                                           void *user_data);

/**
 * @functypedef
 *
 * :type:`ngtcp2_extend_max_streams` is a callback function which is
 * called every time max stream ID is strictly extended.
 * |max_streams| is the cumulative number of streams which an endpoint
 * can open.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*ngtcp2_extend_max_streams)(ngtcp2_conn *conn,
                                         uint64_t max_streams, void *user_data);

/**
 * @functypedef
 *
 * :type:`ngtcp2_rand` is a callback function to get randomized byte
 * string from application.  Application must fill random |destlen|
 * bytes to the buffer pointed by |dest|.  |ctx| provides the context
 * how the provided random byte string is used.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*ngtcp2_rand)(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                           ngtcp2_rand_ctx ctx, void *user_data);

/**
 * @functypedef
 *
 * :type:`ngtcp2_get_new_connection_id` is a callback function to ask
 * an application for new connection ID.  Application must generate
 * new unused connection ID with the exact |cidlen| bytes and store it
 * in |cid|.  It also has to generate stateless reset token into
 * |token|.  The length of stateless reset token is
 * :macro:`NGTCP2_STATELESS_RESET_TOKENLEN` and it is guaranteed that
 * the buffer pointed by |cid| has the sufficient space to store the
 * token.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*ngtcp2_get_new_connection_id)(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                            uint8_t *token, size_t cidlen,
                                            void *user_data);

/**
 * @functypedef
 *
 * :type:`ngtcp2_remove_connection_id` is a callback function which
 * notifies the application that connection ID |cid| is no longer used
 * by remote endpoint.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*ngtcp2_remove_connection_id)(ngtcp2_conn *conn,
                                           const ngtcp2_cid *cid,
                                           void *user_data);

/**
 * @functypedef
 *
 * :type:`ngtcp2_update_key` is a callback function which tells the
 * application that it should update and install new keys.
 *
 * In the callback function, the application has to generate new keys
 * for both encryption and decryption, and install them to |conn|
 * using `ngtcp2_conn_update_tx_key` and `ngtcp2_conn_update_rx_key`.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*ngtcp2_update_key)(ngtcp2_conn *conn, void *user_data);

/**
 * @functypedef
 *
 * :type:`ngtcp2_path_validation` is a callback function which tells
 * the application the outcome of path validation.  |path| is the path
 * that was validated.  If |res| is
 * :enum:`NGTCP2_PATH_VALIDATION_RESULT_SUCCESS`, the path validation
 * succeeded.  If |res| is
 * :enum:`NGTCP2_PATH_VALIDATION_RESULT_FAILURE`, the path validation
 * failed.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*ngtcp2_path_validation)(ngtcp2_conn *conn,
                                      const ngtcp2_path *path,
                                      ngtcp2_path_validation_result res,
                                      void *user_data);

/**
 * @functypedef
 *
 * :type:`ngtcp2_select_preferred_addr` is a callback function which
 * asks a client application to choose server address from preferred
 * addresses |paddr| received from server.  An application should
 * write preferred address in |dest|.  If an application denies the
 * preferred addresses, just leave |dest| unmodified (or set dest->len
 * to 0) and return 0.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*ngtcp2_select_preferred_addr)(ngtcp2_conn *conn,
                                            ngtcp2_addr *dest,
                                            const ngtcp2_preferred_addr *paddr,
                                            void *user_data);

typedef struct {
  ngtcp2_client_initial client_initial;
  ngtcp2_recv_client_initial recv_client_initial;
  ngtcp2_recv_crypto_data recv_crypto_data;
  ngtcp2_handshake_completed handshake_completed;
  ngtcp2_recv_version_negotiation recv_version_negotiation;
  /**
   * in_encrypt is a callback function which is invoked to encrypt
   * Initial packets.
   */
  ngtcp2_encrypt in_encrypt;
  /**
   * in_decrypt is a callback function which is invoked to decrypt
   * Initial packets.
   */
  ngtcp2_decrypt in_decrypt;
  /**
   * encrypt is a callback function which is invoked to encrypt
   * packets other than Initial packets.
   */
  ngtcp2_encrypt encrypt;
  /**
   * decrypt is a callback function which is invoked to decrypt
   * packets other than Initial packets.
   */
  ngtcp2_decrypt decrypt;
  /**
   * in_hp_mask is a callback function which is invoked to get mask to
   * encrypt or decrypt Initial packet header.
   */
  ngtcp2_hp_mask in_hp_mask;
  /**
   * hp_mask is a callback function which is invoked to get mask to
   * encrypt or decrypt packet header other than Initial packets.
   */
  ngtcp2_hp_mask hp_mask;
  ngtcp2_recv_stream_data recv_stream_data;
  ngtcp2_acked_crypto_offset acked_crypto_offset;
  ngtcp2_acked_stream_data_offset acked_stream_data_offset;
  ngtcp2_stream_open stream_open;
  ngtcp2_stream_close stream_close;
  ngtcp2_recv_stateless_reset recv_stateless_reset;
  ngtcp2_recv_retry recv_retry;
  ngtcp2_extend_max_streams extend_max_local_streams_bidi;
  ngtcp2_extend_max_streams extend_max_local_streams_uni;
  ngtcp2_rand rand;
  ngtcp2_get_new_connection_id get_new_connection_id;
  ngtcp2_remove_connection_id remove_connection_id;
  ngtcp2_update_key update_key;
  ngtcp2_path_validation path_validation;
  ngtcp2_select_preferred_addr select_preferred_addr;
  ngtcp2_stream_reset stream_reset;
  ngtcp2_extend_max_streams extend_max_remote_streams_bidi;
  ngtcp2_extend_max_streams extend_max_remote_streams_uni;
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

/**
 * @function
 *
 * `ngtcp2_conn_client_new` creates new :type:`ngtcp2_conn`, and
 * initializes it as client.  |dcid| is randomized destination
 * connection ID.  |scid| is source connection ID.  |version| is a
 * QUIC version to use.  |path| is the network path where this QUIC
 * connection is being established.  |callbacks|, and |settings| must
 * not be NULL, and the function make a copy of each of them.
 * |user_data| is the arbitrary pointer which is passed to the
 * user-defined callback functions.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOMEM`
 *     Out of memory.
 */
NGTCP2_EXTERN int
ngtcp2_conn_client_new(ngtcp2_conn **pconn, const ngtcp2_cid *dcid,
                       const ngtcp2_cid *scid, const ngtcp2_path *path,
                       uint32_t version, const ngtcp2_conn_callbacks *callbacks,
                       const ngtcp2_settings *settings, void *user_data);

/**
 * @function
 *
 * `ngtcp2_conn_server_new` creates new :type:`ngtcp2_conn`, and
 * initializes it as server.  |dcid| is a destination connection ID.
 * |scid| is a source connection ID.  |path| is the network path where
 * this QUIC connection is being established.  |version| is a QUIC
 * version to use.  |callbacks|, and |settings| must not be NULL, and
 * the function make a copy of each of them.  |user_data| is the
 * arbitrary pointer which is passed to the user-defined callback
 * functions.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOMEM`
 *     Out of memory.
 */
NGTCP2_EXTERN int
ngtcp2_conn_server_new(ngtcp2_conn **pconn, const ngtcp2_cid *dcid,
                       const ngtcp2_cid *scid, const ngtcp2_path *path,
                       uint32_t version, const ngtcp2_conn_callbacks *callbacks,
                       const ngtcp2_settings *settings, void *user_data);

/**
 * @function
 *
 * `ngtcp2_conn_del` frees resources allocated for |conn|.  It also
 * frees memory pointed by |conn|.
 */
NGTCP2_EXTERN void ngtcp2_conn_del(ngtcp2_conn *conn);

/**
 * @function
 *
 * `ngtcp2_conn_read_handshake` performs QUIC cryptographic handshake
 * by reading given data.  |pkt| points to the buffer to read and
 * |pktlen| is the length of the buffer.  |path| is the network path.
 *
 * The application should call `ngtcp2_conn_write_handshake` (or
 * `ngtcp2_conn_client_write_handshake` for client session) to make
 * handshake go forward after calling this function.
 *
 * Application should call this function until
 * `ngtcp2_conn_get_handshake_completed` returns nonzero.  After the
 * completion of handshake, `ngtcp2_conn_read_pkt` and
 * `ngtcp2_conn_write_pkt` should be called instead.
 *
 * This function must not be called from inside the callback
 * functions.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes: (TBD).
 */
NGTCP2_EXTERN int ngtcp2_conn_read_handshake(ngtcp2_conn *conn,
                                             const ngtcp2_path *path,
                                             const uint8_t *pkt, size_t pktlen,
                                             ngtcp2_tstamp ts);

/**
 * @function
 *
 * `ngtcp2_conn_write_handshake` performs QUIC cryptographic handshake
 * by writing handshake packets.  It may write a packet in the given
 * buffer pointed by |dest| whose capacity is given as |destlen|.
 * Application must ensure that the buffer pointed by |dest| is not
 * empty.
 *
 * Application should keep calling this function repeatedly until it
 * returns zero, or negative error code.
 *
 * Application should call this function until
 * `ngtcp2_conn_get_handshake_completed` returns nonzero.  After the
 * completion of handshake, `ngtcp2_conn_read_pkt` and
 * `ngtcp2_conn_write_pkt` should be called instead.
 *
 * During handshake, application can send 0-RTT data (or its response)
 * using `ngtcp2_conn_write_stream`.
 * `ngtcp2_conn_client_write_handshake` is generally efficient because
 * it can coalesce Handshake packet and 0-RTT packet into one UDP
 * packet.
 *
 * This function returns 0 if it cannot write any frame because buffer
 * is too small, or packet is congestion limited.  Application should
 * keep reading and wait for congestion window to grow.
 *
 * This function must not be called from inside the callback
 * functions.
 *
 * This function returns the number of bytes written to the buffer
 * pointed by |dest| if it succeeds, or one of the following negative
 * error codes: (TBD).
 */
NGTCP2_EXTERN ssize_t ngtcp2_conn_write_handshake(ngtcp2_conn *conn,
                                                  uint8_t *dest, size_t destlen,
                                                  ngtcp2_tstamp ts);

/**
 * @function
 *
 * `ngtcp2_conn_client_write_handshake` is just like
 * `ngtcp2_conn_write_handshake`, but it is for client only, and can
 * write 0-RTT data.  This function can coalesce handshake packet and
 * 0-RTT packet into single UDP packet, thus it is generally more
 * efficient than the combination of `ngtcp2_conn_write_handshake` and
 * `ngtcp2_conn_write_stream`.
 *
 * |stream_id|, |fin|, |datav|, and |datavcnt| are stream identifier
 * to which 0-RTT data is sent, whether it is a last data chunk in
 * this stream, a vector of 0-RTT data, and its number of elements
 * respectively.  If there is no 0RTT data to send, pass negative
 * integer to |stream_id|.  The amount of 0RTT data sent is assigned
 * to |*pdatalen|.  If no data is sent, -1 is assigned.  Note that 0
 * length STREAM frame is allowed in QUIC, so 0 might be assigned to
 * |*pdatalen|.
 *
 * This function returns 0 if it cannot write any frame because buffer
 * is too small, or packet is congestion limited.  Application should
 * keep reading and wait for congestion window to grow.
 *
 * This function returns the number of bytes written to the buffer
 * pointed by |dest| if it succeeds, or one of the following negative
 * error codes: (TBD).
 */
NGTCP2_EXTERN ssize_t ngtcp2_conn_client_write_handshake(
    ngtcp2_conn *conn, uint8_t *dest, size_t destlen, ssize_t *pdatalen,
    int64_t stream_id, uint8_t fin, const ngtcp2_vec *datav, size_t datavcnt,
    ngtcp2_tstamp ts);

/**
 * @function
 *
 * `ngtcp2_conn_read_pkt` decrypts QUIC packet given in |pkt| of
 * length |pktlen| and processes it.  |path| is the network path the
 * packet is delivered.  This function must be called after QUIC
 * handshake has finished successfully.
 *
 * This function must not be called from inside the callback
 * functions.
 *
 * This function returns 0 if it succeeds, or negative error codes.
 * In general, if the error code which satisfies
 * ngtcp2_erro_is_fatal(err) != 0 is returned, the application should
 * just close the connection by calling
 * `ngtcp2_conn_write_connection_close` or just delete the QUIC
 * connection using `ngtcp2_conn_del`.  It is undefined to call the
 * other library functions.
 */
NGTCP2_EXTERN int ngtcp2_conn_read_pkt(ngtcp2_conn *conn,
                                       const ngtcp2_path *path,
                                       const uint8_t *pkt, size_t pktlen,
                                       ngtcp2_tstamp ts);

/**
 * @function
 *
 * `ngtcp2_conn_write_pkt` writes a QUIC packet in the buffer pointed
 * by |dest| whose length is |destlen|.  |ts| is the timestamp of the
 * current time.
 *
 * If |path| is not NULL, this function stores the network path with
 * which the packet should be sent.  Each addr field must point to the
 * buffer which is at least 128 bytes.  ``sizeof(struct
 * sockaddr_storage)`` is enough.  The assignment might not be done if
 * nothing is written to |dest|.
 *
 * If there is no packet to send, this function returns 0.
 *
 * Application should keep calling this function repeatedly until it
 * returns zero, or negative error code.
 *
 * This function returns 0 if it cannot write any frame because buffer
 * is too small, or packet is congestion limited.  Application should
 * keep reading and wait for congestion window to grow.
 *
 * This function must not be called from inside the callback
 * functions.
 *
 * This function returns the number of bytes written in |dest| if it
 * succeeds, or one of the following negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE`
 *     User-defined callback function failed.
 * :enum:`NGTCP2_ERR_PKT_NUM_EXHAUSTED`
 *     The packet number has reached at the maximum value, therefore
 *     the function cannot make new packet on this connection.
 *
 * In general, if the error code which satisfies
 * ngtcp2_erro_is_fatal(err) != 0 is returned, the application should
 * just close the connection by calling
 * `ngtcp2_conn_write_connection_close` or just delete the QUIC
 * connection using `ngtcp2_conn_del`.  It is undefined to call the
 * other library functions.
 */
NGTCP2_EXTERN ssize_t ngtcp2_conn_write_pkt(ngtcp2_conn *conn,
                                            ngtcp2_path *path, uint8_t *dest,
                                            size_t destlen, ngtcp2_tstamp ts);

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
 * `ngtcp2_conn_get_handshake_completed` returns nonzero if handshake
 * has completed.
 */
NGTCP2_EXTERN int ngtcp2_conn_get_handshake_completed(ngtcp2_conn *conn);

/**
 * @function
 *
 * `ngtcp2_conn_install_initial_tx_keys` installs packet protection
 * key |key| of length |keylen| and IV |iv| of length |ivlen|, and
 * packet header protection key |hp| of length |hplen| to encrypt
 * outgoing Initial packets.  If they have already been set, they are
 * overwritten.
 *
 * After receiving Retry packet, the DCID most likely changes.  In
 * that case, client application must generate these keying materials
 * again based on new DCID and install them again.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOMEM`
 *     Out of memory.
 */
NGTCP2_EXTERN int ngtcp2_conn_install_initial_tx_keys(
    ngtcp2_conn *conn, const uint8_t *key, size_t keylen, const uint8_t *iv,
    size_t ivlen, const uint8_t *hp, size_t hplen);

/**
 * @function
 *
 * `ngtcp2_conn_install_initial_rx_keys` installs packet protection
 * key |key| of length |keylen| and IV |iv| of length |ivlen|, and
 * packet header protection key |hp| of length |hplen| to decrypt
 * incoming Initial packets.  If they have already been set, they are
 * overwritten.
 *
 * After receiving Retry packet, the DCID most likely changes.  In
 * that case, client application must generate these keying materials
 * again based on new DCID and install them again.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOMEM`
 *     Out of memory.
 */
NGTCP2_EXTERN int ngtcp2_conn_install_initial_rx_keys(
    ngtcp2_conn *conn, const uint8_t *key, size_t keylen, const uint8_t *iv,
    size_t ivlen, const uint8_t *hp, size_t hplen);

/**
 * @function
 *
 * `ngtcp2_conn_install_handshake_tx_keys` installs packet protection
 * key |key| of length |keylen| and IV |iv| of length |ivlen|, and
 * packet header protection key |hp| of length |hplen| to encrypt
 * outgoing Handshake packets.
 *
 * TLS stack generates the packet protection key and IV, and therefore
 * application don't have to generate them.  For client, they are
 * derived from client_handshake_traffic_secret.  For server, they are
 * derived from server_handshake_traffic_secret.  The packet number
 * encryption key must be generated using the method described in QUIC
 * specification.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGTCP2_ERR_INVALID_STATE`
 *     Keying materials have already been installed.
 */
NGTCP2_EXTERN int ngtcp2_conn_install_handshake_tx_keys(
    ngtcp2_conn *conn, const uint8_t *key, size_t keylen, const uint8_t *iv,
    size_t ivlen, const uint8_t *hp, size_t hplen);

/**
 * @function
 *
 * `ngtcp2_conn_install_handshake_rx_keys` installs packet protection
 * key |key| of length |keylen| and IV |iv| of length |ivlen|, and
 * packet header protection key |hp| of length |hplen| to decrypt
 * incoming Handshake packets.
 *
 * TLS stack generates the packet protection key and IV, and therefore
 * application don't have to generate them.  For client, they are
 * derived from server_handshake_traffic_secret.  For server, they are
 * derived from client_handshake_traffic_secret.  The packet number
 * encryption key must be generated using the method described in QUIC
 * specification.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGTCP2_ERR_INVALID_STATE`
 *     Keying materials have already been installed.
 */
NGTCP2_EXTERN int ngtcp2_conn_install_handshake_rx_keys(
    ngtcp2_conn *conn, const uint8_t *key, size_t keylen, const uint8_t *iv,
    size_t ivlen, const uint8_t *hp, size_t hplen);

/**
 * @function
 *
 * `ngtcp2_conn_set_aead_overhead` tells the ngtcp2 library the length
 * of AEAD tag which the negotiated cipher suites defines.  This
 * function must be called before encrypting or decrypting the
 * incoming packets other than Initial packets.
 */
NGTCP2_EXTERN void ngtcp2_conn_set_aead_overhead(ngtcp2_conn *conn,
                                                 size_t aead_overhead);

/**
 * @function
 *
 * `ngtcp2_conn_install_early_rx_keys` installs packet protection key
 * |key| of length |keylen| and IV |iv| of length |ivlen|, and packet
 * header protection key |hp| of length |hplen| to encrypt or decrypt
 * 0RTT packets.
 *
 * TLS stack generates the packet protection key and IV, and therefore
 * application don't have to generate them.  They are derived from
 * client_early_traffic_secret.  The packet number encryption key must
 * be generated using the method described in QUIC specification.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGTCP2_ERR_INVALID_STATE`
 *     Keying materials have already been installed.
 */
NGTCP2_EXTERN int
ngtcp2_conn_install_early_keys(ngtcp2_conn *conn, const uint8_t *key,
                               size_t keylen, const uint8_t *iv, size_t ivlen,
                               const uint8_t *hp, size_t hplen);

/**
 * @function
 *
 * `ngtcp2_conn_install_tx_keys` installs packet protection key |key|
 * of length |keylen| and IV |iv| of length |ivlen|, and packet header
 * protection key |hp| of length |hplen| to encrypt outgoing Short
 * packets.
 *
 * TLS stack generates the packet protection key and IV, and therefore
 * application don't have to generate them.  For client, they are
 * derived from client_application_traffic_secret.  For server, they
 * are derived from server_application_traffic_secret.  The packet
 * number encryption key must be generated using the method described
 * in QUIC specification.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGTCP2_ERR_INVALID_STATE`
 *     Keying materials have already been installed.
 */
NGTCP2_EXTERN int ngtcp2_conn_install_tx_keys(ngtcp2_conn *conn,
                                              const uint8_t *key, size_t keylen,
                                              const uint8_t *iv, size_t ivlen,
                                              const uint8_t *hp, size_t hplen);

/**
 * @function
 *
 * `ngtcp2_conn_install_rx_keys` installs packet protection key |key|
 * of length |keylen| and IV |iv| of length |ivlen|, and packet header
 * protection key |hp| of length |hplen| to decrypt incoming Short
 * packets.
 *
 * TLS stack generates the packet protection key and IV, and therefore
 * application don't have to generate them.  For client, they are
 * derived from server_application_traffic_secret.  For server, they
 * are derived from client_application_traffic_secret.  The packet
 * number encryption key must be generated using the method described
 * in QUIC specification.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGTCP2_ERR_INVALID_STATE`
 *     Keying materials have already been installed.
 */
NGTCP2_EXTERN int ngtcp2_conn_install_rx_keys(ngtcp2_conn *conn,
                                              const uint8_t *key, size_t keylen,
                                              const uint8_t *iv, size_t ivlen,
                                              const uint8_t *hp, size_t hplen);

/**
 * @function
 *
 * `ngtcp2_conn_update_tx_key` installs the updated packet protection
 * key |key| of length |keylen| and IV |iv| of length |ivlen|.  They
 * are used to encrypt an outgoing packet.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGTCP2_ERR_INVALID_STATE`
 *     The updated keying materials have not been synchronized yet.
 */
NGTCP2_EXTERN int ngtcp2_conn_update_tx_key(ngtcp2_conn *conn,
                                            const uint8_t *key, size_t keylen,
                                            const uint8_t *iv, size_t ivlen);

/**
 * @function
 *
 * `ngtcp2_conn_update_rx_key` installs the updated packet protection
 * key |key| of length |keylen| and IV |iv| of length |ivlen|.  They
 * are used to decrypt an incoming packet.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGTCP2_ERR_INVALID_STATE`
 *     The updated keying materials have not been synchronized yet.
 */
NGTCP2_EXTERN int ngtcp2_conn_update_rx_key(ngtcp2_conn *conn,
                                            const uint8_t *key, size_t keylen,
                                            const uint8_t *iv, size_t ivlen);

/**
 * @function
 *
 * `ngtcp2_conn_initiate_key_update` initiates the key update.  Prior
 * to calling this function, the application has to install updated
 * keys using `ngtcp2_conn_update_tx_key` and
 * `ngtcp2_conn_update_rx_key`.
 *
 * Do not call this function if the local endpoint updates key in
 * response to the key update of the remote endpoint.  In other words,
 * don't call this function inside :type:`ngtcp2_update_key` callback
 * function.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_INVALID_STATE`
 *     The updated keying materials have not been synchronized yet; or
 *     updated keys are not available.
 */
NGTCP2_EXTERN int ngtcp2_conn_initiate_key_update(ngtcp2_conn *conn);

/**
 * @function
 *
 * `ngtcp2_conn_loss_detection_expiry` returns the expiry time point
 * of loss detection timer.  Application should call
 * `ngtcp2_conn_on_loss_detection_timer` and `ngtcp2_conn_write_pkt`
 * (or `ngtcp2_conn_write_handshake` if handshake has not finished
 * yet) when it expires.  It returns UINT64_MAX if loss detection
 * timer is not armed.
 */
NGTCP2_EXTERN ngtcp2_tstamp
ngtcp2_conn_loss_detection_expiry(ngtcp2_conn *conn);

/**
 * @function
 *
 * `ngtcp2_conn_ack_delay_expiry` returns the expiry time point of
 * delayed protected ACK.  Application should call
 * `ngtcp2_conn_write_pkt` (or `ngtcp2_conn_write_handshake` if
 * handshake has not finished yet) when it expires.  It returns
 * UINT64_MAX if there is no expiry.
 */
NGTCP2_EXTERN ngtcp2_tstamp ngtcp2_conn_ack_delay_expiry(ngtcp2_conn *conn);

/**
 * @function
 *
 * `ngtcp2_conn_get_expiry` returns the next expiry time.  This
 * function returns the timestamp such that
 * min(ngtcp2_conn_loss_detection_expiry(conn),
 * ngtcp2_conn_ack_delay_expiry(conn)).
 */
NGTCP2_EXTERN ngtcp2_tstamp ngtcp2_conn_get_expiry(ngtcp2_conn *conn);

/**
 * @function
 *
 * `ngtcp2_conn_set_remote_transport_params` sets transport parameter
 * |params| to |conn|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_PROTO`
 *     If |conn| is server, and negotiated_version field is not the
 *     same as the used version.
 */
NGTCP2_EXTERN int
ngtcp2_conn_set_remote_transport_params(ngtcp2_conn *conn,
                                        const ngtcp2_transport_params *params);

/**
 * @function
 *
 * `ngtcp2_conn_set_early_remote_transport_params` sets |params| as
 * transport parameter previously received from a server.  The
 * parameters are used to send 0-RTT data.  QUIC requires that client
 * application should remember transport parameter as well as session
 * ticket.
 *
 * At least following fields must be set:
 *
 * * initial_max_stream_id_bidi
 * * initial_max_stream_id_uni
 * * initial_max_stream_data_bidi_local
 * * initial_max_stream_data_bidi_remote
 * * initial_max_stream_data_uni
 * * initial_max_data
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_INVALID_STATE`
 *     |conn| is initialized as a server.
 */
NGTCP2_EXTERN int ngtcp2_conn_set_early_remote_transport_params(
    ngtcp2_conn *conn, const ngtcp2_transport_params *params);

/**
 * @function
 *
 * `ngtcp2_conn_get_local_transport_params` fills settings values in
 * |params|.
 */
NGTCP2_EXTERN void
ngtcp2_conn_get_local_transport_params(ngtcp2_conn *conn,
                                       ngtcp2_transport_params *params);

/**
 * @function
 *
 * `ngtcp2_conn_open_bidi_stream` opens new bidirectional stream.  The
 * |stream_user_data| is the user data specific to the stream.  The
 * open stream ID is stored in |*pstream_id|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOMEM`
 *     Out of memory
 * :enum:`NGTCP2_ERR_STREAM_ID_BLOCKED`
 *     The remote peer does not allow |stream_id| yet.
 */
NGTCP2_EXTERN int ngtcp2_conn_open_bidi_stream(ngtcp2_conn *conn,
                                               int64_t *pstream_id,
                                               void *stream_user_data);

/**
 * @function
 *
 * `ngtcp2_conn_open_uni_stream` opens new unidirectional stream.  The
 * |stream_user_data| is the user data specific to the stream.  The
 * open stream ID is stored in |*pstream_id|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOMEM`
 *     Out of memory
 * :enum:`NGTCP2_ERR_STREAM_ID_BLOCKED`
 *     The remote peer does not allow |stream_id| yet.
 */
NGTCP2_EXTERN int ngtcp2_conn_open_uni_stream(ngtcp2_conn *conn,
                                              int64_t *pstream_id,
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
 *     |stream_id| is 0
 * :enum:`NGTCP2_ERR_STREAM_NOT_FOUND`
 *     Stream does not exist
 */
NGTCP2_EXTERN int ngtcp2_conn_shutdown_stream(ngtcp2_conn *conn,
                                              int64_t stream_id,
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
 *     |stream_id| is 0
 * :enum:`NGTCP2_ERR_STREAM_NOT_FOUND`
 *     Stream does not exist
 */
NGTCP2_EXTERN int ngtcp2_conn_shutdown_stream_write(ngtcp2_conn *conn,
                                                    int64_t stream_id,
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
 *     |stream_id| is 0
 * :enum:`NGTCP2_ERR_STREAM_NOT_FOUND`
 *     Stream does not exist
 */
NGTCP2_EXTERN int ngtcp2_conn_shutdown_stream_read(ngtcp2_conn *conn,
                                                   int64_t stream_id,
                                                   uint16_t app_error_code);

/**
 * @function
 *
 * `ngtcp2_conn_write_stream` is just like
 * `ngtcp2_conn_writev_stream`.  The only difference is that it
 * conveniently accepts a single buffer.
 */
NGTCP2_EXTERN ssize_t ngtcp2_conn_write_stream(
    ngtcp2_conn *conn, ngtcp2_path *path, uint8_t *dest, size_t destlen,
    ssize_t *pdatalen, int64_t stream_id, uint8_t fin, const uint8_t *data,
    size_t datalen, ngtcp2_tstamp ts);

/**
 * @function
 *
 * `ngtcp2_conn_writev_stream` writes a packet containing stream data
 * of stream denoted by |stream_id|.  The buffer of the packet is
 * pointed by |dest| of length |destlen|.
 *
 * If |path| is not NULL, this function stores the network path with
 * which the packet should be sent.  Each addr field must point to the
 * buffer which is at least 128 bytes.  ``sizeof(struct
 * sockaddr_storage)`` is enough.  The assignment might not be done if
 * nothing is written to |dest|.
 *
 * If the all given data is encoded as STREAM frame in|dest|, and if
 * |fin| is nonzero, fin flag is set in outgoing STREAM frame.
 * Otherwise, fin flag in STREAM frame is not set.
 *
 * This packet may contain frames other than STREAM frame.  The packet
 * might not contain STREAM frame if other frames occupy the packet.
 * In that case, |*pdatalen| would be -1 if |pdatalen| is not NULL.
 *
 * If |fin| is nonzero, and 0 length STREAM frame is successfully
 * serialized, |*pdatalen| would be 0.
 *
 * The number of data encoded in STREAM frame is stored in |*pdatalen|
 * if it is not NULL.
 *
 * This function returns 0 if it cannot write any frame because buffer
 * is too small, or packet is congestion limited.  Application should
 * keep reading and wait for congestion window to grow.
 *
 * This function must not be called from inside the callback
 * functions.
 *
 * This function returns the number of bytes written in |dest| if it
 * succeeds, or one of the following negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOMEM`
 *     Out of memory
 * :enum:`NGTCP2_ERR_STREAM_NOT_FOUND`
 *     Stream does not exist
 * :enum:`NGTCP2_ERR_STREAM_SHUT_WR`
 *     Stream is half closed (local); or stream is being reset.
 * :enum:`NGTCP2_ERR_PKT_NUM_EXHAUSTED`
 *     Packet number is exhausted, and cannot send any more packet.
 * :enum:`NGTCP2_ERR_CALLBACK_FAILURE`
 *     User callback failed
 * :enum:`NGTCP2_ERR_NOKEY`
 *     No encryption key is available.
 * :enum:`NGTCP2_ERR_EARLY_DATA_REJECTED`
 *     Early data was rejected by server.
 * :enum:`NGTCP2_ERR_STREAM_DATA_BLOCKED`
 *     Stream is blocked because of flow control.
 */
NGTCP2_EXTERN ssize_t ngtcp2_conn_writev_stream(
    ngtcp2_conn *conn, ngtcp2_path *path, uint8_t *dest, size_t destlen,
    ssize_t *pdatalen, int64_t stream_id, uint8_t fin, const ngtcp2_vec *datav,
    size_t datavcnt, ngtcp2_tstamp ts);

/**
 * @function
 *
 * `ngtcp2_conn_write_connection_close` writes a packet which contains
 * a CONNECTION_CLOSE frame in the buffer pointed by |dest| whose
 * capacity is |datalen|.
 *
 * If |path| is not NULL, this function stores the network path with
 * which the packet should be sent.  Each addr field must point to the
 * buffer which is at least 128 bytes.  ``sizeof(struct
 * sockaddr_storage)`` is enough.  The assignment might not be done if
 * nothing is written to |dest|.
 *
 * This function must not be called from inside the callback
 * functions.
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
NGTCP2_EXTERN ssize_t ngtcp2_conn_write_connection_close(
    ngtcp2_conn *conn, ngtcp2_path *path, uint8_t *dest, size_t destlen,
    uint16_t error_code, ngtcp2_tstamp ts);

/**
 * @function
 *
 * `ngtcp2_conn_write_application_close` writes a packet which
 * contains a APPLICATION_CLOSE frame in the buffer pointed by |dest|
 * whose capacity is |datalen|.
 *
 * If |path| is not NULL, this function stores the network path with
 * which the packet should be sent.  Each addr field must point to the
 * buffer which is at least 128 bytes.  ``sizeof(struct
 * sockaddr_storage)`` is enough.  The assignment might not be done if
 * nothing is written to |dest|.
 *
 * This function must not be called from inside the callback
 * functions.
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
 */
NGTCP2_EXTERN ssize_t ngtcp2_conn_write_application_close(
    ngtcp2_conn *conn, ngtcp2_path *path, uint8_t *dest, size_t destlen,
    uint16_t app_error_code, ngtcp2_tstamp ts);

/**
 * @function
 *
 * `ngtcp2_conn_is_in_closing_period` returns nonzero if |conn| is in
 * closing period.
 */
NGTCP2_EXTERN int ngtcp2_conn_is_in_closing_period(ngtcp2_conn *conn);

/**
 * @function
 *
 * `ngtcp2_conn_is_in_draining_period` returns nonzero if |conn| is in
 * draining period.
 */
NGTCP2_EXTERN int ngtcp2_conn_is_in_draining_period(ngtcp2_conn *conn);

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
                                                       int64_t stream_id,
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
 * `ngtcp2_conn_get_bytes_in_flight` returns the number of bytes which
 * is the sum of outgoing QUIC packet length in flight.  This does not
 * include a packet which only includes ACK frames.
 */
NGTCP2_EXTERN size_t ngtcp2_conn_get_bytes_in_flight(ngtcp2_conn *conn);

/**
 * @function
 *
 * `ngtcp2_conn_get_dcid` returns the non-NULL pointer to destination
 * connection ID.  If no destination connection ID is present, the
 * return value is not ``NULL``, and its datalen field is 0.
 */
NGTCP2_EXTERN const ngtcp2_cid *ngtcp2_conn_get_dcid(ngtcp2_conn *conn);

/**
 * @function
 *
 * `ngtcp2_conn_get_num_scid` returns the number of source connection
 * IDs which the local endpoint has provided to the peer and have not
 * retired.
 */
NGTCP2_EXTERN size_t ngtcp2_conn_get_num_scid(ngtcp2_conn *conn);

/**
 * @function
 *
 * `ngtcp2_conn_get_scid` writes the all source connection IDs which
 * the local endpoint has provided to the peer and have not retired in
 * |dest|.  The buffer pointed by |dest| must have
 * ``sizeof(ngtcp2_cid) * n`` bytes available, where n is the return
 * value of `ngtcp2_conn_get_num_scid()`.
 */
NGTCP2_EXTERN size_t ngtcp2_conn_get_scid(ngtcp2_conn *conn, ngtcp2_cid *dest);

/**
 * @function
 *
 * `ngtcp2_conn_get_negotiated_version` returns the negotiated version.
 */
NGTCP2_EXTERN uint32_t ngtcp2_conn_get_negotiated_version(ngtcp2_conn *conn);

/**
 * @function
 *
 * `ngtcp2_conn_early_data_rejected` tells |conn| that 0-RTT data was
 * rejected by a server.
 */
NGTCP2_EXTERN int ngtcp2_conn_early_data_rejected(ngtcp2_conn *conn);

/**
 * @function
 *
 * `ngtcp2_conn_get_rcvry_stat` stores recovery information in the
 * object pointed by |rcs|.
 */
NGTCP2_EXTERN void ngtcp2_conn_get_rcvry_stat(ngtcp2_conn *conn,
                                              ngtcp2_rcvry_stat *rcs);

/**
 * @struct
 *
 * ngtcp2_iovec is a struct compatible to standard struct iovec.
 */
typedef struct {
  void *iov_base;
  size_t iov_len;
} ngtcp2_iovec;

/**
 * @function
 *
 * `ngtcp2_conn_on_loss_detection_timer` should be called when a timer
 * returned from `ngtcp2_conn_earliest_expiry` fires.
 *
 * Application should call `ngtcp2_conn_handshake` if handshake has
 * not completed, otherwise `ngtcp2_conn_write_pkt` (or
 * `ngtcp2_conn_write_stream` if it has data to send) to send TLP/RTO
 * probe packets.
 *
 * This function must not be called from inside the callback
 * functions.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOMEM`
 *     Out of memory
 */
NGTCP2_EXTERN int ngtcp2_conn_on_loss_detection_timer(ngtcp2_conn *conn,
                                                      ngtcp2_tstamp ts);

/**
 * @function
 *
 * `ngtcp2_conn_submit_crypto_data` submits crypto stream data |data|
 * of length |datalen| to the library for transmission.  The
 * encryption level is automatically determined by the installed keys.
 *
 * Application should keep the buffer pointed by |data| alive until
 * the data is acknowledged.  The acknowledgement is notified by
 * :type:`ngtcp2_acked_crypto_offset` callback.
 */
NGTCP2_EXTERN int ngtcp2_conn_submit_crypto_data(ngtcp2_conn *conn,
                                                 const uint8_t *data,
                                                 const size_t datalen);

/**
 * @function
 *
 * `ngtcp2_conn_set_retry_ocid` tells |conn| that application as a
 * server received |ocid| included in token from client.  |ocid| will
 * be sent in transport parameter.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * enum:`NGTCP2_ERR_INVALID_STATE`
 *     |conn| is not initialized as a server.
 */
NGTCP2_EXTERN int ngtcp2_conn_set_retry_ocid(ngtcp2_conn *conn,
                                             const ngtcp2_cid *ocid);

/**
 * @function
 *
 * `ngtcp2_conn_set_local_addr` sets local endpoint address |addr| to
 * |conn|.
 */
NGTCP2_EXTERN void ngtcp2_conn_set_local_addr(ngtcp2_conn *conn,
                                              const ngtcp2_addr *addr);

/**
 * @function
 *
 * `ngtcp2_conn_set_remote_addr` sets remote endpoint address |addr|
 * to |conn|.
 */
NGTCP2_EXTERN void ngtcp2_conn_set_remote_addr(ngtcp2_conn *conn,
                                               const ngtcp2_addr *addr);

/**
 * @function
 *
 * `ngtcp2_conn_get_remote_addr` returns the remote endpoint address
 * set in |conn|.
 */
NGTCP2_EXTERN const ngtcp2_addr *ngtcp2_conn_get_remote_addr(ngtcp2_conn *conn);

/**
 * @function
 *
 * `ngtcp2_conn_initiate_migration` starts connection migration to the
 * given |path|.  Only client can initiate migration.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_INVALID_STATE`
 *     |conn| is initialized as server; or no unused connection ID is
 *     available.
 * :enum:`NGTCP2_ERR_INVALID_ARGUMENT`
 *     |path| equals the current path.
 * :enum:`NGTCP2_ERR_NOMEM`
 *     Out of memory
 */
NGTCP2_EXTERN int ngtcp2_conn_initiate_migration(ngtcp2_conn *conn,
                                                 const ngtcp2_path *path,
                                                 ngtcp2_tstamp ts);

/**
 * @function
 *
 * `ngtcp2_conn_get_max_local_streams_uni` returns the cumulative
 * number of streams which local endpoint can open.
 */
NGTCP2_EXTERN uint64_t ngtcp2_conn_get_max_local_streams_uni(ngtcp2_conn *conn);

/**
 * @function
 *
 * `ngtcp2_conn_get_max_data_left` returns the number of bytes that
 * this local endpoint can send in this connection.
 */
NGTCP2_EXTERN uint64_t ngtcp2_conn_get_max_data_left(ngtcp2_conn *conn);

/**
 * @function
 *
 * `ngtcp2_strerror` returns the text representation of |liberr|.
 */
NGTCP2_EXTERN const char *ngtcp2_strerror(int liberr);

/**
 * @function
 *
 * `ngtcp2_err_is_fatal` returns nonzero if |liberr| is a fatal error.
 */
NGTCP2_EXTERN int ngtcp2_err_is_fatal(int liberr);

/**
 * @function
 *
 * `ngtcp2_err_infer_quic_transport_error_code` returns a QUIC
 * transport error code which corresponds to |liberr|.
 */
NGTCP2_EXTERN uint16_t ngtcp2_err_infer_quic_transport_error_code(int liberr);

/**
 * @function
 *
 * `ngtcp2_addr_init` initializes |dest| with the given arguments and
 * returns |dest|.
 */
NGTCP2_EXTERN ngtcp2_addr *ngtcp2_addr_init(ngtcp2_addr *dest, const void *addr,
                                            size_t addrlen, void *user_data);

/**
 * @function
 *
 * `ngtcp2_path_storage_init` initializes |ps| with the given
 * arguments.  This function copies |local_addr| and |remote_addr|.
 */
NGTCP2_EXTERN void
ngtcp2_path_storage_init(ngtcp2_path_storage *ps, const void *local_addr,
                         size_t local_addrlen, void *local_user_data,
                         const void *remote_addr, size_t remote_addrlen,
                         void *remote_user_data);

/**
 * @function
 *
 * `ngtcp2_path_storage_zero` initializes |ps| with the zero length
 * addresses.
 */
NGTCP2_EXTERN void ngtcp2_path_storage_zero(ngtcp2_path_storage *ps);

/**
 * @function
 *
 * `ngtcp2_settings_default` initializes |settings| with the default
 * values.  First this function fills |settings| with 0 and set the
 * default value to the following fields:
 *
 * * max_packet_size = NGTCP2_MAX_PKT_SIZE
 * * ack_delay_component = NGTCP2_DEFAULT_ACK_DELAY_EXPONENT
 * * max_ack_delay = NGTCP2_DEFAULT_MAX_ACK_DELAY
 */
NGTCP2_EXTERN void ngtcp2_settings_default(ngtcp2_settings *settings);

#ifdef __cplusplus
}
#endif

#endif /* NGTCP2_H */
