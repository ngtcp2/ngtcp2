/*
 * ngtcp2
 *
 * Copyright (c) 2018 ngtcp2 contributors
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
#include "ngtcp2_log.h"

#include <stdio.h>
#include <unistd.h>

void ngtcp2_log_init(ngtcp2_log *log, int fd, ngtcp2_tstamp ts) {
  log->fd = fd;
  log->ts = ts;
}

  /*
   * # Log header
   *
   * ITIMESTMP CID EV
   * ||            |
   * |\            event (PK, RC)
   * | timestamp (low 32 bits)
   * level
   *
   * # long packet
   *
   * PKN VERSION
   *
   * # short packet
   *
   * PKN
   *
   * # frame
   *
   * write packet info, then:
   *
   * TYPE
   *
   * followed by frame type specific format.
   *
   * # STREAM frame
   *
   * TYPEHEX id=<HEX> fin=<N> offset=<N> len=<N> uni=<N>
   *
   * # ACK frame
   *
   * TYPEHEX ack_delay_unscaled=<N> ack_delay=<N> ack_block_count=<N>
   * following ack blocks:
   *
   * for first ack block:
   * TYPEHEX gap=-1 [<N>..<N>]
   *
   * for second, and later ack blocks:
   * TYPEHEX gap=<N> [<N>..<N>]
   *
   * # PING frame
   *
   * TYPEHEX len=<N> data=<HEXS>
   *
   * # MAX_DATA frame
   *
   * TYPEHEX max_data=<N>
   *
   * # MAX_STREAM_ID frame
   *
   * TYPEHEX max_stream_id=<HEX>
   *
   * # MAX_STREAM_DATA frame
   *
   * TYPEHEX id=<HEX> max_stream_data=<N>
   *
   * # CONNECTION_CLOSE frame
   *
   * TYPEHEX error_code=<S>(<HEX>) reason_len=<N>
   *
   * # PADDING frame (consecutive)
   *
   * TYPEHEX len=<N>
   *
   */

#define NGTCP2_LOG_BUFLEN 4096

#define NGTCP2_LOG_HD "I%016" PRIu64 " 0x%016" PRIx64 " %s"
#define NGTCP2_LOG_LONG_PKT NGTCP2_LOG_HD " 0x%08x %10" PRIu64 " %s %s(0x%02x)"

#define PKT_HD_FIELDS                                                          \
  ts - log->ts, hd->conn_id, "pk", hd->version, hd->pkt_num, dir,              \
      strpkttype(hd), hd->type

static const char *strerrorcode(uint16_t error_code) {
  switch (error_code) {
  case NGTCP2_NO_ERROR:
    return "NO_ERROR";
  case NGTCP2_INTERNAL_ERROR:
    return "INTERNAL_ERROR";
  case NGTCP2_FLOW_CONTROL_ERROR:
    return "FLOW_CONTROL_ERROR";
  case NGTCP2_STREAM_ID_ERROR:
    return "STREAM_ID_ERROR";
  case NGTCP2_STREAM_STATE_ERROR:
    return "STREAM_STATE_ERROR";
  case NGTCP2_FINAL_OFFSET_ERROR:
    return "FINAL_OFFSET_ERROR";
  case NGTCP2_FRAME_FORMAT_ERROR:
    return "FRAME_FORMAT_ERROR";
  case NGTCP2_TRANSPORT_PARAMETER_ERROR:
    return "TRANSPORT_PARAMETER_ERROR";
  case NGTCP2_VERSION_NEGOTIATION_ERROR:
    return "VERSION_NEGOTIATION_ERROR";
  case NGTCP2_PROTOCOL_VIOLATION:
    return "PROTOCOL_VIOLATION";
  case NGTCP2_UNSOLICITED_PONG:
    return "UNSOLICITED_PONG";
  case NGTCP2_TLS_HANDSHAKE_FAILED:
    return "TLS_HANDSHAKE_FAILED";
  case NGTCP2_TLS_FATAL_ALERT_GENERATED:
    return "TLS_FATAL_ALERT_GENERATED";
  case NGTCP2_TLS_FATAL_ALERT_RECEIVED:
    return "TLS_FATAL_ALERT_RECEIVED";
  default:
    if (0x100u <= error_code && error_code <= 0x1ffu) {
      return "FRAME_ERROR";
    }
    return "UNKNOWN";
  }
}

static const char *strpkttype_long(uint8_t type) {
  switch (type) {
  case NGTCP2_PKT_VERSION_NEGOTIATION:
    return "VN";
  case NGTCP2_PKT_INITIAL:
    return "Initial";
  case NGTCP2_PKT_RETRY:
    return "Retry";
  case NGTCP2_PKT_HANDSHAKE:
    return "Handshake";
  case NGTCP2_PKT_0RTT_PROTECTED:
    return "0RTT";
  default:
    return "UNKNOWN";
  }
}

static const char *strpkttype_short(uint8_t type) {
  switch (type) {
  case NGTCP2_PKT_01:
    return "S01";
  case NGTCP2_PKT_02:
    return "S02";
  case NGTCP2_PKT_03:
    return "S03";
  default:
    return "UNKNOWN";
  }
}

static const char *strpkttype(const ngtcp2_pkt_hd *hd) {
  if (hd->flags & NGTCP2_PKT_FLAG_LONG_FORM) {
    return strpkttype_long(hd->type);
  }
  return strpkttype_short(hd->type);
}

static void log_printf(ngtcp2_log *log, const char *fmt, ...) {
  va_list ap;
  int n;
  char buf[NGTCP2_LOG_BUFLEN];

  va_start(ap, fmt);
  n = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  if (n < 0 || (size_t)n >= sizeof(buf)) {
    return;
  }

  write(log->fd, buf, (size_t)n);
}

static void log_pkt(ngtcp2_log *log, const ngtcp2_pkt_hd *hd, const char *dir,
                    ngtcp2_tstamp ts) {
  if (log->fd == -1) {
    return;
  }
  log_printf(log, NGTCP2_LOG_LONG_PKT "\n", PKT_HD_FIELDS);
}

void ngtcp2_log_rx_pkt(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                       ngtcp2_tstamp ts) {
  log_pkt(log, hd, "rx", ts);
}

void ngtcp2_log_tx_pkt(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                       ngtcp2_tstamp ts) {
  log_pkt(log, hd, "tx", ts);
}

static void log_fr_stream(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                          const ngtcp2_stream *fr, const char *dir,
                          ngtcp2_tstamp ts) {
  log_printf(log,
             (NGTCP2_LOG_LONG_PKT " STREAM(0x%02x) id=0x%" PRIx64
                                  " fin=%d offset=%" PRIu64 " len=%" PRIu64
                                  " uni=%d\n"),
             PKT_HD_FIELDS, fr->type | fr->flags, fr->stream_id, fr->fin,
             fr->offset, fr->datalen, (fr->stream_id & 0x2) != 0);
}

static void log_fr_ack(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                       const ngtcp2_ack *fr, const char *dir,
                       ngtcp2_tstamp ts) {
  uint64_t largest_ack, min_ack;
  size_t i;

  log_printf(log,
             (NGTCP2_LOG_LONG_PKT " ACK(0x%02x) largest_ack=%" PRIu64
                                  " ack_delay=%" PRIu64 "(%" PRIu64
                                  ") ack_block_count=%zu\n"),
             PKT_HD_FIELDS, fr->type, fr->largest_ack, fr->ack_delay_unscaled,
             fr->ack_delay, fr->num_blks);

  largest_ack = fr->largest_ack;
  min_ack = fr->largest_ack - fr->first_ack_blklen;

  log_printf(log,
             (NGTCP2_LOG_LONG_PKT " ACK(0x%02x) block=[%" PRIu64 "..%" PRIu64
                                  "] block_count=%" PRIu64 "\n"),
             PKT_HD_FIELDS, fr->type, largest_ack, min_ack,
             fr->first_ack_blklen);

  for (i = 0; i < fr->num_blks; ++i) {
    const ngtcp2_ack_blk *blk = &fr->blks[i];
    largest_ack = min_ack - blk->gap - 2;
    min_ack = largest_ack - blk->blklen;
    log_printf(
        log,
        (NGTCP2_LOG_LONG_PKT " ACK(0x%02x) block=[%" PRIu64 "..%" PRIu64
                             "] gap=%" PRIu64 " block_count=%" PRIu64 "\n"),
        PKT_HD_FIELDS, fr->type, largest_ack, min_ack, blk->gap, blk->blklen);
  }
}

static void log_fr_padding(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                           const ngtcp2_padding *fr, const char *dir,
                           ngtcp2_tstamp ts) {
  log_printf(log, (NGTCP2_LOG_LONG_PKT " PADDING(0x%02x) len=%" PRIu64 "\n"),
             PKT_HD_FIELDS, fr->type, fr->len);
}

/* rst_stream */

static void log_fr_connection_close(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                                    const ngtcp2_connection_close *fr,
                                    const char *dir, ngtcp2_tstamp ts) {
  log_printf(log,
             (NGTCP2_LOG_LONG_PKT
              " CONNECTION_CLOSE(0x%02x) error_code=%s(%" PRIu64 ") "
              "reason_len=%" PRIu64 "\n"),
             PKT_HD_FIELDS, fr->type, strerrorcode(fr->error_code),
             fr->error_code, fr->reasonlen);
}

/* application close */

static void log_fr_max_data(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                            const ngtcp2_max_data *fr, const char *dir,
                            ngtcp2_tstamp ts) {
  log_printf(log,
             (NGTCP2_LOG_LONG_PKT " MAX_DATA(0x%02x) max_data=%" PRIu64 "\n"),
             PKT_HD_FIELDS, fr->type, fr->max_data);
}

static void log_fr_max_stream_data(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                                   const ngtcp2_max_stream_data *fr,
                                   const char *dir, ngtcp2_tstamp ts) {
  log_printf(log,
             (NGTCP2_LOG_LONG_PKT " MAX_STREAM_DATA(0x%02x) id=0x%" PRIx64
                                  " max_stream_data=%" PRIu64 "\n"),
             PKT_HD_FIELDS, fr->type, fr->stream_id, fr->max_stream_data);
}

static void log_fr_max_stream_id(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                                 const ngtcp2_max_stream_id *fr,
                                 const char *dir, ngtcp2_tstamp ts) {
  log_printf(log,
             (NGTCP2_LOG_LONG_PKT
              " MAX_STREAM_ID(0x%02x) max_stream_id=%" PRIu64 "\n"),
             PKT_HD_FIELDS, fr->type, fr->max_stream_id);
}

static void log_fr_ping(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                        const ngtcp2_ping *fr, const char *dir,
                        ngtcp2_tstamp ts) {
  log_printf(log, (NGTCP2_LOG_LONG_PKT " PING(0x%02x) len=%" PRIu64 "\n"),
             PKT_HD_FIELDS, fr->type, fr->datalen);
}

/* blocked */
/* stream_blocked */
/* stream_id_blocked */
/* new_connection_id */
/* stop_sending */
/* pong */

static void log_fr(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                   const ngtcp2_frame *fr, const char *dir, ngtcp2_tstamp ts) {
  if (log->fd == -1) {
    return;
  }

  switch (fr->type) {
  case NGTCP2_FRAME_STREAM:
    log_fr_stream(log, hd, &fr->stream, dir, ts);
    break;
  case NGTCP2_FRAME_ACK:
    log_fr_ack(log, hd, &fr->ack, dir, ts);
    break;
  case NGTCP2_FRAME_PING:
    log_fr_ping(log, hd, &fr->ping, dir, ts);
    break;
  case NGTCP2_FRAME_MAX_STREAM_ID:
    log_fr_max_stream_id(log, hd, &fr->max_stream_id, dir, ts);
    break;
  case NGTCP2_FRAME_MAX_DATA:
    log_fr_max_data(log, hd, &fr->max_data, dir, ts);
    break;
  case NGTCP2_FRAME_MAX_STREAM_DATA:
    log_fr_max_stream_data(log, hd, &fr->max_stream_data, dir, ts);
    break;
  case NGTCP2_FRAME_CONNECTION_CLOSE:
    log_fr_connection_close(log, hd, &fr->connection_close, dir, ts);
    break;
  case NGTCP2_FRAME_PADDING:
    log_fr_padding(log, hd, &fr->padding, dir, ts);
    break;
  default:
    log_pkt(log, hd, dir, ts);
  }
}

void ngtcp2_log_rx_fr(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                      const ngtcp2_frame *fr, ngtcp2_tstamp ts) {
  log_fr(log, hd, fr, "rx", ts);
}

void ngtcp2_log_tx_fr(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                      const ngtcp2_frame *fr, ngtcp2_tstamp ts) {
  log_fr(log, hd, fr, "tx", ts);
}

/* void ngtcp2_log_pkt_lost() {} */
/* void ngtcp2_log_rcvry_stat() {} */
