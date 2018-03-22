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
#include <assert.h>
#include <errno.h>

#include "ngtcp2_str.h"

void ngtcp2_log_init(ngtcp2_log *log, uint64_t *conn_id, int fd,
                     ngtcp2_tstamp ts) {
  log->conn_id = conn_id;
  log->fd = fd;
  log->ts = log->last_ts = ts;
}

  /*
   * # Log header
   *
   * <LEVEL><TIMESTAMP> <CID> <EVENT>
   *
   * <LEVEL>:
   *   Log level.  I=Info, W=Warning, E=Error
   *
   * <TIMESTAMP>:
   *   Timestamp relative to ngtcp2_log.ts field in nanoseconds
   *   resolution.
   *
   * <CID>:
   *   Connection ID in hex string.
   *
   * <EVENT>:
   *   Event.  pkt=packet, frm=frame, rcv=recovery, cry=crypto,
   *   con=connection(catch all)
   *
   * # Frame event
   *
   * <PKN> <DIR> <PKTNAME>(<PKTTYPE>) <FRAMENAME>(<FRAMETYPE>)
   *
   * <PKN>:
   *   Packet number.
   *
   * <DIR>:
   *   Flow direction.  tx=transmission, rx=reception
   *
   * <PKTNAME>:
   *   Packet name.  (e.g., Initial, Handshake, S01)
   *
   * <PKTTYPE>:
   *   Packet type in hex string.
   *
   * <FRAMENAME>:
   *   Frame name.  (e.g., STREAM, ACK, PING)
   *
   * <FRAMETYPE>:
   *   Frame type in hex string.
   */

#define NGTCP2_LOG_BUFLEN 4096

/* TODO Split second and remaining fraction with comma */
#define NGTCP2_LOG_HD "I%016" PRIu64 " 0x%016" PRIx64 " %s"
#define NGTCP2_LOG_PKT NGTCP2_LOG_HD " %" PRIu64 " %s %s(0x%02x)"

#define NGTCP2_LOG_FRM_HD_FIELDS(DIR)                                          \
  log->last_ts - log->ts, hd->conn_id, "frm", hd->pkt_num, (DIR),              \
      strpkttype(hd), hd->type

#define NGTCP2_LOG_PKT_HD_FIELDS(DIR)                                          \
  log->last_ts - log->ts, hd->conn_id, "pkt", hd->pkt_num, (DIR),              \
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

static const char *strapperrorcode(uint16_t app_error_code) {
  switch (app_error_code) {
  case NGTCP2_STOPPING:
    return "STOPPING";
  default:
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

static const char *strevent(ngtcp2_log_event ev) {
  switch (ev) {
  case NGTCP2_LOG_EVENT_PKT:
    return "pkt";
  case NGTCP2_LOG_EVENT_FRM:
    return "frm";
  case NGTCP2_LOG_EVENT_RCV:
    return "rcv";
  case NGTCP2_LOG_EVENT_CRY:
    return "cry";
  case NGTCP2_LOG_EVENT_CON:
    return "con";
  case NGTCP2_LOG_EVENT_NONE:
  default:
    return "non";
  }
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

  while (write(log->fd, buf, (size_t)n) == -1 && errno == EINTR)
    ;
}

static void log_fr_stream(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                          const ngtcp2_stream *fr, const char *dir) {
  log_printf(log,
             (NGTCP2_LOG_PKT " STREAM(0x%02x) id=0x%" PRIx64
                             " fin=%d offset=%" PRIu64 " len=%" PRIu64
                             " uni=%d\n"),
             NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type | fr->flags, fr->stream_id,
             fr->fin, fr->offset, fr->datalen, (fr->stream_id & 0x2) != 0);
}

static void log_fr_ack(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                       const ngtcp2_ack *fr, const char *dir) {
  uint64_t largest_ack, min_ack;
  size_t i;

  /* TODO show ack_delay with units (e.g., 120.02ms) */
  log_printf(log,
             (NGTCP2_LOG_PKT " ACK(0x%02x) largest_ack=%" PRIu64
                             " ack_delay=%" PRIu64 "(%" PRIu64
                             ") ack_block_count=%zu\n"),
             NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type, fr->largest_ack,
             fr->ack_delay_unscaled, fr->ack_delay, fr->num_blks);

  largest_ack = fr->largest_ack;
  min_ack = fr->largest_ack - fr->first_ack_blklen;

  log_printf(log,
             (NGTCP2_LOG_PKT " ACK(0x%02x) block=[%" PRIu64 "..%" PRIu64
                             "] block_count=%" PRIu64 "\n"),
             NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type, largest_ack, min_ack,
             fr->first_ack_blklen);

  for (i = 0; i < fr->num_blks; ++i) {
    const ngtcp2_ack_blk *blk = &fr->blks[i];
    largest_ack = min_ack - blk->gap - 2;
    min_ack = largest_ack - blk->blklen;
    log_printf(log,
               (NGTCP2_LOG_PKT " ACK(0x%02x) block=[%" PRIu64 "..%" PRIu64
                               "] gap=%" PRIu64 " block_count=%" PRIu64 "\n"),
               NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type, largest_ack, min_ack,
               blk->gap, blk->blklen);
  }
}

static void log_fr_padding(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                           const ngtcp2_padding *fr, const char *dir) {
  log_printf(log, (NGTCP2_LOG_PKT " PADDING(0x%02x) len=%" PRIu64 "\n"),
             NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type, fr->len);
}

static void log_fr_rst_stream(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                              const ngtcp2_rst_stream *fr, const char *dir) {
  log_printf(log,
             (NGTCP2_LOG_PKT " RST_STREAM(0x%02x) id=0x%" PRIu64
                             " app_error_code=%s(0x%04x) final_offset=%" PRIu64
                             "\n"),
             NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type, fr->stream_id,
             strapperrorcode(fr->app_error_code), fr->app_error_code,
             fr->final_offset);
}

static void log_fr_connection_close(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                                    const ngtcp2_connection_close *fr,
                                    const char *dir) {
  log_printf(log,
             (NGTCP2_LOG_PKT " CONNECTION_CLOSE(0x%02x) error_code=%s(%" PRIu64
                             ") "
                             "reason_len=%" PRIu64 "\n"),
             NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type,
             strerrorcode(fr->error_code), fr->error_code, fr->reasonlen);
}

static void log_fr_application_close(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                                     const ngtcp2_application_close *fr,
                                     const char *dir) {
  log_printf(log,
             (NGTCP2_LOG_PKT
              " APPLICATION_CLOSE(0x%02x) app_error_code=%s(%" PRIu64 ") "
              "reason_len=%" PRIu64 "\n"),
             NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type,
             strapperrorcode(fr->app_error_code), fr->app_error_code,
             fr->reasonlen);
}

static void log_fr_max_data(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                            const ngtcp2_max_data *fr, const char *dir) {
  log_printf(log, (NGTCP2_LOG_PKT " MAX_DATA(0x%02x) max_data=%" PRIu64 "\n"),
             NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type, fr->max_data);
}

static void log_fr_max_stream_data(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                                   const ngtcp2_max_stream_data *fr,
                                   const char *dir) {
  log_printf(log,
             (NGTCP2_LOG_PKT " MAX_STREAM_DATA(0x%02x) id=0x%" PRIx64
                             " max_stream_data=%" PRIu64 "\n"),
             NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type, fr->stream_id,
             fr->max_stream_data);
}

static void log_fr_max_stream_id(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                                 const ngtcp2_max_stream_id *fr,
                                 const char *dir) {
  log_printf(
      log,
      (NGTCP2_LOG_PKT " MAX_STREAM_ID(0x%02x) max_stream_id=%" PRIu64 "\n"),
      NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type, fr->max_stream_id);
}

static void log_fr_ping(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                        const ngtcp2_ping *fr, const char *dir) {
  /* The maximum length of PONG data is 255, and +1 for terminal
     NULL. */
  char buf[256];

  log_printf(log, (NGTCP2_LOG_PKT " PING(0x%02x) len=%" PRIu64 " data=%s\n"),
             NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type, fr->datalen,
             ngtcp2_encode_hex(buf, fr->data, fr->datalen));
}

static void log_fr_blocked(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                           const ngtcp2_blocked *fr, const char *dir) {
  log_printf(log, (NGTCP2_LOG_PKT " BLOCKED(0x%02x) offset=%" PRIu64 "\n"),
             NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type, fr->offset);
}

static void log_fr_stream_blocked(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                                  const ngtcp2_stream_blocked *fr,
                                  const char *dir) {
  log_printf(log,
             (NGTCP2_LOG_PKT " STREAM_BLOCKED(0x%02x) id=%" PRIu64
                             " offset=%" PRIu64 "\n"),
             NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->stream_id, fr->offset);
}

static void log_fr_stream_id_blocked(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                                     const ngtcp2_stream_id_blocked *fr,
                                     const char *dir) {
  log_printf(log,
             (NGTCP2_LOG_PKT " STREAM_ID_BLOCKED(0x%02x) id=0x%" PRIx64
                             " offset=%" PRIu64 "\n"),
             NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type, fr->stream_id);
}

static void log_fr_new_connection_id(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                                     const ngtcp2_new_connection_id *fr,
                                     const char *dir) {
  char buf[sizeof(fr->stateless_reset_token) * 2 + 1];

  log_printf(log,
             (NGTCP2_LOG_PKT
              " NEW_CONNECTION_ID(0x%02x) seq=%u conn_id=0x%016" PRIx64
              " stateless_reset_token=%s\n"),
             NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type, fr->seq, fr->conn_id,
             ngtcp2_encode_hex(buf, fr->stateless_reset_token,
                               sizeof(fr->stateless_reset_token)));
}

static void log_fr_stop_sending(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                                const ngtcp2_stop_sending *fr,
                                const char *dir) {
  log_printf(log,
             (NGTCP2_LOG_PKT " STOP_SENDING(0x%02x) id=0x%" PRIx64
                             " app_error_code=%s(0x%04x)\n"),
             NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type, fr->stream_id,
             strapperrorcode(fr->app_error_code), fr->app_error_code);
}

static void log_fr_pong(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                        const ngtcp2_pong *fr, const char *dir) {
  /* The maximum length of PONG data is 255, and +1 for terminal
     NULL. */
  char buf[256];

  log_printf(log, (NGTCP2_LOG_PKT " PONG(0x%02x) len=%" PRIu64 " data=%s\n"),
             NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type, fr->datalen,
             ngtcp2_encode_hex(buf, fr->data, fr->datalen));
}

static void log_fr(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                   const ngtcp2_frame *fr, const char *dir) {
  if (log->fd == -1) {
    return;
  }

  switch (fr->type) {
  case NGTCP2_FRAME_STREAM:
    log_fr_stream(log, hd, &fr->stream, dir);
    break;
  case NGTCP2_FRAME_ACK:
    log_fr_ack(log, hd, &fr->ack, dir);
    break;
  case NGTCP2_FRAME_PADDING:
    log_fr_padding(log, hd, &fr->padding, dir);
    break;
  case NGTCP2_FRAME_RST_STREAM:
    log_fr_rst_stream(log, hd, &fr->rst_stream, dir);
    break;
  case NGTCP2_FRAME_CONNECTION_CLOSE:
    log_fr_connection_close(log, hd, &fr->connection_close, dir);
    break;
  case NGTCP2_FRAME_APPLICATION_CLOSE:
    log_fr_application_close(log, hd, &fr->application_close, dir);
    break;
  case NGTCP2_FRAME_MAX_DATA:
    log_fr_max_data(log, hd, &fr->max_data, dir);
    break;
  case NGTCP2_FRAME_MAX_STREAM_DATA:
    log_fr_max_stream_data(log, hd, &fr->max_stream_data, dir);
    break;
  case NGTCP2_FRAME_MAX_STREAM_ID:
    log_fr_max_stream_id(log, hd, &fr->max_stream_id, dir);
    break;
  case NGTCP2_FRAME_PING:
    log_fr_ping(log, hd, &fr->ping, dir);
    break;
  case NGTCP2_FRAME_BLOCKED:
    log_fr_blocked(log, hd, &fr->blocked, dir);
    break;
  case NGTCP2_FRAME_STREAM_BLOCKED:
    log_fr_stream_blocked(log, hd, &fr->stream_blocked, dir);
    break;
  case NGTCP2_FRAME_STREAM_ID_BLOCKED:
    log_fr_stream_id_blocked(log, hd, &fr->stream_id_blocked, dir);
    break;
  case NGTCP2_FRAME_NEW_CONNECTION_ID:
    log_fr_new_connection_id(log, hd, &fr->new_connection_id, dir);
    break;
  case NGTCP2_FRAME_STOP_SENDING:
    log_fr_stop_sending(log, hd, &fr->stop_sending, dir);
    break;
  case NGTCP2_FRAME_PONG:
    log_fr_pong(log, hd, &fr->pong, dir);
    break;
  default:
    assert(0);
  }
}

void ngtcp2_log_rx_fr(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                      const ngtcp2_frame *fr) {
  log_fr(log, hd, fr, "rx");
}

void ngtcp2_log_tx_fr(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                      const ngtcp2_frame *fr) {
  log_fr(log, hd, fr, "tx");
}

void ngtcp2_log_rx_vn(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                      const uint32_t *sv, size_t nsv) {
  size_t i;

  for (i = 0; i < nsv; ++i) {
    log_printf(log, (NGTCP2_LOG_PKT " v=0x%08x\n"),
               NGTCP2_LOG_PKT_HD_FIELDS("rx"), sv[i]);
  }
}

void ngtcp2_log_rx_sr(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                      const ngtcp2_pkt_stateless_reset *sr) {
  char buf[NGTCP2_STATELESS_RESET_TOKENLEN + 1];

  log_printf(log, (NGTCP2_LOG_PKT " token=%s randlen=%zu\n"),
             NGTCP2_LOG_PKT_HD_FIELDS("rx"),
             ngtcp2_encode_hex(buf, sr->stateless_reset_token,
                               sizeof(sr->stateless_reset_token)),
             sr->randlen);
}

void ngtcp2_log_pkt_lost(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                         ngtcp2_tstamp sent_ts, int unprotected) {
  ngtcp2_log_info(log, NGTCP2_LOG_EVENT_RCV,
                  "packet lost %" PRIu64 " sent_ts=%" PRIu64 " unprotected=%d",
                  hd->pkt_num, sent_ts, unprotected != 0);
}

/* void ngtcp2_log_rcvry_stat() {} */

void ngtcp2_log_info(ngtcp2_log *log, ngtcp2_log_event ev, const char *fmt,
                     ...) {
  va_list ap;
  int n;
  char buf[NGTCP2_LOG_BUFLEN];

  if (log->fd == -1) {
    return;
  }

  va_start(ap, fmt);
  n = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  if (n < 0 || (size_t)n >= sizeof(buf)) {
    return;
  }

  log_printf(log, (NGTCP2_LOG_HD " %s\n"), log->last_ts - log->ts,
             *log->conn_id, strevent(ev), buf);
}
