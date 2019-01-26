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
#include "ngtcp2_vec.h"

void ngtcp2_log_init(ngtcp2_log *log, const ngtcp2_cid *scid,
                     ngtcp2_printf log_printf, ngtcp2_tstamp ts,
                     void *user_data) {
  if (scid) {
    ngtcp2_encode_hex(log->scid, scid->data, scid->datalen);
  } else {
    log->scid[0] = '\0';
  }
  log->log_printf = log_printf;
  log->ts = log->last_ts = ts;
  log->user_data = user_data;
}

/*
 * # Log header
 *
 * <LEVEL><TIMESTAMP> <SCID> <EVENT>
 *
 * <LEVEL>:
 *   Log level.  I=Info, W=Warning, E=Error
 *
 * <TIMESTAMP>:
 *   Timestamp relative to ngtcp2_log.ts field in milliseconds
 *   resolution.
 *
 * <SCID>:
 *   Source Connection ID in hex string.
 *
 * <EVENT>:
 *   Event.  pkt=packet, frm=frame, rcv=recovery, cry=crypto,
 *   con=connection(catch all)
 *
 * # Frame event
 *
 * <DIR> <PKN> <PKTNAME>(<PKTTYPE>) <FRAMENAME>(<FRAMETYPE>)
 *
 * <DIR>:
 *   Flow direction.  tx=transmission, rx=reception
 *
 * <PKN>:
 *   Packet number.
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
#define NGTCP2_LOG_HD "I%08" PRIu64 " 0x%s %s"
#define NGTCP2_LOG_PKT NGTCP2_LOG_HD " %s %" PRIu64 " %s(0x%02x)"
#define NGTCP2_LOG_TP NGTCP2_LOG_HD " remote transport_parameters"

#define NGTCP2_LOG_FRM_HD_FIELDS(DIR)                                          \
  timestamp_cast(log->last_ts - log->ts), (const char *)log->scid, "frm",      \
      (DIR), hd->pkt_num, strpkttype(hd), hd->type

#define NGTCP2_LOG_PKT_HD_FIELDS(DIR)                                          \
  timestamp_cast(log->last_ts - log->ts), (const char *)log->scid, "pkt",      \
      (DIR), hd->pkt_num, strpkttype(hd), hd->type

#define NGTCP2_LOG_TP_HD_FIELDS                                                \
  timestamp_cast(log->last_ts - log->ts), (const char *)log->scid, "cry"

static const char *strerrorcode(uint16_t error_code) {
  switch (error_code) {
  case NGTCP2_NO_ERROR:
    return "NO_ERROR";
  case NGTCP2_INTERNAL_ERROR:
    return "INTERNAL_ERROR";
  case NGTCP2_SERVER_BUSY:
    return "SERVER_BUSY";
  case NGTCP2_FLOW_CONTROL_ERROR:
    return "FLOW_CONTROL_ERROR";
  case NGTCP2_STREAM_LIMIT_ERROR:
    return "STREAM_LIMIT_ERROR";
  case NGTCP2_STREAM_STATE_ERROR:
    return "STREAM_STATE_ERROR";
  case NGTCP2_FINAL_OFFSET_ERROR:
    return "FINAL_OFFSET_ERROR";
  case NGTCP2_FRAME_ENCODING_ERROR:
    return "FRAME_ENCODING_ERROR";
  case NGTCP2_TRANSPORT_PARAMETER_ERROR:
    return "TRANSPORT_PARAMETER_ERROR";
  case NGTCP2_VERSION_NEGOTIATION_ERROR:
    return "VERSION_NEGOTIATION_ERROR";
  case NGTCP2_PROTOCOL_VIOLATION:
    return "PROTOCOL_VIOLATION";
  case NGTCP2_INVALID_MIGRATION:
    return "INVALID_MIGRATION";
  default:
    if (0x100u <= error_code && error_code <= 0x1ffu) {
      return "CRYPTO_ERROR";
    }
    return "(unknown)";
  }
}

static const char *strapperrorcode(uint16_t app_error_code) {
  (void)app_error_code;
  return "(unknown)";
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
    return "(unknown)";
  }
}

static const char *strpkttype(const ngtcp2_pkt_hd *hd) {
  if (hd->flags & NGTCP2_PKT_FLAG_LONG_FORM) {
    return strpkttype_long(hd->type);
  }
  return "Short";
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

static uint64_t timestamp_cast(uint64_t ns) { return ns / NGTCP2_MILLISECONDS; }

static void log_fr_stream(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                          const ngtcp2_stream *fr, const char *dir) {
  log->log_printf(
      log->user_data,
      (NGTCP2_LOG_PKT " STREAM(0x%02x) id=0x%" PRIx64 " fin=%d offset=%" PRIu64
                      " len=%" PRIu64 " uni=%d\n"),
      NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type | fr->flags, fr->stream_id,
      fr->fin, fr->offset, ngtcp2_vec_len(fr->data, fr->datacnt),
      (fr->stream_id & 0x2) != 0);
}

static void log_fr_ack(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                       const ngtcp2_ack *fr, const char *dir) {
  uint64_t largest_ack, min_ack;
  size_t i;

  log->log_printf(log->user_data,
                  (NGTCP2_LOG_PKT " ACK(0x%02x) largest_ack=%" PRIu64
                                  " ack_delay=%" PRIu64 "(%" PRIu64
                                  ") ack_block_count=%zu\n"),
                  NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type, fr->largest_ack,
                  fr->ack_delay_unscaled / NGTCP2_MILLISECONDS, fr->ack_delay,
                  fr->num_blks);

  largest_ack = fr->largest_ack;
  min_ack = fr->largest_ack - fr->first_ack_blklen;

  log->log_printf(log->user_data,
                  (NGTCP2_LOG_PKT " ACK(0x%02x) block=[%" PRIu64 "..%" PRIu64
                                  "] block_count=%" PRIu64 "\n"),
                  NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type, largest_ack, min_ack,
                  fr->first_ack_blklen);

  for (i = 0; i < fr->num_blks; ++i) {
    const ngtcp2_ack_blk *blk = &fr->blks[i];
    largest_ack = min_ack - blk->gap - 2;
    min_ack = largest_ack - blk->blklen;
    log->log_printf(log->user_data,
                    (NGTCP2_LOG_PKT " ACK(0x%02x) block=[%" PRIu64 "..%" PRIu64
                                    "] gap=%" PRIu64 " block_count=%" PRIu64
                                    "\n"),
                    NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type, largest_ack,
                    min_ack, blk->gap, blk->blklen);
  }
}

static void log_fr_padding(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                           const ngtcp2_padding *fr, const char *dir) {
  log->log_printf(log->user_data,
                  (NGTCP2_LOG_PKT " PADDING(0x%02x) len=%" PRIu64 "\n"),
                  NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type, fr->len);
}

static void log_fr_reset_stream(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                                const ngtcp2_reset_stream *fr,
                                const char *dir) {
  log->log_printf(log->user_data,
                  (NGTCP2_LOG_PKT
                   " RESET_STREAM(0x%02x) id=0x%" PRIu64
                   " app_error_code=%s(0x%04x) final_offset=%" PRIu64 "\n"),
                  NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type, fr->stream_id,
                  strapperrorcode(fr->app_error_code), fr->app_error_code,
                  fr->final_offset);
}

static void log_fr_connection_close(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                                    const ngtcp2_connection_close *fr,
                                    const char *dir) {
  log->log_printf(log->user_data,
                  (NGTCP2_LOG_PKT
                   " CONNECTION_CLOSE(0x%02x) error_code=%s(0x%04x) "
                   "frame_type=%u reason_len=%" PRIu64 "\n"),
                  NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type,
                  fr->type == NGTCP2_FRAME_CONNECTION_CLOSE
                      ? strerrorcode(fr->error_code)
                      : strapperrorcode(fr->error_code),
                  fr->error_code, fr->frame_type, fr->reasonlen);
}

static void log_fr_max_data(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                            const ngtcp2_max_data *fr, const char *dir) {
  log->log_printf(log->user_data,
                  (NGTCP2_LOG_PKT " MAX_DATA(0x%02x) max_data=%" PRIu64 "\n"),
                  NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type, fr->max_data);
}

static void log_fr_max_stream_data(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                                   const ngtcp2_max_stream_data *fr,
                                   const char *dir) {
  log->log_printf(log->user_data,
                  (NGTCP2_LOG_PKT " MAX_STREAM_DATA(0x%02x) id=0x%" PRIx64
                                  " max_stream_data=%" PRIu64 "\n"),
                  NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type, fr->stream_id,
                  fr->max_stream_data);
}

static void log_fr_max_streams(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                               const ngtcp2_max_streams *fr, const char *dir) {
  log->log_printf(
      log->user_data,
      (NGTCP2_LOG_PKT " MAX_STREAMS(0x%02x) max_streams=%" PRIu64 "\n"),
      NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type, fr->max_streams);
}

static void log_fr_ping(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                        const ngtcp2_ping *fr, const char *dir) {
  log->log_printf(log->user_data, (NGTCP2_LOG_PKT " PING(0x%02x)\n"),
                  NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type);
}

static void log_fr_data_blocked(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                                const ngtcp2_data_blocked *fr,
                                const char *dir) {
  log->log_printf(log->user_data,
                  (NGTCP2_LOG_PKT " DATA_BLOCKED(0x%02x) offset=%" PRIu64 "\n"),
                  NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type, fr->offset);
}

static void log_fr_stream_data_blocked(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                                       const ngtcp2_stream_data_blocked *fr,
                                       const char *dir) {
  log->log_printf(log->user_data,
                  (NGTCP2_LOG_PKT " STREAM_DATA_BLOCKED(0x%02x) id=%" PRIu64
                                  " offset=%" PRIu64 "\n"),
                  NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->stream_id, fr->offset);
}

static void log_fr_streams_blocked(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                                   const ngtcp2_streams_blocked *fr,
                                   const char *dir) {
  log->log_printf(log->user_data,
                  (NGTCP2_LOG_PKT " STREAMS_BLOCKED(0x%02x) id=0x%" PRIx64
                                  " stream_limit=%" PRIu64 "\n"),
                  NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type, fr->stream_limit);
}

static void log_fr_new_connection_id(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                                     const ngtcp2_new_connection_id *fr,
                                     const char *dir) {
  uint8_t buf[sizeof(fr->stateless_reset_token) * 2 + 1];
  uint8_t cid[sizeof(fr->cid.data) * 2 + 1];

  log->log_printf(
      log->user_data,
      (NGTCP2_LOG_PKT " NEW_CONNECTION_ID(0x%02x) seq=%" PRIu64 " cid=0x%s "
                      "stateless_reset_token=0x%s\n"),
      NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type, fr->seq,
      (const char *)ngtcp2_encode_hex(cid, fr->cid.data, fr->cid.datalen),
      (const char *)ngtcp2_encode_hex(buf, fr->stateless_reset_token,
                                      sizeof(fr->stateless_reset_token)));
}

static void log_fr_stop_sending(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                                const ngtcp2_stop_sending *fr,
                                const char *dir) {
  log->log_printf(log->user_data,
                  (NGTCP2_LOG_PKT " STOP_SENDING(0x%02x) id=0x%" PRIx64
                                  " app_error_code=%s(0x%04x)\n"),
                  NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type, fr->stream_id,
                  strapperrorcode(fr->app_error_code), fr->app_error_code);
}

static void log_fr_path_challenge(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                                  const ngtcp2_path_challenge *fr,
                                  const char *dir) {
  uint8_t buf[sizeof(fr->data) * 2 + 1];

  log->log_printf(
      log->user_data, (NGTCP2_LOG_PKT " PATH_CHALLENGE(0x%02x) data=0x%s\n"),
      NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type,
      (const char *)ngtcp2_encode_hex(buf, fr->data, sizeof(fr->data)));
}

static void log_fr_path_response(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                                 const ngtcp2_path_response *fr,
                                 const char *dir) {
  uint8_t buf[sizeof(fr->data) * 2 + 1];

  log->log_printf(
      log->user_data, (NGTCP2_LOG_PKT " PATH_RESPONSE(0x%02x) data=0x%s\n"),
      NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type,
      (const char *)ngtcp2_encode_hex(buf, fr->data, sizeof(fr->data)));
}

static void log_fr_crypto(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                          const ngtcp2_crypto *fr, const char *dir) {
  size_t datalen = 0;
  size_t i;

  for (i = 0; i < fr->datacnt; ++i) {
    datalen += fr->data[i].len;
  }

  log->log_printf(
      log->user_data,
      (NGTCP2_LOG_PKT " CRYPTO(0x%02x) offset=%" PRIu64 " len=%" PRIu64 "\n"),
      NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type, fr->offset, datalen);
}

static void log_fr_new_token(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                             const ngtcp2_new_token *fr, const char *dir) {
  /* Show at most first 64 bytes of token.  If token is longer than 64
     bytes, log first 64 bytes and then append "*" */
  uint8_t buf[128 + 1 + 1];
  uint8_t *p;

  if (fr->tokenlen > 64) {
    p = ngtcp2_encode_hex(buf, fr->token, 64);
    p[128] = '*';
    p[129] = '\0';
  } else {
    p = ngtcp2_encode_hex(buf, fr->token, fr->tokenlen);
  }
  log->log_printf(
      log->user_data,
      (NGTCP2_LOG_PKT " NEW_TOKEN(0x%02x) token=0x%s token_len=%zu\n"),
      NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type, (const char *)p, fr->tokenlen);
}

static void log_fr_retire_connection_id(ngtcp2_log *log,
                                        const ngtcp2_pkt_hd *hd,
                                        const ngtcp2_retire_connection_id *fr,
                                        const char *dir) {
  log->log_printf(
      log->user_data,
      (NGTCP2_LOG_PKT " RETIRE_CONNECTION_ID(0x%02x) seq=%" PRIu64 "\n"),
      NGTCP2_LOG_FRM_HD_FIELDS(dir), fr->type, fr->seq);
}

static void log_fr(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                   const ngtcp2_frame *fr, const char *dir) {
  switch (fr->type) {
  case NGTCP2_FRAME_STREAM:
    log_fr_stream(log, hd, &fr->stream, dir);
    break;
  case NGTCP2_FRAME_ACK:
  case NGTCP2_FRAME_ACK_ECN:
    log_fr_ack(log, hd, &fr->ack, dir);
    break;
  case NGTCP2_FRAME_PADDING:
    log_fr_padding(log, hd, &fr->padding, dir);
    break;
  case NGTCP2_FRAME_RESET_STREAM:
    log_fr_reset_stream(log, hd, &fr->reset_stream, dir);
    break;
  case NGTCP2_FRAME_CONNECTION_CLOSE:
  case NGTCP2_FRAME_CONNECTION_CLOSE_APP:
    log_fr_connection_close(log, hd, &fr->connection_close, dir);
    break;
  case NGTCP2_FRAME_MAX_DATA:
    log_fr_max_data(log, hd, &fr->max_data, dir);
    break;
  case NGTCP2_FRAME_MAX_STREAM_DATA:
    log_fr_max_stream_data(log, hd, &fr->max_stream_data, dir);
    break;
  case NGTCP2_FRAME_MAX_STREAMS_BIDI:
  case NGTCP2_FRAME_MAX_STREAMS_UNI:
    log_fr_max_streams(log, hd, &fr->max_streams, dir);
    break;
  case NGTCP2_FRAME_PING:
    log_fr_ping(log, hd, &fr->ping, dir);
    break;
  case NGTCP2_FRAME_DATA_BLOCKED:
    log_fr_data_blocked(log, hd, &fr->data_blocked, dir);
    break;
  case NGTCP2_FRAME_STREAM_DATA_BLOCKED:
    log_fr_stream_data_blocked(log, hd, &fr->stream_data_blocked, dir);
    break;
  case NGTCP2_FRAME_STREAMS_BLOCKED_BIDI:
  case NGTCP2_FRAME_STREAMS_BLOCKED_UNI:
    log_fr_streams_blocked(log, hd, &fr->streams_blocked, dir);
    break;
  case NGTCP2_FRAME_NEW_CONNECTION_ID:
    log_fr_new_connection_id(log, hd, &fr->new_connection_id, dir);
    break;
  case NGTCP2_FRAME_STOP_SENDING:
    log_fr_stop_sending(log, hd, &fr->stop_sending, dir);
    break;
  case NGTCP2_FRAME_PATH_CHALLENGE:
    log_fr_path_challenge(log, hd, &fr->path_challenge, dir);
    break;
  case NGTCP2_FRAME_PATH_RESPONSE:
    log_fr_path_response(log, hd, &fr->path_response, dir);
    break;
  case NGTCP2_FRAME_CRYPTO:
    log_fr_crypto(log, hd, &fr->crypto, dir);
    break;
  case NGTCP2_FRAME_NEW_TOKEN:
    log_fr_new_token(log, hd, &fr->new_token, dir);
    break;
  case NGTCP2_FRAME_RETIRE_CONNECTION_ID:
    log_fr_retire_connection_id(log, hd, &fr->retire_connection_id, dir);
    break;
  default:
    assert(0);
  }
}

void ngtcp2_log_rx_fr(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                      const ngtcp2_frame *fr) {
  if (!log->log_printf) {
    return;
  }

  log_fr(log, hd, fr, "rx");
}

void ngtcp2_log_tx_fr(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                      const ngtcp2_frame *fr) {
  if (!log->log_printf) {
    return;
  }

  log_fr(log, hd, fr, "tx");
}

void ngtcp2_log_rx_vn(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                      const uint32_t *sv, size_t nsv) {
  size_t i;

  if (!log->log_printf) {
    return;
  }

  for (i = 0; i < nsv; ++i) {
    log->log_printf(log->user_data, (NGTCP2_LOG_PKT " v=0x%08x\n"),
                    NGTCP2_LOG_PKT_HD_FIELDS("rx"), sv[i]);
  }
}

void ngtcp2_log_rx_sr(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                      const ngtcp2_pkt_stateless_reset *sr) {
  uint8_t buf[sizeof(sr->stateless_reset_token) * 2 + 1];

  if (!log->log_printf) {
    return;
  }

  log->log_printf(
      log->user_data, (NGTCP2_LOG_PKT " token=0x%s randlen=%zu\n"),
      NGTCP2_LOG_PKT_HD_FIELDS("rx"),
      (const char *)ngtcp2_encode_hex(buf, sr->stateless_reset_token,
                                      sizeof(sr->stateless_reset_token)),
      sr->randlen);
}

void ngtcp2_log_remote_tp(ngtcp2_log *log, uint8_t exttype,
                          const ngtcp2_transport_params *params) {
  size_t i;
  uint8_t buf[sizeof(params->preferred_address.ip_address) * 2 + 1];

  if (!log->log_printf) {
    return;
  }

  switch (exttype) {
  case NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO:
    log->log_printf(log->user_data, (NGTCP2_LOG_TP " initial_version=0x%08x\n"),
                    NGTCP2_LOG_TP_HD_FIELDS, params->v.ch.initial_version);
    break;
  case NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS:
    log->log_printf(log->user_data,
                    (NGTCP2_LOG_TP " negotiated_version=0x%08x\n"),
                    NGTCP2_LOG_TP_HD_FIELDS, params->v.ee.negotiated_version);
    for (i = 0; i < params->v.ee.len; ++i) {
      log->log_printf(
          log->user_data, (NGTCP2_LOG_TP " supported_version[%zu]=0x%08x\n"),
          NGTCP2_LOG_TP_HD_FIELDS, i, params->v.ee.supported_versions[i]);
    }

    if (params->stateless_reset_token_present) {
      log->log_printf(log->user_data,
                      (NGTCP2_LOG_TP " stateless_reset_token=0x%s\n"),
                      NGTCP2_LOG_TP_HD_FIELDS,
                      (const char *)ngtcp2_encode_hex(
                          buf, params->stateless_reset_token,
                          sizeof(params->stateless_reset_token)));
    }

    if (params->preferred_address.ip_version != NGTCP2_IP_VERSION_NONE) {
      log->log_printf(
          log->user_data, (NGTCP2_LOG_TP " preferred_address.ip_version=%u\n"),
          NGTCP2_LOG_TP_HD_FIELDS, params->preferred_address.ip_version);
      log->log_printf(log->user_data,
                      (NGTCP2_LOG_TP " preferred_address.ip_address=0x%s\n"),
                      NGTCP2_LOG_TP_HD_FIELDS,
                      (const char *)ngtcp2_encode_hex(
                          buf, params->preferred_address.ip_address,
                          params->preferred_address.ip_addresslen));
      log->log_printf(log->user_data,
                      (NGTCP2_LOG_TP " preferred_address.port=%u\n"),
                      NGTCP2_LOG_TP_HD_FIELDS, params->preferred_address.port);
      log->log_printf(log->user_data,
                      (NGTCP2_LOG_TP " preferred_address.cid=0x%s\n"),
                      NGTCP2_LOG_TP_HD_FIELDS,
                      (const char *)ngtcp2_encode_hex(
                          buf, params->preferred_address.cid.data,
                          params->preferred_address.cid.datalen));
      log->log_printf(
          log->user_data,
          (NGTCP2_LOG_TP " preferred_address.stateless_reset_token=0x%s\n"),
          NGTCP2_LOG_TP_HD_FIELDS,
          (const char *)ngtcp2_encode_hex(
              buf, params->preferred_address.stateless_reset_token,
              sizeof(params->preferred_address.stateless_reset_token)));
    }

    if (params->original_connection_id_present) {
      log->log_printf(log->user_data,
                      (NGTCP2_LOG_TP " original_connection_id=0x%s\n"),
                      NGTCP2_LOG_TP_HD_FIELDS,
                      (const char *)ngtcp2_encode_hex(
                          buf, params->original_connection_id.data,
                          params->original_connection_id.datalen));
    }

    break;
  }

  log->log_printf(log->user_data,
                  (NGTCP2_LOG_TP " initial_max_stream_data_bidi_local=%u\n"),
                  NGTCP2_LOG_TP_HD_FIELDS,
                  params->initial_max_stream_data_bidi_local);
  log->log_printf(log->user_data,
                  (NGTCP2_LOG_TP " initial_max_stream_data_bidi_remote=%u\n"),
                  NGTCP2_LOG_TP_HD_FIELDS,
                  params->initial_max_stream_data_bidi_remote);
  log->log_printf(log->user_data,
                  (NGTCP2_LOG_TP " initial_max_stream_data_uni=%u\n"),
                  NGTCP2_LOG_TP_HD_FIELDS, params->initial_max_stream_data_uni);
  log->log_printf(log->user_data, (NGTCP2_LOG_TP " initial_max_data=%u\n"),
                  NGTCP2_LOG_TP_HD_FIELDS, params->initial_max_data);
  log->log_printf(log->user_data,
                  (NGTCP2_LOG_TP " initial_max_bidi_streams=%u\n"),
                  NGTCP2_LOG_TP_HD_FIELDS, params->initial_max_streams_bidi);
  log->log_printf(log->user_data,
                  (NGTCP2_LOG_TP " initial_max_uni_streams=%u\n"),
                  NGTCP2_LOG_TP_HD_FIELDS, params->initial_max_streams_uni);
  log->log_printf(log->user_data, (NGTCP2_LOG_TP " idle_timeout=%u\n"),
                  NGTCP2_LOG_TP_HD_FIELDS, params->idle_timeout);
  log->log_printf(log->user_data, (NGTCP2_LOG_TP " max_packet_size=%u\n"),
                  NGTCP2_LOG_TP_HD_FIELDS, params->max_packet_size);
  log->log_printf(log->user_data, (NGTCP2_LOG_TP " ack_delay_exponent=%u\n"),
                  NGTCP2_LOG_TP_HD_FIELDS, params->ack_delay_exponent);
  log->log_printf(log->user_data, (NGTCP2_LOG_TP " max_ack_delay=%u\n"),
                  NGTCP2_LOG_TP_HD_FIELDS, params->max_ack_delay);
}

void ngtcp2_log_pkt_lost(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                         ngtcp2_tstamp sent_ts) {
  if (!log->log_printf) {
    return;
  }

  ngtcp2_log_info(log, NGTCP2_LOG_EVENT_RCV,
                  "packet lost type=%s(0x%02x) %" PRIu64 " sent_ts=%" PRIu64,
                  (hd->flags & NGTCP2_PKT_FLAG_LONG_FORM)
                      ? strpkttype_long(hd->type)
                      : "Short",
                  hd->type, hd->pkt_num, sent_ts);
}

static void log_pkt_hd(ngtcp2_log *log, const ngtcp2_pkt_hd *hd,
                       const char *dir) {
  uint8_t dcid[sizeof(hd->dcid.data) * 2 + 1];
  uint8_t scid[sizeof(hd->scid.data) * 2 + 1];

  if (!log->log_printf) {
    return;
  }

  ngtcp2_log_info(
      log, NGTCP2_LOG_EVENT_PKT,
      "%s pkn=%" PRIu64 " dcid=0x%s scid=0x%s type=%s(0x%02x) len=%zu k=%d",
      dir, hd->pkt_num,
      (const char *)ngtcp2_encode_hex(dcid, hd->dcid.data, hd->dcid.datalen),
      (const char *)ngtcp2_encode_hex(scid, hd->scid.data, hd->scid.datalen),
      (hd->flags & NGTCP2_PKT_FLAG_LONG_FORM) ? strpkttype_long(hd->type)
                                              : "Short",
      hd->type, hd->len, (hd->flags & NGTCP2_PKT_FLAG_KEY_PHASE) != 0);
}

void ngtcp2_log_rx_pkt_hd(ngtcp2_log *log, const ngtcp2_pkt_hd *hd) {
  log_pkt_hd(log, hd, "rx");
}

void ngtcp2_log_tx_pkt_hd(ngtcp2_log *log, const ngtcp2_pkt_hd *hd) {
  log_pkt_hd(log, hd, "tx");
}

void ngtcp2_log_info(ngtcp2_log *log, ngtcp2_log_event ev, const char *fmt,
                     ...) {
  va_list ap;
  int n;
  char buf[NGTCP2_LOG_BUFLEN];

  if (!log->log_printf) {
    return;
  }

  va_start(ap, fmt);
  n = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  if (n < 0 || (size_t)n >= sizeof(buf)) {
    return;
  }

  log->log_printf(log->user_data, (NGTCP2_LOG_HD " %s\n"),
                  timestamp_cast(log->last_ts - log->ts), log->scid,
                  strevent(ev), buf);
}

void ngtcp2_log_tx_cancel(ngtcp2_log *log, const ngtcp2_pkt_hd *hd) {
  ngtcp2_log_info(log, NGTCP2_LOG_EVENT_PKT,
                  "cancel tx pkt %" PRIu64 " type=%s(0x%02x)", hd->pkt_num,
                  strpkttype(hd), hd->type);
}
