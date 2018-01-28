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
#include "debug.h"

#include <random>

#include "util.h"

namespace ngtcp2 {

namespace debug {

namespace {
auto randgen = util::make_mt19937();
} // namespace

namespace {
std::chrono::steady_clock::time_point ts_base;
} // namespace

void reset_timestamp() { ts_base = std::chrono::steady_clock::now(); }

std::chrono::microseconds timestamp() {
  return std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now() - ts_base);
}

namespace {
auto color_output = false;
} // namespace

void set_color_output(bool f) { color_output = f; }

namespace {
auto *outfile = stderr;
} // namespace

namespace {
const char *ansi_esc(const char *code) { return color_output ? code : ""; }
} // namespace

namespace {
const char *ansi_escend() { return color_output ? "\033[0m" : ""; }
} // namespace

enum ngtcp2_dir {
  NGTCP2_DIR_SEND,
  NGTCP2_DIR_RECV,
};

namespace {
std::string strpkttype_long(uint8_t type) {
  switch (type) {
  case NGTCP2_PKT_VERSION_NEGOTIATION:
    return "Version Negotiation";
  case NGTCP2_PKT_INITIAL:
    return "Initial";
  case NGTCP2_PKT_RETRY:
    return "Retry";
  case NGTCP2_PKT_HANDSHAKE:
    return "Handshake";
  case NGTCP2_PKT_0RTT_PROTECTED:
    return "0-RTT Protected";
  default:
    return "UNKNOWN";
  }
}
} // namespace

namespace {
std::string strpkttype_short(uint8_t type) {
  switch (type) {
  case NGTCP2_PKT_01:
    return "Short 01";
  case NGTCP2_PKT_02:
    return "Short 02";
  case NGTCP2_PKT_03:
    return "Short 03";
  default:
    return "UNKNOWN";
  }
}
} // namespace

namespace {
std::string strframetype(uint8_t type) {
  switch (type) {
  case NGTCP2_FRAME_PADDING:
    return "PADDING";
  case NGTCP2_FRAME_RST_STREAM:
    return "RST_STREAM";
  case NGTCP2_FRAME_CONNECTION_CLOSE:
    return "CONNECTION_CLOSE";
  case NGTCP2_FRAME_APPLICATION_CLOSE:
    return "APPLICATION_CLOSE";
  case NGTCP2_FRAME_MAX_DATA:
    return "MAX_DATA";
  case NGTCP2_FRAME_MAX_STREAM_DATA:
    return "MAX_STREAM_DATA";
  case NGTCP2_FRAME_MAX_STREAM_ID:
    return "MAX_STREAM_ID";
  case NGTCP2_FRAME_PING:
    return "PING";
  case NGTCP2_FRAME_BLOCKED:
    return "BLOCKED";
  case NGTCP2_FRAME_STREAM_BLOCKED:
    return "STREAM_BLOCKED";
  case NGTCP2_FRAME_STREAM_ID_BLOCKED:
    return "STREAM_ID_BLOCKED";
  case NGTCP2_FRAME_NEW_CONNECTION_ID:
    return "NEW_CONNECTION_ID";
  case NGTCP2_FRAME_STOP_SENDING:
    return "STOP_SENDING";
  case NGTCP2_FRAME_PONG:
    return "PONG";
  case NGTCP2_FRAME_ACK:
    return "ACK";
  case NGTCP2_FRAME_STREAM:
    return "STREAM";
  default:
    return "UNKNOWN";
  }
}
} // namespace

namespace {
std::string strerrorcode(uint16_t error_code) {
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
} // namespace

namespace {
std::string strapperrorcode(uint16_t app_error_code) {
  switch (app_error_code) {
  case NGTCP2_STOPPING:
    return "STOPPING";
  default:
    return "UNKNOWN";
  }
}
} // namespace

void print_timestamp() {
  auto t = timestamp().count();
  fprintf(outfile, "%st=%d.%06d%s ", ansi_esc("\033[33m"),
          static_cast<int32_t>(t / 1000000), static_cast<int32_t>(t % 1000000),
          ansi_escend());
}

namespace {
const char *pkt_ansi_esc(ngtcp2_dir dir) {
  return ansi_esc(dir == NGTCP2_DIR_SEND ? "\033[1;35m" : "\033[1;36m");
}
} // namespace

namespace {
const char *frame_ansi_esc(ngtcp2_dir dir) {
  return ansi_esc(dir == NGTCP2_DIR_SEND ? "\033[1;35m" : "\033[1;36m");
}
} // namespace

namespace {
const char *pkt_num_ansi_esc(ngtcp2_dir dir) {
  return ansi_esc(dir == NGTCP2_DIR_SEND ? "\033[38;5;40m" : "\033[38;5;51m");
}
} // namespace

void print_indent() { fprintf(outfile, "           "); }

namespace {
void print_pkt_long(ngtcp2_dir dir, const ngtcp2_pkt_hd *hd) {
  fprintf(outfile,
          "%s%s%s(0x%02x) CID=0x%016" PRIx64 " PKN=%s%" PRIu64 "%s V=0x%08x\n",
          pkt_ansi_esc(dir), strpkttype_long(hd->type).c_str(), ansi_escend(),
          hd->type, hd->conn_id, pkt_num_ansi_esc(dir), hd->pkt_num,
          ansi_escend(), hd->version);
}
} // namespace

namespace {
void print_pkt_short(ngtcp2_dir dir, const ngtcp2_pkt_hd *hd) {
  fprintf(outfile, "%s%s%s(0x%02x) CID=0x%016" PRIx64 " PKN=%s%" PRIu64 "%s\n",
          pkt_ansi_esc(dir), strpkttype_short(hd->type).c_str(), ansi_escend(),
          hd->type, hd->conn_id, pkt_num_ansi_esc(dir), hd->pkt_num,
          ansi_escend());
}
} // namespace

namespace {
void print_pkt(ngtcp2_dir dir, const ngtcp2_pkt_hd *hd) {
  if (hd->flags & NGTCP2_PKT_FLAG_LONG_FORM) {
    print_pkt_long(dir, hd);
  } else {
    print_pkt_short(dir, hd);
  }
}
} // namespace

namespace {
bool is_bidi(uint64_t stream_id) { return (stream_id & 0x2) == 0; }
} // namespace

namespace {
void print_frame(ngtcp2_dir dir, const ngtcp2_frame *fr) {
  fprintf(outfile, "%s%s%s", frame_ansi_esc(dir),
          strframetype(fr->type).c_str(), ansi_escend());
  switch (fr->type) {
  case NGTCP2_FRAME_STREAM:
    fprintf(outfile, "(0x%02x) FIN=%u LEN=%u OFF=%u\n",
            fr->type | fr->stream.flags, (fr->stream.flags & 0x01) != 0,
            (fr->stream.flags & 0x02) != 0, (fr->stream.flags & 0x04) != 0);
    break;
  default:
    fprintf(outfile, "(0x%02x)\n", fr->type);
  }

  switch (fr->type) {
  case NGTCP2_FRAME_STREAM:
    print_indent();
    fprintf(outfile,
            "stream_id=0x%" PRIx64 " fin=%u offset=%" PRIu64
            " data_length=%zu\n",
            fr->stream.stream_id, fr->stream.fin, fr->stream.offset,
            fr->stream.datalen);
    print_indent();
    fprintf(outfile, "; %s\n", is_bidi(fr->stream.stream_id) ? "BIDI" : "UNI");
    break;
  case NGTCP2_FRAME_PADDING:
    print_indent();
    fprintf(outfile, "length=%zu\n", fr->padding.len);
    break;
  case NGTCP2_FRAME_ACK: {
    print_indent();
    fprintf(outfile,
            "largest_ack=%" PRIu64 " ack_delay=%" PRIu64
            " ack_block_count=%zu\n",
            fr->ack.largest_ack, fr->ack.ack_delay, fr->ack.num_blks);
    print_indent();
    auto largest_ack = fr->ack.largest_ack;
    auto min_ack = fr->ack.largest_ack - fr->ack.first_ack_blklen;
    fprintf(outfile,
            "first_ack_block=%" PRIu64 "; [%" PRIu64 "..%" PRIu64 "]\n",
            fr->ack.first_ack_blklen, largest_ack, min_ack);
    for (size_t i = 0; i < fr->ack.num_blks; ++i) {
      auto blk = &fr->ack.blks[i];
      largest_ack = min_ack - blk->gap - 2;
      min_ack = largest_ack - blk->blklen;
      print_indent();
      fprintf(outfile,
              "gap=%" PRIu64 " ack_block=%" PRIu64 "; [%" PRIu64 "..%" PRIu64
              "]\n",
              blk->gap, blk->blklen, largest_ack, min_ack);
    }
    break;
  }
  case NGTCP2_FRAME_RST_STREAM:
    print_indent();
    fprintf(outfile,
            "stream_id=0x%" PRIx64
            " app_error_code=%s(0x%04x) final_offset=%" PRIu64 "\n",
            fr->rst_stream.stream_id,
            strapperrorcode(fr->rst_stream.app_error_code).c_str(),
            fr->rst_stream.app_error_code, fr->rst_stream.final_offset);
    break;
  case NGTCP2_FRAME_CONNECTION_CLOSE:
    print_indent();
    fprintf(outfile, "error_code=%s(0x%04x) reason_length=%zu\n",
            strerrorcode(fr->connection_close.error_code).c_str(),
            fr->connection_close.error_code, fr->connection_close.reasonlen);
    break;
  case NGTCP2_FRAME_APPLICATION_CLOSE:
    print_indent();
    fprintf(outfile, "app_error_code=%s(0x%04x) reason_length=%zu\n",
            strapperrorcode(fr->application_close.app_error_code).c_str(),
            fr->application_close.app_error_code,
            fr->application_close.reasonlen);
    break;
  case NGTCP2_FRAME_MAX_DATA:
    print_indent();
    fprintf(outfile, "max_data=%" PRIu64 "\n", fr->max_data.max_data);
    break;
  case NGTCP2_FRAME_MAX_STREAM_DATA:
    print_indent();
    fprintf(outfile, "stream_id=0x%" PRIx64 " max_stream_data=%" PRIu64 "\n",
            fr->max_stream_data.stream_id, fr->max_stream_data.max_stream_data);
    break;
  case NGTCP2_FRAME_MAX_STREAM_ID:
    print_indent();
    fprintf(outfile, "max_stream_id=0x%" PRIx64 "\n",
            fr->max_stream_id.max_stream_id);
    break;
  case NGTCP2_FRAME_PING:
    print_indent();
    fprintf(outfile, "length=%zu data=%s\n", fr->ping.datalen,
            util::format_hex(fr->ping.data, fr->ping.datalen).c_str());
    break;
  case NGTCP2_FRAME_BLOCKED:
    print_indent();
    fprintf(outfile, "offset=%" PRIu64 "\n", fr->blocked.offset);
    break;
  case NGTCP2_FRAME_STREAM_BLOCKED:
    print_indent();
    fprintf(outfile, "stream_id=0x%" PRIx64 " offset=%" PRIu64 "\n",
            fr->stream_blocked.stream_id, fr->stream_blocked.offset);
    break;
  case NGTCP2_FRAME_STREAM_ID_BLOCKED:
    print_indent();
    fprintf(outfile, "stream_id=0x%" PRIx64 "\n",
            fr->stream_id_blocked.stream_id);
    break;
  case NGTCP2_FRAME_NEW_CONNECTION_ID:
    print_indent();
    fprintf(
        outfile, "seq=%u conn_id=0x%016" PRIx64 " stateless_reset_token=%s\n",
        fr->new_connection_id.seq, fr->new_connection_id.conn_id,
        util::format_hex(fr->new_connection_id.stateless_reset_token).c_str());
    break;
  case NGTCP2_FRAME_STOP_SENDING:
    print_indent();
    fprintf(outfile, "stream_id=0x%" PRIx64 " app_error_code=%s(0x%04x)\n",
            fr->stop_sending.stream_id,
            strapperrorcode(fr->stop_sending.app_error_code).c_str(),
            fr->stop_sending.app_error_code);
    break;
  case NGTCP2_FRAME_PONG:
    print_indent();
    fprintf(outfile, "length=%zu data=%s\n", fr->pong.datalen,
            util::format_hex(fr->pong.data, fr->pong.datalen).c_str());
    break;
  }
}
} // namespace

int send_pkt(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd, void *user_data) {
  print_timestamp();
  fprintf(outfile, "TX ");
  print_pkt(NGTCP2_DIR_SEND, hd);
  return 0;
}

int send_frame(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
               const ngtcp2_frame *fr, void *user_data) {
  print_indent();
  print_frame(NGTCP2_DIR_SEND, fr);
  return 0;
}

int recv_pkt(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd, void *user_data) {
  print_timestamp();
  fprintf(outfile, "RX ");
  print_pkt(NGTCP2_DIR_RECV, hd);
  return 0;
}

int recv_frame(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
               const ngtcp2_frame *fr, void *user_data) {
  print_indent();
  print_frame(NGTCP2_DIR_RECV, fr);
  return 0;
}

int handshake_completed(ngtcp2_conn *conn, void *user_data) {
  print_timestamp();
  fprintf(outfile, "QUIC handshake has completed\n");
  return 0;
}

int recv_version_negotiation(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                             const uint32_t *sv, size_t nsv, void *user_data) {
  for (size_t i = 0; i < nsv; ++i) {
    print_indent();
    fprintf(outfile, "version=0x%08x\n", sv[i]);
  }
  return 0;
}

int recv_stateless_reset(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                         const ngtcp2_pkt_stateless_reset *sr,
                         void *user_data) {
  print_indent();
  fprintf(outfile, "; Stateless Reset\n");
  print_indent();
  fprintf(outfile, "stateless_reset_token=%s randlen=%zu\n",
          util::format_hex(sr->stateless_reset_token,
                           NGTCP2_STATELESS_RESET_TOKENLEN)
              .c_str(),
          sr->randlen);
  util::hexdump(outfile, sr->rand, sr->randlen);
  return 0;
}

bool packet_lost(double prob) {
  auto p = std::uniform_real_distribution<>(0, 1)(randgen);
  return p < prob;
}

void print_transport_params(const ngtcp2_transport_params *params, int type) {
  switch (type) {
  case NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO:
    print_indent();
    fprintf(outfile, "; initial_version=0x%08x\n",
            params->v.ch.initial_version);
    break;
  case NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS:
    print_indent();
    fprintf(outfile, "; negotiated_version=0x%08x\n",
            params->v.ee.negotiated_version);
    for (size_t i = 0; i < params->v.ee.len; ++i) {
      print_indent();
      fprintf(outfile, "; supported_version[%zu]=0x%08x\n", i,
              params->v.ee.supported_versions[i]);
    }
    break;
  }

  print_indent();
  fprintf(outfile, "; initial_max_stream_data=%u\n",
          params->initial_max_stream_data);
  print_indent();
  fprintf(outfile, "; initial_max_data=%u\n", params->initial_max_data);
  print_indent();
  fprintf(outfile, "; initial_max_stream_id_bidi=0x%x\n",
          params->initial_max_stream_id_bidi);
  print_indent();
  fprintf(outfile, "; initial_max_stream_id_uni=0x%x\n",
          params->initial_max_stream_id_uni);
  print_indent();
  fprintf(outfile, "; idle_timeout=%u\n", params->idle_timeout);
  print_indent();
  fprintf(outfile, "; omit_connection_id=%u\n", params->omit_connection_id);
  print_indent();
  fprintf(outfile, "; max_packet_size=%u\n", params->max_packet_size);

  switch (type) {
  case NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS:
  case NGTCP2_TRANSPORT_PARAMS_TYPE_NEW_SESSION_TICKET:
    print_indent();
    fprintf(outfile, "; stateless_reset_token=%s\n",
            util::format_hex(params->stateless_reset_token).c_str());
    break;
  }

  print_indent();
  fprintf(outfile, "; ack_delay_exponent=%u\n", params->ack_delay_exponent);
}

void print_stream_data(uint64_t stream_id, const uint8_t *data,
                       size_t datalen) {
  print_indent();
  fprintf(outfile, "ordered STREAM data stream_id=0x%" PRIx64 "\n", stream_id);
  util::hexdump(outfile, data, datalen);
}

} // namespace debug

} // namespace ngtcp2
