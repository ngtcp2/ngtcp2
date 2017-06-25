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
#include "util.h"

namespace ngtcp2 {

namespace debug {

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
  case NGTCP2_PKT_CLIENT_INITIAL:
    return "Client Initial";
  case NGTCP2_PKT_SERVER_STATELESS_RETRY:
    return "Server Stateless Retry";
  case NGTCP2_PKT_SERVER_CLEARTEXT:
    return "Server Cleartext";
  case NGTCP2_PKT_CLIENT_CLEARTEXT:
    return "Client Cleartext";
  case NGTCP2_PKT_0RTT_PROTECTED:
    return "0-RTT Protected";
  case NGTCP2_PKT_1RTT_PROTECTED_K0:
    return "1-RTT Protected (key phase 0)";
  case NGTCP2_PKT_1RTT_PROTECTED_K1:
    return "1-RTT Protected (key phase 1)";
  case NGTCP2_PKT_PUBLIC_RESET:
    return "Public Reset";
  default:
    return "UNKNOWN(0x" + util::format_hex(type) + ")";
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
  case NGTCP2_FRAME_GOAWAY:
    return "GOAWAY";
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
  case NGTCP2_FRAME_STREAM_ID_NEEDED:
    return "STREAM_ID_NEEDED";
  case NGTCP2_FRAME_NEW_CONNECTION_ID:
    return "NEW_CONNECTION_ID";
  case NGTCP2_FRAME_ACK:
    return "ACK";
  case NGTCP2_FRAME_STREAM:
    return "STREAM";
  default:
    return "UNKNOWN(0x" + util::format_hex(type) + ")";
  }
}
} // namespace

void print_timestamp() {
  auto t = timestamp().count();
  fprintf(outfile, "%s[%3d.%06d]%s ", ansi_esc("\033[33m"),
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
void print_indent() { fprintf(outfile, "             "); }
} // namespace

namespace {
void print_pkt_long(ngtcp2_dir dir, const ngtcp2_pkt_hd *hd) {
  fprintf(outfile, "%s%s%s packet\n", pkt_ansi_esc(dir),
          strpkttype_long(hd->type).c_str(), ansi_escend());
  print_indent();
  fprintf(outfile, "<conn_id=0x%016lx, pkt_num=%lu, ver=0x%08x>\n", hd->conn_id,
          hd->pkt_num, hd->version);
}
} // namespace

namespace {
void print_pkt_short(ngtcp2_dir dir, const ngtcp2_pkt_hd *hd) {
  fprintf(outfile, "short pkt\n");
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
void print_frame(ngtcp2_dir dir, const ngtcp2_frame *fr) {
  fprintf(outfile, "%s%s%s frame\n", frame_ansi_esc(dir),
          strframetype(fr->type).c_str(), ansi_escend());

  switch (fr->type) {
  case NGTCP2_FRAME_STREAM:
    print_indent();
    fprintf(outfile, "<stream_id=0x%08x, offset=%lu, data_length=%zu>\n",
            fr->stream.stream_id, fr->stream.offset, fr->stream.datalen);
    break;
  case NGTCP2_FRAME_PADDING:
    print_indent();
    fprintf(outfile, "<length=%zu>\n", fr->padding.len);
    break;
  case NGTCP2_FRAME_ACK:
    print_indent();
    fprintf(outfile,
            "<num_blks=%zu, num_ts=%zu, largest_ack=%lu, ack_delay=%u>\n",
            fr->ack.num_blks, fr->ack.num_ts, fr->ack.largest_ack,
            fr->ack.ack_delay);
    print_indent();
    fprintf(outfile, "; first_ack_block_length=%lu\n",
            fr->ack.first_ack_blklen);
    for (size_t i = 0; i < fr->ack.num_blks; ++i) {
      auto blk = &fr->ack.blks[i];
      print_indent();
      fprintf(outfile, "; gap=%u, ack_block_length=%lu\n", blk->gap,
              blk->blklen);
    }
    break;
  }
}
} // namespace

int send_pkt(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd, void *user_data) {
  print_timestamp();
  fprintf(outfile, "send ");
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
  fprintf(outfile, "recv ");
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
    fprintf(outfile, "; version=0x%08x\n", sv[i]);
  }
  return 0;
}

} // namespace debug

} // namespace ngtcp2
