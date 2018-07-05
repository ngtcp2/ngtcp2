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
#include "ngtcp2_err.h"

const char *ngtcp2_strerror(int liberr) {
  switch (liberr) {
  case 0:
    return "NO_ERROR";
  case NGTCP2_ERR_INVALID_ARGUMENT:
    return "ERR_INVALID_ARGUMENT";
  case NGTCP2_ERR_UNKNOWN_PKT_TYPE:
    return "ERR_UNKNOWN_PKT_TYPE";
  case NGTCP2_ERR_NOBUF:
    return "ERR_NOBUF";
  case NGTCP2_ERR_BAD_PKT_HASH:
    return "ERR_BAD_PKT_HASH";
  case NGTCP2_ERR_PROTO:
    return "ERR_PROTO";
  case NGTCP2_ERR_INVALID_STATE:
    return "ERR_INVALID_STATE";
  case NGTCP2_ERR_ACK_FRAME:
    return "ERR_ACK_FRAME";
  case NGTCP2_ERR_STREAM_ID_BLOCKED:
    return "ERR_STREAM_ID_BLOCKED";
  case NGTCP2_ERR_STREAM_IN_USE:
    return "ERR_STREAM_IN_USE";
  case NGTCP2_ERR_STREAM_DATA_BLOCKED:
    return "ERR_STREAM_DATA_BLOCKED";
  case NGTCP2_ERR_FLOW_CONTROL:
    return "ERR_FLOW_CONTROL";
  case NGTCP2_ERR_PKT_TIMEOUT:
    return "ERR_PKT_TIMEOUT";
  case NGTCP2_ERR_STREAM_ID:
    return "ERR_STREAM_ID";
  case NGTCP2_ERR_FINAL_OFFSET:
    return "ERR_FINAL_OFFSET";
  case NGTCP2_ERR_PKT_NUM_EXHAUSTED:
    return "ERR_PKT_NUM_EXHAUSTED";
  case NGTCP2_ERR_NOMEM:
    return "ERR_NOMEM";
  case NGTCP2_ERR_TLS_HANDSHAKE:
    return "ERR_TLS_HANDSHAKE";
  case NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM:
    return "ERR_REQUIRED_TRANSPORT_PARAM";
  case NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM:
    return "ERR_MALFORMED_TRANSPORT_PARAM";
  case NGTCP2_ERR_FRAME_FORMAT:
    return "ERR_FRAME_FORMAT";
  case NGTCP2_ERR_TLS_DECRYPT:
    return "ERR_TLS_DECRYPT";
  case NGTCP2_ERR_STREAM_SHUT_WR:
    return "ERR_STREAM_SHUT_WR";
  case NGTCP2_ERR_STREAM_NOT_FOUND:
    return "ERR_STREAM_NOT_FOUND";
  case NGTCP2_ERR_VERSION_NEGOTIATION:
    return "ERR_VERSION_NEGOTIATION";
  case NGTCP2_ERR_TLS_FATAL_ALERT_GENERATED:
    return "ERR_TLS_FATAL_ALERT_GENERATED";
  case NGTCP2_ERR_TLS_FATAL_ALERT_RECEIVED:
    return "ERR_TLS_FATAL_ALERT_RECEIVED";
  case NGTCP2_ERR_STREAM_STATE:
    return "ERR_STREAM_STATE";
  case NGTCP2_ERR_NOKEY:
    return "ERR_NOKEY";
  case NGTCP2_ERR_EARLY_DATA_REJECTED:
    return "ERR_EARLY_DATA_REJECTED";
  case NGTCP2_ERR_RECV_VERSION_NEGOTIATION:
    return "ERR_RECV_VERSION_NEGOTIATION";
  case NGTCP2_ERR_CLOSING:
    return "ERR_CLOSING";
  case NGTCP2_ERR_DRAINING:
    return "ERR_DRAINING";
  case NGTCP2_ERR_CALLBACK_FAILURE:
    return "ERR_CALLBACK_FAILURE";
  case NGTCP2_ERR_INTERNAL:
    return "ERR_INTERNAL";
  case NGTCP2_ERR_CALLBACK_RETRY:
    return "ERR_CALLBACK_RETRY";
  default:
    return "(unknown)";
  }
}

int ngtcp2_err_fatal(int liberr) { return liberr >= NGTCP2_ERR_FATAL; }

uint16_t ngtcp2_err_infer_quic_transport_error_code(int liberr) {
  switch (liberr) {
  case 0:
    return NGTCP2_NO_ERROR;
  case NGTCP2_ERR_ACK_FRAME:
  case NGTCP2_ERR_FRAME_FORMAT:
    return NGTCP2_FRAME_FORMAT_ERROR;
  case NGTCP2_ERR_FLOW_CONTROL:
    return NGTCP2_FLOW_CONTROL_ERROR;
  case NGTCP2_ERR_STREAM_ID:
    return NGTCP2_STREAM_ID_ERROR;
  case NGTCP2_ERR_FINAL_OFFSET:
    return NGTCP2_FINAL_OFFSET_ERROR;
  case NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM:
    return NGTCP2_TRANSPORT_PARAMETER_ERROR;
  case NGTCP2_ERR_INVALID_ARGUMENT:
    return NGTCP2_INTERNAL_ERROR;
  case NGTCP2_ERR_TLS_HANDSHAKE:
    return NGTCP2_TLS_HANDSHAKE_FAILED;
  case NGTCP2_ERR_TLS_FATAL_ALERT_GENERATED:
    return NGTCP2_TLS_FATAL_ALERT_GENERATED;
  case NGTCP2_ERR_TLS_FATAL_ALERT_RECEIVED:
    return NGTCP2_TLS_FATAL_ALERT_RECEIVED;
  case NGTCP2_ERR_STREAM_STATE:
    return NGTCP2_STREAM_STATE_ERROR;
  case NGTCP2_ERR_VERSION_NEGOTIATION:
    return NGTCP2_VERSION_NEGOTIATION_ERROR;
  default:
    return NGTCP2_PROTOCOL_VIOLATION;
  }
}
