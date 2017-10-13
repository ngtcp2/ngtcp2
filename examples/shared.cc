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
#include "shared.h"

namespace ngtcp2 {

uint16_t infer_quic_error_code(int liberr) {
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
  default:
    return NGTCP2_PROTOCOL_VIOLATION;
  }
}

} // namespace ngtcp2
