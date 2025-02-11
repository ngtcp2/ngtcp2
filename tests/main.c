/*
 * ngtcp2
 *
 * Copyright (c) 2016 ngtcp2 contributors
 * Copyright (c) 2012 nghttp2 contributors
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
#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#include "munit.h"

/* include test cases' include files here */
#include "ngtcp2_pkt_test.h"
#include "ngtcp2_range_test.h"
#include "ngtcp2_rob_test.h"
#include "ngtcp2_rtb_test.h"
#include "ngtcp2_acktr_test.h"
#include "ngtcp2_transport_params_test.h"
#include "ngtcp2_idtr_test.h"
#include "ngtcp2_conn_test.h"
#include "ngtcp2_ringbuf_test.h"
#include "ngtcp2_conv_test.h"
#include "ngtcp2_ksl_test.h"
#include "ngtcp2_map_test.h"
#include "ngtcp2_gaptr_test.h"
#include "ngtcp2_vec_test.h"
#include "ngtcp2_strm_test.h"
#include "ngtcp2_pv_test.h"
#include "ngtcp2_pmtud_test.h"
#include "ngtcp2_str_test.h"
#include "ngtcp2_tstamp_test.h"
#include "ngtcp2_cc_test.h"
#include "ngtcp2_qlog_test.h"
#include "ngtcp2_window_filter_test.h"
#include "ngtcp2_settings_test.h"
#include "ngtcp2_ppe_test.h"
#include "ngtcp2_dcidtr_test.h"
#include "ngtcp2_addr_test.h"

int main(int argc, char *argv[]) {
  const MunitSuite suites[] = {
    pkt_suite,
    range_suite,
    rob_suite,
    acktr_suite,
    map_suite,
    transport_params_suite,
    rtb_suite,
    idtr_suite,
    conn_suite,
    ringbuf_suite,
    conv_suite,
    ksl_suite,
    gaptr_suite,
    vec_suite,
    strm_suite,
    pv_suite,
    pmtud_suite,
    str_suite,
    tstamp_suite,
    cc_suite,
    qlog_suite,
    window_filter_suite,
    settings_suite,
    ppe_suite,
    dcidtr_suite,
    addr_suite,
    {0},
  };
  const MunitSuite suite = {
    .prefix = "",
    .suites = suites,
    .iterations = 1,
  };

  init_static_path();

  return munit_suite_main(&suite, NULL, argc, argv);
}
