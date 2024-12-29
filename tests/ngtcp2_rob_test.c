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
#include "ngtcp2_rob_test.h"

#include <stdio.h>

#include "ngtcp2_rob.h"
#include "ngtcp2_test_helper.h"
#include "ngtcp2_mem.h"

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_rob_push),
  munit_void_test(test_ngtcp2_rob_push_random),
  munit_void_test(test_ngtcp2_rob_data_at),
  munit_void_test(test_ngtcp2_rob_remove_prefix),
  munit_test_end(),
};

const MunitSuite rob_suite = {
  .prefix = "/rob",
  .tests = tests,
};

void test_ngtcp2_rob_push(void) {
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_rob rob;
  int rv;
  uint8_t data[256];
  ngtcp2_rob_gap *g;
  ngtcp2_ksl_it it;

  /* Check range overlapping */
  ngtcp2_rob_init(&rob, 64, mem);

  rv = ngtcp2_rob_push(&rob, 34567, data, 145);

  assert_int(0, ==, rv);

  it = ngtcp2_ksl_begin(&rob.gapksl);
  g = ngtcp2_ksl_it_get(&it);

  assert_uint64(0, ==, g->range.begin);
  assert_uint64(34567, ==, g->range.end);

  ngtcp2_ksl_it_next(&it);
  g = ngtcp2_ksl_it_get(&it);

  assert_uint64(34567 + 145, ==, g->range.begin);
  assert_uint64(UINT64_MAX, ==, g->range.end);

  ngtcp2_ksl_it_next(&it);

  assert_true(ngtcp2_ksl_it_end(&it));

  rv = ngtcp2_rob_push(&rob, 34565, data, 1);

  assert_int(0, ==, rv);

  it = ngtcp2_ksl_begin(&rob.gapksl);
  g = ngtcp2_ksl_it_get(&it);

  assert_uint64(0, ==, g->range.begin);
  assert_uint64(34565, ==, g->range.end);

  ngtcp2_ksl_it_next(&it);
  g = ngtcp2_ksl_it_get(&it);

  assert_uint64(34566, ==, g->range.begin);
  assert_uint64(34567, ==, g->range.end);

  rv = ngtcp2_rob_push(&rob, 34563, data, 1);

  assert_int(0, ==, rv);

  it = ngtcp2_ksl_begin(&rob.gapksl);
  g = ngtcp2_ksl_it_get(&it);

  assert_uint64(0, ==, g->range.begin);
  assert_uint64(34563, ==, g->range.end);

  ngtcp2_ksl_it_next(&it);
  g = ngtcp2_ksl_it_get(&it);

  assert_uint64(34564, ==, g->range.begin);
  assert_uint64(34565, ==, g->range.end);

  rv = ngtcp2_rob_push(&rob, 34561, data, 151);

  assert_int(0, ==, rv);

  it = ngtcp2_ksl_begin(&rob.gapksl);
  g = ngtcp2_ksl_it_get(&it);

  assert_uint64(0, ==, g->range.begin);
  assert_uint64(34561, ==, g->range.end);

  ngtcp2_ksl_it_next(&it);
  g = ngtcp2_ksl_it_get(&it);

  assert_uint64(34567 + 145, ==, g->range.begin);
  assert_uint64(UINT64_MAX, ==, g->range.end);

  ngtcp2_ksl_it_next(&it);

  assert_true(ngtcp2_ksl_it_end(&it));

  ngtcp2_rob_free(&rob);

  /* Check removing prefix */
  ngtcp2_rob_init(&rob, 64, mem);

  rv = ngtcp2_rob_push(&rob, 0, data, 123);

  assert_int(0, ==, rv);

  it = ngtcp2_ksl_begin(&rob.gapksl);
  g = ngtcp2_ksl_it_get(&it);

  assert_uint64(123, ==, g->range.begin);
  assert_uint64(UINT64_MAX, ==, g->range.end);

  ngtcp2_ksl_it_next(&it);

  assert_true(ngtcp2_ksl_it_end(&it));

  ngtcp2_rob_free(&rob);

  /* Check removing suffix */
  ngtcp2_rob_init(&rob, 64, mem);

  rv = ngtcp2_rob_push(&rob, UINT64_MAX - 123, data, 123);

  assert_int(0, ==, rv);

  it = ngtcp2_ksl_begin(&rob.gapksl);
  g = ngtcp2_ksl_it_get(&it);

  assert_uint64(0, ==, g->range.begin);
  assert_uint64(UINT64_MAX - 123, ==, g->range.end);

  ngtcp2_ksl_it_next(&it);

  assert_true(ngtcp2_ksl_it_end(&it));

  ngtcp2_rob_free(&rob);
}

static ngtcp2_range randkeys[] = {
  {25996, 26260}, {9431, 9555},   {9113, 9417},   {2992, 3408},
  {35761, 36019}, {38891, 39113}, {30074, 30325}, {9525, 9953},
  {31708, 31944}, {24554, 24864}, {13097, 13472}, {47253, 47400},
  {18424, 18742}, {4618, 4889},   {40871, 41076}, {17642, 18068},
  {47496, 47588}, {1226, 1283},   {17904, 18248}, {9221, 9488},
  {8621, 8773},   {27912, 28344}, {5878, 6121},   {37336, 37545},
  {15403, 15557}, {29314, 29450}, {2342, 2595},   {34000, 34356},
  {46428, 46828}, {40624, 40703}, {47014, 47319}, {13353, 13635},
  {14466, 14682}, {22446, 22654}, {10035, 10140}, {1005, 1410},
  {3741, 4133},   {45734, 46053}, {7954, 8214},   {32666, 32796},
  {45236, 45531}, {32100, 32501}, {25466, 25850}, {2845, 3179},
  {23525, 23991}, {46367, 46459}, {37712, 38164}, {8506, 8680},
  {31702, 31752}, {33364, 33825}, {14284, 14614}, {22928, 23344},
  {29058, 29155}, {36639, 37014}, {29133, 29445}, {31071, 31478},
  {40074, 40370}, {1263, 1383},   {7908, 8181},   {40426, 40716},
  {4830, 5053},   {38241, 38645}, {51197, 51401}, {36180, 36301},
  {14920, 15262}, {5707, 5882},   {32697, 32948}, {42324, 42791},
  {1543, 1732},   {11037, 11395}, {36534, 36707}, {26093, 26322},
  {41862, 42213}, {1373, 1745},   {31322, 31706}, {45474, 45851},
  {19333, 19701}, {49172, 49524}, {10641, 10932}, {17459, 17630},
  {5560, 5936},   {7657, 7988},   {3300, 3357},   {2496, 2600},
  {46018, 46173}, {43127, 43239}, {48949, 49036}, {45094, 45412},
  {8405, 8738},   {8687, 9168},   {41405, 41759}, {22014, 22474},
  {16097, 16426}, {29611, 29931}, {46054, 46250}, {26305, 26545},
  {13696, 13964}, {26899, 26981}, {30797, 30936}, {34125, 34235},
  {50016, 50058}, {46775, 47005}, {4891, 5106},   {12720, 12994},
  {44623, 44967}, {33597, 34060}, {50796, 51295}, {18862, 19242},
  {36166, 36249}, {22237, 22583}, {18188, 18586}, {21376, 21447},
  {49563, 49800}, {10121, 10272}, {39156, 39275}, {17609, 17866},
  {47609, 47829}, {34311, 34631}, {2144, 2433},   {34692, 34824},
  {8309, 8476},   {26969, 27447}, {40651, 40952}, {11906, 12116},
  {22467, 22864}, {35535, 35941}, {33061, 33259}, {21006, 21364},
  {15212, 15504}, {6954, 7356},   {6126, 6405},   {29268, 29514},
  {35221, 35505}, {4163, 4350},   {17374, 17519}, {16170, 16511},
  {37142, 37440}, {6288, 6556},   {27795, 28092}, {35381, 35476},
  {1186, 1455},   {39834, 40197}, {3471, 3906},   {46871, 47242},
  {40258, 40406}, {0, 306},       {31852, 32133}, {23314, 23408},
  {37494, 37625}, {48742, 48990}, {37616, 37905}, {18615, 18991},
  {2561, 2921},   {47767, 48139}, {39616, 39792}, {44791, 45046},
  {2770, 3067},   {16697, 17083}, {9216, 9427},   {37661, 37774},
  {14666, 14976}, {31547, 31819}, {36052, 36356}, {34989, 35285},
  {1651, 2028},   {36264, 36515}, {10257, 10551}, {24381, 24628},
  {28428, 28726}, {4242, 4576},   {44972, 45107}, {12970, 13213},
  {19539, 19828}, {42541, 42763}, {20349, 20630}, {20138, 20418},
  {10884, 11138}, {2717, 2908},   {8292, 8399},   {712, 1101},
  {44451, 44741}, {28660, 28946}, {40955, 41253}, {29424, 29864},
  {14177, 14446}, {30219, 30632}, {24757, 25012}, {47991, 48306},
  {42054, 42252}, {3984, 4419},   {42304, 42506}, {7160, 7543},
  {2004, 2152},   {9777, 10105},  {15724, 16008}, {11263, 11573},
  {15066, 15239}, {12108, 12336}, {17138, 17570}, {30472, 30714},
  {41197, 41294}, {24294, 24496}, {17371, 17514}, {11426, 11749},
  {25223, 25474}, {18083, 18345}, {27611, 27919}, {8116, 8261},
  {40317, 40373}, {46652, 47026}, {18082, 18151}, {19808, 19970},
  {46627, 46885}, {11646, 11789}, {1498, 1687},   {35907, 36081},
  {36340, 36593}, {1255, 1311},   {43485, 43551}, {6586, 6895},
  {10331, 10467}, {26803, 26998}, {14007, 14360}, {35951, 36120},
  {37327, 37592}, {35419, 35724}, {50379, 50514}, {37251, 37489},
  {27313, 27752}, {27502, 27845}, {36608, 36732}, {41751, 42057},
  {19118, 19267}, {16529, 16926}, {49794, 50066}, {37378, 37699},
  {7440, 7552},   {10418, 10650}, {50184, 50635}, {44350, 44579},
  {8178, 8502},   {33838, 34017}, {11582, 11864}, {11756, 11785},
  {42136, 42328}, {39404, 39545}, {13924, 14209}, {29411, 29627},
  {10836, 11139}, {40332, 40598}, {26097, 26561}, {5422, 5512},
  {30687, 30849}, {4399, 4726},   {50679, 50762}, {41224, 41439},
  {46023, 46129}, {22690, 23010}, {37920, 38085}, {25885, 26249},
  {51047, 51185}, {21508, 21904}, {6731, 7010},   {38144, 38493},
  {47648, 47886}, {120, 603},     {49964, 50182}, {43503, 43765},
  {24092, 24436}, {19204, 19509}, {19668, 19930}, {6815, 6963},
  {10552, 10775}, {949, 1239},    {36976, 37348}, {34806, 34901},
  {19939, 20308}, {42245, 42329}, {42700, 43067}, {13821, 14054},
  {28109, 28331}, {32929, 33212}, {23736, 24036}, {31969, 32240},
  {12326, 12612}, {5999, 6132},   {42871, 43283}, {33204, 33496},
  {5757, 5991},   {46826, 46927}, {4994, 5278},   {47371, 47713},
  {20886, 21106}, {38457, 38794}, {48451, 48789}, {34146, 34343},
  {45911, 46248}, {48215, 48615}, {43970, 44131}, {30886, 31216},
  {50135, 50292}, {3726, 3854},   {39041, 39408}, {48617, 48756},
  {46205, 46590}, {39766, 39923}, {20835, 21106}, {43716, 44066},
  {45665, 45789}, {12549, 12755}, {23366, 23752}, {17864, 17942},
  {28288, 28528}, {2744, 2941},   {49355, 49605}, {34527, 34816},
  {23092, 23447}, {5832, 5912},   {21146, 21478}, {30784, 30884},
  {28221, 28469}, {34944, 35047}, {23956, 24126}, {7538, 7890},
  {32496, 32803}, {16404, 16607}, {37968, 38277}, {7399, 7574},
  {28605, 28842}, {50454, 50851}, {20581, 20845}, {21395, 21705},
  {50726, 50871}, {11953, 12278}, {533, 822},     {5298, 5658},
  {48707, 48914}, {21760, 22223}, {1889, 2146},   {6409, 6842},
  {44094, 44473}, {18003, 18336}, {41550, 41926}, {50042, 50136},
  {38646, 38835}, {5425, 5693},   {48967, 49383}, {376, 596},
  {47514, 47704}, {43238, 43663}, {25440, 25655}, {25652, 26050},
  {16909, 17232}, {41312, 41490}, {5909, 6049},   {3153, 3523},
  {27877, 28046}, {26715, 26810}, {10031, 10108}, {32282, 32620},
  {8934, 9219},   {5133, 5493},   {26666, 26787}, {45324, 45630},
  {34880, 35008}, {20823, 20920}, {39571, 39704}, {15523, 15869},
  {4360, 4637},   {46199, 46384}, {35991, 36242}, {46852, 46931},
  {39218, 39644}, {11785, 12029}, {27225, 27366}, {29820, 30097},
  {36778, 37072}, {9871, 10255},  {51065, 51208}, {38775, 39102},
  {39446, 39712}, {33856, 34083}, {28853, 29289}, {526, 666},
  {37510, 37697}, {13455, 13855}, {25648, 25691}, {10694, 11041},
  {26441, 26889}, {18821, 19058}, {3357, 3590},   {15915, 16276},
  {37706, 37934}, {24970, 25281}, {43951, 44124}, {35874, 36128},
};

void test_ngtcp2_rob_push_random(void) {
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_rob rob;
  int rv;
  uint8_t data[512];
  size_t i;

  ngtcp2_rob_init(&rob, 1024 * 1024, mem);
  for (i = 0; i < ngtcp2_arraylen(randkeys); ++i) {
    rv = ngtcp2_rob_push(&rob, randkeys[i].begin, &data[0],
                         (size_t)ngtcp2_range_len(&randkeys[i]));

    assert_int(0, ==, rv);
  }

  assert_uint64(51401, ==, ngtcp2_rob_first_gap_offset(&rob));

  ngtcp2_rob_free(&rob);
}

void test_ngtcp2_rob_data_at(void) {
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_rob rob;
  int rv;
  uint8_t data[256];
  size_t i;
  const uint8_t *p;
  size_t len;
  ngtcp2_rob_data *d;
  ngtcp2_ksl_it it;
  ngtcp2_rob_gap *g;

  for (i = 0; i < sizeof(data); ++i) {
    data[i] = (uint8_t)i;
  }

  ngtcp2_rob_init(&rob, 16, mem);

  rv = ngtcp2_rob_push(&rob, 3, &data[3], 13);

  assert_int(0, ==, rv);

  len = ngtcp2_rob_data_at(&rob, &p, 0);

  assert_size(0, ==, len);

  rv = ngtcp2_rob_push(&rob, 0, &data[0], 3);

  assert_int(0, ==, rv);

  len = ngtcp2_rob_data_at(&rob, &p, 0);

  assert_size(16, ==, len);

  for (i = 0; i < len; ++i) {
    assert_uint8((uint8_t)i, ==, *(p + i));
  }

  ngtcp2_rob_pop(&rob, 0, len);

  rv = ngtcp2_rob_push(&rob, 16, &data[16], 5);

  assert_int(0, ==, rv);

  len = ngtcp2_rob_data_at(&rob, &p, 16);

  assert_size(5, ==, len);

  for (i = 16; i < len; ++i) {
    assert_uint8((uint8_t)i, ==, *(p + i));
  }

  ngtcp2_rob_free(&rob);

  /* Verify the case where data spans over multiple chunks */
  ngtcp2_rob_init(&rob, 16, mem);

  rv = ngtcp2_rob_push(&rob, 0, &data[0], 47);

  assert_int(0, ==, rv);

  len = ngtcp2_rob_data_at(&rob, &p, 0);

  assert_size(16, ==, len);

  ngtcp2_rob_pop(&rob, 0, len);
  len = ngtcp2_rob_data_at(&rob, &p, 16);

  assert_size(16, ==, len);

  ngtcp2_rob_pop(&rob, 16, len);
  len = ngtcp2_rob_data_at(&rob, &p, 32);

  assert_size(15, ==, len);

  ngtcp2_rob_pop(&rob, 32, len);
  ngtcp2_rob_free(&rob);

  /* Verify the case where new offset comes before the existing
     chunk */
  ngtcp2_rob_init(&rob, 16, mem);

  rv = ngtcp2_rob_push(&rob, 17, &data[17], 2);

  assert_int(0, ==, rv);

  len = ngtcp2_rob_data_at(&rob, &p, 0);

  assert_size(0, ==, len);

  rv = ngtcp2_rob_push(&rob, 0, &data[0], 3);

  assert_int(0, ==, rv);

  len = ngtcp2_rob_data_at(&rob, &p, 0);

  assert_size(3, ==, len);

  ngtcp2_rob_pop(&rob, 0, len);

  len = ngtcp2_rob_data_at(&rob, &p, 3);

  assert_size(0, ==, len);

  ngtcp2_rob_free(&rob);

  /* Verify the case where new offset comes after the existing
     chunk */
  ngtcp2_rob_init(&rob, 16, mem);

  rv = ngtcp2_rob_push(&rob, 0, &data[0], 3);

  assert_int(0, ==, rv);

  rv = ngtcp2_rob_push(&rob, 16, &data[16], 32);

  assert_int(0, ==, rv);

  it = ngtcp2_ksl_begin(&rob.dataksl);
  ngtcp2_ksl_it_next(&it);
  d = ngtcp2_ksl_it_get(&it);

  assert_uint64(16, ==, d->range.begin);

  ngtcp2_ksl_it_next(&it);
  d = ngtcp2_ksl_it_get(&it);

  assert_uint64(32, ==, d->range.begin);

  ngtcp2_ksl_it_next(&it);

  assert_true(ngtcp2_ksl_it_end(&it));

  ngtcp2_rob_free(&rob);

  /* Severely scattered data */
  ngtcp2_rob_init(&rob, 16, mem);

  for (i = 0; i < sizeof(data); i += 2) {
    rv = ngtcp2_rob_push(&rob, i, &data[i], 1);

    assert_int(0, ==, rv);
  }

  for (i = 1; i < sizeof(data); i += 2) {
    rv = ngtcp2_rob_push(&rob, i, &data[i], 1);

    assert_int(0, ==, rv);
  }

  for (i = 0; i < sizeof(data) / 16; ++i) {
    len = ngtcp2_rob_data_at(&rob, &p, i * 16);

    assert_size(16, ==, len);

    ngtcp2_rob_pop(&rob, i * 16, len);
  }

  it = ngtcp2_ksl_begin(&rob.gapksl);
  g = ngtcp2_ksl_it_get(&it);

  assert_uint64(256, ==, g->range.begin);

  it = ngtcp2_ksl_begin(&rob.dataksl);

  assert_true(ngtcp2_ksl_it_end(&it));

  ngtcp2_rob_free(&rob);

  /* Verify the case where chunk is reused if it is not fully used */
  ngtcp2_rob_init(&rob, 16, mem);

  rv = ngtcp2_rob_push(&rob, 0, &data[0], 5);

  assert_int(0, ==, rv);

  len = ngtcp2_rob_data_at(&rob, &p, 0);

  assert_size(5, ==, len);

  ngtcp2_rob_pop(&rob, 0, len);

  rv = ngtcp2_rob_push(&rob, 2, &data[2], 8);

  assert_int(0, ==, rv);

  len = ngtcp2_rob_data_at(&rob, &p, 5);

  assert_size(5, ==, len);

  ngtcp2_rob_pop(&rob, 5, len);

  ngtcp2_rob_free(&rob);

  /* Verify the case where 2nd push covers already processed region */
  ngtcp2_rob_init(&rob, 16, mem);

  rv = ngtcp2_rob_push(&rob, 0, &data[0], 16);

  assert_int(0, ==, rv);

  len = ngtcp2_rob_data_at(&rob, &p, 0);

  assert_size(16, ==, len);

  ngtcp2_rob_pop(&rob, 0, len);

  rv = ngtcp2_rob_push(&rob, 0, &data[0], 32);

  assert_int(0, ==, rv);

  len = ngtcp2_rob_data_at(&rob, &p, 16);

  assert_size(16, ==, len);

  ngtcp2_rob_pop(&rob, 16, len);

  ngtcp2_rob_free(&rob);
}

void test_ngtcp2_rob_remove_prefix(void) {
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_rob rob;
  ngtcp2_rob_gap *g;
  ngtcp2_rob_data *d;
  ngtcp2_ksl_it it;
  uint8_t data[256];
  int rv;

  /* Removing data which spans multiple chunks */
  ngtcp2_rob_init(&rob, 16, mem);

  rv = ngtcp2_rob_push(&rob, 1, &data[1], 32);

  assert_int(0, ==, rv);

  ngtcp2_rob_remove_prefix(&rob, 33);

  it = ngtcp2_ksl_begin(&rob.gapksl);
  g = ngtcp2_ksl_it_get(&it);

  assert_uint64(33, ==, g->range.begin);

  it = ngtcp2_ksl_begin(&rob.dataksl);
  d = ngtcp2_ksl_it_get(&it);

  assert_uint64(32, ==, d->range.begin);

  ngtcp2_rob_free(&rob);

  /* Remove an entire gap */
  ngtcp2_rob_init(&rob, 16, mem);

  rv = ngtcp2_rob_push(&rob, 1, &data[1], 3);

  assert_int(0, ==, rv);

  rv = ngtcp2_rob_push(&rob, 5, &data[5], 2);

  assert_int(0, ==, rv);

  ngtcp2_rob_remove_prefix(&rob, 16);

  it = ngtcp2_ksl_begin(&rob.gapksl);
  g = ngtcp2_ksl_it_get(&it);

  assert_uint64(16, ==, g->range.begin);

  ngtcp2_ksl_it_next(&it);

  assert_true(ngtcp2_ksl_it_end(&it));

  ngtcp2_rob_free(&rob);
}
