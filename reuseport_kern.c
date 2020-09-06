#include <stdlib.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/*
 * How to compile:
 *
 * clang-10 -O2 -Wall -target bpf -g -c reuseport_kern.c -o reuseport_kern.o \
 *   -I/path/to/kernel/include
 *
 * See
 * https://www.kernel.org/doc/Documentation/kbuild/headers_install.txt
 * how to install kernel header files.
 */

/* rol32: From linux kernel source code */

/**
 * rol32 - rotate a 32-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline __u32 rol32(__u32 word, unsigned int shift) {
  return (word << shift) | (word >> ((-shift) & 31));
}

/* jhash.h: Jenkins hash support.
 *
 * Copyright (C) 2006. Bob Jenkins (bob_jenkins@burtleburtle.net)
 *
 * https://burtleburtle.net/bob/hash/
 *
 * These are the credits from Bob's sources:
 *
 * lookup3.c, by Bob Jenkins, May 2006, Public Domain.
 *
 * These are functions for producing 32-bit hashes for hash table lookup.
 * hashword(), hashlittle(), hashlittle2(), hashbig(), mix(), and final()
 * are externally useful functions.  Routines to test the hash are included
 * if SELF_TEST is defined.  You can use this free for any purpose.  It's in
 * the public domain.  It has no warranty.
 *
 * Copyright (C) 2009-2010 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
 *
 * I've modified Bob's hash to be useful in the Linux kernel, and
 * any bugs present are my fault.
 * Jozsef
 */

/* __jhash_final - final mixing of 3 32-bit values (a,b,c) into c */
#define __jhash_final(a, b, c)                                                 \
  {                                                                            \
    c ^= b;                                                                    \
    c -= rol32(b, 14);                                                         \
    a ^= c;                                                                    \
    a -= rol32(c, 11);                                                         \
    b ^= a;                                                                    \
    b -= rol32(a, 25);                                                         \
    c ^= b;                                                                    \
    c -= rol32(b, 16);                                                         \
    a ^= c;                                                                    \
    a -= rol32(c, 4);                                                          \
    b ^= a;                                                                    \
    b -= rol32(a, 14);                                                         \
    c ^= b;                                                                    \
    c -= rol32(b, 24);                                                         \
  }

/* __jhash_nwords - hash exactly 3, 2 or 1 word(s) */
static inline __u32 __jhash_nwords(__u32 a, __u32 b, __u32 c, __u32 initval) {
  a += initval;
  b += initval;
  c += initval;

  __jhash_final(a, b, c);

  return c;
}

/* An arbitrary initial parameter */
#define JHASH_INITVAL 0xdeadbeef

static inline __u32 jhash_2words(__u32 a, __u32 b, __u32 initval) {
  return __jhash_nwords(a, b, 0, initval + JHASH_INITVAL + (2 << 2));
}

struct {
  __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
  __uint(max_entries, 255);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
} reuseport_array SEC(".maps");

typedef struct vec {
  __u8 *data;
  __u8 *data_end;
} vec;

typedef struct quic_hd {
  __u8 *dcid;
  __u32 dcid_offset;
  __u32 dcid_len;
  __u8 type;
} quic_hd;

#define SV_DCIDLEN 18
#define MAX_DCIDLEN 20
#define MIN_DCIDLEN 8

static inline int parse_quic(quic_hd *qhd, struct sk_reuseport_md *reuse_md) {
  __u64 len = sizeof(struct udphdr) + 1;
  __u8 *p;
  __u64 dcidlen;

  if (reuse_md->data + len > reuse_md->data_end) {
    return -1;
  }

  p = reuse_md->data + sizeof(struct udphdr);

  if (*p & 0x80) {
    len += 4 + 1;
    if (reuse_md->data + len > reuse_md->data_end) {
      return -1;
    }

    p += 1 + 4;

    dcidlen = *p;

    if (dcidlen > MAX_DCIDLEN || dcidlen < MIN_DCIDLEN) {
      return -1;
    }

    len += 1 + dcidlen;

    if (reuse_md->data + len > reuse_md->data_end) {
      return -1;
    }

    ++p;

    qhd->type =
        (*((__u8 *)(reuse_md->data) + sizeof(struct udphdr)) & 0x30) >> 4;
    qhd->dcid = p;
    qhd->dcid_offset = sizeof(struct udphdr) + 6;
    qhd->dcid_len = dcidlen;
  } else {
    len += SV_DCIDLEN;
    if (reuse_md->data + len > reuse_md->data_end) {
      return -1;
    }

    qhd->type = 0xff;
    qhd->dcid = (__u8 *)reuse_md->data + sizeof(struct udphdr) + 1;
    qhd->dcid_offset = sizeof(struct udphdr) + 1;
    qhd->dcid_len = SV_DCIDLEN;
  }

  return 0;
}

#define NUM_SOCKETS 4

SEC("sk_reuseport")
int _select_by_skb_data(struct sk_reuseport_md *reuse_md) {
  __u32 sk_index;
  int rv;
  quic_hd qhd;
  __u32 a, b;
  __u8 *p;

  rv = parse_quic(&qhd, reuse_md);
  if (rv != 0) {
    return SK_DROP;
  }

  switch (qhd.type) {
  case 0x0: /* Initial */
  case 0x1: /* 0-RTT */
    if (reuse_md->data + sizeof(struct udphdr) + 6 + 8 > reuse_md->data_end) {
      return SK_DROP;
    }

    p = (__u8 *)reuse_md->data + sizeof(struct udphdr) + 6;
    a = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
    b = (p[4] << 24) | (p[5] << 16) | (p[6] << 8) | p[7];

    sk_index = jhash_2words(a, b, reuse_md->hash) % NUM_SOCKETS;

    break;
  case 0x2: /* Handshake */
    if (qhd.dcid_len != SV_DCIDLEN) {
      return SK_DROP;
    }

    if (reuse_md->data + sizeof(struct udphdr) + 6 + 1 > reuse_md->data_end) {
      return SK_DROP;
    }

    sk_index =
        *((__u8 *)reuse_md->data + sizeof(struct udphdr) + 6) % NUM_SOCKETS;

    break;
  case 0xff: /* Short */
    if (qhd.dcid_len != SV_DCIDLEN) {
      return SK_DROP;
    }

    if (reuse_md->data + sizeof(struct udphdr) + 1 + 1 > reuse_md->data_end) {
      return SK_DROP;
    }

    sk_index =
        *((__u8 *)reuse_md->data + sizeof(struct udphdr) + 1) % NUM_SOCKETS;
    break;
  default:
    return SK_DROP;
  }

  rv = bpf_sk_select_reuseport(reuse_md, &reuseport_array, &sk_index, 0);
  if (rv != 0) {
    return SK_DROP;
  }

  return SK_PASS;
}
