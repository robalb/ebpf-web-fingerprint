/* SPDX-License-Identifier: Dual MIT/GPL */
/*
 * Vendored Linux UAPI network headers for BPF programs.
 *
 * These struct definitions match the stable kernel UAPI and have not
 * changed in decades. Vendoring them removes the build dependency on
 * system-installed linux headers (linux-libc-dev, gcc-multilib, etc).
 *
 * Sources: linux/types.h, linux/if_ether.h, linux/ip.h,
 *          linux/ipv6.h, linux/in6.h, linux/tcp.h, linux/in.h,
 *          linux/bpf.h, linux/byteorder.
 */
#ifndef __NET_HEADERS_H__
#define __NET_HEADERS_H__

/* ---- Basic types (linux/types.h) ---- */

typedef __signed__ char   __s8;
typedef unsigned char     __u8;
typedef short             __s16;
typedef unsigned short    __u16;
typedef int               __s32;
typedef unsigned int      __u32;
typedef long long         __s64;
typedef unsigned long long __u64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u16 __sum16;
typedef __u32 __wsum;

/* ---- Byte order (linux/byteorder) ---- */

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __constant_htons(x) ((__be16)((((__u16)(x) & 0x00ffU) << 8) | \
                                      (((__u16)(x) & 0xff00U) >> 8)))
#define __constant_ntohs(x) __constant_htons(x)
#define __LITTLE_ENDIAN_BITFIELD
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define __constant_htons(x) ((__be16)(__u16)(x))
#define __constant_ntohs(x) ((__be16)(__u16)(x))
#define __BIG_ENDIAN_BITFIELD
#else
#error "Unknown byte order"
#endif

/* ---- Ethernet (linux/if_ether.h) ---- */

#define ETH_ALEN   6
#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_8021Q  0x8100
#define ETH_P_8021AD 0x88A8

struct ethhdr {
  unsigned char h_dest[ETH_ALEN];
  unsigned char h_source[ETH_ALEN];
  __be16        h_proto;
} __attribute__((packed));

/* ---- IPv4 (linux/ip.h) ---- */

#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF


struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
  __u8  ihl:4,
        version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
  __u8  version:4,
        ihl:4;
#endif
  __u8    tos;
  __be16  tot_len;
  __be16  id;
  __be16  frag_off;
  __u8    ttl;
  __u8    protocol;
  __sum16 check;
  __be32  saddr;
  __be32  daddr;
};

/* ---- IPv6 address (linux/in6.h) ---- */

struct in6_addr {
  union {
    __u8   u6_addr8[16];
    __be16 u6_addr16[8];
    __be32 u6_addr32[4];
  } in6_u;
#define s6_addr   in6_u.u6_addr8
#define s6_addr16 in6_u.u6_addr16
#define s6_addr32 in6_u.u6_addr32
};

/* ---- IPv6 header (linux/ipv6.h) ---- */

struct ipv6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
  __u8  priority:4,
        version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
  __u8  version:4,
        priority:4;
#endif
  __u8            flow_lbl[3];
  __be16          payload_len;
  __u8            nexthdr;
  __u8            hop_limit;
  struct in6_addr saddr;
  struct in6_addr daddr;
};

/* ---- TCP (linux/tcp.h) ---- */

struct tcphdr {
  __be16  source;
  __be16  dest;
  __be32  seq;
  __be32  ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
  __u16   res1:4,
          doff:4,
          fin:1,
          syn:1,
          rst:1,
          psh:1,
          ack:1,
          urg:1,
          ece:1,
          cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
  __u16   doff:4,
          res1:4,
          cwr:1,
          ece:1,
          urg:1,
          ack:1,
          psh:1,
          rst:1,
          syn:1,
          fin:1;
#endif
  __be16  window;
  __sum16 check;
  __be16  urg_ptr;
};

/* ---- IP protocols (linux/in.h) ---- */

#define IPPROTO_TCP 6

/* ---- BPF (linux/bpf.h) ---- */

#define BPF_ANY 0

enum bpf_map_type {
  BPF_MAP_TYPE_UNSPEC   = 0,
  BPF_MAP_TYPE_HASH     = 1,
  BPF_MAP_TYPE_ARRAY    = 2,
  BPF_MAP_TYPE_LRU_HASH = 9,
};

enum xdp_action {
  XDP_ABORTED  = 0,
  XDP_DROP     = 1,
  XDP_PASS     = 2,
  XDP_TX       = 3,
  XDP_REDIRECT = 4,
};

struct xdp_md {
  __u32 data;
  __u32 data_end;
  __u32 data_meta;
  __u32 ingress_ifindex;
  __u32 rx_queue_index;
  __u32 egress_ifindex;
};

#endif /* __NET_HEADERS_H__ */
