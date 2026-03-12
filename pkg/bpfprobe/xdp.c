// go:build ignore
// +build ignore

// clang-format off
#include <linux/byteorder/little_endian.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <stdbool.h>
#include "../../headers/bpf_helpers.h"
#include "../../headers/bpf_endian.h"
// clang-format on

// to read logs:
// sudo cat  /sys/kernel/debug/tracing/trace_pipe
#define DEBUG 1

char __license[] SEC("license") = "Dual MIT/GPL";
#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF

/*
 * The max bytes of TCP options we are willing to copy
 */
#define TCPOPT_MAXLEN 40

/*
 * TCP destination port, injected at program load.
 * Defaults to 443 when not set
 */
__be16 dst_port = __constant_htons(443);
/*
 * Destination IP, injected at program load.
 * Defaults to 127.0.0.1 when not set
 */
__be32 dst_ip = 16777343;
struct in6_addr dst_ipv6 = {};

/*
 * This eBPF map holds a single counter value that is
 * incremented on every TCP SYN received.
 * This counter val is only used for debug statystics
 * and will be removed in the future.
 */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 1);
} pkt_count SEC(".maps");

/*
 * This eBPF map holds the packed data extracted from
 * all TCP SYN packets directed to our webserver.
 */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 8192);
  __type(key, __u64);
  __type(value, struct tcp_handshake_val);
} tcp_handshakes SEC(".maps");

/*
 * Mirror of the vlan_hdr struct defined in linux/if_vlan.h,
 * which is normally not exposed as part of the linux UAPI.
 */
struct _vlan_hdr {
  __be16 h_vlan_TCI;
  __be16 h_vlan_encapsulated_proto;
};

struct tcp_handshake_val {
  __u64 tick;
  __be32 seq;      /* TCP seq during the TCP SYN - used for correlation */
  __be32 src_addr; /* IP source - used for correlation */
  __be16 src_port; /* TCP source - used for correlation */
  __be16 window;   /* TCP window */
  __u16 optlen;    /* length of the TCP options. */
  __u8 ip_ttl;     /* IP TTL */
  __u8 options[TCPOPT_MAXLEN];
};

static __u64 __always_inline make_key(__u32 ip, __u16 port) {
  return ((__u64)ip << 16) | port;
}

/**
 * Compare two ipv6 addresses.
 * We compare section by section simply because __builtin_memcmp
 * doesn't exist in the current clang-ebpf version.
 */
static bool __always_inline ipv6_addr_equal(const struct in6_addr *a,
                                            const struct in6_addr *b) {
  __u32 diff = 0;

  diff |= a->s6_addr32[0] ^ b->s6_addr32[0];
  diff |= a->s6_addr32[1] ^ b->s6_addr32[1];
  diff |= a->s6_addr32[2] ^ b->s6_addr32[2];
  diff |= a->s6_addr32[3] ^ b->s6_addr32[3];

  return diff == 0;
}

static void __always_inline parse_tcp_syn(struct iphdr *ip, struct tcphdr *tcp,
                                          void *data_end);

static __always_inline int proto_is_vlan(__u16 h_proto) {
  return !!(h_proto == __constant_htons(ETH_P_8021Q) ||
            h_proto == __constant_htons(ETH_P_8021AD));
}

SEC("xdp")
int count_packets(struct xdp_md *ctx) {

  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  /* cursor to keep track of current parsing position */
  void *head = data;

  // ++++++++++
  // ETH layer
  // ++++++++++

  struct ethhdr *eth = head;
  head += sizeof(*eth);

  /* Make sure packet is large enough for parsing eth + 2 VLAN headers */
  if (head + (2 * sizeof(struct _vlan_hdr)) > data_end)
    return XDP_PASS;

  __u16 eth_type = eth->h_proto;

  /* handle vlan tagged packets. */
  if (proto_is_vlan(eth_type)) {
    struct _vlan_hdr *vlan = head;
    head += sizeof(*vlan);
    eth_type = vlan->h_vlan_encapsulated_proto;
  }

  /* Handle inner (double) VLAN tag */
  if (proto_is_vlan(eth_type)) {
    struct _vlan_hdr *vlan = head;
    head += sizeof(*vlan);
    eth_type = vlan->h_vlan_encapsulated_proto;
  }

  // ++++++++++
  // IP layer
  // ++++++++++

  struct iphdr *ip;
  struct ipv6hdr *ip6;

  __u8 ttl = 0;

  if (eth_type == __constant_htons(ETH_P_IP)) {
    ip = head;
    head += sizeof(*ip);

    if (head > data_end)
      return XDP_PASS;

    char is_fragment = ip->frag_off & __constant_htons(IP_MF | IP_OFFSET);
    if (is_fragment)
      return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
      return XDP_PASS;

    if (ip->daddr != dst_ip)
      return XDP_PASS;

    __u32 ip_hdr_len = ip->ihl * 4;
    // sanity check that the packet field is valid
    if (ip_hdr_len < sizeof(*ip)) {
      return XDP_PASS;
    }
    // Adjust the head to follow the dynamic length
    // declared in the packet instead of the struct len
    head += ip_hdr_len - sizeof(*ip);

  } else if (eth_type == __constant_htons(ETH_P_IPV6)) {
    ip6 = head;
    head += sizeof(*ip6);

    if (head > data_end) {
      return XDP_PASS;
    }

    if (ipv6_addr_equal(&ip6->daddr, &dst_ipv6) != 0) {
      return XDP_PASS;
    }

    // TODO: decide how to handle ipv6 extensions.
    // The reationale is that if EHs arrived until here,
    // it's certainly an information we want to know.
    // Also, a fragmented TCP SYN could bypass this code.
    // https://labs.apnic.net/index.php/2023/06/22/a-further-update-on-ipv6-extension-headers/
    if (ip6->nexthdr != IPPROTO_TCP)
      return XDP_PASS;

  } else {
    return XDP_PASS;
  }

  // ++++++++++
  // TCP layer
  // ++++++++++

  struct tcphdr *tcp = head;
  head += sizeof(*tcp);

  if (head > data_end) {
    return XDP_PASS;
  }

  // TODO(al): add IPV6
  if (tcp->dest != dst_port)
    return XDP_PASS;

  // not a TCP SYN packet
  if (!tcp->syn || tcp->ack) {
    return XDP_PASS;
  }

  parse_tcp_syn(ip, tcp, data_end);

  return XDP_PASS;
}

void parse_tcp_syn(struct iphdr *ip, struct tcphdr *tcp, void *data_end) {

  __u16 tcp_hdr_len = tcp->doff * 4;
  /* Sanity check that the packet field is valid */
  if (tcp_hdr_len < sizeof(*tcp)) {
    return;
  }

  struct tcp_handshake_val val = {
      .tick = 0,
      .seq = tcp->seq,
      .src_addr = ip->saddr,
      .src_port = tcp->source,
      .window = tcp->window,
      .optlen = tcp_hdr_len - sizeof(*tcp),
      .ip_ttl = ip->ttl,
  };
  __u64 key = make_key(ip->saddr, tcp->source);

#ifdef DEBUG
  // debug destination filtering
  bpf_printk("TCP destination IP: %d - %d", ip->daddr, dst_ip);
  bpf_printk("TCP destination PORT: %d - %d", tcp->dest, dst_port);
  // debug source filtering
  bpf_printk("TCP source IP: %08x", ip->saddr);
  bpf_printk("TCP source PORT: %04x", tcp->source);
  bpf_printk("TCP hashmap KEY: %016llx", key);
#endif

  // increment the SYN counter
  __u32 counterkey = 0;
  __u64 *count = bpf_map_lookup_elem(&pkt_count, &counterkey);
  if (count) {
    val.tick = *count;
    bpf_printk("TCP SYN saved at tick: %d, tcp.seq: %u", *count,
               __bpf_ntohl(tcp->seq));
    __sync_fetch_and_add(count, 1);
  }

  /* Pointer to the start of the tcp options */
  __u8 *options = (__u8 *)(tcp + 1);

  /* Copy the TCP options from the packet into our struct. */
  for (__u32 i = 0;
       i <= TCPOPT_MAXLEN && i < val.optlen && (void *)options + i < data_end;
       ++i) {
    val.options[i] = options[i];
  }

  bpf_map_update_elem(&tcp_handshakes, &key, &val, BPF_ANY);
}
