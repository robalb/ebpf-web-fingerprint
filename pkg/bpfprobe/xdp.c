// go:build ignore
// +build ignore

// clang-format off
#include "../../headers/net_headers.h"
#include "../../headers/bpf_helpers.h"
#include "../../headers/bpf_endian.h"
// clang-format on

// Set to 1 to enable tracing logs. To read them:
// sudo cat /sys/kernel/debug/tracing/trace_pipe
#define DEBUG 1

// When set to 1, the program will capture all TCP SYNs
// to our destination port, regardless of destination ip.
#define IGNORE_DST_IP 1

// The max bytes of TCP options we are willing to copy
#define TCPOPT_MAXLEN 40

char __license[] SEC("license") = "Dual MIT/GPL";

/*
 * TCP destination port, injected at program load.
 * Defaults to 443 when not set.
 */
__be16 dst_port = __constant_htons(443);

/*
 * Destination IP, injected at program load.
 * Defaults to 127.0.0.1 when not set.
 * Will be ignored if IGNORE_DST_IP is set.
 */
__be32 dst_ip = 16777343;

/*
 * Destination IPv6, injected at program load.
 * Will be ignored if IGNORE_DST_IP is set.
 */
__be32 dst_ipv6[4] = {};

/*
 * This eBPF map holds a single counter value that is
 * incremented on every TCP SYN received.
 * It's used to keep track of the backlog of TCP SYN 
 * packets being tracked, exposing this to userspace.
 */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 1);
} pkt_count SEC(".maps");

/*
 * This eBPF map holds the packed data extracted from
 * all TCP SYN packets directed to the target server.
 */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 8192);
  __type(key, struct tcp_handshake_key);
  __type(value, struct tcp_handshake_val);
} tcp_handshakes SEC(".maps");

struct tcp_handshake_key {
  __be32 addr[4];
  __be16 port;
  __u8 _pad[2];
};

struct tcp_handshake_val {
  __u64 tick;
  __be32 seq;      /* TCP seq during the TCP SYN - used for correlation */
  __be16 window;   /* TCP window */
  __u16 optlen;    /* length of the TCP options. */
  __u8 ip_ttl;     /* IPv4 TTL or IPv6 hop_limit */
  __u8 options[TCPOPT_MAXLEN];
};

/*
 * Mirror of the vlan_hdr struct defined in linux/if_vlan.h,
 * which is normally not exposed as part of the linux UAPI.
 */
struct _vlan_hdr {
  __be16 h_vlan_TCI;
  __be16 h_vlan_encapsulated_proto;
};

/**
 * Compare two ipv6 addresses.
 * We compare section by section simply because __builtin_memcmp
 * in ebpf doesn't work properly in the current clang version.
 */
static __u8 __always_inline ipv6_addr_equal(const struct in6_addr *a,
                                            const struct in6_addr *b) {
  __u32 diff = 0;
  diff |= a->s6_addr32[0] ^ b->s6_addr32[0];
  diff |= a->s6_addr32[1] ^ b->s6_addr32[1];
  diff |= a->s6_addr32[2] ^ b->s6_addr32[2];
  diff |= a->s6_addr32[3] ^ b->s6_addr32[3];
  return diff == 0;
}

static __always_inline int proto_is_vlan(__u16 h_proto) {
  return !!(h_proto == __constant_htons(ETH_P_8021Q) ||
            h_proto == __constant_htons(ETH_P_8021AD));
}

/**
 * Copy TCP options from the packet into the handshake value struct.
 */
static void __always_inline copy_tcp_options(struct tcp_handshake_val *val,
                                             struct tcphdr *tcp,
                                             void *data_end);

#ifdef DEBUG
static void __always_inline debug_ip4(struct iphdr *ip, struct tcphdr *tcp) {
  bpf_printk("TCP source IP4: %08x", ip->saddr);
  bpf_printk("TCP source PORT: %04x", tcp->source);
}

static void __always_inline debug_ip6(struct ipv6hdr *ip6, struct tcphdr *tcp) {
  bpf_printk("TCP source IP6 [0:63]:   %08x:%08x", ip6->saddr.s6_addr32[0], ip6->saddr.s6_addr32[1]);
  bpf_printk("TCP source IP6 [64:127]: %08x:%08x", ip6->saddr.s6_addr32[2], ip6->saddr.s6_addr32[3]);
  bpf_printk("TCP source PORT: %04x", tcp->source);
}
#endif


SEC("xdp")
int count_packets(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  void *head = data;

  // +-------------------+
  //      ETH layer
  // +-------------------+

  struct ethhdr *eth = head;
  head += sizeof(*eth);

  // Make sure the packet is large enough for ETH + 2 VLAN headers
  if (head + (2 * sizeof(struct _vlan_hdr)) > data_end)
    return XDP_PASS;

  __u16 eth_type = eth->h_proto;

  // handle vlan tagged packets.
  if (proto_is_vlan(eth_type)) {
    struct _vlan_hdr *vlan = head;
    head += sizeof(*vlan);
    eth_type = vlan->h_vlan_encapsulated_proto;
  }

  // Handle inner (double) VLAN tag
  if (proto_is_vlan(eth_type)) {
    struct _vlan_hdr *vlan = head;
    head += sizeof(*vlan);
    eth_type = vlan->h_vlan_encapsulated_proto;
  }

  // +-------------------+
  //       IP layer
  // +-------------------+

  struct iphdr *ip;
  struct ipv6hdr *ip6;
  __u8 is_6 = 1;

  if (eth_type == __constant_htons(ETH_P_IP)) {
    is_6 = 0;

    ip = head;
    head += sizeof(*ip);

    if (head > data_end)
      return XDP_PASS;

    char is_fragment = ip->frag_off & __constant_htons(IP_MF | IP_OFFSET);
    if (is_fragment)
      return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
      return XDP_PASS;

    #ifndef IGNORE_DST_IP
        if (ip->daddr != dst_ip)
          return XDP_PASS;
    #endif

    __u32 ip_hdr_len = ip->ihl * 4;
    // sanity check that the packet field is valid
    if (ip_hdr_len < sizeof(*ip)) {
      return XDP_PASS;
    }
    // Adjust the head to follow the dynamic length
    // declared in the packet instead of the struct len
    head += ip_hdr_len - sizeof(*ip);

  } else if (eth_type == __constant_htons(ETH_P_IPV6)) {
    is_6 = 1;

    ip6 = head;
    head += sizeof(*ip6);

    if (head > data_end) {
      return XDP_PASS;
    }

    #ifndef IGNORE_DST_IP
        if (ipv6_addr_equal(&ip6->daddr, (struct in6_addr *)dst_ipv6) != 1) {
          return XDP_PASS;
        }
    #endif

    // TODO: decide how to handle ipv6 extensions.
    // The rationale is that if EHs arrived until here,
    // it's certainly an information we want to know.
    // Also, a fragmented TCP SYN could bypass this code.
    // https://labs.apnic.net/index.php/2023/06/22/a-further-update-on-ipv6-extension-headers/
    if (ip6->nexthdr != IPPROTO_TCP)
      return XDP_PASS;

  } else {
    return XDP_PASS;
  }

  // +-------------------+
  //     TCP layer
  // +-------------------+

  struct tcphdr *tcp = head;
  head += sizeof(*tcp);

  if (head > data_end) {
    return XDP_PASS;
  }

  if (tcp->dest != dst_port)
    return XDP_PASS;

  // not a TCP SYN packet
  if (!tcp->syn || tcp->ack) {
    return XDP_PASS;
  }
        
  __u16 tcp_hdr_len = tcp->doff * 4;
  /* Sanity check that the packet field is valid */
  if (tcp_hdr_len < sizeof(*tcp)) {
    return XDP_PASS;
  }


  // +-------------------+
  // Push to ebpf hashmap
  // +-------------------+

  // increment the SYN counter
  // TODO: replace with BPF_MAP_TYPE_PERCPU_ARRAY
  __u32 counterkey = 0;
  __u64 *count = bpf_map_lookup_elem(&pkt_count, &counterkey);
  if (count) {
    __sync_fetch_and_add(count, 1);
  }

  struct tcp_handshake_val val = {
      .tick = count ? *count : 0,
      .seq = tcp->seq,
      .window = tcp->window,
      .optlen = tcp_hdr_len - sizeof(*tcp),
  };

  struct tcp_handshake_key key = {
      .port = tcp->source,
  };

  if (is_6) {
      #ifdef DEBUG
      debug_ip6(ip6, tcp);
      #endif
      val.ip_ttl = ip6->hop_limit;
      key.addr[0] = ip6->saddr.s6_addr32[0];
      key.addr[1] = ip6->saddr.s6_addr32[1];
      key.addr[2] = ip6->saddr.s6_addr32[2];
      key.addr[3] = ip6->saddr.s6_addr32[3];
  } else {
      #ifdef DEBUG
      debug_ip4(ip, tcp);
      #endif
      val.ip_ttl = ip->ttl;
      key.addr[0] = ip->saddr;
  }

  copy_tcp_options(&val, tcp, data_end);
  bpf_map_update_elem(&tcp_handshakes, &key, &val, BPF_ANY);

  return XDP_PASS;
}

static void __always_inline copy_tcp_options(struct tcp_handshake_val *val,
                                             struct tcphdr *tcp,
                                             void *data_end) {
  __u8 *options = (__u8 *)(tcp + 1);
  for (__u32 i = 0;
       i <= TCPOPT_MAXLEN && i < val->optlen &&
       (void *)options + i < data_end;
       ++i) {
    val->options[i] = options[i];
  }
}
