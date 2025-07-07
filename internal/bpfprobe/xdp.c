// go:build ignore
// +build ignore

// clang-format off
#include <linux/byteorder/little_endian.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include "../../headers/bpf_helpers.h"
#include "../../headers/bpf_endian.h"
// clang-format on

#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF
#define TCPH_MINLEN 20
#define TCPH_MAXLEN 60
#define TCPOPT_MAXLEN 40

char __license[] SEC("license") = "Dual MIT/GPL";

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

/*
 * This eBPF map holds a single counter value that is
 * incremented on every TCP SYN or TLS hello received.
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
 * both TCP SYN and TLS hello packets directed to our
 * webserver.
 */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 8192);
  __type(key, __u64);
  __type(value, struct tcp_handshake_val);
} tcp_handshakes SEC(".maps");

/*
 * signature of a generic TLS hello,
 * supporting both TLS 1.1, 1.2, 1.3
 */
struct __attribute__((packed)) tlshello {
  __u8 recordh_type;
  __u8 recordh_version[2];
  __u8 recordh_len[2];
  __u8 hproto_type;
  __u8 hproto_len[3];
  __u8 hproto_version[2];
};

/*
 * Mirror of the vlan_hdr struct defined in linux/if_vlan.h,
 * which is normally not exposed as part of the linux UAPI.
 */
struct _vlan_hdr {
  __be16 h_vlan_TCI;
  __be16 h_vlan_encapsulated_proto;
};

struct tcp_handshake_val {
  __u64 counter_tick;
  __be32 seq;      /* TCP seq - used for correlation */
  __be32 src_addr; /* IP source - used for correlation */
  __be16 src_port; /* TCP source - used for correlation */
  __be16 window;   /* TCP window */
  __u16 optlen;    /* length of the TCP options. In host endianness */
  __u8 ip_ttl;     /* IP TTL */
  __u8 options[TCPOPT_MAXLEN];
};

static __u64 __always_inline tcp_handshake_make_key(__u32 ip, __u16 port) {
  return ((__u64)ip << 16) | port;
}

static void __always_inline parse_tcp_syn(struct iphdr *ip, struct tcphdr *tcp,
                                          void *data_end);

static void __always_inline parse_tls_hello(struct iphdr *ip,
                                            struct tcphdr *tcp, void *data_end);

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

  if (eth_type != __constant_htons(ETH_P_IP))
    return XDP_PASS;

  // ++++++++++
  // IP layer
  // ++++++++++

  struct iphdr *ip = head;
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

  // ++++++++++
  // TCP layer
  // ++++++++++

  struct tcphdr *tcp = head;
  head += sizeof(*tcp);

  if (head > data_end) {
    return XDP_PASS;
  }

  if (tcp->dest != dst_port)
    return XDP_PASS;

  if (tcp->syn && !tcp->ack) {
    parse_tcp_syn(ip, tcp, data_end);
  } else if (!tcp->syn && tcp->ack) {
    parse_tls_hello(ip, tcp, data_end);
  }

  return XDP_PASS;
}

void parse_tls_hello(struct iphdr *ip, struct tcphdr *tcp, void *data_end) {
  __u32 tcp_hdr_len = tcp->doff * 4;
  /* Sanity check that the packet field is valid */
  if (tcp_hdr_len < sizeof(*tcp)) {
    return;
  }

  struct tlshello *tls = (void *)tcp + tcp_hdr_len;
  if ((void *)(tls + 1) > data_end) {
    return;
  }

  int valid_signature =
      (tls->recordh_type == 0x16 &&      /* TLS content type: handshake */
       tls->recordh_version[0] == 0x3 && /* TLS 1.0 (3.1) - fossilized value */
       tls->recordh_version[1] == 0x1 && /* TLS 1.0 (3.1) */
       tls->hproto_type == 0x1 &&        /* handshake type: client hello */
       tls->hproto_version[0] == 0x3 &&  /* TLS 1.2 (3.3) - fossilized value */
       tls->hproto_version[1] == 0x3     /* TLS 1.2 (3.3) */
      );
  if (!valid_signature) {
    return;
  }

  // increment the SYN counter
  __u32 counterkey = 0;
  __u64 *count = bpf_map_lookup_elem(&pkt_count, &counterkey);
  if (count) {
    bpf_printk("TLS HELLO saved at tick: %d, tcp.seq: %u", *count,
               __bpf_ntohl(tcp->seq));
    __sync_fetch_and_add(count, 1);
  }

  // TODO(al): how do we read the full packet? where do we store it?
  // where do we parse it?

  __u64 key = tcp_handshake_make_key(ip->saddr, tcp->source);
  struct tcp_handshake_val *tcp_syn =
      bpf_map_lookup_elem(&tcp_handshakes, &key);
  if (tcp_syn) {
    bpf_printk("SYN at: %u HELLO at: %u", __bpf_ntohl(tcp_syn->seq),
               __bpf_ntohl(tcp->seq));
  }
}

void parse_tcp_syn(struct iphdr *ip, struct tcphdr *tcp, void *data_end) {
  __u16 tcp_hdr_len = tcp->doff * 4;
  /* Sanity check that the packet field is valid */
  if (tcp_hdr_len < sizeof(*tcp)) {
    return;
  }

  struct tcp_handshake_val val = {
      .counter_tick = 0,
      .seq = tcp->seq,
      .src_addr = ip->saddr,
      .src_port = tcp->source,
      .window = tcp->window,
      .optlen = tcp_hdr_len - sizeof(*tcp),
      .ip_ttl = ip->ttl,
  };
  __u64 key = tcp_handshake_make_key(ip->saddr, tcp->source);

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
    val.counter_tick = *count;
    bpf_printk("TCP SYN saved at tick: %d, tcp.seq: %u", *count,
               __bpf_ntohl(tcp->seq));
    __sync_fetch_and_add(count, 1);
  }

  // Pointer to the start of the tcp options
  __u8 *options = (__u8 *)(tcp + 1);

  // This loop is the homemade equivalent of:
  // __builtin_memcpy(val.options, options, val.optlen);
#pragma clang loop unroll(full)
  for (int i = 0; i < TCPOPT_MAXLEN; i++) {
    if (i < val.optlen && (void *)options + i < data_end) {
      val.options[i] = options[i];
    }
  }

  bpf_map_update_elem(&tcp_handshakes, &key, &val, BPF_ANY);
}
