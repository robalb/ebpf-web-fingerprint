// go:build ignore
// +build ignore

// clang-format off
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

// tcp destination port, in big endian net format.
__be16 dst_port = 0xbb01;
// destination ipv4 addr, in big endian net format.
__u32 dst_ip = 16777343;

char __license[] SEC("license") = "Dual MIT/GPL";

struct tcp_handshake_val {
  // debug data
  __be32 src_addr;
  __be16 src_port;

  // tcp data
  __be16 window;
  __be16 optlen;
  __u8 options[TCPOPT_MAXLEN];
};

inline __u64 tcp_handshake_make_key(__u32 ip, __u16 port) {
  return ((__u64)ip << 16) | port;
}

static void __always_inline parse_tcp_syn(struct iphdr *ip, struct tcphdr *tcp,
                                          void *data_end);

static void __always_inline parse_tls_hello(struct iphdr *ip,
                                            struct tcphdr *tcp, void *data_end);

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 1);
} pkt_count SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 8192);
  __type(key, __u64);
  __type(value, struct tcp_handshake_val);
} tcp_handshakes SEC(".maps");

SEC("xdp")
int count_packets(struct xdp_md *ctx) {

  // Pointers to packet data
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  // --- ETH layer

  struct ethhdr *eth = data;

  if ((void *)(eth + 1) > data_end)
    return XDP_PASS;

  if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
    return XDP_PASS;

  // --- IP layer

  struct iphdr *ip = (struct iphdr *)(eth + 1);

  if ((void *)(ip + 1) > data_end)
    return XDP_PASS;

  char is_fragment = __bpf_ntohs(ip->frag_off) & (IP_MF | IP_OFFSET);
  if (is_fragment)
    return XDP_PASS;

  if (ip->protocol != IPPROTO_TCP)
    return XDP_PASS;

  int ip_hdr_len = ip->ihl * 4;
  if (ip_hdr_len < sizeof(struct iphdr)) {
    return XDP_PASS;
  }

  if ((void *)ip + ip_hdr_len > data_end) {
    return XDP_PASS;
  }

  if (ip->daddr != dst_ip)
    return 0;

  // --- TCP layer

  struct tcphdr *tcp = (struct tcphdr *)((unsigned char *)ip + ip_hdr_len);

  if ((void *)(tcp + 1) > data_end) {
    return XDP_PASS;
  }

  if (tcp->syn && !tcp->ack) {
    parse_tcp_syn(ip, tcp, data_end);
  } else if (!tcp->syn && tcp->ack) {
    // parse_tls_hello(ip, tcp, data_end);
  }

  return XDP_PASS;
}

void parse_tcp_syn(struct iphdr *ip, struct tcphdr *tcp, void *data_end) {
  if (tcp->dest != dst_port)
    return;

  // increment the SYN counter
  __u32 counterkey = 0;
  __u64 *count = bpf_map_lookup_elem(&pkt_count, &counterkey);
  if (count) {
    __sync_fetch_and_add(count, 1);
  }

  struct tcp_handshake_val val = {
      .src_addr = ip->saddr,
      .src_port = tcp->source,
      .optlen = tcp->doff * 4 - TCPH_MINLEN,
      .window = tcp->window,
  };
  __u64 key = tcp_handshake_make_key(ip->saddr, tcp->source);

#ifdef DEBUG
  // debug destination filtering
  bpf_printk("xdp destination IP: %d - %d", ip->daddr, dst_ip);
  bpf_printk("xdp destination PORT: %d - %d", tcp->dest, dst_port);
  // debug source filtering
  bpf_printk("xdp source IP: %08x", ip->saddr);
  bpf_printk("xdp source PORT: %04x", tcp->source);
  bpf_printk("xdp hashmap KEY: %016llx", key);
#endif

  // Pointer to the start of the tcp options
  __u8 *options = (unsigned char *)tcp + TCPH_MINLEN;

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
