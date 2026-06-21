package bpfprobe

import (
	"fmt"
	"github.com/robalb/ebpf-web-fingerprint/pkg/handshake"
)

func (p *Probe) Lookup(h *handshake.Handshake, remoteAddr string) (err error) {
	// Read the counter metrics
	var count uint64
	err = p.objs.PktCount.Lookup(uint32(0), &count)
	if err != nil {
		err = fmt.Errorf("counter map lookup error: %v", err)
		return
	}
	h.SetTickNow(count)

	// Prepare the key to read from the eBPF maps
	tcphKey, keyIpStr, keyPort, err := makeKey(remoteAddr)
	if err != nil {
		err = fmt.Errorf("TCP syn: KEY_ERROR: %v", err)
		return
	}

	fmt.Printf("key: addr=%08x:%08x:%08x:%08x port=%04x\n",
	  tcphKey.Addr[0], tcphKey.Addr[1], tcphKey.Addr[2], tcphKey.Addr[3],
	  tcphKey.Port)

	// Read the tcp syn data
	var tcphVal xdpTcpHandshakeVal
	err = p.objs.TcpHandshakes.Lookup(tcphKey, &tcphVal)
	if err != nil {
		err = fmt.Errorf("TCP syn: LOOKUP_ERROR: %v", err)
		return
	}

	h.SetTickPacket(tcphVal.Tick)

	h.IP = handshake.HandshakeIP{
		SourceAddrStr: keyIpStr,
		TTL:        tcphVal.IpTtl,
	}
	h.TCP = parseTCP(tcphVal, uint16(keyPort))

	return
}
