package bpfprobe

import (
	"fmt"
	"github.com/robalb/deviceid/pkg/handshake"
)

func (p *Probe) Lookup(remoteAddr string, h *handshake.Handshake) (err error) {
	// Read the counter metrics
	var count uint64
	err = p.objs.PktCount.Lookup(uint32(0), &count)
	if err != nil {
		err = fmt.Errorf("counter map lookup error: %v", err)
		return
	}
	h.SetTickNow(count)

	// Prepare the key to read from the eBPF maps
	tcphKey, keyAddr, keyPort, err := makeKey(remoteAddr)
	if err != nil {
		err = fmt.Errorf("TCP syn: KEY_ERROR: %v", err)
		return
	}

	// Read the tcp syn data
	var tcphVal xdpTcpHandshakeVal
	err = p.objs.TcpHandshakes.Lookup(tcphKey, &tcphVal)
	if err != nil {
		err = fmt.Errorf("TCP syn: LOOKUP_ERROR: %v", err)
		return
	}

	// Sanity check, to avoid hash collision reads
	if tcphVal.SrcPort != keyPort {
		err = fmt.Errorf("TCP syn: KEY_PORT_MISMATCH: %v", err)
		return
	}
	if tcphVal.SrcAddr != keyAddr {
		err = fmt.Errorf("TCP syn: KEY_ADDR_MISMATCH: %v", err)
		return
	}

	h.IP = handshake.HandshakeIP{
		SourceAddr: tcphVal.SrcAddr,
		TTL:        tcphVal.IpTtl,
	}
	h.TCP = parseTCP(tcphVal)

	return
}
