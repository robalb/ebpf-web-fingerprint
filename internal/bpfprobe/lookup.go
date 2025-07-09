package bpfprobe

import (
	"crypto/tls"
	"fmt"
)

type Handshake struct {
	tick_now uint64
	IP       HandshakeIP
	TCP      HandshakeTCP
	TLS      HandshakeTLS
}

type HandshakeIP struct {
	SourceAddr uint32
	TTL        uint8
}

type HandshakeTCP struct {
	tick         uint64
	SourcePort   uint16
	Window       uint16
	Option_MSS   uint16
	Option_scale uint8
	OptionList   []uint16
}

type HandshakeTLS struct {
	CipherSuites      []uint16
	ServerName        string
	SupportedCurves   []tls.CurveID
	SupportedPoints   []uint8
	SignatureSchemes  []tls.SignatureScheme
	SupportedProtos   []string
	SupportedVersions []uint16
}

func (h *Handshake) GetPacketBacklog() (delta uint64) {
	return h.tick_now - h.TCP.tick
}

func (p *Probe) Lookup(remoteAddr string) (ret Handshake, err error) {
	// Read the counter metrics
	var count uint64
	err = p.objs.PktCount.Lookup(uint32(0), &count)
	if err != nil {
		err = fmt.Errorf("counter map lookup error: %v", err)
		return
	}
	ret.tick_now = count

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

	ret.IP, ret.TCP = parseTCP(tcphVal)

	// Read the TLS data
	tlsVal, ok := p.LookupTLSHello(remoteAddr)
	if !ok {
		err = fmt.Errorf("TLS hello lookup failed: %v", tlsVal)
		return
	}
	ret.TLS = tlsVal

	return
}
