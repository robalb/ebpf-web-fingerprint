package bpfprobe

import "fmt"

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
	// many TLS libraries support the option of setting a max fragment size.
	// Setting a low value can result in fragmentation of the TLS hello, a
	// technique used to circumvent Deep Packet Inspection systems.
	// for example, see: https://github.com/rustls/rustls/issues/2292
	// This paramenter can be used as an additional fingerprinting feature
	FragmentSize uint16
	// A value of zero indicates that the TLS hello was not fragmented.
	// A value above one indicates a non-standard client behaviour,
	// which can be used as a fingerprinting feature.
	FragmentCount uint16
}

func (p *Probe) Lookup(host string, port string) (ret Handshake, err error) {
	// read the counter metrics
	var count uint64
	err = p.objs.PktCount.Lookup(uint32(0), &count)
	if err != nil {
		err = fmt.Errorf("counter map lookup error")
		return
	}
	ret.tick_now = count

	//prepare the key to read from the eBPF maps
	tcphKey, keyAddr, keyPort, err := makeKey(host, port)
	if err != nil {
		err = fmt.Errorf("TCP syn: KEY_ERROR")
		return
	}

	//read the tcp syn data
	var tcphVal xdpTcpHandshakeVal
	err = p.objs.TcpHandshakes.LookupAndDelete(tcphKey, &tcphVal)
	if err != nil {
		err = fmt.Errorf("TCP syn: LOOKUP_ERROR")
		return
	}

	//sanity check, to avoid hash collision reads
	if tcphVal.SrcPort != keyPort {
		err = fmt.Errorf("TCP syn: KEY_PORT_MISMATCH")
		return
	}
	if tcphVal.SrcAddr != keyAddr {
		err = fmt.Errorf("TCP syn: KEY_ADDR_MISMATCH")
		return
	}

	ret.IP, ret.TCP = parseTCP(tcphVal)

	//read the TLS hello data
	var tlshVal xdpTlsHandshakeVal
	err = p.objs.TlsHandshakes.LookupAndDelete(tcphKey, &tlshVal)
	if err != nil {
		err = fmt.Errorf("TLS hello: LOOKUP_ERROR")
		return
	}

	ret.TLS = parseTLS(tlshVal)

	return
}
