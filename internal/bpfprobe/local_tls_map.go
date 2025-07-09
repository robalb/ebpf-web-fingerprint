package bpfprobe

import (
	"crypto/tls"
)

func (p *Probe) PushTLSHello(h *tls.ClientHelloInfo) error {
	parsedHello := HandshakeTLS{
		CipherSuites:      h.CipherSuites,
		ServerName:        h.ServerName,
		SupportedCurves:   h.SupportedCurves,
		SupportedPoints:   h.SupportedPoints,
		SignatureSchemes:  h.SignatureSchemes,
		SupportedProtos:   h.SupportedProtos,
		SupportedVersions: h.SupportedVersions,
	}
	p.HelloStore.Store(h.Conn.RemoteAddr().String(), parsedHello)
	return nil
}

func (p *Probe) LookupTLSHello(key string) (hello HandshakeTLS, ok bool) {
	ret, ok := p.HelloStore.Load(key)
	hello, _ = ret.(HandshakeTLS)
	return hello, ok
}
