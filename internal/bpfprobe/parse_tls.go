package bpfprobe

import (
	"crypto/tls"
)

func parseTLS(h tls.ClientHelloInfo) HandshakeTLS {
	return HandshakeTLS{
		CipherSuites:      h.CipherSuites,
		ServerName:        h.ServerName,
		SupportedCurves:   h.SupportedCurves,
		SupportedPoints:   h.SupportedPoints,
		SignatureSchemes:  h.SignatureSchemes,
		SupportedProtos:   h.SupportedProtos,
		SupportedVersions: h.SupportedVersions,
	}
}
