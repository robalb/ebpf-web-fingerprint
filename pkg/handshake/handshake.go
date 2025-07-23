package handshake

import (
	"crypto/tls"
)

type Handshake struct {
	tick_now    uint64
	tick_packet uint64
	IP          HandshakeIP
	TCP         HandshakeTCP
	TLS         HandshakeTLS
}

type HandshakeIP struct {
	SourceAddr uint32
	TTL        uint8
}

type HandshakeTCP struct {
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
	Extensions        []uint16
}

func (h *Handshake) GetPacketBacklog() (delta uint64) {
	return h.tick_now - h.tick_packet
}

func (h *Handshake) SetTickNow(tick uint64) {
	h.tick_now = tick
}

func (h *Handshake) SetTickPacket(tick uint64) {
	h.tick_packet = tick
}
