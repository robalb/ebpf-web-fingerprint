package tlswiretap

import (
	"net"
	"sync/atomic"

	"github.com/robalb/ebpf-web-fingerprint/pkg/handshake"
)

type connKeyType struct{}

var connKey = connKeyType{}

type fingerprintKeyType struct{}

var fingerprintKey = fingerprintKeyType{}

type fingerprint struct {
	hex atomic.Pointer[handshake.HandshakeTLS]
}

// A "wiretapped" implementation of net.Conn that includes
// an additional pointer to the client fingerprint.
type WiredConn struct {
	net.Conn
	fingerprint atomic.Pointer[fingerprint]
}

var _ net.Conn = &WiredConn{}

// A "wiretapped" implementation of net.Listener
type WiredListener struct {
	inner net.Listener
}

func (l *WiredListener) Accept() (net.Conn, error) {
	c, err := l.inner.Accept()
	if err != nil {
		return nil, err
	}
	return &WiredConn{Conn: c}, nil
}

func (l *WiredListener) Close() error {
	return l.inner.Close()
}

func (l *WiredListener) Addr() net.Addr {
	return l.inner.Addr()
}

var _ net.Listener = &WiredListener{}
