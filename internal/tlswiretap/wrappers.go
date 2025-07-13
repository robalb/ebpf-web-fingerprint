package tlswiretap

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"github.com/robalb/deviceid/pkg/handshake"
)

func ListenAndServeTLS(srv *http.Server, certFile, keyFile string) error {
	addr := srv.Addr
	if addr == "" {
		addr = ":https"
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	defer ln.Close()

	wrappedLn := &WiredListener{
		inner: ln,
	}

	return srv.ServeTLS(wrappedLn, certFile, keyFile)
}

func PushTLSHello(h *tls.ClientHelloInfo) {
	hshake := &handshake.HandshakeTLS{
		CipherSuites:      h.CipherSuites,
		ServerName:        h.ServerName,
		SupportedCurves:   h.SupportedCurves,
		SupportedPoints:   h.SupportedPoints,
		SignatureSchemes:  h.SignatureSchemes,
		SupportedProtos:   h.SupportedProtos,
		SupportedVersions: h.SupportedVersions,
	}
	conn := h.Conn.(*WiredConn)
	conn.fingerprint.Load().hex.Store(hshake)
}

func ConnContext(ctx context.Context, c net.Conn) context.Context {
	switch c := c.(type) {
	case *tls.Conn:
		conn := c.NetConn().(*WiredConn)
		if conn.fingerprint.Load() == nil {
			conn.fingerprint.CompareAndSwap(nil, &fingerprint{})
		}
		ctx = context.WithValue(ctx, fingerprintKey, conn.fingerprint.Load())
		// ctx = context.WithValue(ctx, connKey, conn.Conn)
	case *net.TCPConn:
		// ctx = context.WithValue(ctx, connKey, c)
	}

	return ctx

}
