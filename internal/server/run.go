package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"time"

	"github.com/robalb/deviceid/internal/bpfprobe"
)

const (
	config_iface    = "veth-ns"
	config_dst_ip   = "10.200.1.2"
	config_dst_port = 443
	config_tls      = true
	config_tls_cert = "cert.pem"
	config_tls_key  = "key.pem"
)

type connKeyType struct{}

var connKey = connKeyType{}

type fingerprintKeyType struct{}

var fingerprintKey = fingerprintKeyType{}

type fingerprint struct {
	hex atomic.Pointer[string]
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

func WiretappedListenAndServeTLS(srv *http.Server, certFile, keyFile string) error {
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

func Run(
	ctx context.Context,
	stdout io.Writer,
	stderr io.Writer,
	args []string,
	getenv func(string) string,
) error {
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)
	defer cancel()

	//+++++++++++++++++++++++
	// Initialize all modules
	//+++++++++++++++++++++++

	// Init logging
	logger := log.New(stdout, "", log.Flags())
	logger.Println("starting... ")

	//init ebpf probe
	probe, err := bpfprobe.New(logger, config_iface, config_dst_ip, config_dst_port)
	if err != nil {
		return fmt.Errorf("ebpf probe failed to start: %v", err)
	}
	defer probe.Close()

	// Init the server handlers
	srv := NewServer(
		logger,
		probe,
	)

	tlsConfig := &tls.Config{
		// Pin the TLS version
		// this is just for experimenting different protocols
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			// Tap into the clientHello handler, and add it to
			// the wiretapped net.Conn this server is based on
			// https://github.com/bpowers/go-fingerprint-example/
			fake := "fake fingerprint " + h.Conn.RemoteAddr().String()
			conn := h.Conn.(*WiredConn)
			conn.fingerprint.Load().hex.Store(&fake)
			return nil, nil
		},
	}

	httpServer := &http.Server{
		Addr:      net.JoinHostPort("", fmt.Sprintf("%d", config_dst_port)),
		Handler:   srv,
		TLSConfig: tlsConfig,
		// Disable HTTP/2
		// see: https://go.googlesource.com/go/+/master/src/net/http/doc.go?autodive=0%2F%2F#81
		// This is just for experimenting protocols
		// TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			var conn *WiredConn
			switch c := c.(type) {
			case *tls.Conn:
				conn = c.NetConn().(*WiredConn)
				if conn.fingerprint.Load() == nil {
					logger.Printf("swapping")
					conn.fingerprint.CompareAndSwap(nil, &fingerprint{})
				}
				ctx = context.WithValue(ctx, fingerprintKey, conn.fingerprint.Load())
				ctx = context.WithValue(ctx, connKey, conn.Conn)
			case *net.TCPConn:
				ctx = context.WithValue(ctx, connKey, c)
			}

			return ctx
		},
	}

	// With keep alive active we run the risk of receiving
	// requests for an IP+PORT tuple that got removed from
	// the eBFP LRU map in the past
	httpServer.SetKeepAlivesEnabled(false)

	//++++++++++++++++++++
	// Start the webserver
	//++++++++++++++++++++
	go func() {
		logger.Printf("listening on %s, TLS enabled: %v\n", httpServer.Addr, config_tls)
		var err error
		if config_tls {
			// err = httpServer.ListenAndServeTLS(config_tls_cert, config_tls_key)
			err = WiretappedListenAndServeTLS(httpServer, config_tls_cert, config_tls_key)
		} else {
			err = httpServer.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(stderr, "error listening and serving: %s\n", err)
		}
	}()

	//++++++++++++++++++
	// Graceful shutdown
	//++++++++++++++++++
	var wg sync.WaitGroup
	// Webserver graceful shutdown
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		logger.Println("Gracefully shutting down webserver...")
		shutdownCtx := context.Background()
		shutdownCtx, cancel := context.WithTimeout(shutdownCtx, 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(stderr, "error shutting down http server: %s\n", err)
		}
	}()

	wg.Wait()
	return nil
}
