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
			// the bpfprobe hashmaps
			probe.PushTLSHello(h)
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
			switch c := c.(type) {
			case *tls.Conn:
				ctx = context.WithValue(ctx, connKey, c.NetConn())
			case *net.TCPConn:
				ctx = context.WithValue(ctx, connKey, c)
			}
			return ctx
		},
	}

	// With keep alible active we run the risk of receiving
	// requests for an IP+PORT tuple that got garbage collected
	// in the past.
	httpServer.SetKeepAlivesEnabled(false)

	//++++++++++++++++++++
	// Start the webserver
	//++++++++++++++++++++
	go func() {
		logger.Printf("listening on %s, TLS enabled: %v\n", httpServer.Addr, config_tls)
		var err error
		if config_tls {
			err = httpServer.ListenAndServeTLS(config_tls_cert, config_tls_key)
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
