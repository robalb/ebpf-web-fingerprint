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
	config_dst_port = 8080
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

	//--------------------
	// Initialize all modules
	//--------------------

	// Init logging
	logger := log.New(stdout, "", log.Flags())
	logger.Println("starting... ")

	//init ebpf probe
	probe, err := bpfprobe.New(logger, config_iface, config_dst_ip, config_dst_port)
	if err != nil {
		return fmt.Errorf("ebpf probe failed to start: %v", err)
	}
	defer probe.Close()

	// Init Server
	srv := NewServer(
		logger,
		probe,
	)

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
	}

	httpServer := &http.Server{
		Addr:      net.JoinHostPort("", fmt.Sprintf("%d", config_dst_port)),
		Handler:   srv,
		TLSConfig: tlsConfig,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connKey, c)
		},
	}

	//--------------------
	// Start the webserver
	//--------------------
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

	//--------------------
	// Graceful shutdown
	//--------------------
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
