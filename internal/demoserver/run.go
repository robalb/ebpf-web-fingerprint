package demoserver

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
	"strconv"
	"syscall"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/robalb/deviceid/internal/bpfprobe"
	"github.com/robalb/deviceid/internal/tlswiretap"
	"golang.org/x/sync/errgroup"
)

func getenvStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
	}
	return def
}

func getenvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}

var (
	config_iface     = getenvStr("IFACE", "veth-ns")
	config_dst_ip    = getenvStr("DST_IP", "10.200.1.2")
	config_dst_port  = getenvInt("DST_PORT", 80)
	config_tls       = getenvBool("TLS", false)
	config_certmagic = getenvBool("CERTMAGIC", true)
	// Hardcoded tls keys. Will be used when certmagic = false
	config_tls_cert = getenvStr("TLS_CERT", "cert.pem")
	config_tls_key  = getenvStr("TLS_KEY", "key.pem")
)

// Run starts the demo fingerprint server.
// The behaviour of the demo server depends on the following env variables:
// IFACE     network interface the server will listen on
// DST_IP    ip on the net interface the server will listen on
// DST_PORT  port the server will listen on (when certmagic is disabled)
// TLS       wether the server should run in TLS mode, with TLS fingerprinting
// CERTMAGIC wether to enable automatic TLS certificate renewal, using certmagic
// TLS_CERT  path to the TLS cert file, used when certmagic=false
// TLS_KEY   path to the TLS key file, used when certmagic=false
func Run(
	ctx context.Context,
	stdout io.Writer,
	stderr io.Writer,
	args []string,
	getenv func(string) string,
) error {
	ctx, cancel := signal.NotifyContext(ctx,
		syscall.SIGINT,  // ctr-C from the terminal
		syscall.SIGTERM, // terminate signal from Docker / kubernetes
	)
	defer cancel()

	//+++++++++++++++++++++++
	// Initialize all modules
	//+++++++++++++++++++++++

	// Init logging
	logger := log.New(stdout, "", log.Flags())
	logger.Println("fingerprint demo server starting... ")

	//init ebpf probe
	probe, err := bpfprobe.New(logger, config_iface, config_dst_ip, config_dst_port)
	if err != nil {
		return fmt.Errorf("ebpf probe failed to start: %v", err)
	}
	defer probe.Close()

	// Init tls management, optional - not required for TLS or TCP fingerprinting
	var acmeServer *http.Server
	var magic *certmagic.Config
	if config_certmagic && config_tls {
		magic = certmagic.NewDefault()
		acme := certmagic.NewACMEIssuer(magic, certmagic.DefaultACME)
		// Define the acmechallenge http server and fallback behaviour
		acmeMux := http.NewServeMux()
		acmeMux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
			fmt.Fprintf(w, "Http endpoint. TODO: redirect to HTTPS")
			// Redirect to HTTPS all HTTP requests that are not acme challenges
			// target := "https://" + req.Host + req.URL.RequestURI()
			// http.Redirect(w, req, target, http.StatusMovedPermanently)
		})
		acmeServer = &http.Server{
			Addr:    ":80",
			Handler: acme.HTTPChallengeHandler(acmeMux),
		}
	}

	httpHandler := NewRouter(
		logger,
		probe,
	)

	tlsConfig := &tls.Config{
		// Pin the TLS version.
		// This is just for experimenting with different protocols,
		// it's not a required step for tls or tcp fingerprinting
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			tlswiretap.PushTLSHello(h)
			return nil, nil
		},
	}
	if magic != nil {
		// activate cermagic - optional, not required for TLS or TCP fingerprinting
		tlsConfig.GetCertificate = magic.GetCertificate
	}

	httpServer := &http.Server{
		Addr:    net.JoinHostPort("", fmt.Sprintf("%d", config_dst_port)),
		Handler: httpHandler,
		// Disable HTTP/2.
		// This is just for experimenting with protocols,
		// it's not required for tls or tcp fingerprinting
		// see: https://go.googlesource.com/go/+/master/src/net/http/doc.go?autodive=0%2F%2F#81
		// TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	if config_tls {
		httpServer.TLSConfig = tlsConfig
		httpServer.ConnContext = tlswiretap.ConnContext
	}

	// With keep alive active we run the risk of receiving
	// requests for an IP+PORT tuple that got removed from
	// the eBFP LRU map in the past
	httpServer.SetKeepAlivesEnabled(false)

	//++++++++++++++++++++
	// Start all modules
	//++++++++++++++++++++

	g, ctx := errgroup.WithContext(ctx)

	//start the main fingerprint server
	g.Go(func() error {
		logger.Printf("fingerprint http server: listening on %s, TLS enabled: %v\n", httpServer.Addr, config_tls)
		var err error
		if config_tls {
			err = tlswiretap.ListenAndServeTLS(httpServer, config_tls_cert, config_tls_key)
		} else {
			err = httpServer.ListenAndServe()
		}

		if err == http.ErrServerClosed {
			return nil
		}
		return err
	})

	// start the HTTP handler that takes care of HTTP acme challenges and HTTPS redirection
	if acmeServer != nil {
		g.Go(func() error {
			logger.Printf("acme http server: listening on :80\n")
			err := acmeServer.ListenAndServe()
			if err == http.ErrServerClosed {
				return nil
			}
			return err
		})
	}

	//++++++++++++++++++++++++++++++++++
	// Graceful Shutdown for all modules
	//++++++++++++++++++++++++++++++++++

	go func() {
		// Block until one of the modules in the error group throws an error,
		// or the parent context is cancelled (ctrl+c | SIGTERM)
		<-ctx.Done()
		logger.Printf("Shutting down. This was caused by either an error in one of the running webserver modules, or by a shutdown request: ctrl+c or SIGTERM")

		// Shutdown the acme webserver if it exists
		if acmeServer != nil {
			logger.Printf("acme server: terminating...")
			shutdownCtx, cancel := context.WithTimeout(
				context.Background(),
				10*time.Second,
			)
			err := acmeServer.Shutdown(shutdownCtx)
			cancel()
			if err != nil {
				logger.Printf("acme server: error while terminating: %s\n", err)
			} else {
				logger.Printf("acme server terminated.")
			}
		}

		// Shutdown the fingerprint webserver,
		// after the acme webserver is closed
		logger.Printf("fingerprint server: terminating...")
		shutdownCtx, cancel := context.WithTimeout(
			context.Background(),
			10*time.Second,
		)
		err := httpServer.Shutdown(shutdownCtx)
		cancel()
		if err != nil {
			logger.Printf("fingerprint server: error while terminating: %s\n", err)
		} else {
			logger.Printf("fingerprint server terminated.")
		}

	}()

	err = g.Wait()
	if err != nil {
		logger.Printf("errgroup terminated with error: %s\n", err)
	}
	return err
}
