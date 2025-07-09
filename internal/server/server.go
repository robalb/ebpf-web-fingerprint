package server

import (
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/robalb/deviceid/internal/bpfprobe"
	"github.com/robalb/deviceid/internal/tcpinfo"
	"github.com/robalb/deviceid/internal/validation"
)

func NewServer(
	logger *log.Logger,
	probe *bpfprobe.Probe,
) http.Handler {
	mux := chi.NewRouter()
	mux.Use(middleware.Logger)
	mux.Use(middleware.Recoverer)
	mux.Use(middleware.Heartbeat("/health"))
	mux.Use(cors.Handler(cors.Options{
		AllowOriginFunc:  func(r *http.Request, origin string) bool { return true },
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "Upgrade", "Cookie"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	}))

	//TODO remove, move all routes in routes.go,
	//pass all deps via func params, including logger
	mux.Route("/test", func(r chi.Router) {
		r.Get("/id", serveTestFinger(logger, probe))
		r.Get("/baseline", serveTestBaseline(logger))
	})

	return mux
}

type DebugResponse struct {
	Handshake     bpfprobe.Handshake
	PacketBacklog uint32
	Sock          string
	Proto         string
	Headers       string
}

func serveTestFinger(
	logger *log.Logger,
	p *bpfprobe.Probe,
) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// get sockinfo
		connBase, ok := r.Context().Value(connKey).(net.Conn)
		if !ok {
			http.Error(w, "connection not found", http.StatusInternalServerError)
			return
		}
		conn, ok := connBase.(*net.TCPConn)
		if !ok {
			http.Error(w, "connection is not tcp", http.StatusInternalServerError)
			return
		}
		info, err := tcpinfo.GetsockoptTCPInfo(conn)
		if err != nil {
			http.Error(w, "getsockopt failed", http.StatusInternalServerError)
		}
		sockinfo := fmt.Sprintf("rtt: %d, rttvar: %d", info.Rtt, info.Rttvar)

		// get HTTP headers
		readableHeaders := ""
		for key, value := range r.Header {
			readableHeaders += key
			readableHeaders += ":"
			readableHeaders += value[0]
		}

		// get TCP / TLS data
		remoteAddr, ok := r.Context().Value(remoteAddrKey).(string)
		if !ok {
			http.Error(w, "remote addr not in context", http.StatusInternalServerError)
			return
		}
		remoteIP, remotePort, _ := net.SplitHostPort(remoteAddr)
		lookupResult, err := p.Lookup(remoteIP, remotePort)
		if err != nil {
			validation.RespondError(w, err.Error(), "", http.StatusInternalServerError)
			return
		}

		validation.RespondOk(w, DebugResponse{
			Handshake:     lookupResult,
			PacketBacklog: uint32(lookupResult.GetPacketBacklog()),
			Sock:          sockinfo,
			Proto:         r.Proto,
			Headers:       readableHeaders,
		})
	}
}

func serveTestBaseline(
	logger *log.Logger,
) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.Println("Mock request")
		validation.RespondOk(w, DebugResponse{
			Handshake:     bpfprobe.Handshake{},
			PacketBacklog: 0,
			Sock:          "mock",
			Proto:         "mock",
			Headers:       "mock",
		})

	}
}
