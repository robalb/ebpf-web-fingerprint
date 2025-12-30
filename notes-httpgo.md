
```go

//++++++++++++++
// http Handler 
//++++++++++++++

type Handler interface {
    ServeHTTP(ResponseWriter, *Request)
}

// custom handlers using a mux:
mux := http.NewServeMux() // implements Handler
mux.HandleFunc(
    "/foo",
    fooHandler // func(ResponseWriter, *Request)
    )

// default, global servermux:
// It's instantiated by default when the http 
// module is imported
var DefaultServeMux = NewServeMux()
// these helper functions will register
// http handlers on the defaultserveMux:
http.HandleFunc(
    "/foo",
    fooHandler // func(ResponseWriter, *Request)
    )


//++++++++++++++
// http Server
//++++++++++++++


httpServer := &http.Server{
    Addr: "host:port",
    // Defaults to http.DefaultServeMux if nil
    Handler: Http.Handler,
	// TLSConfig optionally provides a TLS configuration for use
	// by ServeTLS and ListenAndServeTLS. Note that this value is
	// cloned by ServeTLS and ListenAndServeTLS, so it's not
	// possible to modify the configuration with methods like
	// tls.Config.SetSessionTicketKeys.
    TLSConfig: tls.Config,
	// BaseContext optionally specifies a function that returns
	// the base context for incoming requests on this server.
	// The provided Listener is the specific Listener that's
	// about to start accepting requests.
	// If BaseContext is nil, the default is context.Background().
	// If non-nil, it must return a non-nil context.
	BaseContext func(net.Listener) context.Context
	// ConnContext optionally specifies a function that modifies
	// the context used for a new connection c. The provided ctx
	// is derived from the base context and has a ServerContextKey
	// value.
	ConnContext: func(ctx context.Context, c net.Conn) context.Context

	// ErrorLog specifies an optional logger for errors accepting
	// connections, unexpected behavior from handlers, and
	// underlying FileSystem errors.
	// If nil, logging is done via the log package's standard logger.
	ErrorLog *log.Logger
}



//++++++++++++++
// launching the http Server
//++++++++++++++


// start a non-tls webserver using a default TCP listener
// internally it does this:
//   	ln, err := net.Listen("tcp", addr) // net.Listener
//      return s.Serve(ln)
err = httpServer.ListenAndServe()

// This helper function will define a new Server and will start it.
// if no mux is provided, the server will default to DefaultServeMux
// interanlly it does this:
//     server := &Server{Addr: addr, Handler: handler}
//     return server.ListenAndServe()
http.ListenAndServe("host:port")
http.ListenAndServe("host:port", handler)


//++++++++++++++
// launching the http+tls Server
//++++++++++++++

// start a tls webserver with a default TCP listener
// Filenames containing a certificate and matching private key for the
// server must be provided if neither the [Server]'s TLSConfig.Certificates
// nor TLSConfig.GetCertificate are populated. If the certificate is
// signed by a certificate authority, the certFile should be the
// concatenation of the server's certificate, any intermediates, and
// the CA's certificate.
// internally it does this:
//   	ln, err := net.Listen("tcp", addr) // net.Listener
//      return s.ServeTLS(ln, certFile, keyFile)
err = httpServer.ListenAndServeTLS(
    certfile, //optional
    keyfile //optional
    )

// just like the http version, there are hekper functions that default a blank server and  start it in https mode
http.ListenAndServeTLS("host:port", mux, cerfile, keyfile)

// -----------------
// internals pseudocode: 
// -----------------
ListenAndServeTLS()
    ln, err := net.Listen("tcp", addr) // net.Listener
    return s.ServeTLS(ln, certFile, keyFile)
              /
             /
        serveTLS()
            config := cloneTLSConfig(s.TLSConfig)
            tlsListener := tls.NewListener(l, config) // net.Listener
            return s.Serve(tlsListener) // the same used by http.ListenAndServe



//++++++++++++++
// net.Listener
//++++++++++++++

// A Listener is a generic network listener for stream-oriented protocols.
//
// Multiple goroutines may invoke methods on a Listener simultaneously.
type Listener interface {
	// Accept waits for and returns the next connection to the listener.
	Accept() (Conn, error)

	// Close closes the listener.
	// Any blocked Accept operations will be unblocked and return errors.
	Close() error

	// Addr returns the listener's network address.
	Addr() Addr
}


```
