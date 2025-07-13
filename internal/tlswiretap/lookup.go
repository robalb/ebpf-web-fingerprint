package tlswiretap

import (
	"errors"
	"net/http"

	"github.com/robalb/deviceid/pkg/handshake"
)

// update the given handshake with the client TLS hello data,
// or return an error on fail.
func Lookup(h *handshake.Handshake, r *http.Request) (err error) {
	fingerRaw := r.Context().Value(fingerprintKey)
	if fingerRaw == nil {
		return errors.New("tls fingerprint not in context")
	}

	finger, ok := fingerRaw.(*fingerprint)
	if !ok {
		return errors.New("tls fingerprint type mismatch")
	}

	tls := finger.hex.Load()
	if tls == nil {
		return errors.New("tls fingerprint is nil")
	} else {
		h.TLS = *tls
	}

	return
}
