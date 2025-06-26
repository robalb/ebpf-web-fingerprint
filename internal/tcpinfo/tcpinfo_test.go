//go:build linux
// +build linux

// https://github.com/brucespang/go-tcpinfo

package tcpinfo

import (
	"net"
	"testing"
)

func TestGetsockoptTCPInfo(t *testing.T) {
	var listAddr net.Addr
	ch := make(chan error)
	go func() {
		addr, err := net.ResolveTCPAddr("tcp4", "127.0.0.1:0")
		if err != nil {
			ch <- err
			return
		}
		l, err := net.ListenTCP("tcp4", addr)
		if err != nil {
			ch <- err
			return
		}
		listAddr = l.Addr()
		ch <- nil
		_, _ = l.Accept()
	}()

	err := <-ch
	if err != nil {
		t.Error(err)
	}
	conn, err := net.DialTCP("tcp4", nil, listAddr.(*net.TCPAddr))
	if err != nil {
		t.Error(err)
	}
	tcpInfo, err := GetsockoptTCPInfo(conn)
	if err != nil {
		t.Error(err)
	}

	if tcpInfo.Rtt <= 0 {
		t.Errorf("get tcpinfo failed. tcpInfo=%v", tcpInfo)
	}
}
