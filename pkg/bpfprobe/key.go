package bpfprobe

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

func makeKey(remoteAddr string) (key xdpTcpHandshakeKey, ipStr string, portInt int, err error) {
	ipStr, portStr, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		err = fmt.Errorf("invalid remoteAddr: %v", err)
		return
	}

	portInt, err = strconv.Atoi(portStr)
	if err != nil || portInt < 0 || portInt > 65535 {
		err = fmt.Errorf("invalid port: %s", portStr)
		return
	}
	// note: portInt has its bytes in the native endiannes of the
	// architecture, but we need to explicity set it in BigEndian
	// network order. This is why we call our hton converter func
	port := hostToNet_uint16(uint16(portInt))
	key.Port = port

	ip := net.ParseIP(ipStr)
	if ip == nil {
		err = fmt.Errorf("Invalid IP address: %s", ipStr)
		return
	}
	ip4Bytes := ip.To4()
	if ip4Bytes != nil{
	    // note: ip4Bytes is already in big endian network order,
	    // therefore we only need to convert its type to uint32.
	    // func NativeEndian.Uint32 will not cause any byteswap.
		key.Addr[0] = binary.NativeEndian.Uint32(ip4Bytes)
	}else{
		b := ip.To16()
		key.Addr[0] = binary.NativeEndian.Uint32(b[0:4])
		key.Addr[1] = binary.NativeEndian.Uint32(b[4:8])
		key.Addr[2] = binary.NativeEndian.Uint32(b[8:12])
		key.Addr[3] = binary.NativeEndian.Uint32(b[12:16])
	}

	return
}
