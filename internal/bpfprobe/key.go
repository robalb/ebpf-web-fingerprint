package bpfprobe

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

// Generate an uint64 key from ip and port, with
// the same byte order and endiannes as the ebpf
// program that generated the hasmap entryies.
//
// inline __u64 make_key(__u32 ip, __u16 port) {
//    return ((__u64)ip << 16) | port;
// }
//

func makeKey(remoteAddr string) (key uint64, ip uint32, port uint16, err error) {
	ipStr, portStr, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		err = fmt.Errorf("invalid remoteAddr: %v", err)
		return
	}

	ipBytes := net.ParseIP(ipStr).To4()
	if ipBytes == nil {
		return 0, 0, 0, fmt.Errorf("invalid IPv4 address: %s", ipStr)
	}
	// note: ipBytes is already in big endian network order,
	// therefore we only need to convert its type to uint32.
	// func NativeEndian.Uint32 will not cause any byteswap.
	ip = binary.NativeEndian.Uint32(ipBytes)

	portInt, err := strconv.Atoi(portStr)
	if err != nil || portInt < 0 || portInt > 65535 {
		return 0, 0, 0, fmt.Errorf("invalid port: %s", portStr)
	}
	// // note: portInt has its bytes in the native endiannes of the
	// // architecture, but we need to explicity set it in BigEndian
	// // network order. This is why we call our hton converter func
	port = hostToNet_uint16(uint16(portInt))

	//the end key is a composite of address and port, both in big endian order.
	key = (uint64(ip) << 16) | uint64(port)
	return
}
