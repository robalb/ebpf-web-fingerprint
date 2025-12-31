package bpfprobe

import "encoding/binary"

// NetToHostShort converts a 16-bit integer from network to host byte order, aka "ntohs"
func netToHost_uint16(i uint16) uint16 {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, i)
	return binary.NativeEndian.Uint16(data)
}

// NetToHostLong converts a 32-bit integer from network to host byte order, aka "ntohl"
func netToHost_uint32(i uint32) uint32 {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, i)
	return binary.NativeEndian.Uint32(data)
}

// HostToNetShort converts a 16-bit integer from host to network byte order, aka "htons"
func hostToNet_uint16(i uint16) uint16 {
	b := make([]byte, 2)
	binary.NativeEndian.PutUint16(b, i)
	return binary.BigEndian.Uint16(b)
}

// HostToNetLong converts a 32-bit integer from host to network byte order, aka "htonl"
func hostToNet_uint32(i uint32) uint32 {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, i)
	return binary.BigEndian.Uint32(b)
}
