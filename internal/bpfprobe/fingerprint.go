package bpfprobe

import (
	"fmt"
	"strconv"
	"strings"
)

func fingerprint(t xdpTcpHandshakeVal) string {
	// SrcAddr uint32
	// Ifindex uint32
	// SrcPort uint16

	// Window  uint16
	// Optlen  uint16
	// Options [40]uint8

	window := netToHost_uint16(t.Window)
	// Optlen doesn't come from a net packet. It's an int defined
	// at the ebpf side, which means it has the host's endianness.
	optlen := int(t.Optlen)

	//parse the TCP options
	i := 0
	mss := uint16(0)
	scale := 0
	options := strings.Builder{}

	for i < optlen {
		if i > 0 {
			options.WriteRune('-')
		}
		kind := t.Options[i]

		// EOL option
		if kind == 0 {
			break
		}

		options.WriteString(strconv.FormatUint(uint64(kind), 16))

		// NOP option
		if kind == 1 {
			i += 1
			continue
		}

		// parse the length byte
		length := 0
		if i+1 >= optlen {
			break
		}
		length = int(t.Options[i+1])
		if length < 2 || i+length > optlen {
			break
		}

		// MSS option
		if kind == 2 && length == 4 {
			mss = uint16(t.Options[i])<<8 | uint16(t.Options[i+1])
			mss = netToHost_uint16(mss)
		}

		// Scale option
		if kind == 3 && length == 3 {
			scale = int(t.Options[i+2])
		}

		i += length
	}

	return fmt.Sprintf("%d_%d_%d_%s_%d", window, mss, optlen, options.String(), scale)
}
