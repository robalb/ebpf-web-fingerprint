package bpfprobe

type HandshakeTCP struct {
	MSS        uint16
	Window     uint16
	Scale      uint8
	OptionList []uint16
}

func parseTCP(t xdpTcpHandshakeVal) HandshakeTCP {
	window := netToHost_uint16(t.Window)

	// Optlen doesn't come from a net packet. It's an int defined
	// at the ebpf side, which means it has the host's endianness.
	optlen := int(t.Optlen)

	//parse the TCP options
	i := 0
	mss := uint16(0)
	scale := uint8(0)
	optionList := []uint16{}

	for i < optlen {
		kind := t.Options[i]

		// EOL option
		if kind == 0 {
			break
		}

		optionList = append(optionList, uint16(kind))

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
			scale = t.Options[i+2]
		}

		i += length
	}

	return HandshakeTCP{
		MSS:        mss,
		Window:     window,
		Scale:      scale,
		OptionList: optionList,
	}
}
