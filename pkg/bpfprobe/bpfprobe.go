package bpfprobe

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type Probe struct {
	objs xdpObjects
	link link.Link
}

func (p *Probe) Close() {
	p.objs.Close()
	p.link.Close()
}

func New(
	logger *log.Logger,
	interfaceName string,
	serverPort int,
) (probe *Probe, err error) {
	errCtx := "ebpf"

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("%s: Failed to remove memlock: %v", errCtx, err)
	}

	// List the IP addresses associated to the net interface,
	// choose the first ipv4 and the first ipv6 from that list
	var (
		ief       *net.Interface
		addrs     []net.Addr
		serverIP  net.IP
		serverIP6 net.IP
	)
	if ief, err = net.InterfaceByName(interfaceName); err != nil { // get interface
		return
	}
	if addrs, err = ief.Addrs(); err != nil {
		return
	}
	for _, addr := range addrs {
		ip4 := addr.(*net.IPNet).IP.To4()
		ip6 := addr.(*net.IPNet).IP.To16()
		logger.Printf("Found ip: %v", ip6)
		if ip4 != nil {
			if serverIP == nil {
				serverIP = ip4
			}
		} else if ip6 != nil {
			if serverIP6 == nil {
				serverIP6 = ip6
			}
		}
	}

	if serverIP == nil && serverIP6 == nil {
		return nil, fmt.Errorf("Failed to find a valid address for the provided interface: %s .", interfaceName)
	}
	if serverIP == nil {
		logger.Printf("dst_ip4: not set. eBPF probe will not listen for ipv4 packets")
	}
	if serverIP6 == nil {
		logger.Printf("dst_ip6: not set. eBPF probe will not listen for ipv6 packets")
	}
	if serverIP6 != nil {
		logger.Printf("dst_ip6: %s", serverIP6.String())
	}
	if serverIP != nil {
		logger.Printf("dst_ip4: %s", serverIP.String())
	}

	spec, err := loadXdp()
	if err != nil {
		return nil, fmt.Errorf("%s: Failed to load spec: %v", errCtx, err)
	}

	// Inject the target IPs into the eBPF program.
	// The bytes are already in big-endian network order.
	if serverIP != nil {
		if err := spec.Variables["dst_ip"].Set(serverIP); err != nil {
			return nil, fmt.Errorf("%s: Failed to set dst_ip: %v", errCtx, err)
		}
	}
	if serverIP6 != nil {
		b := serverIP6.To16()
		var ip6 [4]uint32
		ip6[0] = binary.NativeEndian.Uint32(b[0:4])
		ip6[1] = binary.NativeEndian.Uint32(b[4:8])
		ip6[2] = binary.NativeEndian.Uint32(b[8:12])
		ip6[3] = binary.NativeEndian.Uint32(b[12:16])
		if err := spec.Variables["dst_ipv6"].Set(ip6); err != nil {
			return nil, fmt.Errorf("%s: Failed to set dst_ipv6: %v", errCtx, err)
		}
	}

	// Inject the target port in big-endian format.
	port := hostToNet_uint16(uint16(serverPort))
	if err := spec.Variables["dst_port"].Set(port); err != nil {
		return nil, fmt.Errorf("%s: Failed to set dst_port: %v", errCtx, err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs xdpObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("%s: LoadAndAssign failed: %v", errCtx, err)
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("%s: Interface fetch error: %v", errCtx, err)
	}

	// Attach count_packets to the network interface.
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CountPackets,
		Interface: iface.Index,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: AttachXDP failed: %v", errCtx, err)
	}

	logger.Printf("ebpf XDP program successfully attached to %s", interfaceName)
	probe = &Probe{
		objs: objs,
		link: link,
	}
	return
}
