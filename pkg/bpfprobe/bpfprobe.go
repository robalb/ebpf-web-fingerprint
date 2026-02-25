package bpfprobe

import (
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
	if addrs, err = ief.Addrs(); err != nil { // get addresses
		return
	}
	for _, addr := range addrs { // get ipv4 address
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

	if serverIP == nil {
		return nil, fmt.Errorf("%s: Failed to find a valid ipv4 on the net interface: ", interfaceName, err)
	}
	if serverIP6 == nil {
		logger.Printf("dst_ip6: not set. eBPF probe will not listen for ipv6 packets")
	}
	logger.Printf("dst_ip6: %s", serverIP6.String())
	logger.Printf("dst_ip4: %s", serverIP.String())

	spec, err := loadXdp()
	if err != nil {
		return nil, fmt.Errorf("%s: Failed to load spec: %v", errCtx, err)
	}

	// Define the target ip, in big-endian format,
	// and inject the value in the eBPF program
	if err := spec.Variables["dst_ip"].Set(serverIP); err != nil {
		return nil, fmt.Errorf("%s: Failed to set dst_ip: %v", errCtx, err)
	}

	// Define the tartet port, in big-endian format,
	// and inject the value in the eBPF program
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
