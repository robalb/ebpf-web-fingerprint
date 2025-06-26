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
	serverIp string,
	serverPort int,
) (probe *Probe, err error) {
	errCtx := "ebpf"

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("%s: Failed to remove memlock: %v", errCtx, err)
	}

	spec, err := loadXdp()
	if err != nil {
		return nil, fmt.Errorf("%s: Failed to load spec: %v", errCtx, err)
	}

	// Define the target ip, in big-endian format,
	// and inject the value in the eBPF program
	ip := net.ParseIP(serverIp).To4()
	if err := spec.Variables["dst_ip"].Set(ip); err != nil {
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

func (p *Probe) Lookup(host string, port string) (ret string) {

	// read the counter metrics
	var count uint64
	err := p.objs.PktCount.Lookup(uint32(0), &count)
	if err != nil {
		return "map lookup error"
	}
	ret = fmt.Sprintf("%s count: %d", ret, count)

	//prepare the key to read the tcp syn data
	var tcphVal xdpTcpHandshakeVal
	tcphKey, keyAddr, keyPort, err := makeKey(host, port)
	if err != nil {
		return fmt.Sprintf("%s, syn: KEY_ERROR", ret)
	}
	fmt.Printf("KEY: %016x\n", tcphKey)

	//read the tcp syn data
	err = p.objs.TcpHandshakes.Lookup(tcphKey, &tcphVal)
	if err != nil {
		return fmt.Sprintf("%s, syn: LOOKUP_ERROR %v", ret, err)
	}

	fmt.Printf("%v \n", tcphVal)

	//sanity check, to avoid hash collision reads
	if tcphVal.SrcPort != keyPort {
		return fmt.Sprintf("%s, syn: KEY_PORT_MISMATCH", ret)
	}
	if tcphVal.SrcAddr != keyAddr {
		return fmt.Sprintf("%s, syn: KEY_ADDR_MISMATCH ", ret)
	}

	return fingerprint(tcphVal)
}
