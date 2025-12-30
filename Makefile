
EBPF_DIR := internal/bpfprobe
EBPF_PKG := bpfprobe
BPF2GO := github.com/cilium/ebpf/cmd/bpf2go
HEADERS_DIR := headers
GO_BINARY := main
GO_BUILD_FLAGS := CGO_ENABLED=0 GOARCH=amd64

.PHONY: all
all: build

.PHONY: testns_run
testns_run: build
	sudo -E ip netns exec testns ./$(GO_BINARY)

.PHONY: testns_setup
testns_setup:
	sudo ./scripts/netns_setup.sh

.PHONY: testns_teardown
testns_teardown:
	sudo ./scripts/netns_teardown.sh

.PHONY: build
build: $(EBPF_DIR)/xdp_bpfel.go
	$(GO_BUILD_FLAGS) go build -o $(GO_BINARY) ./cmd/demoserver/main.go

# Build eBPF object and Go bindings.
# We use our own libbpf API headers and Linux UAPI headers to avoid
# dependency on system-wide headers, which could be missing or outdated
# TODO: vendor UAPI headers. see: maketest git branch
$(EBPF_DIR)/xdp_bpfel.go: $(HEADERS_DIR)/bpf_helpers.h $(EBPF_DIR)/xdp.c
	go run $(BPF2GO) \
		-go-package $(EBPF_PKG) \
		-output-dir $(EBPF_DIR) \
		-tags linux xdp $(EBPF_DIR)/xdp.c -- \
		-I$(HEADERS_DIR)

# Clean generated files
.PHONY: clean
clean:
	rm -f $(EBPF_DIR)/xdp*.go
	rm -f $(EBPF_DIR)/xdp*.o
	rm -f $(GO_BINARY)

