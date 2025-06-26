#!/usr/bin/env bash
# https://github.com/cilium/ebpf/blob/v0.18.0/examples/headers/update.sh#L8C1-L14C2

# Version of libbpf to fetch headers from
LIBBPF_VERSION=1.4.5
HEADERS_DIR="headers"

# The headers we want
prefix=libbpf-"$LIBBPF_VERSION"
headers=(
    "$prefix"/LICENSE.BSD-2-Clause
    "$prefix"/src/bpf_endian.h
    "$prefix"/src/bpf_helper_defs.h
    "$prefix"/src/bpf_helpers.h
)

# Fetch libbpf release and extract the desired headers
curl -sL "https://github.com/libbpf/libbpf/archive/refs/tags/v${LIBBPF_VERSION}.tar.gz" | \
    tar -xz -C "$HEADERS_DIR" --xform='s#.*/##' "${headers[@]}"
