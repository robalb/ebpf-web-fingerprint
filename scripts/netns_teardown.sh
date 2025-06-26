#!/bin/bash
set -e

# Delete veth if it still exists
sudo ip link del veth-host 2>/dev/null || true

# Delete the namespace
sudo ip netns del testns 2>/dev/null || true

echo "Namespace and interfaces cleaned up."

