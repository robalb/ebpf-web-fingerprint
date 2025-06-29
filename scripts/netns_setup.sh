#!/bin/bash
set -e

# Create namespace
sudo ip netns add testns

# Create veth pair "veth-host" <--> "veth-ns"
sudo ip link add veth-host type veth peer name veth-ns

# Assign one end to namespace
sudo ip link set veth-ns netns testns

# Configure host side
sudo ip addr add 10.200.1.1/24 dev veth-host
sudo ip link set veth-host up

# Configure namespace side
sudo ip netns exec testns ip addr add 10.200.1.2/24 dev veth-ns
sudo ip netns exec testns ip link set veth-ns up
sudo ip netns exec testns ip link set lo up

# disable RST packets, both received and sent to the namespace
# sudo ip netns exec testns iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
# sudo ip netns exec testns iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP

# Add default route in namespace
sudo ip netns exec testns ip route add default via 10.200.1.1

echo "Namespace 'testns' is set up."
echo "Run commands like: sudo ip netns exec testns YOURCOMMAND"

