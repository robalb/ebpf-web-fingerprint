
This tutorial will show you how to run the fingerprint demo server on an internet-facing vps, using automatic tls generation thanks to [Certmagic](https://github.com/caddyserver/certmagic)

## requirements

For this tutorial you will need:

- An ubuntu vps, with a public IPv4. you can get a cheap vps from OVH or Hetzner
- A DNS record pointing to yor VPS IPv4

These are both services you can rent. They will cost you ~5$. You can ask your favourite LLM for help about both these concepts.
The rest of this tutorial assumes you are familiar with the requirements, and that you are runnig 
linux commands from inside your ubuntu vps.

## Compile the demo server

install go, and the linux kernel headers.
On ubuntu:

```bash
sudo apt install linux-headers-$(uname -r)
```

then compile the demo server:

```bash
got clone https://github.com/robalb/ebpf-web-fingerprint
cd ebpf-web-fingerprint
make
```

a new file called `main` will be generated. It's a statically linked ELF, that will run the 
demo web server.

## prepare the systemd unit files

```bash
sudo mkdir -p /opt/demoserver
sudo cp ./main /opt/demoserver/main
sudo chmod +x /opt/demoserver/main
```

## Find the network interface name and ip

```bash
ip a
```

for example, Given this output:

```
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdp/id:684 qdisc fq_codel state UP group default qlen 1000
    link/ether 92:00:06:4f:e9:5e brd ff:ff:ff:ff:ff:ff
    inet 188.245.33.73/32 metric 100 scope global dynamic eth0
       valid_lft 47207sec preferred_lft 47207sec
    inet6 2a01:4f8:1c1a:dd4e::1/64 scope global
       valid_lft forever preferred_lft forever
    inet6 fe80::9000:6ff:fe4f:e95e/64 scope link
       valid_lft forever preferred_lft forever

```

The network interface name and ip we are insterested in are:

```
eth0
188.245.33.73
```

## create the systemd unit

```bash
sudo vi /etc/systemd/system/demoserver.service
```

you will have to configure the field
- IFACE
- DST_IP
- CERTMAGIC_DOMAINS

with the interface name and ip of your vps, and your own domain name.

```
[Unit]
Description=Demo Server (XDP)
After=sys-subsystem-net-devices-eth0.device
Wants=sys-subsystem-net-devices-eth0.device

[Service]
Type=simple

User=root
Group=root

Environment=IFACE=eth0
Environment=DST_IP=188.245.33.73
Environment=DST_PORT=443
Environment=TLS=true
Environment=CERTMAGIC=true
Environment=CERTMAGIC_DOMAINS=example.com
Environment=XDG_DATA_HOME=/var/lib/demoserver

ExecStart=/opt/demoserver/main

# REQUIRED for eBPF / XDP
LimitMEMLOCK=infinity

# Restart policy
Restart=always
RestartSec=10

# eBPF-safe hardening
PrivateTmp=true
ProtectKernelTunables=false
ProtectKernelModules=false
ProtectControlGroups=false
RestrictNamespaces=true

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

## enable and start

```
sudo systemctl daemon-reload
sudo systemctl enable demoserver
sudo systemctl start demoserver
```

Your service will now be accessible at `example.com`

You can test the fingerprint service by visiting:
```
example.com/test/id
```
