# eBPF web fingerprint

a golang webserver for fast TCP & TLS fingerprinting, powered by eBPF.
See [this article](https://halb.it/posts/ebpf-fingerprinting-1/)
for a high-level introduction on the topic.

## Goals

This is currently a test playground. 
It's a demonstrative web server that echoes back to the visitor informations about their 
TCP and TLS handshake. 

The end goal is to abstract the core functionality into a golang library that can be 
easily imported and used from any existing golang webserver or reverse proxy.
This could be extremely valuable for integrating low-level fingerprinting into existing 
reverse proxies such as traefik or caddy, by using their regular plugin system.

This project does not attempt to implement any specific fingerprint
standard or system.
It simply makes raw handshake data accessible in user space.
The choice of what to do with this data should be left to the end user,
since it heavily depends on the project requirements.

## Run the demo server

To build and run the demo server in a dedicated network namespace:
```
make testns_run
```

the server will be accessible at 
`http://10.200.1.2:8080/test/id`

Note that the build process currently requires the Linux UAPI headers to be 
installed on your system.

### Run the demo server, with TLS

first, you must generate a valid self-signed certificate for the ip `10.200.1.2`:

```
openssl req -x509 -nodes -days 730 -newkey rsa:2048 -keyout key.pem -out cert.pem -config san.cnf
```

the server will be accessible at 
`https://10.200.1.2:8080/test/id --unsecure`

to use a specific TLS version:

`https://10.200.1.2:8080/test/id --unsecure --tlsv1.1 --tls-max 1.1`

This project includes some test proxies as submodules in the `test/` folder.
They are useful to test the behaviour of the system under TLS and TCP fragmentation.

to use a specific TLS version and a test proxy, first launch the proxy. then
run:
`https://10.200.1.2:8080/test/id --unsecure --tlsv1.1 --tls-max 1.1 --proxy localhost:4433`

