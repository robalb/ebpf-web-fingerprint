# eBPF web fingerprint

a golang webserver and library for fast TCP & TLS fingerprinting, powered by eBPF.
See [this article](https://halb.it/posts/ebpf-fingerprinting-1/)
for a high-level introduction on the topic.

This project is available in two modes:

1. ### Standalone Test Webserver
A simple webserver that echoes back detailed information about a
visitor's TCP and TLS handshakes.
It can be used to experiment with fingerprintig detection and evasion techniques,
or as a reference implementation of the fingerprint library.

2. ### Golang fingerprint library
A reusable library that can be embedded into existing Golang webservers or
reverse proxies.
It exposes low-level metadata about incoming client connections, enabling advanced fingerprinting and bot detection strategies.


## Run the Test Webserver

To build and run the Webserver in a dedicated network namespace:
```bash
# create a dedicated network namespace
make testns_setup
# compile and run the test server in the dedicated namespace
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
```
curl https://10.200.1.2:8080/test/id --unsecure
```

to use a specific TLS version:

```
curl https://10.200.1.2:8080/test/id --unsecure --tlsv1.1 --tls-max 1.1
```

This project includes some test proxies as submodules in the `test/` folder.
They are useful to test the behaviour of the system under TLS and TCP fragmentation.

to use a specific TLS version and a test proxy, first launch the proxy. then
run:
```
curl https://10.200.1.2:8080/test/id --unsecure --tlsv1.1 --tls-max 1.1 --proxy localhost:4433
```


## Goals

Note that the main goal of this project is to make 
raw handshake data easily accessible from a regular golang webserver,
with as little overhead as possible.

The implementation of specific fingerprint standards or techniques is out of 
scope. The end user should be left with the freedom to implement the system
they want, based on their project requirements.


