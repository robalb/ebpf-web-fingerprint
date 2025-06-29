# eBPF web fingerprint

A golang webserver demonstrating fast TCP & TLS fingerprinting using eBPF

The development of this project is documented [in this article](https://halb.it/posts/ebpf-fingerprinting-1/)

## Goals

The main goal is to 
implement a framework that enables easy access to both TCP 
and TLS handshake data from any regular webserver.
This will provide powerful tools to extend existing reverse proxies
such as nginx or caddy via their regular plugin systems.

## Non-goals

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
