# eBPF web fingerprint

A golang webserver and library for fast TCP & TLS fingerprinting, powered by eBPF.  
See [this article](https://halb.it/posts/ebpf-fingerprinting-1/)
for a high-level introduction on the topic.

This project is available in two modes:

- [Standalone Demo Web Server](#run-the-demo-webserver)

A simple webserver that echoes back detailed information about a
visitor's TCP and TLS handshakes.
It can be used to experiment with fingerprintig detection and evasion techniques,
or as a reference for how to use the fingerprint library.

- [Golang fingerprint library](#using-the-fingerprint-library)

A reusable library that can be embedded into existing Golang webservers or
reverse proxies.
It exposes low-level metadata about incoming client connections, enabling advanced fingerprinting and bot detection strategies.

## Run the Demo Webserver

To build and run the Webserver in a dedicated network namespace:
```bash
# create a dedicated network namespace
make testns_setup
# compile and run the test server in the dedicated namespace
make testns_run
```

the server will be accessible at 
`http://10.200.1.2:8080/test/id`

Note that the build process currently requires the Linux UAPI headers to be installed on your system.
This will change in the future.
On ubuntu/debian, you can install the headers with:
```bash
sudo apt install linux-headers-$(uname -r)
```
You can ask your favourite LLM for help with the installation on other linux distributions.

## Run the demo server in TLS mode

first, you must generate a valid self-signed certificate for the ip `10.200.1.2`:

```
openssl req -x509 -nodes -days 730 -newkey rsa:2048 -keyout key.pem -out cert.pem -config san.cnf
```

Then, run the demo server with tls enabled:

```bash
TLS=true make testns_run
```

the server will be accessible at 
```
curl https://10.200.1.2:8080/test/id --insecure
```

to use a specific TLS version:

```
curl https://10.200.1.2:8080/test/id --insecure --tlsv1.1 --tls-max 1.1
```

This project includes some test proxies as submodules in the `test/` folder.
They are useful to test the behaviour of the system under TLS and TCP fragmentation.

to use a specific TLS version and a test proxy, first launch the proxy. then
run:
```
curl https://10.200.1.2:8080/test/id --insecure --tlsv1.1 --tls-max 1.1 --proxy localhost:4433
```

## Other demo server configurations

The demo server receives configuration via environment variables.

For example, this is how you run the demo server with TLS enabled, listening on port 443.
```bash
TLS=true DST_PORT=443 make testns_run
```

This is the complete list of environment variables you can use, and their defaults:

| Variable    | Default      | Description                                                                                                                                    |
| ----------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `IFACE`     | `veth-ns`    | Network interface the server will listen on. Must exist and have the configured `DST_IP` assigned.                                             |
| `DST_IP`    | `10.200.1.2` | IP address on the selected network interface that the server will listen on.                                                                   |
| `DST_PORT`  | `8080`       | TCP port the server will listen on. When `CERTMAGIC=true`, this **cannot** be `80`.                                                            |
| `TLS`       | `false`      | Enable TLS mode and TLS fingerprinting. Options: `"true"` or `"false"`                                                                         |
| `CERTMAGIC` | `false`      | Enable automatic TLS certificate management via Certmagic. Options: `"true"` or `"false"`. When enabled, `TLS_CERT` and `TLS_KEY` are ignored. |
| `TLS_CERT`  | `cert.pem`   | Path to TLS certificate file. Used only when `TLS="true"` and `CERTMAGIC="false"`.                                                             |
| `TLS_KEY`   | `key.pem`    | Path to TLS private key file. Used only when `TLS="true"` and `CERTMAGIC="false"`.                                                             |


## Using the fingerprint library

If you are interested in ways to add ebpf-based fingerprint capabilities to a web server, 
it is extremely unlikely that you want a high-level and opinionated API that starts a 
webserver for you.

This is why the library does not provide any high level function like:
```
startFingerprintWebServer(":80", handlers)
```

Instead, the fingerprint library provides functionalities to tap into an existing 
golang webserver, enhancing what you already have with TCP and (optionally) TLS handshake data.

Considering the limited size of this project and its simplicity, it might be a good idea to 
vendor it or even better to re-implement it from scratch in your project. The MIT license 
of this code allows it.

A good starting point for using the library is therefore to start the demoserver, and to 
experiment with it. See the [demoserver](Run-the-Demo-Webserver) section.
Then, you can read the code to familiarize with the high-level concepts.

## Goals

Note that the main goal of this project is to make 
raw handshake data easily accessible from a regular golang webserver,
with as little overhead as possible.

The implementation of specific fingerprint standards or techniques is out of 
scope. The end user should be left with the freedom to implement the system
they want, based on their project requirements.


