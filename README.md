# bpf-phun

# Overview
This repository provides sample eBPF program that serves as a connection counter and simple packet filter and port scan detector.
It leverages eXpress Data Path to scan for SYN packets.

Made for fun, with love. My first golang app :-)

## Description
This service consist of two programs.
* bpf program written in C, leveraging XDP, loaded via `tc`
* userspace golang program which interacts with bpf via maps
Program will count connections in term of SYN packets sent to the network interface (`eth0` by default). This does not count for the total of established network connections, rather connection attempts. This is more usefull for synflood detection and port scan detection than tracking established connection count.
Filtering is done based on bpf map contents. BPF program will filter anything present within the map and golang program controls what is in the map and runs logic for scan detection.

## Metrics
Program also exposes metrics available on port `2112` on `/metrics` endpoint - ie. http://localhost:2112/metrics
* `network_new_connections_count` - count of new connections since programm start

### BPF maps
Currently this services uses two hardcoded and pinned BPF maps. A hash and a queue.
I understand that this is not ideal, however it's sufficient for first version.
* `/sys/fs/bpf/tc/globals/conn_map` - `BPF_MAP_TYPE_QUEUE` used for connection tracking
* `/sys/fs/bpf/tc/globals/deny_hash` - `BPF_MAP_TYPE_HASH` hash of blocked ip addresses


## Prerequisites
Linux Kernel 5.4+
Ubuntu 20+ recommended however other distros should work too (not tested!)

make,
docker

#### Other prerequisites are installed via `Dockerfile`
clang
iproute2
kernel-headers
libc-dev

golang1.17.3+

## Build
Simply run:

`make docker`


Or if you wish to build locally run `make`

## Run
By default the program will attach to `eth0`. If you wish to change that, edit the `Makefile`.

### Docker
`make run`

or

`docker run --privileged --network=host -v/sys/fs/bpf:/sys/fs/bpf -ti ${IMAGENAME}`

Note that container needs to run with network type host and be privileged to have access to bpf.
It is possible to control more granuralry using cgroups, but for now this is enough.

### Local
`make install` to install bpf program to eth0

`./filter` - to run the filter handler

## TODO:
* ipv6 support
