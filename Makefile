.PHONY: install uninstall clean build docker run all


INTERFACE=eth0
CC=clang
ARCH=$(shell uname -m)
CFLAGS=-O2 -Wall -target bpf
INCLUDES=-I/usr/include/${ARCH}-linux-gnu
CSRCDIR=src/c
GOSRCDIR=src/go
GOCMD=${GOPATH}/bin/go
GOFLAGS=CGO_ENABLED=0
DOCKERCMD=docker
IMAGENAME=filter
GOPATH=/usr/local/go

all: build

### please note that this is a very simple Makefile just to provide basic features

#while this is absolutely not needed I just wanted to show you that I can
%.o: ${CSRCDIR}/%.c
	${CC} -c ${CFLAGS} ${INCLUDES} $< -o $@

filter:
	${GOFLAGS} ${GOCMD} build -o $@ ${GOSRCDIR}/*.go

#and this is explicit to limit scope
build: filter.o filter

docker:
	${DOCKERCMD} build -t ${IMAGENAME} .

run:
	docker run --privileged --network=host -v/sys/fs/bpf:/sys/fs/bpf -ti ${IMAGENAME}

clean:
	rm -r filter.o filter

uninstall:
	tc qdisc del dev ${INTERFACE} clsact

install: build
	tc qdisc add dev ${INTERFACE} clsact
	tc filter add dev ${INTERFACE} ingress bpf da obj filter.o sec in
	tc filter add dev ${INTERFACE} egress bpf da obj filter.o sec out
