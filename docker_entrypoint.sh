#!/usr/bin/env sh

export GOPATH=/usr/local/go/
export PATH=$PATH:$GOPATH/bin

#get the kernel headers, just in case we land on different kernel
apt-get install -y linux-headers-$(uname -r)

make uninstall; make install

./filter
