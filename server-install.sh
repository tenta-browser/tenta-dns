#!/bin/bash

set +x

if [ -z "$GOPATH" ]; then
  GOPATH="/usr/local/src/gopath"
  echo "GOPATH is empty, setting it to $GOPATH"
fi

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "Installing src to $GOPATH/src"

rm -rf $GOPATH/src/nsnitch
mkdir -p $GOPATH/src/nsnitch
cp -R $DIR/src/nsnitch/* $GOPATH/src/nsnitch/

echo "Installing dependencies to $GOPATH/pkg"

go get -u -v github.com/syndtr/goleveldb/leveldb
go get -u -v github.com/miekg/dns
go get -u -v github.com/leonelquinteros/gorand
go get -u -v github.com/gorilla/mux
go get -u -v github.com/BurntSushi/toml
go get -u -v github.com/sasha-s/go-hll
go get -u -v github.com/oschwald/maxminddb-golang
go get -u -v github.com/dgryski/go-highway

echo "Compiling to $GOPATH/bin"

go install -v nsnitch

echo "Setting up configs"

mkdir -p /etc/nsnitch/{conf.d,certs}

cp $DIR/etc/words.txt /etc/nsnitch/words.txt
if [ -f /etc/nsnitch/config.toml ]; then
  cp $DIR/etc/config.toml /etc/nsnitch/config.toml.new
else
  cp $DIR/etc/config.toml /etc/nsnitch/config.toml
fi
