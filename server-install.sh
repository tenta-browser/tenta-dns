#!/bin/bash

set +x

if [ -z "$GOPATH" ]; then
  GOPATH="/usr/local/src/gopath"
  echo "GOPATH is empty, setting it to $GOPATH"
fi

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "Installing src to $GOPATH/src"

rm -rf $GOPATH/src/tenta-dns
mkdir -p $GOPATH/src/tenta-dns
cp -R $DIR/src/tenta-dns/* $GOPATH/src/tenta-dns/

echo "Installing dependencies to $GOPATH/pkg"

oldifs=$IFS
IFS='
'
for line in `cat ./deps.list`; do
    echo "Installing $line"
    go get -u -v $line
done
IFS=$oldifs

echo "Installing gobgp"

go get github.com/osrg/gobgp/gobgp

echo "Compiling to $GOPATH/bin"

go install -v tenta-dns

echo "Setting up configs"

mkdir -p /etc/nsnitch/conf.d
mkdir -p /etc/nsnitch/certs
mkdir -p /etc/nsnitch/geo.db

cp $DIR/etc/words.txt /etc/nsnitch/words.txt
if [ -f /etc/nsnitch/config.toml ]; then
  cp $DIR/etc/config.toml /etc/nsnitch/config.toml.new
else
  cp $DIR/etc/config.toml /etc/nsnitch/config.toml
fi
