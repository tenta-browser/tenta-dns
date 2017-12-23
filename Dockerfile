FROM alpine

RUN mkdir -p /etc/nsnitch/conf.d && \
    mkdir -p /etc/nsnitch/certs && \
    mkdir -p /etc/nsnitch/geo.db


ADD $GOPATH/github.com/tenta-browser/tenta-dns/etc/words.txt     /etc/nsnitch/words.txt
ADD $GOPATH/github.com/tenta-browser/tenta-dns/etc/config.toml   /etc/nsnitch/config.toml

COPY tenta-dns /app/

CMD ["/app/tenta-dns", "-config", "/etc/nsnitch/config.toml"]