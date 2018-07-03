package responder

import (
	"fmt"

	"github.com/tenta-browser/tenta-dns/runtime"
)

const (
	SPEEDTEST_MAX_FILESIZE_EXPONENT = 10 /// 2^exponent will be the resulting filesize for speedtest (basically, we have 1, 2, 4 ... 1024)
	SPEEDTEST_ONE_UNIT              = "MTen9Qfgh66JKZTwVsPKwaHqYM1mU5SW7cANEa6OG9RSGWsa1N327O7K3lDXQ8wLcjFV5HtoOSmKQKmj0rycBExMPW4Sni9AI7gyb8pwI7OoC9KXyRsKo9iFDB3OdhmraOHmrD9vPQo2FwuR4xC8NM5twOhQfWVysh0gIvlP9TtkspyUQBxHKoCSsI5NZavwXKG1BYLopvczB0vxoQna45AaUZpAKKigoPQOo5pnghxaGYpKAYvKCNYKYCE6Sm8s2irGTmkZTu47ayNzZ1euBkWcuQJ2y6vjoIpKOC2kPpqFo1j79Hm1v8ppz2lwV9gw1OWxhkRVgQc2yEm3KCutYhywTjVUdWoXq5LfeI487WUa4EUVkcmX193VBT1ZzeuVsiQU7yZfGwIDlB5DiwVBDMba1uP9Qyf8FB0O1YsHXpawhiu03UAxgrnojHSGYWWDHBNKhiqvBGxxWfRutP77m0uczZtxzvWYML2zR6VRQ55fOb1MLqrfRPakcZknHAMbe6rflE0XuubjC3PgZvs2BAwPX5MtrVDXxEnBgot4MrTE0ka78Aj1FRTaOvYwEFKFoPsfYitxWvYc13zGAs6XTRjykwdN3SkmloLtHnJ6H996m2VjH9RXof5ta3FkmSddNLxPrXeQNhKKSgFIS5Kb0JTFr3sFapRGQpgT4qIpqbsEbeQfVbBkqVPmy3gUlfDkVlK3FQ5CuVDuY20cpORKCbPzReCBtxu27gKJokrSFJXFQ7ZLh9K3jbMgavtpGS65UTJmK4TZsWKQrzSMsyU6GHIJ9Bjw7Ak5Slb1tpOOrVOmIXnksBIGtFEw9WopK4jx4Rx5GGb3wPajHNI0RCioA2ShkdXDiKAyzNaHI6izdfyRHYHD7Jjjud72EE8Q3Em7XRICDVNVNuKyohPy4hwu32TrRwsGOoEQuiJr8Oeq6YEq5MWS3dxvR00CSIxTQhMTdsBrZdDhA4bmpRUYSb9CWmy3Djwszu8VC6iKxKzH1sX2d1vyyHggXfFyQAhcxz5j"
)

func hostInfo(v4 bool, net string, d *runtime.ServerDomain) (ip string, port int) {
	if v4 {
		ip = d.IPv4
	} else {
		ip = fmt.Sprintf("[%s]", d.IPv6)
	}
	if net == "tcp" {
		if d.DnsTcpPort <= runtime.PORT_UNSET {
			panic("Unable to start a TCP recursive DNS server without a valid TCP port")
		}
		port = d.DnsTcpPort
	} else if net == "udp" {
		if d.DnsUdpPort <= runtime.PORT_UNSET {
			panic("Unable to start a UDP recursive DNS server without a valid UDP port")
		}
		port = d.DnsUdpPort
	} else if net == "tls" {
		if d.DnsTlsPort <= runtime.PORT_UNSET {
			panic("Unable to start a TLS recursive DNS server without a valid TLS port")
		}
		port = d.DnsTlsPort
	} else if net == "https" {
		if d.HttpsPort <= runtime.PORT_UNSET {
			panic("Unable to start a HTTPS recursive DNS server without a valid HTTPS port")
		}
		port = d.HttpsPort
	} else {
		panic(fmt.Sprintf("Unknown network type %s", net))
	}
	return
}
