/**
 * Tenta DNS Server
 *
 *    Copyright 2017 Tenta, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * For any questions, please contact developer@tenta.io
 *
 * dns.go: DNS server
 */

package responder

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"time"

	"github.com/tenta-browser/tenta-dns/common"
	"github.com/tenta-browser/tenta-dns/runtime"

	"github.com/tenta-browser/tenta-dns/log"

	"github.com/leonelquinteros/gorand"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func SnitchDNSServer(cfg runtime.NSnitchConfig, rt *runtime.Runtime, v4 bool, net string, d *runtime.ServerDomain) {
	serveSnitchDNS(cfg, rt, v4, net, d)
}

func serveSnitchDNS(cfg runtime.NSnitchConfig, rt *runtime.Runtime, v4 bool, net string, d *runtime.ServerDomain) {
	ip, port := hostInfo(v4, net, d)
	addr := fmt.Sprintf("%s:%d", ip, port)
	lg := log.GetLogger("dnsnitch").WithField("host_name", d.HostName).WithField("address", ip).WithField("port", port).WithField("proto", net)
	notifyStarted := func() {
		lg.Infof("Started %s dns on %s for %s", net, addr, d.HostName)
	}
	lg.Debugf("Preparing %s dns on %s for %s", net, addr, d.HostName)

	pchan := make(chan interface{}, 1)
	srv := &dns.Server{Addr: addr, Net: net, NotifyStartedFunc: notifyStarted, Handler: dns.HandlerFunc(dnsRecoverWrap(handleSnitch(cfg, rt, d, net, lg), pchan))}

	defer rt.OnFinishedOrPanic(func() {
		srv.Shutdown()
		lg.Infof("Stopped %s dns on %s for %s", net, addr, d.HostName)
	}, pchan)

	if net == "tls" {
		go func() {
			cert, err := tls.LoadX509KeyPair(d.CertFile, d.KeyFile)
			if err != nil {
				lg.Warnf("Failed to setup %s dns server on %s for %s: %s\n", net, addr, d.HostName, err.Error())
				return
			}

			tlscfg := &tls.Config{
				MinVersion:               tls.VersionTLS10,
				Certificates:             []tls.Certificate{cert},
				CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
				PreferServerCipherSuites: true,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
			}

			srv.Net = "tcp-tls"
			srv.TLSConfig = tlscfg

			if err := srv.ListenAndServe(); err != nil {
				lg.Warnf("Failed to setup %s dns server on %s for %s: %s\n", net, addr, d.HostName, err.Error())
			}
		}()
	} else {
		go func() {
			if err := srv.ListenAndServe(); err != nil {
				lg.Warnf("Failed to setup %s dns server on %s for %s: %s\n", net, addr, d.HostName, err.Error())
			}
		}()
	}
}

func handleSnitch(cfg runtime.NSnitchConfig, rt *runtime.Runtime, d *runtime.ServerDomain, network string, lgr *logrus.Entry) dnsHandler {
	nodeloc := cfg.Node.MakeNodeLoc()
	fqdn := dns.Fqdn(d.HostName)
	return func(w dns.ResponseWriter, r *dns.Msg) {
		var (
			v4       bool
			serverIp []dns.RR
			//str       string
			a       net.IP
			queried string
			nettype string
			rec     common.DNSTelemetry
		)

		if network == "tls" {
			rec.TLSEnabled = true
		}
		tme := time.Now().Unix()
		rec.RequestTime = uint64(tme)

		if r.MsgHdr.RecursionDesired {
			rec.FlagRD = true
		}
		if r.MsgHdr.CheckingDisabled {
			rec.FlagCD = true
		}

		m := new(dns.Msg)
		m.SetReply(r)
		m.MsgHdr.Authoritative = true
		m.Compress = true

		if ip, ok := w.RemoteAddr().(*net.UDPAddr); ok {
			//str = "Port: " + strconv.Itoa(ip.Port) + " (udp)"
			a = ip.IP
			v4 = a.To4() != nil
			nettype = "udp"
			rt.Stats.Count("dns:queries:internal:udp")
		}
		if ip, ok := w.RemoteAddr().(*net.TCPAddr); ok {
			//str = "Port: " + strconv.Itoa(ip.Port) + " (tcp)"
			a = ip.IP
			v4 = a.To4() != nil
			nettype = "tcp"
			rt.Stats.Count("dns:queries:internal:tcp")
		}
		if v4 {
			rec.IPFamily = "v4"
			rt.Stats.Count("dns:queries:internal:ipv4")
		} else {
			rec.IPFamily = "v6"
			rt.Stats.Count("dns:queries:internal:ipv6")
		}
		rec.NetType = nettype
		rec.IP = a.String()
		geoquery := rt.Geo.Query(rec.IP)

		rt.Stats.Count("dns:queries:all")
		rt.Stats.Count("dns:queries:snitch")
		rt.Stats.Tick("dns", "queries:all")
		rt.Stats.Tick("dns", "queries:snitch")
		rt.Stats.Card("dns:queries:remote_ips", a.String())

		if len(r.Question) < 1 {
			lgr.Debugf("No question set %s\n", d.HostName)
			rt.Stats.Count("dns:queries:error:no_question")
			m.SetRcode(r, dns.RcodeRefused)
			w.WriteMsg(m)
			return
		}

		queried = r.Question[0].Name

		if !dns.IsSubDomain(fqdn, queried) {
			lgr.Warnf("Invalid subdomain for %s: %s\n", queried, fqdn)
			rt.Stats.Count("dns:queries:error:invalid_subdomain")
			m.SetRcode(r, dns.RcodeNameError)
			w.WriteMsg(m)
			return
		}

		if v4 {
			for _, confA := range cfg.DnsReplyv4 {
				serverIp = append(serverIp, &dns.A{
					Hdr: dns.RR_Header{Name: queried, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
					A:   net.ParseIP(confA),
				})
			}
		} else {
			for _, confAAAA := range cfg.DnsReplyv6 {
				serverIp = append(serverIp, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: queried, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0},
					AAAA: net.ParseIP(confAAAA),
				})
			}
		}

		// t := &dns.TXT{
		//   Hdr: dns.RR_Header{Name: queried, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
		//   Txt: []string{str},
		// }

		rec.Subnet = nil
		var subnetquery *runtime.Query = nil
		for _, e := range r.Extra {
			h := e.Header()
			switch h.Rrtype {
			case dns.TypeOPT:
				opt := e.(*dns.OPT)
				if opt.Do() {
					rec.DNSSECOk = true
					rt.Stats.Count("dns:queries:internal:dnssec_okay")
				}
				for _, o := range opt.Option {
					switch o.Option() {
					case dns.EDNS0NSID:
						rec.NSIDEnabled = true
						rt.Stats.Count("dns:queries:internal:nsid_enabled")
						break
					case dns.EDNS0SUBNET:
						rt.Stats.Count("dns:queries:internal:client_subnet")
						sn := o.(*dns.EDNS0_SUBNET)
						subnetquery = rt.Geo.Query(sn.Address.String())
						cs := &common.ClientSubnet{
							IP:      sn.Address.String(),
							Netmask: int(sn.SourceNetmask),
						}
						if sn.Family == 1 {
							cs.IPFamily = "v4"
						} else if sn.Family == 2 {
							cs.IPFamily = "v6"
						}
						rec.Subnet = cs
						break
					case dns.EDNS0COOKIE:
						rec.Cookie = true
						rt.Stats.Count("dns:queries:internal:dns_cookie")
						break
					case dns.EDNS0TCPKEEPALIVE:
						rt.Stats.Count("dns:queries:internal:tcp_keepalive")
						rec.KeepAlive = true
						rec.KeepAliveTTL = uint(o.(*dns.EDNS0_TCP_KEEPALIVE).Timeout) * 100
						break
					default:
						lgr.Debugf("Message has an OPT Option entry: %d\n", o.Option())
						rt.Stats.Count("dns:queries:internal:unknown_option")
						rec.ExtraEDNS0 += 1
						break
					}
				}
				break
			default:
				lgr.Debugf("Message has an extra entry of type %d\n", h.Rrtype)
				break
			}
		}

		skipdb := false

		writeSOA := func() {
			expires := uint32(uint32(tme/60)*60 + 60 - uint32(tme))
			soa := &dns.SOA{
				Hdr:     dns.RR_Header{Name: dns.Fqdn(d.HostName), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: expires},
				Ns:      dns.Fqdn(fmt.Sprintf("ns1.%s", d.HostName)),
				Mbox:    dns.Fqdn(fmt.Sprintf("hostmaster.%s", d.HostName)),
				Serial:  uint32(uint32(tme/60) * 60),
				Refresh: 900,
				Retry:   900,
				Expire:  1800,
				Minttl:  60,
			}
			m.Answer = append(m.Answer, soa)
			skipdb = true
		}
		writeNS := func() {
			cnt := 1
			for _, ipaddr := range d.NameServers {
				ns := &dns.NS{
					Hdr: dns.RR_Header{Name: queried, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 0},
					Ns:  dns.Fqdn(fmt.Sprintf("ns%d.%s", cnt, d.HostName)),
				}
				m.Answer = append(m.Answer, ns)
				a := &dns.A{
					Hdr: dns.RR_Header{Name: dns.Fqdn(fmt.Sprintf("ns%d.%s", cnt, d.HostName)), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
					A:   net.ParseIP(ipaddr),
				}
				m.Extra = append(m.Extra, a)
				cnt += 1
			}
			skipdb = true
		}
		writeA := func() {
			m.Answer = append(m.Answer, serverIp...)
			//m.Extra = append(m.Extra, t)
		}
		writeCAA := func() {
			makeCaa := func(tag, value string) *dns.CAA {
				return &dns.CAA{
					Hdr:   dns.RR_Header{Name: queried, Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 0},
					Tag:   tag,
					Value: value,
				}
			}

			if len(d.CAAIodef) > 0 {
				for _, iname := range d.CAAIodef {
					m.Answer = append(m.Answer, makeCaa("iodef", iname))
				}
			}
			if len(d.CAAIssue) > 0 {
				for _, iname := range d.CAAIssue {
					m.Answer = append(m.Answer, makeCaa("issue", iname))
				}
			} else {
				m.Answer = append(m.Answer, makeCaa("issue", ";"))
			}
			if len(d.CAAIWild) > 0 {
				for _, iname := range d.CAAIWild {
					m.Answer = append(m.Answer, makeCaa("issuewild", iname))
				}
			} else {
				m.Answer = append(m.Answer, makeCaa("issuewild", ";"))
			}
			skipdb = true
		}

		switch r.Question[0].Qtype {
		case dns.TypeANY:
			rt.Stats.Count("dns:queries:type:soa")
			writeSOA()
			writeNS()
			writeA()
			writeCAA()
			break
		case dns.TypeSOA:
			rt.Stats.Count("dns:queries:type:soa")
			writeSOA()
			break
		case dns.TypeNS:
			rt.Stats.Count("dns:queries:type:ns")
			writeNS()
			break
		case dns.TypeAAAA:
			rt.Stats.Count("dns:queries:internal:aaaa")
			writeA()
		case dns.TypeA:
			rt.Stats.Count("dns:queries:internal:a")
			writeA()
			break
		case dns.TypeCAA:
			rt.Stats.Count("dns:queries:internal:caa")
			writeCAA()
			break
		default:
			break
		}

		// Handle queries for the raw hostnme -- don't store these
		if queried == dns.Fqdn(d.HostName) {
			rt.Stats.Count("dns:queries:type:bare")
			skipdb = true
		}

		// Handle queries for the nameservers
		match, err := regexp.MatchString(fmt.Sprintf("^ns\\d.%s$", dns.Fqdn(d.HostName)), queried)
		if err == nil && match {
			nsnum, _ := strconv.Atoi(string(queried[2]))
			if nsnum < 1 || nsnum > len(d.NameServers) {
				lgr.Warnf("Invalid ns number from %s: %d\n", queried, nsnum)
				fail := new(dns.Msg)
				fail.SetReply(r)
				fail.SetRcode(r, dns.RcodeNameError)
				fail.MsgHdr.Authoritative = true
				fail.Compress = true
				w.WriteMsg(fail)
				return
			}
			nsnum = nsnum - 1
			nsIp := &dns.A{
				Hdr: dns.RR_Header{Name: queried, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(d.NameServers[nsnum]),
			}
			m.Answer = []dns.RR{nsIp}
			m.Extra = []dns.RR{}
			skipdb = true
		}

		// Write the DB record
		if !skipdb {
			query := []byte("query/" + queried)
			query = query[0 : len(query)-1]
			if err := rt.DBPut(common.AddSuffix(query, runtime.KEY_NAME), query); err != nil {
				lgr.Warnf("Failed to save query name: %s", err.Error())
			}
			if err := rt.DBPut(common.AddSuffix(query, runtime.KEY_HOSTNAME), []byte(d.HostName)); err != nil {
				lgr.Warnf("Failed to save host name: %s", err.Error())
			}

			rec.NodeLoc = nodeloc
			georesponse, err := geoquery.Response()
			if err == nil && (georesponse.ISP.ASNumber != 0 || georesponse.Location != "") {
				rec.RequestLoc = georesponse
			} else {
				rt.Stats.Count("dns:queries:error:georesponse_failed")
			}
			if subnetquery != nil {
				subnetgeoresponse, err := subnetquery.Response()
				if err == nil && (subnetgeoresponse.ISP.ASNumber != 0 || subnetgeoresponse.Location != "") {
					rec.Subnet.SubnetLoc = subnetgeoresponse
				} else {
					rt.Stats.Count("dns:queries:error:subnetgeoresponse_failed")
				}
			}

			recarr, _ := json.Marshal(rec)
			if err := rt.DBPut(common.AddSuffix(query, runtime.KEY_DATA), recarr); err != nil {
				lgr.Warnf("Failed to save query time: %s", err.Error())
			}

			// Write the DB index for cleanup
			key := append([]byte("queries/"), []byte(strconv.FormatInt(tme, 10))...)
			key = append(key, []byte("/")...)
			uuid, _ := gorand.UUIDv4()
			key = append(key, []byte(uuid[:])...)
			if err := rt.DBPut(key, query); err != nil {
				lgr.Warnf("Failed to save query index: %s", err.Error())
			}
		}

		if err := w.WriteMsg(m); err != nil {
			lgr.Warnf("Failed to write message: %s", err.Error())
			fail := new(dns.Msg)
			fail.SetReply(r)
			fail.MsgHdr.Authoritative = true
			fail.Compress = true
			fail.SetRcode(r, dns.RcodeServerFailure)
			w.WriteMsg(fail)
		}
	}
}
