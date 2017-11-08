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
 * authoritative_dns.go: Authoritative DNS server responder implementation
 */

package responder

import (
	"crypto/tls"
	"fmt"
	"tenta-dns/log"
	"tenta-dns/runtime"
	"tenta-dns/zones"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func AuthoritativeDNSServer(cfg runtime.AuthorityConfig, rt *runtime.Runtime, v4 bool, net string, d *runtime.ServerDomain) {
	serveAuthoritativeDNS(cfg, rt, v4, net, d)
}

func serveAuthoritativeDNS(cfg runtime.AuthorityConfig, rt *runtime.Runtime, v4 bool, net string, d *runtime.ServerDomain) {
	var ip string
	if v4 {
		ip = d.IPv4
	} else {
		ip = fmt.Sprintf("[%s]", d.IPv6)
	}
	var port int
	if net == "tcp" {
		if d.DnsTcpPort <= runtime.PORT_UNSET {
			panic("Unable to start a TCP snitch without a valid TCP port")
		}
		port = d.DnsTcpPort
	} else if net == "udp" {
		if d.DnsUdpPort <= runtime.PORT_UNSET {
			panic("Unable to start a UDP snitch without a valid TCP port")
		}
		port = d.DnsUdpPort
	} else if net == "tls" {
		if d.DnsTlsPort <= runtime.PORT_UNSET {
			panic("Unable to start a TLS snitch without a valid TLS port")
		}
		port = d.DnsTlsPort
	} else {
		log.GetLogger("dnsauthority").Warnf("Unknown DNS net type %s", net)
		return
	}
	addr := fmt.Sprintf("%s:%d", ip, port)
	lg := log.GetLogger("dnsauthority").WithField("host_name", d.HostName).WithField("address", ip).WithField("port", port).WithField("proto", net)
	notifyStarted := func() {
		lg.Infof("Started %s dns on %s", net, addr)
	}
	lg.Debugf("Preparing %s dns on %s", net, addr)

	pchan := make(chan interface{}, 1)
	srv := &dns.Server{Addr: addr, Net: net, NotifyStartedFunc: notifyStarted, Handler: dns.HandlerFunc(dnsRecoverWrap(handleAuthoritative(rt, *cfg.Zones, lg), pchan))}

	defer rt.OnFinishedOrPanic(func() {
		srv.Shutdown()
		lg.Infof("Stopped %s dns on %s", net, addr)
	}, pchan)

	if net == "tls" {
		go func() {
			cert, err := tls.LoadX509KeyPair(d.CertFile, d.KeyFile)
			if err != nil {
				lg.Warnf("Failed to setup %s dns server on %s for %s: %s", net, addr, d.HostName, err.Error())
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
				lg.Warnf("Failed to setup %s dns server on %s for %s: %s", net, addr, d.HostName, err.Error())
			}
		}()
	} else {
		go func() {
			if err := srv.ListenAndServe(); err != nil {
				lg.Warnf("Problem while serving DNS: %s", err.Error())
			}
		}()
	}
}

func handleAuthoritative(rt *runtime.Runtime, z zones.ZoneSet, lg *logrus.Entry) dnsHandler {
	return func(w dns.ResponseWriter, r *dns.Msg) {

		// Set up the response object
		m := new(dns.Msg)
		m.SetReply(r)
		m.MsgHdr.Authoritative = true
		m.MsgHdr.RecursionAvailable = false

		rt.Stats.Count("dns:queries:all")
		rt.Stats.Count("dns:queries:authoritative")
		rt.Stats.Tick("dns", "queries:all")
		rt.Stats.Tick("dns", "queries:authoritative")

		if len(r.Question) < 1 {
			lg.Warnf("No question set")
			rt.Stats.Count("dns:queries:error:no_question")
			m.SetRcode(r, dns.RcodeRefused)
			w.WriteMsg(m)
			return
		}

		q := r.Question[0]

		if q.Qclass != dns.ClassINET {
			lg.Warnf("Got a non INET class type: %s", dns.ClassToString[q.Qclass])
			m.SetRcode(r, dns.RcodeRefused)
			w.WriteMsg(m)
			return
		}

		switch q.Qtype {
		case dns.TypeA:
			fallthrough
		case dns.TypeAAAA:
			fallthrough
		case dns.TypeMX:
			fallthrough
		case dns.TypeTXT:
			if !checkNameAndQtype(q, z, m, r, w, lg) {
				return
			}
			addAnswers(q.Name, q.Qtype, z, m, lg)
			break
		case dns.TypeANY:
			if !checkName(q, z, m, r, w, lg) {
				return
			}
			for _, t := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeTXT, dns.TypeNS} {
				if _, ok := z[q.Name][t]; ok {
					addAnswers(q.Name, t, z, m, lg)
				}
			}
			break
		default:
			lg.Debugf("Unknoown QType %s", dns.TypeToString[q.Qtype])
			m.SetRcode(r, dns.RcodeRefused)
			w.WriteMsg(m)
			return
		}

		m.SetRcode(r, dns.RcodeSuccess)
		w.WriteMsg(m)
	}
}

func addAnswers(name string, t uint16, z zones.ZoneSet, m *dns.Msg, lg *logrus.Entry) {
	for _, item := range z[name][t] {
		switch item.Kind {
		case zones.ZoneEntryTypeRR:
			m.Answer = append(m.Answer, *item.RR)
		default:
			lg.Debugf("Skipping unhandled zone entry type")
		}
	}
}

func checkName(q dns.Question, z zones.ZoneSet, m *dns.Msg, r *dns.Msg, w dns.ResponseWriter, lg *logrus.Entry) bool {
	if _, ok := z[q.Name]; !ok {
		lg.Debugf("Name %s not found", q.Name)
		m.SetRcode(r, dns.RcodeNameError)
		w.WriteMsg(m)
		return false
	}
	return true
}
func checkNameAndQtype(q dns.Question, z zones.ZoneSet, m *dns.Msg, r *dns.Msg, w dns.ResponseWriter, lg *logrus.Entry) bool {
	if !checkName(q, z, m, r, w, lg) {
		return false
	}
	if _, ok := z[q.Name][q.Qtype]; !ok {
		lg.Debugf("No entries of type %s found for %s", dns.TypeToString[q.Qtype], q.Name)
		m.SetRcode(r, dns.RcodeNameError)
		w.WriteMsg(m)
		return false
	}
	return true
}
