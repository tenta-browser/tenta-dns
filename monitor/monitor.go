/*
** Monitor
** Basic operating principle:
** It can either read a config file, or ingest command line arguments (read flag definitions for more info)
** Firstly, it reads the configs of the running Tenta DNS instance, and parses the location of the module configs (recursor, nsnitch)
** Secondly, reads the module configs and parses all DNS Recursor IP addresses, and all Authoritative DNS addresses (and zone information it should serve)
** Thirdly, sets up TLS listener with the given parameters, and starts to listen for incoming requests
** Lastly, when a request comes in, it launches all preconfigured domains to be resolved by the recursor(s) within a predefined time interval
 */
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/tenta-browser/tenta-dns/log"
	"github.com/tenta-browser/tenta-dns/runtime"
)

const (
	CHECK_HISTORY_LENGTH = 5
	TESTING_PERIOD       = 30
)

var (
	config  = flag.String("config", "", "Path to the configuration file for monitoring service")
	dnsconf = flag.String("dnsconf", "", "Path to Tenta DNS main configuration file (Tenta DNS launch parameter)")
	exclude = flag.String("exclude", "", "Comma separated list of IPs to exclude from testing")
	ip      = flag.String("ip", "", "Local IP address to bind service")
	domain  = flag.String("domain", "", "TLS domain name to serve API from")
	cert    = flag.String("cert", "", "Path to TLS certificate file for domain")
	key     = flag.String("key", "", "Path to TLS key file for domain")
	target  = flag.String("target", "example.com,example.org", "Comma separated list of domains to resolve")
	timeout = flag.Int("timeout", 15, "Maximum duration the DNS server should finish a single query")
	systemd = flag.Bool("systemd", false, "Set only if daemon is run via systemd")
)

var version string

type monitorConfig struct {
	DnsConf, Ip, Domain, Cert, Key string
	Target, Exclude                []string
	Timeout                        int
	Systemd                        bool
}

type dnsInstance struct {
	ip, net, hostname string
	port              int
}

type monitorRuntime struct {
	c *monitorConfig
	d []*dnsInstance
	t *time.Ticker
	m *sync.Mutex
	r [20]bool
}

func checkExcludedIP(rt *monitorRuntime, ip string) bool {
	for _, eip := range rt.c.Exclude {
		if eip == ip {
			return true
		}
	}
	return false
}

func parseDNSConfig(rt *monitorRuntime, holder runtime.ConfigHolder) error {
	for _, r := range holder.Recursors {
		for _, d := range r.Domains {
			if checkExcludedIP(rt, d.IPv4) {
				continue
			}
			if d.DnsTcpPort != runtime.PORT_UNSET {
				rt.d = append(rt.d, &dnsInstance{d.IPv4, "tcp", d.HostName, d.DnsTcpPort})
			}
			if d.DnsUdpPort != runtime.PORT_UNSET {
				rt.d = append(rt.d, &dnsInstance{d.IPv4, "udp", d.HostName, d.DnsUdpPort})
			}
			if d.DnsTlsPort != runtime.PORT_UNSET {
				rt.d = append(rt.d, &dnsInstance{d.IPv4, "tcp-tls", d.HostName, d.DnsTlsPort})
			}
		}
	}
	return nil
}

func pingdomWrapper(rt *monitorRuntime) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var response string
		rt.m.Lock()
		defer rt.m.Unlock()

		for i := CHECK_HISTORY_LENGTH - 1; i >= 0; i-- {
			if rt.r[i] == false {
				response = fmt.Sprintf("<pingdom_http_custom_check>\n" +
					"    <status>FAIL</status>\n" +
					"    <response_time>1</response_time>\n" +
					"</pingdom_http_custom_check>")
				return
			}
		}
		response = fmt.Sprintf("<pingdom_http_custom_check>\n" +
			"    <status>OK</status>\n" +
			"    <response_time>1</response_time>\n" +
			"</pingdom_http_custom_check>")

		w.Header().Set("Content-Disposition", "attachment; filename=status.xml")
		w.Header().Set("Content-Type", "text/xml")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(response)))
		w.Write([]byte(response))

	}
}

func sitrepWrapper(rt *monitorRuntime) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rt.m.Lock()
		defer rt.m.Unlock()
		for i := CHECK_HISTORY_LENGTH - 1; i >= 0; i-- {
			if rt.r[i] == false {
				w.Write([]byte("FAIL"))
				return
			}
		}
		w.Write([]byte("OK"))
	}
}

func createDialer(ip, network string) *net.Dialer {
	switch network {
	case "udp":
		return &net.Dialer{LocalAddr: &net.UDPAddr{IP: net.ParseIP(ip)}}
		break
	case "tcp":
	case "tcp-tls":
		return &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip)}}
		break
	}
	return nil
}

func testDNS(rt *monitorRuntime, log *logrus.Entry) {
	allOK := true
	wg := &sync.WaitGroup{}
	for _, _d := range rt.d {
		wg.Add(1)
		d := _d
		go func() {
			//log.Infof("Launching resolve for %s/%s", d.ip, d.net)
			c := dns.Client{
				Net:            d.net,
				SingleInflight: true,
			}
			if di := createDialer(rt.c.Ip, d.net); d != nil {
				c.Dialer = di
			}
			if d.net == "tcp-tls" {
				c.TLSConfig = &tls.Config{
					MinVersion:               tls.VersionTLS12,
					ServerName:               d.hostname,
					CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
					PreferServerCipherSuites: false,
					CipherSuites: []uint16{
						tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
						tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
					},
				}
			}

			for _, testDomain := range rt.c.Target {
				m := new(dns.Msg)
				m.SetQuestion(dns.Fqdn(testDomain), dns.TypeA)
				m.SetEdns0(4096, true)
				r, rtt, e := c.Exchange(m, fmt.Sprintf("%s:%d", d.ip, d.port))

				if e != nil {
					log.Warnf("An error occured during DNS exchange. Setup: %s/%s [%s]. Cause [%s]", d.ip, d.net, testDomain, e.Error())
					continue
				}
				if r.Rcode != dns.RcodeSuccess {
					log.Warnf("DNS query %s/%s about %s returned non-success rcode [%s]. Failure notice sent.", d.ip, d.net, testDomain, dns.RcodeToString[r.Rcode])
					allOK = false
					break
				}
				if rtt > time.Duration(rt.c.Timeout)*time.Millisecond {
					log.Warnf("Querying %s/%s about %s exceeded rtt threshold [%v]. Retrying.", d.ip, d.net, testDomain, rtt)

					r, rtt, e = c.Exchange(m, fmt.Sprintf("%s:%d", d.ip, d.port))

					if e != nil {
						log.Warnf("An error occured during DNS exchange. Setup: %s/%s [%s]. Cause [%s]", d.ip, d.net, testDomain, e.Error())
						allOK = false
						break
					}
					if r.Rcode != dns.RcodeSuccess {
						log.Warnf("DNS query %s/%s about %s returned non-success rcode [%s]. Failure notice sent.", d.ip, d.net, testDomain, dns.RcodeToString[r.Rcode])
						allOK = false
						break
					}
					if rtt > time.Duration(rt.c.Timeout)*time.Millisecond {
						log.Warnf("Querying %s/%s about %s exceeded rtt threshold [%v]. Failure notice sent.", d.ip, d.net, testDomain, rtt)
						allOK = false
						break
					}
				}
			}
			wg.Done()
		}()
	}
	wg.Wait()

	if allOK {
		log.Infof("SUCCESS for this round")
	} else {
		log.Infof("FAILURE for this round")
	}

	rt.m.Lock()
	defer rt.m.Unlock()

	for i := 18; i >= 0; i-- {
		rt.r[i+1] = rt.r[i]
	}
	rt.r[0] = allOK

}

func usage() {
	fmt.Printf("Tenta DNS Monitorization - build %s\nOptions:", version)
	flag.PrintDefaults()
}

func main() {
	log.SetLogLevel(logrus.InfoLevel)
	lg := log.GetLogger("dnsmon")
	/// Step 1. Make sure either we have command-line arguments or a config file (command line args take precedence)
	flag.Usage = usage
	flag.Parse()

	rt := &monitorRuntime{m: &sync.Mutex{}}
	cfg := &monitorConfig{}

	for i := range rt.r {
		rt.r[i] = true
	}

	if config == nil {
		lg.Infof("Attempting to construct context from commandline arguments")
		if dnsconf == nil || ip == nil || domain == nil || cert == nil || key == nil {
			lg.Errorf("Service halted. Missing commandline arguments")
			os.Exit(1)
		}

		cfg = &monitorConfig{
			DnsConf: *dnsconf,
			Exclude: strings.Split(*exclude, ","),
			Ip:      *ip,
			Domain:  *domain,
			Cert:    *cert,
			Key:     *key,
			Target:  strings.Split(*target, ","),
			Timeout: *timeout,
			Systemd: *systemd,
		}
	} else {
		lg.Infof("Attempting to construct context from config file [%s]", *config)
		if _, err := toml.DecodeFile(*config, cfg); err != nil {
			lg.Errorf("Service halted. Configuration file error. [%s]", err.Error())
			os.Exit(1)
		}
	}
	rt.c = cfg
	tentaHolder := runtime.ParseConfig(cfg.DnsConf, false, false)
	if e := parseDNSConfig(rt, tentaHolder); e != nil {
		lg.Errorf("Cannot parse DNS configuration. [%s]", e.Error())
		os.Exit(1)
	}
	lg.Infof("Parsed Tenta DNS configurations")

	rt.t = time.NewTicker(TESTING_PERIOD * time.Second)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/checkup", sitrepWrapper(rt))
	mux.HandleFunc("/api/v1/pingdom", pingdomWrapper(rt))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	go func() {
		srv := &http.Server{
			Addr:    net.JoinHostPort(rt.c.Ip, "80"),
			Handler: mux,
		}
		if e := srv.ListenAndServe(); e != nil {
			lg.Errorf("HTTP listener error [%s]", e.Error())
		}
	}()

	go func() {
		tlscfg := &tls.Config{
			MinVersion:               tls.VersionTLS10,
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
				tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
		}
		srv := &http.Server{
			Addr:      net.JoinHostPort(rt.c.Ip, "443"),
			Handler:   mux,
			TLSConfig: tlscfg,
		}
		if e := srv.ListenAndServeTLS(rt.c.Cert, rt.c.Key); e != nil {
			lg.Errorf("HTTPS listener error [%s]", e.Error())
		}
	}()

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case rs := <-sig:
			lg.Infof("Received termination signal [%s]. Exiting.", rs)
			os.Exit(0)
			break
		case <-rt.t.C:
			lg.Debugf("Received test signal. Working.")
			testDNS(rt, lg)
			break
		}
	}
}
