package responder

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/tenta-browser/tenta-dns/common"
	"github.com/tenta-browser/tenta-dns/runtime"
)

const (
	RECURSIVE_DNS_UDP_SIZE      = 4096
	RECURSIVE_DNS_NETWORK_ERROR = -1
)

// ResolverRuntime -- central piece of a resolve; holds all the necessary data, incoming query, ancillary modules etc
type ResolverRuntime struct {
	c *runtime.DNSCacheHolder
	p *runtime.Pool
	f *runtime.Feedback
	s *runtime.Stats
	/// session specific vars
	provider     string         /// the type of service we provide (opennic/iana roots)
	original     *dns.Msg       /// the original request that came in (aggregated form of all the query flags and parameters)
	record       uint16         /// requested RR type (miek dns lib format)
	domain       string         /// the original requested domain
	zones        []string       /// tokens of the original domain
	prefNet      string         /// preferred network to use for upstream queries
	transactions []*transaction /// a log of all the transactions until an answer is formulated
}

type entity struct {
	ip, name, zone string
}

type transaction struct {
	e entity        /// the entity being questioned
	q string        /// the domain in question
	t uint16        /// the RR type in question
	c int           /// reply RCODE
	r time.Duration /// the rtt of the transaction
}

var (
	NetworkToPort = map[string]string{"udp": "53", "tcp": "53", "tcp-tls": "853"}
)

/// do a very simple DNS query, without any interpretation of the returned data
func doQuery(rrt *ResolverRuntime, targetServer entity, qname string, qtype uint16) (r *dns.Msg, e error) {
	c, p := setupClient(rrt, targetServer)
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype).SetEdns0(RECURSIVE_DNS_UDP_SIZE, true)
	m.Compress = true
	trans := &transaction{e: targetServer, q: qname, t: qtype}
	r, rtt, e := c.Exchange(m, net.JoinHostPort(targetServer.ip, p))
	if e != nil {
		trans.c = RECURSIVE_DNS_NETWORK_ERROR
		appendTransaction(rrt, trans)
		e = fmt.Errorf("transport error during DNS exchange [%s]", e.Error())
		return
	}
	trans.c = r.Rcode
	trans.r = rtt
	appendTransaction(rrt, trans)

	return
}

// Resolve -- takes a DNS question, and turns it into a DNS answer, be that a set of RRs or a failure
func Resolve(rrt *ResolverRuntime, incoming *dns.Msg) (outgoing *dns.Msg) {

	return
}

/*
** Helper functions -- temporarily placed here
 */

/// returns an array of domain bits organized from top to bottom (DNS direction) with previous tokens appended, in FQDN
/// form eg "foo.bar.example.com" becomes {"com.", "example.com.", "bar.example.com.", "foo.bar.example.com."}
func tokenizeDomain(in string) []string {
	in = strings.Trim(in, ".")
	temp := strings.Split(in, ".")
	out := []string{""}
	l := len(temp)
	for i := l - 1; i >= 0; i-- {
		out = append(out, strings.Join([]string{temp[i], out[l-1-i]}, "."))
	}
	return out[1:]
}

/// setupClient takes care of setting up the transport for the query.
/// Handles TLS capabilities retrieval/storage, udp/tcp preference (based on earlier rate limiting etc)
func setupClient(rrt *ResolverRuntime, server entity) (c *dns.Client, p string) {
	c = new(dns.Client)
	/// retrieve cache network preference of the server. first we check whether it supports tls, if not then tcp,
	/// if not, then default (probably udp)
	if tlsCap, ok := rrt.c.GetBool(rrt.provider, runtime.MapKey(runtime.KV_TLS_CAPABILITY, server.ip)); ok && tlsCap {
		c.Net = "tcp-tls"
		p = "853"
		c.TLSConfig = common.TLSConfigDNS()
		c.TLSConfig.ServerName = server.name
	} else if tcpPref, ok := rrt.c.GetBool(rrt.provider, runtime.MapKey(runtime.KV_TCP_PREFERENCE, server.ip)); ok && tcpPref {
		c.Net = "tcp"
		p = "53"
	} else {
		c.Net = rrt.prefNet
		p = NetworkToPort[rrt.prefNet]
	}

	if c.Net == "udp" {
		c.Dialer = rrt.p.RandomizeUDPDialer()
	} else {
		c.Dialer = rrt.p.RandomizeTCPDialer()
	}

	return
}

func appendTransaction(rrt *ResolverRuntime, t *transaction) {
	rrt.transactions = append(rrt.transactions, t)
}
