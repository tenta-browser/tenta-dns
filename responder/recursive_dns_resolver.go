package responder

import (
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/miekg/dns"
	"github.com/tenta-browser/tenta-dns/common"
	"github.com/tenta-browser/tenta-dns/runtime"
)

const (
	RECURSIVE_DNS_UDP_SIZE      = 4096
	RECURSIVE_DNS_NETWORK_ERROR = -1
)

const (
	PROVIDER_TENTA   = "iana"
	PROVIDER_OPENNIC = "opennic"
)

// ResolverRuntime -- central piece of a resolve; holds all the necessary data, incoming query, ancillary modules etc
type ResolverRuntime struct {
	c *runtime.DNSCacheHolder
	p *runtime.Pool
	f *runtime.Feedback
	s *runtime.Stats
	l *logrus.Entry
	/// session specific vars
	provider      string               /// the type of service we provide (opennic/iana roots)
	original      *dns.Msg             /// the original request that came in (aggregated form of all the query flags and parameters)
	record        uint16               /// requested RR type (miek dns lib format)
	domain        string               /// the original requested domain
	zones         []string             /// tokens of the original domain
	prefNet       string               /// preferred network to use for upstream queries
	transactions  []*transaction       /// a log of all the transactions until an answer is formulated
	targetServers map[string][]*entity /// a zone string to available nameservers map (the first level, "." is filled automatically)
}

/// this structure is about an entity, it's primary element is one IP
/// ergo, it's not a collection of all the ips for an entity
type entity struct {
	ip, name, zone string
}

type transaction struct {
	e *entity       /// the entity being questioned
	q string        /// the domain in question
	t uint16        /// the RR type in question
	c int           /// reply RCODE
	r time.Duration /// the rtt of the transaction
}

type parallelQueryResult struct {
	r *dns.Msg
	e error
}

var (
	NetworkToPort = map[string]string{"udp": "53", "tcp": "53", "tcp-tls": "853"}
)

/// root server declarations.
/// TODO: move these off to a config directive?
var (
	opennicRootServers = []*entity{
		newEntity("ns2.opennic.glue", "161.97.219.84", "."), newEntity("ns3.opennic.glue", "104.168.144.17", "."), newEntity("ns4.opennic.glue", "163.172.168.171", "."),
		newEntity("ns5.opennic.glue", "94.103.153.176", "."), newEntity("ns6.opennic.glue", "207.192.71.13", "."), newEntity("ns8.opennic.glue", "178.63.116.152", "."),
		newEntity("ns9.opennic.glue", "174.138.48.29", "."), newEntity("ns10.opennic.glue", "188.226.146.136", "."), newEntity("ns11.opennic.glue", "45.55.97.204", "."),
		newEntity("ns12.opennic.glue", "79.124.7.81", ".")}
	ianaRootServers = []*entity{
		newEntity("a.root-servers.net", "198.41.0.4", "."), newEntity("b.root-servers.net", "199.9.14.201", "."), newEntity("c.root-servers.net", "192.33.4.12", "."),
		newEntity("d.root-servers.net", "199.7.91.13", "."), newEntity("e.root-servers.net", "192.203.230.10", "."), newEntity("f.root-servers.net", "192.5.5.241", "."),
		newEntity("g.root-servers.net", "192.112.36.4", "."), newEntity("h.root-servers.net", "198.97.190.53", "."), newEntity("i.root-servers.net", "192.36.148.17", "."),
		newEntity("j.root-servers.net", "192.58.128.30", "."), newEntity("k.root-servers.net", "193.0.14.129", "."), newEntity("l.root-servers.net", "199.7.83.42", "."),
		newEntity("m.root-servers.net", "202.12.27.33", ".")}
	mappedRootServers = map[string][]*entity{PROVIDER_OPENNIC: opennicRootServers, PROVIDER_TENTA: ianaRootServers}
)

/// do a very simple DNS query, without any interpretation of the returned data
func doQuery(rrt *ResolverRuntime, targetServer *entity, qname string, qtype uint16) (r *dns.Msg, e error) {
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

/// launch multiple resolutions concurently.
/// parallelism lies in resolving all the questions _at the same time_
/// used in case of cache entry expiration of A records
func resolveParallelHarness(rrt *ResolverRuntime, target []*dns.NS) (result []*entity) {
	input := []*dns.Msg{}
	for _, ns := range target {
		input = append(input, newDNSQuery(ns.Ns, dns.TypeA))
	}
	achan := make(chan *dns.Msg, len(input))
	for _, q := range input {
		go func(question *dns.Msg) {
			answer := Resolve(&runtime.Runtime{Cache: rrt.c, IPPool: rrt.p, SlackWH: rrt.f, Stats: rrt.s},
				rrt.l, rrt.provider, question)
			answer.Question = question.Question
			achan <- answer
		}(q)
	}
	counter := 0
	for {
		if counter == len(input) {
			break
		}
		select {
		case t := <-achan:
			counter++
			for _, ans := range t.Answer {
				if a, ok := ans.(*dns.A); ok {
					result = append(result, newEntity(a.Hdr.Name, a.A.String(), ""))
				}
			}
		case <-time.After(100 * time.Millisecond):
			break
		}
	}
	return
}

/// launches a DNS query to all available and able servers, uses the first valid answer
/// parallelism lies in the ask all the NSes _at the same time_
func doQueryParallelHarness(rrt *ResolverRuntime, targetServers []*entity, qname string, qtype uint16) (*dns.Msg, error) {

	res := make(chan *parallelQueryResult, len(targetServers))
	for _, srv := range targetServers {
		go func(thisEntity *entity) {
			r, e := doQuery(rrt, thisEntity, qname, qtype)
			res <- &parallelQueryResult{r, e}
		}(srv)
	}
	var r *parallelQueryResult
	for r = range res {
		if r.e != nil {
			rrt.l.Errorf("Error in parallel doQuery [%s]", r.e.Error())
			continue
		}
		if r.r.Rcode == dns.RcodeSuccess {
			return r.r, r.e
		}
	}
	/// returns last erroneous result, for future reference
	return r.r, r.e

}

// Resolve -- takes a DNS question, and turns it into a DNS answer, be that a set of RRs or a failure.
// *outgoing* is only partially filled, RCODE and RRs are set, the rest is up to the caller.
// Expects a *runtime.Runtime, and a *dns.Msg as input, it then sets up a ResolverRuntime for internal use
// Its operating principle is to do one time setup and checks, and then launch the recursive parts to do their work
func Resolve(rt *runtime.Runtime, lg *logrus.Entry, provider string, incoming *dns.Msg) (outgoing *dns.Msg) {
	lg.Infof("Constructing resolver context, for [%s]/[%s]/[%s]", provider, incoming.Question[0].Name, dns.TypeToString[incoming.Question[0].Qtype])
	rrt := &ResolverRuntime{
		c: rt.Cache, p: rt.IPPool, f: rt.SlackWH, s: rt.Stats, l: lg, original: incoming, provider: provider,
	}
	/// session setup
	rrt.domain = dns.Fqdn(rrt.original.Question[0].Name)
	rrt.zones = tokenizeDomain(rrt.domain)
	rrt.targetServers = newTargetServerMap(rrt)
	/// TODO: figure out a better way to handle preferred network setup
	rrt.prefNet = "udp"
	rrt.record = rrt.original.Question[0].Qtype
	rrt.transactions = []*transaction{}

	/// first order of business, check the cache
	/// and in order to do so, we do the following
	/// check QTYPE for full domain in cache -- if we get a hit, then return it, if not:
	/// recursively track back for NS records -- when we get a hit we continue the loop from there
	rrt.l.Infof("Checking cache for response")
	entryPoint := 0
	if targetRR := rrt.c.Retrieve(rrt.provider, rrt.domain, rrt.record); targetRR != nil {
		rrt.l.Infof("Response can be formulated from cache.")
		return setupResult(rrt, dns.RcodeSuccess, targetRR, nil, nil)
	} else {
		rrt.l.Infof("Cache holds no exact matches. Retrieving intermediary NS records.")
		/// we invert the zones array, most specific first, least specific last
		zonesAsc := invertStringArray(rrt.zones)
		for i, z := range zonesAsc {
			if targetNS := ToNS(rrt.c.Retrieve(rrt.provider, z, dns.TypeNS)); targetNS != nil {
				/// now it gets a bit trickier, we have to get A records for these NSes,
				/// which may or may not be in cache
				/// so to optimize work, let's do it like this, if the NS is in the same zone hierarchy as the target,
				/// we track one step back in the caching loop, otherwise we launch a separate resolve for the NS record(s)
				rrt.l.Infof("We have NS records for zone [%s]. Checking A records.", z)
				/// so for each NS record we check the cache
				nsEntities := []*entity{}
				for _, ns := range targetNS {
					if targetA := ToA(rrt.c.Retrieve(rrt.provider, ns.Ns, dns.TypeA)); targetA != nil {
						for _, a := range targetA {
							nsEntities = append(nsEntities, &entity{name: ns.Ns, ip: a.A.String(), zone: z})
						}
					}
				}

				/// we have at least _some_ data we can use, so we break out
				if len(nsEntities) != 0 {
					rrt.l.Infof("We have matching A records. Query loop diminished. Resuming from [%s] down to [%s]", z, rrt.domain)
					entryPoint = len(rrt.zones) - 1 - i
					rrt.targetServers[z] = nsEntities
					break
				} else {
					/// here we can evaluate if we are better off doing a separate resolve of the cached ns, or step further up
					/// and to put that into practice, we compare the NS record(s) to the current zone (z) token bits
					/// if we have match greater or equal than the TLD+1 part, we step back, otherwise, we do a parallel resolve for all the NS records
					rrt.l.Infof("No matching A records found for any NS records. Evaluating a separate resolve feasability.")
					/// easiest way is to calculate number of dots in the common suffix of the two expressions
					for _, ns := range targetNS {
						numDots := 0
						for i := 0; i < int(math.Min(float64(len(z)), float64(len(ns.Ns)))); i++ {
							if z[len(z)-1-i] != ns.Ns[len(ns.Ns)-1-i] {
								break
							}
							if z[len(z)-1-i] == "."[0] {
								numDots++
							}
						}
						/// TLD+1 match would mean at least 4 dots match, or if target domain is shorter, then numDots should equal the number of theoretical zones in the domain
						if numDots > 3 || numDots == len(rrt.zones) {
							// we let the next iteration of the loop to...
							continue
						}
					}
					rrt.l.Infof("We havent found a NS in the same zone hierarchy as the target [%s] -- [%v]", z, targetNS)
					rrt.l.Infof("Executing a parallel resolve for NS records")
					entryPoint = len(rrt.zones) - 1 - i
					rrt.targetServers[z] = resolveParallelHarness(rrt, targetNS)
					break
				}
			}
		}
	}

	return
}

func doQueryRecursively(rrt *ResolverRuntime, level int) *dns.Msg {
	return nil
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

func setupResult(rrt *ResolverRuntime, rcode int, answer, authority, additional []dns.RR) *dns.Msg {
	return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: rcode}, Answer: answer, Ns: authority, Extra: additional}
}

/// setupClient takes care of setting up the transport for the query.
/// Handles TLS capabilities retrieval/storage, udp/tcp preference (based on earlier rate limiting etc)
func setupClient(rrt *ResolverRuntime, server *entity) (c *dns.Client, p string) {
	c = new(dns.Client)
	/// retrieve cache network preference of the server. first we check whether it supports tls, if not then tcp,
	/// if not, then default (_probably_ udp)
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
	/// request random IP from the pool
	if c.Net == "udp" {
		c.Dialer = rrt.p.RandomizeUDPDialer()
	} else {
		c.Dialer = rrt.p.RandomizeTCPDialer()
	}

	return
}

/// appends a transaction to the list
func appendTransaction(rrt *ResolverRuntime, t *transaction) {
	rrt.transactions = append(rrt.transactions, t)
}

func invertStringArray(in []string) (out []string) {
	for i := len(in) - 1; i >= 0; i-- {
		out = append(out, in[i])
	}
	return
}

func newTargetServerMap(rrt *ResolverRuntime) map[string][]*entity {
	ret := make(map[string][]*entity)
	ret["."] = mappedRootServers[rrt.provider]
	return ret
}

func newEntity(name, ip, zone string) *entity {
	return &entity{name: name, ip: ip, zone: zone}
}

/// shorthand for imitating incoming queries
func newDNSQuery(qname string, qtype uint16) *dns.Msg {
	return new(dns.Msg).SetQuestion(qname, qtype).SetEdns0(RECURSIVE_DNS_UDP_SIZE, true)
}

/// DNSSEC shorthands
/// returns true if resolver is asked to validate upstream DNSSEC responses
func doWeValidateDNSSEC(rrt *ResolverRuntime) bool {
	if rrt.original.CheckingDisabled == true {
		return false
	}
	return true
}

func hasDOFlag(m *dns.Msg) bool {
	opts := m.IsEdns0()
	if opts == nil {
		return false
	} else {
		return opts.Do()
	}
}

/// returns true if resolver is asked to include DNSSEC records in the response to the client
func doWeReturnDNSSEC(rrt *ResolverRuntime) bool {
	return hasDOFlag(rrt.original)
}

/// returns true if we have to set the AD flag according to the current situation regarding DNSSEC validations
/// the client's interest is usually shown when the incoming query has a set AD bit
func doWeTouchADFlag(rrt *ResolverRuntime) bool {
	return rrt.original.AuthenticatedData
}
