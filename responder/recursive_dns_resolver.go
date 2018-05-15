package responder

import (
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/jinzhu/copier"
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

const (
	RR_NAVIGATOR_NEXT = iota
	RR_NAVIGATOR_BREAK
	RR_NAVIGATOR_BREAK_AND_PROPAGATE
)

const (
	RESPONSE_UNKNOWN = iota
	RESPONSE_ANSWER
	RESPONSE_ANSWER_REDIRECT
	RESPONSE_DELEGATION
	RESPONSE_DELEGATION_GLUE
	RESPONSE_NXDOMAIN
	RESPONSE_EMPTY_NON_TERMINAL
	RESPONSE_NODATA
	RESPONSE_REDIRECT
	RESPONSE_REDIRECT_GLUE
)

var (
	RESPONSE_EMPTY = [][]dns.RR{nil, nil, nil}
	EXTRA_EMPTY    = &runtime.ItemCacheExtra{false, false, false, nil}
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
	currentZone   string               /// the zone we are currently quering in (it's the parent zone of the current query subject (may be more than one label difference between the two))
	prefNet       string               /// preferred network to use for upstream queries
	transactions  []*transaction       /// a log of all the transactions until an answer is formulated
	targetServers map[string][]*entity /// a zone string to available nameservers map (the first level, "." is filled automatically)
	redirections  []*dns.CNAME         /// a collection of all the redirections (that ultimately will make it into the answer section) until an answer can be formulated
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

type resolverResponse struct {
	qname    string
	qtype    uint16
	response *dns.Msg
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
	rrt.l.Infof("Entering doQuery() with [%s][%s] -- [%v]", qname, dns.TypeToString[qtype], targetServer)
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
	rrt.l.Infof("Entering resolveParallelHarness() with [%v]", target)
	input := []*dns.Msg{}
	for _, ns := range target {
		input = append(input, newDNSQuery(ns.Ns, dns.TypeA))
	}
	achan := make(chan *dns.Msg, len(input))
	for _, q := range input {
		go func(question *dns.Msg) {
			answer, _ := Resolve(NewResolverRuntime(&runtime.Runtime{Cache: rrt.c, IPPool: rrt.p, SlackWH: rrt.f, Stats: rrt.s}, rrt.l, rrt.provider, question))
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
	rrt.l.Infof("Entering doQueryParallelHarness() with [%s][%s] -- [%v]", qname, dns.TypeToString[qtype], targetServers)
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

func NewResolverRuntime(rt *runtime.Runtime, lg *logrus.Entry, provider string, incoming *dns.Msg) (rrt *ResolverRuntime) {
	lg.Infof("Constructing resolver context, for [%s]/[%s]/[%s]", provider, incoming.Question[0].Name, dns.TypeToString[incoming.Question[0].Qtype])
	rrt = &ResolverRuntime{
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
	return
}

// Resolve -- takes a DNS question, and turns it into a DNS answer, be that a set of RRs or a failure.
// *outgoing* is only partially filled, RCODE and RRs are set, the rest is up to the caller.
// Expects a fully setup *ResolverRuntime as input (see NewResolverRuntime())
func Resolve(rrt *ResolverRuntime) (outgoing *dns.Msg, e error) {
	rrt.l.Infof("Starting a fresh resolve for [%s][%s]", rrt.domain, dns.TypeToString[rrt.record])
	/// first order of business, check the cache
	/// and in order to do so, we do the following
	/// check QTYPE for full domain in cache -- if we get a hit, then return it, if not:
	/// recursively track back for NS records -- when we get a hit we continue the loop from there
	rrt.l.Infof("Checking cache for response")
	entryPoint := 0
	targetRR, extra := rrt.c.Retrieve(rrt.provider, rrt.domain, rrt.record, doWeReturnDNSSEC(rrt))

	if r, e, p := handleExtras(rrt, targetRR, extra); p {
		return r, e
	}

	if isValidCacheResponse(targetRR, doWeReturnDNSSEC(rrt)) {
		rrt.l.Infof("Response can be formulated from cache.")
		return setupResult(rrt, dns.RcodeSuccess, targetRR), nil
	} else {
		rrt.l.Infof("Cache holds no exact matches. Retrieving intermediary NS records.")
		/// we invert the zones array, most specific first, least specific last
		zonesAsc := invertStringArray(rrt.zones)
		for i, z := range zonesAsc {
			/// we don't need dnssec
			cacheResp, extra := rrt.c.Retrieve(rrt.provider, z, dns.TypeNS, false)
			if r, e, p := handleExtras(rrt, cacheResp, extra); p {
				return r, e
			}
			if targetNS := ToNS(cacheResp); targetNS != nil {
				/// now it gets a bit trickier, we have to get A records for these NSes,
				/// which may or may not be in cache
				/// so to optimize work, let's do it like this, if the NS is in the same zone hierarchy as the target,
				/// we track one step back in the caching loop, otherwise we launch a separate resolve for the NS record(s)
				rrt.l.Infof("We have NS records for zone [%s]. Checking A records.", z)
				/// so for each NS record we check the cache
				nsEntities := []*entity{}
				for _, ns := range targetNS {
					cacheResp, extra := rrt.c.Retrieve(rrt.provider, ns.Ns, dns.TypeA, false)
					if r, e, p := handleExtras(rrt, cacheResp, extra); p {
						return r, e
					}
					if targetA := ToA(cacheResp); targetA != nil {
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
					rrt.currentZone = z
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
					rrt.currentZone = z
					break
				}
			}
		}
	}

	/// do the actual recursion
	return doQueryRecursively(rrt, entryPoint)
}

/// function for recursive invocation. handles one level of the query hierarchy, calls itself for next level
/// operating principle: previous level has set up a list of NSes to question, so it will ask the question specific
/// to its level, and analyze the response, set up the environment for the next invocation
func doQueryRecursively(rrt *ResolverRuntime, level int) (*dns.Msg, error) {
	currentToken := rrt.zones[level]
	isFinalQuestion := isBottomLevel(rrt, level)
	rrt.l.Infof("Entering doQueryRecursively() with [%s]/[%s], isFinal [%v]", currentToken, rrt.domain, isFinalQuestion)
	/// first of all, check the cache, and check if we're at the bottom level
	/// if we're at bottom, we ask the final qtype, if not, we ask NS
	qtype := dns.TypeNS
	if isFinalQuestion {
		qtype = rrt.record
	}
	cachedRR, extra := rrt.c.Retrieve(rrt.provider, currentToken, qtype, doWeReturnDNSSEC(rrt))
	if r, e, p := handleExtras(rrt, cachedRR, extra); p {
		return r, e
	}
	if cachedRR != nil {
		rrt.l.Infof("Found the solution in cache. Using it.")
		/// if we're at bottom level, aka final question, we can return this as result
		if isFinalQuestion {
			return setupResult(rrt, dns.RcodeSuccess, cachedRR), nil
			/// TODO: find a way to utilize target servers as authority section records
		} else { /// not last question, we use it to set up next level, and shortcut there
			rrt.targetServers[rrt.zones[level+1]] = fetchNSAsEntity(rrt, rrt.zones[level+1], false, false)
			return doQueryRecursively(rrt, level+1)
		}
	}
	/// at this point we know that we can't skip an rtt to the NSes
	res, err := doQueryParallelHarness(rrt, rrt.targetServers[currentToken], currentToken, qtype)
	/// propagate back (this means, that all NSes returned an error)
	if err != nil {
		rrt.l.Errorf("Error in recursive aspect. [%s]", err.Error())
		return nil, err
	}

	/// no fatal error means we can proceed to DNSSEC validation
	if isDNSSECResponse(res) {
		if e := validateDNSSEC(rrt, res, level); !e {
			/// validator returns error only on critical security issues only (which warrant an instant propagation of the error)
			return nil, fmt.Errorf("bogus DNSSEC response")
		}
	}

	/// TODO: add record security check
	cacheResponse(rrt, res)
	answerType := evaluateResponse(rrt, currentToken, qtype, level, res)

	switch answerType {
	case RESPONSE_ANSWER:
		rrt.l.Infof("Got an answer. Returning it.")
		return res, nil
	case RESPONSE_DELEGATION:
		rrt.l.Infof("Got a naked delegation.")
		nsRR := []*dns.NS{}
		rrNavigator(res, func(rr dns.RR) int {
			if rr.Header().Rrtype == dns.TypeNS {
				nsRR = append(nsRR, rr.(*dns.NS))
			}
			return RR_NAVIGATOR_NEXT
		})
		rrt.targetServers[rrt.zones[level+1]] = resolveParallelHarness(rrt, nsRR)
		rrt.l.Infof("Going deeper into the rabbithole.")
		return doQueryRecursively(rrt, level+1)
	case RESPONSE_DELEGATION_GLUE:
		rrt.l.Infof("Got delegation /w glue records.")
		servers := []*entity{}
		rrNavigator(res.Ns, func(rr dns.RR) int {
			if rr.Header().Rrtype == dns.TypeNS && rr.Header().Name == currentToken {
				rrNavigator(res.Extra, func(rrIn dns.RR) int {
					if rrIn.Header().Rrtype == dns.TypeA && rrIn.Header().Name == rr.(*dns.NS).Ns {
						servers = append(servers, newEntity(rrIn.Header().Name, rrIn.(*dns.A).A.String(), currentToken))
					}
					return RR_NAVIGATOR_NEXT
				})
			}
			return RR_NAVIGATOR_NEXT
		})
		rrt.targetServers[rrt.zones[level+1]] = servers
		rrt.l.Infof("Going deeper into the rabbithole.")
		return doQueryRecursively(rrt, level+1)
	case RESPONSE_EMPTY_NON_TERMINAL:
		rrt.l.Infof("Got an NXDOMAIN for an empty-non-terminal. Retrying same servers for one more label.")
		rrt.targetServers[rrt.zones[level+1]] = rrt.targetServers[currentToken]
		return doQueryRecursively(rrt, level+1)
	case RESPONSE_NODATA:
		rrt.l.Infof("Got a NODATA. Caching and returning it.")
		rrt.c.Insert(rrt.provider, currentToken, dns.TypeToRR[qtype](), &runtime.ItemCacheExtra{Nodata: true})
		if doWeReturnDNSSEC(rrt) && isDNSSECResponse(res) {
			return res, nil
		} else {
			retSoa := fetchRRByType(res, dns.TypeSOA)
			return setupResult(rrt, dns.RcodeSuccess, retSoa[0]), nil
		}
	case RESPONSE_NXDOMAIN:
		rrt.l.Infof("Got an NXDOMAIN. Caching and returning it.")
		rrt.c.Insert(rrt.provider, currentToken, dns.TypeToRR[qtype](), &runtime.ItemCacheExtra{Nxdomain: true})
		if doWeReturnDNSSEC(rrt) && isDNSSECResponse(res) {
			return res, nil
		} else {
			retSoa := fetchRRByType(res, dns.TypeSOA)
			return setupResult(rrt, dns.RcodeNameError, retSoa[0]), nil
		}
	case RESPONSE_REDIRECT, RESPONSE_REDIRECT_GLUE:
		rrt.l.Infof("Got a naked CNAME. Following and resolving it.")
		cnames := []*dns.CNAME{}
		rrNavigator(res, func(rr dns.RR) int {
			if rr.Header().Rrtype == dns.TypeCNAME {
				cnames = append(cnames, rr.(*dns.CNAME))
			}
			return RR_NAVIGATOR_NEXT
		})
		lastOwner := redirectNavigator(currentToken, cnames)

		if redirectResult, err := Resolve(NewResolverRuntime(&runtime.Runtime{Cache: rrt.c, IPPool: rrt.p, SlackWH: rrt.f, Stats: rrt.s},
			rrt.l, rrt.provider, newDNSQuery(lastOwner, qtype))); err != nil {
			rrt.l.Errorf("Redirect resolution failed with [%s]", err.Error())
			return nil, err
		} else {
			rrt.l.Infof("Redirect resolved successfully. Returning with added references.")
			redirectResult.Answer = append(redirectResult.Answer, fetchRRByType(res, dns.TypeCNAME)...)
			return redirectResult, nil
		}
	case RESPONSE_UNKNOWN:
		rrt.l.Fatalf("Cannot determine the type of answer [%s]", res.String())
		return nil, fmt.Errorf("unknown response type")
	}

	return nil, nil
}

/*
** Helper functions -- temporarily placed here
 */
// func negativeCacheMapKey(prefix, qname string, qtype )

/// convenience func to store a response or all records from it
func cacheResponse(rrt *ResolverRuntime, in *dns.Msg) {
	qname := in.Question[0].Name

	if isDNSSECResponse(in) {
		rrt.c.InsertResponse(rrt.provider, qname, in)
	}

	rrNavigator(in, func(rr dns.RR) int {
		rrt.c.Insert(rrt.provider, qname, rr, EXTRA_EMPTY)
		return RR_NAVIGATOR_NEXT
	})

}

func evaluateResponse(rrt *ResolverRuntime, qname string, qtype uint16, level int, r *dns.Msg) (rtype int) {

	if r.Rcode == dns.RcodeSuccess {
		/// it can be answer, delegation, delegation /w glue, redirect, nodata
		hasCNAME := false
		hasSOA := false
		hasNS := false

		rrNavigator(r.Ns, func(rr dns.RR) int {
			if rr.Header().Rrtype == dns.TypeSOA {
				hasSOA = true
			}
			if rr.Header().Rrtype == dns.TypeNS {
				hasNS = true
			}
			return RR_NAVIGATOR_NEXT
		})

		/// check NODATA
		if r.Answer == nil && hasSOA {
			return RESPONSE_NODATA
		}

		/// check if it is a straight-forward answer
		for _, rr := range r.Answer {
			if rr.Header().Rrtype == qtype && rr.Header().Name == qname {
				return RESPONSE_ANSWER
			} else if rr.Header().Rrtype == dns.TypeCNAME {
				hasCNAME = true
			}
		}

		/// check whether response contains multiple CNAMES and an answer too
		if hasCNAME {
			redirects := []*dns.CNAME{}
			rrNavigator(r, func(rr dns.RR) int {
				if rr.Header().Rrtype == dns.TypeCNAME {
					redirects = append(redirects, rr.(*dns.CNAME))
				}
				return RR_NAVIGATOR_NEXT
			})
			lastOwner := redirectNavigator(qname, redirects)

			if rrNavigator(r.Answer, func(rr dns.RR) int {
				if rr.Header().Rrtype == qtype && rr.Header().Name == lastOwner {
					return RR_NAVIGATOR_BREAK_AND_PROPAGATE
				}
				return RR_NAVIGATOR_NEXT
			}) == RR_NAVIGATOR_BREAK_AND_PROPAGATE {
				return RESPONSE_ANSWER_REDIRECT
			}

		}

		/// check for CNAMES (with or without additional info)
		if hasCNAME {
			if !hasNS {
				return RESPONSE_REDIRECT
			}
			return RESPONSE_REDIRECT_GLUE
		}

		/// check delegation
		if hasNS {
			if r.Extra == nil {
				return RESPONSE_DELEGATION
			}
			return RESPONSE_DELEGATION_GLUE
		}

	} else if r.Rcode == dns.RcodeNameError {
		/// the various cases of NXDOMAIN
		if isBottomLevel(rrt, level) {
			return RESPONSE_EMPTY_NON_TERMINAL
		}
		return RESPONSE_NXDOMAIN
	}

	return RESPONSE_UNKNOWN
}

/// function that starts off at an owner name, and navigates all linked CNAME records given to reach the last CNAMEs reference field
func redirectNavigator(start string, redirects []*dns.CNAME) string {
	for {
		foundInCycle := false
		for _, cn := range redirects {
			if cn.Header().Name == start {
				start = cn.Target
				foundInCycle = true
			}
		}
		if !foundInCycle {
			break
		}
	}
	return start
}

/// function to validate DNSSEC records
func validateDNSSEC(rrt *ResolverRuntime, in *dns.Msg, level int) bool {
	rrt.l.Infof("Entering validateDNSSEC() with [%v]", in)
	if dkrr := fetchRRByType(in, dns.TypeDNSKEY); dkrr != nil {
		dks := []*dns.DNSKEY{}
		rrNavigator(dkrr, func(rr dns.RR) int {
			if rr.Header().Rrtype == dns.TypeDNSKEY {
				dks = append(dks, rr.(*dns.DNSKEY))
			}
			return RR_NAVIGATOR_NEXT
		})
		if !validateDNSKEY(rrt, level, dks) {
			return false
		}
	}
	if !validateNSEC(rrt, in) {
		return false
	}
	if !validateNSEC3(rrt, in) {
		return false
	}
	if !validateRRSIG(rrt, level, in) {
		return false
	}

	return true
}

/// validates an array of DNSKEYS (needs curent level of reursive hierarchy)
/// operating principle:
/// get (via cache or network) DS records from parent zone
/// sequentially try to validate every DNSKEY with one of the retrieved DSes
/// fail if a DNSKEY can't be validated
func validateDNSKEY(rrt *ResolverRuntime, level int, dks []*dns.DNSKEY) bool {
	rrt.l.Infof("Entering validateDNSKEY() with [%v]", dks)
	dss, err := fetchFromCacheOrNetwork(rrt, rrt.zones[level], dns.TypeDS)
	if err != nil {
		/// if we cannot produce DS records matching our DNSKEY, fail without question
		return false
	}

	failed := false
	rrNavigator(dss, func(dsRR dns.RR) int {
		lFailed := false
		for _, dnskey := range dks {
			ds := dsRR.(*dns.DS)

			td := dnskey.ToDS(ds.DigestType)
			if !(td != nil && equalsDS(td, ds)) {
				lFailed = true
				break
			}
		}
		if lFailed == true {
			failed = true
			return RR_NAVIGATOR_BREAK
		}
		return RR_NAVIGATOR_NEXT
	})
	if failed {
		return false
	}
	return true
}

/// validates RRSIG records
/// operating principle:
/// for every set (answer, authority, additional): sort all records into a map
/// --> for every RRSIG in set, try to validate the covered type array
func validateRRSIG(rrt *ResolverRuntime, level int, in *dns.Msg) bool {
	rrFilter := map[uint16][]dns.RR{}
	rrHolder := [][]dns.RR{in.Answer, in.Ns, in.Extra}
	dks := []*dns.DNSKEY{}
	dksRR, eRR := fetchFromCacheOrNetwork(rrt, rrt.zones[level], dns.TypeDNSKEY)
	if eRR != nil {
		rrt.l.Errorf("Cannot fetch cache/network DNSKEY for zone [%s]: [%s]", rrt.zones[level], eRR.Error())
		return false
	}
	/// gather DNSKEYs
	rrNavigator(dksRR, func(rr dns.RR) int {
		if rr.Header().Rrtype == dns.TypeDNSKEY {
			dks = append(dks, rr.(*dns.DNSKEY))
		}
		return RR_NAVIGATOR_NEXT
	})

	/// for every section, map the RRs and then try to validate them using the RRSIGs and DNSKEYS
	/// on error return false without hesitation
	for _, arr := range rrHolder {
		rrNavigator(arr, func(rr dns.RR) int {
			rrFilter[rr.Header().Rrtype] = append(rrFilter[rr.Header().Rrtype], rr)
			return RR_NAVIGATOR_NEXT
		})
		if rrNavigator(rrFilter[dns.TypeRRSIG], func(rrout dns.RR) int {
			if rrNavigator(dks, func(rrin dns.RR) int {
				if rrout.(*dns.RRSIG).Verify(rrin.(*dns.DNSKEY), rrFilter[rrout.(*dns.RRSIG).TypeCovered]) != nil {
					return RR_NAVIGATOR_BREAK_AND_PROPAGATE
				}
				return RR_NAVIGATOR_NEXT
			}) == RR_NAVIGATOR_BREAK_AND_PROPAGATE {
				return RR_NAVIGATOR_BREAK_AND_PROPAGATE
			}
			return RR_NAVIGATOR_NEXT
		}) == RR_NAVIGATOR_BREAK_AND_PROPAGATE {
			return false
		}
	}
	return true
}

func fetchRRByType(from *dns.Msg, tp uint16) (ret []dns.RR) {
	rrNavigator(from, func(rr dns.RR) int {
		if rr.Header().Rrtype == tp {
			ret = append(ret, rr)
		}
		return RR_NAVIGATOR_NEXT
	})
	return
}

func validateNSEC(rrt *ResolverRuntime, in *dns.Msg) bool {
	rrt.l.Infof("Entering validateNSEC()")
	nsec := []*dns.NSEC{}
	rrNavigator(in, func(rr dns.RR) int {
		if rr.Header().Rrtype == dns.TypeNSEC {
			nsec = append(nsec, rr.(*dns.NSEC))
		}
		return RR_NAVIGATOR_NEXT
	})
	return true
}

func validateNSEC3(rrt *ResolverRuntime, in *dns.Msg) bool {
	return true
}

/// basic convenience for ranging through various RR collections
/// TODO: replace in all places
func rrNavigator(input interface{}, action func(dns.RR) int) (ret int) {
	switch t := input.(type) {
	case *dns.Msg:
		rrHolder := [][]dns.RR{t.Answer, t.Ns, t.Extra}
		for _, arr := range rrHolder {
			for _, rr := range arr {
				rc := action(rr)
				if rc == RR_NAVIGATOR_BREAK {
					return
				} else if rc == RR_NAVIGATOR_BREAK_AND_PROPAGATE {
					return rc
				}
			}
		}
	case []dns.RR:
		for _, rr := range t {
			rc := action(rr)
			if rc == RR_NAVIGATOR_BREAK {
				return
			} else if rc == RR_NAVIGATOR_BREAK_AND_PROPAGATE {
				return rc
			}
		}
	case [][]dns.RR:
		for _, arr := range t {
			for _, rr := range arr {
				rc := action(rr)
				if rc == RR_NAVIGATOR_BREAK {
					return
				} else if rc == RR_NAVIGATOR_BREAK_AND_PROPAGATE {
					return rc
				}
			}
		}
	}
	return
}

/// function for determining if a response has DNSSEC records (DO bit alone is not enough)
func isDNSSECResponse(in *dns.Msg) (ret bool) {
	rrNavigator(in, func(rr dns.RR) int {
		if rr.Header().Rrtype == dns.TypeDNSKEY || rr.Header().Rrtype == dns.TypeDS || rr.Header().Rrtype == dns.TypeNSEC || rr.Header().Rrtype == dns.TypeNSEC3 ||
			rr.Header().Rrtype == dns.TypeRRSIG {
			ret = true
			return RR_NAVIGATOR_BREAK
		}
		return RR_NAVIGATOR_NEXT
	})

	return
}

/// function to determine if cache response has any valid hits
func isValidCacheResponse(cr interface{}, dnssec bool) bool {
	if resp, ok := cr.(*dns.Msg); dnssec && ok && resp != nil {
		return true
	} else if rr, ok := cr.([]dns.RR); !dnssec && ok && rr != nil {
		return true
	}
	return false
}

/// returns true if we reached the bottom level of DNS query loop (theoreticaly, not taking possible CNAME redirections etc into account)
func isBottomLevel(rrt *ResolverRuntime, level int) bool {
	if level < len(rrt.zones)-1 {
		return false
	}
	return true
}

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

/// sets up result
func setupResult(rrt *ResolverRuntime, rcode int, opaqueResponse interface{}) *dns.Msg {
	switch t := opaqueResponse.(type) {
	case [][]dns.RR:
		return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: rcode}, Answer: t[0], Ns: t[1], Extra: t[2]}
	case []dns.RR:
		return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: rcode}, Answer: t}
	case dns.RR: /// single RR means a SOA for nxdomain/nodata responses
		return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: rcode}, Ns: []dns.RR{t}}
	case *dns.Msg:
		t.Rcode = rcode
		return t
	default:
		return nil
	}
}

/// handle extras returned by cache (nxdomain or nodata)
func handleExtras(rrt *ResolverRuntime, cacheRet interface{}, extra *runtime.ItemCacheExtra) (ret *dns.Msg, err error, propagate bool) {
	rrt.l.Infof("Entering handleExtras() with [%v]", extra)
	if extra.Nxdomain || extra.Nodata {
		retCode := dns.RcodeNameError
		if extra.Nodata {
			retCode = dns.RcodeSuccess
		}
		switch t := cacheRet.(type) {
		case *dns.Msg:
			ret := new(dns.Msg)
			if e := copier.Copy(ret, t); e != nil {
				return nil, fmt.Errorf("cannot deep-copy response contents from cache [%s]", e.Error()), true
			}
			return ret, nil, true
		case []dns.RR:
			/// TODO: fetch a soa for nxdomain responses
			return setupResult(rrt, retCode, RESPONSE_EMPTY), nil, true
		}
	}
	return nil, nil, false
}

/// setupClient takes care of setting up the transport for the query.
/// Handles TLS capabilities retrieval/storage, udp/tcp preference (based on earlier rate limiting etc)
func setupClient(rrt *ResolverRuntime, server *entity) (c *dns.Client, p string) {
	rrt.l.Infof("Entering setupClient() with [%v]", server)
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

/// generic RR fetch or resolve
/// TODO: figure out how to handle CNAMEs (matter of fact this is a global improvement)
func fetchFromCacheOrNetwork(rrt *ResolverRuntime, zone string, record uint16) (ret []dns.RR, err error) {
	rrt.l.Infof("Entering fetchFromCacheOrNetwork() with [%s][%s]", zone, dns.TypeToString[record])
	cacheRes, extra := rrt.c.Retrieve(rrt.provider, zone, record, false)
	/// just return nil
	if extra.Nxdomain || extra.Nodata {
		return nil, fmt.Errorf("nxdomain on cache retrieve")
	}
	if isValidCacheResponse(cacheRes, false) {
		rrNavigator(cacheRes, func(rr dns.RR) int {
			if rr.Header().Rrtype == record {
				ret = append(ret, rr)
			}
			return RR_NAVIGATOR_NEXT
		})
		if len(ret) != 0 {
			return
		}
	}

	/// reaching this point means we cannot serve the answer from cache
	networkDS, err := Resolve(NewResolverRuntime(&runtime.Runtime{Cache: rrt.c, IPPool: rrt.p, SlackWH: rrt.f, Stats: rrt.s}, rrt.l, rrt.provider, newDNSQuery(zone, record)))
	if err != nil {
		return nil, err
	}
	ret = fetchRRByType(networkDS, record)
	if len(ret) == 0 {
		return nil, fmt.Errorf("cannot produce requested record")
	}
	return
}

/// convenience function consisting of retrieving NS records from cache, retrieving their matching A records
/// (or, in case they don't exist, resolving them), and constructing the result as an entity array
/// zone -- is the token we search for in cache. namely it's the nameserver, we want resolved.
/// resolveNS -- launch a resolve if we don't have a cache entry for NS
/// resolveA -- launch a resolve for A records, if cache is empty
func fetchNSAsEntity(rrt *ResolverRuntime, zone string, resolveNS, resolveA bool) (nsEntities []*entity) {
	rrt.l.Infof("Entering fetchNSAsENtity() with [%s]/[%v][%v]", zone, resolveNS, resolveA)
	/// do the cache get for NS records
	cacheRet, extra := rrt.c.Retrieve(rrt.provider, zone, dns.TypeNS, false)
	if _, _, p := handleExtras(rrt, cacheRet, extra); p {
		/// return a generic nil
		/// TODO: maybe add signalling for special cases like nxdomain
		return nil
	}
	targetNS := ToNS(cacheRet)

	if targetNS == nil {
		rrt.l.Infof("fetchNSAsEntity: Cache miss for NS records.")
		/// we are specifically bound not to resolve NS records. nothing more to do here
		if !resolveNS {
			rrt.l.Infof("fetchNSAsEntity: Returning empty handed (ns resolve forbidden).")
			return nil
		}
		rrt.l.Infof("fetchNSAsEntity: Retrieving NS records the hard way.")
		resolvedNS, _ := Resolve(NewResolverRuntime(&runtime.Runtime{Cache: rrt.c, IPPool: rrt.p, SlackWH: rrt.f, Stats: rrt.s}, rrt.l, rrt.provider, newDNSQuery(zone, dns.TypeNS)))
		/// check if we have glue records (if indeed we have, construct the entities array, and return it, else, pass the Ns array further down to processing)
		for _, answer := range resolvedNS.Answer {
			if ns, ok := answer.(*dns.NS); ok {
				targetNS = append(targetNS, ns)
				for _, additional := range resolvedNS.Extra {
					if a, ok := additional.(*dns.A); ok && ns.Ns == a.Hdr.Name {
						/// TODO: put KV store query for zone membership here
						nsEntities = append(nsEntities, newEntity(ns.Ns, a.A.String(), ""))
					}
				}
			}
		}
		/// we got lucky and have something to return without further processing
		if len(nsEntities) != 0 {
			return
		}
		/// if not, we have a set up targetNS array to continue the operation
	}
	/// now we have NS RRs in targetNS array, try to translate them into A records
	rrt.l.Infof("fetchNSAsEntity: We have NS records for zone [%s]. Checking A records.", zone)
	for _, ns := range targetNS {
		cacheRet, extra := rrt.c.Retrieve(rrt.provider, ns.Ns, dns.TypeA, false)
		if _, _, p := handleExtras(rrt, cacheRet, extra); p {
			/// don't break out just yet
			continue
		}
		if targetA := ToA(cacheRet); targetA != nil {
			for _, a := range targetA {
				nsEntities = append(nsEntities, &entity{name: ns.Ns, ip: a.A.String(), zone: zone})
			}
		}
	}
	/// we have at least _some_ data we can use, so we return that
	if len(nsEntities) != 0 {
		rrt.l.Infof("fetchNSAsEntity: We have matching A records. Returning.")
		return
	} else if resolveA {
		rrt.l.Infof("fetchNSAsEntity: No matching A records found for any NS records. Launching resolve")
		return resolveParallelHarness(rrt, targetNS)
	}
	rrt.l.Infof("fetchNSAsEntity: Returning empty handed")
	return nil
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
