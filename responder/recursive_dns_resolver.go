package responder

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/jinzhu/copier"
	"github.com/miekg/dns"
	"github.com/tenta-browser/tenta-dns/common"
	"github.com/tenta-browser/tenta-dns/log"
	"github.com/tenta-browser/tenta-dns/runtime"
)

const (
	LOGGING_NONE = iota
	LOGGING_LOGRUS
	LOGGING_PRINTF
	LOGGING_FILE
)

const (
	THREADING_NONE = iota
	THREADING_NETWORK_ONLY
	THREADING_MAX
)

var (
	THREADING = THREADING_NONE
	LOGGING   = LOGGING_PRINTF
)

const (
	RECURSIVE_DNS_UDP_SIZE                      = 4096
	RECURSIVE_DNS_NETWORK_ERROR                 = -1
	RECURSIVE_DNS_WAIT_ON_RATELIMIT             = 1000 /// millisec
	RECURSIVE_DNS_NUM_BLOCKED_BEFORE_FAILURE    = 3
	RECURSIVE_DNS_NUM_RECURSIONS_BEFORE_FAILURE = 30
	RECURSIVE_DNS_ALLOW_ISLANDS_OF_SECURITY     = true
	RECURSIVE_DNS_FILE_LOGGING_LOCATION         = "" /// folder in which to dump resolver debug files, when LOGGING_FILE is active
)

const (
	PROVIDER_TENTA   = "iana"
	PROVIDER_OPENNIC = "opennic"
)

const (
	NETWORK_UDP = "udp"
	NETWORK_TCP = "tcp"
	NETWORK_TLS = "tcp-tls"
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
	RESPONSE_ANSWER_HIDDEN
	RESPONSE_DELEGATION
	RESPONSE_DELEGATION_GLUE
	RESPONSE_DELEGATION_AUTHORITATIVE
	RESPONSE_NXDOMAIN
	///RESPONSE_EMPTY_NON_TERMINAL
	RESPONSE_NODATA
	RESPONSE_REDIRECT
	RESPONSE_REDIRECT_GLUE
	RESPONSE_THROTTLE_SUSPECT
)

var responseTypeToString = map[int]string{
	RESPONSE_UNKNOWN:                  "unknown",
	RESPONSE_ANSWER:                   "answer",
	RESPONSE_ANSWER_REDIRECT:          "answer/redirect",
	RESPONSE_ANSWER_HIDDEN:            "lucky",
	RESPONSE_DELEGATION:               "delegation",
	RESPONSE_DELEGATION_GLUE:          "delegation/glue",
	RESPONSE_DELEGATION_AUTHORITATIVE: "delegation/authoritative",
	RESPONSE_NXDOMAIN:                 "nxdomain",
	RESPONSE_NODATA:                   "nodata",
	RESPONSE_REDIRECT:                 "redirect",
	RESPONSE_REDIRECT_GLUE:            "redirect/glue",
	RESPONSE_THROTTLE_SUSPECT:         "blocked",
}

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
	blockTracker  map[string]int       /// a map to track blocked requests
	oomAlert      int32                /// contrary to what the name says, it's a counter for the number of recursions made (global, per request handler)
	oomAlert2     int32                /// same as above, it detects loops in another aspect
	fileLogger    *os.File             /// logger activated when LOGGING is LOGGING_FILE

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

func (e *entity) String() string {
	return fmt.Sprintf("[%s/%s/<%s>]", e.name, e.ip, e.zone)
}

/// do a very simple DNS query, without any interpretation of the returned data
func doQuery(rrt *ResolverRuntime, targetServer *entity, qname string, qtype uint16) (r *dns.Msg, e error) {
	LogInfo(rrt, "Entering doQuery() with [%s][%s] -- [%v]", qname, dns.TypeToString[qtype], targetServer)
	c, p := setupClient(rrt, targetServer)
	c.Timeout = 5 * time.Second
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype).SetEdns0(RECURSIVE_DNS_UDP_SIZE, true)
	m.Compress = true
	m.RecursionDesired = false

	trans := &transaction{e: targetServer, q: qname, t: qtype}
	LogInfo(rrt, "Executing query [%s][%s] -- [%s]", c.Net, net.JoinHostPort(targetServer.ip, p), m.Question[0].String())
	r, rtt, e := c.Exchange(m, net.JoinHostPort(targetServer.ip, p))
	if e != nil {
		trans.c = RECURSIVE_DNS_NETWORK_ERROR
		appendTransaction(rrt, trans)
		e = fmt.Errorf("transport error during DNS exchange [%s]", e.Error())
		return
	}
	// LogInfo(rrt, "DNS query yields: [%v][%s]\n[%s]", rtt, targetServer, r.String())
	trans.c = r.Rcode
	trans.r = rtt
	appendTransaction(rrt, trans)

	return
}

/// launch multiple resolutions concurently.
/// parallelism lies in resolving all the questions _at the same time_
/// used in case of cache entry expiration of A records
func resolveParallelHarness(rrt *ResolverRuntime, target []*dns.NS) (result []*entity) {
	LogInfo(rrt, "Entering resolveParallelHarness() with [%v]", target)
	start := time.Now()
	input := []*dns.Msg{}
	for _, ns := range target {
		input = append(input, newDNSQuery(ns.Ns, dns.TypeA))
	}
	if THREADING != THREADING_MAX {
		answer, _ := Resolve(NewResolverRuntime(&runtime.Runtime{Cache: rrt.c, IPPool: rrt.p, SlackWH: rrt.f, Stats: rrt.s}, rrt.l, rrt.provider, input[0], rrt.oomAlert, rrt.oomAlert2, rrt.fileLogger))
		if answer != nil {
			answer.Question = input[0].Question
			if answer.Answer != nil {
				for _, ans := range answer.Answer {
					if a, ok := ans.(*dns.A); ok {
						result = append(result, newEntity(a.Hdr.Name, a.A.String(), ""))
					}
				}
			}
		}
		return
	} else {
		/// TODO make this a random two servers
		input = input[:1]
	}
	achan := make(chan *dns.Msg, len(input))
	for _, q := range input {
		go func(question *dns.Msg) {
			answer, _ := Resolve(NewResolverRuntime(&runtime.Runtime{Cache: rrt.c, IPPool: rrt.p, SlackWH: rrt.f, Stats: rrt.s}, rrt.l, rrt.provider, question, rrt.oomAlert, rrt.oomAlert2, rrt.fileLogger))
			if answer != nil {
				answer.Question = question.Question
				achan <- answer
			}
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
			if t.Answer != nil {
				for _, ans := range t.Answer {
					if a, ok := ans.(*dns.A); ok {
						result = append(result, newEntity(a.Hdr.Name, a.A.String(), ""))
					}
				}
			}
		case <-time.After(100 * time.Millisecond):
			break
		}
	}
	LogInfo(rrt, "Parallel query done in [%v]", time.Now().Sub(start))
	return
}

/// launches a DNS query to all available and able servers, uses the first valid answer
/// parallelism lies in the ask all the NSes _at the same time_
func doQueryParallelHarness(rrt *ResolverRuntime, targetServers []*entity, qname string, qtype uint16) (*dns.Msg, error) {
	LogInfo(rrt, "Entering doQueryParallelHarness() with [%s][%s] -- [%v]", qname, dns.TypeToString[qtype], targetServers)
	if len(targetServers) == 0 {
		return nil, fmt.Errorf("there are no configured servers")
	}
	if targetServers[0].zone == "." || THREADING == THREADING_NONE {
		return doQuery(rrt, targetServers[0], qname, qtype)
	}

	routinesDone := int32(0)
	res := make(chan *parallelQueryResult, len(targetServers))
	for _, srv := range targetServers {
		go func(thisEntity *entity) {
			r, e := doQuery(rrt, thisEntity, qname, qtype)
			res <- &parallelQueryResult{r, e}
			if atomic.AddInt32(&routinesDone, 1) == int32(len(targetServers)) {
				close(res)
			}
		}(srv)
	}
	var r, secondBest *parallelQueryResult
	for r = range res {
		if r.e != nil {
			LogError(rrt, "Error in parallel doQuery [%s]", r.e.Error())
			continue
		}
		if r.r.Rcode == dns.RcodeSuccess {
			return r.r, r.e
		} else {
			secondBest = r
		}
	}
	/// returns last erroneous result, for future reference
	if r != nil && r.e != nil && secondBest != nil && secondBest.e == nil {
		return secondBest.r, secondBest.e
	}

	return r.r, r.e

}

func NewResolverRuntime(rt *runtime.Runtime, lg *logrus.Entry, provider string, incoming *dns.Msg, recursionStats, recursionStats2 int32, fileLogger *os.File) (rrt *ResolverRuntime) {
	rrt = &ResolverRuntime{
		c: rt.Cache, p: rt.IPPool, f: rt.SlackWH, s: rt.Stats, l: lg, original: incoming, provider: provider,
		oomAlert: recursionStats, oomAlert2: recursionStats2, fileLogger: fileLogger,
	}
	LogInfo(rrt, "Constructing resolver context, for [%s]/[%s]/[%s]", provider, incoming.Question[0].Name, dns.TypeToString[incoming.Question[0].Qtype])
	/// session setup
	rrt.domain = dns.Fqdn(rrt.original.Question[0].Name)
	rrt.zones = tokenizeDomain(rrt.domain)
	LogInfo(rrt, "Domain tokenized as [%v]", rrt.zones)
	rrt.targetServers = newTargetServerMap(rrt)
	/// TODO: figure out a better way to handle preferred network setup
	rrt.prefNet = NETWORK_UDP
	rrt.record = rrt.original.Question[0].Qtype
	rrt.transactions = []*transaction{}
	rrt.blockTracker = make(map[string]int)
	return
}

// Resolve -- takes a DNS question, and turns it into a DNS answer, be that a set of RRs or a failure.
// *outgoing* is only partially filled, RCODE and RRs are set, the rest is up to the caller.
// Expects a fully setup *ResolverRuntime as input (see NewResolverRuntime())
func Resolve(rrt *ResolverRuntime) (outgoing *dns.Msg, e error) {
	if atomic.AddInt32(&rrt.oomAlert2, 1) > RECURSIVE_DNS_NUM_RECURSIONS_BEFORE_FAILURE {
		LogError(rrt, "Dangerous number of resolves spawned for [%s/%s]. Pulling the plug.", rrt.domain, dns.TypeToString[rrt.record])
		// os.Exit(2)
		return nil, fmt.Errorf("exceeded number of permitted recursions")
	}

	LogInfo(rrt, "Starting a fresh resolve for [%s][%s], DO[%v]/CD[%v]", rrt.domain, dns.TypeToString[rrt.record], doWeReturnDNSSEC(rrt), doWeValidateDNSSEC(rrt))
	/// first order of business, check the cache
	/// and in order to do so, we do the following
	/// check QTYPE for full domain in cache -- if we get a hit, then return it, if not:
	/// recursively track back for NS records -- when we get a hit we continue the loop from there
	if rrt.record == dns.TypeDS {
		rrt.zones = rrt.zones[:len(rrt.zones)-1]
	}
	LogInfo(rrt, "Checking cache for exact match...")
	targetRR, extra := rrt.c.Retrieve(rrt.provider, rrt.domain, rrt.record, doWeReturnDNSSEC(rrt))

	if r, e, p := handleExtras(rrt, targetRR, extra); p {
		return r, e
	}

	if isValidCacheResponse(targetRR, doWeReturnDNSSEC(rrt)) {
		LogInfo(rrt, "Response can be formulated from cache. [%v]", targetRR)
		return setupResult(rrt, dns.RcodeSuccess, targetRR), nil
	} else {
		LogInfo(rrt, "No exact match in cache. Improvising...")
	}

	entryPoint := 0
	LogInfo(rrt, "Checking whether we have preconfigured targetServers and zones.")
	if rrt.currentZone != "" && rrt.targetServers[rrt.currentZone] != nil {
		LogInfo(rrt, "We have a valid setup at zone [%s] wih entities [%v]", rrt.currentZone, rrt.targetServers[rrt.currentZone])
		for i, z := range rrt.zones {
			if z == rrt.currentZone {
				return doQueryRecursively(rrt, i)
			}
		}
	}
	rrt.currentZone = "."

	LogInfo(rrt, "Retrieving intermediary NS records.")
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
			LogInfo(rrt, "We have NS records for zone [%s]. Checking A records.", z)
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
				entryPoint = len(rrt.zones) - 1 - i
				rrt.targetServers[z] = nsEntities
				rrt.currentZone = z
				LogInfo(rrt, "We have matching A records. Query loop diminished. Resuming from [%s] down to [%s]", rrt.zones[entryPoint], rrt.domain)
				break
			}
			/*
				else {
					/// here we can evaluate if we are better off doing a separate resolve of the cached ns, or step further up
					/// and to put that into practice, we compare the NS record(s) to the current zone (z) token bits
					/// if we have match greater or equal than the TLD+1 part, we step back, otherwise, we do a parallel resolve for all the NS records
					LogInfo(rrt, "No matching A records found for any NS records. Evaluating a separate resolve feasability.")
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
					LogInfo(rrt, "We havent found a NS in the same zone hierarchy as the target [%s] -- [%v]", z, targetNS)
					LogInfo(rrt, "Executing a parallel resolve for NS records")
					entryPoint = len(rrt.zones) - 1 - i
					rrt.targetServers[z] = resolveParallelHarness(rrt, targetNS)
					rrt.currentZone = z
					break

				}
			*/
		}
	}

	/// do the actual recursion
	outgoing, e = doQueryRecursively(rrt, entryPoint)
	return
}

/// function for recursive invocation. handles one level of the query hierarchy, calls itself for next level
/// operating principle: previous level has set up a list of NSes to question, so it will ask the question specific
/// to its level, and analyze the response, set up the environment for the next invocation
func doQueryRecursively(rrt *ResolverRuntime, _level int) (*dns.Msg, error) {
	if atomic.AddInt32(&rrt.oomAlert, 1) > RECURSIVE_DNS_NUM_RECURSIONS_BEFORE_FAILURE {
		LogError(rrt, "Dangerous number of recursions for [%s/%s]. Pulling the plug.", rrt.domain, dns.TypeToString[rrt.record])
		// os.Exit(2)
		return nil, fmt.Errorf("exceeded number of permitted recursions")
	}
	/// level always shows what zone we have NSes set up. We can safely ask questions about the next token.
	/// unless level == len(rrt.zones) (aka. iob error), which means we are at the final question
	LogInfo(rrt, "Entering doQueryRecursively() with level [%d/%d]", _level, len(rrt.zones))
	isFinalQuestion := isBottomLevel(rrt, _level)
	if isFinalQuestion {
		_level--
	}
	currentZone := rrt.currentZone
	if _level >= len(rrt.zones)-1 {
		LogError(rrt, "Not sure how this happened, but we are at level [%d]/[%d], isfinal [%v], currentZone is [%s], domain is [%s] and currentToken is IOB error",
			_level, len(rrt.zones), isFinalQuestion, currentZone, rrt.domain)
		return nil, fmt.Errorf("level calculation soft panic")
	}
	currentToken := rrt.zones[_level+1]
	/// no more use of integer _level is allowed. Except when going deeper in recursion.

	/// first of all, check the cache, and check if we're at the bottom level
	/// if we're at bottom, we ask the final qtype, if not, we ask NS
	qtype := dns.TypeNS
	if isFinalQuestion {
		qtype = rrt.record
		/// need this hack because DS asks about child zone from parent zone (current token, current zone, and isfinal are not in sync)
		if qtype == dns.TypeDS {
			currentToken = rrt.domain
		}
	}
	LogInfo(rrt, "CurrentZone [%s], CurrentToken [%s], isFinal [%v]", currentZone, currentToken, isFinalQuestion)
	cachedRR, extra := rrt.c.Retrieve(rrt.provider, currentToken, qtype, doWeReturnDNSSEC(rrt))
	if r, e, p := handleExtras(rrt, cachedRR, extra); p {
		return r, e
	}
	LogInfo(rrt, "Cache request for [%s/%s] yields [%v][%v]", currentToken, dns.TypeToString[qtype], extra, cachedRR)
	if isValidCacheResponse(cachedRR, doWeReturnDNSSEC(rrt)) {
		LogInfo(rrt, "Found the solution in cache. Using it. [%v]", cachedRR)
		/// if we're at bottom level, aka final question, we can return this as result
		if isFinalQuestion {
			return setupResult(rrt, dns.RcodeSuccess, cachedRR), nil
			/// TODO: find a way to utilize target servers as authority section records
		} else { /// not last question, we use it to set up next level, and shortcut there
			rrt.targetServers[currentToken] = fetchNSAsEntity(rrt, currentToken, false, false)
			return doQueryRecursively(rrt, _level+1)
		}
	}
	/// at this point we know that we can't skip an rtt to the NSes
	res, err := doQueryParallelHarness(rrt, rrt.targetServers[currentZone], currentToken, qtype)
	answerType := RESPONSE_UNKNOWN
	/// propagate back (this means, that all NSes returned an error)
	if err != nil {
		if strings.Contains(err.Error(), "i/o timeout") {
			LogInfo(rrt, "We have a timeout which is considered as a throttle attempt")
			answerType = RESPONSE_THROTTLE_SUSPECT
		} else {
			LogError(rrt, "Error in recursive aspect. [%s]", err.Error())
			return nil, err
		}
	} else {
		cosmetizeRecords(res)

		LogInfo(rrt, "DNS query:\n[%s]", res.String())
		/// no fatal error means we can proceed to DNSSEC validation
		answerType = evaluateResponse(rrt, currentToken, qtype, isFinalQuestion, res)
		LogInfo(rrt, "We cannot be certain, but the answer looks like an [%s]", responseTypeToString[answerType])
		if isDNSSECResponse(res) {
			/// hack to support authoritative _delegation_ into child zone without DS record (and more importantly, with RRSIGS signed with child zone DNSKEY)
			/// we do a DS first (and the DS will be signed with parent DNSKEY) - this can be verified
			/// we do a child zone DNSKEY - this can be verified, even if the RRSIG is signed with the queried key, because ve validate DNSKEY first, and then RRSIG
			if answerType == RESPONSE_DELEGATION_AUTHORITATIVE && fetchRRByType(res, dns.TypeDS) == nil {
				LogInfo(rrt, "Caught an authoritative delegation for [%s]", res.Question[0].String())
				rrtDS := NewResolverRuntime(&runtime.Runtime{Cache: rrt.c, IPPool: rrt.p, SlackWH: rrt.f, Stats: rrt.s}, rrt.l, rrt.provider, newDNSQuery(currentToken, dns.TypeDS), rrt.oomAlert, rrt.oomAlert2, rrt.fileLogger)
				setupZone(rrtDS, currentToken, extractCommonElements(fetchRRByType(res, dns.TypeNS), rrt.targetServers[currentZone]))
				Resolve(rrtDS)
				rrtDNSKEY := NewResolverRuntime(&runtime.Runtime{Cache: rrt.c, IPPool: rrt.p, SlackWH: rrt.f, Stats: rrt.s}, rrt.l, rrt.provider, newDNSQuery(currentToken, dns.TypeDNSKEY), rrt.oomAlert, rrt.oomAlert2, rrt.fileLogger)
				setupZone(rrtDNSKEY, currentToken, extractCommonElements(fetchRRByType(res, dns.TypeNS), rrt.targetServers[currentZone]))
				Resolve(rrtDNSKEY)
			}
			if e := validateDNSSEC(rrt, res, currentZone, currentToken, answerType); !e {
				/// validator returns error only on critical security issues only (which warrant an instant propagation of the error)
				LogInfo(rrt, "Caught a bogus dnssec response!")
				return setupResult(rrt, dns.RcodeServerFailure, nil), fmt.Errorf("bogus DNSSEC response")
			}
		}

		/// TODO: add record security check
		cacheResponse(rrt, res, answerType)

		if !isFinalQuestion && answerType != RESPONSE_NODATA && answerType != RESPONSE_NXDOMAIN {
			rrt.currentZone = currentToken
		}
	}

	switch answerType {
	case RESPONSE_ANSWER, RESPONSE_ANSWER_REDIRECT:
		LogInfo(rrt, "Got an answer. Returning it.")
		tmp := setupResult(rrt, dns.RcodeSuccess, res)
		return tmp, nil
	case RESPONSE_DELEGATION:
		LogInfo(rrt, "Got a naked delegation.")
		nsRR := []*dns.NS{}
		rrNavigator(res, func(rr dns.RR) int {
			if rr.Header().Rrtype == dns.TypeNS {
				nsRR = append(nsRR, rr.(*dns.NS))
			}
			return RR_NAVIGATOR_NEXT
		})
		rrt.targetServers[currentToken] = resolveParallelHarness(rrt, nsRR)
		LogInfo(rrt, "Going deeper into the rabbithole.")
		return doQueryRecursively(rrt, _level+1)
	case RESPONSE_ANSWER_HIDDEN:
		LogInfo(rrt, "Got a tricky answer. Extracting, and returning it.")
		answers := fetchRRByType(res, rrt.record)
		return setupResult(rrt, dns.RcodeSuccess, answers), nil
	case RESPONSE_DELEGATION_GLUE:
		LogInfo(rrt, "Got delegation /w glue records.")
		servers := []*entity{}
		rrNavigator(res, func(rr dns.RR) int {
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
		rrt.targetServers[currentToken] = servers
		LogInfo(rrt, "Setting up next level [%s] with [%v]", currentToken, servers)
		LogInfo(rrt, "Going deeper into the rabbithole.")
		return doQueryRecursively(rrt, _level+1)
	case RESPONSE_DELEGATION_AUTHORITATIVE:
		LogInfo(rrt, "Got an authoritative delegation.")
		rrt.targetServers[currentToken] = extractCommonElements(fetchRRByType(res, dns.TypeNS), rrt.targetServers[currentZone])
		return doQueryRecursively(rrt, _level+1)
	// case RESPONSE_EMPTY_NON_TERMINAL:
	case RESPONSE_NODATA:
		LogInfo(rrt, "Got a NODATA. Caching and returning it.")
		if !isFinalQuestion {
			LogInfo(rrt, "Got an empty non-terminal. Retrying same servers for one more label.")
			rrt.targetServers[currentToken] = rrt.targetServers[currentZone]
			return doQueryRecursively(rrt, _level+1)
		}
		rrt.c.Insert(rrt.provider, currentToken, dns.TypeToRR[qtype](), &runtime.ItemCacheExtra{Nodata: true})
		if doWeReturnDNSSEC(rrt) && isDNSSECResponse(res) {
			return setupResult(rrt, res.Rcode, res), nil
		} else {
			retSoa := fetchRRByType(res, dns.TypeSOA)
			if retSoa != nil {
				return setupResult(rrt, dns.RcodeSuccess, retSoa[0]), nil
			}
			return setupResult(rrt, dns.RcodeSuccess, nil), nil
		}
	case RESPONSE_NXDOMAIN:
		LogInfo(rrt, "Got an NXDOMAIN. Caching and returning it.")
		if !isFinalQuestion {
			LogInfo(rrt, "Got an empty non-terminal. Retrying same servers for one more label.")
			rrt.targetServers[currentToken] = rrt.targetServers[currentZone]
			return doQueryRecursively(rrt, _level+1)
		}
		rrt.c.Insert(rrt.provider, currentToken, dns.TypeToRR[qtype](), &runtime.ItemCacheExtra{Nxdomain: true})
		if doWeReturnDNSSEC(rrt) && isDNSSECResponse(res) {
			return setupResult(rrt, dns.RcodeNameError, res), nil
		} else {
			retSoa := fetchRRByType(res, dns.TypeSOA)
			if retSoa != nil {
				return setupResult(rrt, dns.RcodeNameError, retSoa[0]), nil
			}
			return setupResult(rrt, dns.RcodeNameError, nil), nil
		}
	case RESPONSE_REDIRECT, RESPONSE_REDIRECT_GLUE:
		LogInfo(rrt, "Got a naked CNAME. Following and resolving it.")
		cnames := []*dns.CNAME{}
		rrNavigator(res, func(rr dns.RR) int {
			if rr.Header().Rrtype == dns.TypeCNAME {
				cnames = append(cnames, rr.(*dns.CNAME))
			}
			return RR_NAVIGATOR_NEXT
		})
		lastOwner := redirectNavigator(currentToken, cnames)
		var redirectResult *dns.Msg
		var err error

		if answerType == RESPONSE_REDIRECT && res.Authoritative && strings.HasSuffix(lastOwner, res.Question[0].Name) {
			/// an extra hack for `list.tmall.com` (CNAME resolve loop)
			LogInfo(rrt, "Doing the CNAME redirection loop prevention")
			rrtCNAME := NewResolverRuntime(&runtime.Runtime{Cache: rrt.c, IPPool: rrt.p, SlackWH: rrt.f, Stats: rrt.s}, rrt.l, rrt.provider, newDNSQuery(lastOwner, rrt.record), rrt.oomAlert, rrt.oomAlert2, rrt.fileLogger)
			setupZone(rrtCNAME, lastOwner, rrt.targetServers[currentZone])
			redirectResult, err = Resolve(rrtCNAME)
		} else {
			redirectResult, err = Resolve(NewResolverRuntime(&runtime.Runtime{Cache: rrt.c, IPPool: rrt.p, SlackWH: rrt.f, Stats: rrt.s},
				rrt.l, rrt.provider, newDNSQuery(lastOwner, rrt.record), rrt.oomAlert, rrt.oomAlert2, rrt.fileLogger))
		}

		if err != nil {
			LogError(rrt, "Redirect resolution failed with [%s]", err.Error())
			return nil, err
		} else if redirectResult == nil || redirectResult.Answer == nil {
			LogError(rrt, "Redirect resolution turned up an empty answer. Q:[%s/%s]", lastOwner, dns.TypeToString[rrt.record])
			return nil, fmt.Errorf("error occured during CNAME redirection")
		} else {
			LogInfo(rrt, "Redirect resolved successfully. Returning with added references.")
			redirectResult.Answer = append(redirectResult.Answer, fetchRRByType(res, dns.TypeCNAME)...)
			return setupResult(rrt, dns.RcodeSuccess, redirectResult), nil
		}
	case RESPONSE_THROTTLE_SUSPECT:
		if rrt.blockTracker[currentToken] < RECURSIVE_DNS_NUM_BLOCKED_BEFORE_FAILURE-1 {
			time.Sleep(time.Millisecond * RECURSIVE_DNS_WAIT_ON_RATELIMIT)
			return doQueryRecursively(rrt, _level)
		} else if rrt.blockTracker[currentToken] < RECURSIVE_DNS_NUM_BLOCKED_BEFORE_FAILURE-1 {
			time.Sleep(time.Millisecond * RECURSIVE_DNS_WAIT_ON_RATELIMIT)
			rrt.prefNet = NETWORK_TCP
			return doQueryRecursively(rrt, _level)
		} else {
			return setupResult(rrt, dns.RcodeServerFailure, nil), nil
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

/// remove DNSSEC records from *Msg
func removeDNSSECRecords(in *dns.Msg) {
	for _, holder := range []*[]dns.RR{&in.Answer, &in.Ns, &in.Extra} {
		temp := []dns.RR{}
		rrNavigator(holder, func(rr dns.RR) int {
			if !(rr.Header().Rrtype == dns.TypeRRSIG || rr.Header().Rrtype == dns.TypeNSEC || rr.Header().Rrtype == dns.TypeNSEC3 ||
				rr.Header().Rrtype == dns.TypeNSEC3PARAM || rr.Header().Rrtype == dns.TypeDS) {
				temp = append(temp, rr)
			}
			return RR_NAVIGATOR_NEXT
		})
		holder = &temp
	}
}

/// function to uniformize domain names (lowercase) in specific records -- before any evaluation or logic is done
func cosmetizeRecords(in *dns.Msg) {
	rrNavigator(in, func(rr dns.RR) int {
		/// if it's not an NSEC3 and it's not an NSEC3 covering RRSIG
		if (rr.Header().Rrtype != dns.TypeNSEC3 && rr.Header().Rrtype != dns.TypeRRSIG) ||
			(rr.Header().Rrtype == dns.TypeRRSIG && rr.(*dns.RRSIG).TypeCovered != dns.TypeNSEC3) {
			rr.Header().Name = strings.ToLower(rr.Header().Name)
		}
		switch t := rr.(type) {
		case *dns.NS:
			t.Ns = strings.ToLower(t.Ns)
		case *dns.CNAME:
			t.Target = strings.ToLower(t.Target)
		}
		return RR_NAVIGATOR_NEXT
	})
}

/// convenience func to store a response or all records from it
func cacheResponse(rrt *ResolverRuntime, in *dns.Msg, responseType int) {
	if isDNSSECResponse(in) && (fetchRRByType(in, in.Question[0].Qtype) != nil || fetchRRByType(in, dns.TypeCNAME) != nil) {
		rrt.c.InsertResponse(rrt.provider, in.Question[0].Name, in)
	}

	rrNavigator(in, func(rr dns.RR) int {
		rrt.c.Insert(rrt.provider, rr.Header().Name, rr, EXTRA_EMPTY)
		return RR_NAVIGATOR_NEXT
	})

}

func evaluateResponse(rrt *ResolverRuntime, qname string, qtype uint16, isFinal bool, r *dns.Msg) (rtype int) {

	if r.Rcode == dns.RcodeSuccess {
		/// it can be answer, delegation, delegation /w glue, redirect, nodata
		hasCNAME := false
		hasSOA := false
		hasNS := false
		hasOtherNS := false

		rrNavigator(r, func(rr dns.RR) int {
			if rr.Header().Rrtype == dns.TypeNS {
				if strings.ToLower(rr.Header().Name) == strings.ToLower(qname) {
					hasNS = true
				} else {
					hasOtherNS = true
				}
			}
			return RR_NAVIGATOR_NEXT
		})

		rrNavigator(r.Ns, func(rr dns.RR) int {
			if rr.Header().Rrtype == dns.TypeSOA {
				hasSOA = true
				return RR_NAVIGATOR_BREAK
			}
			return RR_NAVIGATOR_NEXT
		})

		/// check if it is a straight-forward answer
		for _, rr := range r.Answer {
			if rr.Header().Rrtype == qtype && strings.ToLower(rr.Header().Name) == strings.ToLower(qname) && qtype == rrt.record && strings.ToLower(qname) == strings.ToLower(rrt.domain) {
				return RESPONSE_ANSWER
			} else if rr.Header().Rrtype == dns.TypeCNAME {
				hasCNAME = true
			}
		}

		/// return special answer type result when our question is answered incidentally in additional section
		for _, arr := range [][]dns.RR{r.Ns, r.Extra} {
			for _, rr := range arr {
				if rr.Header().Rrtype == rrt.record && strings.ToLower(rr.Header().Name) == strings.ToLower(rrt.domain) {
					return RESPONSE_ANSWER_HIDDEN
				}
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
				if rr.Header().Rrtype == qtype && strings.ToLower(rr.Header().Name) == strings.ToLower(lastOwner) {
					return RR_NAVIGATOR_BREAK_AND_PROPAGATE
				}
				return RR_NAVIGATOR_NEXT
			}) == RR_NAVIGATOR_BREAK_AND_PROPAGATE {
				return RESPONSE_ANSWER_REDIRECT
			}

		}

		/// check for CNAMES (with or without additional info)
		if hasCNAME {
			if !hasNS && !hasOtherNS {
				return RESPONSE_REDIRECT
			}
			return RESPONSE_REDIRECT_GLUE
		}

		/// check delegation
		if hasNS {
			if hasCommonElements(fetchRRByType(r, dns.TypeNS), rrt.targetServers[rrt.currentZone]) {
				return RESPONSE_DELEGATION_AUTHORITATIVE
			}
			if cleanAdditionalSection(r.Extra) == nil {
				return RESPONSE_DELEGATION
			}
			return RESPONSE_DELEGATION_GLUE
		}

		/// check NODATA
		if r.Answer == nil {
			return RESPONSE_NODATA
		}

	} else if r.Rcode == dns.RcodeNameError {
		return RESPONSE_NXDOMAIN
	} else if r.Rcode == dns.RcodeServerFailure || r.Rcode == dns.RcodeRefused {
		/// hacky approach, TODO: figure out a way to track only the throttling servers (either update at goroutine level (needs rwmutex or syncmap), or propagate server info with response)
		rrt.blockTracker[qname]++
		return RESPONSE_THROTTLE_SUSPECT
	} else if r.Rcode == dns.RcodeFormatError {
		/// suppose that we managed to properly calculate qname, qtype and qclass; let's interpret formerr as a rate limiting technique
		rrt.blockTracker[qname]++
		return RESPONSE_THROTTLE_SUSPECT
	}

	return RESPONSE_UNKNOWN
}

/// func used primarily (and solely) for checking whether a delegation to a sub-zone has the same servers as the parent zone
func hasCommonElements(arr1 []dns.RR, arr2 []*entity) bool {
	for _, _ns1 := range arr1 {
		ns1, ok := _ns1.(*dns.NS)
		if !ok {
			continue
		}
		for _, ns2 := range arr2 {
			if ns1.Ns == ns2.name {
				return true
			}
		}
	}
	return false
}

func extractCommonElements(arr1 []dns.RR, arr2 []*entity) (servers []*entity) {
	for _, _ns1 := range arr1 {
		ns1, ok := _ns1.(*dns.NS)
		if !ok {
			continue
		}
		for _, ns2 := range arr2 {
			if ns1.Ns == ns2.name {
				servers = append(servers, ns2)
			}
		}
	}
	return
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
func validateDNSSEC(rrt *ResolverRuntime, in *dns.Msg, currentZone, currentToken string, responseType int) bool {
	LogInfo(rrt, "Entering validateDNSSEC() with [%v] in zone [%s]", in.Question[0].String(), currentZone)
	if dkrr := fetchRRByType(in, dns.TypeDNSKEY); dkrr != nil {
		dks := []*dns.DNSKEY{}
		rrs := []*dns.RRSIG{}
		rrNavigator(dkrr, func(rr dns.RR) int {
			if rr.Header().Rrtype == dns.TypeDNSKEY {
				dks = append(dks, rr.(*dns.DNSKEY))
			}
			return RR_NAVIGATOR_NEXT
		})
		rrNavigator(in, func(rr dns.RR) int {
			if rr.Header().Rrtype == dns.TypeRRSIG && rr.(*dns.RRSIG).TypeCovered == dns.TypeDNSKEY {
				rrs = append(rrs, rr.(*dns.RRSIG))
			}
			return RR_NAVIGATOR_NEXT
		})
		if len(rrs) == 0 {
			LogInfo(rrt, "Cannot validate unsigned DNSKEYs (RRSIG missing)")
			return false
		}
		LogInfo(rrt, "Trying to validate DNSKEYS [%v]", dks)
		if !validateDNSKEY(rrt, currentZone, dks, rrs) {
			LogInfo(rrt, "Unable to validate DNSKEYS!")
			return false
		}
		/// we cache the DNSKEYS quickly, because we might need them before this function returns
		LogInfo(rrt, "DNSKEYS successfully validated. Caching them. [%v]", dks)
		// rrNavigator(dks, func(rr dns.RR) int {
		for _, dk := range dks {
			LogInfo(rrt, "Inserting [%s]", dk.String())
			rrt.c.Insert(rrt.provider, dk.Header().Name, dk, EXTRA_EMPTY)
		}
		// return RR_NAVIGATOR_NEXT
		// })
	}
	if !validateNSEC(rrt, in, currentZone, currentToken, responseType) {
		return false
	}
	LogInfo(rrt, "NSEC successfully validated")
	if !validateNSEC3(rrt, in, currentZone, currentToken, responseType) {
		return false
	}
	LogInfo(rrt, "NSEC3 successfully validated")
	if !validateRRSIG(rrt, currentZone, in) {
		LogInfo(rrt, "Unable to validate RRSIGs!")
		return false
	}
	LogInfo(rrt, "RRSIG successfully validated")
	return true
}

/// validates an array of DNSKEYS (needs curent level of reursive hierarchy)
/// operating principle:
/// get (via cache or network) DS records from parent zone
/// sequentially try to validate every DNSKEY with one of the retrieved DSes
/// fail if a DNSKEY can't be validated
func validateDNSKEY(rrt *ResolverRuntime, currentZone string, dks []*dns.DNSKEY, rss []*dns.RRSIG) bool {
	LogInfo(rrt, "Entering validateDNSKEY() with [%s][%v]", currentZone, dks)
	LogInfo(rrt, "Zones are [%v]", rrt.zones)
	dss, err := fetchFromCacheOrNetwork(rrt, currentZone, dns.TypeDS)
	if err != nil {
		/// if we cannot produce DS records matching our DNSKEY, fail without question
		LogError(rrt, "Cannot produce DS record. Cause [%s]. Checking whether we tolerate islands of security.", err.Error())
		if RECURSIVE_DNS_ALLOW_ISLANDS_OF_SECURITY {
			LogInfo(rrt, "We do, yay.")
			return true
		}
		LogError(rrt, "We don't, failing this thread.")
		return false
	}
	LogInfo(rrt, "We fetched DS records [%v]", dss)

	/// not necessarily the KSK (for example in a zone that covers two levels); it's the key that is validated by the parent DS, and which is used to sign the DNSKEY RRSet
	mainDNSKEYs := []*dns.DNSKEY{}
	for _, rrsig := range rss {
		for _, dk := range dks {
			if dk.KeyTag() == rrsig.KeyTag {
				mainDNSKEYs = append(mainDNSKEYs, dk)
			}
		}
	}

	if len(mainDNSKEYs) == 0 {
		LogInfo(rrt, "Cannot find DNSKEYS that signed the RRSet. Failed DNSKEY validation.")
		return false
	}
	validatedAtLeastOne := false
	for _, dk := range mainDNSKEYs {
		for _, ds := range dss {
			if ds.Header().Rrtype == dns.TypeDS && equalsDS(ds.(*dns.DS), dk.ToDS(ds.(*dns.DS).DigestType)) {
				validatedAtLeastOne = true
			}
		}
	}
	/// we can safely pass true back if we validate at least one DNSKEY, which signed the (whole) DNSKEY RRSet
	/// attack vectors can be (but checked):
	/// - injected bogus DNSKEY (would fail RRSIG validation down the line)
	/// - RRSIG (which references DNSKEY) does not cover all the DNSKEYS (opens up injection vulnerability), would also fail RRSIG validation
	return validatedAtLeastOne
}

/// validates RRSIG records
/// operating principle:
/// for every set (answer, authority, additional): sort all records into a map
/// --> for every RRSIG in set, try to validate the covered type array
func validateRRSIG(rrt *ResolverRuntime, currentZone string, in *dns.Msg) bool {
	LogInfo(rrt, "Entering validateRRSIG()")
	rrFilter := map[uint16]map[string][]dns.RR{}
	rrHolder := [][]dns.RR{in.Answer, in.Ns, in.Extra}
	rrSigs := fetchRRByType(in, dns.TypeRRSIG)
	dnskeyMap := map[string][]dns.RR{}
	var err error
	if len(rrSigs) == 0 {
		return true
	}

	for _, rrs := range rrSigs {
		sigOwner := rrs.(*dns.RRSIG).SignerName
		if _, ok := dnskeyMap[sigOwner]; !ok {
			dnskeyMap[sigOwner], err = fetchFromCacheOrNetwork(rrt, sigOwner, dns.TypeDNSKEY)
			if err != nil {
				LogError(rrt, "Cannot fetch cache/network DNSKEY for zone [%s]: [%s]", currentZone, err.Error())
				return false
			} else {
				LogInfo(rrt, "We did fetch the following keys \n [%v]", dnskeyMap[sigOwner])
			}
		}
	}
	// LogInfo(rrt, "We have all the necessary DNSKEYS, we can resume validation.")
	// LogInfo(rrt, "We have [%v]", dnskeyMap)
	/// for every section, map the RRs and then try to validate them using the RRSIGs and DNSKEYS
	/// on error return false without hesitation
	/// algorith is as follows:
	/// loop a holder (section), and add items into the filters (global, local) until an RRSIG is found
	/// when an RRSIG is found try to validate with all the covered records, or just the ones found since the last RRSIG (supports NSEC/NSEC3 signings)
	for _, arr := range rrHolder {
		rrNavigator(arr, func(rr dns.RR) int {
			if rrFilter[rr.Header().Rrtype] == nil {
				rrFilter[rr.Header().Rrtype] = map[string][]dns.RR{}
			}
			rrFilter[rr.Header().Rrtype][rr.Header().Name] = append(rrFilter[rr.Header().Rrtype][rr.Header().Name], rr)
			return RR_NAVIGATOR_NEXT
		})
		rrLFilter := map[uint16]map[string][]dns.RR{}
		for _, rr := range arr {
			if rrSig, ok := rr.(*dns.RRSIG); ok {
				rrSigValid := false
				for _, dks := range dnskeyMap[rrSig.SignerName] {
					if dks.(*dns.DNSKEY).KeyTag() != rrSig.KeyTag {
						continue
					}
					LogInfo(rrt, "Found KEY with tag [%d] :: [%s]", rrSig.KeyTag, dks.String())
					/// try to validate: signature isnt expired, validate with global or validate with local filter
					if rrSig.ValidityPeriod(time.Now()) && (rrSig.Verify(dks.(*dns.DNSKEY), rrFilter[rrSig.TypeCovered][rrSig.Header().Name]) != nil ||
						rrSig.Verify(dks.(*dns.DNSKEY), rrLFilter[rrSig.TypeCovered][rrSig.Header().Name]) != nil ||
						rrSig.Verify(dks.(*dns.DNSKEY), []dns.RR{dks}) != nil) {
						rrSigValid = true
						break
					} else {
						LogInfo(rrt, "[global filter] Tried to validate [%s]\n with key\n[%s]\nand records\n[%v]", rrSig.String(), dks.String(), rrFilter[rrSig.TypeCovered][rrSig.Header().Name])
						LogInfo(rrt, "[local filter] Tried to validate [%s]\n with key\n[%s]\nand records\n[%v]", rrSig.String(), dks.String(), rrLFilter[rrSig.TypeCovered][rrSig.Header().Name])
					}
				}
				if rrSigValid == false {
					return false
				}
				rrLFilter = map[uint16]map[string][]dns.RR{}
			} else {
				if rrLFilter[rr.Header().Rrtype] == nil {
					rrLFilter[rr.Header().Rrtype] = map[string][]dns.RR{}
				}
				rrLFilter[rr.Header().Rrtype][rr.Header().Name] = append(rrLFilter[rr.Header().Rrtype][rr.Header().Name], rr)
			}
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

func validateNSEC(rrt *ResolverRuntime, in *dns.Msg, currentZone, currentToken string, responseType int) bool {
	LogInfo(rrt, "Entering validateNSEC()")
	nsecs := []dns.RR{} //fetchRRByType(in.Answer, dns.TypeNSEC)
	for _, rr := range in.Answer {
		if rr.Header().Rrtype == dns.TypeNSEC {
			nsecs = append(nsecs, rr)
		}
	}
	if len(nsecs) == 0 {
		return true
	}
	expectWildcardDeny := true
	if dns.CountLabel(currentToken) > dns.CountLabel(currentZone)+1 {
		expectWildcardDeny = false
	}

	var wildcardDeny, encloseDeny, dataDeny *dns.NSEC
	rrNavigator(nsecs, func(rr dns.RR) int {
		if rr.Header().Rrtype == dns.TypeNSEC {
			if rr.Header().Name == currentToken {
				dataDeny = rr.(*dns.NSEC)
			} else if rr.Header().Name == currentZone {
				wildcardDeny = rr.(*dns.NSEC)
			} else {
				encloseDeny = rr.(*dns.NSEC)
			}
		}
		return RR_NAVIGATOR_NEXT
	})
	deniedRecord, deniedEnvelope := false, false
	/// nxdomain check: did we get wildcard expansion denial, did we get enclosed type denial,
	/// enclosed owner label comes before query token, enclosed next label comes after query token
	if encloseDeny != nil {

		if expectWildcardDeny && wildcardDeny == nil {
			LogInfo(rrt, "WARNING!!! Expected a windcard denial, but haven't received one; this fails NSEC validation. (letting it slide now)")
			///return false
		}
		if strings.HasPrefix(encloseDeny.Hdr.Name, currentToken) {
			LogInfo(rrt, "NSEC owner label includes query token integrally; this fails NSEC validation.")
			return false
		}

		commonLeft, cli := commonPrefix(encloseDeny.Hdr.Name, currentToken)

		if !(commonLeft == encloseDeny.Hdr.Name || encloseDeny.Hdr.Name[cli] < currentToken[cli]) {
			LogInfo(rrt, "Query token comes alphabetically before NSEC owner label; this fails NSEC validation.")
			return false
		}

		if strings.HasPrefix(currentToken, encloseDeny.NextDomain) {
			LogInfo(rrt, "NSEC next domain included in query token integrally; this fails NSEC validation.")
			return false
		}

		commonRight, cri := commonPrefix(encloseDeny.NextDomain, currentToken)

		if !(commonRight == encloseDeny.NextDomain || currentToken[cri] < encloseDeny.NextDomain[cri]) {
			LogInfo(rrt, "Query token comes alphabetically before NSEC owner label; this fails NSEC validation.")
			return false
		}
		deniedEnvelope = true
	}
	/// nodata check: did we get data denial, did it deny the record type we queried for
	if dataDeny != nil {
		if responseType == RESPONSE_DELEGATION || responseType == RESPONSE_DELEGATION_AUTHORITATIVE || responseType == RESPONSE_DELEGATION_GLUE ||
			responseType == RESPONSE_ANSWER_HIDDEN {
			if isTypeCovered(dataDeny, dns.TypeDS) && isTypeCovered(dataDeny, dns.TypeNS) {
				LogInfo(rrt, "DS&NS covered by NSEC. This is not a valid NODATA response.")
				return false
			}
		} else {
			if isTypeCovered(dataDeny, in.Question[0].Qtype) {
				LogInfo(rrt, "Requested type [%s] is covered by NSEC. This is not a valid NODATA response.", dns.TypeToString[in.Question[0].Qtype])
				return false
			}
		}

		deniedRecord = true
	}

	if deniedEnvelope || deniedRecord {
		return true
	}
	return false
}

func validateNSEC3(rrt *ResolverRuntime, in *dns.Msg, currentZone, currentToken string, responseType int) bool {
	LogInfo(rrt, "Entering validateNSEC3()")
	_nsec3s := fetchRRByType(in, dns.TypeNSEC3)
	if _nsec3s == nil {
		/// TODO: add a bit of nuance to this test
		return true
	}
	nsec3s := []*dns.NSEC3{}
	rrNavigator(_nsec3s, func(rr dns.RR) int {
		if n, ok := rr.(*dns.NSEC3); ok {
			nsec3s = append(nsec3s, n)
		}
		return RR_NAVIGATOR_NEXT
	})

	/// algorithm [rfc 7129]: we find the closest encloser, from there we find the next closer NSEC3, and finally we try to cover the wildcard prefixed to the closest encloser
	/// if nothing fails, it means that all is okay
	/// we have 3 cases: nxdomain (3 nsec3s), nodata (1 nsec3), referral with opt-out (2 nsec3, same as nxdomain, without wildcard denial)
	providedClosestEncloserProof, providedWildcardProof, providedRecordNotAvailableProof := false, false, false
	optoutZone := false
	ownerToDeny := currentToken
	if responseType == RESPONSE_REDIRECT_GLUE {
		cnameNS := fetchRRByType(in, dns.TypeNS)
		if len(cnameNS) != 0 {
			ownerToDeny = cnameNS[0].Header().Name
		}
	}
	qname := strings.Split(strings.Trim(ownerToDeny, "."), ".")
	qtype := in.Question[0].Qtype
	closestEncloser, nextCloser := "", ""
	if nsec3s[0].Flags > 0 {
		optoutZone = true
	}
	LogInfo(rrt, "We try to validate NSEC3 using token [%s]", ownerToDeny)
	/// check for matching NSEC3 record
	for _, nsec3 := range nsec3s {
		if nsec3.Match(ownerToDeny) {
			if qtype == dns.TypeNS {
				if !isTypeCovered(nsec3, dns.TypeNS) || !isTypeCovered(nsec3, dns.TypeDS) {
					LogInfo(rrt, "we have found proof that the qtype is not present")
					providedRecordNotAvailableProof = true
					break
				}
			} else {
				if !isTypeCovered(nsec3, qtype) {
					LogInfo(rrt, "we have found proof that the qtype is not present")
					providedRecordNotAvailableProof = true
					break
				}

			}

			LogInfo(rrt, "we found a matching nsec3, and type is covered. this smells fishy, failing")
			return false
		}
	}

	/// we do the closest encloser test
	for i := 0; i < len(qname); i++ {
		for _, nsec3 := range nsec3s {
			closestEncloser = strings.Join(qname[i:], ".") + "."
			if nsec3.Match(closestEncloser) && i > 0 {
				nextCloser = strings.Join(qname[i-1:], ".") + "."
				LogInfo(rrt, "Found CE [%s] and NC [%s]", closestEncloser, nextCloser)
			}
		}
	}

	if closestEncloser != "" {
		for _, nsec3 := range nsec3s {
			if nsec3.Cover(nextCloser) || strings.HasPrefix(nsec3.Hdr.Name, nsec3.NextDomain) {
				providedClosestEncloserProof = true
			}
			if nsec3.Cover("*."+closestEncloser) || strings.HasPrefix(nsec3.Hdr.Name, nsec3.NextDomain) {
				providedWildcardProof = true
			}
		}
	}
	LogInfo(rrt, "We have closestencloser proof [%v] | wildcard proof [%v] | record na [%v]", providedClosestEncloserProof, providedWildcardProof, providedRecordNotAvailableProof)
	switch responseType {
	case RESPONSE_NXDOMAIN:
		LogInfo(rrt, "We have NXDOMAIN, and [%v]&&[%v]", providedClosestEncloserProof, providedWildcardProof)
		return providedClosestEncloserProof && providedWildcardProof
	case RESPONSE_NODATA:
		if in.Question[0].Qtype != dns.TypeDS {
			LogInfo(rrt, "We have NODATA, and [%v]", providedRecordNotAvailableProof)
			return providedRecordNotAvailableProof
		}
		fallthrough
	case RESPONSE_DELEGATION, RESPONSE_DELEGATION_AUTHORITATIVE, RESPONSE_DELEGATION_GLUE, RESPONSE_ANSWER_HIDDEN:
		LogInfo(rrt, "We have DELEGATION, and [this? %v][%v] or [this? %v][%v]", optoutZone, providedClosestEncloserProof, optoutZone, providedRecordNotAvailableProof)
		if optoutZone {
			return providedClosestEncloserProof
		}
		return providedRecordNotAvailableProof
	case RESPONSE_REDIRECT_GLUE:
		return providedRecordNotAvailableProof
	}
	LogInfo(rrt, "Returning, because answer type [%s] is not handled", responseTypeToString[responseType])
	return false
}

func isTypeCovered(nsecN dns.RR, tp uint16) bool {
	switch r := nsecN.(type) {
	case *dns.NSEC:
		for _, rtp := range r.TypeBitMap {
			if tp == rtp {
				return true
			}
		}
	case *dns.NSEC3:
		for _, rtp := range r.TypeBitMap {
			if tp == rtp {
				return true
			}
		}
	}
	return false
}

func commonPrefix(s1, s2 string) (string, int) {
	min := len(s1)
	if len(s2) < len(s1) {
		min = len(s2)
	}
	for i := 0; i < min; i++ {
		if s1[i] != s2[i] {
			return s1[:i], i
		}
	}
	return s1[:min], min
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
	// fmt.Printf("isvalid cache ret? [%v][%v]\n", dnssec, cr)
	if resp, ok := cr.(*dns.Msg); dnssec && ok && resp != nil {
		return true
	} else if rr, ok := cr.([]dns.RR); !dnssec && ok && rr != nil && len(rr) > 0 {
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
	/// if it's not the root level (aka {"."})
	if len(out) > 2 {
		out[0] = "."
	} else {
		out = out[1:]
	}
	return out
}

/// sets up result
func setupResult(rrt *ResolverRuntime, rcode int, opaqueResponse interface{}) (ret *dns.Msg) {
	switch t := opaqueResponse.(type) {
	case [][]dns.RR:
		ret = &dns.Msg{Answer: t[0], Ns: t[1], Extra: t[2]}
	case []dns.RR:
		ret = &dns.Msg{Answer: t}
	case dns.RR: /// single RR means a SOA for nxdomain/nodata responses
		ret = &dns.Msg{Ns: []dns.RR{t}}
	case *dns.Msg:
		//t.Rcode = rcode
		ret = &dns.Msg{MsgHdr: t.MsgHdr, Answer: cloneSection(t.Answer), Ns: cloneSection(t.Ns), Extra: cloneSection(t.Extra)}
	default:
		ret = &dns.Msg{}
	}
	ret.SetRcode(rrt.original, rcode)
	LogInfo(rrt, "Setting up result as answer to Q [%s] Id [%d] RC [%s]\n[%v]\n\n", rrt.original.Question[0].String(), rrt.original.Id, dns.RcodeToString[ret.Rcode], ret)
	return
}

func cloneSection(s []dns.RR) (out []dns.RR) {
	for _, rr := range s {
		out = append(out, dns.Copy(rr))
	}
	return
}

/// handle extras returned by cache (nxdomain or nodata)
func handleExtras(rrt *ResolverRuntime, cacheRet interface{}, extra *runtime.ItemCacheExtra) (ret *dns.Msg, err error, propagate bool) {
	// LogInfo(rrt, "Entering handleExtras() with [%v]", extra)
	/// TODO investigate why it's nil
	if extra == nil {
		return nil, nil, false
	}

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

func handleTLSProbe(rrt *ResolverRuntime, server *entity) {
	m := new(dns.Msg)
	m.SetQuestion(".", dns.TypeNULL)
	c := new(dns.Client)
	hostname := server.name
	if dns.IsFqdn(server.name) {
		hostname = strings.TrimRight(hostname, ".")
	}
	port := "853"
	c.Net = NETWORK_TLS
	c.TLSConfig = common.TLSConfigDNS()
	c.TLSConfig.ServerName = hostname
	c.Timeout = 3 * time.Second
	_, _, err := c.Exchange(m, net.JoinHostPort(server.ip, port))
	if err != nil {
		LogInfo(rrt, "TLSPROBE: error for [%s]: [%s]", server.String(), err.Error())
		rrt.c.Put(rrt.provider, runtime.MapKey(runtime.KV_TLS_CAPABILITY, server.ip), false)
		return
	}
	// logger.debug("DISCOVERY SUCCESS :[%s]: [%s]", target+port, reply.String())
	LogInfo(rrt, "TLSPROBE: success for [%s]", server.String())
	rrt.c.Put(rrt.provider, runtime.MapKey(runtime.KV_TLS_CAPABILITY, server.ip), true)
	return
}

/// setupClient takes care of setting up the transport for the query.
/// Handles TLS capabilities retrieval/storage, udp/tcp preference (based on earlier rate limiting etc)
func setupClient(rrt *ResolverRuntime, server *entity) (c *dns.Client, p string) {
	LogInfo(rrt, "Entering setupClient() with [%v]", server)
	c = new(dns.Client)
	/// retrieve cache network preference of the server. first we check whether it supports tls, if not then tcp,
	/// if not, then default (_probably_ udp)
	c.Net = rrt.prefNet
	p = NetworkToPort[rrt.prefNet]

	tlsCap, ok := rrt.c.GetBool(rrt.provider, runtime.MapKey(runtime.KV_TLS_CAPABILITY, server.ip))
	if ok && tlsCap {
		c.Net = NETWORK_TLS
		p = "853"
		c.TLSConfig = common.TLSConfigDNS()
		if dns.IsFqdn(server.name) {
			c.TLSConfig.ServerName = strings.TrimRight(server.name, ".")
		} else {
			c.TLSConfig.ServerName = server.name
		}
	} else if !ok {
		go handleTLSProbe(rrt, server)
	}

	tcpPref, ok := rrt.c.GetBool(rrt.provider, runtime.MapKey(runtime.KV_TCP_PREFERENCE, server.ip))
	if ok && tcpPref {
		c.Net = NETWORK_TCP
		p = "53"
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
	LogInfo(rrt, "Entering fetchFromCacheOrNetwork() with [%s][%s]", zone, dns.TypeToString[record])
	cacheRes, extra := rrt.c.Retrieve(rrt.provider, zone, record, false)
	/// just return nil

	if extra != nil && (extra.Nxdomain || extra.Nodata) {
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
	networkDS, err := Resolve(NewResolverRuntime(&runtime.Runtime{Cache: rrt.c, IPPool: rrt.p, SlackWH: rrt.f, Stats: rrt.s}, rrt.l, rrt.provider, newDNSQuery(zone, record), rrt.oomAlert, rrt.oomAlert2, rrt.fileLogger))
	if err != nil {
		return nil, err
	} else if networkDS == nil {
		return nil, fmt.Errorf("cannot produce requested record")
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
	LogInfo(rrt, "Entering fetchNSAsENtity() with [%s]/[%v][%v]", zone, resolveNS, resolveA)
	/// do the cache get for NS records
	cacheRet, extra := rrt.c.Retrieve(rrt.provider, zone, dns.TypeNS, false)
	if _, _, p := handleExtras(rrt, cacheRet, extra); p {
		/// return a generic nil
		/// TODO: maybe add signalling for special cases like nxdomain
		return nil
	}
	targetNS := ToNS(cacheRet)

	if targetNS == nil {
		LogInfo(rrt, "fetchNSAsEntity: Cache miss for NS records.")
		/// we are specifically bound not to resolve NS records. nothing more to do here
		if !resolveNS {
			LogInfo(rrt, "fetchNSAsEntity: Returning empty handed (ns resolve forbidden).")
			return nil
		}
		LogInfo(rrt, "fetchNSAsEntity: Retrieving NS records the hard way.")
		resolvedNS, _ := Resolve(NewResolverRuntime(&runtime.Runtime{Cache: rrt.c, IPPool: rrt.p, SlackWH: rrt.f, Stats: rrt.s}, rrt.l, rrt.provider, newDNSQuery(zone, dns.TypeNS), rrt.oomAlert, rrt.oomAlert2, rrt.fileLogger))
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
	LogInfo(rrt, "fetchNSAsEntity: We have NS records for zone [%s]. Checking A records.", zone)
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
		LogInfo(rrt, "fetchNSAsEntity: We have matching A records. Returning.")
		return
	} else if resolveA {
		LogInfo(rrt, "fetchNSAsEntity: No matching A records found for any NS records. Launching resolve")
		return resolveParallelHarness(rrt, targetNS)
	}
	LogInfo(rrt, "fetchNSAsEntity: Returning empty handed")
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

// return an RR array with OPTS removed from Additional section
func cleanAdditionalSection(extra []dns.RR) (clean []dns.RR) {
	rrNavigator(extra, func(rr dns.RR) int {
		if rr.Header().Rrtype != dns.TypeOPT {
			clean = append(clean, rr)
		}
		return RR_NAVIGATOR_NEXT
	})
	return
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

func setupZone(rrt *ResolverRuntime, zone string, targets []*entity) {
	rrt.currentZone = zone
	rrt.targetServers[zone] = targets
}

/// other data helpers

func getRootTrustAnchors(rt *runtime.Runtime, l *logrus.Entry, provider string) error {
	rootDS := make([]dns.RR, 0)

	if provider == PROVIDER_TENTA {
		data, err := http.Get(rootAnchorURL)
		if err != nil {
			return fmt.Errorf("cannot download trust anchor [%s]", err)
		}
		defer data.Body.Close()
		rootCertData, err := ioutil.ReadAll(data.Body)
		if err != nil {
			return fmt.Errorf("cannot read response data [%s]", err)
		}

		r := resultData{}
		if err := xml.Unmarshal([]byte(rootCertData), &r); err != nil {
			return fmt.Errorf("problem during unmarshal. [%s]", err)
		}

		for _, dsData := range r.KeyDigest {
			deleg := new(dns.DS)
			deleg.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 14400, Rdlength: 0}
			deleg.Algorithm = dsData.Algorithm
			deleg.Digest = dsData.Digest
			deleg.DigestType = dsData.DigestType
			deleg.KeyTag = dsData.KeyTag
			rootDS = append(rootDS, deleg)
		}

	} else if provider == PROVIDER_OPENNIC {
		q := newQueryParam(".", dns.TypeDNSKEY, l, new(log.EventualLogger), provider, rt, new(ExchangeHistory))
		krr, e := q.doResolve(resolveMethodFinalQuestion)
		if e != nil {
			return fmt.Errorf("Cannot get opennic root keys. [%s]", e.Error())
		}
		for _, rr := range krr {
			if k, ok := rr.(*dns.DNSKEY); ok {
				rootDS = append(rootDS, k.ToDS(2))
			}
		}
	}
	///storeCache(provider, ".", rootDS)
	rrNavigator(rootDS, func(rr dns.RR) int {
		rt.Cache.Insert(provider, rr.Header().Name, rr, EXTRA_EMPTY)
		return RR_NAVIGATOR_NEXT
	})

	return nil
}

func getZoneAXFR(rt *runtime.Runtime, l *logrus.Entry, provider, zone string) error {
	t := new(dns.Transfer)
	m := new(dns.Msg)
	m.SetAxfr(zone)
	r, e := t.In(m, rootServers[provider][0].ipv4+":53")
	if e != nil {
		return fmt.Errorf("cannot execute zone transfer [%s]", e.Error())
	}

	for env := range r {
		if env.Error != nil {
			l.Infof("Zone transfer envelope error [%s]", env.Error.Error())
			continue
		}
		for _, rr := range env.RR {
			switch rr.(type) {
			case *dns.A, *dns.AAAA, *dns.NS, *dns.DS, *dns.DNSKEY:
				rt.Cache.Insert(provider, rr.Header().Name, rr, EXTRA_EMPTY)
			}
		}

	}

	return nil
}

func LogInfo(rrt *ResolverRuntime, format string, args ...interface{}) {
	if LOGGING == LOGGING_NONE {
		return
	} else if LOGGING == LOGGING_PRINTF {
		fmt.Printf(format+"\n", args...)
		return
	} else if LOGGING == LOGGING_LOGRUS {
		rrt.l.Infof(format, args...)
	} else {
		rrt.fileLogger.WriteString(fmt.Sprintf(format+"\n", args...))
	}
}

func LogError(rrt *ResolverRuntime, format string, args ...interface{}) {
	if LOGGING == LOGGING_NONE {
		return
	} else if LOGGING == LOGGING_PRINTF {
		fmt.Printf(format+"\n", args...)
		return
	} else if LOGGING == LOGGING_LOGRUS {
		rrt.l.Errorf(format, args...)
	} else {
		rrt.fileLogger.WriteString(fmt.Sprintf(format+"\n", args...))
	}
}
