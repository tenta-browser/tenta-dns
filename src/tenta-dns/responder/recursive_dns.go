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
 * recursor.go: DNS recursor implementation
 */

package responder

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"reflect"
	"runtime/debug"
	"strings"
	nlog "tenta-dns/log"
	"tenta-dns/runtime"
	"time"

	"github.com/miekg/dns"
	"github.com/muesli/cache2go"
	"github.com/sirupsen/logrus"
)

const (
	resolveLogFile = "dns_errors.log"
)

const (
	dnsProviderTenta   = "tenta"
	dnsProviderOpennic = "opennic"
)

const (
	rootAnchorURL = "https://data.iana.org/root-anchors/root-anchors.xml"
)

const (
	cacheHitDomain = iota
	cacheHitTLD
	cacheMiss
)

const (
	lastProblemNXDOMAIN = iota
	lastProblemFORMERR
	lastProblemREFUSED
	lastProblemSERVFAIL
	lastPRoblemTimeout
)

const (
	severitySuccess  = iota /// yeah, success, probably won't be used at all
	severityNuisance        /// error which does not block normal procedures, so handling is not necessary
	severityMajor           /// difference being, handle error, or
	severityFatal           /// exit without question
)

const (
	errorCannotResolve   = iota /// resolve failed, cause propagated upward
	errorCacheMiss              /// it's not exactly an error per se
	errorCacheWriteError        /// generic cache errors
	errorCacheReadError         /// -- || --
	errorCacheTimeFormat        /// time format error
	errorLoopDetected           /// resolving loop
	errorInvalidArgument        /// invalid argument supplied to one of the functions
	errorUnresolvable           /// the domain specified cannot be resolved, as in, somewhere in the stack, an irrevocable NXDOMAIN popped up
	errorDNSSECBogus            /// bogus dnssec-specific record, drop resolve pursuant to rfc considerations
)

const (
	serverCapabilityTrue    = iota /// server supports tls (cache hit)
	serverCapabilityFalse          /// server does not support tls (cache hit)
	serverCapabilityUnknown        /// chache miss
)

const (
	resolveMethodRecursive = iota
	resolveMethodCacheOnly
	resolveMethodFinalQuestion
	resolveMethodRecursiveNonPedantic
)

var (
	request              = func() *string { t := ""; return &t }()    //flag.String("domain", "", "The domain to be looked up. Should be in fqdn form.")
	setup                = func() *bool { t := false; return &t }()   //flag.Bool("setup", false, "Initialization of (quasi-)static data, like DNS root server addresses, database creation etc.")
	clearCache           = func() *bool { t := false; return &t }()   //flag.Bool("clear", false, "Clear the resolver cache")
	queryRecord          = func() *uint { t := uint(1); return &t }() //flag.Uint("record", 1, "Record type to query from the server (default is A) (see list for matching values for RR types)")
	debugLevel           = func() *bool { t := false; return &t }()   //flag.Bool("debug", false, "If set, debug mode is on, full verbosity")
	serverMode           = func() *bool { t := true; return &t }()    //flag.Bool("server", false, "Starts in server mode, listening for incoming dns queries")
	targetNS             = func() *string { t := ""; return &t }()    //flag.String("ns", "", "Resolver to use in client mode")
	targetNSName         = func() *string { t := ""; return &t }()    //flag.String("nshostname", "", "Resolver name to use in client mode")
	certCache            = func() *string { t := ""; return &t }()    //flag.String("certcache", "", "Use the specified path for local certificate cache")
	dnssecEnabled        = func() *bool { t := false; return &t }()   //flag.Bool("dnssec", false, "starts server in dnssec enabled mode")
	forgivingDNSSECCheck = true
	preferredProtocol    = "udp"
	/// TODO -- externalize as a config directive the ips of root servers (both iana and opennic)
	opennicRoots    = []*rootServer{&rootServer{"ns2.opennic.glue", "161.97.219.84", "2001:470:4212:10:0:100:53:1"}}
	ianaRoots       = []*rootServer{&rootServer{"b.root-servers.net", "192.228.79.201", "2001:500:84::b"}}
	rootServers     = map[string][]*rootServer{"tenta": ianaRoots, "opennic": opennicRoots}
	severityLiteral = []string{"Success", "Nuisance", "Major", "Fatal"}
	logger          = newLogger()
	//logFile, _      = os.Create(resolveLogFile)
	/// tools to check for incoming request duplication
	// duplicationCheck = make(map[string]int)
	// duplicationSync  = new(sync.Mutex)
)

type rootServer struct {
	name, ipv4, ipv6 string
}

type historyItem struct {
	server, domain string
	record         uint16
}

type queryParam struct {
	vanilla               string
	tokens                []string
	record, errors        uint16
	continuation          bool
	rangeLimit            int /// index from where to continue
	serverHint            string
	CDFlagSet             bool
	result                []dns.RR
	history               []historyItem
	logBuffer             *bytes.Buffer
	timeWasted            time.Duration
	chainOfTrustIntact    bool
	spawnedFrom           *queryParam
	ilog                  *logrus.Entry        /// this is an instant log, it shows the message instantly
	elog                  *nlog.EventualLogger /// this one will be shown if certain conditions are met
	provider              string
	authority, additional *[]dns.RR
	rt                    *runtime.Runtime
}

/// 2 structs to help parse xml response from iana -- root zone trust anchor
type keyDigestData struct {
	KeyTag     uint16 `xml:"KeyTag"`
	Algorithm  uint8  `xml:"Algorithm"`
	DigestType uint8  `xml:"DigestType"`
	Digest     string `xml:"Digest"`
	//ValidFrom  string `xml:"validFrom,attr"`
}

type resultData struct {
	//Zone      string
	KeyDigest []keyDigestData
}

func (q *queryParam) newContinationParam(rangeLimit int, serverHint string) *queryParam {
	return &queryParam{q.vanilla, q.tokens, q.record, 0, true, rangeLimit, serverHint, q.CDFlagSet, nil, q.history, q.logBuffer, 0, q.chainOfTrustIntact, q, q.ilog, q.elog, q.provider, q.authority, q.additional, q.rt}
}

/// fork-join scheme for lookup continuations
func (q *queryParam) join() {
	if q.spawnedFrom != nil {
		q.spawnedFrom.chainOfTrustIntact = q.chainOfTrustIntact
	}
}

func (q *queryParam) debug(format string, args ...interface{}) {
	// if *debugLevel == false {
	// 	q.logBuffer.WriteString(fmt.Sprintf(format, args...))
	// } else {
	// 	logger.debug(format, args...)

	// }
	q.elog.Queuef(format, args...)
}

func (q *queryParam) setChainOfTrust(b bool) {
	q.debug("Setting [%v] for chain of trust!!!\n", b)
	q.chainOfTrustIntact = b
}

const (
	hexSymbols = "0123456789abcdef"
)

func randHex(length int) (ret string) {
	for i := 0; i < length; i++ {
		ret += string(hexSymbols[rand.Intn(len(hexSymbols))])
	}
	return
}

func (q *queryParam) flushDebugLog(domain string) {
	log, _ := os.Create("logs/" + domain + randHex(5))
	f := bufio.NewWriter(log)
	defer log.Close()
	defer log.Sync()
	defer f.Flush()
	f.Write(q.logBuffer.Bytes())
}

func (q *queryParam) addToResultSet(partial []dns.RR) {
	if q.result == nil {
		q.result = make([]dns.RR, 0)
	}
	q.result = append(q.result, partial...)
}

func (q *queryParam) alreadyTried(new historyItem) bool {
	for _, h := range q.history {
		if h.domain == new.domain && h.server == new.server && h.record == new.record {
			return true
		}
	}
	return false
}

func (q *queryParam) markTried(new historyItem) {
	q.history = append(q.history, new)
}

/// extending logger class for custom debug function
type dnsLogger struct {
	*log.Logger
	ilog *logrus.Entry
}

func newLogger() *dnsLogger {
	return &dnsLogger{log.New(os.Stdout, "tenta-dns: ", log.Ltime|log.Lshortfile), nil}
}

func (l *dnsLogger) debug(format string, args ...interface{}) {
	// if *debugLevel == true {
	// 	l.Printf(format, args...)
	// }
	l.ilog.Infof(format, args...)
}

type dnsError struct {
	error
	errorCode, severity uint16
}

func newError(code, severity uint16, format string, args ...interface{}) *dnsError {
	return &dnsError{fmt.Errorf(format, args), code, severity}
}

func (e *dnsError) String() string {
	return fmt.Sprintf("[%s--%d] %s", severityLiteral[e.severity], e.errorCode, e.error)
}

/// assumes domain is valid (eg. tenta.io, asd.qwe.zxc.lol)
/// dnssec is on by default
func newQueryParam(vanilla string, record uint16, ilog *logrus.Entry, elog *nlog.EventualLogger, provider string, rt *runtime.Runtime) *queryParam {
	if dns.IsFqdn(vanilla) {
		vanilla = vanilla[:len(vanilla)-1]
	}
	temp := strings.Split(vanilla, ".")
	tokens := make([]string, len(temp))
	for i := len(temp) - 1; i >= 0; i-- {
		tokens[len(temp)-i-1] = strings.Join(temp[i:len(temp)], ".") + "."
	}
	return &queryParam{dns.Fqdn(vanilla), tokens, record, 0, false, 0, "", false, nil, make([]historyItem, 0), new(bytes.Buffer), 0, true, nil, ilog, elog, provider, new([]dns.RR), new([]dns.RR), rt}
}

/// define it here for short term clarity
type cacheData struct {
	records []dns.RR
}

/// other than classic dns.RR type (generally used for non-dns specific information caching)
/// also saving the key (just to be sure)
type cacheItem struct {
	key, value string
}

/// TODO -- remove all usage of non-receiver calls to cache
/// provider either tenta or opennic; domain is fqdn form
func storeCache(provider, domain string, _recordLiteral interface{}) (time.Duration, *dnsError) {
	var retDuration time.Duration
	if provider == dnsProviderOpennic || provider == dnsProviderTenta {
		recordLiteral, ok := _recordLiteral.([]dns.RR)
		if !ok {
			/// perhaps too chatty?
			return retDuration, newError(errorInvalidArgument, severityMajor, "invalid argument [%s/%s] expected []RR got %s ", provider, domain, reflect.TypeOf(_recordLiteral).String())
		}
		ulteriorRR := make([]dns.RR, 0)
		ulteriorDomain := make([]string, 0)
		t := cache2go.Cache(provider + "/" + domain)
		lockwait := time.Now()
		retDuration += time.Now().Sub(lockwait)
		for _, rr := range recordLiteral {
			if a, ok := rr.(*dns.A); ok {
				// logger.debug("Trying also to store [%s]\n", fmt.Sprintf("%s.IN-ADDR.ARPA.\t%d\tIN\tPTR\t%s", a.A.String(), a.Hdr.Ttl, domain))
				ptr, err := dns.NewRR(fmt.Sprintf("%s.IN-ADDR.ARPA.\t%d\tIN\tPTR\t%s", a.A.String(), a.Hdr.Ttl, domain))
				if err == nil {
					ulteriorRR = append(ulteriorRR, ptr)
					ulteriorDomain = append(ulteriorDomain, ptr.Header().Name)
				}
			}
			var strToAdd string
			switch rr.(type) {
			case *dns.RRSIG, *dns.DNSKEY, *dns.TSIG, *dns.DS:
				strToAdd = rr.String()
			default:
				strToAdd = strings.ToLower(rr.String())
			}

			t.Add(strToAdd, time.Duration(rr.Header().Ttl+1)*time.Second, nil)
		}

		for i, ptr := range ulteriorRR {
			storeCache(provider, ulteriorDomain[i], []dns.RR{ptr})
		}
	} else if provider == "common" {
		recordLiteral, ok := _recordLiteral.([]cacheItem)
		if !ok {
			// too chatty?
			return retDuration, newError(errorInvalidArgument, severityMajor, "invalid argument [%s/%s] expected []string got %s ", provider, domain, reflect.TypeOf(_recordLiteral).String())
		}
		com := cache2go.Cache(provider + "/" + domain)
		lockwait := time.Now()
		retDuration += time.Now().Sub(lockwait)
		for _, item := range recordLiteral {
			com.Add(item.key, 0, item.value)
		}
	}
	return retDuration, nil
}

func (q *queryParam) storeCache(provider, domain string, _recordLiteral interface{}) (time.Duration, *dnsError) {
	var retDuration time.Duration
	if provider == dnsProviderOpennic || provider == dnsProviderTenta {
		recordLiteral, ok := _recordLiteral.([]dns.RR)
		if !ok {
			/// perhaps too chatty?
			return retDuration, newError(errorInvalidArgument, severityMajor, "invalid argument [%s/%s] expected []RR got %s ", provider, domain, reflect.TypeOf(_recordLiteral).String())
		}
		ulteriorRR := make([]dns.RR, 0)
		ulteriorDomain := make([]string, 0)
		t := cache2go.Cache(provider + "/" + domain)
		lockwait := time.Now()
		retDuration += time.Now().Sub(lockwait)
		for _, rr := range recordLiteral {
			if a, ok := rr.(*dns.A); ok {
				q.debug("Trying also to store [%s]\n", fmt.Sprintf("%s.IN-ADDR.ARPA.\t%d\tIN\tPTR\t%s", a.A.String(), a.Hdr.Ttl, domain))
				ptr, err := dns.NewRR(fmt.Sprintf("%s.IN-ADDR.ARPA.\t%d\tIN\tPTR\t%s", a.A.String(), a.Hdr.Ttl, domain))
				if err == nil {
					ulteriorRR = append(ulteriorRR, ptr)
					ulteriorDomain = append(ulteriorDomain, ptr.Header().Name)
				}
			}

			/// cache duplication protection for records that should be unique
			if rr.Header().Rrtype == dns.TypeSOA || rr.Header().Rrtype == dns.TypeCNAME {
				/// it has an entry for that type of record, so skipping
				if _, _, e := q.retrieveCache(provider, domain, rr.Header().Rrtype); e == nil {
					continue
				}
			}

			// timeBytes, _ := time.Now().Add(time.Duration(rr.Header().Ttl) * time.Second).MarshalText()
			q.debug("Trying to store [%s/%s] [%v] for [%d]\n", provider, domain, rr, rr.Header().Ttl)
			var strToAdd string
			switch rr.(type) {
			case *dns.RRSIG, *dns.DNSKEY, *dns.TSIG, *dns.DS:
				strToAdd = rr.String()
			default:
				strToAdd = strings.ToLower(rr.String())
			}
			t.Add(strToAdd, time.Duration(rr.Header().Ttl+1)*time.Second, q.chainOfTrustIntact)
		}
		for i, ptr := range ulteriorRR {
			q.storeCache(provider, ulteriorDomain[i], []dns.RR{ptr})
		}
	} else if provider == "common" {
		recordLiteral, ok := _recordLiteral.([]cacheItem)
		if !ok {
			// too chatty?
			return retDuration, newError(errorInvalidArgument, severityMajor, "invalid argument [%s/%s] expected []string got %s ", provider, domain, reflect.TypeOf(_recordLiteral).String())
		}
		com := cache2go.Cache(provider + "/" + domain)
		lockwait := time.Now()
		retDuration += time.Now().Sub(lockwait)
		for _, item := range recordLiteral {
			q.debug("saving item: [%s-%s-%s] -> [%s]\n", provider, domain, item.key, item.value)
			//err := b.Put([]byte(item.key), []byte(item.value))
			com.Add(item.key, 0, item.value)
		}
	}
	return retDuration, nil
}

func (q *queryParam) retrieveCache(provider, domain string, recordType uint16) (retrr []dns.RR, retDuration time.Duration, e *dnsError) {
	retrr = make([]dns.RR, 0)
	cacheTab := cache2go.Cache(provider + "/" + domain)
	if provider == dnsProviderTenta || provider == dnsProviderOpennic {
		allTrue := true
		cacheTab.Foreach(func(key interface{}, data *cache2go.CacheItem) {
			rrString, ok := key.(string)
			if data.Data() != nil && data.Data().(bool) == false {
				allTrue = false
			}

			if !ok {
				/// error. handle it.
				return
			}
			rr, err := dns.NewRR(rrString)
			if err != nil {
				return
			}
			/// if record is of desired type, let's put it in the result slice
			/// amended to return saved RRSIG records for the target record
			if rr.Header().Rrtype == recordType || (q.CDFlagSet && rr.Header().Rrtype == dns.TypeRRSIG && rr.(*dns.RRSIG).TypeCovered == recordType) {
				q.debug("[CACHE RET] :: [%s]\n", rr.String())
				inCacheDuration := uint32(time.Now().Sub(data.CreatedOn()).Seconds())
				//q.debug("Adjusting TTL [%d] - [%f][%d]\n", rr.Header().Ttl, data.LifeSpan().Seconds(), uint32(data.LifeSpan().Seconds()))
				rr.Header().Ttl -= inCacheDuration
				retrr = append(retrr, rr)
			}
			/// follow through CNAME redirection, unless of course CNAME is whate we're looking for
			/// but in order for the client to understand the final result, add the CNAME iself to the result set
			if rr.Header().Rrtype == dns.TypeCNAME && recordType != dns.TypeCNAME {
				q.debug("Doing the cname dereference. [%s]->[%s]\n", domain, rr.(*dns.CNAME).Target)
				retrr := append(retrr, rr)
				derefRR, tdur, er := q.retrieveCache(provider, rr.(*dns.CNAME).Target, recordType)
				retDuration += tdur
				if er == nil {
					/// adding CNAME dereference to the final result (for context for the final host/record tuple)
					retrr = append(retrr, derefRR...)
				}
			}

		})

		if !allTrue {
			q.setChainOfTrust(false)
		}
	}
	if len(retrr) == 0 {
		return nil, retDuration, newError(errorCacheReadError, severityMajor, "cache entry not found [%s -- %s]", provider, domain)
	}
	return retrr, retDuration, nil
}

/// ulteriorly, will return a whole RR line (or more, in fact), if matches the type
func retrieveCache(provider, domain string, recordType uint16) (retrr []dns.RR, retDuration time.Duration, e *dnsError) {
	retrr = make([]dns.RR, 0)
	cacheTab := cache2go.Cache(provider + "/" + domain)

	if provider == dnsProviderTenta || provider == dnsProviderOpennic {
		cacheTab.Foreach(func(key interface{}, data *cache2go.CacheItem) {
			rrString, ok := key.(string)
			if !ok {
				/// error. handle it.
				return
			}
			rr, err := dns.NewRR(rrString)
			if err != nil {
				return
			}
			/// if record is of desired type, let's put it in the result slice
			if rr.Header().Rrtype == recordType {
				retrr = append(retrr, rr)
			}
			/// follow through CNAME redirection, unless of course CNAME is whate we're looking for
			/// but in order for the client to understand the final result, add the CNAME iself to the result set
			if rr.Header().Rrtype == dns.TypeCNAME && recordType != dns.TypeCNAME {
				logger.debug("Doing the cname dereference. [%s]->[%s]\n", domain, rr.(*dns.CNAME).Target)
				retrr := append(retrr, rr)
				derefRR, tdur, er := retrieveCache(provider, rr.(*dns.CNAME).Target, recordType)
				retDuration += tdur
				if er == nil {
					/// adding CNAME dereference to the final result (for context for the final host/record tuple)
					retrr = append(retrr, derefRR...)
				}
			}

		})
	}
	if len(retrr) == 0 {
		return nil, retDuration, newError(errorCacheReadError, severityMajor, "cache entry not found [%s -- %s]", provider, domain)
	}
	return retrr, retDuration, nil
}

/// can't really mix this with the RRbased caching, so separate retrieve function for textual data
func retrieveItem(provider, domain, key string) (string, time.Duration, *dnsError) {
	// ret := ""
	var retDuration time.Duration
	// logger.debug("Trying to retrieve [%s-%s-%s]\n", provider, domain, key)
	// lockwait := time.Now()
	cacheTab := cache2go.Cache(provider + "/" + domain)
	value, err := cacheTab.Value(key)
	if err != nil {
		return "", retDuration, newError(errorCacheReadError, severityMajor, "cache read error [%s -- %s -- %s] [%s]", provider, domain, key, err)
	}
	if retString, ok := value.Data().(string); ok {
		return retString, retDuration, nil
	}
	return "", retDuration, newError(errorCacheReadError, severityMajor, "cache entry not found [%s -- %s -- %s]", provider, domain, key)
	// err := db.View(func(tx *bolt.Tx) error {
	// 	retDuration += time.Now().Sub(lockwait)
	// 	pb := tx.Bucket([]byte(provider))
	// 	if pb == nil {
	// 		return newError(errorCacheMiss, severitySuccess, "cache miss [%s]", domain)
	// 	}
	// 	b := pb.Bucket([]byte(domain))
	// 	if b == nil {
	// 		return newError(errorCacheMiss, severitySuccess, "cache miss [%s]", domain)
	// 	}

	// 	ret = string(b.Get([]byte(key)))
	// 	return nil
	// })
	// if err != nil {
	// 	return "", retDuration, newError(errorCacheReadError, severityMajor, "cache entry not found [%s -- %s -- %s]", provider, domain, key)
	// }
	// if ret != "" {
	// 	return ret, retDuration, nil
	// }
	// return "", retDuration, newError(errorCacheReadError, severityMajor, "cache entry not found [%s -- %s -- %s]", provider, domain, key)
}

func verifyServerCertificates(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	concatCerts := make([]byte, 0)
	for _, crtbytes := range rawCerts {
		concatCerts = append(concatCerts, crtbytes...)
	}
	fmtCerts, err := x509.ParseCertificates(concatCerts)
	if err != nil {
		logger.debug("Cannot parse Certificate from peer. [%s]\n", err)
		return nil
	}

	for _, cert := range fmtCerts {
		logger.debug("PEER CERTIFICATE::\n")
		logger.debug("\tSignature algo [%s]\n\tPK algo [%d]\n\tIssuer [%v]\n\tSubject [%v]\n", cert.SignatureAlgorithm.String(), cert.PublicKeyAlgorithm, cert.Issuer, cert.Subject)
	}

	return nil
}

/// helper function to wrap a cache retrieve and error checking
func hasTLSCapability(provider, domain, key string) (time.Duration, int) {
	val, tw, err := retrieveItem(provider, domain, key)
	if err != nil {
		return tw, serverCapabilityUnknown
	}
	if val == "true" {
		return tw, serverCapabilityTrue
	}
	return tw, serverCapabilityFalse
}

/// TODO
func setupDNSClient(client *dns.Client, port *string, target string, tlsCapability int, needsTCP bool, provider string, rt *runtime.Runtime) (tw time.Duration) {
	if tlsCapability == serverCapabilityTrue {
		hostname := target
		// hostnameAvailable := false
		if *targetNSName == "" {
			targetPTR, _tw, err := retrieveCache(provider, target+".IN-ADDR.ARPA.", dns.TypePTR)
			tw += _tw
			if err == nil {
				if ptr, ok := targetPTR[0].(*dns.PTR); ok {
					hostname = ptr.Ptr
					// hostnameAvailable = true
				}
			}
		} else {
			hostname = *targetNSName
			// hostnameAvailable = true
		}
		client.Net = "tcp-tls"
		*port = ":853"
		hostname = strings.TrimRight(hostname, ".")
		client.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS10,
			ServerName: hostname,
			//InsecureSkipVerify:       hostnameAvailable,
			CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			PreferServerCipherSuites: false,
			/// add some cert debugging -> this is cert data save entry point (used solely for debugging now)
			/// VerifyPeerCertificate: verifyServerCertificates,
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
		needsTCP = true

	} else if needsTCP {
		client.Net = "tcp"
		*port = ":53"
	} else {
		client.Net = "udp"
		*port = ":53"
	}

	if needsTCP {
		client.Dialer = rt.IPPool.RandomizeTCPDialer()
	} else {
		client.Dialer = rt.IPPool.RandomizeUDPDialer()
	}

	return
}

/// a simple tls based discovery query
func doTLSDiscovery(target, provider string, rt *runtime.Runtime) (tw time.Duration) {
	m := new(dns.Msg)
	m.SetQuestion(".", dns.TypeNULL)
	c := new(dns.Client)
	port := ""
	setupDNSClient(c, &port, target, serverCapabilityTrue, false, provider, rt)
	//c.Timeout = 3 * time.Second
	_, _, err := c.Exchange(m, target+port)
	if err != nil {
		// logger.debug("DISCOVERY :: ERROR [%s]: [%s]", target+port, err)
		t, err := storeCache("common", target, []cacheItem{cacheItem{key: "hasTLSSupport", value: "false"}})
		tw += t
		if err != nil {
			// logger.debug("Cache store error [%s]\n", err.String())
		}
		return
	}
	/// TODO -- add non-anonymized stats for dns-over-tls support
	// logger.debug("DISCOVERY SUCCESS :[%s]: [%s]", target+port, reply.String())
	/// at this point the query is a success -> save tls cap to cache
	t, derr := storeCache("common", target, []cacheItem{cacheItem{key: "hasTLSSupport", value: "true"}})
	tw += t
	if derr != nil {
		// logger.debug("Cache store error [%s]\n", derr.String())
	}
	return
}

func findMatching(ds *dns.DS, dnskeyArr []*dns.DNSKEY) bool {
	for _, dnskey := range dnskeyArr {
		//fmt.Printf("cmp:: matching\n%s\n%s\n", dnskey.ToDS(ds.DigestType).String(), ds.String())
		if td := dnskey.ToDS(ds.DigestType); td != nil && equalsDS(dnskey.ToDS(ds.DigestType), ds) {
			return true
		}
	}
	return false
}

func findKeyWithTag(ks []*dns.DNSKEY, t uint16) *dns.DNSKEY {
	for _, k := range ks {
		if k.KeyTag() == t {
			return k
		}
	}
	return nil
}

func (q *queryParam) validateSignatures(keyR []*dns.DNSKEY, fullMsg *dns.Msg) error {
	rrMap := make(map[uint16][]dns.RR)
	recordHolder := fullMsg.Answer
	if len(fullMsg.Answer) == 0 {
		recordHolder = fullMsg.Ns
	}
	for _, answer := range recordHolder {
		if rrMap[answer.Header().Rrtype] == nil {
			rrMap[answer.Header().Rrtype] = make([]dns.RR, 0)
		}
		rrMap[answer.Header().Rrtype] = append(rrMap[answer.Header().Rrtype], answer)
	}

	if len(rrMap[dns.TypeRRSIG]) == 0 {
		q.debug("There's no RRSIG in response\n")
		q.setChainOfTrust(false)
		/// will spends some more thoughts as this is an error or not, but right now it's considered a non-error
		return nil
	}

	for _, dnskey := range keyR {
		q.debug("Validating with key [%d][%s]\n", dnskey.KeyTag(), dnskey.String())
	}

	for _, rr := range rrMap[dns.TypeRRSIG] {
		rrsig := rr.(*dns.RRSIG)
		key := findKeyWithTag(keyR, rrsig.KeyTag)
		if key == nil {
			q.debug("Couldn't find matching key for RRSIG [%d]\n", rrsig.KeyTag)
			q.setChainOfTrust(false)
			break
		}

		/// NSEC3 signing is not based on RRSets, but single records (for some uncomprehensible reason)
		if rrsig.TypeCovered != dns.TypeNSEC3 && rrsig.TypeCovered != dns.TypeNSEC {
			if e := rrsig.Verify(key, rrMap[rrsig.TypeCovered]); e != nil {
				q.debug("RRSIG verification failed!!\n")
				q.setChainOfTrust(false)
				return fmt.Errorf("cannot verify rrsig [%s]", rrsig.String())
			}
		} else if rrsig.TypeCovered == dns.TypeNSEC3 {
			isValidRRSIG := false
			/// what we do is basically try to validate all nsec3 records, since the ordering is now _messed up_ (and shouldn't really build on that in the first place either)
			for _, nsec3RR := range rrMap[dns.TypeNSEC3] {
				if nsec3, ok := nsec3RR.(*dns.NSEC3); ok && rrsig.Verify(key, []dns.RR{nsec3}) == nil {
					isValidRRSIG = true
				}
			}

			if !isValidRRSIG {
				q.debug("RRSIG verification failed!!\n")
				q.setChainOfTrust(false)
				return fmt.Errorf("cannot verify rrsig [%s]", rrsig.String())
			}

		} else if rrsig.TypeCovered == dns.TypeNSEC {
			isValidRRSIG := false
			/// what we do is basically try to validate all nsec3 records, since the ordering is now _messed up_ (and shouldn't really build on that in the first place either)
			for _, nsecRR := range rrMap[dns.TypeNSEC] {
				if nsec, ok := nsecRR.(*dns.NSEC); ok && rrsig.Verify(key, []dns.RR{nsec}) == nil {
					isValidRRSIG = true
				}
			}

			if !isValidRRSIG {
				q.debug("RRSIG verification failed!!\n")
				q.setChainOfTrust(false)
				return fmt.Errorf("cannot verify rrsig [%s]", rrsig.String())
			}

		}
	}
	/// check if we broke out of the loop because no key was found
	if q.chainOfTrustIntact == false {
		/// will provide more deb. when necessary
		return fmt.Errorf("cannot find DNSKEY for a keytag")
	}
	/// at this point we have validated all RRSIG records from answer section
	return nil
}

func sliceRRtoDNSKEY(rr []dns.RR) []*dns.DNSKEY {
	if rr == nil || len(rr) == 0 {
		return nil
	}

	ret := make([]*dns.DNSKEY, 0)
	for _, r := range rr {
		ret = append(ret, r.(*dns.DNSKEY))
	}
	return ret
}

func inferCurrentLevel(queryString string, queryType uint16) string {
	var currentLevel string
	ending := ""
	if dns.CountLabel(queryString) == 1 {
		ending = "."
	}
	if queryType == dns.TypeNS {
		if queryString != "." {
			currentLevel = strings.Join(strings.Split(queryString, ".")[1:], ".") + ending
		} else {
			currentLevel = "."
		}
	} else {
		currentLevel = queryString
	}
	return currentLevel
}

/// handles one non-recursive query (object & subject) from a specified target
/// improvement: if server is unknown, do udp (and launch a parallel tls attempt, and save server's attitude towards using tls for future reference)
func (q *queryParam) simpleResolve(object, target string, subject uint16, suggestedTimeout int) (*dns.Msg, time.Duration, *dnsError) {
	/// before anything do the dnssec stuff
	/// if the chain of trust is broken, don't bother tho'
	/// we do this with a breakable if
	/// and we calculate current level in dns hierarchy
	currentLevel := ""
	for q.chainOfTrustIntact && subject != dns.TypeDNSKEY {
		currentLevel = inferCurrentLevel(object, subject)
		/// root zone is level 1
		q.debug("performing dnssec query. for level [%s]\n", currentLevel)
		dsr, _, e := q.simpleResolve(currentLevel, target, dns.TypeDNSKEY, 0)
		//q.debug("DNSSEC query:\n%s\n", dsr.String())
		if e != nil {
			if forgivingDNSSECCheck {
				q.chainOfTrustIntact = false
				break
			}
			return nil, 0, newError(errorCannotResolve, severityFatal, "failed for dnskeys. [%s]", e.String())
		}

		if !q.chainOfTrustIntact {
			break
		}

		k := make([]*dns.DNSKEY, 0)
		krr := make([]dns.RR, 0)
		r := make([]*dns.RRSIG, 0)

		hasSOA := false
		for _, aut := range dsr.Ns {
			if _, ok := aut.(*dns.SOA); ok {
				hasSOA = true
				break
			}
		}

		if len(dsr.Answer) == 0 && hasSOA {
			currentLevel = strings.Join(strings.Split(currentLevel, ".")[1:], ".")
			q.debug("Observed SOA on DNSKEY query. Reached bottom of the stack. means current level is in fact [%s]\n", currentLevel)
			break /// without altering the chain of trust
		}

		for _, ans := range dsr.Answer {
			if kr, ok := ans.(*dns.DNSKEY); ok {
				q.debug("OBTAINED DNSKEY :: [%d][%s]\n", kr.KeyTag(), kr.String())
				k = append(k, kr)
				krr = append(krr, dns.RR(kr))
			} else if rr, ok := ans.(*dns.RRSIG); ok {
				r = append(r, rr)
			}
		}

		/// break chain if composition of reply doesn't match expectations
		if len(k) == 0 || len(r) == 0 {
			q.setChainOfTrust(false)
			q.debug("Breaking chain of trust since either keys or rrsigs are missing!\n")
			break
		}

		/// now we validate DNSKEY RRSIG, and the DNSKEYS present in parent-published DS
		/// first we make sure we have at least one key matching parent DS
		numDSMatched := 0
		q.debug("Retrieving from cache [%s][%s][DS]\n", q.provider, object)
		pubDS, _, e := q.retrieveCache(q.provider, currentLevel, dns.TypeDS)
		/// error is active only when no records are returned
		q.debug("Got %d DS records from cache.\n", len(pubDS))
		if e != nil {
			if forgivingDNSSECCheck {
				q.setChainOfTrust(false)
				break
			}
			return nil, 0, newError(errorCacheMiss, severityMajor, "cannot fetch DS records [%s]", e.String())
		}
		for _, rr := range pubDS {
			pds, ok := rr.(*dns.DS)
			fmt.Printf("Trying to match [%v]\nVS\n[%v]", pds, k)
			if ok && findMatching(pds, k) {
				q.debug("matched!!!\n")
				numDSMatched++
			}
		}
		/// if dnskeys are provided but can't authenticate them by parent ds-es, that smells funny and should bail, as per rfc suggestion
		if numDSMatched == 0 {
			q.debug("Cannot authnticate DNSKEY with parent DS.\n")
			if forgivingDNSSECCheck {
				q.setChainOfTrust(false)
				break
			}
			q.setChainOfTrust(false)
			return nil, 0, newError(errorDNSSECBogus, severityFatal, "bogus DNSSEC records, no match from parent DS")
		}
		/// at this point we have validated the chain from parent to current zone
		/// we can safely store these records in our cache
		_, e = q.storeCache(q.provider, currentLevel, krr)
		if e != nil {
			/// this constitues a less than fatal error, which for this first round breaks normal flow just the same
			if forgivingDNSSECCheck {
				q.setChainOfTrust(false)
				break
			}
			return nil, 0, newError(errorCacheWriteError, severityMajor, "cannot save DNSKEY in cache [%s]", e.String())
		}
		/// next up is: validating current DNSKEY records via RRSIG
		if e := q.validateSignatures(k, dsr); e != nil {
			// if forgivingDNSSECCheck {
			// 	q.setChainOfTrust(false)
			// 	break
			// }
			q.setChainOfTrust(false)
			return nil, 0, newError(errorDNSSECBogus, severityFatal, "bogus dnssec response [%s]", e)
		}

		/// if it's broken, but no error is returned
		if q.chainOfTrustIntact == false {
			break
		}
		/// other stuff to be done?
		break
	}

	message := new(dns.Msg)
	if q.CDFlagSet {
		message.CheckingDisabled = true
	}
	/// send queries with DO flag, irrespective of the status of the chain of trust
	// if q.chainOfTrustIntact {
	message.SetEdns0(4096, *dnssecEnabled)
	// }

	message.SetQuestion(object, uint16(subject))
	/// aka, if it's not used in dig mode, don't request recursion
	if *targetNS == "" {
		message.RecursionDesired = false

	}
	_, targetCap := hasTLSCapability("common", target, "hasTLSSupport")
	q.debug("[%s] TARGET CAP recognized as [%d]\n\n", target, targetCap)
	client := new(dns.Client)

	port := ""
	setupDNSClient(client, &port, target, targetCap, preferredProtocol == "tcp", q.provider, q.rt)

	if targetCap == serverCapabilityUnknown {
		go func() {
			/// duration does not matter here so much
			doTLSDiscovery(target, q.provider, q.rt)
		}()
	}

	//client.Timeout = 5000 * time.Millisecond
	//client.UDPSize = 4096
	client.ReadTimeout = (5 + time.Duration(suggestedTimeout)) * time.Second
	if suggestedTimeout != 0 {
		q.debug("Querying with increaset timeout [%d] seconds", 5+suggestedTimeout)
	}
	reply, rtt, err := client.Exchange(message, target+port)
	q.debug("Question was [%s]\nNet stats: [%s][%s]\n", message.Question[0].String(), target+port, client.Net)
	q.debug(">>> Query response <<<\n%s\n", reply.String())

	/// some cases partial support for EDNS0 can yield a FORMERR to EDNS queries
	/// wiping EDNS0 OPTS from ADDITIONAL section
	if reply != nil && reply.Rcode == dns.RcodeFormatError {
		q.debug("FORMERR caught -- retrying without edns0.\n")
		message.Extra = []dns.RR{}
		reply, rtt, err = client.Exchange(message, target+port)
		q.debug("Question was [%s]\nNet stats: [%s][%s]\n", message.Question[0].String(), target+port, client.Net)
		q.debug(">>> Query response <<<\n%s\n", reply.String())
	}

	// if message is larger than generic udp packet size 512, retry on tcp
	if err == dns.ErrTruncated {
		q.debug("Retrying on TCP. Stay tuned.\n")
		setupDNSClient(client, &port, target, serverCapabilityFalse, true, q.provider, q.rt)
		reply, rtt, err = client.Exchange(message, target+port)
	}

	if err != nil {
		return nil, 0, newError(errorCannotResolve, severityFatal, "simpleResolve failed. [%s]", err)
	}

	switch reply.Rcode {
	case dns.RcodeServerFailure:
		q.errors |= lastProblemSERVFAIL
	case dns.RcodeFormatError:
		q.errors |= lastProblemFORMERR
	case dns.RcodeRefused:
		q.errors |= lastProblemREFUSED
	case dns.RcodeNameError:
		q.errors |= lastProblemNXDOMAIN
	}

	if reply.Rcode == dns.RcodeServerFailure {
		return nil, 0, newError(errorCannotResolve, severityMajor, "simpleResolve got SERVFAIL.")
	} else if reply.Rcode == dns.RcodeRefused {
		return nil, 0, newError(errorCannotResolve, severityMajor, "simpleResolve got REFUSED.")
	}

	q.debug("Dns rountrip time is [%v]\n", rtt)

	for q.chainOfTrustIntact && subject != dns.TypeDNSKEY {
		// currentLevel := inferCurrentLevel(object, subject)
		q.debug("Getting dnskeys for [%s] from cache.\n", currentLevel)
		cachedKeys, _, e := q.retrieveCache(q.provider, currentLevel, dns.TypeDNSKEY)
		if e != nil {
			/// as argued in the dnskey validation phase, take no chances
			/// either dnskeys missing from server altogether (very bad) or missing from cache (slightly bad)
			/// make a lookup for DNSKEY for the specific zone
			// q.debug("LAUNCHING RESOLVE FOR MISSING DNSKEY\n\n\n\n")
			// qkey := newQueryParam(currentLevel, dns.TypeDNSKEY, q.ilog, q.elog, q.provider, q.rt)
			// qkey.setChainOfTrust(false) /// ironically
			// cachedKeys, e = qkey.doResolve(resolveMethodRecursive)
			// q.debug("FINISHING RESOLVE FOR MISSING DNSKEY\n\n\n\n")
			if e != nil && forgivingDNSSECCheck {
				q.setChainOfTrust(false)
				break
			}
			// return nil, 0, newError(errorCacheMiss, severityMajor, "cannot produce DNSKEY from cache [%s]", e.String())
		}
		q.debug("Validating signatures.\n")
		if e := q.validateSignatures(sliceRRtoDNSKEY(cachedKeys), reply); e != nil {
			// if forgivingDNSSECCheck {
			// 	q.setChainOfTrust(false)
			// 	break
			// }
			q.setChainOfTrust(false)
			return nil, 0, newError(errorDNSSECBogus, severityFatal, fmt.Sprintf("bogus dnssec response for [%s] [%s]", object, e.Error()))
		}

		q.debug("Managed to validate all RRSIGS!\n")
		break
	}

	return reply, 0, nil
}

/// scans additional section for further information (any type) about the given record (which has rtype type) -- this is gathering data for caching mostly
func scanAdditionalSection(additional []dns.RR, recordName string, rtype uint16) (ret []dns.RR) {
	ret = make([]dns.RR, 0)
	for _, rr := range additional {
		if rr.Header().Name == recordName {
			ret = append(ret, rr)
		}
	}
	if len(ret) == 0 {
		return nil
	}
	return
}

/// scans additional section for a specified type of record (ttype, `target type`) (mostly A/AAAA) that matches target record which has rtype type
/// returns only one record as it is used for further navigating the flow
func scanAdditionalSectionForType(additional []dns.RR, recordName string, ttype uint16) (ret dns.RR) {
	ret = nil
	for _, rr := range additional {
		// logger.debug("SCAN:: [%s] vs [%s]\n", rr.Header().Name, recordName)
		if rr.Header().Name == recordName && rr.Header().Rrtype == ttype {
			return rr
		}
	}
	return
}

func untangleCNAMEindirections(start string, c []*dns.CNAME) *dns.CNAME {
	if len(c) == 1 {
		return c[0]
	}
	// logger.debug("Untangling [%v]\n", c)
	var current *dns.CNAME
	/// brute force
	for i := 0; i < len(c); i++ {
		for _, cname := range c {
			if cname.Hdr.Name == start {
				start = cname.Target
				current = cname
				break
			}
		}
	}

	// logger.debug("The last one is [%s]\n", current.String())
	return current
}

/// return true of checks out, false otherwise
/// as of this moment it protects against:
/// - injecting loopback address into cache (for a NS) - thus each query would most probably launch an infinite query, if attack is designed well, ergo - dos
/// - injecting other domain's NS records into it's own auth response, diverting traffic to a designated malicious ip
/// - skips NSEC and NSEC3 records, as they pose no threat
func contextIndependentValidateRR(rr dns.RR, domain string) bool {
	/// the first is for basically any record, and the second is for SOA records
	if !dns.IsSubDomain(domain, rr.Header().Name) && !dns.IsSubDomain(rr.Header().Name, domain) && rr.Header().Rrtype != dns.TypeNSEC && rr.Header().Rrtype != dns.TypeNSEC3 {
		// logger.debug("[%s] is not a subdomain of [%s]!!!!\n\n", rr.Header().Name, domain)
		return false
	}
	if a, ok := rr.(*dns.A); ok && a.A.IsLoopback() {
		return false
	}
	return true
}

/// l is a non-nil reference
func populateFallbackServers(t string, l *[]string, rr []dns.RR) {
	*l = make([]string, len(rr))
	for _, r := range rr {
		if a, ok := r.(*dns.A); ok && !existingFallback(t, l, r) {

			*l = append(*l, a.A.String())
		}
	}
}

func insertFallbackServer(t string, l *[]string, rr dns.RR) {
	if *l == nil {
		*l = make([]string, 0)
	}
	if a, ok := rr.(*dns.A); ok && !existingFallback(t, l, rr) {
		*l = append(*l, a.A.String())
	}
}

func existingFallback(t string, l *[]string, rr dns.RR) bool {
	a, ok := rr.(*dns.A)
	if !ok {
		return false
	}
	if t == a.A.String() {
		return false
	}
	for _, item := range *l {
		if item == a.A.String() {
			return true
		}
	}
	return false
}

/// this is the main loop for domain tokens -- returns one ip address or error
func (q *queryParam) doResolve(resolveTechnique int) (resultRR []dns.RR, e *dnsError) {
	targetServer := rootServers[q.provider][0].ipv4
	var fallbackServers []string
	rangelimit := 0
	/// first of all check the cache
	/// check fqdn directly for the target recordtype
	resultRR = make([]dns.RR, 0)
	q.debug("Trying to resolve directly from cache.\n")
	rr, tw, err := q.retrieveCache(q.provider, q.vanilla, q.record)
	q.timeWasted += tw
	if err == nil {
		//return rr.(*dns.A).A.String(), nil
		q.debug("Cache HIT. Returning solution. [%v]")
		return rr, nil
	} else if resolveTechnique == resolveMethodCacheOnly {
		q.debug("Cache miss, and requested cache response only. Returning failure.")
		return nil, err
	}
	/// or check via NS records
	for i := len(q.tokens) - 1; i >= 0; i-- {
		/// let's just handle A records for now (will add CNAME, SOA, negative cache and whatever else in the future)
		tok := q.tokens[i]
		rr, tw, err := q.retrieveCache(q.provider, tok, dns.TypeNS)
		q.timeWasted += tw

		if err != nil {
			continue
		}
		q.debug("Found NS record.")
		ns := rr[0].(*dns.NS)
		rr2, tw, err := q.retrieveCache(q.provider, ns.Ns, dns.TypeA)
		q.timeWasted += tw
		if err != nil {
			/// error checking here (this means real error)
			continue
		}
		a := rr2[0].(*dns.A)
		targetServer = a.A.String()
		for _, nsRR := range rr[1:] {
			rr2, tw, err = q.retrieveCache(q.provider, nsRR.(*dns.NS).Ns, dns.TypeA)
			if err != nil {
				continue
			}
			for _, fallbackRR := range rr2 {
				if _, ok := fallbackRR.(*dns.A); ok {
					insertFallbackServer(targetServer, &fallbackServers, fallbackRR)
				}
			}
		}
		rangelimit = i
		break
	}

	if q.continuation {
		rangelimit = q.rangeLimit
		targetServer = q.serverHint
	}

	if resolveTechnique != resolveMethodFinalQuestion {
		/// main loop for domain tokens
		for i, token := range q.tokens[rangelimit:] {
			/// hacky, but let's check if previous step did get a resolve for this here step
			q.debug("Iteration [%s] of [%s]\n", token, q.vanilla)
			q.debug("Check if solution magically did appear in the cache.\n")
			/// in form of a NS(&A) record for i < len(tokens)
			if i != len(q.tokens)-1 {
				nsrr, tw, _ := q.retrieveCache(q.provider, token, dns.TypeNS)
				q.timeWasted += tw

				if nsrr != nil {
					arr, tw, _ := q.retrieveCache(q.provider, nsrr[0].(*dns.NS).Ns, dns.TypeA)
					q.timeWasted += tw
					if arr != nil {
						q.debug("Skipping step due to already cached value for [%s] -> [%s]\n", token, arr[0].(dns.RR).String())
						targetServer = arr[0].(*dns.A).A.String()
						if len(arr) > 1 {
							populateFallbackServers(targetServer, &fallbackServers, arr[1:])
						}
						continue
					}
				}
			} else { /// target record type otherwise
				arr, tw, err := q.retrieveCache(q.provider, token, q.record)
				q.timeWasted += tw
				if err == nil {
					/// last step, so this is the actual return value
					q.debug("Solution found in cache [%s]\n", token)
					return arr, nil
				}
			}

			q.debug(">>> Querying [%s] about [%s]<<<\n", targetServer, token)

			his := historyItem{server: targetServer, domain: token, record: dns.TypeNS}
			if q.alreadyTried(his) {
				q.debug("HISTORY REPEATING ITSELF!!!!\n\n\n")
				return nil, newError(errorLoopDetected, severityMajor, "loop detected")
			}
			q.markTried(his)
			q.debug("Marking [%v] as tried\n\n\n", his)
			q.debug("Chain of trust is [%v]\n", q.chainOfTrustIntact)
			q.debug("TargetServer is [%s] and backupServers are [%v]\n", targetServer, fallbackServers)

			finalTargetServers := make([]string, 0)
			finalTargetServers = append(finalTargetServers, targetServer)
			finalTargetServers = append(finalTargetServers, fallbackServers...)
			var reply *dns.Msg
			maxIter := 2
			if len(finalTargetServers) < maxIter {
				maxIter = len(finalTargetServers)
			}
			q.errors = 0
			for ind, iteratedTargetServer := range finalTargetServers[:maxIter] {
				reply, tw, err = q.simpleResolve(token, iteratedTargetServer, dns.TypeNS, 0)
				q.timeWasted += tw
				if err != nil {
					if ind < len(finalTargetServers)-1 {
						q.debug("Simpleresolve failed on primary address, falling back.\n")
						continue
					}
					q.debug("Problem found:: [%s]\n", err.String())
					if err.severity > severityNuisance {
						q.debug("Error in siple resolve. returning with error.")
						return nil, err
					}
				} else if len(reply.Answer)+len(reply.Ns) == 0 {
					q.debug("Empty response (ANSWER+AUTHORITY) means try another server")
					continue
				} else {
					break
				}
			}
			oldTargetServer := targetServer
			targetServer = ""
			fallbackServers = nil
			targetHost := make([]string, 0)
			hasNSRecord, hasARecord, hasCNAMERecord, hasSOARecord, hasDSRecord := false, false, false, false, false
			// if all goes well, reply should hold `answer` in authority section (appended with eventual glue records in additional)
			// handle reply being authoritative
			// handle reply in answer or authority
			// handle soa and cname

			/// if reply has answer section (also check for aa flag)
			// recordHolder := reply.Ns
			// if len(reply.Answer) > 0 { // && reply.Authoritative {
			// 	q.debug("We have ANSWERS section populated.\n")
			// 	recordHolder = reply.Answer
			// } else if len(reply.Ns) > 0 {
			// 	q.debug("We have AUTHORITY section populated.\n")
			// 	recordHolder = reply.Ns
			// } else {
			// 	q.debug("Nothing interesting received!!!\n")
			// 	/// hack similar in nature to the SOA response to the partial domain (while querying the full yields result)
			// 	if token == q.vanilla {
			// 		q.debug("Returning since this is the end. My only friend.\n")
			// 		return nil, newError(errorCannotResolve, severityMajor, "no usable response [%s]", token)
			// 	}

			// 	//fmt.Printf("Another trick we can try.\n")
			// 	qc := q.newContinationParam(len(q.tokens)-1, oldTargetServer)
			// 	defer qc.join()
			// 	qc.timeWasted = q.timeWasted
			// 	return qc.doResolve(resolveMethodRecursive)

			// }

			if reply == nil {
				return []dns.RR{}, nil
			}

			recordHolder := make([]dns.RR, 0) //len(reply.Answer)+len(reply.Ns)+len(reply.Extra))
			for _, record := range reply.Answer {
				recordHolder = append(recordHolder, record)
			}
			for _, record := range reply.Ns {
				recordHolder = append(recordHolder, record)
			}
			for _, record := range reply.Extra {
				_, okOPT := record.(*dns.OPT)
				_, okTSIG := record.(*dns.TSIG)
				if !okOPT && !okTSIG {
					recordHolder = append(recordHolder, record)
				}
			}
			q.debug("Record holder has [%d] elements.\n", len(recordHolder))
			foundCNAMEs := make([]*dns.CNAME, 0)

			/// handle the case of NXDOMAIN without accompanying SOA record (<random_alphanum>.dns.grc.com for NS query)
			/// we have to return and empty NXDOMAIN (TODO: do a lookup for SOA to return?)
			if len(recordHolder) == 0 && token == q.vanilla && reply.Rcode == dns.RcodeNameError {
				return []dns.RR{}, newError(errorUnresolvable, severityMajor, "intermediary lookup is NXDOMAIN [%s]", token)
			}

			/// this is a sloppy variant of the return SOA on intermediary queries
			if len(recordHolder) == 0 && token != q.vanilla {
				qc := q.newContinationParam(len(q.tokens)-1, oldTargetServer)
				shortcut, err := qc.doResolve(resolveMethodRecursive)
				if err != nil {
					q.debug("Hail Mary failed [%s]\n", err.String())
				} else {
					defer qc.join()
					q.debug("Tried the good old query-more-tokens-on-nothing trick with success.")
					return shortcut, nil
				}
			}

			for _, rr := range recordHolder {
				/// first of all validate RR
				if !contextIndependentValidateRR(rr, token) {
					/// entry point for ns blacklisting (TODO)
					q.debug("Found malicious RR [%s]. Skipping.\n", rr.String())
					continue
				}
				if ds, ok := rr.(*dns.DS); ok {
					q.debug("Found DS records")
					hasDSRecord = true
					/// store ds records to the child's cache
					_, _ = q.storeCache(q.provider, token, []dns.RR{ds})
				}

				/// check answer being of type NS
				if ns, ok := rr.(*dns.NS); ok {
					tw, _ = q.storeCache(q.provider, ns.Header().Name, []dns.RR{ns})
					q.timeWasted += tw
					hasNSRecord = true
					targetHost = append(targetHost, ns.Ns)
					additional := scanAdditionalSection(reply.Extra, ns.Ns, dns.TypeNS)
					if additional != nil {
						tw, err := q.storeCache(q.provider, ns.Ns, additional)
						q.timeWasted += tw
						if err != nil {
							/// cache not working is nuisance error, as in normal flow is not interrupted
							/// set a context independent signal for ulterior investigation
						}
					} else if resolveTechnique == resolveMethodRecursive {
						/// we have a NS record without glue, so we go ahead and take the time to resolve it
						/// because there are surprisingly many cases in which one NS has A record, and it times out often (logically)
						q.debug("\n\n\nLAUNCHING PEDANTIC INTERMEDIARY RESOLVE FOR [%s]\n\n\n", ns.Ns)
						qIntermediary := newQueryParam(ns.Ns, dns.TypeA, q.ilog, q.elog, q.provider, q.rt)
						additional, e = qIntermediary.doResolve(resolveMethodRecursiveNonPedantic)
						if e != nil {
							q.debug("Cannot resolve intermediary NS [%s]\n", ns.Ns)
						} else {
							q.debug("Intermediary resolve successful!!")
						}
					}

					/// if this is the last step in loop, and NS type records are sought, this is the answer.
					if token == q.vanilla && q.record == dns.TypeNS {
						q.addToResultSet([]dns.RR{ns})
					}

					for _, add := range additional {
						a, ok := add.(*dns.A)
						if !ok {
							continue
						}
						if targetServer == "" {
							targetServer = a.A.String()
						} else {
							insertFallbackServer(targetServer, &fallbackServers, a)
						}
					}
					// special case handling when queried type is NS:
					// adding all NS records to result slice
					// after response loop check again and simply return
					/*
						if targetServer == "" {
							/// check for glue records
							if addRR == nil {
								/// no problem, we resolve it the hard way
								if targetServer == "" {
									logger.debug("Launching a sub-resolve\n\n")
									newq := newQueryParam(ns.Ns)
									targetServer, err = newq.doResolve()
									if err != nil {
										/// okay, this is obviously not good, but let's see if any other records can provide an address to move on
										continue
									}
								}
							}
						}
					*/
					/// check for A answer
				} else if a, ok := rr.(*dns.A); ok {
					hasARecord = true
					tw, _ = q.storeCache(q.provider, a.Header().Name, []dns.RR{a})
					q.timeWasted += tw

					if targetServer == "" {
						targetServer = a.A.String()
					} else {
						insertFallbackServer(targetServer, &fallbackServers, a)
					}
					//tw, _ = q.storeCache(q.provider, reply.Question[0].Name, []dns.RR{a})
					q.timeWasted += tw
				} else if cname, ok := rr.(*dns.CNAME); ok {
					foundCNAMEs = append(foundCNAMEs, cname)
					hasCNAMERecord = true
				} else if soa, ok := rr.(*dns.SOA); ok {
					/// check SOA answer, and check if the name in the record match the name in the question
					/// if so we add one token to the group, and retry same server (as it advertised itself as authority over the zone)
					hasSOARecord = true
					/// experience shows that this trick works for SOA replies other than nxdomain too, so cautiously will remove the if
					//if reply.MsgHdr.Rcode == dns.RcodeNameError {
					/// read: this is not the final form of the domain that is being queried

					/// okay, so, NXDOMAIN for the full domain, this unequivocally means that the domain is unresolvable
					if token == q.vanilla && reply.MsgHdr.Rcode == dns.RcodeNameError {
						/// entry point for negative caching!!! (todo)
						q.debug("Explicit nxdomain found, for full query string. returning immediately.")
						/// transferring this here SOA to the result set
						*q.authority = []dns.RR{rr}
						return nil, newError(errorUnresolvable, severitySuccess, "domain [%s] is unresolvable", q.vanilla)
					}
					nxdomainOnFullString := false
					q.storeCache(q.provider, soa.Hdr.Name, []dns.RR{soa})
					if token != q.vanilla {
						/// add negative cache entry as stated in soa record.
						/// but as learned from 'search.files.bbci.co.uk' example SOA with NXDOMAIN can mean to try again with more tokens in the url for the same NS
						/// this is a gamble (and it really is) so instead of setting the next iteration ip, we launch a separate resolve and check return for success/fail
						/// but first check if this will lead to a loop
						if q.vanilla == soa.Ns {
							continue
						}
						q.debug("Trying a Hail Mary on the SOA NS\n")
						/// do a continuation, or rather, try the full domain name on the same server
						qc := q.newContinationParam(len(q.tokens)-1, oldTargetServer)
						q.timeWasted += qc.timeWasted
						shortcut, err := qc.doResolve(resolveMethodRecursive)
						if err != nil {
							q.debug("Hail Mary failed [%s]\n", err.String())
							if err.errorCode == errorUnresolvable {
								nxdomainOnFullString = true
								*q.authority = *qc.authority
							}
							//continue // as in take the next record from the reply in the big loop
						} else {
							defer qc.join()
							q.debug("Tried the good old query-more-tokens-on-soa trick with success.")
							return shortcut, nil
						}
					}
					/// extend this condition with NXDOMAIN on full query string
					if reply.MsgHdr.Rcode == dns.RcodeNameError || nxdomainOnFullString {
						q.debug("Explicit nxdomain found, for partial query string. adding more tokens did not work. returning with NXDOMAIN.")
						return nil, newError(errorUnresolvable, severitySuccess, "domain [%s] is unresolvable", q.vanilla)
					}

					/// this is the tricky part:
					/// we queried for the full domain, and for a NS record
					/// obviously, the NS said, yeah, i'm the guy you're looking for, and sends a SOA
					/// but that should mean:
					/// 1. reply has no error (aka NOERROR flag)
					/// 2. query string is the full domain
					/// but additionally, we need to check if NS or SOA records are the main queried types too
					/// update: there are some cases in which the SOA.NS is an (yet unknown) alias of one of the nss governing the zone
					/// this would mean, we can break out of the NS loop and try directly the final query from the last NS (this one right here)

					if reply.MsgHdr.Rcode == dns.RcodeSuccess && token == q.vanilla {
						if q.record == dns.TypeNS || q.record == dns.TypeSOA {
							q.addToResultSet([]dns.RR{soa})
						} else {
							/// but before letting this one break out of the loop let's make sure that it's not a CNAME that's waiting at the end of the line
							/// specifically interesting are the cases, when CNAME dereferences are not revealed by any other types of queries, just A
							/// more interesting is the case when a CNAME record is not revealed for a CNAME query, just LITERALLY an A query (not even CNAME, yeah),
							/// so the above code will be modified to do a last-step A query of the current target
							q.debug("Trying to lure out a hidden CNAME. Stay tuned.\n")
							soaCont := q.newContinationParam(i+1, oldTargetServer)
							soaCont.record = dns.TypeA
							soaCNAME, err := soaCont.doResolve(resolveMethodFinalQuestion)
							q.timeWasted += soaCont.timeWasted
							cnameSlice := make([]*dns.CNAME, 0)
							addressSlice := make([]*dns.A, 0)
							q.debug("Luring out ended.\n\n")
							/// means it has no CNAME at the end
							if err != nil {
								if err.errorCode == errorDNSSECBogus {
									q.setChainOfTrust(false)
									return nil, err
								}
								targetServer = oldTargetServer
								break
							} else {
								soaCont.join()
								for _, cnr := range soaCNAME {
									if cn, ok := cnr.(*dns.CNAME); ok {

										cnameSlice = append(cnameSlice, cn)
									}
								}

								for _, cnr := range soaCNAME {
									if a, ok := cnr.(*dns.A); ok {

										addressSlice = append(addressSlice, a)
									}
								}

								if len(cnameSlice) > 0 {
									finalTarget := untangleCNAMEindirections(token, cnameSlice)
									soaDerefCont := newQueryParam(finalTarget.Target, q.record, q.ilog, q.elog, q.provider, q.rt)
									soaDerefRes, err := soaDerefCont.doResolve(resolveMethodRecursive)
									q.logBuffer.Write(soaDerefCont.logBuffer.Bytes())
									q.timeWasted += soaDerefCont.timeWasted
									if err == nil {
										soaDerefRes = append(soaDerefRes, soaCNAME...)
									}
									return soaDerefRes, err
								} else if len(addressSlice) > 0 {

									q.addToResultSet(soaCNAME)
									//q.result = append(q.result, addressSlice...)
									return q.result, nil
								}
							}
							/// if we have only SOA in record holder and target server is still empty (and we already did an A on the same server), return that result set
							if len(recordHolder) == 1 && targetServer == "" {
								return soaCNAME, nil
							}

						}
						targetHost = append(targetHost, soa.Ns)
						q.debug("SOA record's NS entry added as target host.\n [%s]\n", soa.Ns)
					}
				}
			}

			if !hasDSRecord {
				/// no signed delegation present, dropping dnssec from this point forward
				q.debug("breaking chain of trust, no DS records found")
				q.setChainOfTrust(false)
			}

			if (q.record == dns.TypeNS) && token == q.vanilla && (hasNSRecord) {
				q.debug("Returning early because NS/SOA records were queried.\n")
				return q.result, nil
			}
			if (q.record == dns.TypeSOA) && token == q.vanilla && (hasSOARecord) {
				q.debug("Returning early because NS/SOA records were queried.\n")
				return q.result, nil
			}

			if hasCNAMERecord {
				/// moved all CNAME handling until after all of the reply records are read.
				q.debug("second cname handling.[%s][%s][%v]\n", token, q.vanilla, foundCNAMEs)
				cname := untangleCNAMEindirections(token, foundCNAMEs)

				/// do not take partial domain name CNAMES into account, rather retry same server with more domain parts on the left
				/// but there are cases, when the partial domain CNAME is the onl way through, like 'settings.data.microsoft.com'
				/// so creating a continuation for this, and if it yields a result, will use it, otherwise, fall back to partial cname dereference
				if token != q.vanilla {
					// targetServer = oldTargetServer
					// continue
					q.debug("Detected partial domain alias. First trying more tokens on same server, the fallback to this CNAME redirection.\n")
					qcname := q.newContinationParam(len(q.tokens)-1, oldTargetServer)
					q.timeWasted += qcname.timeWasted
					cnameCont, err := qcname.doResolve(resolveMethodRecursive)
					q.debug("partial CNAME block resulted [%v]\n", cnameCont)
					if err == nil {
						defer qcname.join()
						return cnameCont, err
					}

				}

				/// if partial dereference isn't working, let's try partial
				hasCNAMERecord = true
				tw, _ = q.storeCache(q.provider, cname.Header().Name, []dns.RR{cname})
				q.timeWasted += tw
				/// this is not cool, we'll have to resolve the canonical name to get a usable ip address
				q.debug("Going further down the rabbithole, via CNAME redirection [%s]\n", cname.Target)
				newq := newQueryParam(cname.Target, q.record, q.ilog, q.elog, q.provider, q.rt)
				cnameDereference, err := newq.doResolve(resolveMethodRecursive)
				q.logBuffer.Write(newq.logBuffer.Bytes())
				/// this is an aggregated check for no error, and no nxdomain (et al)
				/// but as it turns out (obviously) it is customary to CNAME over partial domains too, so that needs checking too
				/// let's handle error separately, if unresolvable, just continue to the next rr
				/// let's save the CNAME into the result slice
				rrSlice := make([]dns.RR, len(foundCNAMEs))
				for i := range foundCNAMEs {
					rrSlice[i] = foundCNAMEs[i]
				}
				if cnameDereference != nil {
					cnameDereference = append(cnameDereference, rrSlice...)
				}
				q.timeWasted += newq.timeWasted
				return cnameDereference, err

			}

			/// unfortunately answer/authority/additional combo could not lead directly to a next step IP
			if targetServer == "" && len(fallbackServers) == 0 {
				/// check every NS record, as it's possible that the one target host picked does not have a matching A in additional
				if hasNSRecord {
					for _, rr := range recordHolder {
						if ns, ok := rr.(*dns.NS); ok {
							addRR := scanAdditionalSectionForType(reply.Extra, ns.Ns, dns.TypeA)
							if addRR != nil {
								if a, ok := addRR.(*dns.A); ok {
									// logger.debug("Next Step ip found from additional section [%s]:[%s]\n", ns.Ns, a.A.String())
									// targetServer = a.A.String()
									// break
									// so instead of sticking with only one of the servers, let's try out every one of them
									// if this works out, this cuts normal flow in half, and messes up readability and many other things
									// the basic idea being, the big loop basically ends here, and splits into len(authority_section)
									// loops that take off from the next token in the big loop, secventially. the first one to produce a final answer
									// gets propagated through this doResolve instance (if all (or rather, the first) delegated nameservers can yield, then, there's no extra step)
									qc := q.newContinationParam(i+1, a.A.String())
									q.timeWasted += qc.timeWasted
									q.debug("Launching continuation for [%s] via [%s]/[%s][%v][%v]\n\n\n", qc.vanilla, a.Hdr.Name, a.A.String(), qc.chainOfTrustIntact, q.chainOfTrustIntact)
									technique := resolveMethodRecursive
									if token == q.vanilla {
										technique = resolveMethodFinalQuestion
									}
									resultIP, err := qc.doResolve(technique)
									if err != nil {
										q.debug("Continuation [%s] failed for [%s]/[%s].\n\n\n", qc.vanilla, a.Hdr.Name, a.A.String())
										continue
									}
									q.debug("Continuation SUCCESS [%s] for [%s]/[%s].\n\n\n", qc.vanilla, a.Hdr.Name, a.A.String())
									q.setChainOfTrust(qc.chainOfTrustIntact)
									defer qc.join()
									return resultIP, nil
									/// take the long route?
									// targetServer = a.A.String()
									// break

								}
							}
						}
					}
					// if targetServer != "" {
					// 	continue
					// }
				}
				if hasARecord {
					/// this should not be happening
				}
				if hasSOARecord {
				}
				/// if still there's no targetServer (ip)
				q.debug("Trying to retrieve it from cache.\n")
				for _, tHost := range targetHost {
					arr, tw, err := q.retrieveCache(q.provider, tHost, dns.TypeA)
					q.timeWasted += tw
					if err == nil {
						a := arr[0].(*dns.A)
						q.debug("Success from cache.\n")
						targetServer = a.A.String()
						if len(arr) > 1 {
							populateFallbackServers(targetServer, &fallbackServers, arr[1:])
						}
						break
					}
				}

				if targetServer != "" {
					continue
				}

				q.debug("We have to recourse to resolving some things ourselves [%v]\n\n", targetHost)

				for _, tHost := range targetHost {
					if tHost == q.vanilla {
						q.debug("LOOP DETECTED:: bailing.\n")
						//return "", newError(errorLoopDetected, severityMajor, "loop detected for [%s]", targetHost)
						continue
					}

					if tHost != "" {
						q.debug("Trying to resolve eluding host. Launching sub-resolve for [%s]\n\n", tHost)
						/// resolve meaning A record, to be used further
						newq := newQueryParam(tHost, dns.TypeA, q.ilog, q.elog, q.provider, q.rt)
						_targetServer, err := newq.doResolve(resolveMethodRecursive)
						q.logBuffer.Write(newq.logBuffer.Bytes())
						if err != nil {
							/// okay, this is obviously not good, but let's see if any other records can provide an address to move on
							q.debug("Sub-Resolve FAIL >>>[%s]\n\n", tHost)
							continue
						}
						targetServer = _targetServer[0].(*dns.A).A.String()
						if len(_targetServer) > 1 {
							populateFallbackServers(targetServer, &fallbackServers, _targetServer[1:])
						}
						q.debug("Sub-Resolve end >>>[%s]\n\n", tHost)
						q.timeWasted += newq.timeWasted
						/// the fear that the final A query will result in an unhandled CNAME makes this hack a life-saver
						// if token == q.vanilla {
						// 	q.debug("TargetServer found out in last iteration, launching continuation to avoid unhandled CNAME.\n")
						// 	nnewq := q.newContinationParam(len(q.tokens)-1, targetServer)
						// 	defer nnewq.join()
						// 	return nnewq.doResolve(resolveMethodRecursive)
						// }
						break
					}
				}
			}

			/// we did not found the next step IP (in this specific case, the final query IP)
			/// some cases when an authoritative server serves 2 levels (eg. asd.domain.com, and domain.com)
			/// won't reply anything to a NS query for asd.domain.com
			/// this catches that, and diverts execution to final query
			if targetServer == "" && len(recordHolder) == 0 {
				targetServer = oldTargetServer
				break
			}

			/// means we have a serious problem on our hands, we have to bail, and perhaps add a negative cache entry
			if targetServer == "" {
				q.debug("Problem!!!\n")
				return nil, newError(errorCannotResolve, severityMajor, "cannot resolve [%s]", token)
			}

		}
	}
	/// at this point targetServer either should hold the ip of the authority on the domain, or nil (in which case the domain is unresolvable, and a SOA will be requested and a negative cache entry added)
	/// one last query (of the correct type) to ask from the last NS
	if *targetNS != "" {
		targetServer = *targetNS
	}
	finalTargetServers := make([]string, 0)
	finalTargetServers = append(finalTargetServers, targetServer)
	finalTargetServers = append(finalTargetServers, fallbackServers...)
	/// retry policy: trying backup servers has bigger priority than increasing timeout
	wantsToErrorOut := false
	var reply *dns.Msg
	q.debug("TargetServer is [%s] and backupServers are [%v]\n", targetServer, fallbackServers)
	maxIter := 2
	if len(finalTargetServers) < maxIter {
		maxIter = len(finalTargetServers)
	}
	for ind, iteratedTargetServer := range finalTargetServers[:maxIter] {
		q.debug(">>> FINAL - Querying [%s] about [%s]<<<\n", iteratedTargetServer, q.vanilla)
		reply, tw, err = q.simpleResolve(q.vanilla, iteratedTargetServer, q.record, 0)
		q.timeWasted += tw
		if err != nil {
			/// on dnssec validation error, no more chit-chat, just exit with servfail
			if err.errorCode == errorDNSSECBogus {
				q.debug("DNSSEC validation failed. Exiting immediately.\n")
				return nil, err
			}
			if ind < len(finalTargetServers)-1 {
				continue
			}
			q.debug("Problem found:: [%s]\n", err.String())
			if err.severity > severityNuisance {
				/// start secondary timeout recovery
				if strings.HasSuffix(err.Error(), "timeout") {
					wantsToErrorOut = true
					break
				}
				return nil, err
			}
		} else if len(reply.Answer)+len(reply.Ns) == 0 {
			q.debug("Empty response means try another server")
			continue
		} else {
			break
		}
	}
	/// launch queries with shamelessly big timeout, don't exit on error (we're already on borrowed bandwidth)
	if wantsToErrorOut {
		for ind, iteratedTargetServer := range finalTargetServers {
			q.debug(">>> FINAL TIMEOUT RECOVERY - Querying [%s] about [%s]<<<\n", iteratedTargetServer, q.vanilla)
			reply, tw, err = q.simpleResolve(q.vanilla, iteratedTargetServer, q.record, 300)
			if err != nil {
				if ind < len(finalTargetServers)-1 {
					continue
				}
				q.debug("Problem found:: [%s]\n", err.String())
			} else {
				wantsToErrorOut = false
				break
			}
		}
	}

	/// if still hasn't been resolved, return last error
	if wantsToErrorOut {
		return nil, err
	}

	/// due to refused or any other issue that is considered error by simpleResolve()
	/// just return an empty result set
	if reply == nil {
		return []dns.RR{}, nil
	}

	q.debug("CD flag is [%v]\n", q.CDFlagSet)
	// there's no way around it, ned to handle cnames in the final query too
	finalCnames := make([]*dns.CNAME, 0)
	finalCnameRR := make([]dns.RR, 0)
	for _, rr := range reply.Answer {
		/// support ANY queries
		if cname, ok := rr.(*dns.CNAME); ok {
			finalCnames = append(finalCnames, cname)
			finalCnameRR = append(finalCnameRR, rr)
		}
		if rr.Header().Rrtype == q.record || q.record == dns.TypeANY || (q.CDFlagSet && rr.Header().Rrtype == dns.TypeRRSIG && rr.(*dns.RRSIG).TypeCovered == q.record) {
			resultRR = append(resultRR, rr)
		}
		q.storeCache(q.provider, rr.Header().Name, []dns.RR{rr})
	}

	/// if indeed, there has been CNAME records found in the final query (and that's something we weren't expecting)
	if len(finalCnames) > 0 && q.record != dns.TypeCNAME {
		q.debug("Final query CNAME caught, and handled.\n")
		lastCNAME := untangleCNAMEindirections(q.vanilla, finalCnames)
		qfinal := newQueryParam(lastCNAME.Target, q.record, q.ilog, q.elog, q.provider, q.rt)
		//qfinal.addToResultSet(finalCnameRR)
		res, err := qfinal.doResolve(resolveMethodRecursive)
		q.logBuffer.Write(qfinal.logBuffer.Bytes())
		if err == nil {
			res = append(res, finalCnameRR...)
		}
		return res, err
	}

	/// if ANSWER section is empty, return last result (which is 0 answer, and 1 authority (SOA))
	if len(resultRR) == 0 {
		*q.authority = reply.Ns
		fmt.Printf("Copying [%d] records\n", len(reply.Ns)+len(reply.Extra))
		return resultRR, nil
	}

	if q.result == nil {
		q.result = resultRR
	} else {
		q.result = append(q.result, resultRR...)
		resultRR = q.result
	}
	q.debug("\n\n\nFinishing doResolve for [%s] successfully with [%s]\n\n\n", q.vanilla, q.result)
	return resultRR, nil
}

func handleDNSMessage(loggy *logrus.Entry, provider, network string, rt *runtime.Runtime, operatorID string) dnsHandler {

	l := loggy
	return func(w dns.ResponseWriter, r *dns.Msg) {
		startTime := time.Now()
		rt.Stats.Count(StatsQueryTotal)
		if network == "udp" {
			rt.Stats.Count(StatsQueryUDP)
		} else if network == "tcp" {
			rt.Stats.Count(StatsQueryTCP)
		} else if network == "tls" {
			rt.Stats.Count(StatsQueryTLS)
		}
		rt.Stats.Count("dns:queries:all")
		rt.Stats.Count("dns:queries:recursive")
		rt.Stats.Tick("dns", "queries:all")
		rt.Stats.Tick("dns", "queries:recursive")
		rt.Stats.Card(StatsQueryUniqueIps, w.RemoteAddr().String())

		// This domain was seen to be polluting the query.
		// TODO: Configurable fast-drop blacklist
		if strings.Contains(r.Question[0].String(), "vkcache") {
			return
		}

		// drop queries about `local' TLD
		if qtok := strings.Split(r.Question[0].Name, "."); (len(qtok) > 0 && qtok[len(qtok)-1] == "local") || (len(qtok) > 1 && qtok[len(qtok)-2] == "local" && qtok[len(qtok)-1] == "") {
			if network != "udp" {
				w.Close()
			}
			return
		}

		// Check with rate limiter (and save to stats on false)
		if network == "udp" && !w.RemoteAddr().(*net.UDPAddr).IP.IsLoopback() && !rt.RateLimiter.CountAndPass(net.ParseIP(w.RemoteAddr().String())) {
			rt.Stats.Tick("resolver", "throttled")
			rt.Stats.Card(StatsQueryLimitedIps, w.RemoteAddr().String())
			return
		}

		// Don't allow ANY over UDP
		if network == "udp" && r.Question[0].Qtype == dns.TypeANY {
			refuseAny(w, r, rt)
			return
		}

		l = l.WithField("domain", r.Question[0].Name)
		elogger := new(nlog.EventualLogger)
		elogger.Queuef("%v -- STARTING NEW TOPLEVEL RESOLVE FOR [%s][RecDesired - %v]", time.Now(), r.Question[0].Name, r.RecursionDesired)
		qp := newQueryParam(r.Question[0].Name, r.Question[0].Qtype, l, elogger, provider, rt)
		qp.CDFlagSet = r.CheckingDisabled
		resolveMethodToUse := resolveMethodRecursive
		if r.RecursionDesired == false {
			resolveMethodToUse = resolveMethodCacheOnly
		}
		qp.chainOfTrustIntact = *dnssecEnabled
		answer, err := qp.doResolve(resolveMethodToUse)
		resolvTime := time.Now().Sub(startTime)
		response := new(dns.Msg)

		if err != nil {
			elogger.Queuef("RESOLVE RETURNED ERROR [%s]", err.String())
			if err.errorCode != errorUnresolvable {
				elogger.Queuef("Failed for [%s -- %d] - [%s]", qp.vanilla, qp.record, err)
				rt.Stats.Count(StatsQueryFailure)
				response.SetRcode(r, dns.RcodeServerFailure)
				/// supress error messages about failed PTR lookups, and queries with RD unset
				if r.Question[0].Qtype != dns.TypePTR && r.RecursionDesired {
					rt.SlackWH.SendFeedback(runtime.NewPayload(operatorID, fmt.Sprintf("%s [%s/RD=%v/CD=%v]",
						qp.vanilla, dns.TypeToString[r.Question[0].Qtype], r.RecursionDesired, r.CheckingDisabled), err.String(), ""))
				}
			} else {
				elogger.Queuef("[%s -- %d] unresolvable.", qp.vanilla, qp.record)
				response.SetRcode(r, dns.RcodeNameError)
			}
			elogger.Flush(l)
		} else {
			elogger.Queuef("ANSWER is: [%v][%v][%s]", resolvTime, qp.timeWasted, answer)
			response.SetRcode(r, dns.RcodeSuccess)
		}

		response.RecursionAvailable = true
		if qp.chainOfTrustIntact && qp.CDFlagSet != true {
			response.AuthenticatedData = true
		}
		response.Compress = true
		response.Answer = answer
		response.Ns = *qp.authority
		response.Extra = *qp.additional
		response.SetEdns0(4096, false)
		w.WriteMsg(response)
	}
}

func ServeDNS(cfg runtime.RecursorConfig, rt *runtime.Runtime, v4 bool, net string, d *runtime.ServerDomain, opennicMode bool, dnssecMode bool) {
	// TODO: Get rid of these old variables variables
	*dnssecEnabled = dnssecMode
	*debugLevel = true
	provider := "tenta"
	if opennicMode == true {
		provider = "opennic"
	}
	ip, port := hostInfo(v4, net, d)
	addr := fmt.Sprintf("%s:%d", ip, port)
	lg := nlog.GetLogger("dnsrecursor").WithField("host_name", d.HostName).WithField("address", ip).WithField("port", port).WithField("proto", net)
	logger.ilog = lg
	operator := fmt.Sprintf("%s/%s", provider, net)
	rt.SlackWH.SendMessage("started up.", operator)

	notifyStarted := func() {
		lg.Infof("Started %s dns recursor on %s", net, addr)
	}
	lg.Debugf("Preparing %s dns recursor on %s", net, addr)

	pchan := make(chan interface{}, 1)
	srv := &dns.Server{Addr: addr, Net: net, NotifyStartedFunc: notifyStarted, Handler: dns.HandlerFunc(dnsRecoverWrap(handleDNSMessage(lg, provider, net, rt, operator), pchan))}
	defer rt.OnFinishedOrPanic(func() {
		srv.Shutdown()
		lg.Infof("Stopped %s dns resolver on %s", net, addr)
		rt.SlackWH.SendMessage("shutting down.", operator)
	}, pchan)
	defer func() {
		if rcv := recover(); rcv != nil {
			snd := &StackAddedPanic{debug.Stack(), rcv}
			fmt.Printf("Panic in ServeDNS [%s]\n", snd)
			pchan <- snd
		}
	}()

	if dnssecMode {
		if e := getTrustedRootAnchors(lg, provider, rt); e != nil {
			panic(fmt.Sprintf("Cannot obtain root trust anchors. [%v]\n", e))
		}
	}

	transferRootZone(lg, provider)

	if net == "tls" {
		go func() {
			cert, err := tls.LoadX509KeyPair(d.CertFile, d.KeyFile)
			if err != nil {
				lg.Warnf("Failed to setup %s dns resolver on %s for %s: %s", net, addr, d.HostName, err.Error())
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
				lg.Warnf("Failed to setup %s dns resolver on %s for %s: %s", net, addr, d.HostName, err.Error())
			}
		}()
	} else {
		go func() {
			if err := srv.ListenAndServe(); err != nil {
				lg.Warnf("Problem while solving DNS questions: %s", err.Error())
			}
		}()
	}
}
