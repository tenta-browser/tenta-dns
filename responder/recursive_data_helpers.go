package responder

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/muesli/cache2go"
	"github.com/tenta-browser/tenta-dns/log"
	"github.com/tenta-browser/tenta-dns/runtime"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type ExchangeHistoryItem struct {
	duration                                               time.Duration
	targetIP, targetName, querySubject, queryObject, notes string
}

type ExchangeHistory []*ExchangeHistoryItem

func newExchangeHistoryItem(duration time.Duration, targetIP, targetName, querySubject, queryObject, notes string) *ExchangeHistoryItem {
	return &ExchangeHistoryItem{duration, targetIP, targetName, querySubject, queryObject, notes}
}

func (h *ExchangeHistory) Add(i *ExchangeHistoryItem) {
	*h = append(*h, i)
}

func (h ExchangeHistory) String() (s string) {
	d := time.Duration(0)
	for _, i := range h {
		d += i.duration
		s += fmt.Sprintf("\t[%v][%s[%s]][%s/%s]", i.duration, i.targetIP, i.targetName, i.queryObject, i.querySubject)
		if i.notes != "" {
			s += " - " + i.notes
		}
		s += "\n"
	}
	s += fmt.Sprintf("TOTAL:\t[%v]", d)
	return
}

func EnsureLogDir() {
	os.Mkdir("/tmp/tenta-logs", 0666)
}

func GetLogDir() string {
	return "/tmp/tenta-logs"
}

// Deep equality check for DS records
func equalsDS(a, b *dns.DS) bool {
	if a.Algorithm == b.Algorithm &&
		strings.ToLower(a.Digest) == strings.ToLower(b.Digest) &&
		a.DigestType == b.DigestType &&
		a.KeyTag == b.KeyTag {
		return true
	}
	return false
}

// Download trust anchors
func getTrustedRootAnchors(l *logrus.Entry, provider string, rt *runtime.Runtime) error {
	rootDS := make([]dns.RR, 0)

	if provider == "tenta" {
		data, err := http.Get(rootAnchorURL)
		if err != nil {
			return fmt.Errorf("Trusted root anchor obtain failed [%s]", err)
		}
		defer data.Body.Close()
		rootCertData, err := ioutil.ReadAll(data.Body)
		if err != nil {
			return fmt.Errorf("Cannot read response data [%s]", err)
		}

		r := resultData{}
		if err := xml.Unmarshal([]byte(rootCertData), &r); err != nil {
			return fmt.Errorf("Problem during unmarshal. [%s]", err)
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

	} else if provider == "opennic" {
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
	storeCache(provider, ".", rootDS)

	return nil
}

// Try to transfer the whole root zone in one shot. That'll speed
// things up!
func transferRootZone(l *logrus.Entry, provider string) error {
	t := new(dns.Transfer)
	m := new(dns.Msg)
	m.SetAxfr(".")
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
				storeCache(provider, rr.Header().Name, []dns.RR{rr})
			}
		}

	}

	return nil
}

/// Cache primitives
/// Solves problems:
/// - cache multiplication (ttl should not be part of the search key!)
/// - save PTR IP in reverse order (correctly)
type DomainCache struct {
	CoT bool
	TTL uint32
}

func formatIPAddressReverse(a net.IP) string {
	addr := a.To4()
	return fmt.Sprintf("%d.%d.%d.%d", addr[3], addr[2], addr[1], addr[0])
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
			/// normalize TTLs
			savedTTL := rr.Header().Ttl
			rr.Header().Ttl = 0

			if a, ok := rr.(*dns.A); ok {
				q.debug("Trying also to store [%s]\n", fmt.Sprintf("%s.IN-ADDR.ARPA.\t%d\tIN\tPTR\t%s", formatIPAddressReverse(a.A), savedTTL, domain))
				ptr, err := dns.NewRR(fmt.Sprintf("%s.IN-ADDR.ARPA.\t%d\tIN\tPTR\t%s", formatIPAddressReverse(a.A), savedTTL, domain))
				if err == nil {
					ulteriorRR = append(ulteriorRR, ptr)
					ulteriorDomain = append(ulteriorDomain, ptr.Header().Name)
				}
			}

			/// normalize case-edness
			var strToAdd string
			switch rr.(type) {
			case *dns.RRSIG, *dns.DNSKEY, *dns.TSIG, *dns.DS:
				strToAdd = rr.String()
			default:
				strToAdd = strings.ToLower(rr.String())
			}

			/// cache duplication protection
			/// just a precaution (because saving with 0 ttl _should_ prevent any duplication)
			if _, e := t.Value(strToAdd); e != nil {
				t.Delete(strToAdd)
			}

			q.debug("Trying to store [%s/%s] [%v] for [%d]\n", provider, domain, rr, savedTTL)
			t.Add(strToAdd, time.Duration(savedTTL+1)*time.Second, &DomainCache{q.chainOfTrustIntact, savedTTL})
			rr.Header().Ttl = savedTTL
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
			if !ok || data == nil {
				cacheTab.Delete(key)
				return
			}
			domCache, ok := data.Data().(*DomainCache)
			if !ok {
				q.debug("Cache inconsistency! Deleting key [%s]\n", rrString)
				cacheTab.Delete(key)
				return
			}
			rr, err := dns.NewRR(rrString)
			if err != nil {
				return
			}
			rr.Header().Ttl = domCache.TTL
			inCacheDuration := uint32(time.Now().Sub(data.CreatedOn()).Seconds())
			rr.Header().Ttl -= inCacheDuration
			if rr.Header().Ttl < 0 {
				cacheTab.Delete(key)
				return
			}
			if domCache.CoT == false {
				allTrue = false
			}
			/// if record is of desired type, let's put it in the result slice
			/// amended to return saved RRSIG records for the target record
			if rr.Header().Rrtype == recordType || (q.CDFlagSet && rr.Header().Rrtype == dns.TypeRRSIG && rr.(*dns.RRSIG).TypeCovered == recordType) {
				q.debug("[CACHE RET] :: [%s]\n", rr.String())
				retrr = append(retrr, rr)
			}
			/// follow through CNAME redirection, unless of course CNAME is whate we're looking for
			/// but in order for the client to understand the final result, add the CNAME iself to the result set
			if rr.Header().Rrtype == dns.TypeCNAME && recordType != dns.TypeCNAME {
				q.debug("Doing the cname dereference. [%s]->[%s]\n", domain, rr.(*dns.CNAME).Target)
				retrr = append(retrr, rr)
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
			/// normalize TTLs
			savedTTL := rr.Header().Ttl
			rr.Header().Ttl = 0

			if a, ok := rr.(*dns.A); ok {
				// logger.debug("Trying also to store [%s]\n", fmt.Sprintf("%s.IN-ADDR.ARPA.\t%d\tIN\tPTR\t%s", formatIPAddressReverse(a.A), savedTTL, domain))
				ptr, err := dns.NewRR(fmt.Sprintf("%s.IN-ADDR.ARPA.\t%d\tIN\tPTR\t%s", formatIPAddressReverse(a.A), savedTTL, domain))
				if err == nil {
					ulteriorRR = append(ulteriorRR, ptr)
					ulteriorDomain = append(ulteriorDomain, ptr.Header().Name)
				}
			}

			/// normalize case-edness
			var strToAdd string
			switch rr.(type) {
			case *dns.RRSIG, *dns.DNSKEY, *dns.TSIG, *dns.DS:
				strToAdd = rr.String()
			default:
				strToAdd = strings.ToLower(rr.String())
			}

			/// cache duplication protection
			/// just a precaution (because saving with 0 ttl _should_ prevent any duplication)
			if _, e := t.Value(strToAdd); e != nil {
				t.Delete(strToAdd)
			}

			// logger.debug("Trying to store [%s/%s] [%v] for [%d]\n", provider, domain, rr, savedTTL)
			t.Add(strToAdd, time.Duration(savedTTL+1)*time.Second, &DomainCache{false, savedTTL})
			rr.Header().Ttl = savedTTL
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
			// logger.debug("saving item: [%s-%s-%s] -> [%s]\n", provider, domain, item.key, item.value)
			//err := b.Put([]byte(item.key), []byte(item.value))
			com.Add(item.key, 0, item.value)
		}
	}
	return retDuration, nil
}

/// ulteriorly, will return a whole RR line (or more, in fact), if matches the type
func retrieveCache(provider, domain string, recordType uint16) (retrr []dns.RR, retDuration time.Duration, e *dnsError) {
	retrr = make([]dns.RR, 0)
	cacheTab := cache2go.Cache(provider + "/" + domain)
	if provider == dnsProviderTenta || provider == dnsProviderOpennic {
		cacheTab.Foreach(func(key interface{}, data *cache2go.CacheItem) {
			rrString, ok := key.(string)
			if !ok || data == nil {
				cacheTab.Delete(key)
				return
			}
			domCache, ok := data.Data().(*DomainCache)
			if !ok {
				logger.debug("Cache inconsistency! Deleting key [%s]\n", rrString)
				cacheTab.Delete(key)
				return
			}
			rr, err := dns.NewRR(rrString)
			if err != nil {
				return
			}
			rr.Header().Ttl = domCache.TTL
			inCacheDuration := uint32(time.Now().Sub(data.CreatedOn()).Seconds())
			rr.Header().Ttl -= inCacheDuration
			if rr.Header().Ttl < 0 {
				cacheTab.Delete(key)
				return
			}
			/// if record is of desired type, let's put it in the result slice
			/// amended to return saved RRSIG records for the target record
			if rr.Header().Rrtype == recordType {
				// logger.debug("[CACHE RET] :: [%s]\n", rr.String())
				retrr = append(retrr, rr)
			}
			/// follow through CNAME redirection, unless of course CNAME is whate we're looking for
			/// but in order for the client to understand the final result, add the CNAME iself to the result set
			if rr.Header().Rrtype == dns.TypeCNAME && recordType != dns.TypeCNAME {
				// logger.debug("Doing the cname dereference. [%s]->[%s]\n", domain, rr.(*dns.CNAME).Target)
				retrr = append(retrr, rr)
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
