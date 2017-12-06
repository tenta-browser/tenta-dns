package responder

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

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
