package zones

import (
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"sort"
)

type ZoneSet map[string]map[uint16][]ZoneEntry // Map from strings to maps from RR_types to ZoneEntry lists

type ZoneEntryType uint8

const (
	ZoneEntryTypeRR ZoneEntryType = iota
	ZoneEntryTypeWeighted
	ZoneEntryTypeNearest
	ZoneEntryTypeGeo
)

type ZoneEntry struct {
	Kind ZoneEntryType
	RR   *dns.RR
}

func NewZoneSet() ZoneSet {
	ret := make(map[string]map[uint16][]ZoneEntry)
	return ret
}

func NewZoneSetItem() map[uint16][]ZoneEntry {
	return make(map[uint16][]ZoneEntry)
}

func (z ZoneSet) PrintToLog(lg *logrus.Entry) {
	urls := make([]string, 0)
	for url, _ := range z {
		urls = append(urls, url)
	}
	sort.Strings(urls)
	for _, url := range urls {
		lg.Debugf("URL '%s'", url)
		item := z[url]
		for kind, elist := range item {
			lg.Debugf("  Kind %s has %d entries", dns.TypeToString[kind], len(elist))
		}
	}
}
