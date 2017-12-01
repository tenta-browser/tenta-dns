package zones

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"tenta-dns/log"

	"github.com/miekg/dns"
)

func LoadZones(path string) (ZoneSet, error) {
	lg := log.GetLogger("zone-parser")

	ret := NewZoneSet()
	files, err := ioutil.ReadDir(path)
	if err != nil {
		lg.Errorf("Unable to open zones path %s: %s", path, err.Error())
		return ret, err
	}

	for _, file := range files {
		lg.Debugf("Found file %s", file.Name())
		match, err := regexp.MatchString("^.*\\.tdns$", file.Name())
		if err == nil && match {
			origin := file.Name()[0 : len(file.Name())-4]
			lg.Infof("Loading zone %s", origin)
			path := filepath.Join(path, file.Name())
			reader, err := os.Open(path)
			if err != nil {
				lg.Errorf("Failed to open file %s: %s", path, err.Error())
				return ret, err
			}
			//			defer reader.Close()
			dns.PrivateHandle("GROUP", TypeGROUP, NewGROUP(lg))
			dns.PrivateHandle("DYNA", TypeDYNA, NewDYNA)
			for tkn := range dns.ParseZone(reader, origin, path) {
				if tkn.Error != nil {
					lg.Errorf("Zone %s: %s", origin, tkn.Error.Error())
					return ret, err
				} else {
					switch tkn.RR.Header().Rrtype {
					case TypeGROUP:
						fallthrough
					case TypeDYNA:
						lg.Debugf("Skipping custom type")
						lg.Debugf("Zone %s: %s [%s]", origin, tkn.RR.String(), tkn.Comment)
						break
					default:
						if len(tkn.Header().Name) < 1 {
							lg.Warnf("Got back a token with an empty name: %s", tkn.RR.String())
							break
						}
						if _, ok := ret[tkn.Header().Name]; !ok {
							ret[tkn.Header().Name] = NewZoneSetItem()
						}
						if _, ok := ret[tkn.Header().Name][tkn.Header().Rrtype]; !ok {
							ret[tkn.Header().Name][tkn.Header().Rrtype] = make([]ZoneEntry, 0)
						}
						ret[tkn.Header().Name][tkn.Header().Rrtype] = append(ret[tkn.Header().Name][tkn.Header().Rrtype], ZoneEntry{ZoneEntryTypeRR, &tkn.RR})
						break
					}
				}
			}
			// It's impossible to exit this loop without going through this finalizer. In the event this changes,
			// care will need to be taken to ensure that the reader is closed and the types are removed.
			dns.PrivateHandleRemove(TypeDYNA)
			dns.PrivateHandleRemove(TypeGROUP)
			reader.Close()
		}
	}

	return ret, nil
}
