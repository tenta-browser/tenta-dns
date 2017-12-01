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
 * geo.go: Geo interface functionality
 */

package runtime

import (
	"fmt"
	"net"
	"path/filepath"
	"github.com/tenta-browser/tenta-dns/common"
	"github.com/tenta-browser/tenta-dns/log"
	"time"

	"github.com/oschwald/maxminddb-golang"
	"github.com/sirupsen/logrus"
)

type responsewrapper struct {
	response *common.GeoLocation
	err      error
}

type Query struct {
	dummy bool
	ip    string
	resp  chan *responsewrapper
	valid bool
}

type ErrResponseTimeout struct {
	s string
}

func (e *ErrResponseTimeout) Error() string {
	return e.s
}

type ErrNotStarted struct{}

func (e *ErrNotStarted) Error() string {
	return "The geo service was configured not to start"
}

type Geo struct {
	dummy   bool
	loaded  bool
	reload  chan bool
	queries chan *Query
	citydb  *maxminddb.Reader
	ispdb   *maxminddb.Reader
	tordb   *TorHash
	lg      *logrus.Entry
}

func StartGeo(cfg Config, rt *Runtime, dummy bool) *Geo {
	g := new(Geo)

	if !dummy {
		g.lg = log.GetLogger("geo")
		g.loaded = false
		g.reload = make(chan bool, 2) // Startup reload + after the updater runs, we might have one pending
		g.queries = make(chan *Query, 1024)

		rt.AddService()
		go geolisten(cfg, rt, g)

		g.Reload()
	} else {
		g.dummy = true
	}
	return g
}

func (g *Geo) Reload() {
	if g.dummy {
		return
	}
	g.lg.Debug("Config reload requested")
	g.reload <- true
}

func (g *Geo) Query(ip string) *Query {
	q := new(Query)
	if !g.dummy {
		q.ip = ip
		q.resp = make(chan *responsewrapper, 1)
		q.valid = true
		g.queries <- q
	} else {
		q.dummy = true
	}
	return q
}

func (q *Query) Response() (*common.GeoLocation, error) {
	if q.dummy {
		return nil, &ErrNotStarted{}
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	select {
	case wrap := <-q.resp:
		return wrap.response, wrap.err
	case <-ticker.C:
		q.valid = false
		return nil, &ErrResponseTimeout{"Timed out waiting for geo response"}
	}
}

func geolisten(cfg Config, rt *Runtime, g *Geo) {
	defer rt.wg.Done()
	g.lg.Debug("Started listener")
	defer func() {
		g.lg.Debug("Shut down")
	}()
	for {
		if g.loaded {
			select {
			case q := <-g.queries:
				if q.valid {
					doQuery(q, g)
				} else {
					g.lg.Debug("Query is no longer valid")
				}
			case <-g.reload:
				g.lg.Debug("Got a command to reload in loaded state")
				doReload(cfg, rt, g)
			case <-rt.stop:
				g.lg.Debug("Got shutdown command in loaded state")
				return
			}
		} else {
			select {
			case <-g.reload:
				g.lg.Debug("Got a command to reload in unloaded state")
				doReload(cfg, rt, g)
			case <-rt.stop:
				g.lg.Debug("Got shutdown command in unloaded state")
				return
			}
		}
	}
}

func doReload(cfg Config, rt *Runtime, g *Geo) {
	g.loaded = false
	g.lg.Info("Doing a reload")
	success := 0

	citykey := fmt.Sprintf(DB_TEMPLATE_VERSION, "GeoIP2-City")
	cityver, err := rt.DBGet([]byte(citykey))
	if err == nil {
		cityfile := filepath.Join(cfg.GeoDBPath, fmt.Sprintf("%s-%s.mmdb", "GeoIP2-City", cityver))
		g.lg.Debugf("Geo: Opening city file %s", cityfile)
		r, err := maxminddb.Open(cityfile)
		if err == nil {
			g.citydb = r
			success += 1
		} else {
			g.lg.Errorf("Failed to open city database %s: %s", cityfile, err.Error())
		}
	}

	ispkey := fmt.Sprintf(DB_TEMPLATE_VERSION, "GeoIP2-ISP")
	ispver, err := rt.DBGet([]byte(ispkey))
	if err == nil {
		ispfile := filepath.Join(cfg.GeoDBPath, fmt.Sprintf("%s-%s.mmdb", "GeoIP2-ISP", ispver))
		g.lg.Debugf("Opening isp file %s", ispfile)
		r, err := maxminddb.Open(ispfile)
		if err == nil {
			g.ispdb = r
			success += 1
		} else {
			g.lg.Errorf("Failed to open isp database %s: %s", ispfile, err.Error())
		}
	}

	if success == 2 {
		g.loaded = true
		g.lg.Info("Reloaded Successfully")
	} else {
		g.lg.Error("Reload failure")
	}
}

func shouldIncludeSubdivision(iso string) bool {
	if iso == "US" || iso == "CA" || iso == "MX" || iso == "IN" || iso == "CN" {
		return true
	}
	return false
}

func doQuery(q *Query, g *Geo) {
	ip := net.ParseIP(q.ip)
	ret := &common.GeoLocation{
		ISP:          &common.ISP{},
		LocationI18n: make(map[string]string, 0),
	}

	ispErr := g.ispdb.Lookup(ip, &ret.ISP)
	if ispErr != nil {
		g.lg.Warnf("ISP error: %s", ispErr.Error())
		ret.ISP = nil
	}
	var record struct {
		Position common.Position `maxminddb:"location"`
		City     struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"city"`
		Subdivisions []struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"subdivisions"`
		Country struct {
			Names   map[string]string `maxminddb:"names"`
			ISOCode string            `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	lookupError := g.citydb.Lookup(ip, &record)
	if lookupError != nil {
		g.lg.Warnf("Lookup error: %s", lookupError.Error())
		ret = nil
	} else {

		ret.Position = &record.Position

		if country, ok := record.Country.Names["en"]; ok {
			ret.Country = country
			for lang, countryName := range record.Country.Names {
				var subdivision string = ""
				if shouldIncludeSubdivision(record.Country.ISOCode) && len(record.Subdivisions) > 0 {
					subdivision, ok = record.Subdivisions[0].Names[lang]
					if !ok {
						subdivision, ok = record.Subdivisions[0].Names["en"]
						if !ok {
							subdivision = ""
						}
					}
				}
				var cityName = ""
				cityName, ok = record.City.Names[lang]
				if !ok {
					cityName, ok = record.City.Names["en"]
					if !ok {
						cityName = ""
					}
				}
				if subdivision != "" {
					countryName = fmt.Sprintf("%s, %s", subdivision, countryName)
				}
				if cityName != "" {
					countryName = fmt.Sprintf("%s, %s", cityName, countryName)
				}
				ret.LocationI18n[lang] = countryName
			}
		}
		if city, ok := record.City.Names["en"]; ok {
			ret.City = city
		}
		if location, ok := ret.LocationI18n["en"]; ok {
			ret.Location = location
		}
		ret.CountryISO = record.Country.ISOCode
	}

	if g.tordb != nil {
		if nodeid, present := g.tordb.Exists(q.ip); present {
			ret.TorNode = &nodeid
		} else {
			ret.TorNode = nil
		}
	}

	wrap := &responsewrapper{
		response: ret,
		err:      lookupError,
	}
	q.resp <- wrap
}
