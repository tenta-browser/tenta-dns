/**
 * NSnitch DNS Server
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
	"time"
	"path/filepath"
	"github.com/oschwald/maxminddb-golang"
)

type ISP struct {
	Organization	string	`maxminddb:"organization"json:"organization"`
	ASNumber	uint	`maxminddb:"autonomous_system_number"json:"as_number"`
	ASOrganization	string	`maxminddb:"autonomous_system_organization"json:"as_owner"`
	ISP		string	`maxminddb:"isp"json:"isp"`
}

type Position struct {
	Latitude	float32	`maxminddb:"latitude"json:"latitude"`
	Longitude	float32 `maxminddb:"longitude"json:"longitude"`
	Radius		uint 	`maxminddb:"accuracy_radius"json:"uncertainty_km"`
	TimeZone	string	`maxminddb:"time_zone"json:"time_zone"`
}

type GeoLocation struct {
	Position*	Position      		`json:"position"`
	ISP*		ISP			`json:"network"`
	City		string			`json:"city"`
	Country		string			`json:"country"`
	CountryISO	string			`json:"iso_country"`
	Location	string			`json:"location"`
	LocationI18n	map[string]string	`json:"localized_location"`
	TorNode		*string			`json:"tor_node"`
}

type responsewrapper struct {
	response	*GeoLocation
	err		error
}

type Query struct {
	ip		string
	resp		chan *responsewrapper
	valid		bool
}

type ErrResponseTimeout struct {
	s		string
}
func (e* ErrResponseTimeout) Error() string {
	return e.s
}

type Geo struct {
	loaded		bool
	reload		chan bool
	queries		chan *Query
	citydb		*maxminddb.Reader
	ispdb		*maxminddb.Reader
	tordb		*TorHash
}

func StartGeo(cfg* Config, rt* Runtime) *Geo {
	g := new(Geo)

	g.loaded = false
	g.reload = make(chan bool, 2) // Startup reload + after the updater runs, we might have one pending
	g.queries = make(chan *Query, 1024)

	rt.AddService()
	go geolisten(cfg, rt, g)

	g.Reload()
	return g
}

func (g* Geo) Reload() {
	fmt.Printf("Geo: Reloading Config Requested\n")
	g.reload <- true
}

func (g* Geo) Query(ip string) *Query {
	q := new(Query)
	q.ip = ip
	q.resp = make(chan *responsewrapper, 1)
	q.valid = true
	g.queries <- q
	return q
}

func (q* Query) Response() (*GeoLocation, error) {
	ticker :=  time.NewTicker(50*time.Millisecond)
	defer ticker.Stop()
	select {
	case wrap:=<-q.resp:
		return wrap.response, wrap.err
	case <-ticker.C:
		q.valid = false
		return nil,&ErrResponseTimeout{"Timed out waiting for geo response"}
	}
}

func geolisten(cfg* Config, rt* Runtime, g* Geo) {
	defer rt.wg.Done()
	fmt.Printf("Geo: Starting listener\n")
	defer func() {
		fmt.Printf("Geo: Shut down\n")
	}()
	for {
		if g.loaded {
			select {
			case q := <-g.queries:
				//fmt.Printf("Geo: Got a query for %s\n", q.ip)
				if (q.valid) {
					doQuery(q, g)
				} else {
					fmt.Printf("Geo: Query is no longer valid\n")
				}
			case <-g.reload:
				fmt.Printf("Geo: Got a command to reload in loaded state\n")
				doReload(cfg, rt, g)
			case <-rt.stop:
				fmt.Printf("Geo: Got shutdown command in loaded state\n")
				return
			}
		} else {
			select {
			case <-g.reload:
				fmt.Printf("Geo: Got a command to reload in unloaded state\n")
				doReload(cfg, rt, g)
			case <-rt.stop:
				fmt.Printf("Geo: Got shutdown command in unloaded state\n")
				return
			}
		}
	}
}

func doReload(cfg* Config, rt* Runtime, g* Geo) {
	g.loaded = false
	fmt.Printf("Geo: Doing a reload\n")
	success := 0

	citykey := fmt.Sprintf(DB_TEMPLATE_VERSION, "GeoIP2-City")
	cityver, err := rt.DBGet([]byte(citykey))
	if (err == nil) {
		cityfile := filepath.Join(cfg.GeoDBPath, fmt.Sprintf("%s-%s.mmdb", "GeoIP2-City", cityver))
		fmt.Printf("Geo: Opening city file %s\n", cityfile)
		r, err := maxminddb.Open(cityfile)
		if (err == nil) {
			g.citydb = r
			success += 1
		} else {
			fmt.Printf("Geo: Failed to open city database: %s", err.Error())
		}
	}

	ispkey := fmt.Sprintf(DB_TEMPLATE_VERSION, "GeoIP2-ISP")
	ispver, err := rt.DBGet([]byte(ispkey))
	if (err == nil) {
		ispfile := filepath.Join(cfg.GeoDBPath, fmt.Sprintf("%s-%s.mmdb", "GeoIP2-ISP", ispver))
		fmt.Printf("Geo: Opening isp file %s\n", ispfile)
		r, err := maxminddb.Open(ispfile)
		if (err == nil) {
			g.ispdb = r
			success += 1
		} else {
			fmt.Printf("Geo: Failed to open isp database: %s\n", err.Error())
		}
	}

	if success == 2 {
		g.loaded = true
		fmt.Printf("Geo: Reloaded Successfully\n")
	} else {
		fmt.Printf("Geo: Reload failure\n")
	}
}

func ShouldIncludeSubdivision(iso string) bool {
	if (iso == "US" || iso == "CA" || iso == "MX" || iso == "IN" || iso == "CN") {
		return true
	}
	return false
}

func doQuery(q* Query, g* Geo) {
	ip := net.ParseIP(q.ip)
	ret := &GeoLocation{
		ISP: &ISP{},
		LocationI18n: make(map[string]string,0),
	}

	ispErr := g.ispdb.Lookup(ip, &ret.ISP)
	if ispErr != nil {
		fmt.Println(ispErr.Error())
		ret.ISP = nil
	}
	var record struct {
		Position Position `maxminddb:"location"`
		City struct {
			Names	map[string]string `maxminddb:"names"`
		} `maxminddb:"city"`
		Subdivisions[] struct {
			Names	map[string]string `maxminddb:"names"`
		} `maxminddb:"subdivisions"`
		Country struct {
			Names	map[string]string `maxminddb:"names"`
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	lookupError := g.citydb.Lookup(ip, &record)
	if lookupError != nil {
		fmt.Println(lookupError.Error())
		ret = nil
	} else {

		ret.Position = &record.Position

		if country, ok := record.Country.Names["en"]; ok {
			ret.Country = country
			for lang, countryName := range record.Country.Names {
				var subdivision string = ""
				if ShouldIncludeSubdivision(record.Country.ISOCode) && len(record.Subdivisions) > 0 {
					subdivision, ok = record.Subdivisions[0].Names[lang]
					if !ok {
						subdivision, ok = record.Subdivisions[0].Names["en"]
						if !ok {
							subdivision = ""
						}
					}
				}
				var cityName= ""
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

	if (g.tordb != nil) {
		if nodeid, present := g.tordb.Exists(q.ip); present {
			ret.TorNode = &nodeid
		} else {
			ret.TorNode = nil
		}
	}

	wrap := &responsewrapper{
		response: ret,
		err: lookupError,
	}
	q.resp<-wrap
}