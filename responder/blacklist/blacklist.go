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
 * blacklist.go: DNS Blacklist lookups
 */

package blacklist

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
	"github.com/tenta-browser/tenta-dns/common"
	"github.com/tenta-browser/tenta-dns/runtime"
	"time"

	"github.com/leonelquinteros/gorand"
	"github.com/miekg/dns"
	"github.com/syndtr/goleveldb/leveldb"
)

type dnscheckresponse struct {
	list    string
	isError bool
	isFound bool
}

func Checkblacklists(cfg runtime.NSnitchConfig, rt *runtime.Runtime, ip net.IP) *common.BlacklistData {
	// TODO: Add deadline for lookups
	ret := &common.BlacklistData{Results: make(map[string]bool)}
	responses := make(chan *dnscheckresponse)
	started := 0
	for _, rbl := range cfg.Blacklists {
		go lookup(rt, ip, rbl, responses)
		started += 1
	}
	for started > 0 {
		select {
		case response := <-responses:
			started -= 1
			if !response.isError {
				ret.Results[response.list] = response.isFound
				ret.NumberOfLists += 1
				if response.isFound {
					ret.NumberFound += 1
				}
			}
			break
		}
	}
	if ret.NumberFound > 0 {
		ret.OnBlacklist = true
	}
	return ret
}

func lookup(rt *runtime.Runtime, ip net.IP, rbl string, responder chan *dnscheckresponse) {
	ipparts := strings.Split(ip.String(), ".")
	// TODO: IPv6
	url := fmt.Sprintf("%s.%s.%s.%s.%s.", ipparts[3], ipparts[2], ipparts[1], ipparts[0], rbl)
	ret := &dnscheckresponse{list: rbl, isError: false, isFound: false}
	truebyte := []byte("1")
	errbyte := []byte("2")

	cachekey := []byte(fmt.Sprintf("rbl/%s", url))
	val, dberr := rt.DB.Get(cachekey, nil)
	rt.Stats.Tick("database", "get")
	if dberr == nil {
		//fmt.Printf("Blacklist: Loaded %s from cache\n", url)
		if bytes.Equal(val, truebyte) {
			ret.isFound = true
		} else if bytes.Equal(val, errbyte) {
			ret.isError = true
		}
		responder <- ret
		return
	}
	if dberr != leveldb.ErrNotFound {
		rt.Stats.Tick("database", "get_error")
	}

	//fmt.Printf("Blacklist: Doing lookup on %s\n", url)
	m := new(dns.Msg)
	m.SetQuestion(url, dns.TypeA)
	c := new(dns.Client)
	c.DialTimeout = time.Second * 4
	c.ReadTimeout = time.Second * 4
	c.WriteTimeout = time.Second
	in, _, dnserr := c.Exchange(m, "8.8.8.8:53")
	if dnserr != nil {
		fmt.Printf("Blacklist: Error performing lookup on %s: %s\n", url, dnserr.Error())
		ret.isError = true
	} else {
		//fmt.Printf("Blacklist: Performed lookup in %d time\n", rtt)
		if in.Rcode == dns.RcodeNameError {
			//fmt.Printf("Blacklist: No record found\n")
			ret.isFound = false
		} else {
			//fmt.Printf("Blacklist: Record found\n")
			ret.isFound = true
		}
	}
	trans, dberr := rt.DB.OpenTransaction()
	if dberr == nil {
		if ret.isError {
			trans.Put(cachekey, errbyte, nil)
		} else if ret.isFound {
			trans.Put(cachekey, truebyte, nil)
		} else {
			trans.Put(cachekey, []byte("0"), nil)
		}
		key := append([]byte("blacklist/"), []byte(strconv.FormatInt(time.Now().Unix(), 10))...)
		key = append(key, []byte("/")...)
		uuid, _ := gorand.UUID()
		key = append(key, []byte(uuid)...)
		trans.Put(key, cachekey, nil)

		dberr := trans.Commit()
		if dberr != nil {
			rt.Stats.TickN("database", "put_error", 2)
		}
		rt.Stats.TickN("database", "put", 2)
	}
	responder <- ret
}
