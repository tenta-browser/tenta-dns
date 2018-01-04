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
	"sync"
	"time"

	"github.com/tenta-browser/tenta-dns/common"
	"github.com/tenta-browser/tenta-dns/runtime"

	"github.com/leonelquinteros/gorand"
	"github.com/miekg/dns"
	"github.com/syndtr/goleveldb/leveldb"
)

// Enforcer enforces blacklists.
type Enforcer struct {
	rt  *runtime.Runtime
	cfg runtime.NSnitchConfig
	dns *dns.Client
}

// New returns an initialized blacklist Enforcer.
func New(rt *runtime.Runtime, cfg runtime.NSnitchConfig) *Enforcer {
	return &Enforcer{
		rt:  rt,
		cfg: cfg,
		dns: &dns.Client{
			DialTimeout:  4 * time.Second,
			ReadTimeout:  4 * time.Second,
			WriteTimeout: time.Second,
		},
	}
}

type dnscheckresponse struct {
	list    string
	isError bool
	isFound bool
}

// Check checks an IP address against registered blacklists.
func (e *Enforcer) Check(ip net.IP) *common.BlacklistData {
	// TODO: Add deadline for lookups
	ret := &common.BlacklistData{Results: make(map[string]bool)}
	responses := make(chan *dnscheckresponse)
	wg := &sync.WaitGroup{}
	wg.Add(len(e.cfg.Blacklists))
	for _, rbl := range e.cfg.Blacklists {
		go e.lookup(ip, rbl, responses)
	}
	go func() {
		wg.Wait()
		close(responses)
	}()
	for resp := range responses {
		wg.Done()
		if resp.isError {
			continue
		}
		ret.Results[resp.list] = resp.isFound
		ret.NumberOfLists++
		if resp.isFound {
			ret.NumberFound++
		}
	}
	if ret.NumberFound > 0 {
		ret.OnBlacklist = true
	}
	return ret
}

func ipToURL(ip net.IP, bl string) string {
	// TODO: Add support for IPv6.
	ipparts := strings.Split(ip.String(), ".")
	return fmt.Sprintf("%s.%s.%s.%s.%s.", ipparts[3], ipparts[2], ipparts[1], ipparts[0], bl)
}

type cacheValue int

func (c cacheValue) bytes() []byte {
	return []byte(strconv.Itoa(int(c)))
}

const (
	cvFalse cacheValue = iota
	cvTrue
	cvError
)

func (e *Enforcer) lookup(ip net.IP, rbl string, responder chan<- *dnscheckresponse) {
	url := ipToURL(ip, rbl)
	cachekey := []byte(fmt.Sprintf("rbl/%s", url))

	ret := &dnscheckresponse{list: rbl}
	val, dberr := e.rt.DB.Get(cachekey, nil)
	e.rt.Stats.Tick("database", "get")
	if dberr == nil {
		//fmt.Printf("Blacklist: Loaded %s from cache\n", url)
		if bytes.Equal(val, cvTrue.bytes()) {
			ret.isFound = true
		} else if bytes.Equal(val, cvError.bytes()) {
			ret.isError = true
		}
		responder <- ret
		return
	}
	if dberr != leveldb.ErrNotFound {
		e.rt.Stats.Tick("database", "get_error")
	}

	//fmt.Printf("Blacklist: Doing lookup on %s\n", url)
	m := new(dns.Msg)
	m.SetQuestion(url, dns.TypeA)
	in, _, dnserr := e.dns.Exchange(m, "8.8.8.8:53")
	if dnserr != nil {
		//fmt.Printf("Blacklist: Error performing lookup on %s: %v\n", url, dnserr)
		ret.isError = true
	} else {
		//fmt.Printf("Blacklist: Performed lookup in %d time\n", rtt)
		if in.Rcode == dns.RcodeNameError {
			//fmt.Println("Blacklist: No record found")
			ret.isFound = false
		} else {
			//fmt.Println("Blacklist: Record found")
			ret.isFound = true
		}
	}
	trans, dberr := e.rt.DB.OpenTransaction()
	if dberr != nil {
		responder <- ret
		return
	}
	e.writeCache(trans, cachekey, ret)
}

func (e *Enforcer) writeCache(trans *leveldb.Transaction, k []byte, resp *dnscheckresponse) {
	var v cacheValue
	switch {
	case resp.isError:
		v = cvError
	case resp.isFound:
		v = cvTrue
	default:
		v = cvFalse
	}
	trans.Put(k, v.bytes(), nil)
	key := append([]byte("blacklist/"), []byte(strconv.FormatInt(time.Now().Unix(), 10))...)
	key = append(key, []byte("/")...)
	uuid, _ := gorand.UUID()
	key = append(key, []byte(uuid)...)
	trans.Put(key, k, nil)
	if err := trans.Commit(); err != nil {
		e.rt.Stats.TickN("database", "put_error", 2)
		trans.Discard()
	}
	e.rt.Stats.TickN("database", "put", 2)
}
