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
 * cache.go: Cache for dns resolver
 */

package runtime

import (
	"math"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	CACHE_EVICTION_RATE = 30 /// expressed in seconds
)

type DNSCache struct {
	m *sync.RWMutex           /// global read-write mutex; write is used for map-level operations (INS/DEL keys, cleanup)
	c *cleanup                /// global cleanup
	l map[string]*domainCache /// the effective front-facing layer of the cache
}

type domainCache struct {
	m *sync.RWMutex                    /// ops mutex
	l map[uint16]map[string]*itemCache /// an RR list/map, in all its splendor
	/// rationale behind using a map (vs list/array) is as follows:
}

type itemCache struct {
	time.Time                 /// time created
	time.Duration             /// ttl value
	dns.RR                    /// the actual record
	val           interface{} /// other values stored pertaining to the record (DNSSEC situation, etc)
}

type cleanup struct {
	i map[int64][]*cleanupItem /// list of cleanable items (key is unix timestamp)
	t *time.Ticker             /// cleanup interval ticker
	c chan *cleanupItem        /// chan to receive cleanup targets
	q chan bool                /// stop chan
	o int64                    /// origin -- works as a clock skew equalizer -- map keys are synchronized to this value (o + n*INTERVAL);
	/// and at every interval current time is also normalized to this value -- it's updated every cleanup cycle
}

type cleanupItem struct {
	firstKey  string /// key in DNSCache map
	secondKey uint16 /// key in domainCache first map, aka map[uin16]map[string]dns.RR
	///									   					   ^^^^^ this one
	key string /// key in domainCache second map, aka map[uin16]map[string]dns.RR
	///									   						    ^^^^^^ this one
	when int64 /// unix timestamp of when the item is planned for eviction
}

/*
** Runtime module functions
 */
func StartCache() *DNSCache {
	// return &DNSCache{new(sync.RWMutex)}
	return nil
}

/*
** Core cache functionalities
 */

func itemCacheFromRR(rr dns.RR, extra interface{}) *itemCache {
	return &itemCache{time.Now(), time.Duration(rr.Header().Ttl) * time.Second, rr, extra}
}

/// returns a string reprezentation of a resource record, with volatile parts wiped (eg. TTL) for comparison purposes
func neutralizeRecord(rr dns.RR) string {
	t := dns.Copy(rr)
	t.Header().Ttl = 0

	switch rec := t.(type) {
	case *dns.SOA:
		rec.Expire, rec.Minttl, rec.Refresh, rec.Retry = 0, 0, 0, 0
	}

	return t.String()
}

func (d *DNSCache) Insert(domain string, rr dns.RR, extra interface{}) {
	d.insertInternal(domain, neutralizeRecord(rr), itemCacheFromRR(rr, extra))
}

func (d *DNSCache) insertInternal(domain, key string, cachee *itemCache) {
	d.m.Lock()
	dom, ok := d.l[domain]
	if !ok {
		dom = &domainCache{new(sync.RWMutex), make(map[uint16]map[string]*itemCache)}
		d.l[domain] = dom
	}
	dom.m.Lock()
	defer dom.m.Unlock()
	d.m.Unlock()
	rrtype := cachee.RR.Header().Rrtype
	dom.l[rrtype][key] = cachee
	/// submit item for cleanup
	d.c.c <- &cleanupItem{domain, rrtype, key, time.Now().Unix() + int64(cachee.Duration*time.Second)}
}

func (d *DNSCache) Retrieve(domain string, t uint16) (ret []dns.RR) {
	d.m.RLock()
	dom, ok := d.l[domain]
	if !ok {
		d.m.RUnlock()
		return
	}
	dom.m.RLock()
	defer dom.m.RUnlock()
	d.m.RUnlock()

	interm := dom.l[t]
	for k, v := range interm {
		/// if item is queried before rounded eviction time
		if v.Time.Add(v.Duration).Before(time.Now()) {
			delete(interm, k)
			continue
		}
		ret = append(ret, v.RR)
	}
	return
}

/*
** Cache cleanup
 */

func newCleanup() *cleanup {
	return &cleanup{make(map[int64][]*cleanupItem), time.NewTicker(CACHE_EVICTION_RATE * time.Second), make(chan *cleanupItem, 1000), make(chan bool, 1), time.Now().Unix()}
}

func (d *DNSCache) startCleanup() {
	go func() {
		isQuitting := false
		for {
			select {
			/// time for cleanup
			case <-d.c.t.C:
				/// update origin
				d.c.o += CACHE_EVICTION_RATE
				/// get cleanable elements
				evictees := d.c.i[d.c.o]
				/// cycle all elements and remove references to them
				for _, e := range evictees {
					d.m.RLock()
					dom, ok := d.l[e.firstKey]
					if !ok {
						d.m.RUnlock()
						/// this should raise some eyebrows
						continue
					}
					dom.m.Lock()
					d.m.RUnlock()
					/// we delete the key
					delete(dom.l[e.secondKey], e.key)
					/// if we left the type map empty, delete the type index too
					if len(dom.l[e.secondKey]) == 0 {
						delete(dom.l, e.secondKey)
					}
					dom.m.Unlock()
				}
			case <-d.c.q:
				/// maybe a simple return would suffice here?
				isQuitting = true
				break
			case target := <-d.c.c:
				if target.when < d.c.o+CACHE_EVICTION_RATE {
					continue
				}
				index := d.c.o + int64(math.Floor(float64(target.when-d.c.o)/float64(CACHE_EVICTION_RATE)))
				d.c.i[index] = append(d.c.i[index], target)
			}
			if isQuitting == true {
				break
			}
		}
	}()
}
