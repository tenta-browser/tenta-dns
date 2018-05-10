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
	"github.com/sirupsen/logrus"
)

const (
	CACHE_EVICTION_RATE = 30 /// expressed in seconds
	CACHE_OPENNIC       = "opennic"
	CACHE_IANA          = "iana"
)

const (
	KV_TLS_CAPABILITY = "tlscap"
	KV_TCP_PREFERENCE = "tcppref"
)

const (
	ITEM_CACHE_DNSSEC_DESIGNATION = "dnssec-"
)

type DNSCacheHolder struct {
	m map[string]*DNSCache /// multiplexer for multiple insulated caches
}

type DNSCache struct {
	m  *sync.RWMutex           /// global read-write mutex; write is used for map-level operations (INS/DEL keys, cleanup)
	c  *cleanup                /// global cleanup
	l  map[string]*domainCache /// the effective front-facing layer of the cache
	k  *sync.Map               /// key-value store attached to every instance of cache (storing non-RR data)
	lg *logrus.Entry           /// logging
}

type domainCache struct {
	m *sync.RWMutex                         /// ops mutex
	l map[uint16]map[string]opaqueCacheItem /// an RR list/map, in all its splendor
	/// rationale behind using a map (vs list/array) is as follows:
}

type opaqueCacheItem interface {
	isDNSSECStore() bool
	mapKey() string
	keyQType() uint16
	timeCreated() time.Time
	validity() time.Duration
	adjustValidity(int64)
}

type responseCache struct {
	time.Time
	time.Duration
	*dns.Msg
}

type itemCache struct {
	time.Time                     /// time created
	time.Duration                 /// ttl value
	dns.RR                        /// the actual record
	val           *ItemCacheExtra /// other values stored pertaining to the record (DNSSEC situation, etc)
}

type cleanup struct {
	i map[int64][]*cleanupItem /// list of cleanable items (key is unix timestamp)
	t *time.Ticker             /// cleanup interval ticker
	c chan *cleanupItem        /// chan to receive cleanup targets
	q chan bool                /// stop chan
	w *sync.WaitGroup          /// stop wait sync
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

type ItemCacheExtra struct {
	Nxdomain, Nodata, Cname bool
	Redirect                []*dns.CNAME
}

/*
** Opaque Cache Item implementations
 */

func (i *itemCache) isDNSSECStore() bool {
	return false
}

func (i *itemCache) mapKey() string {
	return neutralizeRecord(i.RR)
}

func (i *itemCache) keyQType() uint16 {
	return i.RR.Header().Rrtype
}

func (i *itemCache) timeCreated() time.Time {
	return i.Time
}

func (i *itemCache) validity() time.Duration {
	return i.Duration
}

func (i *itemCache) adjustValidity(delta int64) {
	i.Header().Ttl = uint32(int64(i.Header().Ttl) + delta)
}

func (r *responseCache) isDNSSECStore() bool {
	return true
}

func (r *responseCache) mapKey() string {
	return ITEM_CACHE_DNSSEC_DESIGNATION + dns.TypeToString[r.Question[0].Qtype]
}

func (r *responseCache) keyQType() uint16 {
	return r.Question[0].Qtype
}

func (r *responseCache) timeCreated() time.Time {
	return r.Time
}

func (r *responseCache) validity() time.Duration {
	return r.Duration
}

func (r *responseCache) adjustValidity(delta int64) {
	rrHolder := [][]dns.RR{r.Answer, r.Ns, r.Extra}

	for _, h := range rrHolder {
		for _, rr := range h {
			rr.Header().Ttl = uint32(int64(rr.Header().Ttl) + delta)
		}
	}
}

/*
** Runtime module functions
 */

// StartCache -- Creates, starts and returns a cache object
func StartCache(log *logrus.Entry, designations ...string) *DNSCacheHolder {
	ret := &DNSCacheHolder{make(map[string]*DNSCache)}

	for _, cn := range designations {
		ret.m[cn] = &DNSCache{
			m:  new(sync.RWMutex),
			c:  newCleanup(),
			l:  make(map[string]*domainCache),
			k:  new(sync.Map),
			lg: log.WithField("provider", cn),
		}
	}

	if len(designations) != len(ret.m) {
		log.Fatalf("Supplied %d names out of which only %d is unique.", len(designations), len(ret.m))
		panic("Cannot start cache with ambiguous names")
	}

	for _, c := range ret.m {
		c.startCleanup()
	}

	return ret
}

// Stop -- stops caching (stops cleanup thread)
func (d *DNSCacheHolder) Stop() {
	for _, c := range d.m {
		c.stopCleanup()
	}
}

/*
** KV Store primitives
 */

func (d *DNSCacheHolder) Put(provider, key string, value interface{}) {
	d.m[provider].k.Store(key, value)
}

func (d *DNSCacheHolder) Get(provider, key string) interface{} {
	ret, _ := d.m[provider].k.Load(key)
	return ret
}

func (d *DNSCacheHolder) GetString(provider, key string) (string, bool) {
	ret, ok := d.m[provider].k.Load(key)
	if !ok {
		return "", false
	}
	rets, ok := ret.(string)
	if !ok {
		return "", false
	}
	return rets, true
}

func (d *DNSCacheHolder) GetBool(provider, key string) (bool, bool) {
	ret, ok := d.m[provider].k.Load(key)
	if !ok {
		return false, false
	}
	retb, ok := ret.(bool)
	if !ok {
		return false, false
	}
	return retb, true
}

/*
** Core cache functionalities
 */

func (d *DNSCacheHolder) Insert(provider, domain string, rr dns.RR, extra *ItemCacheExtra) {
	/// concurrent read from a generic map
	if c, ok := d.m[provider]; ok {
		c.insert(domain, rr, extra)
	}
}

func (d *DNSCacheHolder) InsertResponse(provider, domain string, r *dns.Msg) {
	if c, ok := d.m[provider]; ok {
		c.insertResponse(domain, r)
	}
}

func (d *DNSCacheHolder) Retrieve(provider, domain string, t uint16, dnssec bool) (ret interface{}, extra *ItemCacheExtra) {
	if c, ok := d.m[provider]; ok {
		return c.retrieve(domain, t, dnssec)
	}
	return nil, nil
}

func itemCacheFromRR(rr dns.RR, extra *ItemCacheExtra) *itemCache {
	return &itemCache{time.Now(), time.Duration(rr.Header().Ttl) * time.Second, rr, extra}
}

func responseCacheFromMsg(m *dns.Msg) *responseCache {
	minTTL := time.Hour * 72
	rrHolder := [][]dns.RR{m.Answer, m.Ns, m.Extra}

	for _, h := range rrHolder {
		for _, rr := range h {
			if minTTL > time.Duration(rr.Header().Ttl)*time.Second {
				minTTL = time.Duration(rr.Header().Ttl) * time.Second
			}
		}
	}

	return &responseCache{time.Now(), minTTL, m}
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

func (d *DNSCache) insert(domain string, rr dns.RR, extra *ItemCacheExtra) {
	d.insertInternal(domain, itemCacheFromRR(rr, extra))
}

func (d *DNSCache) insertResponse(domain string, resp *dns.Msg) {
	d.insertInternal(domain, responseCacheFromMsg(resp))
}

func (d *DNSCache) insertInternal(domain string, cachee opaqueCacheItem) {
	d.m.Lock()
	dom, ok := d.l[domain]
	if !ok {
		dom = &domainCache{new(sync.RWMutex), make(map[uint16]map[string]opaqueCacheItem)}
		d.l[domain] = dom
	}
	dom.m.Lock()
	defer dom.m.Unlock()
	d.m.Unlock()
	rrtype := cachee.keyQType()
	if _, ok := dom.l[rrtype]; !ok {
		dom.l[rrtype] = make(map[string]opaqueCacheItem)
	}
	dom.l[rrtype][cachee.mapKey()] = cachee
	/// submit item for cleanup
	d.c.c <- &cleanupItem{
		domain, rrtype, cachee.mapKey(),
		time.Now().Unix() +
			int64(cachee.validity()/time.Second)}
}

func (d *DNSCache) retrieve(domain string, t uint16, dnssec bool) (ret interface{}, extra *ItemCacheExtra) {
	d.m.RLock()
	dom, ok := d.l[domain]
	if !ok {
		d.m.RUnlock()
		return
	}
	dom.m.RLock()
	defer dom.m.RUnlock()
	d.m.RUnlock()
	retRegular := []dns.RR{}
	interm := dom.l[t]
	for k, v := range interm {
		/// if item is queried before rounded eviction time
		if v.timeCreated().Add(v.validity()).Before(time.Now()) {
			delete(interm, k)
			continue
		} else { /// if opaque cache item has valid TTL
			if dnssec && v.isDNSSECStore() { /// if we need dnssec and we have a dnssec response, we return *the* response (only one of those per RRtype)
				v.adjustValidity(int64(-time.Now().Sub(v.timeCreated()) / time.Second))
				return v.(*responseCache).Msg, nil
			} else if !dnssec && !v.isDNSSECStore() { /// if we need regular item and we have a RR
				v.adjustValidity(int64(-time.Now().Sub(v.timeCreated()) / time.Second))
				retRegular = append(retRegular, v.(*itemCache).RR)
				if extra == nil && v.(*itemCache).val != nil {
					extra = v.(*itemCache).val
				}
			} else { /// mixed parameters
				continue
			}
		}
	}
	if dnssec {
		return retRegular, extra
	}
	/// return a nil struct pointer so the interface (ptr) itself wouldn't be nil
	var retDummyDnssec *dns.Msg
	return retDummyDnssec, nil
}

/*
** Cache cleanup
 */

func newCleanup() *cleanup {
	return &cleanup{make(map[int64][]*cleanupItem), time.NewTicker(CACHE_EVICTION_RATE * time.Second), make(chan *cleanupItem, 1000),
		make(chan bool, 1), new(sync.WaitGroup), time.Now().Unix()}
}

func (d *DNSCache) startCleanup() {
	d.c.w.Add(1)
	go func() {
		defer d.c.w.Done()
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

func (d *DNSCache) stopCleanup() {
	d.c.q <- true
	d.c.w.Wait()
}

/*
** Helpers and convenience methods
 */
// MapKey -- creates a key-value store key with the given prefix and suffix. (to put simply joins them with a colon char)
func MapKey(prefix, suffix string) string {
	return prefix + ":" + suffix
}

func AsRR(in interface{}) []dns.RR {
	if ret, ok := in.([]dns.RR); ok {
		return ret
	}
	return nil
}

func AsMsg(in interface{}) *dns.Msg {
	if ret, ok := in.(*dns.Msg); ok {
		return ret
	}
	return nil
}
