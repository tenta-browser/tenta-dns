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
 * limiter.go: Rate limiter implementation
 */

package runtime

import (
	"math"
	"math/rand"
	"net"
	"sync"
	"tenta-dns/log"
	"time"

	"github.com/sirupsen/logrus"
)

const UPDATE_DELAY = time.Minute

type Limiter struct {
	limits    map[string]uint64
	limitLock *sync.RWMutex
	sender    chan string
	stop      chan bool
	wg        *sync.WaitGroup
	tables    [5]map[string]uint64
	offset    uint64
	lg        *logrus.Entry
	v4mask    net.IPMask
	v6mask    net.IPMask
}

func StartLimiter(offset uint64) *Limiter {
	ret := &Limiter{}
	ret.offset = offset
	ret.lg = log.GetLogger("limiter")
	ret.sender = make(chan string, 16384)
	ret.limitLock = &sync.RWMutex{}
	ret.limits = make(map[string]uint64)
	ret.tables = [5]map[string]uint64{}
	ret.v4mask = net.CIDRMask(24, 32)
	ret.v6mask = net.CIDRMask(40, 128)
	ret.stop = make(chan bool)
	ret.wg = &sync.WaitGroup{}
	ret.wg.Add(1)
	go countlimits(ret)
	return ret
}

func (l *Limiter) Stop() {
	defer l.wg.Wait()
	l.stop <- true
}

func (l *Limiter) Count(key string) {
	select {
	case l.sender <- key:
		break
	case <-time.After(time.Millisecond):
		l.lg.Debug("Skipping count due to chan overflow")
		break
	}
}

func (l *Limiter) CountAndPass(ip net.IP) bool {
	var key string
	if ip.To4() != nil {
		key = ip.Mask(l.v4mask).String()
	} else {
		key = ip.Mask(l.v6mask).String()
	}
	//l.lg.Debugf("Checking %s", key)
	l.Count(key)
	l.limitLock.RLock()
	limit := l.limits[key]
	l.limitLock.RUnlock()
	if limit < uint64(rand.Int31()) {
		return true
	}
	return false
}

func countlimits(l *Limiter) {
	defer l.wg.Done()
	cl := &sync.WaitGroup{}
	t := time.NewTicker(UPDATE_DELAY)
	defer t.Stop()
	cycle := 0
	curr := make(map[string]uint64)
	for {
		select {
		case <-l.stop:
			l.lg.Debug("Shutting down counter")
			cl.Wait() // Wait for any pending update goroutine to complete
			return
		case key := <-l.sender:
			curr[key] += 1
			break
		case <-t.C:
			l.tables[cycle] = curr
			curr = make(map[string]uint64)
			cycle = (cycle + 1) % 5
			go updatecounts(l, cl)
		}
	}
}

func updatecounts(l *Limiter, cl *sync.WaitGroup) {
	cl.Add(1)
	defer cl.Done()
	limits := make(map[string]uint64)
	slices := uint64(0)
	for _, ptr := range l.tables {
		if ptr != nil {
			slices += 1
			for key, cnt := range ptr {
				limits[key] += cnt
			}
		}
	}
	for key, cnt := range limits {
		limits[key] = cnt / slices
		if limits[key] <= l.offset {
			delete(limits, key)
			continue
		} else if limits[key] > 2<<30-1 {
			limits[key] = math.MaxInt32
		} else if limits[key] <= l.offset*2 {
			step := (2<<28 - 1) / l.offset
			limits[key] = limits[key] * step
		} else {
			limits[key] = limits[key] + (2<<30-1-limits[key])>>1
		}
	}
	l.limitLock.Lock()
	defer l.limitLock.Unlock()
	l.limits = limits
}
