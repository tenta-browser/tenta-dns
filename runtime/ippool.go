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
 * ippool.go: Manages IP pool rotation
 */

package runtime

import (
	"math/rand"
	"net"
	"github.com/tenta-browser/tenta-dns/log"
	"time"
)

type Pool struct {
	p []net.IP
	r *rand.Rand
}

func StartIPPool(cfgIPs []string) *Pool {
	l := log.GetLogger("runtime")
	var ips []net.IP
	if cfgIPs == nil || len(cfgIPs) == 0 {
		l.Infof("Starting without any outbound IP specified. Default IP will be used.")
		ips = nil
	} else {
		ips = make([]net.IP, 0)
		for _, strIP := range cfgIPs {
			ip := net.ParseIP(strIP)
			ips = append(ips, ip)
		}
		l.Infof("Initialized IP Pool with [%v]", ips)
	}

	return &Pool{ips, rand.New(rand.NewSource(time.Now().UnixNano()))}
}

func (p *Pool) RandomizeUDPDialer() *net.Dialer {
	ret := &net.Dialer{}
	if len(p.p) > 0 {
		ret.LocalAddr = &net.UDPAddr{IP: p.p[p.r.Intn(len(p.p))]}
	}
	return ret
}

func (p *Pool) RandomizeTCPDialer() *net.Dialer {
	ret := &net.Dialer{}
	if len(p.p) > 0 {
		ret.LocalAddr = &net.TCPAddr{IP: p.p[p.r.Intn(len(p.p))]}
	}
	return ret
}
