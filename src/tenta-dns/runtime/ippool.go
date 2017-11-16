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
	"fmt"
	"math/rand"
	"net"
	"tenta-dns/log"
	"time"
)

type Pool struct {
	p []net.Addr
	r *rand.Rand
}

func ListAvailableIPs() ([]net.Addr, error) {
	ret := make([]net.Addr, 0)
	ifs, e := net.Interfaces()
	l := log.GetLogger("common")
	if e != nil {
		l.Fatalf("Cannot query local interfaces")
		panic(fmt.Sprintf("Cannot query network interfaces", e.Error()))
	}

	for _, intf := range ifs {
		l.Debugf("Scanning intf [%s]", intf.Name)
		if addrs, e := intf.Addrs(); e == nil {
			for _, addr := range addrs {
				l.Debugf("Scanning address [%s]", addr.String())

				switch a := addr.(type) {
				case *net.IPNet:
					if a.IP.IsGlobalUnicast() { //} && !common.IsPrivateIp(a.IP) {
						ret = append(ret, addr)
					}
				case *net.IPAddr:
					if a.IP.IsGlobalUnicast() { //} && !common.IsPrivateIp(a.IP) {
						ret = append(ret, addr)
					}
				}
			}
		}
	}
	if len(ret) == 0 {
		panic(fmt.Sprintf("Empty ip pool"))
	}
	return ret, nil
}

func StartIPPool() *Pool {
	l := log.GetLogger("runtime")
	ips, e := ListAvailableIPs()
	if e != nil {
		l.Fatalf("Cannot get list of available IP addresses [%s]", e.Error())
		panic(e)
	}
	l.Infof("Initialized IP Pool with [%v]", ips)
	return &Pool{ips, rand.New(rand.NewSource(time.Now().UnixNano()))}
}

func (p *Pool) RandomizeIP() net.Addr {
	return p.p[p.r.Intn(len(p.p)-1)]
}
