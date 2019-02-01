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
 * dns_common.go: Constants and functions used all across responder package
 */

package responder

import (
	"fmt"
	"runtime/debug"

	"github.com/miekg/dns"
)

const (
	StatsQueryTotal = "resolver:queries:total"
	StatsQueryUDP   = "resolver:queries:udp"
	StatsQueryTCP   = "resolver:queries:tcp"
	StatsQueryTLS   = "resolver:queries:tls"
	/// will fine tune the definition of failure
	StatsQueryFailure    = "resolver:queries:failed"
	StatsQueryLimitedIps = "resolver:queries:limited_ips"
	StatsQueryUniqueIps  = "resolver:queries:remote_ips"
)

var EDNSOptions = map[uint16]bool{
	dns.EDNS0LLQ:          true,
	dns.EDNS0UL:           true,
	dns.EDNS0NSID:         true,
	dns.EDNS0DAU:          true,
	dns.EDNS0DHU:          true,
	dns.EDNS0N3U:          true,
	dns.EDNS0SUBNET:       true,
	dns.EDNS0EXPIRE:       true,
	dns.EDNS0COOKIE:       true,
	dns.EDNS0TCPKEEPALIVE: true,
	dns.EDNS0PADDING:      true,
	dns.EDNS0LOCALSTART:   true,
	dns.EDNS0LOCALEND:     true,
}

type StackAddedPanic struct {
	trc []byte
	rcv interface{}
}

func (s *StackAddedPanic) String() string {
	return fmt.Sprintf("[%v]\n%s", s.rcv, s.trc)
}

type dnsHandler func(w dns.ResponseWriter, r *dns.Msg)

func dnsRecoverWrap(hndl dnsHandler, notify chan interface{}) dnsHandler {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		defer func() {
			if rcv := recover(); rcv != nil {
				snd := &StackAddedPanic{debug.Stack(), rcv}
				fmt.Printf("This is how we write this [%s]\n", snd)
				notify <- snd
			}
		}()
		hndl(w, r)
	}
}
