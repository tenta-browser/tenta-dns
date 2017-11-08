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

import "github.com/miekg/dns"

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

type dnsHandler func(w dns.ResponseWriter, r *dns.Msg)

func dnsRecoverWrap(hndl dnsHandler, notify chan interface{}) dnsHandler {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		defer func() {
			if rcv := recover(); rcv != nil {
				notify <- rcv
			}
		}()
		hndl(w, r)
	}
}
