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
 * peer.go: Anycast Peer object declaration and primitives
 */

package anycast

type Peer struct {
	IP          string
	AS          uint32
	Password    string
	Description string
}

func (p Peer) Equals(o Peer) bool {
	if p.IP != o.IP {
		return false
	}
	if p.AS != o.AS {
		return false
	}
	if p.Password != o.Password {
		return false
	}
	if p.Description != o.Description {
		return false
	}
	return true
}
