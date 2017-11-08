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
 * bgpconfig.go: Routine collection over bgp configuration objects
 */

package anycast

type BGPConfig struct {
	AS                uint32
	IPv4              string
	IPv6              string
	EnableCommunities bool
	EnableRPC         bool
	RPCPort           uint32
}

func (b BGPConfig) Equals(o BGPConfig) bool {
	if b.AS != o.AS {
		return false
	}
	if b.IPv4 != o.IPv4 {
		return false
	}
	if b.IPv6 != o.IPv6 {
		return false
	}
	if b.EnableCommunities != o.EnableCommunities {
		return false
	}
	if b.EnableRPC != o.EnableRPC {
		return false
	}
	if b.RPCPort != o.RPCPort {
		return false
	}
	return true
}

func (b BGPConfig) Enabled() bool {
	return !b.Equals(BGPConfig{})
}
