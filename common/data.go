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
 * data.go: Data structure definitions
 */

package common

type DefaultJSONObject struct {
	Status  string      `json:"status"`
	Type    string      `json:"type"`
	Data    interface{} `json:"data"`
	Message string      `json:"message"`
	Code    int         `json:"code"`
}

type DNSTelemetry struct {
	IP           string        `json:"ip"`
	IPFamily     string        `json:"ip_family"`
	NetType      string        `json:"net_type"`
	TLSEnabled   bool          `json:"tls_enabled"`
	DNSSECOk     bool          `json:"dnssec_enabled"`
	NSIDEnabled  bool          `json:"nsid_requested"`
	RequestTime  uint64        `json:"request_time,string"`
	KeepAlive    bool          `json:"tcp_keep_alive_enabled"`
	KeepAliveTTL uint          `json:"tcp_keep_alive_ms"`
	Cookie       bool          `json:"dns_cookie"`
	ExtraEDNS0   int           `json:"additional_edns0_records"`
	FlagRD       bool          `json:"recursion_desired"`
	FlagCD       bool          `json:"checking_disabled"`
	RequestLoc   *GeoLocation  `json:"request_location"`
	Subnet       *ClientSubnet `json:"client_subnet"`
	NodeLoc      *GeoLocation  `json:"node_location"`
	RFC4343Fail  bool          `json:"rfc4343_intolerance"`
}

type ClientSubnet struct {
	IP        string       `json:"ip"`
	Netmask   int          `json:"netmask"`
	IPFamily  string       `json:"ip_family"`
	DraftMode bool         `json:"draft_mode"`
	SubnetLoc *GeoLocation `json:"subnet_location"`
}

type GeoLookupData struct {
	NodeLoc    *GeoLocation `json:"node_location"`
	RequestLoc *GeoLocation `json:"request_location"`
	IP         string       `json:"ip_address"`
}

type StatsData struct {
	Keys       *[]string          `json:"keys"`
	Counters   *map[string]uint64 `json:"counters"`
	PFCounters *map[string]uint64 `json:"cardinalities"`
}

type BlacklistData struct {
	OnBlacklist   bool            `json:"blacklisted"`
	NumberOfLists int             `json:"number_of_lists"`
	NumberFound   int             `json:"number_blacklisted"`
	Results       map[string]bool `json:"results"`
}
