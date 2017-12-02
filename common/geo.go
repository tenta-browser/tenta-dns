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
 * geo.go: Geo data structure definitions
 */

package common

type ISP struct {
	Organization   string `maxminddb:"organization" json:"organization"`
	ASNumber       uint   `maxminddb:"autonomous_system_number" json:"as_number"`
	ASOrganization string `maxminddb:"autonomous_system_organization" json:"as_owner"`
	ISP            string `maxminddb:"isp" json:"isp"`
}

type Position struct {
	Latitude  float32 `maxminddb:"latitude" json:"latitude"`
	Longitude float32 `maxminddb:"longitude" json:"longitude"`
	Radius    uint    `maxminddb:"accuracy_radius" json:"uncertainty_km"`
	TimeZone  string  `maxminddb:"time_zone" json:"time_zone"`
}

type GeoLocation struct {
	Position     *Position         `json:"position"`
	ISP          *ISP              `json:"network"`
	City         string            `json:"city"`
	Country      string            `json:"country"`
	CountryISO   string            `json:"iso_country"`
	Location     string            `json:"location"`
	LocationI18n map[string]string `json:"localized_location"`
	TorNode      *string           `json:"tor_node"`
}
