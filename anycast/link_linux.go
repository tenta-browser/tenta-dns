// +build linux

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
 * link_linux.go: Link management on Linux platforms
 */

package anycast

import (
	"fmt"
	"net"
	"github.com/tenta-browser/tenta-dns/common"

	"github.com/milosgajdos83/tenus"
	"github.com/sirupsen/logrus"
)

func addLink(d *[]string, b common.Netblock, cnt *uint, lg *logrus.Entry) {
	name := fmt.Sprintf("bgp%d", *cnt)
	*cnt += 1
	ip, ipnet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", b.IP, b.Netmask))
	if err != nil {
		lg.Errorf("Error parsing CIDR to create link link %s for %s: %s", name, b.IP, err.Error())
		return
	}
	lg.Debugf("Adding link %s for %s", name, b.IP)
	link, err := tenus.NewLink(name)
	if err != nil {
		lg.Errorf("Error creating link %s for %s: %s", name, b.IP, err.Error())
		return
	}
	*d = append(*d, name)
	err = link.SetLinkIp(ip, ipnet)
	if err != nil {
		lg.Errorf("Error setting link IP address %s for %s: %s", b.IP, name, err.Error())
		return
	}
	err = link.SetLinkUp()
	if err != nil {
		lg.Errorf("Error setting link %s for %s Up: %s", name, b.IP, err.Error())
		return
	}
}

func removeLinks(d *[]string, lg *logrus.Entry) {
	for _, name := range *d {
		lg.Debugf("Removing link %s", name)
		link, err := tenus.NewLinkFrom(name)
		if err != nil {
			lg.Errorf("Unable to retrieve link %s", name)
			continue
		}
		err = link.SetLinkDown()
		if err != nil {
			lg.Warnf("Unable to set link %s Down", name)
		}
		err = link.DeleteLink()
		if err != nil {
			lg.Errorf("Unable to remove link %s, you may need to do so manually", name)
		}
	}
}
