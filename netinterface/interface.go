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
 * netinterface.go: Network interface management routines
 */

package netinterface

import (
	"fmt"
	"net"
	"sync"
	"tenta-dns/common"
	"tenta-dns/log"
	"time"

	"github.com/sirupsen/logrus"
)

func WatchInterfaces(ifaces []common.Interface) (chan common.Status, chan bool, *sync.WaitGroup) {
	notify := make(chan common.Status, 1024)
	stop := make(chan bool, 1)
	lg := log.GetLogger("netinterface")
	wg := &sync.WaitGroup{}
	go func() {
		defer func() {
			if rcv := recover(); rcv != nil {
				lg.Errorf("Got a panic from the interface watcher. Sending a fatal failure: %s", rcv)
				notify <- common.Status{State: common.StateCriticalFailure, ID: fmt.Sprintf("%s", rcv)}
			}
			wg.Done()
		}()
		wg.Add(1)
		manageInterfaces(ifaces, notify, stop, lg)
	}()
	return notify, stop, wg
}

func manageInterfaces(ifaces []common.Interface, notify chan common.Status, stop chan bool, lg *logrus.Entry) {
	lg.Debug("Starting up")
	t := time.NewTicker(time.Millisecond * 250)
	run := true
	prev := make(map[string]common.InterfaceState)
	for _, i := range ifaces {
		prev[i.ID] = common.StateMissing
	}
	for run {
		select {
		case <-t.C:
			up := make(map[string]bool, 0)
			hfaces, err := net.Interfaces()
			if err != nil {
				lg.Errorf("Unable to list interfaces: %s", err.Error())
				panic(err.Error())
			}
			for _, h := range hfaces {
				haddrs, err := h.Addrs()
				if err != nil {
					lg.Errorf("Unable to list addresses on %s: %s", h.Name, err.Error())
					panic(err.Error())
				}
				for _, a := range haddrs {
					var ip net.IP
					switch v := a.(type) {
					case *net.IPNet:
						ip = v.IP
					case *net.IPAddr:
						ip = v.IP
					default:
						panic(fmt.Sprintf("Got an uknown address type from a hardware interface: %s", a.String()))
					}
					for _, i := range ifaces {
						if i.IP.Equal(ip) {
							up[i.ID] = true
						}
					}
				}
			}
			for id := range prev {
				if _, ok := up[id]; ok {
					if prev[id] != common.StateUp {
						prev[id] = common.StateUp
						notify <- common.Status{State: common.StateUp, ID: id}
					}
				} else {
					if prev[id] != common.StateDown {
						prev[id] = common.StateDown
						notify <- common.Status{State: common.StateDown, ID: id}
					}
				}
			}
		case <-stop:
			run = false
		}
	}
	lg.Debug("Shutting down")
}
