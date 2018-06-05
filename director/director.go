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
 * director.go: Declaration and primitives of Director object, in charge of orchestrating the concurrent execution of various services
 */

package director

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tenta-browser/tenta-dns/anycast"
	"github.com/tenta-browser/tenta-dns/common"
	"github.com/tenta-browser/tenta-dns/log"
	"github.com/tenta-browser/tenta-dns/netinterface"
	"github.com/tenta-browser/tenta-dns/responder"
	"github.com/tenta-browser/tenta-dns/runtime"

	"github.com/coreos/go-systemd/daemon"
	"github.com/sirupsen/logrus"
	"github.com/tevino/abool"
)

const RECENT_FAILURE_LIMIT = 3
const RECENT_FAILURE_WINDOW = time.Minute * 15

//noinspection GoNameStartsWithPackageName
type Director struct {
	h        runtime.ConfigHolder
	r        *runtime.Runtime
	wg       *sync.WaitGroup
	lg       *logrus.Entry
	stop     chan bool
	running  abool.AtomicBool
	stopping abool.AtomicBool
}

func NewDirector(hld runtime.ConfigHolder) *Director {
	return &Director{
		hld,
		nil,
		&sync.WaitGroup{},
		log.GetLogger("director"),
		make(chan bool, 1),
		*abool.NewBool(false),
		*abool.NewBool(false),
	}
}

func (dir *Director) Orchestrate(systemd bool) {
	dir.wg.Add(1)
	go dir.doOrchestrate(systemd)
}

func (dir *Director) doOrchestrate(systemd bool) {
	defer dir.wg.Done()
	if !dir.running.SetToIf(false, true) {
		dir.lg.Warn("Tried to orchestrate on an already running director")
		return
	}
	dir.lg.Debug("Running orchestrator")

	func() { // Ensure that we panic or succeed right away
		defer func() {
			if rcv := recover(); rcv != nil {
				dir.lg.Errorf("Panic while setting up the runtime: %s", rcv)
				os.Exit(2)
			}
		}()
		dir.r = runtime.NewRuntime(dir.h.MasterConfig)
	}()

	failures := make(chan failure, 50)
	players := make(map[string]*player)
	interfaces := make([]common.Interface, 0)

	if dir.h.MasterConfig.ThreadedResolver {
		dir.lg.Infof("Setting resolver style as threaded")
		responder.THREADING = responder.THREADING_NETWORK_ONLY
	} else {
		dir.lg.Infof("Setting resolver style as non-threaded")
		responder.THREADING = responder.THREADING_NONE
	}

	for _, ncfg := range dir.h.NSnitchs {
		base := filepath.Base(ncfg.ConfigFile)
		for _, s := range domainLister(ncfg.Domains, true, true) {
			id := fmt.Sprintf("nsnitch+%s%s", s.id, base)
			thisCfg := ncfg
			players[id] = newPlayer(id, failures, func(s startdata) starter {
				return func() {
					dir.r.AddService()
					if s.net == "http" || s.net == "https" {
						responder.SnitchHTTPServer(thisCfg, dir.r, s.ipv4, s.net, s.d)
					} else {
						responder.SnitchDNSServer(thisCfg, dir.r, s.ipv4, s.net, s.d)
					}
				}
			}(s), nil)
			if s.ipv4 {
				interfaces = append(interfaces, common.Interface{ID: id, IP: net.ParseIP(s.d.IPv4), Type: common.TypeIPv4, Name: ""})
			} else {
				interfaces = append(interfaces, common.Interface{ID: id, IP: net.ParseIP(s.d.IPv6), Type: common.TypeIPv6, Name: ""})
			}
		}
	}

	for _, rcfg := range dir.h.Recursors {
		base := filepath.Base(rcfg.ConfigFile)
		for _, s := range domainLister(rcfg.Domains, true, false) {
			id := fmt.Sprintf("recursor+%s%s", s.id, base)
			b := rcfg.OpenNic
			players[id] = newPlayer(id, failures, func(s startdata) starter {
				return func() {
					dir.r.AddService()
					responder.ServeDNS(rcfg, dir.r, s.ipv4, s.net, s.d, b, true)
				}
			}(s), nil)
			if s.ipv4 {
				interfaces = append(interfaces, common.Interface{ID: id, IP: net.ParseIP(s.d.IPv4), Type: common.TypeIPv4, Name: ""})
			} else {
				interfaces = append(interfaces, common.Interface{ID: id, IP: net.ParseIP(s.d.IPv6), Type: common.TypeIPv6, Name: ""})
			}
		}
	}

	for _, acfg := range dir.h.Authorities {
		base := filepath.Base(acfg.ConfigFile)
		for _, s := range domainLister(acfg.Domains, true, false) {
			id := fmt.Sprintf("authority+%s%s", s.id, base)
			players[id] = newPlayer(id, failures, func(s startdata) starter {
				return func() {
					dir.r.AddService()
					responder.AuthoritativeDNSServer(acfg, dir.r, s.ipv4, s.net, s.d)
				}
			}(s), nil)
			if s.ipv4 {
				interfaces = append(interfaces, common.Interface{ID: id, IP: net.ParseIP(s.d.IPv4), Type: common.TypeIPv4, Name: ""})
			} else {
				interfaces = append(interfaces, common.Interface{ID: id, IP: net.ParseIP(s.d.IPv6), Type: common.TypeIPv6, Name: ""})
			}
		}
	}

	sdwatch := false
	sdinterval := time.Hour
	if systemd {
		daemon.SdNotify(false, "READY=1")
		daemon.SdNotify(false, fmt.Sprintf("STATUS=Configured %d modules", len(players)))
		sdinterval, err := daemon.SdWatchdogEnabled(false)
		if err != nil || sdinterval == 0 {
			sdwatch = false
			dir.lg.Warnf("Unable to get systemd interval %s", err.Error())
		} else {
			sdwatch = true
			sdinterval = time.Duration(sdinterval / 3)
			dir.lg.Debugf("SystemD watchdog interval %s", sdinterval.String())
		}
	} else {
		dir.lg.Debugf("Not using SystemD, setting interval to %s", sdinterval.String())
	}

	sig := getWatcher()
	resetter := time.NewTicker(RECENT_FAILURE_WINDOW)
	watcher := time.NewTicker(time.Second)
	sdticker := time.NewTicker(time.Second)
	netupdates, netstopper, netwait := netinterface.WatchInterfaces(interfaces)
	bgpupdates, bgpstopper, bgpwait := anycast.AdvertiseRoutes(dir.h.MasterConfig.BGP, dir.h.MasterConfig.Peers, dir.h.MasterConfig.Netblocks, interfaces)
	statsreceiver := dir.r.Stats.AddBroadcastWatcher()
	run := true
	forced := false
	for run {
		select {
		case <-dir.stop:
			goto stop
			break
		case <-sdticker.C:
			if sdwatch {
				daemon.SdNotify(false, "WATCHDOG=1")
			}
			break
		case <-resetter.C:
			for _, p := range players {
				dir.lg.Debugf("%s running since %s. It has %d recent failures", p.id, p.started.Format(time.UnixDate), p.fails)
				atomic.StoreUint32(&p.fails, 0)
			}
			break
		case <-watcher.C:
			for _, p := range players {
				if p.didStart() && !p.running && !p.dead {
					dir.lg.Warnf("%s is no longer running but hasn't died", p.id)
				}
			}
			break
		case s := <-statsreceiver:
			if sdwatch {
				parts := make([]string, 0)
				parts = append(parts, fmt.Sprintf("%d modules configured", len(players)))
				rnum := 0
				for _, p := range players {
					if p.didStart() && p.running {
						rnum += 1
					}
				}
				parts = append(parts, fmt.Sprintf("%d modules running", rnum))
				if dnum, ok := s["dns:queries:all/average"]; ok {
					parts = append(parts, fmt.Sprintf("%s DNS rps", dnum))
				}
				if hnum, ok := s["http:queries:all/average"]; ok {
					parts = append(parts, fmt.Sprintf("%s HTTP rps", hnum))
				}
				msg := fmt.Sprintf("STATUS=%s", strings.Join(parts, ", "))
				daemon.SdNotify(false, msg)
			}
			break
		case b := <-bgpupdates:
			dir.lg.Debugf("Got BGP update %s", b.String())
			if b.Status == anycast.RouteStatusCriticalFailure {
				dir.lg.Errorf("Forcing shutdown due to bgp subsystem failure")
				forced = true
				goto stop
			}
			break
		case u := <-netupdates:
			dir.lg.Debugf("Got network update %s", u.String())
			if u.State == common.StateCriticalFailure {
				dir.lg.Errorf("Forcing shutdown due to network subsystem failure")
				forced = true
				goto stop
			}
			if u.State == common.StateUp {
				if p, ok := players[u.ID]; ok {
					if !p.didStart() {
						dir.lg.Debugf("Starting up %s, as it's network is now available", p.id)
						p.start()
					}
				}
			}
			if u.State == common.StateDown {
				if p, ok := players[u.ID]; ok {
					if p.didStart() {
						dir.lg.Warnf("The network interface for %s is no longer available.", p.id)
					} else {
						dir.lg.Infof("Not starting %s as the network is not available.", p.id)
					}
				}
			}
			break
		case f := <-failures:
			dir.lg.Warnf("Got a failure in %s: %s", f.p.id, f.r)
			dir.r.SlackWH.SendMessage(fmt.Sprintf("panic caught: ```%s```", f.r), f.p.id)
			fails := atomic.LoadUint32(&f.p.fails)
			if fails >= RECENT_FAILURE_LIMIT {
				dir.lg.Errorf("Perma killing %s", f.p.id)
				f.p.dead = true
			}
			if !f.p.dead {
				dir.lg.Debugf("Restarting %s", f.p.id)
				f.p.start()
			}
			break
		case s := <-sig:
			dir.lg.Debugf("Caught signal %s", s.String())
			for _, p := range players {
				if p.didStart() && !p.dead {
					dir.lg.Infof("%s running since %s. It has %d recent failures", p.id, p.started.Format(time.UnixDate), p.fails)
					p.fails = 0
				} else if p.dead {
					dir.lg.Infof("%s has been prema-killed", p.id)
				} else {
					dir.lg.Infof("%s has not been started", p.id)
				}
			}
			break
		}
		continue
	stop:
		resetter.Stop()
		watcher.Stop()
		sdticker.Stop()
		run = false
	}

	dir.lg.Debug("Performing shutdown")
	dir.r.Shutdown()

	bgpstopper <- true
	bgpwait.Wait()

	netstopper <- true
	netwait.Wait()

	dir.lg.Debug("Stopped")
	if forced {
		os.Exit(5)
	}
}

func (dir Director) Stop() {
	if dir.stopping.SetToIf(false, true) {
		dir.stop <- true
		dir.lg.Debug("Asked to stop")
	} else {
		dir.lg.Warn("Tried to stop a director that's already stopping")
	}
	dir.wg.Wait()
}

type startdata struct {
	id   string
	ipv4 bool
	net  string
	d    *runtime.ServerDomain
}

func domainLister(doms map[string]*runtime.ServerDomain, includedns bool, includehttp bool) []startdata {
	ret := make([]startdata, 0)
	for _, d := range doms {
		if d.IPv4 != "" {
			if includedns {
				if d.DnsUdpPort != runtime.PORT_DISABLED {
					ret = append(ret, startdata{fmt.Sprintf("dns-udp://%s:%d/", d.IPv4, d.DnsUdpPort), true, "udp", d})
				}
				if d.DnsTcpPort != runtime.PORT_DISABLED {
					ret = append(ret, startdata{fmt.Sprintf("dns-tcp://%s:%d/", d.IPv4, d.DnsUdpPort), true, "tcp", d})
				}
				if d.DnsTlsPort != runtime.PORT_DISABLED {
					ret = append(ret, startdata{fmt.Sprintf("dns-tls://%s:%d/", d.IPv4, d.DnsUdpPort), true, "tls", d})
				}
			}
			if includehttp {
				if d.HttpPort != runtime.PORT_DISABLED {
					ret = append(ret, startdata{fmt.Sprintf("http://%s:%d/", d.IPv4, d.DnsUdpPort), true, "http", d})
				}
				if d.HttpsPort != runtime.PORT_DISABLED {
					ret = append(ret, startdata{fmt.Sprintf("https://%s:%d/", d.IPv4, d.DnsUdpPort), true, "https", d})
				}
			}
		}
		if d.IPv6 != "" {
			if includedns {
				if d.DnsUdpPort != runtime.PORT_DISABLED {
					ret = append(ret, startdata{fmt.Sprintf("dns-udp://[%s]:%d/", d.IPv4, d.DnsUdpPort), false, "udp", d})
				}
				if d.DnsTcpPort != runtime.PORT_DISABLED {
					ret = append(ret, startdata{fmt.Sprintf("dns-tcp://[%s]:%d/", d.IPv4, d.DnsUdpPort), false, "tcp", d})
				}
				if d.DnsTlsPort != runtime.PORT_DISABLED {
					ret = append(ret, startdata{fmt.Sprintf("dns-tls://[%s]:%d/", d.IPv4, d.DnsUdpPort), false, "tls", d})
				}
			}
			if includehttp {
				if d.HttpPort != runtime.PORT_DISABLED {
					ret = append(ret, startdata{fmt.Sprintf("http://[%s]:%d/", d.IPv4, d.DnsUdpPort), false, "http", d})
				}
				if d.HttpsPort != runtime.PORT_DISABLED {
					ret = append(ret, startdata{fmt.Sprintf("https://[%s]:%d/", d.IPv4, d.DnsUdpPort), false, "https", d})
				}
			}
		}
	}
	return ret
}
