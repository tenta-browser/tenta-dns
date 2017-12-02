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
 * anycast.go: Routine collection for Anycast addressing
 */

package anycast

import (
	"fmt"
	"github.com/tenta-browser/tenta-dns/common"
	"github.com/tenta-browser/tenta-dns/log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	api "github.com/osrg/gobgp/api"
	bgpconfig "github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
	gobgp "github.com/osrg/gobgp/server"
	"github.com/osrg/gobgp/table"
	"github.com/sirupsen/logrus"
)

func watchRoutes(srv *gobgp.BgpServer, stop chan bool, wg *sync.WaitGroup, lg *logrus.Entry) {
	wg.Add(1)
	defer wg.Done()
	lg.Info("Watching routes")
	w := srv.Watch(gobgp.WatchBestPath(true))
	run := true
	for run {
		select {
		case <-stop:
			run = false
			break
		case ev := <-w.Event():
			switch msg := ev.(type) {
			case *gobgp.WatchEventBestPath:
				for _, path := range msg.PathList {
					// do something useful
					lg.Debug(path)
				}
			}
		}
	}
	lg.Debug("Stopping route watcher")
}

func watchPeerState(srv *gobgp.BgpServer, stop chan bool, wg *sync.WaitGroup, lg *logrus.Entry) {
	wg.Add(1)
	defer wg.Done()
	lg.Info("Watching peers")
	w := srv.Watch(gobgp.WatchPeerState(true))
	run := true
	for run {
		select {
		case <-stop:
			run = false
			break
		case ev := <-w.Event():
			switch msg := ev.(type) {
			case *gobgp.WatchEventPeerState:
				lg.Debugf("Peer %s has state %s", msg.PeerID, msg.State.String())
			}
		}
	}
	lg.Debug("Stopping peer watcher")
}

func AdvertiseRoutes(b BGPConfig, peers map[string]Peer, netblocks map[string]common.Netblock, interfaces []common.Interface) (chan RouteUpdate, chan bool, *sync.WaitGroup) {
	notify := make(chan RouteUpdate, 1024)
	stop := make(chan bool, 1)
	lg := log.GetLogger("bgp")
	wg := &sync.WaitGroup{}
	go func() {
		dummies := make([]string, 0)
		enable := b.Enabled() && common.AnycastSupported()
		defer func(createdifaces *[]string) {
			if rcv := recover(); rcv != nil {
				lg.Errorf("Got a panic from the bgp subsystem. Sending a fatal failure: %s", rcv)
				notify <- RouteUpdate{"", RouteStatusCriticalFailure}
			}
			if enable {
				removeLinks(createdifaces, lg)
			}
			wg.Done()
		}(&dummies)
		wg.Add(1)
		if enable {
			doAdvertiseRoutes(b, peers, netblocks, interfaces, &dummies, notify, stop, lg)
		} else {
			lg.Debug("Not starting BGP server, since it's not enabled or supported")
		}
	}()
	return notify, stop, wg
}

func doAdvertiseRoutes(cfg BGPConfig, peers map[string]Peer, netblocks map[string]common.Netblock, interfaces []common.Interface, dummies *[]string, notify chan RouteUpdate, stop chan bool, lg *logrus.Entry) {
	lg.Infof("Strting BGP server as AS%d", cfg.AS)

	// TODO: Probably need to do a double function wrap to catch panics here
	srv := gobgp.NewBgpServer()
	go srv.Serve()

	global := &bgpconfig.Global{
		Config: bgpconfig.GlobalConfig{
			As:       cfg.AS,
			RouterId: cfg.IPv4,
			Port:     -1,
		},
	}

	if err := srv.Start(global); err != nil {
		lg.Errorf("Failed to start the BGP server: %s", err.Error())
		panic(err.Error())
	}

	var g *api.Server
	if cfg.EnableRPC {
		lg.Infof("Starting bgp rpc server on 127.0.0.1:%d", cfg.RPCPort)
		// TODO: Offer multiple addresses? Multiple ports? ...?
		g = api.NewGrpcServer(srv, fmt.Sprintf("127.0.0.1:%d", cfg.RPCPort))
		go g.Serve()
	}

	started := uint(0)
	stopper := make(chan bool, 1024)
	wg := &sync.WaitGroup{}

	go watchRoutes(srv, stopper, wg, lg)
	started += 1

	go watchPeerState(srv, stopper, wg, lg)
	started += 1

	for name, p := range peers {
		neighbor := &bgpconfig.Neighbor{
			Config: bgpconfig.NeighborConfig{
				NeighborAddress: p.IP,
				PeerAs:          p.AS,
				Description:     p.Description,
			},
		}
		if len(p.Password) > 0 {
			neighbor.Config.AuthPassword = p.Password
		}
		if cfg.EnableCommunities {
			neighbor.Config.SendCommunity = bgpconfig.COMMUNITY_TYPE_STANDARD
		}
		lg.Debugf("Adding peer %s [AS%d] at %s", name, p.AS, p.IP)
		if err := srv.AddNeighbor(neighbor); err != nil {
			lg.Errorf("Failed to add peer %s: %s", name, err.Error())
			panic(err.Error())
		}
	}

	advblocks := make(map[string]common.Netblock)
	advifaces := make(map[string]common.Netblock)

	// Run through the netblocks and add any that we must advertise because they're forced
	for name, b := range netblocks {
		if b.Force {
			advblocks[name] = b
		}
	}

	// Run through the interfaces and identify any that need to be announced via BGP
	for _, i := range interfaces {
		for name, b := range netblocks {
			_, bnet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", b.IP, b.Netmask))
			if err != nil {
				lg.Error("Unable to parse netblock")
				panic("Unable to parse netblock")
			}
			if bnet.Contains(i.IP) {
				lg.Debugf("%s is within %s [%s], announcing it", i.IP.String(), name, bnet.String())
				advblocks[name] = b
				if i.IP.To4() != nil {
					// We use the sting as the key here (and not the ID), since multiple service IDs may share the same IP
					advifaces[i.IP.String()] = common.Netblock{IP: i.IP.String(), Netmask: 32, Force: true}
				} else {
					advifaces[i.IP.String()] = common.Netblock{IP: i.IP.String(), Netmask: 128, Force: true}
				}
			}
		}
	}

	for _, b := range advblocks {
		advertisNetblock(cfg, srv, b, lg)
	}

	cnt := uint(0)
	for _, b := range advifaces {
		advertisNetblock(cfg, srv, b, lg)
		addLink(dummies, b, &cnt, lg)
		notify <- RouteUpdate{IP: b.IP, Status: RouteStatusAnnounced}
	}

	for _, d := range *dummies {
		lg.Infof("Added link %s", d)
	}

	select {
	case <-stop:
		break
	}

	lg.Debug("Shutting down")

	for i := uint(0); i < started; i += 1 {
		stopper <- true
	}
	wg.Wait()

	if g != nil {
		// TODO: Talk to GoBGP team about why this takes parameters which it doesn't use
		g.StopServer(nil, nil)
	}
	srv.Stop()

	lg.Debug("Stopped")
}

func advertisNetblock(cfg BGPConfig, srv *gobgp.BgpServer, b common.Netblock, lg *logrus.Entry) {
	lg.Debugf("Advertising %s/%d", b.IP, b.Netmask)
	_, ipnet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", b.IP, b.Netmask))
	if err != nil {
		lg.Errorf("Unable to parse CIDR for %s/%d", b.IP, b.Netmask)
		return
	}
	if ipnet.IP.To4() != nil {
		attrs4 := []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
			bgp.NewPathAttributeNextHop(cfg.IPv4),
			bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{cfg.AS})}),
		}
		if len(b.Communities) > 0 {
			comm := make([]uint32, 0)
			for _, c := range b.Communities {
				parts := strings.Split(c, ":")
				if len(parts) != 2 {
					lg.Warnf("Error parsing community %s", c)
					continue
				}
				as, err := strconv.ParseUint(parts[0], 10, 16)
				if err != nil {
					lg.Warnf("Error parsing community %s", c)
					continue
				}
				cmn, err := strconv.ParseUint(parts[1], 10, 16)
				comm = append(comm, uint32(as<<16+cmn))
			}
			attrs4 = append(attrs4, bgp.NewPathAttributeCommunities(comm))
		}
		if _, err := srv.AddPath("", []*table.Path{table.NewPath(nil, bgp.NewIPAddrPrefix(b.Netmask, b.IP), false, attrs4, time.Now(), false)}); err != nil {
			lg.Errorf("Unable to add %s/%d to path", b.IP, b.Netmask)
		}
	} else {
		lg.Debugf("Don't currently know how to add IPv6 to the path")
	}
}
