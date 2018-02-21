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
 * runtime.go: Core runtime
 */

package runtime

import (
	"encoding/binary"
	"os"
	"sync"
	"time"

	"github.com/tenta-browser/tenta-dns/log"

	"github.com/sirupsen/logrus"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
)

const KEY_START_TIME = "start-time"
const KEY_GEODB_UPDATED = "geodb-updated-time"

//noinspection GoNameStartsWithPackageName
type Runtime struct {
	wg          *sync.WaitGroup
	DB          *leveldb.DB
	Geo         *Geo
	Stats       *Stats
	IPPool      *Pool
	stop        chan bool
	started     uint
	lg          *logrus.Entry
	RateLimiter *Limiter
	SlackWH     *Feedback
}

type finisher func()

type FailureNotifier func()

func NewRuntime(cfg Config) *Runtime {
	rt := new(Runtime)
	var wg sync.WaitGroup
	rt.wg = &wg
	rt.stop = make(chan bool, 4)
	rt.lg = log.GetLogger("runtime")

	if len(cfg.GeoDBPath) > 0 {
		if stat, err := os.Stat(cfg.GeoDBPath); err != nil || !stat.IsDir() {
			rt.lg.Errorf("Unable to open geo database path %s", cfg.GeoDBPath)
			panic(err)
		}
	}

	db, err := leveldb.OpenFile(cfg.DatabasePath, nil)
	if err != nil {
		rt.lg.Errorf("Unable to open database %s: %s", cfg.DatabasePath, err.Error())
		panic(err)
	}

	rt.DB = db
	rt.lg.Debugf("Using database %s", cfg.DatabasePath)

	startTimeBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(startTimeBytes, uint64(time.Now().Unix()))
	if err = rt.DB.Put([]byte(KEY_START_TIME), startTimeBytes, nil); err != nil {
		rt.lg.Errorf("Error: Unable to write to DB: %s", err.Error())
		panic(err)
	}

	rt.IPPool = StartIPPool(cfg.OutboundIPs)
	rt.SlackWH = StartFeedback(cfg, rt)
	rt.Stats = StartStats(rt)
	rt.RateLimiter = StartLimiter(cfg.RateThreshold)
	rt.AddService()
	go garbageman(cfg, rt)

	if len(cfg.GeoDBPath) > 0 {
		rt.Geo = StartGeo(cfg, rt, false)

		rt.AddService()
		go geoupdater(cfg, rt)

		rt.AddService()
		go torupdater(cfg, rt)
	} else {
		rt.Geo = StartGeo(cfg, rt, true)

		rt.lg.Debug("Not starting geo service, as it's not configured to run")
	}

	return rt
}

func (rt *Runtime) AddService() {
	rt.wg.Add(1)
	rt.started += 1
}

func (rt *Runtime) OnFinished(fn finisher) {
	defer rt.wg.Done()
	<-rt.stop
	if fn != nil {
		fn()
	}
}

func (rt *Runtime) OnFinishedOrPanic(fn finisher, pchan chan interface{}) {
	defer rt.wg.Done()
	var rcv *interface{}
	select {
	case <-rt.stop:
		break
	case r := <-pchan:
		rcv = &r
		rt.started -= 1 // We won't be shutting it down later, so let it go
		break
	}
	if fn != nil {
		fn()
	}
	if rcv != nil {
		panic(*rcv)
	}
}

func (rt *Runtime) Shutdown() {
	rt.lg.Info("Shutting down")
	for i := uint(0); i < rt.started; i += 1 {
		rt.stop <- true
	}
	rt.wg.Wait()
	rt.SlackWH.Stop()
	rt.Stats.Stop()
	rt.DB.Close()
	rt.lg.Info("Shutdown complete")
}

func (rt *Runtime) DBGet(key []byte) (value []byte, err error) {
	rt.Stats.Tick("database", "get")
	value, err = rt.DB.Get(key, nil)
	if err != nil && err != errors.ErrNotFound {
		rt.Stats.Tick("database", "get_error")
	}
	return value, err
}

func (rt *Runtime) DBPut(key, value []byte) (err error) {
	rt.Stats.Tick("database", "put")
	err = rt.DB.Put(key, value, nil)
	if err != nil {
		rt.Stats.Tick("database", "put_error")
	}
	return err
}
