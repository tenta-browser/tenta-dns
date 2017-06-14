/**
 * NSnitch DNS Server
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
	"os"
	"fmt"
	"sync"
	"time"
	"encoding/binary"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
)

const KEY_START_TIME = "start-time"
const KEY_GEODB_UPDATED = "geodb-updated-time"

type Runtime struct {
	wg      *sync.WaitGroup
	DB      *leveldb.DB
	Geo     *Geo
	Stats   *Stats
	stop    chan bool
	started uint
}

type finisher func()

func NewRuntime(cfg *Config) *Runtime {
	rt := new(Runtime)
	var wg sync.WaitGroup
	rt.wg = &wg
	rt.stop = make(chan bool, 4)

	if stat, err := os.Stat(cfg.GeoDBPath); err != nil || !stat.IsDir() {
		fmt.Printf("Error: Unable to open geo database path %s\n", cfg.GeoDBPath)
		os.Exit(2)
	}

	db, err := leveldb.OpenFile(cfg.DatabasePath, nil)
	if err != nil {
		fmt.Printf("Error: Unable to open database %s: %s\n", cfg.DatabasePath, err.Error())
		os.Exit(2)
	}

	rt.DB = db
	fmt.Printf("Using database %s\n", cfg.DatabasePath)

	startTimeBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(startTimeBytes, uint64(time.Now().Unix()))
	if err = rt.DB.Put([]byte(KEY_START_TIME), startTimeBytes, nil); err != nil {
		fmt.Printf("Error: Unable to write to DB: %s\n", err.Error())
		os.Exit(2)
	}

	rt.Stats = StartStats(cfg, rt)

	rt.AddService()
	go garbageman(cfg, rt)

	rt.Geo = StartGeo(cfg, rt)

	rt.AddService()
	go geoupdater(cfg, rt)

	rt.AddService()
	go torupdater(cfg, rt)

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

func (rt *Runtime) Shutdown() {
	for i := uint(0); i < rt.started; i += 1 {
		rt.stop <- true
	}
	rt.wg.Wait()
	rt.Stats.Stop()
	rt.DB.Close()
	fmt.Printf("Shutdown complete\n")
}

func (rt *Runtime) DBGet(key []byte) (value []byte, err error) {
	rt.Stats.Tick("database", "get")
	value, err = rt.DB.Get(key, nil)
	if err != nil && err != errors.ErrNotFound {
		rt.Stats.Tick("database", "get_error")
	}
	return value, err
}

func (rt* Runtime) DBPut(key, value []byte) (err error) {
	rt.Stats.Tick("database", "put")
	err = rt.DB.Put(key, value, nil)
	if err != nil {
		rt.Stats.Tick("database", "put_error")
	}
	return err
}