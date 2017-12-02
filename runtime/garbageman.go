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
 * garbageman.go: Database cleanup facility
 */

package runtime

import (
	"fmt"
	"github.com/tenta-browser/tenta-dns/common"
	"github.com/tenta-browser/tenta-dns/log"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

const (
	KEY_NAME     = "name"
	KEY_DATA     = "data"
	KEY_HOSTNAME = "hostname"
)

func garbageman(cfg Config, rt *Runtime) {
	defer rt.wg.Done()
	lg := log.GetLogger("garbageman")
	lg.Debug("Starting up")
	ticker := time.NewTicker(time.Second)
	var collected int
	for {
		select {
		case <-ticker.C:
			//lg.Debug("Collecting garbage")
			now := time.Now().Unix()
			prefix := (now - cfg.DatabaseTTL)

			// Handle DNS Lookup entries
			iter := rt.DB.NewIterator(&util.Range{Start: []byte("queries/"), Limit: append([]byte(fmt.Sprintf("queries/%d", prefix)), 0xFF)}, nil)
			droplist := make([][]byte, 0)
			for iter.Next() {
				k := make([]byte, len(iter.Key()))
				copy(k, iter.Key())
				droplist = append(droplist, k)
				v := make([]byte, len(iter.Value()))
				copy(v, iter.Value())
				droplist = append(droplist, common.AddSuffix(v, KEY_NAME))
				droplist = append(droplist, common.AddSuffix(v, KEY_DATA))
				droplist = append(droplist, common.AddSuffix(v, KEY_HOSTNAME))
			}
			iter.Release()
			batch := new(leveldb.Batch)
			droplist_len := len(droplist)
			for i := 0; i < droplist_len; i += 1 {
				batch.Delete(droplist[i])
				collected += 1
			}
			if droplist_len > 0 {
				rt.Stats.TickN("database", "get", uint64(droplist_len))
				rt.Stats.TickN("database", "delete", uint64(droplist_len))
			}
			if err := rt.DB.Write(batch, nil); err != nil {
				lg.Warnf("Failed applying transaction: %s", err.Error())
				rt.Stats.TickN("database", "get_error", uint64(droplist_len))
				rt.Stats.TickN("database", "delete_error", uint64(droplist_len))
			}

			// Handle Blacklist Entries
			// TOD: Store blacklist in cache2go
			//blprefix := (now - cfg.BlacklistTTL)
			//iter = rt.DB.NewIterator(&util.Range{Start: []byte("blacklist/"), Limit: append([]byte(fmt.Sprintf("blacklist/%d", blprefix)), 0xFF)}, nil)
			//droplist = make([][]byte, 0)
			//for iter.Next() {
			//	k := make([]byte, len(iter.Key()))
			//	copy(k, iter.Key())
			//	v := make([]byte, len(iter.Value()))
			//	copy(v, iter.Value())
			//	droplist = append(droplist, k)
			//	droplist = append(droplist, v)
			//}
			//iter.Release()
			//batch = new(leveldb.Batch)
			//droplist_len = len(droplist)
			//for i := 0; i < droplist_len; i += 1 {
			//	batch.Delete(droplist[i])
			//	collected += 1
			//}
			if droplist_len > 0 {
				rt.Stats.TickN("database", "get", uint64(droplist_len))
				rt.Stats.TickN("database", "delete", uint64(droplist_len))
			}
			if err := rt.DB.Write(batch, nil); err != nil {
				lg.Debug("error applying transaction")
				rt.Stats.TickN("database", "get_error", uint64(droplist_len))
				rt.Stats.TickN("database", "delete_error", uint64(droplist_len))
			}

			if now%300 == 0 {
				lg.WithField("now", now).Debugf("Collected: %d", collected)
				collected = 0
			}
		case <-rt.stop:
			ticker.Stop()
			lg.Debug("Shutting down")
			return
		}
	}
}
