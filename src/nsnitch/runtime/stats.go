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
 * stats.go: Stats subsystem
 */

package runtime

import (
	"time"
	"sync"
	"fmt"
	"github.com/sasha-s/go-hll"
	"github.com/dgryski/go-highway"
	"encoding/binary"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"strings"
	"github.com/syndtr/goleveldb/leveldb/util"
)

type EventType uint8

const (
	EvtTypeCount 	= 1
	EvtTypeCard  	= 2
	EvtTypeLatency	= 3
)

type Event struct {
	Key		string
	Type		EventType
	Count		uint64
	Value		[]byte
	Time		uint64
}

type PerSecond struct {
	Component	string
	Type		string
	Count		uint64
}

type Stats struct {
	queue	chan *Event
	persec	chan *PerSecond
	stop	chan bool
	lock*	sync.Mutex
	wg*	sync.WaitGroup
	lanes*  highway.Lanes
}

func StartStats(cfg* Config, rt* Runtime) *Stats {
	s := new (Stats)
	s.queue = make(chan *Event, 4096)
	s.persec = make(chan *PerSecond, 8192)
	s.stop = make(chan bool)
	var wg sync.WaitGroup
	s.wg = &wg
	s.wg.Add(1)
	var lock sync.Mutex
	s.lock = &lock

	s.lanes = &highway.Lanes{0x0706050403020100, 0x0F0E0D0C0B0A0908, 0x1716151413121110, 0x1F1E1D1C1B1A1918}

	go processstats(cfg, rt, s)

	return s
}

func (s* Stats) Stop() {
	s.lock.Lock()
	defer s.wg.Wait()
	defer s.lock.Unlock()
	s.stop<-true
	fmt.Printf("Stats: Sent stop signal\n")
}

func (s* Stats) Count(key string) {
	s.CountN(key, 1)
}

func (s* Stats) CountN(key string, increment uint64) {
	e := &Event{
		Key: key,
		Type: EvtTypeCount,
		Count: increment,
	}
	s.queue<-e
}

func (s* Stats) Card(key, value string) {
	e := &Event{
		Key: key,
		Type: EvtTypeCard,
		Value: []byte(value),
	}
	s.queue<-e
}

func (s* Stats) Latency(key string, value uint64) {
	e := &Event{
		Key: key,
		Type: EvtTypeLatency,
		Time: value,
	}
	s.queue<-e
}

func (s* Stats) Tick(component, action_type string) {
	s.TickN(component, action_type, 1)
}
func (s* Stats) TickN(component string, action_type string, count uint64) {
	p := &PerSecond{
		Component: component,
		Type: action_type,
		Count: count,
	}
	s.persec<-p
}

func processstats(cfg* Config, rt* Runtime, s* Stats) {
	defer s.wg.Done()
	fmt.Printf("Stats: Starting Stats Service\n")
	ticker := time.NewTicker(time.Millisecond*10)
	defer ticker.Stop()
	buffer := make([]*Event, 0)
	defer func() {
		fmt.Printf("Stats: Stopped Stats Service\n")
	}()
	currentPerSecondSecond := time.Now().Unix()
	lastQueueUpdate := currentPerSecondSecond
//	lastPerSecondMinute := int64(0)
	register := make(map[int64]map[string]uint64)
	lastAverage := int64(0)
	for {
		select {
		case <-s.stop:
			// Check to see if we got a stop message
			fmt.Printf("Stats: Got stop command\n")
			if (len(buffer) > 0) {
				fmt.Printf("Stats: Inserting %d final stats\n", len(buffer))
				insertStats(cfg, rt, s, buffer)
			}
			return
		case p := <-s.persec:
			// Process "per second" ticks
			//var created_register = ""
			//var created_subkey = ""
			if _,ok := register[currentPerSecondSecond]; !ok {
				register[currentPerSecondSecond] = make(map[string]uint64)
			//	created_register = "created register"
			}
			register_key := strings.Join([]string{p.Component, p.Type}, ":")
			if _, ok := register[currentPerSecondSecond][register_key]; !ok {
				register[currentPerSecondSecond][register_key] = 0
			//	created_subkey = "created subkey"
			}
			register[currentPerSecondSecond][register_key] += p.Count
			//fmt.Printf("  + %s %d %s %s\n", register_key, p.Count, created_register, created_subkey)
		case e := <-s.queue:
			// Empty the stats queue into a buffer
			buffer = append(buffer, e)
		case <-ticker.C:
			// Run on a tick
			now := time.Now().Unix()
			if (now > currentPerSecondSecond) {
				if _,ok := register[now - 16*60]; ok { // Delete from 16 minutes ago
					register[now - 16*60] = nil
				}
				//fmt.Printf("Stats: PerSecond: Second ticked %d\n", currentPerSecondSecond)
				//// TODO: "Broadcast" this
				//for key,value := range register[currentPerSecondSecond] {
				//	fmt.Printf("    > %s -> %d\n", key, value)
				//}
				currentPerSecondSecond = now
			}
			if (now - lastQueueUpdate > 1) {
				if (len(buffer) < 1) {
					continue
				}
				fmt.Printf("Stats: Have %d stats to insert\n", len(buffer))
				insertStats(cfg, rt, s, buffer)
				buffer = nil
				fmt.Printf("Stats: Have %d stats after insert\n", len(buffer))
				lastQueueUpdate = now
			}
			if (now % 60) == 0 && lastAverage != now {
				fmt.Printf("60 Second Averages\n******************\n");
				averages := make(map[string]uint64)
				totals := make(map[string]uint64)
				for i := now - 60; i < now; i += 1 {
					for key,ticks := range register[i] {
						averages[key] += ticks
						totals[key] += ticks
					}
				}
				for key, ticks := range averages {
					fmt.Printf("  + %s -> %d (%d avg)\n", key, totals[key], (ticks / 60))
				}
				lastAverage = now
			}
			// TODO: Minute, 5 minute and 15 minute rolling averages
		}
	}
}

func insertStats(cfg* Config, rt* Runtime, s* Stats, buffer []*Event) {

	now := time.Now()
	timestamp := fmt.Sprintf("%04d-%02d-%02dT%02d:%02d", now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute())
	counters := make(map[string]uint64)
	pfcounters := make(map[string]hll.HLL)
	latencies := make(map[string][]uint64)
	allkeys := make(map[string]bool)
	trueval := []byte("true")

	for _,e := range buffer{
		switch e.Type {
		case EvtTypeCount:
			// Preparing counters
			if _,ok := counters[e.Key]; !ok {
				counters[e.Key] = 0
			}
			counters[e.Key] += e.Count
			allkeys[e.Key] = true
			break
		case EvtTypeCard:
			// Preparing HLLs
			if _,ok := pfcounters[e.Key]; !ok {
				pfsize, err := hll.SizeByP(14)
				if err != nil {
					continue
				}
				pfcounters[e.Key] = make(hll.HLL, pfsize)
			}
			pfcounters[e.Key].Add(highway.Hash(*s.lanes, e.Value))
			allkeys[e.Key] = true
			break
		case EvtTypeLatency:
			if _,ok := latencies[e.Key]; !ok {
				latencies[e.Key] = make([]uint64, 4)
			}
			latencies[e.Key] = append(latencies[e.Key], e.Time)
			allkeys[e.Key] = true
			break
		default:
			fmt.Printf("Stats: Error event %s has unknown type %d\n", e.Key, e.Type)
			break
		}
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	fetched := uint64(64)
	put := uint64(0)
	trans, err := rt.DB.OpenTransaction()
	if err != nil {
		fmt.Printf("Stats: Error: Unable to open transaction to perist stats: %s\n", err.Error())
		return
	}

	for key,value := range counters {
		for _,dtype := range []string{"total", timestamp} {
			var count uint64 = 0
			dbkey := []byte(fmt.Sprintf("stats:counter:%s:%s", key, dtype))
			count_bytes, err := trans.Get(dbkey, nil)
			if err == nil {
				count = binary.LittleEndian.Uint64(count_bytes)
			} else if err == errors.ErrNotFound {
				count_bytes = make([]byte, 8)
			} else {
				fmt.Printf("Stats: Error fetcing existing counter %s: %s\n", key, err.Error())
				continue
			}
			fetched += 1
			fmt.Printf("Stats: %s adding %d to %d\n", dbkey, value, count)
			count += value
			binary.LittleEndian.PutUint64(count_bytes, count)
			err = trans.Put(dbkey, count_bytes, nil)
			if err != nil {
				fmt.Print("Stats: Error adding counter %s\n", dbkey)
			}
			put += 1
		}
	}

	for key, pfcounter := range pfcounters {
		for _,dtype := range []string{"total", timestamp} {
			fmt.Printf("Storing data type %s\n", dtype)
			dbkey := []byte(fmt.Sprintf("stats:hll:%s:%s", key, dtype))
			counter, err := trans.Get(dbkey, nil)
			if err == nil {
				hll.HLL(counter).Merge(pfcounter)
			} else if err == errors.ErrNotFound {
				counter = []byte(pfcounter)
			} else {
				fmt.Printf("Stats: Error fetching existing HLL %s: %s\n", dbkey, err.Error())
			}
			fetched += 1
			fmt.Printf("Stats: %s adding %d counts to %d (size %d)\n", dbkey, pfcounter.EstimateCardinality(), hll.HLL(counter).EstimateCardinality(), len(pfcounter))
			err = trans.Put(dbkey, counter, nil)
			if err != nil {
				fmt.Printf("Stats: Error adding HLL %s\n", dbkey)
			}
			put += 1
		}
	}

	for key, _ := range allkeys {
		dbkey := []byte(fmt.Sprintf("stats:allkeys:%s", key))
		err = trans.Put(dbkey, trueval, nil)
		if err != nil {
			fmt.Printf("Stats: Error adding key to allkeys %s\n", dbkey)
		}
		put += 1
	}

	for key, latency := range latencies {
		fmt.Printf("Stats: %s latency  (size %d)\n", key, len(latency))
	}

	err = trans.Commit()
	if (err != nil) {
		fmt.Printf("Stats: Error committing transaction\n")
		s.TickN("database", "get", fetched)
		s.TickN("database", "put", put)
		s.TickN("database", "get_error", fetched)
		s.TickN("database", "put_error", put)
	}
	s.TickN("database", "get", fetched)
	s.TickN("database", "put", put)
}

func (s *Stats) ListKeys(rt *Runtime) (*[]string, error) {
	ret := make([]string,0)
	iter := rt.DB.NewIterator(util.BytesPrefix([]byte("stats:allkeys:")), nil)
	cnt := 0
	for iter.Next() {
		ret = append(ret, string(iter.Key()[14:])) // strip of stats:allkeys:
		cnt += 1
	}
	s.TickN("database", "get", uint64(cnt))
	if err := iter.Error(); err != nil {
		s.Tick("database", "get_error")
		return nil, err
	}
	iter.Release()
	return &ret, nil
}