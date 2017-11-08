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
 * player.go: A wrapper around the services to handle panic and recover accordingly
 */

package director

import (
	"sync/atomic"
	"tenta-dns/runtime"
	"time"
)

type starter func()
type cleaner func()

type player struct {
	id      string
	st      starter
	cl      runtime.FailureNotifier
	fails   uint32
	started time.Time
	running bool
	dead    bool
	dnotify chan failure
}

type failure struct {
	p *player
	r interface{}
}

func newPlayer(id string, dnotify chan failure, start starter, clean runtime.FailureNotifier) *player {
	ret := &player{}
	ret.id = id
	ret.dnotify = dnotify
	ret.st = start
	ret.cl = clean
	ret.dead = false
	ret.running = false
	return ret
}

func (p *player) start() {
	p.running = true
	p.started = time.Now()
	go func() {
		defer func() {
			p.running = false
			if rcv := recover(); rcv != nil {
				if p.cl != nil {
					p.cl()
				}
				atomic.AddUint32(&p.fails, 1)
				p.dnotify <- failure{p, rcv}
			}
		}()
		p.st()
	}()
}

func (p *player) didStart() bool {
	return !p.started.Equal(time.Time{})
}
