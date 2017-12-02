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
 * limiter_test.go: Rate limiter tests
 */

package runtime

import (
	"github.com/tenta-browser/tenta-dns/log"
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestLimiter_Basic(t *testing.T) {
	log.SetLogLevel(logrus.DebugLevel)
	tip := net.ParseIP("1.2.3.4")
	offset := 500
	l := StartLimiter(uint64(offset))
	pass := l.CountAndPass(tip)
	if !pass {
		t.Fatal("Expecing a pass on a new new limier, but didn't get one")
	}
	for i := 0; i < offset-1; i += 1 {
		l.CountAndPass(tip)
	}
	time.Sleep(UPDATE_DELAY + time.Second)
	pass = l.CountAndPass(tip)
	if !pass {
		t.Fatal("Expecing a pass while less than limit, but didn't get one")
	}
	limits := 0
	for i := 0; i < 100; i += 1 {
		if !l.CountAndPass(tip) {
			limits += 1
		}
	}
	l.lg.Debugf("Got limited %d times out of 100 (%f)", limits, float32(limits)/float32(100))
	l.Stop()
}

func TestLimiter_AndAHalf(t *testing.T) {
	log.SetLogLevel(logrus.DebugLevel)
	tip := net.ParseIP("1.2.3.4")
	offset := 500
	l := StartLimiter(uint64(offset))
	pass := l.CountAndPass(tip)
	if !pass {
		t.Fatal("Expecing a pass on a new new limier, but didn't get one")
	}
	for i := 0; i < offset-1+int(offset/2); i += 1 {
		l.CountAndPass(tip)
	}
	time.Sleep(UPDATE_DELAY + time.Second)
	limits := 0
	for i := 0; i < 100; i += 1 {
		if !l.CountAndPass(tip) {
			limits += 1
		}
	}
	l.lg.Debugf("Got limited %d times out of 100 (%f)", limits, float32(limits)/float32(100))
	l.Stop()
}

func TestLimiter_DoubleOffset(t *testing.T) {
	log.SetLogLevel(logrus.DebugLevel)
	tip := net.ParseIP("1.2.3.4")
	offset := 500
	l := StartLimiter(uint64(offset))
	pass := l.CountAndPass(tip)
	if !pass {
		t.Fatal("Expecing a pass on a new new limier, but didn't get one")
	}
	for i := 0; i < offset*2-1; i += 1 {
		l.CountAndPass(tip)
	}
	time.Sleep(UPDATE_DELAY + time.Second)
	limits := 0
	for i := 0; i < 100; i += 1 {
		if !l.CountAndPass(tip) {
			limits += 1
		}
	}
	l.lg.Debugf("Got limited %d times out of 100 (%f)", limits, float32(limits)/float32(100))
	limits = 0
	for i := 0; i < 100; i += 1 {
		if !l.CountAndPass(tip) {
			limits += 1
		}
	}
	l.lg.Debugf("Got limited %d times out of 100 (%f)", limits, float32(limits)/float32(100))
	l.Stop()
}

func TestLimiter_TripleOffset(t *testing.T) {
	log.SetLogLevel(logrus.DebugLevel)
	tip := net.ParseIP("1.2.3.4")
	offset := 500
	l := StartLimiter(uint64(offset))
	pass := l.CountAndPass(tip)
	if !pass {
		t.Fatal("Expecing a pass on a new new limier, but didn't get one")
	}
	for i := 0; i < offset*3-1; i += 1 {
		l.CountAndPass(tip)
	}
	time.Sleep(UPDATE_DELAY + time.Second)
	limits := 0
	for i := 0; i < 100; i += 1 {
		if !l.CountAndPass(tip) {
			limits += 1
		}
	}
	l.lg.Debugf("Got limited %d times out of 100 (%f)", limits, float32(limits)/float32(100))
	limits = 0
	for i := 0; i < 100; i += 1 {
		if !l.CountAndPass(tip) {
			limits += 1
		}
	}
	l.lg.Debugf("Got limited %d times out of 100 (%f)", limits, float32(limits)/float32(100))
	l.Stop()
}
