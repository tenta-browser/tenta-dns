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
 * feedback.go: Provides primitives for Slack webhook notifications
 */

package runtime

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"tenta-dns/log"
	"time"

	"github.com/sirupsen/logrus"
)

type Payload struct {
	dom, err, stack string
}

type Feedback struct {
	nopmode bool
	msg     chan []byte
	stop    chan bool
	wg      *sync.WaitGroup
	whURL   string
	l       *logrus.Entry
}

func (p *Payload) ShortEncode() []byte {

	return []byte("payload=" + url.QueryEscape(fmt.Sprintf("{\"text\":\"Error occured resolving domain `%s`\n`%s`\"}", p.dom, p.err)))
}

func (p *Payload) LongEncode() []byte {
	return []byte("payload=" + url.QueryEscape(fmt.Sprintf("{\"text\":\"Error occured resolving domain `%s`\n`%s`\n%s\"}", p.dom, p.err, p.stack)))
}

func NewPayload(dom, err, stack string) *Payload {
	return &Payload{dom: dom, err: err, stack: stack}
}

func StartFeedback(cfg Config, rt *Runtime) *Feedback {
	f := &Feedback{}
	if t, ok := cfg.SlackFeedback["url"]; !ok {
		f.nopmode = true
	} else {
		f.msg = make(chan []byte)
		f.stop = make(chan bool)
		f.whURL = t
		f.l = log.GetLogger("feedback")
		wg := &sync.WaitGroup{}
		f.wg = wg
		go f.startFeedbackService()
		f.wg.Add(1)
		f.l.Infof("Started Feedback service")
	}
	return f
}

func (f *Feedback) SendFeedback(p *Payload) {
	if !f.nopmode {
		f.msg <- p.ShortEncode()
	}
}

func (f *Feedback) SendMessage(s string) {
	if !f.nopmode {
		m := "payload=" + url.QueryEscape(fmt.Sprintf("{\"text\": \"%s\"}", s))
		f.msg <- []byte(m)
	}
}

func (f *Feedback) startFeedbackService() {
	defer f.wg.Done()
	for {
		select {
		case <-f.stop:
			f.l.Infof("Stop signal received. Exiting.")
			return
		case b := <-f.msg:
			resp, err := http.Post(f.whURL, "application/x-www-form-urlencoded", bytes.NewReader(b))
			defer resp.Body.Close()
			if err != nil {
				f.l.Infof("Unable to send to Slack. Cause [%s]", err.Error())
			} else if resp.StatusCode != 200 {
				f.l.Infof("Unable to send to Slack. HTTP status [%d]", resp.StatusCode)
			}
			break
		case <-time.After(100 * time.Millisecond):
			break
		}
	}
}

func (f *Feedback) Stop() {
	if !f.nopmode {
		defer f.wg.Wait()
		f.stop <- true
	}
}
