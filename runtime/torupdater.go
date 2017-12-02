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
 * torupdater.go: Tor node list updater
 */

package runtime

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"github.com/tenta-browser/tenta-dns/log"
	"time"
)

const (
	STATE_NODE = iota
	STATE_PUBLISHED
	STATE_UPDATED
	STATE_ADDRESS
)

func torupdater(cfg Config, rt *Runtime) {
	defer rt.wg.Done()

	lg := log.GetLogger("torupdater")

	ticker := time.NewTicker(time.Hour * 6)

	lg.Info("Starting up")

	for {
		lg.Info("Checking for updates")

		resp, err := http.Get(cfg.TorUrl)
		if err != nil {
			lg.Errorf("Unable to get tor list: %s", err.Error())
		} else {
			// Happy days, we got data

			nodes, err := tokenizeresponse(resp.Body)
			if err != nil {
				lg.Warnf("Got an error tokenizing updates: %s", err)
			}
			resp.Body.Close()

			lg.Debugf("Successfully got %d tor nodes", len(nodes))
			hash := NewTorHash()
			for _, node := range nodes {
				hash.Add(node)
			}

			lg.Debugf("Successfully built a TorHash with %d entries", hash.Len())

			rt.Geo.tordb = hash
		}

		select {
		case <-ticker.C:
			// Nothing to do here, just loop to the top
		case <-rt.stop:
			ticker.Stop()
			lg.Info("Shutting down")
			return
		}
	}
}

/**
 * Parse a series of entries like this:
 *
 *    ExitNode 47E25A3042414FAA1D934D546FBF9E60E80678E2
 *    Published 2017-10-25 08:25:17
 *    LastStatus 2017-10-25 09:03:28
 *    ExitAddress 80.82.67.166 2017-10-25 09:08:02
 *
 * This is a straight forward state based parser with the small
 * wrinkle that a single node may have 1 _or more_ ExitAddresses,
 * so we have to scan until we see the a new ExitNode or we finish.
 */
func tokenizeresponse(body io.ReadCloser) ([]*TorNode, error) {
	scanner := bufio.NewScanner(body)

	state := STATE_NODE
	node := NewTorNode()
	ret := make([]*TorNode, 0)

	for scanner.Scan() {
		line := scanner.Text()

		switch state {
		case STATE_PUBLISHED:
			if strings.HasPrefix(line, "Published") {
				node.Published = parsetortime(line[10:])
				state = STATE_UPDATED
			} else {
				return nil, errors.New("Published prefix not detected")
			}
			break
		case STATE_UPDATED:
			if strings.HasPrefix(line, "LastStatus") {
				node.Updated = parsetortime(line[11:])
				state = STATE_ADDRESS
			} else {
				return nil, errors.New("LastStatus prefix not detected")
			}
			break
		case STATE_ADDRESS:
			if strings.HasPrefix(line, "ExitAddress") {
				parts := strings.SplitAfter(line, " ")
				ip := &ExitAddress{IP: strings.Trim(parts[1], " "), Date: parsetortime(fmt.Sprintf("%s%s", parts[2], parts[3]))}
				node.Addresses = append(node.Addresses, *ip)
				break
			} else if strings.HasPrefix(line, "ExitNode") {
				ret = append(ret, node)
				node = NewTorNode()
				state = STATE_NODE
				// Fallthrough
			} else {
				return nil, errors.New("No transtion from address state found")
			}
			fallthrough
		case STATE_NODE:
			if strings.HasPrefix(line, "ExitNode") {
				node.NodeId = line[9:]
				state = STATE_PUBLISHED
			} else {
				return nil, errors.New("Exit node prefix not detected")
			}
			break
		default:
			return nil, errors.New("State error")
		}
	}
	// Handle the case where we got to the end of the file and we have a pending
	// node which we haven't put onto the output array yet
	if state == STATE_ADDRESS {
		ret = append(ret, node)
	} else {
		// We didn't get a complete node at the end, which is still an error
		return nil, errors.New("Ended in an incorrect state")
	}
	return ret, nil
}

func parsetortime(t string) *time.Time {
	// 2017-05-06 10:02:47
	timestamp, err := time.Parse("2006-01-02 15:04:05", t)
	if err != nil {
		return nil
	}
	return &timestamp
}
