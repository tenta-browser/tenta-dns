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
 * torupdater.go: Tor node list updater
 */

package runtime

import (
	"fmt"
	"time"
	"net/http"
	"io"
	"bufio"
	"strings"
	"errors"
)

const TOR_URL = "https://check.torproject.org/exit-addresses"

const STATE_NODE = 1
const STATE_PUBLISHED = 2
const STATE_UPDATED = 3
const STATE_ADDRESS = 4

func torupdater(cfg* Config, rt* Runtime) {
	defer rt.wg.Done()

	ticker := time.NewTicker(time.Hour*6)

	fmt.Printf("Tor Updater: Starting up\n")

	for {
		fmt.Printf("Tor Updater: Checking for updates\n")

		resp, err := http.Get(TOR_URL)
		if err != nil {
			fmt.Printf("Tor Updater: Unable to get tor list: %s\n", err.Error())
		} else {
			// Happy days, we got data

			nodes, err := tokenizeresponse(resp.Body)
			if err != nil {
				fmt.Printf("Tor Updater: Got an error tokenizing: %s\n", err)
			}
			resp.Body.Close()

			fmt.Printf("Tor Updater: Successfully got %d tor nodes\n", len(nodes))
			hash := NewTorHash()
			for _,node := range nodes {
				hash.Add(node)
			}

			fmt.Printf("Tor Updater: Successfully built a TorHash with %d entries\n", hash.Len())

			rt.Geo.tordb = hash
		}

		select {
		case <-ticker.C:
			// Nothing to do here, just loop to the top
		case <-rt.stop:
			ticker.Stop()
			fmt.Printf("Tor Updater: Shutting down\n")
			return
		}
	}
}

func tokenizeresponse(body io.ReadCloser) ([]*TorNode, error) {
	scanner := bufio.NewScanner(body)

	state := STATE_NODE
	node := NewTorNode()
	ret := make([]*TorNode,0)

	for scanner.Scan() {
		line := scanner.Text()

		switch state {
		case STATE_PUBLISHED:
			if (strings.HasPrefix(line, "Published")) {
				node.Published = parsetortime(line[10:])
				state = STATE_UPDATED
			} else {
				return nil, errors.New("Published prefix not detected")
			}
			break
		case STATE_UPDATED:
			if (strings.HasPrefix(line, "LastStatus")) {
				node.Updated = parsetortime(line[11:])
				state = STATE_ADDRESS
			} else {
				return nil, errors.New("LastStatus prefix not detected")
			}
			break
		case STATE_ADDRESS:
			if (strings.HasPrefix(line, "ExitAddress")) {
				parts := strings.SplitAfter(line, " ")
				ip := &ExitAddress{IP: strings.Trim(parts[1], " "), Date:parsetortime(fmt.Sprintf("%s%s", parts[2], parts[3]))}
				node.Addresses = append(node.Addresses, *ip)
				break
			} else if (strings.HasPrefix(line, "ExitNode")) {
				//fmt.Printf("Tor Updater: Got Node: %s\n", node.toString())
				ret = append(ret, node)
				node = NewTorNode()
				state = STATE_NODE
				// Fallthrough
			} else {
				return nil, errors.New("No transtion from address state found")
			}
			fallthrough
		case STATE_NODE:
			if (strings.HasPrefix(line, "ExitNode")) {
				node.NodeId = line[9:]
				state = STATE_PUBLISHED
			} else {
				return nil, errors.New("Exit node prefix not detected")
			}
			break
		default:
			return nil, errors.New("State error")
		}
		//fmt.Printf("Tor Updater: Got line: %s\n", line)
	}
	return ret, nil
}

func parsetortime(t string) *time.Time {
	// 2017-05-06 10:02:47
	timestamp, err := time.Parse("2006-01-02 15:04:05", t)
	if err != nil {
		fmt.Printf("Tor Updater: Warning: Error parsing Tor Time %s\n", err.Error())
		return nil
	}
	return &timestamp
}