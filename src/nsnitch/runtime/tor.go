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
 * tor.go: Tor node checker
 */

package runtime

import (
	"time"
	"fmt"
)

type TorNode struct {
	NodeId		string
	Published 	*time.Time
	Updated		*time.Time
	Addresses	[]ExitAddress
}

type ExitAddress struct {
	IP	string
	Date	*time.Time
}

func NewTorNode() *TorNode {
	return &TorNode{Addresses:make([]ExitAddress,0)}
}

func (t *TorNode) toString() string {
	return fmt.Sprintf("Node %s with %d IPs", t.NodeId, len(t.Addresses))
}

type TorHash struct {
	hash map[string]string
	cnt  int
}

func NewTorHash() *TorHash {
	return &TorHash{hash: make(map[string]string), cnt: 0}
}

func (t* TorHash) Add(node *TorNode) {
	for _, addr := range node.Addresses {
		t.hash[addr.IP] = node.NodeId
		t.cnt += 1
	}
}

func (t* TorHash) Exists(ip string) (string, bool) {
	if nodeid, ok := t.hash[ip]; ok {
		return nodeid, true
	}
	return "", false
}

func (t* TorHash) Len() int {
	return t.cnt
}