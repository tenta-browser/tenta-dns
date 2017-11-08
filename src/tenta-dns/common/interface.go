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
 * interface.go: Declaration and routines of (network) Interface objects
 */

package common

import (
	"fmt"
	"net"
)

type InterfaceType int
type InterfaceState int

const (
	TypeUnknown InterfaceType = iota
	TypeIPv4
	TypeIPv6
)

const (
	StateUnknown InterfaceState = iota
	StateUp
	StateDown
	StateMissing
	StateCriticalFailure
)

type Interface struct {
	ID   string
	IP   net.IP
	Type InterfaceType
	Name string
}

func (i Interface) String() string {
	return fmt.Sprintf("For %s, %s %s", i.ID, i.IP.String(), i.Type.String())
}

type Status struct {
	State InterfaceState
	ID    string
}

func (s Status) String() string {
	return fmt.Sprintf("%s is %s", s.ID, s.State.String())
}

func (t InterfaceType) String() string {
	switch t {
	case TypeIPv4:
		return "IPv4"
	case TypeIPv6:
		return "IPv6"
	case TypeUnknown:
		fallthrough
	default:
		return "Unknown"
	}
}

func (s InterfaceState) String() string {
	switch s {
	case StateUp:
		return "Up"
	case StateDown:
		return "Down"
	case StateMissing:
		return "Missing"
	case StateCriticalFailure:
		return "CritFail"
	case StateUnknown:
		fallthrough
	default:
		return "Unknown"
	}
}
