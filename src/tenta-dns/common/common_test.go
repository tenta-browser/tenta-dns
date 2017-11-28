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
 * common_test.go: Tests for common functions
 */

package common

import (
	"bytes"
	"net"
	"testing"
)

func TestAddSuffix(t *testing.T) {

	tt := []struct {
		start    []byte
		suffix   string
		expected []byte
	}{
		{[]byte(""), "", []byte("/")},
		{[]byte("a"), "", []byte("a/")},
		{[]byte(""), "a", []byte("/a")},
		{[]byte("ü"), "ü", []byte("ü/ü")},
		{[]byte(""), "ü", []byte("/ü")},
		{[]byte("ü"), "", []byte("ü/")},
		{[]byte("test"), "path", []byte("test/path")},
		{[]byte("test/again"), "path", []byte("test/again/path")},
		{[]byte("test/again\\"), "path", []byte("test/again\\/path")},
		{[]byte{0xe2, 0x8c, 0x98}, "\u2318", []byte{0xe2, 0x8c, 0x98, 0x2f, 0xe2, 0x8c, 0x98}},
	}

	for _, test := range tt {
		actual := AddSuffix(test.start, test.suffix)
		if !bytes.Equal(test.expected, actual) {
			t.Errorf("AddSuffix(%#v, %#v) returned %#v, wanted %#v", test.start, test.suffix, actual, test.expected)
		}
	}
}

func TestIsPrivateIp(t *testing.T) {

	tt := []struct {
		a        net.IP
		expected bool
	}{
		{net.IPv4(10, 0, 0, 0), true},
		{net.IPv4(10, 255, 0, 0), true},
		{net.IPv4(10, 255, 255, 0), true},
		{net.IPv4(10, 255, 255, 255), true},
		{net.IPv4(11, 0, 0, 0), false},
		{net.IPv4(172, 16, 0, 0), true},
		{net.IPv4(172, 16, 255, 0), true},
		{net.IPv4(172, 16, 255, 0), true},
		{net.IPv4(172, 16, 255, 255), true},
		{net.IPv4(172, 31, 0, 0), true},
		{net.IPv4(172, 31, 255, 0), true},
		{net.IPv4(172, 31, 255, 255), true},
		{net.IPv4(172, 32, 0, 0), false},
		{net.IPv4(192, 168, 0, 0), true},
		{net.IPv4(192, 168, 255, 0), true},
		{net.IPv4(192, 168, 255, 255), true},
		{net.IPv4(192, 169, 0, 0), false},
	}

	for _, test := range tt {
		actual := IsPrivateIp(test.a)
		if actual != test.expected {
			t.Errorf("IsPrivateIp(%v) returned %v, wanted %v", test.a, actual, test.expected)
		}
	}
}
