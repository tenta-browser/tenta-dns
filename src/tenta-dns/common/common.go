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
 * common.go: Common functions
 */

package common

import (
	"crypto/rand"
	"math/big"
	"os"
	"tenta-dns/log"
)

func AddSuffix(start []byte, suffix string) []byte {
	return append(start, []byte("/"+suffix)...)
}

func RandInt(max uint) uint {
	bi, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		lg := log.GetLogger("common")
		lg.Fatalf("Unable to generate a random number: %s", err.Error())
		os.Exit(5)
	}
	return uint(bi.Uint64())
}
