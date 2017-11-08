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
 * randomizer.go: Generate random subdomain names
 */

package randomizer

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"tenta-dns/common"
	"tenta-dns/log"
	"tenta-dns/runtime"
	"unicode"

	"github.com/leonelquinteros/gorand"
)

type Randomizer interface {
	Rand() (string, error)
}

type UUIDRandomizer struct{}

func NewUUIDRandomizer() Randomizer {
	return Randomizer(UUIDRandomizer{})
}

func (rnd UUIDRandomizer) Rand() (string, error) {
	uuid, err := gorand.UUID()
	return string(uuid), err
}

type WordRandomizer struct {
	wordlist    []string
	wordlistlen uint
}

func NewWordListRandomizer(cfg runtime.NSnitchConfig) Randomizer {
	lg := log.GetLogger("wordlist")
	lg.Debug("Setting up wordlist randomizer")
	rnd := WordRandomizer{}
	var (
		err    error
		part   []byte
		prefix bool
	)
	file, err := os.Open(cfg.WordListPath)
	if err != nil {
		lg.Errorf("Unable to open wordlist file %s", cfg.WordListPath)
		panic(errors.New("Unable to open wordlist file"))
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	buffer := bytes.NewBuffer(make([]byte, 0))

	for {
		if part, prefix, err = reader.ReadLine(); err != nil {
			break
		}
		buffer.Write(part)
		if !prefix {
			rnd.wordlist = append(rnd.wordlist, buffer.String())
			buffer.Reset()
		}
	}

	if err != io.EOF {
		lg.Warnf("Failed reading %s: %s", cfg.WordListPath, err.Error())
	}

	rnd.wordlistlen = uint(len(rnd.wordlist))

	lg.Debugf("Read %d words while setting up the wordlist randomizer", rnd.wordlistlen)

	return Randomizer(rnd)
}

func (rnd WordRandomizer) Rand() (string, error) {
	buffer := bytes.NewBuffer(make([]byte, 0))
	for i := 0; i < 4; i += 1 {
		if i != 0 {
			switch common.RandInt(7) {
			case 0, 1:
				buffer.WriteString(fmt.Sprintf("%d", common.RandInt(100)))
			case 2, 3, 4:
				buffer.WriteString("-")
				break
			case 5:
				buffer.WriteString("4")
				break
			default:
				// Do nothing, no separtor
				break
			}
		}
		word := rnd.wordlist[common.RandInt(rnd.wordlistlen)]
		switch common.RandInt(4) {
		case 0, 1, 2:
			for i, v := range word {
				word = string(unicode.ToUpper(v)) + word[i+1:]
				break
			}
			break
		default:
			// Do nothing
			break
		}
		buffer.WriteString(word)
	}
	return buffer.String(), nil
}
