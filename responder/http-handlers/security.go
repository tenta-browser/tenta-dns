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
 * security.go: API security functions
 */

package http_handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/tenta-browser/tenta-dns/runtime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

func computeSignature(cfg runtime.Config, r *http.Request, q url.Values) error {
	var timestamp, key, token, request_url, token_now, secret string
	var placeholder []string
	var timestamp_int, timestamp_now int64
	var error_counter uint
	var ok bool
	var err error
	if placeholder, ok = q["timestamp"]; !ok {
		return errors.New("Missing 'timestamp' query parameter")
	}
	if len(placeholder) < 1 {
		return errors.New("Empty 'timetamp' query parameter")
	}
	timestamp = placeholder[0]
	if placeholder, ok = q["key"]; !ok {
		return errors.New("Missing 'key' parameter")
	}
	if len(placeholder) < 1 {
		return errors.New("Empty 'key' parameter")
	}
	key = placeholder[0]
	if secret, ok = cfg.LookupCreds[key]; !ok {
		return errors.New("Cannot find specified key")
	}
	if placeholder, ok = q["token"]; !ok {
		return errors.New("Missing 'token' parameter")
	}
	if len(placeholder) < 1 {
		return errors.New("Empty 'token' parameter")
	}
	token = placeholder[0]
	if timestamp_int, err = strconv.ParseInt(timestamp, 10, 64); err != nil {
		return errors.New("Could not convert timestamp")
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	request_url = fmt.Sprintf("%s://%s%s", scheme, host, r.URL.Path)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(request_url))
	mac.Write([]byte(timestamp))
	token_now = fmt.Sprintf("%x", mac.Sum(nil))
	timestamp_now = time.Now().Unix()

	var diff int64
	var must_set uint = 10

	// Constant time code
	if timestamp_now > timestamp_int {
		diff = timestamp_now - timestamp_int
	} else {
		diff = timestamp_int - timestamp_now
	}
	if diff < 60 {
		must_set = 0 // No error
	} else {
		must_set = 1 // Error
	}
	error_counter += must_set
	must_set = 10

	if hmac.Equal([]byte(token_now), []byte(token)) {
		must_set = 0 // No Error
	} else {
		must_set = 1 // Error
	}
	error_counter += must_set

	if error_counter == 0 {
		return nil
	} else {
		return errors.New("Signature mismatch")
	}
}
