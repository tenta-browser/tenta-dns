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
 * http_handler_bllookup.go: DNS RBL Lookup API
 */

package http_handlers

import (
	"fmt"
	"net"
	"net/http"
	"github.com/tenta-browser/tenta-dns/common"
	"github.com/tenta-browser/tenta-dns/responder/blacklist"
	"github.com/tenta-browser/tenta-dns/runtime"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

type BLLookupError struct {
	s    string
	Code int
}

func (e *BLLookupError) Error() string {
	return e.s
}

func HandleHTTPBLLookup(cfg runtime.NSnitchConfig, rt *runtime.Runtime, lgr *logrus.Entry) httpHandler {
	return wrapExtendedHttpHandler(rt, lgr, "blacklist", func(w http.ResponseWriter, r *http.Request, lg *logrus.Entry) {
		var ip string
		var err *BLLookupError
		var ret *common.BlacklistData
		vars := mux.Vars(r)

		if vars != nil && len(vars) > 0 {
			query := r.URL.Query()
			if query != nil && len(query) > 0 {
				if _, ok := vars["foreign_ip"]; ok {
					ip = vars["foreign_ip"]
					sigError := computeSignature(cfg.Base, r, query)
					if sigError != nil {
						lg.Warnf("Signature Error: %s", sigError)
						err = &BLLookupError{s: "Invalid signature", Code: 403}
					}
				} else {
					err = &BLLookupError{s: "Missing required path param 'foreign_ip'", Code: 404}
				}
			} else {
				err = &BLLookupError{s: "Missing query string", Code: 400}
			}
		} else {
			var spliterr error
			ip, _, spliterr = net.SplitHostPort(r.RemoteAddr)
			if spliterr != nil {
				err = &BLLookupError{s: fmt.Sprintf("Unble to split remote address: %s", spliterr.Error()), Code: 500}
			}
		}

		rawip := net.ParseIP(ip)
		if rawip != nil {
			ipv4 := rawip.To4()
			if ipv4 != nil {
				ret = blacklist.Checkblacklists(cfg, rt, ipv4)
			} else {
				err = &BLLookupError{s: fmt.Sprintf("Unable to perform lookup on IPv6 at present"), Code: 422}
			}
		} else {
			err = &BLLookupError{s: fmt.Sprintf("Unable to parse IP address: %s", ip), Code: 400}
		}

		data := &common.DefaultJSONObject{
			Status:  "OK",
			Type:    "TENTA_NSNITCH",
			Data:    ret,
			Message: "",
			Code:    200,
		}

		if err == nil {
			data.Message = fmt.Sprintf("Did lookup for %s", ip)
		} else {
			data.Status = "ERROR"
			data.Code = err.Code
			lg.WithField("status_code", err.Code).Debugf("Request failed: %s", err.Error())
		}
		extraHeaders(cfg, w, r)
		mustMarshall(w, data, lg)
	})
}
