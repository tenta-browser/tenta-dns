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
 * http_handler_geolookup.go: Geo Data API
 */

package http_handlers

import (
	"fmt"
	"net"
	"net/http"
	"tenta-dns/common"
	"tenta-dns/runtime"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

type GeoLookupError struct {
	s    string
	Code int
}

func (e *GeoLookupError) Error() string {
	return e.s
}

func HandleHTTPGeoLookup(cfg runtime.NSnitchConfig, rt *runtime.Runtime, lgr *logrus.Entry) httpHandler {
	nodeloc := cfg.Node.MakeNodeLoc()
	return wrapExtendedHttpHandler(rt, lgr, "geolookup", func(w http.ResponseWriter, r *http.Request, lg *logrus.Entry) {
		var ip string
		var err *GeoLookupError
		vars := mux.Vars(r)

		if vars != nil && len(vars) > 0 {
			query := r.URL.Query()
			if query != nil && len(query) > 0 {
				if _, ok := vars["foreign_ip"]; ok {
					ip = vars["foreign_ip"]
					sigError := computeSignature(cfg.Base, r, query)
					if sigError != nil {
						lg.Warnf("Signature Error: %s", sigError)
						err = &GeoLookupError{s: "Invalid signature", Code: 403}
					}
				} else {
					err = &GeoLookupError{s: "Missing required path param 'foreign_ip'", Code: 404}
				}
			} else {
				err = &GeoLookupError{s: "Missing query string", Code: 400}
			}
		} else {
			var spliterr error
			ip, _, spliterr = net.SplitHostPort(r.RemoteAddr)
			if spliterr != nil {
				err = &GeoLookupError{s: fmt.Sprintf("Unble to split remote address: %s", err.Error()), Code: 500}
			}
		}

		data := &common.DefaultJSONObject{
			Status: "OK",
			Type:   "TENTA_NSNITCH",
			Data: &common.GeoLookupData{
				RequestLoc: nil,
				NodeLoc:    nodeloc,
				IP:         "",
			},
			Message: "",
			Code:    200,
		}
		if err == nil {
			geoquery := rt.Geo.Query(ip)
			georesponse, err := geoquery.Response()
			if err == nil && (georesponse.ISP.ASNumber != 0 || georesponse.Location != "") {
				data.Data.(*common.GeoLookupData).RequestLoc = georesponse
			}
			data.Data.(*common.GeoLookupData).IP = ip
		} else {
			data.Status = "ERROR"
			data.Code = err.Code
			lg.WithField("status_code", err.Code).Debugf("Request failed: %s", err.Error())
		}
		extraHeaders(cfg, w, r)
		mustMarshall(w, data, lg)
	})
}
