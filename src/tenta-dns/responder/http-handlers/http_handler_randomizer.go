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
 * http_handler_randomizer.go: Domain Name Randomizer API
 */

package http_handlers

import (
	"fmt"
	"net/http"
	"tenta-dns/common"
	"tenta-dns/responder/randomizer"
	"tenta-dns/runtime"

	"github.com/sirupsen/logrus"
)

func HandleHTTPRedirector(cfg runtime.NSnitchConfig, rt *runtime.Runtime, d *runtime.ServerDomain, lgr *logrus.Entry) httpHandler {
	var rnd randomizer.Randomizer
	if cfg.RedirectMode == "wordlist" {
		rnd = randomizer.NewWordListRandomizer(cfg)
	} else {
		rnd = randomizer.NewUUIDRandomizer()
	}
	return wrapExtendedHttpHandler(rt, lgr, "randomizer", func(w http.ResponseWriter, r *http.Request, lg *logrus.Entry) {
		data := &common.DefaultJSONObject{
			Status:  "OK",
			Type:    "TENTA_NSNITCH",
			Data:    nil,
			Message: "",
			Code:    200,
		}
		api_response := false
		query := r.URL.Query()
		if _, ok := query["api_response"]; ok {
			api_response = true
		}
		subdomain, err := rnd.Rand()
		extraHeaders(cfg, w, r)
		if err != nil {
			data.Code = 500
			data.Message = "Internal Server Error"
			data.Status = "ERROR"
			mustMarshall(w, data, lg)
		} else {
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			redirecturl := fmt.Sprintf("%s://%s.%s/api/v1/report", scheme, subdomain, d.HostName)
			if api_response {
				data.Data = &map[string]string{"url": redirecturl}
				mustMarshall(w, data, lg)
			} else {
				http.Redirect(w, r, redirecturl, http.StatusFound)
			}
		}
	})
}
