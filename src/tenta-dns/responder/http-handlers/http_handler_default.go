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
 * http_handler_default.go: Default (404) route
 */

package http_handlers

import (
	"net/http"
	"tenta-dns/common"
	"tenta-dns/runtime"

	"github.com/sirupsen/logrus"
)

func HandleHTTPDefault(cfg runtime.NSnitchConfig, rt *runtime.Runtime, lgr *logrus.Entry) httpHandler {
	return wrapExtendedHttpHandler(rt, lgr, "error", func(w http.ResponseWriter, r *http.Request, lg *logrus.Entry) {
		w.WriteHeader(http.StatusNotFound)
		data := &common.DefaultJSONObject{
			Status:  "ERROR",
			Type:    "TENTA_NSNITCH",
			Data:    nil,
			Message: "Not Found",
			Code:    404,
		}
		lg.Debug("404 Not Found")
		extraHeaders(cfg, w, r)
		mustMarshall(w, data, lg)
	})
}
