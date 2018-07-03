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
 * http_handler_speedtest.go: Speedtest API
 */

package http_handlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/tenta-browser/tenta-dns/runtime"

	"github.com/sirupsen/logrus"
)

func HandleHTTPSpeedtest(cfg runtime.NSnitchConfig, rt *runtime.Runtime, d *runtime.ServerDomain, content map[int]string, lgr *logrus.Entry) httpHandler {
	lg := lgr.WithField("api", "speedtest")
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		fileIndStr := vars["size_exp"]
		fileInd, e := strconv.Atoi(fileIndStr)
		if e != nil {
			lg.Errorf("Cannot convert expected numeric input (got [%s])", fileIndStr)
			w.WriteHeader(400)
			return
		}
		if fileInd < 0 || fileInd > 10 {
			lg.Errorf("Invalid file size requested [%d]", fileInd)
			w.WriteHeader(400)
			return
		}

		w.Header().Set("Content-Disposition", "attachment; filename=speedtest.txt")
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content[fileInd])))
		w.Write([]byte(content[fileInd]))
	}
}
