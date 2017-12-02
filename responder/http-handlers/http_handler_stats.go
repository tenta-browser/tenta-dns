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
 * http_handler_stats.go: Server stats API
 */

package http_handlers

import (
	"net/http"
	"github.com/tenta-browser/tenta-dns/common"
	"github.com/tenta-browser/tenta-dns/runtime"

	"github.com/sirupsen/logrus"
)

type StatsLookupError struct {
	s    string
	Code int
}

func (e *StatsLookupError) Error() string {
	return e.s
}

func HandleHTTPStatsLookup(cfg runtime.NSnitchConfig, rt *runtime.Runtime, lgr *logrus.Entry) httpHandler {
	return wrapExtendedHttpHandler(rt, lgr, "stats", func(w http.ResponseWriter, r *http.Request, lg *logrus.Entry) {
		var err *StatsLookupError

		keys, lookuperr := rt.Stats.ListKeys(rt)
		if lookuperr != nil {
			err = &StatsLookupError{s: "Unable to fetch keys", Code: 500}
		}

		data := &common.DefaultJSONObject{
			Status:  "OK",
			Type:    "TENTA_NSNITCH",
			Data:    &common.StatsData{},
			Message: "",
			Code:    200,
		}

		if err == nil {
			data.Data.(*common.StatsData).Keys = keys
		} else {
			data.Status = "ERROR"
			data.Code = err.Code
			lg.WithField("status_code", err.Code).Debugf("Request failed: %s", err.Error())

		}
		extraHeaders(cfg, w, r)
		mustMarshall(w, data, lg)
	})
}
