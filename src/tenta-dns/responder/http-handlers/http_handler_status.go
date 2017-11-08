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
 * http_handler_status.go: Server status API
 */

package http_handlers

import (
	"encoding/binary"
	"fmt"
	"net/http"
	"tenta-dns/common"
	"tenta-dns/runtime"
	"time"

	"github.com/sirupsen/logrus"
)

func HandleHTTPStatus(cfg runtime.NSnitchConfig, rt *runtime.Runtime, lgr *logrus.Entry) httpHandler {
	return wrapExtendedHttpHandler(rt, lgr, "status", func(w http.ResponseWriter, r *http.Request, lg *logrus.Entry) {
		startTimeBytes, err := rt.DBGet([]byte(runtime.KEY_START_TIME))
		runfor := uint32(0)
		data := &common.DefaultJSONObject{
			Status: "OK",
			Type:   "TENTA_NSNITCH",
			Data: map[string]string{
				"uptime":    "unset",
				"database":  "available",
				"geoupdate": "unset",
			},
			Message: "System Okay",
			Code:    200,
		}
		if err != nil {
			data.Status = "Error"
			data.Data.(map[string]string)["database"] = "failed"
			data.Message = "System Error"
			data.Code = 500
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			runfor = uint32(time.Now().Unix()) - uint32(binary.LittleEndian.Uint64(startTimeBytes))
			data.Data.(map[string]string)["uptime"] = fmt.Sprintf("%d", runfor)
			if geoUpdateTimeBytes, err := rt.DBGet([]byte(runtime.KEY_GEODB_UPDATED)); err == nil {
				updated := uint32(time.Now().Unix()) - uint32(binary.LittleEndian.Uint64(geoUpdateTimeBytes))
				data.Data.(map[string]string)["geoupdate"] = fmt.Sprintf("%d", updated)
			}
		}
		extraHeaders(cfg, w, r)
		mustMarshall(w, data, lg)
	})
}
