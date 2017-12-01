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
 * helpers.go: HTTP Handler Helpers
 */

package http_handlers

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"tenta-dns/common"
	"tenta-dns/runtime"
	"time"

	"github.com/leonelquinteros/gorand"
	"github.com/sirupsen/logrus"
)

type httpHandler func(w http.ResponseWriter, r *http.Request)
type extendedHttpHandler func(w http.ResponseWriter, r *http.Request, lg *logrus.Entry)

func wrapExtendedHttpHandler(rt *runtime.Runtime, lg *logrus.Entry, name string, ehandler extendedHttpHandler) httpHandler {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		request_id, err := gorand.UUID()
		if err != nil {
			lg.Errorf("Unable to generate request id: %s", err.Error())
			panic(err)
		}
		// TODO: Should we put a canonical "request timestamp" here?
		lg = lg.WithField("request_uri", r.RequestURI).WithField("request_id", request_id).WithField("http_handler", name)
		lg.Debug("Handling request")
		ehandler(w, r, lg)
		end := time.Now()
		latency := uint64(end.Unix() - start.Unix())
		rt.Stats.Tick("http", "requests:all")
		rt.Stats.Tick("http", fmt.Sprintf("requests:%s", name))
		rt.Stats.Latency("http:requests:all", latency)
		rt.Stats.Latency(fmt.Sprintf("http:requests:%s", name), latency)
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err == nil {
			rt.Stats.Card("http:remote_ips", ip)
		}
	}
}

func extraHeaders(cfg runtime.NSnitchConfig, w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	corsenabled := false
	for _, org := range cfg.CorsDomains {
		if fmt.Sprintf("http://%s", org) == origin {
			corsenabled = true
			break
		}
		if fmt.Sprintf("https://%s", org) == origin {
			corsenabled = true
			break
		}
	}
	if corsenabled {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
}

func mustMarshall(w http.ResponseWriter, djo *common.DefaultJSONObject, lg *logrus.Entry) {
	out, err := json.Marshal(djo)
	if err != nil {
		lg.Warnf("Failed marshalling JSON: %s", err.Error())
		w.Write([]byte("{\"status\":\"ERROR\",\"type\":\"TENTA_NSNITCH\",\"data\":null,\"message\":\"Internal Server Error\",\"code\":500}"))
	} else {
		w.Write(out)
	}
}
