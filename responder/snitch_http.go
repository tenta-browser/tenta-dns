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
 * http.go: HTTP Server
 */

package responder

import (
	"fmt"
	"net/http"
	"time"

	"github.com/tenta-browser/tenta-dns/log"
	handlers "github.com/tenta-browser/tenta-dns/responder/http-handlers"
	"github.com/tenta-browser/tenta-dns/runtime"

	"encoding/base64"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/tenta-browser/tenta-dns/common"
)

func SnitchHTTPServer(cfg runtime.NSnitchConfig, rt *runtime.Runtime, v4 bool, net string, d *runtime.ServerDomain) {
	var ip string
	if v4 {
		ip = d.IPv4
	} else {
		ip = fmt.Sprintf("[%s]", d.IPv6)
	}
	var port int
	if net == "http" {
		if d.HttpPort <= runtime.PORT_UNSET {
			panic("Unable to start a HTTP nsnitch without a valid port")
		}
		port = d.HttpPort
	} else if net == "https" {
		if d.HttpsPort <= runtime.PORT_UNSET {
			panic("Unable to start a HTTPS nsnitch without a valid port")
		}
		port = d.HttpsPort
	} else {
		log.GetLogger("httpsnitch").Warnf("Unknown HTTP net type %s", net)
		return
	}

	lg := log.GetLogger("httpsnitch").WithField("address", ip).WithField("proto", "http").WithField("port", port).WithField("host_name", d.HostName)

	pchan := make(chan interface{}, 1)
	router := mux.NewRouter()
	router.NotFoundHandler = http.HandlerFunc(httpPanicWrap(handlers.HandleHTTPDefault(cfg, rt, lg), pchan))
	router.HandleFunc("/api/v1/status", httpPanicWrap(handlers.HandleHTTPStatus(cfg, rt, lg), pchan)).Methods("GET").Host(d.HostName)
	router.HandleFunc("/api/v1/report", httpPanicWrap(handlers.HandleHTTPReport(cfg, rt, d, lg), pchan)).Methods("GET").Host(fmt.Sprintf("{subdomain:[A-Za-z0-9\\-_]+}.%s", d.HostName))
	router.HandleFunc("/api/v1/randomizer", httpPanicWrap(handlers.HandleHTTPRedirector(cfg, rt, d, lg), pchan)).Methods("GET").Host(d.HostName)
	router.HandleFunc("/api/v1/geolookup", httpPanicWrap(handlers.HandleHTTPGeoLookup(cfg, rt, lg), pchan)).Methods("GET").Host(d.HostName)
	router.HandleFunc("/api/v1/geolookup/{foreign_ip}", httpPanicWrap(handlers.HandleHTTPGeoLookup(cfg, rt, lg), pchan)).Methods("GET").Host(d.HostName)
	router.HandleFunc("/api/v1/blacklist", httpPanicWrap(handlers.HandleHTTPBLLookup(cfg, rt, lg), pchan)).Methods("GET").Host(d.HostName)
	router.HandleFunc("/api/v1/blacklist/{foreign_ip}", httpPanicWrap(handlers.HandleHTTPBLLookup(cfg, rt, lg), pchan)).Methods("GET").Host(d.HostName)
	router.HandleFunc("/api/v1/stats", httpPanicWrap(handlers.HandleHTTPStatsLookup(cfg, rt, lg), pchan)).Methods("GET").Host(d.HostName)
	router.HandleFunc("/speedtest/{size_exp:[0-9]+}", httpPanicWrap(handlers.HandleHTTPSpeedtest(cfg, rt, lg), pchan)).Methods("GET").Host(d.HostName)
	for _, wk := range cfg.WellKnowns {
		var b []byte
		if wk.Base64 {
			var err error
			b, err = base64.StdEncoding.DecodeString(wk.Body)
			if err != nil {
				lg.Warnf("Unable to decode body from well known %s: %s", wk.Path, err)
				continue
			}
		} else {
			b = []byte(wk.Body)
		}
		lg.Infof("Installing well known %s", wk.Path)
		router.HandleFunc(fmt.Sprintf("/.well-known/%s", wk.Path), httpPanicWrap(handlers.HandleHTTPWellKnown(cfg, rt, lg, wk.Path, b, wk.MimeType), pchan)).Methods("GET").Host(d.HostName)
	}

	if net == "http" {
		serveHTTP(rt, d, ip, port, router, lg, pchan)
	} else {
		serveHTTPS(rt, d, ip, port, router, lg, pchan)
	}
}

func httpPanicWrap(hndl func(w http.ResponseWriter, r *http.Request), notify chan interface{}) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rcv := recover(); rcv != nil {
				notify <- rcv
			}
		}()
		hndl(w, r)
	}
}

func serveHTTP(rt *runtime.Runtime, d *runtime.ServerDomain, ip string, port int, handler http.Handler, lg *logrus.Entry, pchan chan interface{}) {

	addr := fmt.Sprintf("%s:%d", ip, port)

	srv := &http.Server{
		Addr:         addr,
		WriteTimeout: 59 * time.Second,
		ReadTimeout:  20 * time.Second,
		Handler:      handler,
	}
	defer rt.OnFinishedOrPanic(func() {
		srv.Shutdown(nil)
		lg.Infof("Shutdown HTTP server for %s", d.HostName)
	}, pchan)
	lg.Info("Started listening for HTTP")

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			lg.Warnf("Failed to setup HTTP server: %s", err.Error())
		}
	}()
}

func serveHTTPS(rt *runtime.Runtime, d *runtime.ServerDomain, ip string, port int, handler http.Handler, lg *logrus.Entry, pchan chan interface{}) {

	addr := fmt.Sprintf("%s:%d", ip, port)

	srv := &http.Server{
		Addr:         addr,
		WriteTimeout: 59 * time.Second,
		ReadTimeout:  20 * time.Second,
		Handler:      handler,
	}
	defer rt.OnFinishedOrPanic(func() {
		srv.Shutdown(nil)
		lg.Info("Shutdown HTTPS server")
	}, pchan)

	srv.TLSConfig = common.TLSConfigLegacyHTTPS()

	lg.Info("Started listening for HTTPS")

	go func() {
		if err := srv.ListenAndServeTLS(d.CertFile, d.KeyFile); err != nil && err != http.ErrServerClosed {
			lg.Warnf("Failed to setup HTTPS server: %s", err.Error())
		}
	}()
}
