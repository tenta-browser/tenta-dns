/**
 * NSnitch DNS Server
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
	"time"
	"net/http"
	"crypto/tls"
	"encoding/json"
	"encoding/binary"
	"github.com/miekg/dns"
	"github.com/gorilla/mux"
	"github.com/syndtr/goleveldb/leveldb"
	"nsnitch/common"
	"nsnitch/runtime"
	"net"
	"net/url"
	"errors"
	"strconv"
	"crypto/sha256"
	"crypto/hmac"
)

type httpHandler func(w http.ResponseWriter, r *http.Request)

func HTTPServer(cfg *runtime.Config, rt *runtime.Runtime) {
	router := mux.NewRouter()
	router.NotFoundHandler = http.HandlerFunc(handleHTTPDefault(cfg, rt))
	for _, d := range cfg.Domains {
		router.HandleFunc("/api/v1/status", handleHTTPStatus(cfg, rt, &d)).Methods("GET").Host(d.HostName)
		router.HandleFunc("/api/v1/report", handleHTTPReport(cfg, rt, &d)).Methods("GET").Host(fmt.Sprintf("{subdomain:[A-Za-z0-9\\-_]+}.%s", d.HostName))
		router.HandleFunc("/api/v1/randomizer", handleHTTPRedirector(cfg, rt, &d)).Methods("GET").Host(d.HostName)
		router.HandleFunc("/api/v1/geolookup", handleHTTPGeoLookup(cfg, rt, &d)).Methods("GET").Host(d.HostName)
		router.HandleFunc("/api/v1/geolookup/{foreign_ip}", handleHTTPGeoLookup(cfg, rt, &d)).Methods("GET").Host(d.HostName)
		router.HandleFunc("/api/v1/blacklist", handleHTTPBLLookup(cfg, rt, &d)).Methods("GET").Host(d.HostName)
		router.HandleFunc("/api/v1/blacklist/{foreign_ip}", handleHTTPBLLookup(cfg, rt, &d)).Methods("GET").Host(d.HostName)
		router.HandleFunc("/api/v1/stats", handleHTTPStatsLookup(cfg, rt, &d)).Methods("GET").Host(d.HostName)
	}
	http.Handle("/", router)

	if (cfg.HttpPort > 0) {
		for _, d := range cfg.Domains {
			if d.IPv4 != "" {
				rt.AddService()
				go serveHTTP(cfg, rt, d.HostName, d.IPv4, cfg.HttpPort)
			}
			if d.IPv6 != "" {
				rt.AddService()
				go serveHTTP(cfg, rt, d.HostName, fmt.Sprintf("[%s]", d.IPv6), cfg.HttpPort)
			}
		}
	}

	if (cfg.HttpsPort > 0) {
		for _, d := range cfg.Domains {
			if (d.CertFile == "") {
				continue
			}
			if d.IPv4 != "" {
				rt.AddService()
				go serveHTTPS(cfg, rt, d.HostName, d.IPv4, cfg.HttpsPort)
			}
			if d.IPv6 != "" {
				rt.AddService()
				go serveHTTPS(cfg, rt, d.HostName, fmt.Sprintf("[%s]", d.IPv6), cfg.HttpsPort)
			}
		}
	}
}

func serveHTTP(cfg *runtime.Config, rt *runtime.Runtime, hostname string, ip string, port int) {
	addr := fmt.Sprintf("%s:%d", ip, port)

	srv := &http.Server{
		Addr: addr,
		WriteTimeout: 59 * time.Second,
		ReadTimeout: 20 * time.Second,
	}
	defer rt.OnFinished(func() {
		srv.Shutdown(nil)
		fmt.Printf("Shutdown HTTP server for %s on %s\n", hostname, addr)
	})
	fmt.Printf("Started listening HTTP for %s on %s\n", hostname, addr)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Failed to setup HTTP server: %s\n", err.Error())
		}
	}()
}

func serveHTTPS(cfg *runtime.Config, rt *runtime.Runtime, hostname string, ip string, port int) {
	d := cfg.Domains[hostname]
	addr := fmt.Sprintf("%s:%d", ip, port)

	srv := &http.Server{
		Addr: addr,
		WriteTimeout: 59 * time.Second,
		ReadTimeout: 20 * time.Second,
	}
	defer rt.OnFinished(func() {
		srv.Shutdown(nil)
		fmt.Printf("Shutdown HTTPS server for %s on %s\n", hostname, addr)
	})

	tlscfg := &tls.Config{
		MinVersion:               tls.VersionTLS10,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
	}

	srv.TLSConfig = tlscfg

	fmt.Printf("Started listening HTTPS for %s on %s\n", hostname, addr)
	go func() {
		if err := srv.ListenAndServeTLS(d.CertFile, d.KeyFile); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Failed to setup HTTPS server: %s\n", err.Error())
		}
	}()
}

func handleHTTPReport(cfg *runtime.Config, rt *runtime.Runtime, d *runtime.Domain) httpHandler {
	return func(w http.ResponseWriter, r *http.Request) {
		key := []byte(fmt.Sprintf("query/%s", r.Host))
		//fmt.Printf("Handling report request for d.HostName: %s, r.Host: %s\n", d.HostName, r.Host)

		if ! dns.IsSubDomain(d.HostName, r.Host) {
			fmt.Printf("Handling request for invalid domain. Serving: %s, Requested: %s\n", d.HostName, r.Host)
			handleHTTPDefault(cfg, rt)(w, r)
			return
		}

		data := &DefaultJSONObject{
			Status:  "OK",
			Type:    "TENTA_NSNITCH",
			Data:    nil,
			Message: "",
			Code:    200,
		}

		_, err := rt.DBGet(common.AddSuffix(key, runtime.KEY_NAME))
		if err != nil {
			// Fix for race where this request completes before the DNS goroutine has finished writing the DB record
			time.Sleep(500 * time.Millisecond)
			_, err := rt.DBGet(common.AddSuffix(key, runtime.KEY_NAME))
			if err != nil {
				fmt.Printf("DB Error: %s\n", err.Error())
				data.Status = "ERROR"
				if err == leveldb.ErrNotFound {
					w.WriteHeader(http.StatusNotFound)
					data.Message = "Not Found"
					data.Code = 404
				} else {
					w.WriteHeader(http.StatusInternalServerError)
					data.Message = "Internal Error"
					data.Code = 500
				}
				mustMarshall(w, data)
				return
			}
		}
		recarr, _ := rt.DBGet(common.AddSuffix(key, runtime.KEY_DATA))
		rec := &DNSTelemetry{}
		json.Unmarshal(recarr, rec)

		data.Data = rec

		extraHeaders(cfg, w, r)
		mustMarshall(w, data)
	}
}

type GeoLookupError struct {
	s		string
	Code		int
}
func (e* GeoLookupError) Error() string {
	return e.s
}

type StatsLookupError struct {
	s		string
	Code		int
}
func (e* StatsLookupError) Error() string {
	return e.s
}

type BLLookupError struct {
	s		string
	Code		int
}
func (e* BLLookupError) Error() string {
	return e.s
}


func computeSignature(cfg* runtime.Config, r* http.Request, q url.Values) error {
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

func handleHTTPBLLookup(cfg *runtime.Config, rt *runtime.Runtime, d *runtime.Domain) httpHandler {
	return func(w http.ResponseWriter, r *http.Request) {
		var ip string
		var err* BLLookupError
		var ret *BlacklistData
		vars := mux.Vars(r)

		if vars != nil && len(vars) > 0 {
			query := r.URL.Query()
			if query != nil && len(query) > 0 {
				if _, ok := vars["foreign_ip"]; ok {
					ip = vars["foreign_ip"]
					sigError := computeSignature(cfg, r, query)
					if sigError != nil {
						fmt.Printf("Sig Error: %s\n", sigError)
						err = &BLLookupError{s:"Invalid signature", Code: 403}
					}
				} else {
					err = &BLLookupError{s:"Missing required path param 'foreign_ip'", Code: 404}
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
				ret = checkblacklists(cfg, rt, ipv4)
			} else {
				err = &BLLookupError{s: fmt.Sprintf("Unable to perform lookup on IPv6 at present"), Code: 422}
			}
		} else {
			err = &BLLookupError{s: fmt.Sprintf("Unable to parse IP address: %s", ip), Code: 400}
		}

		data := &DefaultJSONObject{
			Status: "OK",
			Type:   "TENTA_NSNITCH",
			Data: ret,
			Message: "",
			Code:    200,
		}

		if err == nil {
			data.Message = fmt.Sprintf("Did lookup for %s", ip)
		} else {
			data.Status = "ERROR"
			data.Code = err.Code
		}
		extraHeaders(cfg, w, r)
		mustMarshall(w, data)
	}
}

func handleHTTPStatsLookup(cfg *runtime.Config, rt *runtime.Runtime, d *runtime.Domain) httpHandler {
	return func(w http.ResponseWriter, r *http.Request) {
		var err* StatsLookupError

		keys, lookuperr := rt.Stats.ListKeys(rt)
		if lookuperr != nil {
			err = &StatsLookupError{s:"Unable to fetch keys", Code: 500}
		}

		data := &DefaultJSONObject{
			Status: "OK",
			Type:   "TENTA_NSNITCH",
			Data: &StatsData{},
			Message: "",
			Code:    200,
		}

		if err == nil {
			data.Data.(*StatsData).Keys = keys
		} else {
			data.Status = "ERROR"
			data.Code = err.Code
		}
		extraHeaders(cfg, w, r)
		mustMarshall(w, data)
	}
}

func handleHTTPGeoLookup(cfg *runtime.Config, rt *runtime.Runtime, d *runtime.Domain) httpHandler {
	nodeloc := makeNodeLoc(cfg)
	return func(w http.ResponseWriter, r *http.Request) {
		var ip string
		var err* GeoLookupError
		vars := mux.Vars(r)

		if vars != nil && len(vars) > 0 {
			query := r.URL.Query()
			if query != nil && len(query) > 0 {
				if _, ok := vars["foreign_ip"]; ok {
					ip = vars["foreign_ip"]
					sigError := computeSignature(cfg, r, query)
					if sigError != nil {
						fmt.Printf("Sig Error: %s\n", sigError)
						err = &GeoLookupError{s:"Invalid signature", Code: 403}
					}
				} else {
					err = &GeoLookupError{s:"Missing required path param 'foreign_ip'", Code: 404}
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

		data := &DefaultJSONObject{
			Status: "OK",
			Type:   "TENTA_NSNITCH",
			Data: &GeoLookupData{
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
				data.Data.(*GeoLookupData).RequestLoc = georesponse
			}
			data.Data.(*GeoLookupData).IP = ip
		} else {
			data.Status = "ERROR"
			data.Code = err.Code
		}
		extraHeaders(cfg, w, r)
		mustMarshall(w, data)
	}
}

func handleHTTPRedirector(cfg *runtime.Config, rt *runtime.Runtime, d *runtime.Domain) httpHandler {
	var rnd Randomizer
	if cfg.RedirectMode == "wordlist" {
		rnd = NewWordListRandomizer(cfg)
	} else {
		rnd = NewUUIDRandomizer()
	}
	return func(w http.ResponseWriter, r *http.Request) {
		data := &DefaultJSONObject{
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
			mustMarshall(w, data)
		} else {
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			redirecturl := fmt.Sprintf("%s://%s.%s/api/v1/report", scheme, subdomain, d.HostName)
			if api_response {
				data.Data = &map[string]string{"url": redirecturl}
				mustMarshall(w, data)
			} else {
				http.Redirect(w, r, redirecturl, http.StatusFound)
			}
		}
	}
}

func handleHTTPDefault(cfg *runtime.Config, rt *runtime.Runtime) httpHandler {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		data := &DefaultJSONObject{
			Status:  "ERROR",
			Type:    "TENTA_NSNITCH",
			Data:    nil,
			Message: "Not Found",
			Code:    404,
		}
		extraHeaders(cfg, w, r)
		mustMarshall(w, data)
	}
}

func handleHTTPStatus(cfg *runtime.Config, rt *runtime.Runtime, d *runtime.Domain) httpHandler {
	return func(w http.ResponseWriter, r *http.Request) {
		startTimeBytes, err := rt.DBGet([]byte(runtime.KEY_START_TIME))
		runfor := uint32(0)
		data := &DefaultJSONObject{
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
		mustMarshall(w, data)
	}
}

func extraHeaders(cfg *runtime.Config, w http.ResponseWriter, r *http.Request) {
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

func mustMarshall(w http.ResponseWriter, djo *DefaultJSONObject) {
	out, err := json.Marshal(djo)
	if err != nil {
		w.Write([]byte("{\"status\":\"ERROR\",\"type\":\"TENTA_NSNITCH\",\"data\":null,\"message\":\"Internal Server Error\",\"code\":500}"))
	} else {
		w.Write(out)
	}
}
