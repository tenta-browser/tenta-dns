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
 * nsnitch.go: Main entry point
 */

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"tenta-dns/director"
	"tenta-dns/log"
	"tenta-dns/runtime"

	"github.com/coreos/go-systemd/daemon"
	"github.com/sirupsen/logrus"
)

var (
	cfgfile        = flag.String("config", "", "Path to the configuration file")
	checkonly      = flag.Bool("check", false, "Perform a config check and immediately exit")
	ignoreplatform = flag.Bool("ignoreplatform", false, "Ignore platform when performing config checking (e.g. check configs on windows to run on linux)")
	quiet          = flag.Bool("quiet", false, "Don't produce any output to the terminal")
	verbose        = flag.Bool("verbose", false, "Produce lots of output to the terminal (overrides the -quiet flag)")
	systemd        = flag.Bool("systemd", false, "Assume running under systemd and send control notifications. NOTE: Behavior is undefined if using this flag without systemd")
)

func usage() {
	fmt.Println("Tenta DNS")
	fmt.Println("Full featured DNS server with DNSSEC and DNS-over-TLS")
	fmt.Println("Options:")
	flag.PrintDefaults()
}

func main() {
	log.SetLogLevel(logrus.InfoLevel)
	flag.Usage = usage
	flag.Parse()

	if *quiet {
		log.SetLogLevel(logrus.FatalLevel)
	}
	if *verbose {
		log.SetLogLevel(logrus.DebugLevel)
	}

	if *systemd {
		daemon.SdNotify(false, "RELOADING=1")
	}

	lg := log.GetLogger("main")
	lg.Info("Starting up")

	if *cfgfile == "" {
		lg.Error("Error: Missing Config path path")
		usage()
		os.Exit(1)
	}

	if *checkonly && *ignoreplatform {
		lg.Debug("Ignoring platform restrictions in config file check")
	}
	hld := runtime.ParseConfig(*cfgfile, *checkonly, *checkonly && *ignoreplatform)
	if *checkonly {
		lg.Info("Config files are valid, exiting from config check mode")
		os.Exit(0)
	}

	d := director.NewDirector(hld)
	d.Orchestrate(*systemd)

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	lg.Info(fmt.Sprintf("Signal (%s) received, stopping", s))
	if *systemd {
		daemon.SdNotify(false, "STOPPING=1")
	}

	d.Stop()

	os.Exit(0)
}
