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
 * nsnitch.go: Main entry point
 */

package main

import (
  "os"
  "fmt"
  "flag"
  "syscall"
  "os/signal"
  "nsnitch/runtime"
  "nsnitch/responder"
)

var (
  cfgfile  = flag.String("config", "", "Path to the configuration file")
)

func usage()  {
  fmt.Println("NSnitch Intermediate Resolver Analyzer")
  fmt.Println("Used as part of the Tenta Browser Privacy Test")
  fmt.Println("Options:")
  flag.PrintDefaults()
}

func main() {
  flag.Usage = usage
  flag.Parse()

  if *cfgfile == "" {
    fmt.Println("Error: Missing Config path path\n")
    usage()
    os.Exit(1)
  }

  cfg := runtime.ParseConfig(*cfgfile)
  rt := runtime.NewRuntime(cfg)

  go responder.HTTPServer(cfg, rt)
  go responder.DNSServer(cfg, rt)

  sig := make(chan os.Signal)
  signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
  s := <-sig
  fmt.Printf("\nSignal (%s) received, stopping\n", s)

  rt.Shutdown()

  os.Exit(0)
}
