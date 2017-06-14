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
 * config.go: Configuration facility
 */

package runtime

import (
  "os"
  "fmt"
  "regexp"
  "io/ioutil"
  "path/filepath"
  "github.com/BurntSushi/toml"
)

type Config struct {
  DatabasePath    string
  DatabaseTTL     int64
  IncludePath     string
  NodeCity        string
  NodeState       string
  NodeCountry     string
  NodeCountryISO  string
  NodeLatitude    float32
  NodeLongitude   float32
  NodeISP         string
  NodeAS          uint
  NodeOrg         string
  NodeTimeZone    string
  Domains         map[string]Domain
  HttpPort        int
  HttpsPort       int
  DnsUdpPort      int
  DnsTcpPort      int
  DnsTlsPort      int
  RedirectMode    string
  WordListPath    string
  CorsDomains     []string
  MaxmindKey      string
  GeoDBPath       string
  LookupCreds     map[string]string
  AdminCreds      map[string]string
  Blacklists      []string
  BlacklistTTL    int64
}

type Domain struct {
  HostName      string
  IPv4          string
  IPv6          string
  CertFile      string
  KeyFile       string
  NameServers   []string
}

func ParseConfig(path string) *Config {
  var cfg Config
  if _, err := toml.DecodeFile(path, &cfg); err != nil {
    fmt.Printf("Error loading config file: %s\n", err.Error())
    os.Exit(1)
  }

  if cfg.IncludePath == "" {
    fmt.Printf("Error loading config: 'includepath' is not set\n")
    os.Exit(1)
  }

  files, err := ioutil.ReadDir(cfg.IncludePath)
  if err != nil {
    fmt.Printf("Error opening include path %s: %s\n", cfg.IncludePath, err.Error())
    os.Exit(1)
  }

  cfg.Domains = make(map[string]Domain)

  for _,file := range files {
    match, err := regexp.MatchString("^.*\\.toml$", file.Name())
    if err == nil && match {
      var d Domain
      _, err := toml.DecodeFile(filepath.Join(cfg.IncludePath, file.Name()), &d)
      if err != nil {
        fmt.Printf("  Warning: Config: Unable to load config file %s", filepath.Join(cfg.IncludePath, file.Name()))
      } else {
        cfg.Domains[d.HostName] = d
      }
    }
  }

  return &cfg
}
