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
 * config.go: Configuration facility
 */

package runtime

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"

	"github.com/tenta-browser/tenta-dns/anycast"
	"github.com/tenta-browser/tenta-dns/common"
	"github.com/tenta-browser/tenta-dns/log"
	"github.com/tenta-browser/tenta-dns/zones"

	"github.com/BurntSushi/toml"
	"github.com/sirupsen/logrus"
	"encoding/base64"
)

const PORT_UNSET = 0
const PORT_DISABLED = -1
const LIMITER_RPS_THRESHOLD = 500

type Config struct {
	DatabasePath      string
	DatabaseTTL       int64
	IncludePath       string
	MaxmindKey        string
	GeoDBPath         string
	TorUrl            string
	LookupCreds       map[string]string
	AdminCreds        map[string]string
	Peers             map[string]anycast.Peer
	BGP               anycast.BGPConfig
	Netblocks         map[string]common.Netblock
	DefaultHttpPort   int
	DefaultHttpsPort  int
	DefaultDnsUdpPort int
	DefaultDnsTcpPort int
	DefaultDnsTlsPort int
	RateThreshold     uint64
	OutboundIPs       []string
	SlackFeedback     map[string]string
}

type NSnitchConfig struct {
	Base         Config
	ConfigFile   string
	Domains      map[string]*ServerDomain
	Node         NodeConfig
	RedirectMode string
	WordListPath string
	CorsDomains  []string
	Blacklists   []string
	WellKnowns	 []WellKnown
	BlacklistTTL int64
}

type RecursorConfig struct {
	Base       Config
	ConfigFile string
	Domains    map[string]*ServerDomain
	OpenNic    bool
}

type AuthorityConfig struct {
	Base       Config
	ConfigFile string
	Domains    map[string]*ServerDomain
	ZonesPath  string
	Zones      *zones.ZoneSet
}

type ServerDomain struct {
	HostName    string
	IPv4        string
	IPv6        string
	CertFile    string
	KeyFile     string
	NameServers []string
	HttpPort    int
	HttpsPort   int
	DnsUdpPort  int
	DnsTcpPort  int
	DnsTlsPort  int
}

type NodeConfig struct {
	City       string
	State      string
	Country    string
	CountryISO string
	Latitude   float32
	Longitude  float32
	ISP        string
	AS         uint
	Org        string
	TimeZone   string
}

type WellKnown struct {
	Path		string
	Body		string
	Base64		bool
	MimeType	string
}

type ConfigHolder struct {
	MasterConfig Config
	NSnitchs     []NSnitchConfig
	Recursors    []RecursorConfig
	Authorities  []AuthorityConfig
}

const (
	ModuleTypeNSnitch = iota
	ModuleTypeRecursor
	ModuleTypeAuthority
	ModuleTypeUnknown
)

func ParseConfig(path string, checkonly bool, ignoreplatform bool) ConfigHolder {
	var cfg Config
	var hld ConfigHolder
	hld.NSnitchs = make([]NSnitchConfig, 0)
	hld.Recursors = make([]RecursorConfig, 0)
	hld.Authorities = make([]AuthorityConfig, 0)
	lg := log.GetLogger("config")
	cnt := 0
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		lg.Errorf("Failed loading config file '%s': %s", path, err.Error())
		os.Exit(1)
	}
	cnt += 1

	if cfg.RateThreshold == 0 {
		lg.Warnf("Rate limiter threshold not set, using default value of %d", LIMITER_RPS_THRESHOLD)
		cfg.RateThreshold = LIMITER_RPS_THRESHOLD
	}

	ensureDefaultPorts(&cfg)
	if cfg.IncludePath == "" {
		lg.Errorf("'includepath' is not set")
		os.Exit(1)
	}
	lg.Debugf("Opening include path %s", cfg.IncludePath)

	files, err := ioutil.ReadDir(cfg.IncludePath)
	if err != nil {
		lg.Errorf("Unable to open include path %s: %s", cfg.IncludePath, err.Error())
		os.Exit(1)
	}

	hld.MasterConfig = cfg

	if cfg.BGP.Enabled() && len(cfg.Netblocks) > 0 && !common.AnycastSupported() && !ignoreplatform {
		lg.Error("Anycast not supported on this platform. Please use explicit IP addresses.")
		os.Exit(3)
	}
	if cfg.BGP.Enabled() && len(cfg.Netblocks) > 0 {
		for _, b := range cfg.Netblocks {
			if len(b.Communities) > 0 && !cfg.BGP.EnableCommunities {
				lg.Errorf("Invalid BGP setup. Netblock %s/%d requires community support but global BGP config disables it.", b.IP, b.Netmask)
				os.Exit(3)
			}
			for _, c := range b.Communities {
				match, err := regexp.MatchString("^\\d{1,5}:\\d{1,5}$", c)
				if err != nil || !match {
					lg.Errorf("Invalid community definition %s. It should be like \"ASNUM:COMMUNITY\"", c)
					os.Exit(3)
				}
			}
		}
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		lg.Debugf("Checking file %s", file.Name())
		match, err := regexp.MatchString("^.*\\.toml$", file.Name())
		if err == nil && match {
			cfgname := filepath.Join(cfg.IncludePath, file.Name())
			filebody, err := ioutil.ReadFile(cfgname)
			if err != nil {
				lg.Warnf("Unable to load config file %s", cfgname)
				if checkonly {
					os.Exit(4)
				} else {
					continue
				}
			}
			isnsnitch, err := regexp.Match("\\s*servertype\\s*=\\s*\"nsnitch\"", filebody)
			if err != nil {
				lg.Warnf("Unable to match while processing config files. Failed in file %s", cfgname)
				if checkonly {
					os.Exit(4)
				}
			}
			isrecursor, err := regexp.Match("\\s*servertype\\s*=\\s*\"recursor\"", filebody)
			if err != nil {
				lg.Warnf("Unable to match while processing config files. Failed in file %s", cfgname)
				if checkonly {
					os.Exit(4)
				}
			}
			isauthority, err := regexp.Match("\\s*servertype\\s*=\\s*\"authority\"", filebody)
			if err != nil {
				lg.Warnf("Unable to match while processing config files. Failed in file %s", cfgname)
				if checkonly {
					os.Exit(4)
				}
			}
			truecount := 0
			moduletype := ModuleTypeUnknown
			if isnsnitch {
				lg.Debugf("File %s being loaded as an NSNitch config file", cfgname)
				truecount += 1
				moduletype = ModuleTypeNSnitch
			}
			if isrecursor {
				lg.Debugf("File %s being loaded as a Recursor config file", cfgname)
				truecount += 1
				moduletype = ModuleTypeRecursor
			}
			if isauthority {
				lg.Debugf("File %s being loaded as a Authority config file", cfgname)
				truecount += 1
				moduletype = ModuleTypeAuthority
			}
			if truecount < 1 || moduletype == ModuleTypeUnknown {
				lg.Fatalf("Config file %s defines no module type, but must define one.", cfgname)
				os.Exit(1)
			}
			if truecount > 1 {
				lg.Fatalf("Config file %s defines more than one module type, but should only define one.", cfgname)
				os.Exit(1)
			}
			switch moduletype {
			case ModuleTypeNSnitch:
				c, err := parseNSnitchConfig(hld.MasterConfig, cfgname, lg, ignoreplatform)
				if err == nil {
					c.ConfigFile = cfgname
					c.Base = hld.MasterConfig
					hld.NSnitchs = append(hld.NSnitchs, c)
					cnt += 1
				} else {
					lg.Errorf("Unable to load %s: %s", cfgname, err.Error())
					if checkonly {
						os.Exit(4)
					}
				}
				break
			case ModuleTypeRecursor:
				r, err := parseRecursorConfig(hld.MasterConfig, cfgname, lg, ignoreplatform)
				if err == nil {
					r.ConfigFile = cfgname
					r.Base = hld.MasterConfig
					hld.Recursors = append(hld.Recursors, r)
					cnt += 1
				} else {
					lg.Errorf("Unable to load %s: %s", cfgname, err.Error())
					if checkonly {
						os.Exit(4)
					}
				}
				break
			case ModuleTypeAuthority:
				a, err := parseAuthorityConfig(hld.MasterConfig, cfgname, lg, ignoreplatform)
				if err == nil {
					a.ConfigFile = cfgname
					a.Base = hld.MasterConfig
					hld.Authorities = append(hld.Authorities, a)
					cnt += 1
				} else {
					lg.Errorf("Unable to load %s: %s", cfgname, err.Error())
					if checkonly {
						os.Exit(4)
					}
				}
				break
			default:
				lg.Errorf("Invalid config parser state, unknonwn module type")
				os.Exit(1)
			}
		} else if err != nil {
			lg.Warnf("Error: Unable to match file names while loading module configs: %s", err.Error())
			if checkonly {
				os.Exit(4)
			}
		}
	}

	doms := make(map[string]string)

	for _, n := range hld.NSnitchs {
		for _, d := range n.Domains {
			err := depublicateDomains(doms, d, n.ConfigFile, lg)
			if err != nil {
				lg.Fatalf("Server conflict")
				os.Exit(1)
			}
		}
	}
	for _, r := range hld.Recursors {
		for _, d := range r.Domains {
			err := depublicateDomains(doms, d, r.ConfigFile, lg)
			if err != nil {
				lg.Fatalf("Server conflict")
				os.Exit(1)
			}
		}
	}
	for _, a := range hld.Authorities {
		for _, d := range a.Domains {
			err := depublicateDomains(doms, d, a.ConfigFile, lg)
			if err != nil {
				lg.Fatalf("Server conflict")
				os.Exit(1)
			}
		}
	}

	for s, f := range doms {
		lg.Debugf("Have service %s from %s", s, f)
	}

	lg.Debugf("Successfully loaded %d config files", cnt)

	return hld
}

func depublicateDomains(doms map[string]string, d *ServerDomain, cfgfile string, lg *logrus.Entry) error {
	netstrings := make([]string, 0)
	for _, ip := range [...]string{d.IPv4, d.IPv6} {
		if ip == "" {
			continue
		}
		if ip == d.IPv6 {
			ip = fmt.Sprintf("[%s]", ip)
		}
		if d.DnsTlsPort != PORT_DISABLED {
			netstrings = append(netstrings, fmt.Sprintf("dns-tls://%s:%d", ip, d.DnsTlsPort))
		}
		if d.DnsUdpPort != PORT_DISABLED {
			netstrings = append(netstrings, fmt.Sprintf("dns-udp://%s:%d", ip, d.DnsUdpPort))
		}
		if d.DnsTcpPort != PORT_DISABLED {
			netstrings = append(netstrings, fmt.Sprintf("dns-tcp://%s:%d", ip, d.DnsTcpPort))
		}
		if d.HttpPort != PORT_DISABLED {
			netstrings = append(netstrings, fmt.Sprintf("http://%s:%d", ip, d.HttpPort))
		}
		if d.HttpsPort != PORT_DISABLED {
			netstrings = append(netstrings, fmt.Sprintf("https://%s:%d", ip, d.HttpsPort))
		}
	}
	for _, s := range netstrings {
		if val, ok := doms[s]; ok {
			lg.Errorf("Got service %s from file %s, but a conflicting service was defined in file %s", s, cfgfile, val)
			return errors.New(fmt.Sprintf("Got service %s from file %s, but a conflicting service was defined in file %s", s, cfgfile, val))
		}
		doms[s] = cfgfile
	}
	return nil
}

func parseNSnitchConfig(master Config, path string, lg *logrus.Entry, ignoreplatform bool) (NSnitchConfig, error) {
	var cfg NSnitchConfig
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		lg.Errorf("Failed loading config file '%s': %s", path, err.Error())
		return cfg, errors.New(fmt.Sprintf("Unable to open '%s': %s", path, err.Error()))
	}
	for _, domain := range cfg.Domains {
		err := validateAndDefaultDomain(master, lg, domain, path)
		if err != nil {
			return cfg, err
		}
	}
	if !ignoreplatform && len(cfg.Domains) < 1 {
		lg.Warnf("Unable to parse NSnitch config: Contains no configured domains to bind to")
		return cfg, errors.New("Unable to parse NSnitch config: Contains no configured domains to bind to")
	}
	return cfg, nil
}

func parseRecursorConfig(master Config, path string, lg *logrus.Entry, ignoreplatform bool) (RecursorConfig, error) {
	var cfg RecursorConfig
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		lg.Errorf("Failed loading config file '%s': %s", path, err.Error())
		return cfg, errors.New(fmt.Sprintf("Unable to open '%s': %s", path, err.Error()))
	}
	for _, domain := range cfg.Domains {
		err := validateAndDefaultDomain(master, lg, domain, path)
		if err != nil {
			return cfg, err
		}
	}
	if !ignoreplatform && len(cfg.Domains) < 1 {
		lg.Warnf("Unable to parse Recursor config: Contains no configured domains to bind to")
		return cfg, errors.New("Unable to parse Recursor config: Contains no configured domains to bind to")
	}
	return cfg, nil
}

func parseAuthorityConfig(master Config, path string, lg *logrus.Entry, ignoreplatform bool) (AuthorityConfig, error) {
	var cfg AuthorityConfig
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		lg.Errorf("Failed loading config file '%s': %s", path, err.Error())
		return cfg, errors.New(fmt.Sprintf("Unable to open '%s': %s", path, err.Error()))
	}
	for _, domain := range cfg.Domains {
		err := validateAndDefaultDomain(master, lg, domain, path)
		if err != nil {
			return cfg, err
		}
	}
	if !ignoreplatform && len(cfg.Domains) < 1 {
		lg.Warnf("Unable to parse Authority config: Contains no configured domains to bind to")
		return cfg, errors.New("Unable to parse Recursor config: Contains no configured domains to bind to")
	}

	zset, err := zones.LoadZones(cfg.ZonesPath)
	if err != nil {
		lg.Errorf("Unable to load zones for Authority config %s: %s", path, err.Error())
		return cfg, err
	}
	cfg.Zones = &zset

	return cfg, nil
}

func validateAndDefaultDomain(master Config, lg *logrus.Entry, d *ServerDomain, path string) error {
	if d.HttpPort == PORT_UNSET {
		d.HttpPort = master.DefaultHttpPort
	}
	if d.DnsTcpPort == PORT_UNSET {
		d.DnsTcpPort = master.DefaultDnsTcpPort
	}
	if d.DnsUdpPort == PORT_UNSET {
		d.DnsUdpPort = master.DefaultDnsUdpPort
	}
	if len(d.CertFile) > 0 && len(d.KeyFile) > 0 && (d.DnsTlsPort != PORT_DISABLED || d.HttpsPort != PORT_DISABLED) {
		if _, err := os.Stat(d.CertFile); os.IsNotExist(err) {
			lg.Warnf("Unable to open certificate file %s", d.CertFile)
			return err
		}
		if _, err := os.Stat(d.KeyFile); os.IsNotExist(err) {
			lg.Warnf("Unable to open key file %s", d.CertFile)
			return err
		}
		if d.DnsTlsPort == PORT_UNSET {
			d.DnsTlsPort = master.DefaultDnsTlsPort
		}
		if d.HttpsPort == PORT_UNSET {
			d.HttpsPort = master.DefaultHttpsPort
		}
	} else {
		if len(d.CertFile) > 0 || len(d.KeyFile) > 0 {
			// Only warn if one of these items has been set
			lg.Warnf("Disabling TLS and HTTPS on %s from %s. Both cerfile and keyfile need to be set to enable these.", d.HostName, path)
		}
		d.DnsTlsPort = PORT_DISABLED
		d.HttpsPort = PORT_DISABLED
	}
	if d.DnsTlsPort == PORT_UNSET {
		d.DnsTlsPort = PORT_DISABLED
	}
	if d.HttpsPort == PORT_UNSET {
		d.HttpsPort = PORT_DISABLED
	}
	return nil
}

func ensureDefaultPorts(cfg *Config) {
	if cfg.DefaultDnsUdpPort == PORT_UNSET {
		cfg.DefaultDnsUdpPort = PORT_DISABLED
	}
	if cfg.DefaultDnsTcpPort == PORT_UNSET {
		cfg.DefaultDnsTcpPort = PORT_DISABLED
	}
	if cfg.DefaultDnsTlsPort == PORT_UNSET {
		cfg.DefaultDnsTlsPort = PORT_DISABLED
	}
	if cfg.DefaultHttpPort == PORT_UNSET {
		cfg.DefaultHttpPort = PORT_DISABLED
	}
	if cfg.DefaultHttpsPort == PORT_UNSET {
		cfg.DefaultHttpsPort = PORT_DISABLED
	}
}

func (cfg *NodeConfig) MakeNodeLoc() *common.GeoLocation {
	nodeloc := &common.GeoLocation{
		Position: &common.Position{
			Latitude:  cfg.Latitude,
			Longitude: cfg.Longitude,
			Radius:    10,
			TimeZone:  cfg.TimeZone,
		},
		ISP: &common.ISP{
			ISP:            cfg.ISP,
			ASNumber:       cfg.AS,
			ASOrganization: cfg.ISP,
			Organization:   cfg.Org,
		},
	}
	locString := cfg.Country
	if shouldIncludeSubdivision(cfg.CountryISO) && cfg.State != "" {
		locString = fmt.Sprintf("%s, %s", cfg.State, locString)
	}
	if cfg.City != "" {
		locString = fmt.Sprintf("%s, %s", cfg.City, locString)
	}

	nodeloc.Location = locString
	nodeloc.LocationI18n = make(map[string]string)
	nodeloc.LocationI18n["en"] = locString

	nodeloc.City = cfg.City
	nodeloc.Country = cfg.Country
	nodeloc.CountryISO = cfg.CountryISO
	nodeloc.TorNode = nil

	return nodeloc
}
