Tenta DNS
=========

[![Build Status](https://travis-ci.org/tenta-browser/tenta-dns.svg?branch=master)](https://travis-ci.org/tenta-browser/tenta-dns)
[![Go Report Card](https://goreportcard.com/badge/github.com/tenta-browser/tenta-dns)](https://goreportcard.com/report/github.com/tenta-browser/tenta-dns)
[![GoDoc](https://godoc.org/github.com/tenta-browser/tenta-dns?status.svg)](https://godoc.org/github.com/tenta-browser/tenta-dns)

![Tenta Gopher](logo.png?raw=true "Tenta Gopher")

A full-fledged DNS solution, including DNSSEC and DNS-over-TLS

Tenta DNS provides a DNS server suite comprising an authoritative DNS server, recursive DNS server, and NSnitch,
which provides a DNS server capable of recording the IP address of requests made against
it and then makes that IP available via a JSON API. Tenta DNS also provides lookups for
Tor Node membership, DNS blacklist status and Geo data. Finally, Tenta DNS includes built-in
BGP integration, offering single engine convenience for DNS anycasting. We welcome people to
use our hosted versions of recursive resolver and NSnitch. Please see `Usage`,
for details on how to set Tenta DNS as your default DNS resolver, or `APIs`,
for NSnitch REST API information.

Contact: developer@tenta.io

Usage
=====

Just want to use our hosted recursive resolver? We offer two options, using either [OpenNIC](https://opennic.org)
root servers or the normal ICANN root servers.

Our OpenNIC nameservers are at `99.192.182.100` and `99.192.182.101`

ICANN nameservers are at `99.192.182.200` and `99.192.182.201`

Please consult our [how-to page](https://tenta.com/dns-setup-guides), on setting up your DNS resolver.

Installation
============

1. Run `install-deps.sh` (or `install-deps.bat` on windows).
1. Run `build.sh` or (or `build.bat` on windows).
1. Modify `etc/config.toml` and `etc\conf.d\*.toml` for your installation.
1. 🙈🙉🙊

REST APIs
=========

We'd be thrilled for people to use our APIs as part of your app or system. In order to use our hosted API, please provide
a link to https://tenta.com/ with the text "Powered by Tenta" or similar. If you need to perform arbitrary lookups (e.g.
you want information for an IP different than the requesting IP, like from a server), message us for an API key. If
you need CORS whitelisted for the public APIs, please email us with your domain name(s).

All APIs under the path `/api/v1`.

* `status`: Public status checking endpoint for basic liveness monitoring
* `report`: Generate a report from a specific DNS lookup. Only works on subdomains, explicity looked up via DNS already.
* `randomizer`: Generate (and optionally redirect to) a random subdomain. Set `?api_response=true` to get a JSON result
instead of a redirect.
* `geolookup`: GeoIP info about the requesting IP.
* `geolookup/{IP}`: GeoIP info about the specified IP address. Requires auth.
* `blacklist`: Perform DNS blacklist lookup for the requesting IP.
* `blacklist/{IP}`: DNS blacklist info for the specified IP address. Requires auth.
* `stats`: Work in Progress. Server performance information.

Explanation of NSnitch DNS Probe
================================

In addition to the REST APIs, core functionality relies upon DNS lookups. After creating glue records pointing
`ns1.nstoro.com` and `ns2.nstoro.com` to the IP(s) of a Tenta DNS server.

1. From javascript, load nstoro.com/api/v1/randomizer, it will redirect to abc123.nstoro.com/api/v1/report (where abc123 is a big random)
1. Since the domain name is not cached (since it's totally random), the browser initiates a DNS lookup
1. Since the intermediate resolver cannot have it cached, it too initiates a DNS lookup
1. When nsnitch gets the lookup, it returns a valid answer for the domain name, and stores the IP that contacted it along with details
1. When the browser actually makes the request, the stored data is sent back
1. Data automatically expires after 5 minutes

External Dependencies
=====================

We rely on lots of excellent open source libraries, including [miekg/dns](https://github.com/miekg/dns) and
[osrg/gobgp](https://github.com/osrg/gobgp), as well as many others. For a complete list of our dependencies and required notification,
please take a look at [NOTICES.md](NOTICES.md)

The `words.txt` file used for random names in NSnitch is from [dreamsteep.com](http://diginoodles.com/The_English_Open_Word_List_%28EOWL%29).

License
=======

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Please see [LICENSE](LICENSE) for more. For any questions, please contact developer@tenta.io

Credits
=======

You're welcome to use the hosted version of our JSON APIs free on your site. We kindly ask that in return you show us some link love to https://tenta.com. We’d love to know how you’re using it, so do let us know!

Contributing
============

We welcome contributions, feedback and plain old complaining. Feel free to open
an issue or shoot us a message to developer@tenta.io. If you'd like to contribute,
please open a pull request and send us an email to sign a contributor agreement.

About Tenta
===========

Tenta DNS is brought to you by Team Tenta. Tenta is your [private, encrypted browser](https://tenta.com) that protects your data instead of selling it. We're building a next-generation browser that combines all the privacy tools you need, including built-in OpenVPN. Everything is encrypted by default. That means your bookmarks, saved tabs, web history, web traffic, downloaded files, IP address and DNS. A truly incognito browser that's fast and easy.
