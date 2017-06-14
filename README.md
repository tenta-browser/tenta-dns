NSnitch
=======

Find out which name servers are snitching on you.

Provides a DNS server which records the IP address of requests made against
it and then makes that IP available via a JSON API. Also provides lookups for
Tor Node membership, DNS blacklist status and Geo data. We welcome people to
use our hosted version on nstoro.com. Please see `APIs` for details.

Contact: developer@tenta.io

Installation
============

1. Run `install-deps.sh` (or `install-deps.bat` on windows).
1. Run `build.sh` or (or `build.bat` on windows).
1. Modify `etc/config.toml` for your installation.
1. 

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

Explanation of DNS Probe
========================

In addition to the REST APIs, core functionality relies upon DNS lookups. After creating glue records pointing
`ns1.nstoro.com` and `ns2.nstoro.com` to the IP(s) of a NSNitch server.

1. From javascript, load nstoro.com/api/v1/randomizer, it will redirect to abc123.nstoro.com/api/v1/report (where abc123 is a big random)
1. Since the domain name is not cached (since it's totally random), the browser initiates a DNS lookup
1. Since the intermediate resolver cannot have it cached, it too initiates a DNS lookup
1. When nsnitch gets the lookup, it returns a valid answer for the domain name, and stores the IP that contacted it along with details
1. When the browser actually makes the request, the stored data is sent back
1. Data automatically expires after 5 minutes

External Dependencies
=====================

The `words.txt` is from http://dreamsteep.com/projects/the-english-open-word-list.html

As per that license, please note:

   UK Advanced Cryptics Dictionary Licensing Information:
   
   Copyright © J Ross Beresford 1993-1999. All Rights Reserved. The following restriction is placed on the use of this publication: if the UK Advanced Cryptics Dictionary is used in a software package or redistributed in any form, the copyright notice must be prominently displayed and the text of this document must be included verbatim.
   
   There are no other restrictions: I would like to see the list distributed as widely as possible.

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

For any questions, please contact developer@tenta.io

Credits
=======

We provide this API free to use on your site. We kindly ask that in return you show us some link love to https://tenta.com. Wed love to know how youre using it, so do let us know!

Contributing
============

We welcome contributions, feedback and plain old complaining. Feel free to open
an issue or shoot us a message to developer@tenta.io. If you'd like to contribute,
please open a pull request and send us an email to sign a contributor agreement.

About Tenta
===========

This browser privacy test tool is brought to you by Team Tenta. Tenta is your [private, encrypted browser](https://tenta.com) that protects your data instead of selling. We're building a next-generation browser that combines all the privacy tools you need, including built-in OpenVPN. Everything is encrypted by default. That means your bookmarks, saved tabs, web history, web traffic, downloaded files, IP address and DNS. A truly incognito browser that's fast and easy.

