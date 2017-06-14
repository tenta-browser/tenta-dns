# NSnitch DNS Server
#
#    Copyright 2017 Tenta, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# For any questions, please contact developer@tenta.io
#
# install-deps.bat: Windows dependency installer

ECHO OFF
set GOPATH=%CD%

echo Installing dependencies to %GOPATH%\pkg

go get -u -v github.com/syndtr/goleveldb/leveldb
go get -u -v github.com/miekg/dns
go get -u -v github.com/leonelquinteros/gorand
go get -u -v github.com/gorilla/mux
go get -u -v github.com/BurntSushi/toml
go get -u -v github.com/sasha-s/go-hll
go get -u -v github.com/oschwald/maxminddb-golang
go get -u -v github.com/dgryski/go-highway
