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
 * geoupdater.go: Geo database updater
 */

package runtime

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"github.com/tenta-browser/tenta-dns/log"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
)

const URL_TEMPLATE = "https://download.maxmind.com/app/geoip_download?edition_id=%s&suffix=%s&license_key=%s"
const DB_TEMPLATE_VERSION = "geo-key-%s"

func geoupdater(cfg Config, rt *Runtime) {
	defer rt.wg.Done()
	lg := log.GetLogger("geoupdater")
	products := [2]string{"GeoIP2-City", "GeoIP2-ISP"}
	lg.Debug("Starting up")
	ticker := time.NewTicker(time.Hour)
	for {
		successful := 0
		for _, product := range products {
			var err error
			var url, dbkey, dbfilename string
			var newmd5, oldmd5 []byte
			var resp *http.Response
			var archive *gzip.Reader
			var tr *tar.Reader
			lg.Debugf("Checking for updates to %s", product)
			url = fmt.Sprintf(URL_TEMPLATE, product, "tar.gz.md5", cfg.MaxmindKey)
			lg.Debugf("Checking %s", url)
			resp, err = http.Get(url)
			if err != nil {
				lg.Warnf("Failed fetching %s: %s", url, err.Error())
				goto DONE
			}
			newmd5, err = ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				lg.Warnf("Failed reading %s: %s", url, err.Error())
				goto DONE
			}
			if string(newmd5) == "Invalid license key\n" {
				lg.Warnf("Invalid license key for %s", product)
				err = errors.New("Invalid license key")
				goto DONE
			}
			lg.Debugf("New hash for %s is %s", product, newmd5)
			dbkey = fmt.Sprintf(DB_TEMPLATE_VERSION, product)
			lg.Debugf("Checking database for %s", dbkey)
			oldmd5, err = rt.DBGet([]byte(dbkey))
			if err != nil {
				if err != leveldb.ErrNotFound {
					lg.Warnf("Error reading database: %s", err.Error())
					goto DONE
				} else {
					lg.Debugf("No existing record found in the database for %s", product)
					oldmd5 = make([]byte, 0)
					err = nil
				}
			}
			dbfilename = filepath.Join(cfg.GeoDBPath, fmt.Sprintf("%s-%s.mmdb", product, newmd5))
			if bytes.Compare(oldmd5, newmd5) == 0 {
				if _, err := os.Stat(dbfilename); err == nil {
					lg.Debugf("Nothing to do, %s is up to date", product)
					goto DONE
				}
				lg.Warnf("Database isn't updated, but %s is missing", dbfilename)
			}
			lg.Debugf("Need to update the underlying database %s", dbfilename)
			url = fmt.Sprintf(URL_TEMPLATE, product, "tar.gz", cfg.MaxmindKey)
			lg.Debugf("Fetching from %s", url)
			resp, err = http.Get(url)
			if err != nil {
				lg.Warnf("Failed to download database %s from %s: %s", dbfilename, url, err.Error())
				goto DONE
			}
			archive, err = gzip.NewReader(resp.Body)
			if err != nil {
				lg.Warnf("Failed to open return data as a gzip file %s: %s", url, err.Error())
				resp.Body.Close()
				goto DONE
			}
			tr = tar.NewReader(archive)

			for {
				header, innerErr := tr.Next()
				if innerErr == io.EOF {
					goto DONE
				}
				if innerErr != nil {
					err = innerErr
					goto DONE
				}

				if matched, _ := regexp.MatchString("^.*mmdb$", header.Name); matched {
					lg.Debugf("Found DB File: %s (%d bytes), writing to %s", header.Name, header.Size, dbfilename)

					fhandle, innerErr := os.OpenFile(dbfilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
					if innerErr != nil {
						lg.Warnf("Error opening geo database file %s for writing: %s", dbfilename, innerErr.Error())
						err = innerErr
						goto DONE
					}

					size, innerErr := io.Copy(fhandle, tr)
					if innerErr != nil {
						fhandle.Close()
						err = innerErr
						lg.Warnf("Error writing out geo database file %s: %s", dbfilename, innerErr.Error())
						goto DONE
					}

					lg.Debugf("Successfully updated %d bytes into %s", size, dbfilename)
					fhandle.Close()

					innerErr = rt.DBPut([]byte(dbkey), newmd5)
					if innerErr != nil {
						err = innerErr
						lg.Warnf("Error saving geo file %s version to DB %s: %s", dbfilename, dbkey, innerErr.Error())
						goto DONE
					}

					if bytes.Compare(oldmd5, newmd5) != 0 {
						oldfilename := filepath.Join(cfg.GeoDBPath, fmt.Sprintf("%s-%s.mmdb", product, oldmd5))

						if _, innerErr := os.Stat(oldfilename); innerErr == nil {
							lg.Debugf("Removing old geo database file %s", oldfilename)
							innerErr = os.Remove(oldfilename)
							if innerErr != nil {
								lg.Warnf("Error removing old geo database file %s: %s", oldfilename, innerErr.Error())
							}
						}
					}
					break
				}
			}
			successful += 1
		DONE:
			if archive != nil {
				archive.Close()
			}
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
			if err != nil {
				lg.Errorf("Failed updating %s: %s", product, err.Error())
			}
		}
		if successful > 0 {
			// TODO: Count number of databases desired and determine success based on that, not just any success as it is now
			lg.Debugf("Did a successful update, notifying Geo and updating database")
			rt.Geo.Reload()
			startTimeBytes := make([]byte, 8)
			binary.LittleEndian.PutUint64(startTimeBytes, uint64(time.Now().Unix()))
			if err := rt.DBPut([]byte(KEY_GEODB_UPDATED), startTimeBytes); err != nil {
				lg.Warnf("Unable to write to DB %s: %s", KEY_GEODB_UPDATED, err.Error())
			}
		}
		select {
		case <-ticker.C:
			// Nothing to do here, go to the top of the loop and check for updates
		case <-rt.stop:
			ticker.Stop()
			lg.Debug("Shutting down")
			return
		}
	}
}
