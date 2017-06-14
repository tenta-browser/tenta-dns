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
 * geoupdater.go: Geo database updater
 */

package runtime

import (
	"fmt"
	"time"
	"net/http"
	"encoding/binary"
	"io/ioutil"
	"bytes"
	"github.com/syndtr/goleveldb/leveldb"
	"archive/tar"
	"compress/gzip"
	"io"
	"regexp"
	"os"
	"path/filepath"
)

const URL_TEMPLATE = "https://download.maxmind.com/app/geoip_download?edition_id=%s&suffix=%s&license_key=%s"
const DB_TEMPLATE_VERSION = "geo-key-%s"

func geoupdater(cfg* Config, rt* Runtime) {
	defer rt.wg.Done()
	products := [2]string{"GeoIP2-City", "GeoIP2-ISP"}
	fmt.Println("Geo Updater: starting up")
	ticker := time.NewTicker(time.Hour);
	for {
		successful := 0
		for _,product := range products {
			var err error
			var url, dbkey, dbfilename string
			var newmd5, oldmd5 []byte
			var resp *http.Response
			var archive *gzip.Reader
			var tr *tar.Reader
			fmt.Printf("Geo Updater: Checking for updates to %s\n", product)
			url = fmt.Sprintf(URL_TEMPLATE, product, "tar.gz.md5", cfg.MaxmindKey)
			fmt.Printf("Geo Updater: Checking %s\n", url)
			resp, err = http.Get(url)
			if err != nil {
				fmt.Printf("Geo Updater: Error fetching %s\n", url)
				goto DONE
			}
			newmd5, err = ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				fmt.Printf("Geo Updter: Error reading %s\n", url)
				goto DONE
			}
			fmt.Printf("Geo Updater: New hash for %s is %s\n", product, newmd5)
			dbkey = fmt.Sprintf(DB_TEMPLATE_VERSION, product)
			fmt.Printf("Geo Updater: Checking database for %s\n", dbkey)
			oldmd5, err = rt.DBGet([]byte(dbkey))
			if err != nil {
				if err != leveldb.ErrNotFound {
					fmt.Printf("Geo Updater: Error reading database\n")
					goto DONE
				} else {
					fmt.Printf("Geo Updater: No existing record found in the database for %s\n", product)
					oldmd5 = make([]byte, 0)
					err = nil
				}
			}
			dbfilename = filepath.Join(cfg.GeoDBPath, fmt.Sprintf("%s-%s.mmdb", product, newmd5))
			if bytes.Compare(oldmd5, newmd5) == 0 {
				if _, err := os.Stat(dbfilename); err == nil {
					fmt.Printf("Geo Updater: Nothing to do, %s is up to date\n", product)
					goto DONE
				}
				fmt.Printf("Geo Updater: Database isn't updated, but %s is missing\n", dbfilename)
			}
			fmt.Printf("Geo Updater: Need to update the underlying database\n")
			url = fmt.Sprintf(URL_TEMPLATE, product, "tar.gz", cfg.MaxmindKey)
			fmt.Printf("Geo Updater: Fetching from %s\n", url)
			resp, err = http.Get(url)
			if err != nil {
				fmt.Printf("Geo Updater: Failed to download database %s\n", url)
				goto DONE
			}
			archive, err = gzip.NewReader(resp.Body)
			if err != nil {
				fmt.Printf("Geo Updater: Failed to open return data as a gzip file %s\n", url)
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
					fmt.Printf("Geo Updater: Found DB File: %s (%d)\n", header.Name, header.Size)


					fmt.Printf("Geo Updater: Writing file to %s\n", dbfilename)

					fhandle, innerErr := os.OpenFile(dbfilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
					if innerErr != nil {
						fmt.Printf("Geo Updater: Error opening geo database file for writing\n")
						err = innerErr
						goto DONE
					}

					size, innerErr := io.Copy(fhandle, tr)
					if innerErr != nil {
						fhandle.Close()
						err = innerErr
						fmt.Printf("Geo Updater: Error writing out geo database file\n")
						goto DONE
					}

					fmt.Printf("Geo Updater: Successfully updated %d bytes into %s\n", size, dbfilename)
					fhandle.Close()

					innerErr = rt.DBPut([]byte(dbkey), newmd5)
					if innerErr != nil {
						err = innerErr
						fmt.Printf("Geo Updater: Error saving geo file version to DB\n")
						goto DONE
					}

					if bytes.Compare(oldmd5, newmd5) != 0 {
						oldfilename := filepath.Join(cfg.GeoDBPath, fmt.Sprintf("%s-%s.mmdb", product, oldmd5))

						if _, innerErr := os.Stat(oldfilename); innerErr == nil {
							fmt.Printf("Geo Updater: Removing old geo database file %s\n", oldfilename)
							innerErr = os.Remove(oldfilename)
							if innerErr != nil {
								fmt.Printf("Geo Updater: Error removing old geo database file %s: %s\n", oldfilename, innerErr.Error())
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
				fmt.Printf("Geo Updater: ERROR Updating %s: %s\n", product, err.Error())
			}
		}
		if successful > 0 {
			fmt.Printf("Geo Updater: Did a successful update, notifying Geo and updating database\n")
			rt.Geo.Reload()
			startTimeBytes := make([]byte, 8)
			binary.LittleEndian.PutUint64(startTimeBytes, uint64(time.Now().Unix()))
			if err := rt.DBPut([]byte(KEY_GEODB_UPDATED), startTimeBytes); err != nil {
				fmt.Printf("Geo Updater: ERROR Unable to write to DB: %s\n", err.Error())
			}
		}
		select {
		case <-ticker.C:
			// Nothing to do here, go to the top of the loop and check for updates
		case <-rt.stop:
			ticker.Stop()
			fmt.Println("Geo Updater: shutting down")
			return
		}
	}

}