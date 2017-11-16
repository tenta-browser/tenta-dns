package main

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"sync"
	"tenta-dns/log"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

var (
	ip       = flag.String("ip", "127.0.0.1", "IP address to stress")
	port     = flag.Uint("port", 53, "Port to test")
	tcp      = flag.Bool("tcp", false, "Whether to use TCP mode")
	tls      = flag.Bool("tls", false, "Whether to use TLS (implies -tcp)")
	workers  = flag.Uint("workers", 0, "Number of simultaneous test workers to run (0 => autoselect)")
	quiet    = flag.Bool("quiet", false, "Don't produce any output to the terminal")
	verbose  = flag.Bool("verbose", false, "Produce lots of output to the terminal (overrides the -quiet flag)")
	limit    = flag.Uint("limit", 1000, "How many domain names to use in the test (max 1000000)")
	errfile  = flag.String("errfile", "", "If specified, write errors to this file")
	printver = flag.Bool("version", false, "Print the version and exit")
)

var version string

const alexaUrl = "https://s3.amazonaws.com/alexa-static/top-1m.csv.zip"

func usage() {
	fmt.Printf("Tenta DNS Stresser %s", version)
	fmt.Println()
	fmt.Println("Testing harness for Tenta DNS")
	fmt.Println("Options:")
	flag.PrintDefaults()
}

func main() {
	log.SetLogLevel(logrus.InfoLevel)
	flag.Usage = usage
	flag.Parse()

	if *printver {
		fmt.Println(version)
		os.Exit(0)
	}

	if *quiet {
		log.SetLogLevel(logrus.FatalLevel)
	}
	if *verbose {
		log.SetLogLevel(logrus.DebugLevel)
	}

	if *workers < 1 {
		*workers = uint(runtime.NumCPU())
	}
	if *workers > 1 {
		*workers -= 1 // Leave aside a worker to feed the channel
	}

	lg := log.GetLogger("stresser")
	start := time.Now()
	lg.Infof("Starting test with %d workers", *workers)
	lg.Infof("Resolving up to %d names", *limit)

	resp, err := http.Get(alexaUrl)
	if err != nil {
		lg.Errorf("Unable to download domain listing: %s", err.Error())
	} else {
		defer resp.Body.Close()
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			lg.Errorf("Unable to read domain listing body: %s", err.Error())
		} else {
			r, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
			if err != nil {
				lg.Errorf("Unable to decode domain listing data as zip: %s", err.Error())
			} else {
				lg.Debugf("Got zip file")
				for _, f := range r.File {
					lg.Debugf("Found file %s", f.Name)
					if f.Name == "top-1m.csv" {
						fr, err := f.Open()
						defer fr.Close()
						if err != nil {
							lg.Errorf("Failure while opening file %s", f.Name)
						} else {
							cr := csv.NewReader(fr)
							testRecords(cr, *workers, lg)
						}
						break
					}
				}
			}
		}
	}

	duration := time.Now().Sub(start)
	lg.Infof("Finished in %s", duration.String())
}

type result struct {
	name    string
	time    time.Duration
	msg     string
	success bool
}

type worker struct {
	wg      *sync.WaitGroup
	lg      *logrus.Entry
	stop    chan bool
	work    chan string
	results chan result
}

func (w *worker) doWork(id uint) {
	lg := w.lg.WithField("id", id)
	defer lg.Debug("Done")
	w.wg.Add(1)
	defer w.wg.Done()
	lg.Debug("Started")
	run := true
	for run {
		select {
		case <-w.stop:
			lg.Debug("Got stop command")
			run = false
			break
		case name := <-w.work:
			start := time.Now()
			//lg.Debugf("Querying %s", name)
			time.Sleep(time.Millisecond * time.Duration(rand.Intn(100)))
			m := new(dns.Msg)
			m.Id = dns.Id()
			m.RecursionDesired = true
			m.CheckingDisabled = false
			m.Question = make([]dns.Question, 1)
			m.Question[0] = dns.Question{Name: dns.Fqdn(name), Qtype: dns.TypeA, Qclass: dns.ClassINET}
			c := new(dns.Client)
			c.Net = "udp"
			if *tcp {
				c.Net = "tcp"
			}
			if *tls {
				c.Net = "tcp-tls"
			}
			c.SingleInflight = true
			c.DialTimeout = time.Second
			c.WriteTimeout = time.Second * 3
			c.ReadTimeout = time.Second * 30
			in, _, err := c.Exchange(m, net.JoinHostPort(*ip, strconv.Itoa(int(*port))))
			s := false
			msg := ""
			if err != nil {
				msg = fmt.Sprintf("Error querying %s: %s", name, err.Error())
			} else {
				if in.Rcode != dns.RcodeSuccess {
					msg = fmt.Sprintf("Got a bad RCode for %s: %s", name, dns.RcodeToString[in.Rcode])
				} else {
					s = true
					msg = fmt.Sprintf("Query for %s OK", name)
				}
			}
			r := result{name: name, time: time.Since(start), success: s, msg: msg}
			w.results <- r
			break
		}
	}
}

func testRecords(r *csv.Reader, num uint, lg *logrus.Entry) {
	wg := &sync.WaitGroup{}
	workers := make([]worker, 0)
	work := make(chan string, num*2+1)
	rc := make(chan result, num*2+1)
	for i := uint(0); i < num; i += 1 {
		wrk := worker{wg: wg, lg: lg, stop: make(chan bool, 1), work: work, results: rc}
		go wrk.doWork(i)
		workers = append(workers, wrk)
	}
	cnt := uint(0)
	results := make(map[string]result)
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			lg.Errorf("Failed to read record: %s", err.Error())
			break
		}
		cnt += 1
		work <- rec[1]
		select {
		case r := <-rc:
			results[r.name] = r
			break
		case <-time.After(time.Microsecond):
			break
		}
		if cnt == *limit {
			break
		}
	}
	for len(work) > 0 {
		select {
		case r := <-rc:
			results[r.name] = r
			break
		case <-time.After(time.Microsecond):
			break
		}
	}
	run := true
	for run {
		select {
		case r := <-rc:
			results[r.name] = r
			break
		case <-time.After(time.Second * 60):
			run = false
			break
		}
	}
	for _, w := range workers {
		w.stop <- true
	}
	total := 0
	success := 0
	errstr := ""
	for _, r := range results {
		total += 1
		if r.success {
			success += 1
		} else {
			lg.Debugf("%s: failure: %s", r.name, r.msg)
			errstr += r.msg + "\n"
		}
	}
	if *errfile != "" && success < total {
		err := ioutil.WriteFile(*errfile, []byte(errstr), os.ModePerm)
		if err != nil {
			lg.Errorf("Unable to write results file %s: %s", *errfile, err.Error())
		}
	}
	lg.Infof("%d out of %d queries succeeded (%0.02f%%)", success, total, (float64(success)/float64(total))*100)
	wg.Wait()
}
