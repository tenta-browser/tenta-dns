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
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/tenta-browser/tenta-dns/log"
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

const (
	maxLimit  = 1000000
	alexaDir  = "https://s3.amazonaws.com/alexa-static"
	alexaFile = "top-1m.csv.zip"
)

func usage() {
	fmt.Println("Stress tester for Tenta DNS\n" +
		"Options:")
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
	if *limit > maxLimit {
		fmt.Printf("limit must be < %d", maxLimit)
		os.Exit(1)
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

	lg := log.GetLogger("stresser")
	start := time.Now()
	defer func() {
		lg.Infof("Finished in %s", time.Now().Sub(start))
	}()
	lg.Infof("Starting test with %d workers", *workers)
	lg.Infof("Resolving up to %d domain names", *limit)

	resp, err := http.Get(alexaDir + "/" + alexaFile)
	if err != nil {
		lg.Errorf("Unable to download domain listing: %v", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		lg.Errorf("Unable to read domain listing body: %v", err)
		os.Exit(1)
	}
	r, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		lg.Errorf("Unable to decode domain listing data as zip: %v", err)
		os.Exit(1)
	}
	lg.Debugf("Got zip file")
	for _, f := range r.File {
		lg.Debugf("Found file %s", f.Name)
		if f.Name != strings.TrimSuffix(alexaFile, ".zip") {
			continue
		}
		fr, err := f.Open()
		if err != nil {
			lg.Errorf("Failure while opening file %s", f.Name)
			os.Exit(1)
		}
		defer fr.Close()
		testRecords(csv.NewReader(fr), *workers, lg)
		return
	}
}

type result struct {
	name string
	time time.Duration
	err  error
}

type worker struct {
	dc      *dns.Client
	lg      *logrus.Entry
	wg      *sync.WaitGroup
	work    <-chan string
	results chan<- result
}

func dnsMsg(name string) *dns.Msg {
	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
			CheckingDisabled: false,
		},
		Question: []dns.Question{
			{
				Name:   dns.Fqdn(name),
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			},
		},
	}
	m.SetEdns0(4096, false)
	return m
}

func (w *worker) doWork() {
	defer w.wg.Done()
	for name := range w.work {
		start := time.Now()
		in, _, err := w.dc.Exchange(dnsMsg(name), net.JoinHostPort(*ip, strconv.Itoa(int(*port))))
		var queryErr error
		switch {
		case err != nil:
			queryErr = fmt.Errorf("Error querying %q: %v", name, err)
		case in.Rcode != dns.RcodeSuccess:
			queryErr = fmt.Errorf("Got a bad RCode for %q: %s", name, dns.RcodeToString[in.Rcode])
		}
		r := result{name: name, time: time.Since(start), err: queryErr}
		w.results <- r
		// Create some skew in the worker pacing.
		time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
	}
}

func dnsClient() *dns.Client {
	c := &dns.Client{
		Net:            "udp",
		SingleInflight: true,
		DialTimeout:    time.Second,
		WriteTimeout:   3 * time.Second,
		ReadTimeout:    30 * time.Second,
	}
	if *tcp {
		c.Net = "tcp"
	}
	if *tls {
		c.Net = "tcp-tls"
	}
	return c
}

func testRecords(r *csv.Reader, num uint, lg *logrus.Entry) {
	wg := &sync.WaitGroup{}
	work := make(chan string, num*50)
	rc := make(chan result, num*30)
	wg.Add(int(num))
	for i := uint(1); i <= num; i++ {
		wrk := worker{
			wg:      wg,
			lg:      lg,
			work:    work,
			results: rc,
			dc:      dnsClient(),
		}
		go wrk.doWork()
	}
	lg.Debugf("Started %d workers", num)
	go func() {
		defer lg.Debug("All workers finished")
		wg.Wait()
		close(rc)
	}()
	go func() {
		defer lg.Debug("Finished dispatching work")
		// Feed the work queue up to the user-provided limit.
		for i := uint(0); i < *limit; i++ {
			rec, err := r.Read()
			if err == io.EOF {
				lg.Debugf("Reached EOF after %d records", i)
				break
			}
			if err != nil || len(rec) == 0 {
				lg.Errorf("Failed to read record")
				continue
			}
			work <- rec[1]
		}
		close(work)
	}()

	results := make(map[string]result)
	var total int
	errs := []string{}
	for res := range rc {
		total++
		if res.err != nil {
			lg.Debugf("%s: failure: %v", res.name, res.err)
			errs = append(errs, res.err.Error())
			continue
		}
		results[res.name] = res
	}
	if *errfile != "" && len(errs) > 0 {
		if err := ioutil.WriteFile(*errfile, []byte(strings.Join(errs, "\n")), os.ModePerm); err != nil {
			lg.Errorf("Unable to write errors to file %s: %v", *errfile, err)
		}
	}
	success := total - len(errs)
	lg.Infof("%d out of %d queries succeeded (%0.02f%%)", success, total, (float64(success)/float64(total))*100)
}
