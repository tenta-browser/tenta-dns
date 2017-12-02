package zones

import (
	"errors"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"regexp"
	"strings"
)

const TypeGROUP uint16 = 0xFF00

type GROUP struct {
	def string // rdata representing the definition
	lg  *logrus.Entry
}

func NewGROUP(log *logrus.Entry) func() dns.PrivateRdata {
	return func() dns.PrivateRdata { return &GROUP{"", log} }
}

func (rd *GROUP) Len() int       { return len([]byte(rd.def)) }
func (rd *GROUP) String() string { return rd.def }
func (rd *GROUP) Parse(txt []string) error {
	rd.def = strings.TrimSpace(strings.Join(txt, " "))
	for _, line := range txt {
		line = strings.TrimSpace(line)
		match, err := regexp.MatchString("^[a-z]+=[a-z0-9\\.]+$", line)
		if err != nil || !match {
			return err
		}
		pos := strings.Index(line, "=")
		arg := line[:pos]
		val := line[pos+1:]
		rd.lg.Debugf("Got argument %s with value %s", arg, val)
	}
	return nil
}
func (rd *GROUP) Pack(buf []byte) (int, error) {
	return 0, errors.New("Not implemented")
}
func (rd *GROUP) Unpack(buf []byte) (int, error) {
	return 0, errors.New("Not implemented")
}
func (rd *GROUP) Copy(dest dns.PrivateRdata) error {
	return errors.New("Not implemented")
}
