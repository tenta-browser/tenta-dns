package zones

import (
	"errors"
	"github.com/miekg/dns"
	"strings"
)

const TypeDYNA uint16 = 0xFF01

type DYNA struct {
	def string // rdata representing the definition
}

func NewDYNA() dns.PrivateRdata { return &DYNA{""} }

func (rd *DYNA) Len() int       { return len([]byte(rd.def)) }
func (rd *DYNA) String() string { return rd.def }
func (rd *DYNA) Parse(txt []string) error {
	rd.def = strings.TrimSpace(strings.Join(txt, " "))
	return nil
}
func (rd *DYNA) Pack(buf []byte) (int, error) {
	return 0, errors.New("Not implemented")
}
func (rd *DYNA) Unpack(buf []byte) (int, error) {
	return 0, errors.New("Not implemented")
}
func (rd *DYNA) Copy(dest dns.PrivateRdata) error {
	return errors.New("Not implemented")
}
