package responder

import (
	"github.com/miekg/dns"
	"strings"
)

// Deep equality check for DS records
func equalsDS(a, b *dns.DS) bool {
	if a.Algorithm == b.Algorithm &&
		strings.ToLower(a.Digest) == strings.ToLower(b.Digest) &&
		a.DigestType == b.DigestType &&
		a.KeyTag == b.KeyTag {
		return true
	}
	return false
}
