package responder

import (
	"github.com/miekg/dns"
	"github.com/tenta-browser/tenta-dns/runtime"
)

// Politely decline to answer ANY queries
func refuseAny(w dns.ResponseWriter, r *dns.Msg, rt *runtime.Runtime) {
	rt.Stats.Tick("resolver", "refuse-any")
	hinfo := &dns.HINFO{
		Cpu: "ANY obsolete",
		Os:  "See draft-ietf-dnsop-refuse-any",
	}
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Compress = true
	msg.Answer = append(msg.Answer, hinfo)
	msg.SetRcode(r, dns.RcodeSuccess)
	w.WriteMsg(msg)
}

/// Set up a couple of typed cache returns, for specific usages
/// General policy is to skip type conversion errors, and return valid data

func ToA(cr interface{}) (ret []*dns.A) {
	if rr, ok := cr.([]dns.RR); ok {
		for _, r := range rr {
			if a, ok := r.(*dns.A); ok {
				ret = append(ret, a)
			}
		}
	} else if rs, ok := cr.(*dns.Msg); ok {
		for _, r := range rs.Answer {
			if a, ok := r.(*dns.A); ok {
				ret = append(ret, a)
			}
		}
	}
	return
}

func ToNS(cr interface{}) (ret []*dns.NS) {
	if rr, ok := cr.([]dns.RR); ok {
		for _, r := range rr {
			if ns, ok := r.(*dns.NS); ok {
				ret = append(ret, ns)
			}
		}
	} else if rs, ok := cr.(*dns.Msg); ok {
		for _, r := range rs.Answer {
			if ns, ok := r.(*dns.NS); ok {
				ret = append(ret, ns)
			}
		}
	}
	return
}
