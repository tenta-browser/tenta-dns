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
