package responder

import (
	"strings"

	"github.com/miekg/dns"
	"github.com/tenta-browser/tenta-dns/runtime"
)

type JSONQuestion struct {
	Name   string
	RRtype uint16 `json:"Type"`
}

type JSONRR struct {
	*JSONQuestion
	TTL  uint32
	Data string
}

type JSONResponse struct {
	Status                        int
	TC, RD, RA, AD, CD            bool
	Question                      []*JSONQuestion
	Answer, Authority, Additional []*JSONRR `json:",omitempty"`
}

func JSONFromMsg(in *dns.Msg) *JSONResponse {
	resp := &JSONResponse{Status: in.Rcode, TC: in.Truncated, RD: in.RecursionDesired, RA: in.RecursionAvailable, AD: in.AuthenticatedData, CD: in.CheckingDisabled,
		Question: []*JSONQuestion{&JSONQuestion{Name: in.Question[0].Name, RRtype: in.Question[0].Qtype}}}

	if in.Answer != nil {
		resp.Answer = []*JSONRR{}
		for _, ans := range in.Answer {
			resp.Answer = append(resp.Answer, &JSONRR{&JSONQuestion{ans.Header().Name, ans.Header().Rrtype}, ans.Header().Ttl, strings.TrimLeft(ans.String(), ans.Header().String())})
		}
	}

	if in.Ns != nil {
		resp.Authority = []*JSONRR{}
		for _, ans := range in.Ns {
			resp.Authority = append(resp.Authority, &JSONRR{&JSONQuestion{ans.Header().Name, ans.Header().Rrtype}, ans.Header().Ttl, strings.TrimLeft(ans.String(), ans.Header().String())})
		}
	}
	cleanExtra := cleanAdditionalSection(in.Extra)
	if len(cleanExtra) != 0 {
		resp.Additional = []*JSONRR{}
		for _, ans := range cleanExtra {
			resp.Additional = append(resp.Additional, &JSONRR{&JSONQuestion{ans.Header().Name, ans.Header().Rrtype}, ans.Header().Ttl, strings.TrimLeft(ans.String(), ans.Header().String())})
		}
	}

	return resp
}

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
