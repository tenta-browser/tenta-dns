package runtime

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/tenta-browser/tenta-dns/log"
)

const (
	DNS_PROVIDER = "opennic"
)

func BenchmarkInsert(b *testing.B) {
	lg := log.GetLogger("bench")
	h := StartCache(lg, DNS_PROVIDER)
	rr, _ := dns.NewRR("dns.tenta.io\t60\tIN\tA\t99.192.182.100")

	for i := 0; i < b.N; i++ {
		go func() {
			h.Insert(DNS_PROVIDER, "dns.tenta.io", rr, nil)
		}()
	}
}

func TestCleanup(t *testing.T) {
	lg := log.GetLogger("bench")
	h := StartCache(lg, DNS_PROVIDER)
	rr, e := dns.NewRR("dns.tenta.io\t2\tIN\tA\t99.192.182.100")
	if e != nil {
		lg.Fatalf("IDIOT! [%s]", e.Error())
		return
	}
	h.Insert(DNS_PROVIDER, "dns.tenta.io", rr, nil)
	time.Sleep(40 * time.Second)
	f := h.Retrieve(DNS_PROVIDER, "dns.tenta.io", dns.TypeA)
	if len(f) > 0 {
		t.Fatalf("You didn't clean the item up!!\n")
		t.FailNow()
	}

}
