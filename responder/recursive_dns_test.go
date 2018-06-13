package responder

import (
	"testing"
)

func TestTokenize(t *testing.T) {
	t1 := tokenizeDomain(".foo.bar.example.com.")
	ct1 := []string{"com.", "example.com.", "bar.example.com.", "foo.bar.example.com."}

	if len(t1) != len(ct1) {
		t.Fatalf("Length of output and control does not correspond.\n")
		t.FailNow()
	}

	for i, token := range t1 {
		if token != ct1[i] {
			t.Fatalf("Token %d mismatch [%s] vs [%s].\n", i, token, ct1[i])
			t.FailNow()
		}
	}
}
