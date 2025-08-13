package ipv6

import (
	"math/big"
	"net"
	"testing"
	"testing/quick"
)

func TestParseAndFormat(t *testing.T) {
	addr, err := Parse("2001:db8::1")
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != "2001:db8::1" {
		t.Fatalf("unexpected: %s", addr.String())
	}
	if addr.Expanded() != "2001:0db8:0000:0000:0000:0000:0000:0001" {
		t.Fatalf("expanded mismatch: %s", addr.Expanded())
	}
}

func TestCIDR(t *testing.T) {
	c, err := ParseCIDR("2001:db8::/64")
	if err != nil {
		t.Fatal(err)
	}
	if c.FirstHost().String() != "2001:db8::" {
		t.Fatal("first host mismatch")
	}
	if c.LastHost().Expanded() != "2001:0db8:0000:0000:ffff:ffff:ffff:ffff" {
		t.Fatalf("last host mismatch: %s", c.LastHost().Expanded())
	}
	if c.HostCount().Cmp(new(big.Int).Lsh(big.NewInt(1), 64)) != 0 {
		t.Fatal("host count wrong")
	}
}

func TestSplit(t *testing.T) {
	c, _ := ParseCIDR("2001:db8::/124")
	subs, err := c.Split(126)
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 4 {
		t.Fatalf("expected 4 got %d", len(subs))
	}
}

func TestSummarize(t *testing.T) {
	var list []CIDR
	for i := 0; i < 2; i++ { // two /65 forming /64
		c, _ := ParseCIDR("2001:db8::/65")
		if i == 1 {
			c = c.Next()
		}
		list = append(list, c)
	}
	res := Summarize(list)
	if len(res) != 1 || res[0].String() != "2001:db8::/64" {
		t.Fatalf("unexpected summarize: %v", res)
	}
}

func TestReverse(t *testing.T) {
	addr, _ := Parse("2001:db8::1")
	rev := addr.ReverseDNS()
	if rev[len(rev)-9:] != "ip6.arpa." {
		t.Fatalf("bad reverse: %s", rev)
	}
}

func TestQuickParseExpand(t *testing.T) {
	f := func(high, low uint64) bool {
		// construct address
		b := make([]byte, 16)
		for i := 0; i < 8; i++ {
			b[i] = byte(high >> (56 - 8*i))
		}
		for i := 0; i < 8; i++ {
			b[8+i] = byte(low >> (56 - 8*i))
		}
		addr, err := NewAddress(b)
		if err != nil {
			return false
		}
		parsed, err := Parse(addr.String())
		if err != nil {
			return false
		}
		return parsed.Expanded() == addr.Expanded()
	}
	if err := quick.Check(f, nil); err != nil {
		t.Fatal(err)
	}
}

func TestAdjacency(t *testing.T) {
	c1, _ := ParseCIDR("2001:db8::/64")
	c2 := c1.Next()
	// c2 base should equal lastHost+1 masked to /64 (i.e., its own base)
	expected := c1.LastHost().Add(big.NewInt(1)).Mask(64)
	if expected.Compare(c2.Base()) != 0 {
		t.Fatalf("adjacency base mismatch: %s != %s", expected, c2.Base())
	}
	if c1.Overlaps(c2) {
		t.Fatal("adjacent networks should not overlap")
	}
	if c2.Prev().String() != c1.String() {
		t.Fatal("prev failed")
	}
}

func TestContainsAndOverlap(t *testing.T) {
	outer, _ := ParseCIDR("2001:db8::/48")
	inner, _ := ParseCIDR("2001:db8:0:1::/64")
	if !outer.ContainsCIDR(inner) {
		t.Fatal("expected containment")
	}
	if !outer.ContainsAddress(inner.FirstHost()) {
		t.Fatal("address containment")
	}
	if !outer.Overlaps(inner) {
		t.Fatal("expected overlap")
	}
	cA, _ := ParseCIDR("2001:db8:1::/64")
	cB, _ := ParseCIDR("2001:db8:2::/64")
	if cA.Overlaps(cB) {
		t.Fatal("should not overlap")
	}
}

func TestArithmeticAndDistance(t *testing.T) {
	addr, _ := Parse("2001:db8::1")
	b := addr.Add(big.NewInt(10))
	if Distance(addr, b).Cmp(big.NewInt(10)) != 0 {
		t.Fatal("distance mismatch")
	}
	if b.Sub(big.NewInt(10)).String() != addr.String() {
		t.Fatal("sub mismatch")
	}
	if addr.Offset(5).String() != addr.Add(big.NewInt(5)).String() {
		t.Fatal("offset mismatch")
	}
}

func TestErrorsAndEdges(t *testing.T) {
	// invalid IPv4-mapped
	if _, err := NewAddress(net.ParseIP("127.0.0.1")); err == nil {
		t.Fatal("expected error for IPv4")
	}
	if _, err := Parse("not-an-ip"); err == nil {
		t.Fatal("expected parse error")
	}
	if _, err := ParseCIDR("2001:db8::/129"); err == nil {
		t.Fatal("expected cidr error")
	}
	// overlaps branch where first has longer prefix
	cA, _ := ParseCIDR("2001:db8::/65")
	cB, _ := ParseCIDR("2001:db8::/64")
	if !cA.Overlaps(cB) {
		t.Fatal("expected overlap with reversed sizes")
	}
	// distance with reverse order
	a1, _ := Parse("2001:db8::1")
	a2, _ := Parse("2001:db8::5")
	if Distance(a2, a1).Cmp(big.NewInt(4)) != 0 {
		t.Fatal("distance reverse mismatch")
	}
}
