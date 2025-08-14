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

func TestAddNegativeDelta(t *testing.T) {
	addr, _ := Parse("::5")
	res := addr.Add(big.NewInt(-3))
	if res.String() != "::2" {
		t.Fatalf("expected ::2 got %s", res)
	}
}

func TestSplitEquality(t *testing.T) {
	c, _ := ParseCIDR("2001:db8::/64")
	subs, err := c.Split(64)
	if err != nil || len(subs) != 1 || subs[0].String() != c.String() {
		t.Fatalf("split equality failed: %v %v", subs, err)
	}
	it, err := c.SubnetIterator(64)
	if err != nil {
		t.Fatal(err)
	}
	one, ok := it.Next()
	if !ok || one.String() != c.String() {
		t.Fatalf("iterator equality failed: %v %v", one, ok)
	}
	_, ok = it.Next()
	if ok {
		t.Fatal("iterator should be exhausted")
	}
}

func TestMaskInvalidPanics(t *testing.T) {
	addr, _ := Parse("::1")
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for invalid Mask prefix")
		}
	}()
	_ = addr.Mask(129)
}

func TestSplitCap(t *testing.T) {
	c, _ := ParseCIDR("2001:db8::/64")
	// attempt absurd split beyond MaxSplitParts (choose prefix far enough)
	badPrefix := c.plen + 30 // 1<<30 > MaxSplitParts (1<<20)
	_, err := c.Split(badPrefix)
	if err == nil {
		t.Fatalf("expected excessive split error")
	}
}

// Fuzz tests (merged from fuzz_test.go)
func FuzzParse(f *testing.F) {
	seeds := []string{"::1", "2001:db8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		addr, err := Parse(in)
		if err != nil {
			return
		}
		p2, err := Parse(addr.String())
		if err != nil {
			t.Fatalf("re-parse failed: %v", err)
		}
		if p2.String() != addr.String() {
			t.Fatalf("roundtrip mismatch %s != %s", p2, addr)
		}
	})
}

func FuzzSummarize(f *testing.F) {
	f.Add("2001:db8::/64", "2001:db8:0:0:8000::/65")
	f.Fuzz(func(t *testing.T, a, b string) {
		c1, err1 := ParseCIDR(a)
		c2, err2 := ParseCIDR(b)
		if err1 != nil || err2 != nil {
			return
		}
		list := []CIDR{c1, c2}
		res := Summarize(list)
		for _, orig := range list {
			contained := false
			for _, s := range res {
				if s.ContainsCIDR(orig) {
					contained = true
					break
				}
			}
			if !contained {
				t.Fatalf("lost coverage for %v", orig)
			}
		}
	})
}

func FuzzSplit(f *testing.F) {
	f.Add("2001:db8::/120", 124)
	f.Fuzz(func(t *testing.T, cidrStr string, newPrefix int) {
		c, err := ParseCIDR(cidrStr)
		if err != nil {
			return
		}
		if newPrefix <= c.plen || newPrefix > 128 || newPrefix-c.plen > 8 {
			return
		}
		subs, err := c.Split(newPrefix)
		if err != nil {
			return
		}
		for i := 0; i < len(subs); i++ {
			if !c.ContainsCIDR(subs[i]) {
				t.Fatalf("sub not contained %v", subs[i])
			}
			for j := i + 1; j < len(subs); j++ {
				if subs[i].Overlaps(subs[j]) {
					t.Fatalf("overlap %v %v", subs[i], subs[j])
				}
			}
		}
	})
}

// Benchmarks (merged from bench_test.go)
func BenchmarkSplit(b *testing.B) {
	c, _ := ParseCIDR("2001:db8::/64")
	for i := 0; i < b.N; i++ {
		_, _ = c.Split(68)
	}
}
func BenchmarkSummarize(b *testing.B) {
	base, _ := ParseCIDR("2001:db8::/64")
	subs, _ := base.Split(68)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Summarize(subs)
	}
}
func BenchmarkDistance(b *testing.B) {
	a, _ := Parse("2001:db8::1")
	c := a.Add(big.NewInt(1 << 32))
	for i := 0; i < b.N; i++ {
		_ = Distance(a, c)
	}
}
func BenchmarkReverseDNS(b *testing.B) {
	a, _ := Parse("2001:db8::1")
	for i := 0; i < b.N; i++ {
		_ = a.ReverseDNS()
	}
}
